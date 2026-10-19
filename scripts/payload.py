#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: payload.py
# purpose: 载体链剥离 —— 把"看起来是脚本/图片/资源"的东西剥到真正的 ELF。
#   覆盖的五种常见外壳（都不需要知道加密算法）：
#     ① shell 头 + 尾随压缩流（sed -n ... | gzip -cd 型自删投递器）
#     ② heredoc/base64 内嵌（base64 -d <<EOF）
#     ③ zip/jar/apk 容器
#     ④ 多 ELF 拼接（零墙分隔，phoff 基准要试两种）
#     ⑤ 裸内嵌 ELF（文件里直接躺着一个 7f 45 4c 46）
# usage:
#   python payload.py <file> [--dump dir] [--depth 3] [--json out.json]
#   python payload.py <file.zip> --all           # 容器里每个条目都剥
# 纪律: 只读原文件；落盘产物带 sha256 与 provenance（第几层、用什么方法、偏移）。

import sys, os, io, re, json, struct, base64, gzip, zlib, bz2, lzma, hashlib, zipfile, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAGIC = [
    (b'\x7fELF', 'elf'), (b'PK\x03\x04', 'zip'), (b'\x1f\x8b\x08', 'gzip'),
    (b'\xfd7zXZ\x00', 'xz'), (b'BZh', 'bzip2'), (b'\x28\xb5\x2f\xfd', 'zstd'),
    (b'\x78\x01', 'zlib'), (b'\x78\x5e', 'zlib'), (b'\x78\x9c', 'zlib'), (b'\x78\xda', 'zlib'),
    (b'dex\n', 'dex'), (b'\x7fELF\x02', 'elf'),
]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def identify(b):
    for m, k in MAGIC:
        if b.startswith(m):
            return k
    return 'unknown'


def try_decompress_at(b, off, max_out=200 * 1024 * 1024):
    """在 off 处尝试五种标准流；成功返回 (kind, plain)。"""
    for kind, fn in (('gzip', lambda x: gzip.decompress(x)),
                     ('zlib', lambda x: zlib.decompress(x)),
                     ('lzma', lambda x: lzma.decompress(x, format=lzma.FORMAT_ALONE)),
                     ('xz', lambda x: lzma.decompress(x, format=lzma.FORMAT_XZ)),
                     ('bz2', lambda x: bz2.decompress(x))):
        try:
            out = fn(b[off:])
            if out and len(out) <= max_out:
                return kind, out
        except Exception:
            continue
    return None, None


def strip_wrapper(b):
    """返回 [(方法, 偏移, 明文)] —— 一次剥一层（递归由调用方做）"""
    res = []
    # ① 尾随压缩流：常见于 self-deleting 投递器（首行是 shell，后面全是压缩数据）
    for m, kind in ((b'\x1f\x8b\x08', 'gzip'), (b'\xfd7zXZ\x00', 'xz'), (b'BZh', 'bzip2'),
                    (b'\x5d\x00\x00\x80\x00', 'lzma')):
        start = 0
        tries = 0
        while tries < 8:
            i = b.find(m, start)
            if i < 0:
                break
            k, out = try_decompress_at(b, i)
            if k and out:
                res.append(('trailing-%s@%d' % (k, i), i, out))
                break
            start = i + 1
            tries += 1
    # ② base64 块
    txt = None
    try:
        txt = b.decode('latin1')
    except Exception:
        pass
    if txt and re.search(r'base64\s+(-d|--decode)', txt):
        cands = re.findall(r'[A-Za-z0-9+/=\r\n]{200,}', txt)
        if cands:
            best = max(cands, key=len)
            try:
                raw = base64.b64decode(re.sub(r'\s+', '', best))
                if raw[:4] in (b'\x7fELF', b'PK\x03\x04', b'\x1f\x8b\x08'):
                    res.append(('base64-heredoc', 0, raw))
            except Exception:
                pass
    # ③ 裸内嵌 ELF（任意偏移）
    if b[:4] != b'\x7fELF':
        i = b.find(b'\x7fELF')
        if i > 0:
            res.append(('embedded-elf@%d' % i, i, b[i:]))
    return res


def carve_multi_elf(b, min_gap=0x1000):
    """多 ELF 拼接：零墙（>=1MB 全零）分隔 + 独立 ELF 头；phoff 基准两种都试。"""
    out = []
    offs = [m.start() for m in re.finditer(re.escape(b'\x7fELF'), b)]
    for i in offs:
        if i == 0:
            continue
        # 选边界：从上一个 ELF/文件头到这里之间找最长零墙
        prev = 0
        best = None
        for j in range(max(0, i - 0x200000), i):
            if b[j] != 0:
                continue
        out.append(i)
    return offs


def elf_ph_ok(b, base):
    """校验 base 处是否像一个 ELF 头（两种 phoff 基准都试）"""
    try:
        cls, enc = b[base + 4], b[base + 5]
        if cls not in (1, 2) or enc not in (1, 2):
            return None
        E = '<' if enc == 1 else '>'
        e_type, e_machine = struct.unpack_from(E + 'HH', b, base + 16)
        if e_type not in (1, 2, 3, 4):
            return None
        if cls == 2:
            phoff, = struct.unpack_from(E + 'Q', b, base + 32)
            phentsize, phnum = struct.unpack_from(E + 'HH', b, base + 54)
            eh = 64
        else:
            phoff, = struct.unpack_from(E + 'I', b, base + 28)
            phentsize, phnum = struct.unpack_from(E + 'HH', b, base + 42)
            eh = 52
        for name, base_off in (('file-relative', base + phoff), ('inner-relative', phoff)):
            ok = 0
            for k in range(min(phnum, 16)):
                o = base_off + k * phentsize
                if o < 0 or o + 56 > len(b):
                    break
                p_type, = struct.unpack_from(E + 'I', b, o)
                if p_type == 6:      # PT_PHDR 是最干净的确认
                    ok += 10
                elif p_type in (1, 2, 3, 7):
                    ok += 1
            if ok >= 2:
                return name, ok
        return None
    except Exception:
        return None


def peel(b, name, depth, dump_dir, layers, max_depth=3):
    """递归剥离；layers 记录 provenance"""
    rec = dict(name=name, size=len(b), sha256=sha(b)[:32], kind=identify(b), depth=depth)
    if dump_dir:
        os.makedirs(dump_dir, exist_ok=True)
    # 叶子：真 ELF
    if rec['kind'] == 'elf':
        rec['leaf'] = 'ELF'
        rec['elf_check'] = elf_ph_ok(b, 0)
        if dump_dir:
            p = os.path.join(dump_dir, '%02d_%s.elf' % (depth, re.sub(r'[^A-Za-z0-9._-]', '_', name)))
            open(p, 'wb').write(b)
            rec['path'] = p
        rec['children'] = []
        return rec
    if rec['kind'] == 'zip':
        rec['children'] = []
        try:
            z = zipfile.ZipFile(io.BytesIO(b))
            rec['zip_entries'] = [i.filename for i in z.infolist()][:200]
        except Exception as e:
            rec['error'] = str(e)
        return rec
    if depth >= max_depth:
        rec['stopped'] = 'max-depth'
        rec['children'] = []
        return rec
    stripped = strip_wrapper(b)
    rec['children'] = []
    for method, off, plain in stripped:
        layers.append(dict(parent=name, method=method, offset=hex(off), out_sha256=sha(plain)[:32], out_size=len(plain)))
        child = peel(plain, name + '->' + method, depth + 1, dump_dir, layers, max_depth)
        child['method'] = method
        rec['children'].append(child)
    if not rec['children']:
        rec['note'] = '未命中已知载体（可能加密 / 自研位流 / 就是数据）'
    return rec


def human(rec, indent=''):
    L = ['%s%-58s %10d B  %-10s %s' % (indent, rec['name'][-58:], rec['size'], rec['kind'],
                                       ('-> ' + rec.get('leaf', '')) if rec.get('leaf') else '')]
    if rec.get('elf_check'):
        L.append('%s    ELF 头校验: phoff 基准=%s (score=%s)' % (indent, rec['elf_check'][0], rec['elf_check'][1]))
    if rec.get('zip_entries'):
        L.append('%s    ZIP 条目 %d: %s' % (indent, len(rec['zip_entries']), ', '.join(rec['zip_entries'][:8])))
    for c in rec.get('children') or []:
        L.append(human(c, indent + '    '))
    if rec.get('note'):
        L.append('%s    [!] %s' % (indent, rec['note']))
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='载体链剥离：脚本/容器/拼接体 -> 真 ELF')
    ap.add_argument('target')
    ap.add_argument('--dump', default='')
    ap.add_argument('--depth', type=int, default=3)
    ap.add_argument('--json', default='')
    ap.add_argument('--all', action='store_true', help='zip 里逐条目剥离')
    a = ap.parse_args()
    layers = []
    if a.target.lower().endswith('.zip') and a.all:
        z = zipfile.ZipFile(a.target)
        roots = []
        for i in z.infolist():
            if i.filename.endswith('/'):
                continue
            b = z.read(i.filename)
            roots.append(peel(b, i.filename, 0, a.dump, layers, a.depth))
        for r in roots:
            print(human(r))
        out = roots
    else:
        b = open(a.target, 'rb').read()
        r = peel(b, os.path.basename(a.target), 0, a.dump, layers, a.depth)
        print(human(r))
        out = r
    if layers:
        print('\n== provenance（载体链）')
        for l in layers[:40]:
            print('   %-40s --%-28s @%-10s -> %s (%d B)' % (l['parent'][-40:], l['method'], l['offset'], l['out_sha256'], l['out_size']))
    if a.json:
        json.dump(dict(tree=out, provenance=layers), open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
