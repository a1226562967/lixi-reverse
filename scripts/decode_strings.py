#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib + 自带 aesgcm), file: decode_strings.py
# purpose: 字符串解密两用：
#   ① 已知密钥 → 批量解（GCM / 裸 XOR / 无解密 + UTF-16BE/UTF-8 组装）
#   ② **不知道密钥 → 盲扫**（`--scan`）：在非执行段找密文候选，穷举 256 个单字节 key ×
#      5 种变换（xor/add/sub/rol/ror），按可打印率排序，**并把比例一起回传**
#      （随机数据也会撞出可打印，比例就是唯一的证据强度）。
# usage:
#   python decode_strings.py <apk|dex|elf> --key <base64|hex> --prefix "f1:" --mode gcm
#   python decode_strings.py <elf> --scan            # 盲扫单字节变换
# 纪律: 可打印率 < 0.75 一律不报；报出来也不等于"已还原"。

import sys, os, re, json, math, base64, zipfile, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import aesgcm

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# ---------------- ① 已知密钥 ----------------
def parse_key(s):
    s = s.strip()
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
        return bytes.fromhex(s)
    return base64.b64decode(s + '=' * (-len(s) % 4))


def assemble(raw, charset):
    if charset == 'utf16be':
        if len(raw) % 2:
            return None
        return ''.join(chr((raw[i] << 8) | raw[i + 1]) for i in range(0, len(raw) - 1, 2))
    if charset == 'utf16le':
        if len(raw) % 2:
            return None
        return raw.decode('utf-16le', 'replace')
    return raw.decode('utf-8', 'replace')


def decrypt_one(tok, key, mode, iv_len, tag_len):
    data = base64.b64decode(tok)
    if mode == 'gcm':
        iv = data[:iv_len]
        ct = data[iv_len:len(data) - tag_len] if tag_len else data[iv_len:]
        return aesgcm.gcm_decrypt(key, iv, ct)
    if mode == 'xor':
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return data


# ---------------- ② 盲扫（不知道密钥） ----------------
def score_printable(b):
    if not b:
        return 0.0
    return sum(1 for c in b if c in PRINTABLE) / len(b)


def variants(block):
    """产出 (变换名, key, 结果字节)：单字节 xor 全 256，add/sub 各 255，rol/ror 各 7"""
    for k in range(256):
        yield ('xor', k, bytes(c ^ k for c in block))
    for k in range(1, 256):
        yield ('add', k, bytes((c - k) & 0xFF for c in block))
        yield ('sub', k, bytes((c + k) & 0xFF for c in block))
    for k in range(1, 8):
        yield ('ror', k, bytes(((c >> k) | (c << (8 - k))) & 0xFF for c in block))
        yield ('rol', k, bytes(((c << k) | (c >> (8 - k))) & 0xFF for c in block))


def _ent(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    e = 0.0
    for k in c:
        if k:
            q = k / n
            e -= q * math.log2(q)
    return e


def looks_like_cipher(b, min_ent=6.0):
    """密文候选：可打印率低 + 熵够高。字模/资源表/ASCII 图的可打印率也低，但熵低 ⇒ 被过滤。"""
    if not b or all(c == 0 for c in b):
        return False
    if score_printable(b) > 0.55:
        return False
    return _ent(b) >= min_ent


ALNUM = set(range(0x30, 0x3A)) | set(range(0x41, 0x5B)) | set(range(0x61, 0x7B))


def quality(out):
    """复合质量分：可打印率 × 字符多样性 × 字母数字占比。
    只按可打印率排会全是 '\t\t\t\t' 和 '====' —— 那是填充，不是字符串。"""
    if not out:
        return 0.0, 0, 0.0
    pr = score_printable(out)
    uniq = len(set(out))
    alnum = sum(1 for c in out if c in ALNUM) / len(out)
    q = pr * min(1.0, uniq / 16.0) * (0.3 + 0.7 * alnum)
    return round(q, 3), uniq, round(alnum, 3)


def semantic(out):
    """语义加权：可打印只是"像字"，含这些才是"真字符串"。返回 (加分, 标签[])"""
    sc, tags = 0.0, []
    if b'://' in out:
        sc += 0.6; tags.append('url')
    if b'{' in out and b'}' in out:
        sc += 0.4; tags.append('json')
    if any(0xE4 <= c <= 0xE9 for c in out):
        sc += 0.5; tags.append('cjk-utf8')
    if any(x in out for x in (b'/data/', b'/system/', b'.so', b'/proc/', b'/sdcard/')):
        sc += 0.3; tags.append('path')
    if b'==' in out or b'\x00' in out:
        sc -= 0.2
    return sc, tags


def scan_region(d, lo, hi, block, limit, min_ratio, scan_max=None):
    hits = []
    end = min(hi, lo + scan_max) if scan_max else hi
    for off in range(lo, max(lo, end - block), block):
        blk = d[off:off + block]
        if not looks_like_cipher(blk):
            continue
        best = None
        for name, k, out in variants(blk):
            r = score_printable(out)
            if r < min_ratio:
                continue
            q, uniq, alnum = quality(out)
            if uniq < 8 or alnum < 0.25:      # 排除 '				' / '=====' 这类填充
                continue
            if best is None or q > best[0]:
                best = (q, '%s 0x%02x' % (name, k), r, out, uniq, alnum)
        if best:
            hits.append(dict(off=off, transform=best[1], quality=best[0], ratio=round(best[2], 3),
                             uniq=best[4], alnum=best[5],
                             sample=best[3][:48].decode('latin1', 'replace')))
    return hits


def scan_target(path, block, limit, min_ratio, scan_max=None):
    d = open(path, 'rb').read()
    regions = []
    if d[:4] == b'\x7fELF':
        from elfprobe import Elf
        elf = Elf(d)
        for p in elf.phdrs:
            if p['type'] == 1 and p['filesz'] and not (p['flags'] & 1):
                regions.append((p['off'], min(p['off'] + p['filesz'], len(d))))
    else:
        regions.append((0, len(d)))
    out = []
    for lo, hi in regions:
        out += scan_region(d, lo, hi, block, limit * 4, min_ratio, scan_max)
    out.sort(key=lambda x: -x['quality'])
    return out[:limit]


# ---------------- 主流程 ----------------
def main():
    ap = argparse.ArgumentParser(description='字符串解密：已知密钥批量解 / 不知道密钥盲扫')
    ap.add_argument('target')
    ap.add_argument('--key', default='', help='base64 或 hex（--scan 时不需要）')
    ap.add_argument('--prefix', default='', help='混淆串前缀，如 "f1:"')
    ap.add_argument('--mode', choices=['gcm', 'xor', 'none'], default='gcm')
    ap.add_argument('--iv-len', type=int, default=12)
    ap.add_argument('--tag-len', type=int, default=16)
    ap.add_argument('--charset', choices=['utf16be', 'utf16le', 'utf8'], default='utf16be')
    ap.add_argument('--scan', action='store_true', help='盲扫：穷举 256 单字节 key × 5 种变换')
    ap.add_argument('--scan-block', type=int, default=64)
    ap.add_argument('--scan-limit', type=int, default=40)
    ap.add_argument('--min-ratio', type=float, default=0.75)
    ap.add_argument('--scan-max', type=int, default=2 << 20, help='每个非执行段最多扫多少字节（默认 2MB；大文件先扫前段）')
    ap.add_argument('-o', '--out', default='')
    ap.add_argument('--json', default='')
    a = ap.parse_args()

    if a.scan:
        hits = scan_target(a.target, a.scan_block, a.scan_limit, a.min_ratio, a.scan_max)
        print('[盲扫] %s  block=%d 门槛=%.2f' % (os.path.basename(a.target), a.scan_block, a.min_ratio))
        if not hits:
            print('  0 命中 —— 可能：① 不是单字节变换 ② 密钥运行期派生 ③ AES/RC4（见 references/04 §九 排除顺序）')
            return 0
        print('  %d 个候选（按**复合质量分**排序：可打印率 × 字符多样性 × 字母数字占比）：' % len(hits))
        for x in hits:
            tag = (','.join(x.get('tags') or [])) or '-'
            print('    @%#08x  %-10s 质量=%.2f 比例=%.2f 唯一=%d 语义=%-12s %r' % (
                x['off'], x['transform'], x['quality'], x['ratio'], x['uniq'], tag, x['sample']))
        if a.json:
            json.dump(hits, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            print('  -> %s' % a.json)
        print('  ⚠ 可打印率高 ≠ 解对了（随机数据也能撞出可打印）。要看**是否有语义**：URL / JSON / 中文字段名。')
        return 0

    if not a.key:
        print('[!] 非 --scan 模式必须给 --key（base64 或 hex）')
        return 2
    aesgcm.self_test()
    key = parse_key(a.key)
    print('[i] key=%d 字节 mode=%s prefix=%r charset=%s' % (len(key), a.mode, a.prefix, a.charset))
    blobs = []
    if a.target.lower().endswith(('.apk', '.zip')):
        z = zipfile.ZipFile(a.target)
        for n in z.namelist():
            if n.endswith(('.dex', '.json', '.bin', '.dat', '.so')):
                blobs.append((n, z.read(n)))
    else:
        blobs.append((os.path.basename(a.target), open(a.target, 'rb').read()))
    pre = re.escape(a.prefix.encode()) if a.prefix else b''
    pat = re.compile(pre + rb'([A-Za-z0-9+/=]{8,})')
    seen = {}
    for name, d in blobs:
        for m in pat.finditer(d):
            seen.setdefault(m.group(1).decode('latin1'), name)
    print('[i] 唯一候选串 %d 条' % len(seen))
    ok = err = 0
    rows = []
    for tok, src in seen.items():
        try:
            raw = decrypt_one(tok, key, a.mode, a.iv_len, a.tag_len)
            p = assemble(raw, a.charset) if raw else None
            if not p:
                raise ValueError('empty')
            ok += 1
        except Exception as e:
            p = '<ERR %s>' % str(e)[:40]
            err += 1
        rows.append((src, tok, p))
    print('[i] 解出 %d 条 / 失败 %d 条' % (ok, err))
    for src, tok, p in rows[:30]:
        print('   %-14s %-30s %s' % (src[:14], tok[:30], (p or '')[:90]))
    if a.out:
        with open(a.out, 'w', encoding='utf-8') as f:
            for src, tok, p in rows:
                f.write('%-6s %s\n' % (src, p))
        print('-> %s' % a.out)
    if a.json:
        json.dump([{'source': s, 'token': t, 'plain': p} for s, t, p in rows],
                  open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print('-> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
