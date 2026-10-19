#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: container.py
# purpose: 追加容器（appended container）测绘与可读化 —— 把"极加密 ELF"判清是
#          ① 整体加密 ② 小明文 loader + 尾部加密容器 ③ 资源块（不是加密）。
#   四件事：段覆盖图(uncovered) / 熵剖面与零字节占比 / 魔数搜捕 / 节表恢复 + 垃圾字 NOP。
# usage:
#   python container.py <elf>                       # 只判型（只读）
#   python container.py <elf> --recover-sht out.elf  # 恢复被清零的节表（另存）
#   python container.py <elf> --junkfix out.elf      # NOP 掉"被跳过的非法字"，让 IDA 能建函数
#   python container.py <elf> --json r.json
# 纪律: 默认只读；两种 --out 都写新文件，不动原文件。

import sys, os, re, json, math, struct, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from elfprobe import Elf, EM, ET
from zh import zh_list  # 判定标签中文化


def entropy(b):
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
    return round(e, 3)


def zerobyte_ratio(b):
    return round(b.count(0) / len(b), 4) if b else 0.0


def coverage(elf):
    """PT_LOAD 并集 vs 文件长 → 未覆盖区间列表（追加容器的判据）"""
    segs = sorted([(p['off'], p['off'] + p['filesz']) for p in elf.load_segments() if p['filesz']])
    if not segs:
        return [], [(0, len(elf.d))]
    merged = []
    for a, b in segs:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    gaps = []
    prev = 0
    for a, b in merged:
        if a > prev:
            gaps.append((prev, a))
        prev = max(prev, b)
    if prev < len(elf.d):
        gaps.append((prev, len(elf.d)))
    return merged, gaps


def printable_magics(b, n=8, limit=6):
    """在给定块里找 n 字节可打印 ASCII 串（容器魔数常用 8 字符）"""
    out = []
    for m in re.finditer(rb'[ -~]{%d,%d}' % (n, n + 8), b[:0x10000]):
        out.append(dict(off=m.start(), s=m.group().decode('latin1')))
        if len(out) >= limit:
            break
    return out


def sht_recover(elf, limit_try=200000):
    """暴搜节表：把后段每个 8 字节对齐偏移当 e_shoff，试着解 64 字节项并做一致性校验。"""
    d = elf.d
    n = len(d)
    best = None
    lo = max(0x40, n // 8)
    for off in range(lo, n - 64 * 3, 8):
        try:
            nm, ty, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from('<IIQQQQIIQQ', d, off)
        except Exception:
            continue
        # 允许第一项是 SHT_NULL（全 0），只要求"不是全垃圾"
        if not (ty == 0 and nm == 0 and of == 0):
            if ty > 20:
                continue
            if of > n or sz > n or of + sz > n:
                continue
        # 连解 3 项都自洽才算候选
        ok = 0
        for k in range(3):
            o = off + k * 64
            if o + 64 > n:
                break
            nm2, ty2, fl2, ad2, of2, sz2, lk2, inf2, al2, es2 = struct.unpack_from('<IIQQQQIIQQ', d, o)
            if ty2 <= 20 and of2 <= n and sz2 <= n and of2 + sz2 <= n:
                ok += 1
        if ok >= 3:
            best = off
            break
    return best


def junkfix(elf, out_path, d=None):
    """把"跳转让开"的非法 4 字节 NOP 掉：若某跳转目标 == addr+8，则 NOP addr+4。
    只打 4 种编码：B / B.cond / CBZ|CBNZ / TBZ|TBNZ 且 imm 表示 +8。"""
    d = bytearray(d or elf.d)
    segs = [p for p in elf.phdrs if p['type'] == 1 and (p['flags'] & 1) and p['filesz']]
    hits = []
    for p in segs:
        off, va, sz = p['off'], p['vaddr'], min(p['filesz'], len(d) - p['off'])
        n = sz // 4
        for i in range(n):
            w = struct.unpack_from('<I', d, off + i * 4)[0]
            imm = None
            if (w & 0x7C000000) == 0x14000000:            # B
                v = w & 0x03FFFFFF
                if v & (1 << 25):
                    v -= (1 << 26)
                imm = v
            elif (w & 0xFF000010) == 0x54000000:          # B.cond
                v = (w >> 5) & 0x7FFFF
                if v & (1 << 18):
                    v -= (1 << 19)
                imm = v
            elif (w & 0x7E000000) in (0x34000000, 0x36000000):   # CBZ/CBNZ/TBZ/TBNZ
                v = (w >> 5) & 0x3FFF
                if v & (1 << 13):
                    v -= (1 << 14)
                imm = v
            if imm != 2:      # 目标 = pc + 8 → 跳过下一条
                continue
            if i + 1 >= n:
                continue
            nxt = struct.unpack_from('<I', d, off + (i + 1) * 4)[0]
            bad = nxt in (0x00000042, 0x00000000) or (nxt & 0xFFFF0000) == 0x42000000
            if bad:
                struct.pack_into('<I', d, off + (i + 1) * 4, 0xD503201F)  # NOP
                hits.append(dict(vaddr=va + (i + 1) * 4, was='%08x' % nxt))
    open(out_path, 'wb').write(bytes(d))
    return hits



def parse_footer(d):
    """末尾 32B 常见结构：8 字节魔数 + 3×u64 偏移。通用（不限 MPFOOTER）。"""
    tail = d[-32:]
    magic = tail[:8]
    if not re.fullmatch(rb'[A-Z0-9]{4,10}', magic):
        return None
    a, b, c = struct.unpack('<QQQ', tail[8:32])
    fields = []
    for name, off in (('hdr_off', a), ('mid', b), ('hdr_off2', c)):
        item = dict(field=name, off=off, in_file=(0 < off < len(d) - 16))
        if item['in_file']:
            m = re.match(rb'[A-Z0-9]{4,12}', d[off:off + 16])
            item['head_magic'] = m.group().decode() if m else None
            item['head16'] = d[off:off + 16].hex()
        fields.append(item)
    return dict(magic=magic.decode(), tail_hex=tail.hex(), fields=fields)


def parse_container_header(d, off, n=24):
    """容器头：8 字节魔数 + u32 序列。打印前 n 个 u32，并标出常见 chunk 值。"""
    if not (0 < off < len(d) - 16):
        return None
    m = re.match(rb'[A-Z0-9]{4,12}', d[off:off + 16])
    if not m:
        return None
    u32 = list(struct.unpack_from('<%dI' % n, d, off + 8))
    guess = None
    for i, v in enumerate(u32):
        if v in (0x4000, 0x2000, 0x8000, 0x10000):
            guess = dict(idx=i, value=hex(v), note='疑似 chunk（分块大小）')
            break
    return dict(magic=m.group().decode(), off=off, u32=u32, chunk_guess=guess,
                hex64=d[off:off + 64].hex())


def verdict(r):
    tags = []
    g = r['uncovered_total']
    if g == 0:
        tags.append('NO-UNCOVERED(段覆盖完整 -> 不是追加容器)')
    else:
        big = [x for x in r['uncovered'] if x['size'] > 0x10000]
        for x in big:
            if x['entropy'] > 7.8:
                tags.append('APPENDED-CONTAINER(uncovered %d B @%#x 熵=%s -> 明文 loader + 尾部加密容器)' % (
                    x['size'], x['off'], x['entropy']))
            elif x['zerobyte'] > 0.03:
                tags.append('RESOURCE-BLOCK?(uncovered %d B @%#x 熵=%s 零字节=%s -> 大概率资源块, 不是加密)' % (
                    x['size'], x['off'], x['entropy'], x['zerobyte']))
            else:
                tags.append('UNCOVERED-DATA(%d B @%#x 熵=%s)' % (x['size'], x['off'], x['entropy']))
    t = r['text_entropy']
    if t is not None:
        if t > 7.6:
            tags.append('TEXT-ENCRYPTED(可执行段熵=%s -> 整体加密/自解密, 走 dump 或运行时打桩)' % t)
        elif 5.5 <= t <= 7.2:
            tags.append('TEXT-PLAIN(可执行段熵=%s -> 明文代码, loader 可反编译)' % t)
    if r.get('footer') and r.get('container_header'):
        tags.append('CONTAINER-HEADER(%r @%#x: footer 直接给出了容器位置)' % (
            r['container_header']['magic'], r['container_header']['off']))
    if r['sht_recover_off'] is not None and (r['e_shoff'] == 0 or r['e_shnum'] == 0):
        tags.append('SHT-RECOVERABLE(节表在 %#x, 只是字段被清零)' % r['sht_recover_off'])
    if r['junk_hits'] is not None:
        tags.append('JUNK-JUMPS(%d 处"跳转+8 跳过非法字" -> 是它让 IDA 建不了函数)' % len(r['junk_hits']))
    return tags or ['UNKNOWN(证据不足)']


def scan(path, recover_sht=None, junkfix_out=None):
    d = open(path, 'rb').read()
    if d[:4] != b'\x7fELF':
        return dict(path=os.path.abspath(path), error='not ELF (先 python scripts/payload.py 剥载体)')
    elf = Elf(d)
    merged, gaps = coverage(elf)
    unc = []
    for a, b in gaps:
        blk = d[a:b]
        if len(blk) < 0x400:
            continue
        # 4KB 熵剖面：前段常是 .comment/节表/填充，真正的容器起点是"熵跳变点"
        prof = []
        step = 0x1000
        for o in range(0, min(len(blk), 0x400000), step):
            prof.append((a + o, entropy(blk[o:o + step])))
        jump = None
        for o, e in prof:
            if e > 7.8:
                jump = o
                break
        unc.append(dict(off=a, size=len(blk), entropy=entropy(blk[:0x100000]),
                        zerobyte=zerobyte_ratio(blk[:0x100000]),
                        head32=blk[:32].hex(),
                        container_start=jump,
                        container_off_at_jump=(jump - a) if jump else None,
                        magics=printable_magics(blk),
                        magics_near_container=(printable_magics(d[jump:jump + 0x20000]) if jump else [])))
    rx = [p for p in elf.phdrs if p['type'] == 1 and (p['flags'] & 1) and p['filesz']]
    text_e = None
    if rx:
        p = max(rx, key=lambda x: x['filesz'])
        text_e = entropy(d[p['off']:p['off'] + min(p['filesz'], 0x200000)])
    sht = sht_recover(elf)
    r = dict(path=os.path.abspath(path), size=len(d),
             e_type=ET.get(elf.type, elf.type), machine=EM.get(elf.machine, hex(elf.machine)),
             entry=hex(elf.entry), e_shoff=elf.shoff, e_shnum=elf.shnum,
             load_merged=[dict(off=a, end=b) for a, b in merged],
             uncovered=unc, uncovered_total=sum(x['size'] for x in unc),
             tail32=d[-32:].hex(), tail_ascii=''.join(chr(c) if 32 <= c < 127 else '.' for c in d[-32:]),
             text_entropy=text_e, sht_recover_off=sht,
             junk_hits=None)
    if recover_sht and sht is not None:
        b = bytearray(d)
        struct.pack_into('<Q', b, 40, sht)          # e_shoff
        struct.pack_into('<H', b, 60, 64)           # e_shentsize
        struct.pack_into('<H', b, 62, 64)           # e_shnum（先给个上限）
        open(recover_sht, 'wb').write(bytes(b))
        r['sht_out'] = recover_sht
    if junkfix_out:
        r['junk_hits'] = junkfix(elf, junkfix_out, d)
        r['junk_out'] = junkfix_out
    r['footer'] = parse_footer(d)
    hdr_off = None
    if r['footer']:
        for f in r['footer']['fields']:
            if f['field'] == 'hdr_off' and f.get('in_file'):
                hdr_off = f['off']
                break
    if hdr_off is None:
        for x in unc:
            if x.get('container_start'):
                hdr_off = x['container_start']
                break
    r['container_header'] = parse_container_header(d, hdr_off) if hdr_off else None
    r['verdict'] = verdict(r)
    return r


def human(r):
    if r.get('error'):
        return '[!] %s' % r['error']
    L = ['== %s  (%d B)' % (r['path'], r['size']),
         '   ELF %s entry=%s  e_shoff=%#x e_shnum=%d' % (r['machine'], r['entry'], r['e_shoff'], r['e_shnum'])]
    L.append('   PT_LOAD 并集: %s' % ', '.join('%#x-%#x' % (x['off'], x['end']) for x in r['load_merged']))
    L.append('   可执行段熵 = %s   %s' % (r['text_entropy'],
             '(明文代码)' if r['text_entropy'] and r['text_entropy'] < 7.3 else '(高 -> 整体加密?)'))
    L.append('\n[uncovered] 共 %d B（任何 PT_LOAD 都不覆盖的部分）' % r['uncovered_total'])
    for x in r['uncovered'][:8]:
        L.append('   @%#x  %d B  熵=%s  零字节=%s  head32=%s' % (x['off'], x['size'], x['entropy'], x['zerobyte'], x['head32']))
        if x.get('container_start'):
            L.append('       容器起点(熵跳变) = %#x（uncovered 内偏移 %#x）' % (x['container_start'], x['container_off_at_jump']))
            for mg in x.get('magics_near_container', [])[:3]:
                L.append('       容器头魔数候选 @%#x: %r' % (x['container_start'] + mg['off'], mg['s']))
        for mg in x.get('magics', [])[:2]:
            L.append('       段内可打印串 @%#x: %r' % (x['off'] + mg['off'], mg['s']))
    L.append('   文件末 32B: %s   |%s|' % (r['tail32'], r['tail_ascii']))
    if r['sht_recover_off'] is not None:
        L.append('\n[节表] 暴搜到候选 e_shoff=%#x（当前字段=%#x/%d）→ --recover-sht 可回填' % (
            r['sht_recover_off'], r['e_shoff'], r['e_shnum']))
    else:
        L.append('\n[节表] 暴搜无候选（可能被真的截掉：不影响执行，linker 只认 program headers）')
    if r.get('footer'):
        ft = r['footer']
        L.append('\n[footer] 魔数 %r  末32B=%s' % (ft['magic'], ft['tail_hex']))
        for f in ft['fields']:
            L.append('   %-9s = %#x%s%s' % (f['field'], f['off'],
                     ('  头魔数=%r' % f['head_magic']) if f.get('head_magic') else '',
                     '' if f.get('in_file') else '  (不在文件内)'))
    if r.get('container_header'):
        h = r['container_header']
        L.append('\n[容器头] %r @%#x' % (h['magic'], h['off']))
        L.append('   u32[0..%d] = %s' % (len(h['u32']), ' '.join('%08x' % v for v in h['u32'][:16])))
        L.append('   常见布局: +0x08 ver / +0x0C flags / +0x10 out_size / +0x18 in_size / +0x20 seed / +0x24 chunk / +0x28 nhash')
        if h.get('chunk_guess'):
            L.append('   %s -> u32[%d]=%s' % (h['chunk_guess']['note'], h['chunk_guess']['idx'], h['chunk_guess']['value']))
        L.append('   头前 64B hex = %s' % h['hex64'])
    if r['junk_hits'] is not None:
        L.append('\n[垃圾字] NOP 掉 %d 处（"跳转 +8" 跳过的非法字）→ %s' % (len(r['junk_hits']), r.get('junk_out')))
        for h in r['junk_hits'][:6]:
            L.append('   %#x  原 %s → nop' % (h['vaddr'], h['was']))
    L.append('\n   >> 判定: %s' % zh_list(r['verdict']))
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='追加容器测绘与可读化（段覆盖/熵/魔数/节表/垃圾字）')
    ap.add_argument('target')
    ap.add_argument('--recover-sht', default='')
    ap.add_argument('--junkfix', default='')
    ap.add_argument('--json', default='')
    a = ap.parse_args()
    r = scan(a.target, a.recover_sht or None, a.junkfix or None)
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
