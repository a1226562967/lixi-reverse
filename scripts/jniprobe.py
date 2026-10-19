#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: jniprobe.py
# purpose: JNI 动态注册还原 —— 安卓 native 卡密验证绝大多数走 RegisterNatives 动态注册，
#   符号表里**没有** Java_* 导出。本脚本扫 JNINativeMethod 三指针表，把
#   「Java 方法名 → 原生实现地址」直接映射出来（这是静态分析死角的补丁）。
# usage:
#   python jniprobe.py <libxxx.so>            # 列 JNI 注册表
#   python jniprobe.py <lib>.so --json r.json
#   python jniprobe.py --selftest             # 构造样本自证
# 原理: JNINativeMethod = {const char* name; const char* signature; void* fnPtr;}（24 字节/项）
#   静态文件里 fnPtr 多为 0（PIE 由 R_AARCH64_RELATIVE 运行期填）⇒ 先应用重定位再扫。

import sys, os, re, json, struct, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from elfprobe import Elf

R_AARCH64_RELATIVE = 1027
SIG_RE = re.compile(r'^\((\[*[BCDFIJSZ]|L[^;]+;)*\)(\[*[BCDFIJSZV]|L[^;]+;)$')


def build_maps(elf, d):
    """返回 (readable_segs, exec_segs, v2o)"""
    segs = [p for p in elf.phdrs if p['type'] == 1 and p['filesz']]
    readable = [p for p in segs if p['flags'] & 4]                 # PF_R
    execable = [p for p in segs if p['flags'] & 1]                 # PF_X
    def v2o(v):
        for p in segs:
            if p['vaddr'] <= v < p['vaddr'] + max(p['filesz'], p['memsz']):
                off = p['off'] + (v - p['vaddr'])
                return off if 0 <= off < len(d) else None
        return None
    return readable, execable, v2o


def in_ranges(v, ranges):
    for p in ranges:
        if p['vaddr'] <= v < p['vaddr'] + max(p['filesz'], p['memsz']):
            return True
    return False


def apply_relocs(elf, d):
    """应用 R_AARCH64_RELATIVE：mem[r_offset] = r_addend。返回 dict vaddr->value（只存被重定位的槽）"""
    rel = {}
    targets = []
    s = elf.section('.rela.dyn')
    if s and s['size']:
        targets.append((s['off'], s['size']))
    else:
        # PT_DYNAMIC: DT_RELA(7) / DT_RELASZ(8)
        dyn = elf.dynamic_entries() if hasattr(elf, 'dynamic_entries') else []
        rela_va = rela_sz = None
        for t, v in dyn:
            if t == 7:
                rela_va = v
            elif t == 8:
                rela_sz = v
        if rela_va is not None and rela_sz:
            readable, execable, v2o = build_maps(elf, d)
            off = v2o(rela_va)
            if off is not None:
                targets.append((off, rela_sz))
    for off, sz in targets:
        n = sz // 24
        for i in range(n):
            o = off + i * 24
            if o + 24 > len(d):
                break
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', d, o)
            if (r_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
                rel[r_offset] = r_addend
    return rel


def read_ptr(d, v2o, rel, v, readable):
    """读一个 8 字节指针：优先重定位表，其次文件内容（非 PIE 常是绝对值）"""
    if v in rel:
        return rel[v]
    off = v2o(v)
    if off is None or off + 8 > len(d):
        return None
    val = struct.unpack_from('<Q', d, off)[0]
    return val if val else rel.get(v, 0)


def cstr_at(d, v2o, v, readable, limit=256):
    off = v2o(v)
    if off is None:
        return None
    end = d.find(b'\0', off, off + limit)
    if end <= off:
        return None
    raw = d[off:end]
    if not all(32 <= c < 127 for c in raw):
        return None
    return raw.decode('latin1')


def scan_tables(elf, d, min_entries=2):
    readable, execable, v2o = build_maps(elf, d)
    rel = apply_relocs(elf, d)
    # 候选数据段：可读、非可执行（.data.rel.ro / .rodata / .data）
    cand = [p for p in readable if not (p['flags'] & 1) and p['filesz'] >= 24 * min_entries]
    tables = []
    for p in cand:
        start, end = p['off'], min(p['off'] + p['filesz'], len(d))
        for o in range(start, end - 24, 8):
            v = p['vaddr'] + (o - p['off'])
            p1 = read_ptr(d, v2o, rel, v, readable)
            p2 = read_ptr(d, v2o, rel, v + 8, readable)
            p3 = read_ptr(d, v2o, rel, v + 16, readable)
            if not (p1 and p2 and p3):
                continue
            name = cstr_at(d, v2o, p1, readable, 128)
            # 精度优先：单字符名字 + 不像签名的串在密文里到处都是（实测 67MB 载荷误报 128 条）
            if not name or not re.fullmatch(r'[A-Za-z_$][\w$]{1,80}', name):
                continue
            sig = cstr_at(d, v2o, p2, readable, 256)
            if not sig or not (sig.startswith('(') and ')' in sig):
                continue
            if not in_ranges(p3, execable):
                continue
            # 逐项往后长
            entries = []
            q = o
            while q + 24 <= end:
                vv = p['vaddr'] + (q - p['off'])
                a1 = read_ptr(d, v2o, rel, vv, readable)
                a2 = read_ptr(d, v2o, rel, vv + 8, readable)
                a3 = read_ptr(d, v2o, rel, vv + 16, readable)
                if not (a1 and a2 and a3):
                    break
                nm = cstr_at(d, v2o, a1, readable, 128)
                sg = cstr_at(d, v2o, a2, readable, 256)
                if not nm or not sg or not in_ranges(a3, execable):
                    break
                entries.append(dict(name=nm, sig=sg, vaddr=a3, file_off=v2o(a3)))
                q += 24
            if len(entries) >= min_entries:
                tables.append(dict(table_vaddr=v, count=len(entries), entries=entries))
    # 去重（同一个表可能被多个起点命中：只保留最长/最早）
    tables.sort(key=lambda t: (-t['count'], t['table_vaddr']))
    seen = set()
    out = []
    for t in tables:
        key = t['entries'][0]['vaddr']
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out, rel


def attach_symbols(elf, d, tables):
    """给 fnPtr 附上最近的符号名（有 .symtab 才有；否则留空）"""
    syms = []
    for s in elf.sections:
        if s['name'] in ('.symtab', '.dynsym') and s['size']:
            ent = 24 if elf.cls == 2 else 16
            for i in range(s['size'] // ent):
                o = s['off'] + i * ent
                if o + ent > len(d):
                    break
                if elf.cls == 2:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', d, o)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from('<IIIBBH', d, o)
                if st_shndx != 0 and st_value:
                    syms.append((st_value, st_size))
    if not syms:
        return
    syms.sort()
    for t in tables:
        for e in t['entries']:
            best = None
            for v, sz in syms:
                if v <= e['vaddr'] and (sz == 0 or e['vaddr'] < v + sz):
                    best = v
            e['nearest_sym_off'] = ('+%#x' % (e['vaddr'] - best)) if best else None


def human(r):
    L = ['== %s  (%d B)' % (r['path'], r['size'])]
    if not r['tables']:
        L.append('   JNI 注册表: 0 个（可能没有动态注册 / 表在未识别段 / 目标用了静态 Java_* 命名）')
        L.append('   兜底：strings 搜 Java_ 前缀 → 若为 0 且确有 native 方法，说明注册表被加密或用了其他机制')
        return '\n'.join(L)
    total = sum(t['count'] for t in r['tables'])
    L.append('   JNI 注册表: %d 个表 / %d 个方法（动态注册 → 符号表里看不到 Java_*）' % (len(r['tables']), total))
    for t in r['tables']:
        L.append('\n   [表 @%#x]  %d 项' % (t['table_vaddr'], t['count']))
        for e in t['entries'][:40]:
            L.append('     %-28s %-32s -> %#010x%s' % (
                e['name'], e['sig'], e['vaddr'],
                ('  (%s)' % e['nearest_sym_off']) if e.get('nearest_sym_off') else ''))
        if t['count'] > 40:
            L.append('     … 还有 %d 项（用 --json 看全）' % (t['count'] - 40))
    L.append('\n   >> 用法：这些 `fnPtr` 就是"卡密校验/注册/心跳"的真实落点；'
             '把它们当普通函数分析（rkprobe 的打桩点、elfprobe 的密钥桩都适用）')
    return '\n'.join(L)


def selftest():
    """构造一个带 JNINativeMethod 表的小 ELF64，验证能识别"""
    import tempfile
    d = bytearray(0x3000)
    d[0:4] = b'\x7fELF'; d[4] = 2; d[5] = 1; d[6] = 1
    struct.pack_into('<HHI', d, 16, 3, 183, 1)     # DYN / AARCH64
    base = 0x10000
    phoff = 64
    struct.pack_into('<QQQ', d, 24, base + 0x2000, phoff, 0)   # entry
    struct.pack_into('<IHHHHHH', d, 48, 0, 64, 56, 3, 64, 0, 0)
    # LOAD1 R+X (代码区)
    struct.pack_into('<IIQQQQQQ', d, phoff, 1, 5, 0x1000, base + 0x1000, base + 0x1000, 0x800, 0x800, 0x1000)
    # LOAD2 R (字符串)
    struct.pack_into('<IIQQQQQQ', d, phoff + 56, 1, 4, 0x1800, base + 0x1800, base + 0x1800, 0x400, 0x400, 0x1000)
    # LOAD3 RW (表)
    struct.pack_into('<IIQQQQQQ', d, phoff + 112, 1, 6, 0x1c00, base + 0x1c00, base + 0x1c00, 0x400, 0x400, 0x1000)
    # 字符串
    strs = {0x1800: b'verifyCard', 0x1810: b'(Ljava/lang/String;)I', 0x1830: b'getExpire',
            0x1840: b'()J'}
    for k, v in strs.items():
        d[k:k + len(v) + 1] = v + b'\0'
    # 表（两行三列 = 2 项）
    rows = [(base + 0x1800, base + 0x1810, base + 0x1200),
            (base + 0x1830, base + 0x1840, base + 0x1300)]
    for i, (a, b, c) in enumerate(rows):
        struct.pack_into('<QQQ', d, 0x1c00 + i * 24, a, b, c)
    # 代码区放 nop，让 fnPtr 落在 R+X 内
    for o in range(0x1000, 0x1800, 4):
        struct.pack_into('<I', d, o, 0xD503201F)
    tmp = os.path.join(tempfile.mkdtemp(), 'libfake.so')
    open(tmp, 'wb').write(bytes(d))
    elf = Elf(bytes(d))
    tables, rel = scan_tables(elf, bytes(d))
    ok = bool(tables) and tables[0]['count'] == 2
    print(human(dict(path=tmp, size=len(d), tables=tables)))
    print('\n[selftest] %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    if '--selftest' in sys.argv:
        return selftest()
    ap = argparse.ArgumentParser(description='JNI 动态注册还原（JNINativeMethod 表）')
    ap.add_argument('target')
    ap.add_argument('--json', default='')
    ap.add_argument('--min-entries', type=int, default=2)
    a = ap.parse_args()
    d = open(a.target, 'rb').read()
    if d[:4] != b'\x7fELF':
        print('[!] 不是 ELF（先 python scripts/payload.py 剥载体）')
        return 2
    elf = Elf(d)
    tables, rel = scan_tables(elf, d, a.min_entries)
    attach_symbols(elf, d, tables)
    r = dict(path=os.path.abspath(a.target), size=len(d), tables=tables,
             relocs_applied=len(rel))
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
