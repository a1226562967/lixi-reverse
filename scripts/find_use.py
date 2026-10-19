# -*- coding: utf-8 -*-
# language: Python 3, file: find_use.py — 找出「谁引用了某个方法/字段」并反汇编调用点周边
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexlib import Dex


def find_method_idx(dex, sub):
    out = []
    for i in range(dex.method_ids_size):
        try:
            s = dex.method(i)
        except Exception:
            continue
        if sub in s:
            out.append((i, s))
    return out


def find_field_idx(dex, sub):
    out = []
    for i in range(dex.field_ids_size):
        try:
            s = dex.field(i)
        except Exception:
            continue
        if sub in s:
            out.append((i, s))
    return out


def scan_users(dex, midx_set, fidx_set, limit=40):
    """扫所有方法体, 找出用到这些 idx 的位置"""
    res = []
    for desc, af, cdo in dex.classes():
        for sig, flags, code in dex.methods_of(desc):
            if not code:
                continue
            d = dex.d
            try:
                regs, ins, outs, tries, dbg, n = struct.unpack_from('<HHHHII', d, code)
            except Exception:
                continue
            o = code + 16
            insns = struct.unpack_from('<%dH' % n, d, o)
            hit = []
            i = 0
            while i < n:
                u = insns[i]
                op = u & 0xFF
                from dexlib import OPS, SIZE
                nm, fmt = OPS.get(op, ('?', '10x'))
                sz = SIZE.get(fmt, 1)
                idx = None
                if fmt in ('21c', '22c'):
                    idx = insns[i + 1] if i + 1 < n else None
                elif fmt == '31c':
                    idx = (insns[i + 1] | (insns[i + 2] << 16)) if i + 2 < n else None
                elif fmt in ('35c', '3rc'):
                    idx = insns[i + 1] if i + 1 < n else None
                if idx is not None and (idx in midx_set or idx in fidx_set):
                    hit.append((i, nm, idx))
                i += sz
            if hit:
                res.append((sig, code, hit))
                if len(res) >= limit:
                    return res
    return res


if __name__ == '__main__':
    path = sys.argv[1]
    dex = Dex(path)
    sub = sys.argv[2]
    ms = find_method_idx(dex, sub)
    fs = find_field_idx(dex, sub)
    print('# 方法命中 %d:' % len(ms))
    for i, s in ms[:20]:
        print('   %d %s' % (i, s))
    print('# 字段命中 %d:' % len(fs))
    for i, s in fs[:20]:
        print('   %d %s' % (i, s))
    users = scan_users(dex, set(i for i, _ in ms), set(i for i, _ in fs))
    print('\n# 引用者 %d 个:' % len(users))
    for sig, code, hit in users:
        print('  %s' % sig)
        for off, nm, idx in hit[:6]:
            tgt = ''
            try:
                tgt = dex.method(idx) if idx in set(i for i, _ in ms) else dex.field(idx)
            except Exception:
                tgt = '?'
            print('      +0x%04x %-18s %s' % (off, nm, tgt))
