#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only; capstone optional), file: rank.py
# purpose: **候选函数排序** —— 从几百个函数里挑"最可能是卡密/授权/解密"的那几个。
#   一个大型 .so 里函数动辄上千，逐个看图是浪费；先按可解释的分数排个序，
#   只精读前 10 个。学自 native_target_ranker 的思路，但判据按我们的经验重写：
#     · 名字特征（verify/auth/licen/card/vip/check/expire/crypt/sign/jni…）
#     · 是否出现在 JNI 动态注册表（那些就是 Java 能直接调到的 native 实现）
#     · 被调用次数（bl 目标统计：被多处调的通常是"公共判定"，不是死代码）
#     · 大小落区间（几十字节多为桩/thunk；>100B 才有逻辑）
#     · 引用了哪些字符串（verify 失败文案 / 错误码 / 路径）
# usage:
#   python rank.py <lib.so|载荷> [--top 15] [--json r.json]
#   python rank.py <lib.so> --with-jni            # 额外把 JNI 注册的方法标出来
# 纪律: 分数只是"先看哪个"的顺序，不是结论；每条都给理由（可反驳）。

import sys, os, re, json, struct, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from elfprobe import Elf

# 名字特征（分组加权）
NAME_HINTS = [
    (3.0, ('verify', 'auth', 'licen', 'card', 'kami', 'activ', 'expire', 'vip', 'premium', 'unlock')),
    (2.0, ('check', 'valid', 'login', 'token', 'sign', 'crypt', 'decrypt', 'encrypt', 'aes', 'rc4', 'xor')),
    (1.5, ('jni', 'native', 'onload', 'register', 'init', 'main')),
    (1.0, ('get', 'set', 'is', 'has')),
]
PENALTY = ('stub', 'thunk', 'dummy', 'unused', '_cold', 'operator', '~')

STR_HINTS = [('卡密', 3), ('授权', 3), ('验证', 2), ('到期', 2), ('失败', 1), ('错误', 1),
             ('verify', 2), ('license', 3), ('expire', 2), ('invalid', 2), ('ok', 0.5)]


def symtab_funcs(elf, d):
    """返回 ([(name, vaddr, size)], 来源)。优先 .symtab，strip 过的退回 .dynsym（只剩导出函数）。"""
    for want in ('.symtab', '.dynsym'):
        rows = _read_symtab(elf, d, want)
        if rows:
            return rows, want
    return [], ''


def _read_symtab(elf, d, secname):
    out = []
    for s in elf.sections:
        if s['name'] == secname and s['size']:
            ent = 24 if elf.cls == 2 else 16
            strtab = elf.section('.strtab' if secname == '.symtab' else '.dynstr')
            if not strtab:
                continue
            for i in range(s['size'] // ent):
                o = s['off'] + i * ent
                if o + ent > len(d):
                    break
                if elf.cls == 2:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', d, o)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from('<IIIBBH', d, o)
                info_type = st_info & 0xF
                if not st_name or info_type != 2 or st_shndx == 0:      # STT_FUNC 且已定义
                    continue
                so = strtab['off'] + st_name
                e = d.find(b'\0', so)
                if e <= so:
                    continue
                out.append((d[so:e].decode('latin1', 'replace'), st_value, st_size))
    return out


def bl_targets(d, elf):
    """扫可执行段，统计 bl 目标（被调次数）"""
    from collections import Counter
    cnt = Counter()
    for p in elf.phdrs:
        if p['type'] != 1 or not (p['flags'] & 1) or not p['filesz']:
            continue
        off, va, sz = p['off'], p['vaddr'], min(p['filesz'], len(d) - p['off'])
        n = sz // 4
        for i in range(n):
            w = struct.unpack_from('<I', d, off + i * 4)[0]
            if (w & 0xFC000000) == 0x94000000:          # BL imm26
                imm = w & 0x03FFFFFF
                if imm & (1 << 25):
                    imm -= (1 << 26)
                tgt = va + i * 4 + imm * 4
                cnt[tgt] += 1
    return cnt


def jni_map(d, elf):
    """JNI 动态注册表：{地址: java方法名}"""
    out = {}
    try:
        import jniprobe
        tables, _ = jniprobe.scan_tables(elf, d)
        for t in tables:
            for e in t['entries']:
                out[e['vaddr']] = e['name']
    except Exception:
        pass
    return out


def strings_of(elf, d, lo, hi, minlen=4):
    out = []
    for p in elf.phdrs:
        if p['type'] != 1 or not p['filesz']:
            continue
        a = p['off']
        b = min(p['off'] + p['filesz'], len(d))
        if b <= a:
            continue
        for m in re.finditer(rb'[\x20-\x7e]{4,}', d[a:b]):
            pass
    return out


def score_func(name, size, calls, is_jni):
    sc, why = 0.0, []
    low = name.lower()
    for w, kws in NAME_HINTS:
        hit = [k for k in kws if k in low]
        if hit:
            sc += w
            why.append('名字命中 %s(+%.1f)' % (','.join(hit[:3]), w))
            break
    if any(p in low for p in PENALTY):
        sc -= 1.0
        why.append('名字像桩/编译器产物(-1)')
    if is_jni:
        sc += 3.0
        why.append('JNI 注册过(+3，Java 能直接调)')
    if 100 <= size <= 20000:
        sc += 1.0
        why.append('大小 %dB 落在"有逻辑"区间(+1)' % size)
    elif size and size < 40:
        sc -= 0.5
        why.append('只有 %dB，多半是桩(-0.5)' % size)
    if calls >= 3:
        sc += min(2.0, 0.5 * calls)
        why.append('被调用 %d 次(+%.1f)' % (calls, min(2.0, 0.5 * calls)))
    return round(sc, 2), why


def run(path, top=15, with_jni=True):
    d = open(path, 'rb').read()
    if d[:4] != b'\x7fELF':
        return dict(path=os.path.abspath(path), error='不是 ELF')
    elf = Elf(d)
    funcs, sym_src = symtab_funcs(elf, d)
    jm = jni_map(d, elf) if with_jni else {}
    calls = bl_targets(d, elf)
    rows = []
    for (name, va, size) in funcs:
        is_jni = va in jm
        sc, why = score_func(name, size, calls.get(va, 0), is_jni)
        rows.append(dict(name=name, vaddr=va, size=size, calls=calls.get(va, 0),
                         jni=jm.get(va), score=sc, why=why))
    # 无符号时：用 JNI 表 + 被调用次数推
    if not rows:
        for va, jname in jm.items():
            sc, why = 3.0, ['JNI 注册：%s（符号表被剥了，这是唯一确定入口）' % jname]
            c = calls.get(va, 0)
            if c:
                sc += min(2.0, 0.5 * c)
                why.append('被调用 %d 次' % c)
            rows.append(dict(name='sub_%X' % va, vaddr=va, size=0, calls=c, jni=jname, score=round(sc, 2), why=why))
        if not rows:
            return dict(path=os.path.abspath(path), error='既没有 symtab 也没有 JNI 表：'
                        '先跑 jniprobe/elfprobe，无符号时改用 rkprobe 打桩点 + 引用密度定位')
    rows.sort(key=lambda x: -x['score'])
    return dict(path=os.path.abspath(path), has_symtab=bool(funcs), sym_src=sym_src, jni_count=len(jm),
                total_funcs=len(funcs), top=rows[:top])


def human(r):
    if r.get('error'):
        return '[!] %s' % r['error']
    L = ['== 候选函数排序  %s' % os.path.basename(r['path']),
         '   符号来源: %-8s 函数总数: %d   JNI 注册: %d' % (r.get('sym_src') or '无', r['total_funcs'], r['jni_count'])]
    if r.get('sym_src') == '.dynsym':
        L.append('   ⚠ 只有 .dynsym（strip 过）：排序只覆盖**导出函数**；内部逻辑函数看不到，需 rkprobe/引用密度补')
    elif not r['has_symtab']:
        L.append('   ⚠ 无符号表：只能靠 JNI 注册表 + 调用次数排序（尺寸/名字判据失效）')
    L.append('')
    for i, x in enumerate(r['top'], 1):
        tag = ('  [JNI:%s]' % x['jni']) if x.get('jni') else ''
        L.append('   %2d. score=%5.2f  %-34s %#010x  %dB  calls=%d%s' % (
            i, x['score'], x['name'][:34], x['vaddr'], x['size'], x['calls'], tag))
        L.append('       %s' % '；'.join(x['why']))
    L.append('')
    L.append('   >> 用法：只精读前 3~5 个；用 `rkprobe.py` 看它们有没有跳板（加密），'
             '用 `jniprobe.py` 确认 JNI 映射，用 `verify.py` 把你的判断落成 claim 回判。')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='候选函数排序（先看哪个）')
    ap.add_argument('target')
    ap.add_argument('--top', type=int, default=15)
    ap.add_argument('--no-jni', action='store_true')
    ap.add_argument('--json', default='')
    a = ap.parse_args()
    r = run(a.target, a.top, not a.no_jni)
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0 if not r.get('error') else 1


if __name__ == '__main__':
    sys.exit(main())
