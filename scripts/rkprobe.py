#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only; capstone optional), file: rkprobe.py
# purpose: 运行时打桩点静态侦察 —— 一条命令列出"该在哪里下手"，且全部与加密算法无关。
#   五类找点判据（对应 references/11-runtime-patching.md）：
#     ① 加密跳板 thunk（br x17 模板）   → 返回值打桩点
#     ② .rela.plt 全表                   → 横切机制（alarm/ptrace/exit…）PLT 打桩点
#     ③ .bss 单例标志（2~5 处引用）       → 喂狗点
#     ④ 时间门（clock_gettime/cntvct）    → 到期判定，要数全同族分支
#     ⑤ R_AARCH64_RELATIVE → 跳板        → 虚函数/有消费者（别判死代码）
# usage:
#   python rkprobe.py <elf> [--base 0x0] [--json out.json] [--cap 0x4000000]
# 纪律: 只读，不改文件。输出的地址是静态 vaddr，运行期要加 load base（见 §六.3）。

import sys, os, re, json, struct, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from elfprobe import Elf, EM, ET

# ---- ARM64 关键编码 ----
BR_X17 = 0xD61F0220
BLR_X17 = 0xD63F0220
SVC_0 = 0xD4000001
MRS_CNTVCT = 0xD53BE040      # | (Rt)
MRS_CNTFRQ = 0xD53BE000      # | (Rt)
MOV_W0_1 = 0x52800020
MOV_W0_0 = 0x52800000
NOP = 0xD503201F
# clock_gettime  = syscall 113 (0x71): mov w8,#0x71 ; svc #0
MOV_W8_113 = 0x52800E28
CROSS_MECH = ('alarm', 'setitimer', 'ptrace', 'prctl', 'kill', 'exit', '_exit', 'abort',
              'fork', 'vfork', 'pthread_create', 'syscall', 'timer_create', 'timer_settime',
              'signal', 'sigaction', 'raise', 'dlopen', 'dl_iterate_phdr', 'gettimeofday',
              'clock_gettime', 'time', 'open', 'read', 'fopen', 'fstat', 'stat')


def u32(d, off):
    return struct.unpack_from('<I', d, off)[0]


def adrp_target(w, pc):
    """ADRP: 0x90000000 mask 0x9F000000；返回目标页基址"""
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    page = (pc & ~0xFFF) + (imm << 12)
    return page, (w & 0x1F)


def add_imm(w):
    """ADD (imm): 0x91xxxxxx；返回 (Rn, Rd, imm)"""
    if (w & 0xFF800000) != 0x91000000:
        return None
    imm = (w >> 10) & 0xFFF
    sh = (w >> 22) & 1
    if sh:
        imm <<= 12
    return (w >> 5) & 0x1F, w & 0x1F, imm


def ldst_imm(w):
    """LDR/STR (unsigned offset) 64/32-bit：返回 (Rn, Rt, imm, is_store, size)"""
    if (w & 0x3B000000) != 0x39000000:
        return None
    size = (w >> 30) & 3
    is_store = bool((w >> 22) & 1)
    imm = ((w >> 10) & 0xFFF) << size
    return (w >> 5) & 0x1F, w & 0x1F, imm, is_store, size


# ---------- ① thunk 识别 ----------
THUNK_WIN = 24


def find_thunks(d, segs, out):
    """所有 br x17 处，前 24 条内出现 adr/adrp x16 + sxtw/add + ldr x17 的，判为加密跳板"""
    hits = []
    for s in segs:
        off, va, sz = s['off'], s['vaddr'], min(s['filesz'], len(d) - s['off'])
        n = max(0, sz // 4)
        for i in range(n):
            w = u32(d, off + i * 4)
            if w != BR_X17:
                continue
            lo = max(0, i - THUNK_WIN)
            win = [u32(d, off + k * 4) for k in range(lo, i + 1)]
            has_adr16 = False
            has_sxtw = False
            has_add = False
            has_ldr17 = False
            for j, ww in enumerate(win[:-1]):
                if (ww & 0x9F000000) == 0x10000000 and ((ww >> 5) & 0x1F) == 16:
                    has_adr16 = True
                if (ww & 0xFFFFFC00) == 0x93407C00 or (ww & 0xFFFFFC00) == 0x93407CE0:
                    has_sxtw = True
                if (ww & 0xFF800000) == 0x91000000:
                    has_add = True
                if (ww & 0xFFC00000) == 0xF9400000 and ((ww >> 5) & 0x1F) == 16:
                    has_ldr17 = True
            score = sum([has_adr16, has_sxtw, has_add, has_ldr17])
            if score >= 3:
                # 模板起点：往前找 sub sp,sp,#0x10 (0xD10043FF)；找不到就取 br-0x50
                start = va + i * 4
                for k in range(i, max(-1, i - 24), -1):
                    ww = u32(d, off + k * 4)
                    if ww == 0xD10043FF:
                        start = va + k * 4
                        break
                else:
                    start = va + max(0, i - 20) * 4
                hits.append(dict(vaddr=va + i * 4, start=start, file_off=off + i * 4, score=score,
                                 prev8=[u32(d, off + (i - k) * 4) for k in (2, 1)] if i >= 2 else []))
    out['thunks'] = hits
    return hits


# ---------- ② .rela.plt ----------
def rela_plt(elf):
    plt = elf.section('.rela.plt')
    dynsym = elf.section('.dynsym')
    dynstr = elf.section('.dynstr')
    if not plt or not dynstr:
        return []
    ent = 24
    rows = []
    for i in range(plt['size'] // ent):
        o = plt['off'] + i * ent
        if o + ent > len(elf.d):
            break
        r_off, r_info, r_add = struct.unpack_from('<QQq', elf.d, o)
        sym = r_info >> 32
        typ = r_info & 0xFFFFFFFF
        name = ''
        if dynsym and sym:
            so = dynsym['off'] + sym * 24
            if so + 8 <= len(elf.d):
                st_name = struct.unpack_from('<I', elf.d, so)[0]
                p = dynstr['off'] + st_name
                e = elf.d.find(b'\0', p)
                if 0 < p < len(elf.d) and e > p:
                    name = elf.d[p:e].decode('latin1', 'replace')
        rows.append(dict(idx=i, got=r_off, type=typ, sym=name))
    return rows


# ---------- ③ .bss 单例标志 ----------
def bss_flags(elf, segs, max_refs=8, min_refs=2):
    bss = elf.section('.bss')
    rws = []
    if bss and bss['size']:
        rws.append(dict(vaddr=bss['addr'], size=bss['size']))
    else:
        for p in elf.load_segments():
            if (p['flags'] & 2) and p['memsz'] > p['filesz']:
                rws.append(dict(vaddr=p['vaddr'] + p['filesz'], size=p['memsz'] - p['filesz']))
    if not rws:
        return []
    def in_rw(v):
        for r in rws:
            if r['vaddr'] <= v < r['vaddr'] + r['size']:
                return True
        return False
    refs = {}
    for s in segs:
        off, va, sz = s['off'], s['vaddr'], min(s['filesz'], len(elf.d) - s['off'])
        n = max(0, sz // 4)
        last_adrp = None
        for i in range(n):
            w = u32(elf.d, off + i * 4)
            pc = va + i * 4
            t = adrp_target(w, pc)
            if t:
                last_adrp = t
                continue
            # ADRP + LDR/STR imm 直接拿到目标地址
            l = ldst_imm(w)
            if l and last_adrp:
                rn, rt, imm, is_store, size = l
                if rn == last_adrp[1]:
                    tgt = last_adrp[0] + imm
                    if in_rw(tgt) and size == 2:
                        e = refs.setdefault(tgt, dict(vaddr=tgt, reads=0, writes=0, sites=[]))
                        if is_store:
                            e['writes'] += 1
                        else:
                            e['reads'] += 1
                        if len(e['sites']) < 6:
                            e['sites'].append(dict(vaddr=pc, kind='W' if is_store else 'R'))
                continue
            # ADRP + ADD then LDR/STR [Xn]: 两段式，近似用寄存器跟踪（只跟一层）
            a = add_imm(w)
            if a and last_adrp and a[0] == last_adrp[1]:
                pass  # 记下基址寄存器变化，下一轮 ldst 用 imm 判定时不做精确追踪（保守略过）
    res = [v for v in refs.values() if min_refs <= (v['reads'] + v['writes']) <= max_refs and v['writes'] >= 1]
    res.sort(key=lambda x: x['reads'] + x['writes'])
    return res


# ---------- ④ 时间门 ----------
def time_gates(d, segs, out):
    hits = []
    for s in segs:
        off, va, sz = s['off'], s['vaddr'], min(s['filesz'], len(d) - s['off'])
        n = max(0, sz // 4)
        for i in range(n):
            w = u32(d, off + i * 4)
            pc = va + i * 4
            if w == MRS_CNTVCT or (w & 0xFFFFFC1F) == MRS_CNTVCT:
                hits.append(dict(vaddr=pc, kind='cntvct_el0(单调计时/防回拨)'))
            elif (w & 0xFFFFFC1F) == MRS_CNTFRQ:
                hits.append(dict(vaddr=pc, kind='cntfrq_el0(计时频率)'))
            elif w == MOV_W8_113:
                nxt = u32(d, off + (i + 1) * 4) if (i + 1) < n else 0
                if nxt == SVC_0:
                    hits.append(dict(vaddr=pc, kind='clock_gettime(113) 直接系统调用'))
            elif w == SVC_0 and i >= 2:
                prev = [u32(d, off + (i - k) * 4) for k in (1, 2)]
                hits.append(dict(vaddr=pc, kind='svc #0 (附近 syscall 号见 prev=%s)' % [hex(x) for x in prev]))
    out['time_gates'] = hits
    return hits


# ---------- ⑤ RELATIVE -> 跳板 ----------
def relative_to_thunks(elf, thunks):
    rel = elf.section('.rela.dyn')
    if not rel:
        return []
    spans = [(h.get('start', h['vaddr']), h['vaddr'] + 4, h['vaddr']) for h in thunks]
    rows = []
    for i in range(rel['size'] // 24):
        o = rel['off'] + i * 24
        if o + 24 > len(elf.d):
            break
        r_off, r_info, r_add = struct.unpack_from('<QQq', elf.d, o)
        typ = r_info & 0xFFFFFFFF
        if typ == 1027:      # R_AARCH64_RELATIVE
            for lo, hi, br in spans:
                if lo <= r_add < hi:
                    rows.append(dict(slot=r_off, target=r_add, thunk_br=br))
                    break
    return rows


def human(r):
    L = []
    L.append('== %s  (%d B)' % (r['path'], r['size']))
    L.append('   ELF %s %s entry=%s' % (r['elf']['class'], r['elf']['machine'], r['elf']['entry']))
    t = r['thunks']
    L.append('\n[1] 加密跳板 thunk: %d 处（br x17 模板）' % len(t))
    if t:
        by_score = {}
        for h in t:
            by_score[h['score']] = by_score.get(h['score'], 0) + 1
        L.append('    模板匹配度分布: %s   （score 4=全中最高置信；密文区(ent>7.5)的行是随机噪声，跳过）' % by_score)
        for h in t[:24]:
            L.append('    %#010x  score=%d  %s' % (h['vaddr'], h['score'], h.get('region', '')))
        L.append('    => 建议形态 A：`mov w0,#imm; ret`（8 字节等长覆盖 br 处）')
        L.append('       先读调用者：cbz w0,<成功> => 0 成功；cbnz w0,<成功> => 1 成功')
    p = r['plt']
    mech = [x for x in p if x['sym'] in CROSS_MECH]
    L.append('\n[2] .rela.plt: %d 条，横切机制 %d 条' % (len(p), len(mech)))
    for x in mech[:24]:
        L.append('    slot[%d] GOT=%#x  %s' % (x['idx'], x['got'], x['sym']))
    if mech:
        L.append('    => 建议形态 D：PLT 桩改成 `mov w0,#0; ret`（一次覆盖全程序调用者）')
    b = r['bss']
    L.append('\n[3] .bss 单例标志（2~8 处引用且有写）: %d 个' % len(b))
    for x in b[:16]:
        L.append('    %#010x  reads=%d writes=%d sites=%s' % (
            x['vaddr'], x['reads'], x['writes'], ', '.join('%#x:%s' % (s['vaddr'], s['kind']) for s in x['sites'][:4])))
    if b:
        L.append('    => 喂狗候选：不改检测代码，从外部按 < 检测周期 写回 0（见 references/11 §五）')
    g = r['time_gates']
    L.append('\n[4] 时间门: %d 处' % len(g))
    kinds = {}
    for x in g:
        kinds[x['kind'].split('(')[0]] = kinds.get(x['kind'].split('(')[0], 0) + 1
    L.append('    类型分布: %s' % kinds)
    for x in g[:14]:
        L.append('    %#010x  %s' % (x['vaddr'], x['kind']))
    if g:
        L.append('    => 三种写法常同时存在：三条并列只打一条 = 另外两条照样杀你')
    v = r['relative']
    L.append('\n[5] R_AARCH64_RELATIVE -> 跳板: %d 条（虚函数/回调，有消费者）' % len(v))
    for x in v[:12]:
        L.append('    slot %#x -> %#x' % (x['slot'], x['target']))
    if v:
        L.append('    => 全量 bl 扫不到调用点是正常的：虚调用不产生 bl')
    return '\n'.join(L)


def scan(d, cap=None, path=''):
    """供 autotriage 复用的核心：返回五类打桩点（不打印）。"""
    elf = Elf(d)
    segs = [p for p in elf.phdrs if p['type'] == 1 and (p['flags'] & 1) and p['filesz']]
    if cap:
        segs = [dict(p, filesz=min(p['filesz'], cap)) for p in segs]
    r = dict(path=os.path.abspath(path) if path else '', size=len(d),
             elf=dict(**{'class': {1: 'ELF32', 2: 'ELF64'}.get(elf.cls), 'machine': EM.get(elf.machine),
                         'entry': hex(elf.entry)}))
    out = {}
    find_thunks(d, segs, out)
    r['thunks'] = out['thunks']
    r['plt'] = rela_plt(elf)
    plts = elf.section('.plt')
    if plts:
        for x in r['plt']:
            x['stub'] = plts['addr'] + (x['idx'] + 2) * 16   # .plt[0]/[1] 是保留(resolver)，真桩从 +2 起
    # 区域标注：逐 thunk 取 ±2KB 的局部熵 —— 同一 LOAD 段里既有密文又有明文时段级熵无效
    import math
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
        return e
    for h in r['thunks']:
        fo = h['file_off']
        blk = d[max(0, fo - 0x800):fo + 0x800]
        e = round(entropy(blk), 2)
        h['local_entropy'] = e
        h['suspect_cipher'] = e > 7.5
        h['region'] = ('CIPHER?(ent=%s)' % e) if e > 7.5 else ('TEXT(ent=%s)' % e)
    # 明文区优先，再按 score 降序、地址升序
    r['thunks'].sort(key=lambda h: (h['suspect_cipher'], -h['score'], h['vaddr']))
    r['bss'] = bss_flags(elf, segs)
    time_gates(d, segs, out)
    r['time_gates'] = [x for x in out['time_gates'] if 'svc #0 (附近' not in x['kind']]
    r['relative'] = relative_to_thunks(elf, r['thunks'])
    return r


def main():
    ap = argparse.ArgumentParser(description='运行时打桩点静态侦察（五类判据）')
    ap.add_argument('target')
    ap.add_argument('--json', default='')
    ap.add_argument('--cap', default='', help='只扫可执行段前 N 字节（大文件用，如 0x4000000）')
    a = ap.parse_args()
    d = open(a.target, 'rb').read()
    if d[:4] != b'\x7fELF':
        print('[!] 不是 ELF：先 python scripts/payload.py <file> --dump 剥载体')
        return 2
    elf = Elf(d)
    segs = [p for p in elf.phdrs if p['type'] == 1 and (p['flags'] & 1) and p['filesz']]
    if a.cap:
        lim = int(a.cap, 0)
        segs = [dict(p, filesz=min(p['filesz'], lim)) for p in segs]
    r = scan(d, int(a.cap, 0) if a.cap else None, a.target)
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
