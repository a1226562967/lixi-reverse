#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: verify.py
# purpose: **断言裁决层** —— 让确定性工具当裁判，把"AI 说的"变成 VERIFIED / REFUTED / INCONCLUSIVE。
#   学自 reverify 的做法，并针对本技能的判据重写：
#     · 每条 claim 都有 kind，全部用现有工具（dexlib/elfprobe/rkprobe/jniprobe…）回判；
#     · 每条裁决带 **weight（信息量）** —— 证明"文件以 ELF 开头""到处都是的模板"这种废话权重≈0，
#       避免"全部 verified 但其实什么也没说"；
#     · 裁决落 ledger（按 sha256 内容寻址）：verified 复用、refuted 变 **KNOWN FALSE**（负面记忆，
#       下次不再重复提同一个错假设）；
#     · `--min-information` 是 grounded 门槛：没被反驳 **且** 信息量够，才算"这条结论站得住"。
# usage:
#   python verify.py <目标> --claim '{"kind":"bytes_at","offset":"0x5b","expect":"38 00"}'
#   python verify.py <目标> --claims-file claims.json [--min-information 1.0] [--json out.json]
#   python verify.py <目标> --ledger                  # 看这份样本已经确立/已证伪了什么
# 纪律: 工具不支持/缺参数 ⇒ INCONCLUSIVE（不是 VERIFIED，也不是 REFUTED）；永不把"没检查"记成通过。

import sys, os, re, json, hashlib, argparse, struct

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

VERIFIED, REFUTED, INCONCLUSIVE, OBSERVED = 'VERIFIED', 'REFUTED', 'INCONCLUSIVE', 'OBSERVED'


def hb(s):
    return bytes.fromhex(str(s).replace(' ', '').replace('0x', ''))


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def occ_count(d, needle, cap=200):
    """期望内容在文件里出现多少次（用于 weight 衰减：到处都是 = 信息量低）"""
    if not needle:
        return 0
    n, i = 0, 0
    while n < cap:
        i = d.find(needle, i)
        if i < 0:
            break
        n += 1
        i += 1
    return n


def entropy(b):
    import math
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


# ---------------- 各 kind 的裁决器 ----------------
def k_bytes_at(d, c):
    off = int(str(c.get('offset', '0')), 0)
    exp = hb(c.get('expect', ''))
    space = c.get('space', 'off')
    if space != 'off':
        return INCONCLUSIVE, 'bytes_at 目前只支持文件偏移（space=off）', 0.0
    if not exp:
        return INCONCLUSIVE, '缺 expect', 0.0
    cur = d[off:off + len(exp)]
    if cur == exp:
        # 独特性看**上下文窗口**：只看被断言的 2 字节（如 '38 00'）当然到处都是，
        # 真正有信息量的是"这两字节在这个上下文里"。窗口 = [off-8, off+len+8)
        lo = max(0, off - 8)
        hi = min(len(d), off + len(exp) + 8)
        ctx = d[lo:hi]
        w = 0.05 if all(b in (0, 0xFF) for b in exp) else 1.0
        n_ctx = occ_count(d, ctx)
        n_exp = occ_count(d, exp)
        if n_ctx > 4:
            w *= max(0.08, 4.0 / n_ctx)
        elif n_exp > 50:
            w *= 0.5       # 窗口独特但字节太常见：折半，不算废话也不算强证据
        return VERIFIED, 'bytes_at %#x = %s（上下文窗口出现 %d 次 / 该字节对出现 %d 次）' % (
            off, exp.hex(' '), n_ctx, n_exp), round(w, 3)
    # 反驳时告诉它真实值，方便纠正
    where = d.find(exp)
    extra = ('；期望字节实际出现在 %#x' % where) if where >= 0 else ''
    return REFUTED, 'bytes_at %#x 期望 %s，实际 %s%s' % (off, exp.hex(' '), cur.hex(' '), extra), 0.0


def k_u32(d, c, size=4):
    off = int(str(c.get('offset', '0')), 0)
    exp = c.get('expect')
    if exp is None:
        v = struct.unpack_from('<I' if size == 4 else '<Q', d, off)[0]
        return OBSERVED, 'u%d_at %#x = %#x' % (size * 8, off, v), 1.0
    v = struct.unpack_from('<I' if size == 4 else '<Q', d, off)[0]
    want = int(str(exp), 0)
    if v == want:
        w = 0.2 if want in (0, 0xFFFFFFFF) else 1.0
        return VERIFIED, 'u%d_at %#x = %#x（期望一致）' % (size * 8, off, v), w
    return REFUTED, 'u%d_at %#x 期望 %#x，实际 %#x' % (size * 8, off, want, v), 0.0


def k_pattern(d, c):
    pat = str(c.get('pattern', ''))
    if not pat:
        return INCONCLUSIVE, '缺 pattern', 0.0
    # 支持 ?? 通配
    rx = b''.join([b'.' if x in ('??', '?') else re.escape(hb(x)) for x in pat.split()]) if '?' in pat else hb(pat)
    m = re.search(rx, d, re.S) if isinstance(rx, bytes) else None
    if m:
        n = 0
        i = 0
        while n < 200:
            j = d.find(m.group(0), i)
            if j < 0:
                break
            n += 1
            i = j + 1
        w = 1.0 if n <= 4 else max(0.05, 4.0 / n)
        return VERIFIED, 'pattern 命中 @%#x（共 %d 处）' % (m.start(), n), round(w, 3)
    return REFUTED, 'pattern 0 命中（0 命中先怀疑取址/端序，再怀疑目标）', 0.0


def k_string(d, c):
    s = str(c.get('string', ''))
    if not s:
        return INCONCLUSIVE, '缺 string', 0.0
    variants = [s.encode('utf-8'), s.encode('utf-16le')]
    found, enc = None, None
    for v in variants:
        i = d.find(v)
        if i >= 0:
            found, enc = i, ('utf-8' if v is variants[0] else 'utf-16le')
            break
    if found is None:
        return REFUTED, '字符串未命中（utf-8/utf-16le 都试过）⇒ 若提示语确实在运行时出现，说明它是服务端下发的', 0.0
    v = variants[0] if enc == 'utf-8' else variants[1]
    n = occ_count(d, v)
    w = 1.0 if n <= 4 else max(0.05, 4.0 / n)
    return VERIFIED, '字符串命中 @%#x (%s)，全文件 %d 处' % (found, enc, n), round(w, 3)


def k_elf_section(d, c):
    try:
        from elfprobe import Elf
        elf = Elf(d)
    except Exception as e:
        return INCONCLUSIVE, 'ELF 解析失败：%r' % e, 0.0
    name = c.get('name', '')
    sec = elf.section(name)
    if sec:
        return VERIFIED, 'section %s 存在（size=%d @%#x）' % (name, sec['size'], sec.get('off', 0)), 1.0
    return REFUTED, 'section %s 不存在（e_shnum=%d）' % (name, elf.shnum), 0.0


def k_segment(d, c):
    try:
        from elfprobe import Elf
        elf = Elf(d)
    except Exception as e:
        return INCONCLUSIVE, 'ELF 解析失败：%r' % e, 0.0
    lo = int(str(c.get('vaddr', '0')), 0)
    hi = int(str(c.get('end', '0')), 0) or (lo + 1)
    seg = None
    for p in elf.load_segments():
        if p['vaddr'] <= lo < p['vaddr'] + max(p['filesz'], p['memsz']):
            seg = p
            break
    if not seg:
        return REFUTED, '%#x 不落在任何 PT_LOAD 内' % lo, 0.0
    off = seg['off'] + (lo - seg['vaddr'])
    blk = d[off:off + max(1, min(hi - lo, 1 << 20))]
    e = entropy(blk)
    sexp = c.get('expect_entropy')
    if sexp is None:
        return OBSERVED, '段 %#x 起始 %d 字节熵=%s（filesz=%d flags=%d）' % (lo, len(blk), e, seg['filesz'], seg['flags']), 1.0
    want_hi = float(sexp) if not isinstance(sexp, (list, tuple)) else float(sexp[1])
    want_lo = float(sexp[0]) if isinstance(sexp, (list, tuple)) else 0.0
    if want_lo <= e <= want_hi:
        return VERIFIED, '熵=%s 落在期望 [%s, %s]' % (e, want_lo, want_hi), 1.0
    return REFUTED, '熵=%s 不在期望 [%s, %s]（熵只分明文/非明文，别当算法结论）' % (e, want_lo, want_hi), 0.0


def k_dex_method(d, c):
    """断言"某方法在某偏移有某指令序列" —— 用 dexlib 反汇编回判（补丁点必过这一关）"""
    path = c.get('path')
    if not path or not os.path.exists(path):
        return INCONCLUSIVE, '需要 path 指向 dex 文件（claim 里给 "path"）', 0.0
    try:
        from dexlib import Dex
    except Exception as e:
        return INCONCLUSIVE, 'dexlib 不可用：%r' % e, 0.0
    m = c.get('method', '')
    want = hb(c.get('expect', ''))
    if not m or not want:
        return INCONCLUSIVE, '缺 method/expect', 0.0
    try:
        dx = Dex(path)
    except Exception as e:
        return INCONCLUSIVE, 'dex 打开失败：%r' % e, 0.0
    for mm in dx.methods_of_class(c.get('class', '')) if c.get('class') else []:
        pass
    # 直接扫：用 dexql 的能力更省事，但这里保持零依赖 -> 用 Dex.disasm 需要 code_off，改由调用方给
    off = c.get('code_off')
    if not off:
        return INCONCLUSIVE, 'dex_method 需要 code_off（dexql --method 会打印它）', 0.0
    code_off = int(str(off), 0)
    try:
        lines, _ = dx.disasm(code_off)
        blob = ' | '.join(lines)
    except Exception as e:
        return INCONCLUSIVE, '反汇编失败：%r' % e, 0.0
    cu = int(str(c.get('cu', '0')), 0)
    fo = code_off + 16 + cu * 2
    cur = open(path, 'rb').read()[fo:fo + len(want)] if want else b''
    if cur == want:
        return VERIFIED, 'code_off=%#x cu=%#x 处字节 = %s（与断言一致）' % (code_off, cu, cur.hex(' ')), 1.0
    return REFUTED, 'code_off=%#x cu=%#x 实际 %s ≠ 期望 %s' % (code_off, cu, cur.hex(' '), want.hex(' ')), 0.0


def k_jni(d, c):
    try:
        import jniprobe
        from elfprobe import Elf
        elf = Elf(d)
        tables, _ = jniprobe.scan_tables(elf, d)
    except Exception as e:
        return INCONCLUSIVE, 'jniprobe 失败：%r' % e, 0.0
    names = [e['name'] for t in tables for e in t['entries']]
    want = c.get('name')
    if not want:
        return OBSERVED, 'JNI 动态注册方法 %d 个：%s' % (len(names), ', '.join(names[:8])), 1.0 if names else 0.0
    if want in names:
        return VERIFIED, 'JNI 方法 %r 已注册（共 %d 个）' % (want, len(names)), 1.0
    return REFUTED, 'JNI 方法 %r 不在注册表里（现有 %d 个：%s）' % (want, len(names), ', '.join(names[:6])), 0.0


def k_thunk(d, c):
    try:
        import rkprobe
        from elfprobe import Elf
        elf = Elf(d)
        segs = [p for p in elf.phdrs if p['type'] == 1 and (p['flags'] & 1) and p['filesz']]
        out = {}
        rkprobe.find_thunks(d, segs, out)
    except Exception as e:
        return INCONCLUSIVE, 'rkprobe 失败：%r' % e, 0.0
    vas = {h['vaddr'] for h in out.get('thunks', [])}
    want = int(str(c.get('vaddr', '0')), 0)
    if want in vas:
        return VERIFIED, '%#x 是加密跳板（br x17 模板，共 %d 处）' % (want, len(vas)), 1.0
    return REFUTED, '%#x 不是跳板（已找到 %d 处：%s）' % (want, len(vas), ', '.join(hex(x) for x in sorted(vas)[:6])), 0.0



def k_prologue(d, c):
    """函数序言判据：AArch64 函数入口必然是 `sub sp,sp,#imm` / `stp x29,x30,[sp,#-imm]!` / `bti`。
    定位到某个 vaddr 准备打补丁时**必过这一关** —— 目标偏移上不是这几类指令，就说明 vaddr→file 算错了，
    或那根本不是函数入口（打在函数中间会闪退）。"""
    try:
        from elfprobe import Elf
        elf = Elf(d)
    except Exception as e:
        return INCONCLUSIVE, 'ELF 解析失败：%r' % e, 0.0
    v = int(str(c.get('vaddr', '0')), 0)
    off = None
    for p in elf.load_segments():
        if p['vaddr'] <= v < p['vaddr'] + p['filesz']:
            off = p['off'] + (v - p['vaddr'])
            break
    if off is None or off + 4 > len(d):
        return REFUTED, '%#x 不在任何 PT_LOAD 的可读区间内（vaddr 算错了？）' % v, 0.0
    w = struct.unpack_from('<I', d, off)[0]
    kind = None
    if (w & 0xFF800000) == 0xD1000000 and ((w >> 5) & 0x1F) == 31:
        kind = 'sub sp,sp,#imm'
    elif (w & 0xFFC00000) == 0xA9800000:
        kind = 'stp xN,xM,[sp,#-imm]!'
    elif w in (0xD503245F, 0xD503249F, 0xD50324DF, 0xD503251F):
        kind = 'bti'
    elif (w & 0xFFFF0000) == 0xD65F0000:
        kind = 'ret（这是函数尾，不是头）'
    if kind and 'ret' not in kind:
        return VERIFIED, '%#x (file %#x) 是函数序言：%s（%s）' % (v, off, kind, ('%08x' % w)), 1.0
    if kind:
        return REFUTED, '%#x (file %#x) %s —— 你打到函数末尾去了' % (v, off, kind), 0.0
    return REFUTED, ('%#x (file %#x) 首个字 = %08x，不是标准序言（sub sp/stp/bti）'
                     ' ⇒ 要么 v2o 算错，要么这不是函数入口') % (v, off, w), 0.0


HANDLERS = {
    'bytes_at': k_bytes_at,
    'u32_at': lambda d, c: k_u32(d, c, 4),
    'u64_at': lambda d, c: k_u32(d, c, 8),
    'pattern_present': k_pattern,
    'string_present': k_string,
    'section_present': k_elf_section,
    'segment_entropy': k_segment,
    'dex_code': k_dex_method,
    'jni_method': k_jni,
    'thunk_at': k_thunk,
    'prologue_at': k_prologue,
}


# ---------------- ledger（按 sha256 内容寻址） ----------------
def ledger_path(target, case_root=None):
    h = sha256_file(target)
    root = case_root or os.path.join(os.path.dirname(os.path.abspath(target)), 'cases')
    d = os.path.join(root, '.ledger')
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, h + '.json'), h


def load_ledger(p):
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding='utf-8'))
        except Exception:
            pass
    return dict(verified={}, refuted={}, weight=0.0, rounds=0)


def save_ledger(p, L):
    L['rounds'] = L.get('rounds', 0) + 1
    json.dump(L, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)


def claim_key(c):
    return json.dumps(c, sort_keys=True, ensure_ascii=False)


def ledger_text(target, case_root=None):
    p, h = ledger_path(target, case_root)
    L = load_ledger(p)
    L_ = ['== ledger  %s' % os.path.basename(target), '   sha256: %s' % h, '   rounds: %s  累计信息量: %s' % (L.get('rounds', 0), L.get('weight', 0.0))]
    if L['verified']:
        L_.append('\n[已确立 VERIFIED]  %d 条' % len(L['verified']))
        for k, v in list(L['verified'].items())[:20]:
            L_.append('   w=%.2f  %s' % (v.get('weight', 0), v.get('evidence', '')[:110]))
    if L['refuted']:
        L_.append('\n[已知为假 KNOWN FALSE]  %d 条（下次别再提同一个假设）' % len(L['refuted']))
        for k, v in list(L['refuted'].items())[:20]:
            L_.append('   %s' % v.get('evidence', '')[:120])
    if not L['verified'] and not L['refuted']:
        L_.append('   （空：还没有任何被工具裁决过的断言）')
    return '\n'.join(L_)


def run_claims(target, claims, case_root=None, min_info=1.0):
    d = open(target, 'rb').read()
    p, h = ledger_path(target, case_root)
    L = load_ledger(p)
    results = []
    total_w = 0.0
    for c in claims:
        kind = c.get('kind', '')
        key = claim_key(c)
        # 负面记忆：已知为假，直接回 REFUTED（不重复消耗工具时间，也提醒模型别老调重弹）
        if key in L['refuted']:
            results.append(dict(kind=kind, verdict=REFUTED, evidence='KNOWN FALSE（ledger 已记录）: ' + L['refuted'][key]['evidence'][:100], weight=0.0, known=True))
            continue
        if key in L['verified']:
            g = L['verified'][key]
            results.append(dict(kind=kind, verdict=VERIFIED, evidence='已在 ledger: ' + g['evidence'][:100], weight=0.0, known=True))
            continue
        fn = HANDLERS.get(kind)
        if not fn:
            results.append(dict(kind=kind, verdict=INCONCLUSIVE, evidence='不支持的 claim kind（可用：%s）' % ', '.join(sorted(HANDLERS)), weight=0.0))
            continue
        try:
            verdict, ev, w = fn(d, c)
        except Exception as e:
            verdict, ev, w = INCONCLUSIVE, '裁决器异常：%r' % e, 0.0
        w = round(float(w), 3)
        results.append(dict(kind=kind, verdict=verdict, evidence=ev, weight=w, claim=c))
        if verdict == VERIFIED:
            L['verified'][key] = dict(evidence=ev, weight=w)
            total_w += w
        elif verdict == REFUTED:
            L['refuted'][key] = dict(evidence=ev)
    L['weight'] = round(L.get('weight', 0.0) + total_w, 3)
    save_ledger(p, L)
    grounded = (not any(r['verdict'] == REFUTED for r in results)) and (total_w >= float(min_info)) and bool(results)
    return dict(target=os.path.abspath(target), sha256=h, ledger=os.path.basename(p),
                results=results, round_weight=round(total_w, 3), cumulative_weight=L['weight'],
                min_information=float(min_info), grounded=grounded)


def human(r):
    L = ['== 断言裁决  %s' % os.path.basename(r['target']), '   sha256=%s…  ledger=%s' % (r['sha256'][:16], r['ledger'])]
    icon = {VERIFIED: '[OK]', REFUTED: '[X ]', INCONCLUSIVE: '[? ]', OBSERVED: '[..]'}
    for x in r['results']:
        L.append('   %s %-18s w=%.2f  %s' % (icon.get(x['verdict'], '[? ]'), x['kind'], x['weight'], x['evidence']))
    L.append('')
    L.append('   本轮信息量 = %s（门槛 %s）  累计 = %s' % (r['round_weight'], r['min_information'], r['cumulative_weight']))
    if r['grounded']:
        L.append('   >> grounded：没有被反驳，且信息量够 —— 这条分析结论**站得住**')
    elif any(x['verdict'] == REFUTED for x in r['results']):
        L.append('   >> 不 grounded：有断言被工具反驳。**先改断言**，别基于它往下推')
    else:
        L.append('   >> 不 grounded：信息量不足（都在验证"废话"：到处都有的字节/通用模板/重复项）')
    L.append('   ⚠ 工具不支持/缺参数的项是 INCONCLUSIVE —— 不是通过，也不是失败')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='断言裁决层：让工具判定 AI 的结论（VERIFIED/REFUTED/INCONCLUSIVE）')
    ap.add_argument('target')
    ap.add_argument('--claim', default='', help='单条 claim（JSON）')
    ap.add_argument('--claims-file', default='')
    ap.add_argument('--min-information', type=float, default=0.5, help='grounded 门槛（多条 claim 会累加；单条很难到 1.0）')
    ap.add_argument('--case-root', default='')
    ap.add_argument('--ledger', action='store_true', help='只看这份样本的 ledger')
    ap.add_argument('--json', default='')
    a = ap.parse_args()
    if not os.path.exists(a.target):
        print('[!] 目标不存在：%s' % a.target)
        return 2
    if a.ledger:
        print(ledger_text(a.target, a.case_root or None))
        return 0
    claims = []
    if a.claim:
        claims.append(json.loads(a.claim))
    if a.claims_file:
        j = json.load(open(a.claims_file, encoding='utf-8'))
        claims += j if isinstance(j, list) else j.get('claims', [])
    if not claims:
        print('[!] 没给 claim。示例：\n  --claim \'{"kind":"bytes_at","offset":"0x656e1a","expect":"38 00"}\'')
        print('   支持的 kind：%s' % ', '.join(sorted(HANDLERS)))
        return 2
    r = run_claims(a.target, claims, a.case_root or None, a.min_information)
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0 if r['grounded'] else 1


if __name__ == '__main__':
    sys.exit(main())
