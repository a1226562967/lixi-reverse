#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: autoexec.py
# purpose: ★ 自动执行层 —— 技能自己会调用工具：读分诊结果 → 生成步骤 → 自动跑只读分析 →
#          把结果变成"可直接执行的补丁/打桩命令"（带原字节）→ 循环到需要人或不可逆才停。
# usage:
#   python autoexec.py <样本> [--case-root DIR] [--steps 8] [--dry-run]
# 纪律:
#   · 只自动执行**只读**步骤（判型/反汇编/扫描/剥离）。写内存、打补丁、重打包一律只生成命令不执行。
#   · 每步结果落 attempts.md；生成的命令落 analysis/AUTO_PLAN.md。
#   · 三种停点：需要用户在设备上操作 / 不可逆操作 / 缺输入（设备·有效卡·抓包）。
#   · 不许问"要不要继续"——能自动做的直接做。

import sys, os, re, json, subprocess, datetime, argparse, hashlib, struct

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import autotriage

PY = sys.executable
TS = lambda: datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def run_script(name, args, timeout=900):
    cmd = [PY, os.path.join(HERE, name)] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except Exception as e:
        return -1, repr(e)


# ---------------- 步骤生成 ----------------

# 启动词「李喜，路径，需求」里的"需求"→ 路线映射（命中即收敛，不命中就全跑）
NEED_RULES = [
    (('卡密', '授权', '验证', '登录', '激活', '注册', '破解', '绕过', '会员', '试用'),
     'authorization', '授权链：控制面闸门(dex) → 脚本面闸门(.lua) → 服务端重放'),
    (('脱壳', '解包', '明文', '壳', '加密', 'dump', '还原', '提取', '抠'),
     'unpack', '剥壳链：追加容器 → 载体剥离 → 自解密四指纹 → 运行时打桩'),
    (('服务端', '抓包', '重放', '假服务器', '网络', '协议', '心跳'),
     'server', '服务端判决面：三问 → 真响应重放 / 假服务器'),
    (('内核', '驱动', 'ko', '.ko', 'root'), 'kernel', '特权面：.ko 判型与能力面（不是授权问题）'),
    (('判型', '分析', '看看', '是什么', '识别', '查壳', '特征'), 'triage', '只判层判型 + 给下一步'),
]


def need_route(need):
    # 单一真源：scripts/routing.json（改路由只改它 + 跑 route.py --test）
    try:
        import route as _route
        r = _route.route(need or '')
        if r.get('route') == 'all' and need:
            r['label'] = '需求未命中预设（%s）→ 全层扫一遍' % need[:24]
        return r
    except Exception:
        # 兜底：json 缺失时用内置表
        if not need:
            return dict(route='all', label='未指定需求 → 全层扫一遍，按成本排序出命令')
        low = need.lower()
        for kws, route, label in NEED_RULES:
            hit = [k for k in kws if k.lower() in low]
            if hit:
                return dict(route=route, label=label, hit=hit)
        return dict(route='all', label='需求未命中预设（%s）→ 全层扫一遍' % need[:24])


def build_plan(r):
    """返回 step 列表：dict(id, why, kind, cmd(list), auto, needs, expect)"""
    steps = []
    art = r.get('artifacts_dir') or ''
    apk = r.get('apk')
    rt = r.get('runtime') or {}

    if apk:
        # 脚本层优先判：有 .lua 就是脚本壳，闸门不在 dex
        steps.append(dict(id='luaq', why='脚本层判层（assets/*.lua + org/luaj ⇒ 闸门在脚本里）',
                          kind='readonly+generate', auto=True, needs='-',
                          cmd=['luaq.py', r['sample'], '--json', os.path.join(art, 'luaq.json')]))
        gate_done = 0
        dexinfo = apk.get('dex_info') or []
        # 先按"有解码器的、最小的"排，再按 gates 数量排 —— 顺序决定先挖哪个 dex
        by_size = sorted(dexinfo, key=lambda x: x.get('size', 0))
        by_gates = sorted(dexinfo, key=lambda x: -len(x.get('gates') or []))
        ordered = []
        for x in by_size + by_gates:
            if x not in ordered:
                ordered.append(x)
        for it in ordered:
            dex = it.get('path')
            if not dex:
                continue
            # 1) 小 dex / 含解码器 → 深挖字符串与密钥（每类只做一次）
            if (it.get('size', 0) < 200000) and not any(
                    x['id'].startswith('dex-deep') for x in steps):
                steps.append(dict(id='dex-deep-%s' % it['dex'], why='小 dex 或含解码器：取密钥/字符串池/解码器形状',
                                  kind='readonly', auto=True, needs='-',
                                  cmd=['dexql.py', dex, '--strings', '--static', '--decoders', '--limit', '60']))
            # 2) 总闸门 → 反汇编 + 自动找 if-eqz 并算文件偏移与原字节（最多两个 dex、每个 4 条）
            if gate_done >= 2:
                continue
            gs = (it.get('gates') or [])[:4]
            if not gs:
                continue
            gate_done += 1
            for g in gs:
                nm = g['method'].split('->')[-1].split('(')[0]
                steps.append(dict(id='gate-%s-%s' % (it['dex'], nm), why='总闸门反汇编：找那条 if-eqz 并给出原字节',
                                  kind='readonly+generate', auto=True, needs='-', dex=dex, method=nm,
                                  cmd=['dexql.py', dex, '--method', nm, '--limit', '400']))

    # ELF / 包装层剥出来的 ELF
    elf_paths = []
    if r.get('leaf_elfs'):
        elf_paths = r['leaf_elfs'][:3]
    elif r.get('elf') and r.get('sample'):
        elf_paths = [r['sample']]
    for p in elf_paths:
        # 追加容器判定（明文 loader + 尾部加密容器）—— 与打桩点互斥，先判结构
        steps.append(dict(id='container-%s' % os.path.basename(p), why='追加容器/节表/垃圾字判定（结构先于算法）',
                          kind='readonly+generate', auto=True, needs='-',
                          cmd=['container.py', p, '--json', os.path.join(art, 'container.json')]))
        if rt.get('thunks_text'):
            steps.append(dict(id='rk-%s' % os.path.basename(p), why='五类打桩点：跳板/PLT/喂狗点/时间门/虚表',
                              kind='readonly+generate', auto=True, needs='-',
                              cmd=['rkprobe.py', p, '--json', os.path.join(art, 'rk_%s.json' % os.path.basename(p)[:20])],
                              elf=p))
            steps.append(dict(id='patchplan-%s' % os.path.basename(p), why='把打桩点变成带原字节的 pm 命令',
                              kind='generate', auto=True, needs='-', elf=p, internal=True))
            break
        elif not r.get('elf'):
            # 只有分诊阶段没拿到 ELF 形态时才补跑（否则重复扫一遍，大文件白等几十秒）
            steps.append(dict(id='elf-probe-%s' % os.path.basename(p), why='判型（兜底）',
                              kind='readonly', auto=True, needs='-',
                              cmd=['elfprobe.py', p]))

    # 有原版+破解版可比 → 提示 diff（需要第二个文件，属缺输入）
    if apk:
        steps.append(dict(id='diff-hint', why='若手上有破解版/别的版本，逐条目 diff 是性价比最高的一招',
                          kind='manual', auto=False, needs='第二个 APK 路径',
                          cmd=['diff_apk.py', r['sample'], '<破解版.apk>']))
    if r.get('kind') == 'ELF' and not rt.get('thunks_text'):
        steps.append(dict(id='deobf-hint', why='未发现跳板：可能无加密，或全文件加密(需先剥壳)',
                          kind='manual', auto=False, needs='判断是否 NOT-COMPILED(见报告)',
                          cmd=['payload.py', r['sample'], '--dump', art]))
    return steps


# ---------------- 自动生成补丁/打桩命令 ----------------
IF_RE = re.compile(r'^\s*([0-9a-f]{8})\s+(if-eqz|if-nez)\s+v(\d+),\s*->\s*([0-9a-f]{8})')
CODEOFF_RE = re.compile(r'code_off=(0x[0-9a-f]+)')


def analyze_gate_output(out, dex, method):
    """从 dexql --method 输出里抽 if-eqz，算文件偏移与原字节，生成 patch 命令。"""
    m = CODEOFF_RE.search(out)
    if not m:
        return None
    code_off = int(m.group(1), 16)
    lines = out.split('\n')
    cands = []
    for i, ln in enumerate(lines):
        mm = IF_RE.match(ln)
        if not mm:
            continue
        cu = int(mm.group(1), 16)
        fo = code_off + 16 + cu * 2
        try:
            with open(dex, 'rb') as f:
                f.seek(fo)
                raw = f.read(4)
        except Exception:
            raw = b'\x00' * 4
        # 看目标侧：往后 6 行里有没有 invoke-* 调用"启动/进主程序"类方法
        tail = '\n'.join(lines[i + 1:i + 9])
        # 收窄：只认"直接启动/进入主程序"的强特征，避免 run/open 这类词把噪声也算进来
        launchish = bool(re.search(r'(a25|TerminalActions|launchMain|startMain|gotoMain|'
                                   r'MainActivity;->\w*[Ll]aunch|MainActivity;->\w*[Ss]tart)', tail))
        errish = bool(re.search(r'(showNotice|Toast|提示|错误|失败|return\b)', tail))
        cands.append(dict(cu='%08x' % cu, fo='%#x' % fo, insn=mm.group(2), reg='v' + mm.group(3),
                          target=mm.group(4), raw=raw.hex(' '), launch=launchish,
                          guess=('目标侧是"直接启动主程序" → nop 掉这一句即落到成功路径' if launchish
                                 else ('目标侧像错误/提示路径 → 说明这一句是"成功就跳过弹框"，方向相反，慎改' if errish
                                       else '目标侧无强特征 → 先反汇编目标地址那段再定方向'))))
    cands.sort(key=lambda c: (not c['launch'], c['cu']))
    return dict(code_off='%#x' % code_off, cands=cands)


SITE_RE = re.compile(r'^\s*(0x[0-9a-f]+)\s+score=(\d+)\s+(\S+)')


def patch_plan_elf(elf_path, rkjson):
    """把 rkprobe 的打桩点变成带原字节的 pm 命令（不执行）。"""
    try:
        rk = json.load(open(rkjson, encoding='utf-8'))
    except Exception:
        return None
    data = open(elf_path, 'rb').read()
    out = []
    for h in (rk.get('thunks') or []):
        if h.get('suspect_cipher'):
            continue
        fo = h['file_off']
        raw = data[fo:fo + 8].hex()
        out.append(dict(kind='thunk-return', vaddr='%#x' % h['vaddr'], raw8=raw,
                        patch_hex='00008052c0035fd6', note='mov w0,#0; ret（成功=0 时用）',
                        alt_hex='20008052c0035fd6', alt_note='mov w0,#1; ret（成功=1 时用）'))
        if len(out) >= 12:
            break
    for x in (rk.get('plt') or []):
        if x.get('sym') in ('alarm', 'setitimer', 'ptrace', 'exit', '_exit', 'kill'):
            stub = x.get('stub')
            if stub:
                raw = data[stub - 0:stub - 0 + 8].hex() if False else ''
                out.append(dict(kind='plt', vaddr='%#x' % stub, sym=x['sym'],
                                patch_hex='00008052c0035fd6', note='mov w0,#0; ret（横切机制失效）'))
    for b in (rk.get('bss') or [])[:6]:
        out.append(dict(kind='feed-dog', vaddr='%#x' % b['vaddr'], patch_hex='00000000',
                        note='每 < 检测周期/2 写 0（示例 10s；用 PM write）'))
    return out


# ---------------- 主流程 ----------------
def main():
    ap = argparse.ArgumentParser(description='自动执行层：跑完所有只读分析并生成可执行命令')
    ap.add_argument('target')
    ap.add_argument('--case-root', default='')
    ap.add_argument('--steps', type=int, default=8)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--need', default='', help='启动词第三要素：需求（如 "绕过卡密" / "脱壳" / "判型"）')
    ap.add_argument('--timebox', type=int, default=180, help='单步超时秒数（默认 180；超时跳过并在报告标注）')
    a = ap.parse_args()

    case_root = a.case_root or os.path.join(os.path.dirname(os.path.abspath(a.target)), 'cases')
    try:
        _sz = os.path.getsize(a.target)
    except Exception:
        _sz = 0
    print('[1/4] 分诊 …（%s，%.1f MB；大文件按可执行段扫，不整文件逐字节）' % (
        os.path.basename(a.target), _sz / 1048576.0), flush=True)
    r = autotriage.triage(a.target, case_root, False)
    cd = r.get('case_dir') or os.path.join(os.path.dirname(os.path.abspath(a.target)), '_autotriage')
    art = r.get('artifacts_dir') or cd
    os.makedirs(os.path.join(cd, 'analysis'), exist_ok=True)
    attempts = os.path.join(cd, 'attempts.md')
    with open(attempts, 'a', encoding='utf-8') as f:
        f.write('\n## %s autoexec 启动\n- 样本 `%s`\n- 判层 %s\n' % (TS(), r.get('sample'), r.get('layer')))

    nr = need_route(a.need)
    r['need'] = a.need
    r['route'] = nr
    print('    需求: %r -> 路线 %s（%s）' % (a.need or '-', nr['route'], nr['label']))
    # 红线：大块高熵数据段 → 不要整程序离线模拟（这是踩过的坑：27 分钟没结果）
    _e = r.get('elf') or {}
    if any('NO-FULL-EMULATION' in t for t in (_e.get('verdict') or [])):
        _ds = [x for x in (_e.get('data_segments') or []) if x['size'] > 4 * 1048576 and x['entropy'] > 7.5]
        if _ds:
            x0 = _ds[0]
            print('\n[红线] 有 >4MB 高熵数据段：%s  %.1f MB  熵=%s  被代码引用 %d 次' % (
                x0['vaddr'], x0['size'] / 1048576.0, x0['entropy'], x0['refs']), flush=True)
            print('       **不要整程序离线模拟**（百万级指令跑不完）。先找"谁消费这段"：', flush=True)
            print('       解密/解压例程的调用点、mmap/read 到它的位置、它头部的魔数是不是容器/字典。', flush=True)
            print('       同类样本结论：references/08-casebook.md §12（Aiultra：原版无卡密代码，零 NOP ⇒ 重建体）\n', flush=True)
    plan = build_plan(r)
    # 按需求收敛：脱壳优先结构类步骤，授权优先闸门/脚本类步骤
    if nr['route'] == 'unpack':
        plan.sort(key=lambda x: 0 if re.search(r'(container|elf-probe|rk-|patchplan)', x['id']) else 1)
    elif nr['route'] == 'authorization':
        plan.sort(key=lambda x: 0 if re.search(r'(luaq|gate-|dex-deep)', x['id']) else 1)
    elif nr['route'] == 'kernel':
        plan.sort(key=lambda x: 0 if 'ko' in x['id'] or 'container' in x['id'] else 1)
    auto = [s for s in plan if s['auto']][:a.steps]
    manual = [s for s in plan if not s['auto']]
    print('[2/4] 步骤: 自动 %d / 需人 %d' % (len(auto), len(manual)))

    results = {}
    for s in auto:
        print('\n--- [%s] %s' % (s['id'], s['why']))
        if s.get('internal'):
            gen = patch_plan_elf(s['elf'], os.path.join(art, 'rk_%s.json' % os.path.basename(s['elf'])[:20]))
            results[s['id']] = gen
            print('    生成 %d 条打桩命令（不执行）' % (len(gen or [])))
            continue
        print('    正在跑: %s …（上限 %ds）' % (s['cmd'][0], a.timebox), flush=True)
        rc, out = run_script(s['cmd'][0], s['cmd'][1:], timeout=a.timebox)
        results[s['id']] = out
        if rc == -1:
            print('    [!] 超时/失败（%ds 上限）：已跳过，报告里标注"未完成"，换下一路线' % a.timebox, flush=True)
        else:
            print('    完成(rc=%d)，输出 %d 行' % (rc, len(out.splitlines())), flush=True)
        tail = out.strip().split('\n')[-14:]
        print('    rc=%d  %s' % (rc, '\n    '.join(tail)))
        with open(attempts, 'a', encoding='utf-8') as f:
            f.write('- %s `%s` rc=%d\n' % (TS(), s['id'], rc))
        # 闸门步骤：自动抽取 if-eqz + 原字节
        if s['id'].startswith('gate-') and 'dex' in s:
            ad = analyze_gate_output(out, s['dex'], s['method'])
            if ad and ad['cands']:
                results.setdefault('gate_analysis', []).append(dict(dex=s['dex'], method=s['method'], **ad))

    # ---- 汇总 ----
    print('\n[3/4] 汇总 …')
    L = ['# AUTO_PLAN — 自动分析产出（%s）' % TS(), '',
         '- 样本: `%s`' % r.get('sample'), '- 判层: %s' % r.get('layer'),
         '- 需求: %s' % (r.get('need') or '（未指定，全层扫）'),
         '- 路线: **%s** — %s' % (r['route']['route'], r['route']['label']),
         '- 一句话: %s' % r.get('verdict', ''), '']

    e3 = r.get('elf') or {}
    dsbig = [x for x in (e3.get('data_segments') or []) if x['size'] > 4 * 1048576 and x['entropy'] > 7.5]
    if dsbig:
        L.append('## 0 · 红线（先看这条）')
        for x in dsbig:
            L.append('- **不要整程序离线模拟**：`%s` 是 %.1f MB 高熵数据段（熵 %s，代码引用 %d 次）。百万级指令跑不完。'
                     % (x['vaddr'], x['size'] / 1048576.0, x['entropy'], x['refs']))
        L.append('- 正确顺序：① 找消费这段的例程（解密/解压/mmap） ② 看它头部魔数是不是容器 ③ 判"授权层是否链接"')
        L.append('- 同类样本结论：`references/08-casebook.md` §12 Aiultra（原版无卡密代码，零 NOP ⇒ 重建体）')
        L.append('')
    ga = results.get('gate_analysis') or []
    if ga:
        L.append('## A · 控制面补丁候选（带原字节，可直接执行）')
        for g in ga:
            L.append('\n### %s  `%s`  code_off=%s' % (os.path.basename(g['dex']), g['method'], g['code_off']))
            L.append('| 序号 | 指令 | 文件偏移 | 原字节 | 方向提示 |')
            L.append('|---|---|---|---|---|')
            for c in g['cands'][:10]:
                L.append('| %s | %s %s → %s | `%s` | `%s` | %s |' % (
                    c['cu'], c['insn'], c['reg'], c['target'], c['fo'], c['raw'], c['guess']))
            if g['cands']:
                c0 = g['cands'][0]
                new = '00 00'
                L.append('\n```powershell')
                L.append('# 首选候选（%s）—— %s' % (c0['cu'], '强特征：像启动路径' if c0['launch'] else '无强特征，先核对目标地址'))
                L.append('python scripts\\patch_dex.py "%s" patched.dex --offset %s --size 2 --expect "%s" --write "%s"'
                         % (g['dex'], c0['fo'], c0['raw'][:5], new))
                L.append('```')
        L.append('')

    # 打桩清单
    for s in auto:
        if s['id'].startswith('patchplan-'):
            gen = results.get(s['id']) or []
            if gen:
                L.append('## B · 运行时打桩清单（零修改；地址是静态 vaddr，运行期加 load base）')
                L.append('| 类型 | vaddr | 原字节 | 建议补丁 | 说明 |')
                L.append('|---|---|---|---|---|')
                for g in gen:
                    L.append('| %s | `%s` | `%s` | `%s` | %s |' % (
                        g['kind'], g['vaddr'], g.get('raw8', '-'), g['patch_hex'], g['note']))
                th = [g for g in gen if g['kind'] == 'thunk-return']
                if th:
                    L.append('\n```sh')
                    L.append('# 设备上执行（root，走 /proc/pid/mem，不要 ptrace）')
                    L.append('BASE=$(awk \'NR==1{split($1,a,"-");print a[1]}\' <(grep "r-xp.*%s" /proc/$PID/maps))'
                             % os.path.basename(r.get('sample', 'x'))[:12])
                    for g in th[:6]:
                        L.append('pm patch $PID $((BASE + %s)) %s %s   # mov w0,#0; ret' % (g['vaddr'], g['raw8'], g['patch_hex']))
                    L.append('```')
                L.append('⚠ 方向未定：`cbz w0,<成功>` → 返回 0；`cbnz w0,<成功>` → 返回 1。先用错误卡密跑一次看现象，再定值。')
                L.append('')

    if manual:
        L.append('## C · 需要人/需要输入的步骤')
        for s in manual:
            L.append('- **%s** — %s（缺: %s）\n  - `%s`' % (s['id'], s['why'], s['needs'], ' '.join(s['cmd'])))
        L.append('')

    L.append('## 停点判定')
    L.append('- 若上面只有"只读分析"→ 继续往下自动做，不要问"要不要继续"。')
    L.append('- 若要**打补丁/改内存/重打包** → 只生成命令；执行前需要人确认（不可逆/需设备）。')
    L.append('- 若缺设备/有效卡/抓包 → 如实报缺件，并给"没有设备时的静态替代"。')

    plan_path = os.path.join(cd, 'analysis', 'AUTO_PLAN.md')
    open(plan_path, 'w', encoding='utf-8').write('\n'.join(L))
    print('\n[4/4] 产出: %s' % plan_path)
    print('     attempts: %s' % attempts)
    print('\n' + '\n'.join(L[:40]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
