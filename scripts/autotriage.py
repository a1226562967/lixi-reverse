#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: autotriage.py
# purpose: ★ 全自动入口 —— 一个样本进去，一张"这一层的锁在哪、能不能破、下一步打哪"的图出来。
#   判层(控制面 APK / 载荷面 ELF / 特权面 .ko) → 判型(加固/自解密/密文/伪代码) →
#   定判决归属(本地 vs 服务端) → 出候选坐标 + 可复制的下一步命令。
# usage:
#   python autotriage.py <样本>                  # 全自动：立案 + 判层 + 报告
#   python autotriage.py <样本> --case-root D:\cases
#   python autotriage.py <样本> --no-case        # 只出报告，不建案件目录
# 纪律: 只读样本；结论分 observed / inference / unknown；"下一步"必须可执行，不许写"进一步分析"。

import sys, os, re, io, json, zipfile, hashlib, argparse, datetime, subprocess, struct

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import elfprobe
from zh import zh_list  # 判定标签中文化
import koprobe
import payload as payload_mod

TS = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
SHA8 = lambda b: hashlib.sha256(b).hexdigest()[:8]


# ---------------- 立案 ----------------
AGENTS_TMPL = """# 案件锚点 — {name}

- 样本: `{path}`
- sha256: `{sha}`
- 大小: {size} B
- 立案时间: {ts}
- 判层: {layer}
- 结论: {verdict}

## 三层账（控制面 / 载荷面 / 特权面）
| 层 | 载体 | 判决在哪 | 能不能本地破 | 证据 |
|---|---|---|---|---|
| 控制面 | APK/dex | {ctrl} | {ctrl_ok} | {ctrl_ev} |
| 载荷面 | ELF/.so | {pay} | {pay_ok} | {pay_ev} |
| 特权面 | .ko/root | {priv} | — | {priv_ev} |

## 已确认坐标（observed）
{coords}

## 下一次动作
{next}

## 读档顺序（上下文丢失时）
1. 本文件  2. `attempts.md` 尾部  3. `analysis/report.json`
"""

ATTEMPTS_TMPL = """# attempts — {name}

## {ts} 立案
- 目标 `{path}` sha256=`{sha}`
- 动作: autotriage 判层
- 结果: {verdict}
"""


def mkcase(root, path, data, layer, verdict):
    name = os.path.splitext(os.path.basename(path))[0]
    cd = os.path.join(root, '%s-%s' % (name, SHA8(data)))
    for sub in ('', 'analysis', 'artifacts'):
        os.makedirs(os.path.join(cd, sub), exist_ok=True)
    return cd


# ---------------- APK 层 ----------------
UTF16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
PKG_RE = re.compile(r'^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,4}$')


def axml_package_strings(b):
    out = []
    for m in UTF16_RE.finditer(b[:0x400000]):
        try:
            s = m.group().decode('utf-16le', 'ignore')
        except Exception:
            continue
        out.append(s)
    return out


def guess_package(strings):
    cands = [x for x in strings if PKG_RE.match(x)]
    cands = [c for c in cands if not c.startswith(('android.', 'androidx.', 'kotlin.', 'java.', 'javax.'))]
    if not cands:
        return ''
    from collections import Counter
    c = Counter()
    for x in cands:
        segs = x.split('.')
        for n in range(2, len(segs) + 1):
            c['.'.join(segs[:n])] += 1
    if not c:
        return cands[0]
    best = max(c.values())
    common = sorted([k for k, v in c.items() if v == best], key=len)
    return common[0] if common else ''


def triage_apk(path, data, artdir):
    r = {'kind': 'APK'}
    z = zipfile.ZipFile(io.BytesIO(data))
    entries = [i for i in z.infolist() if not i.filename.endswith('/')]
    groups = {}
    for i in entries:
        top = i.filename.split('/')[0]
        groups[top] = groups.get(top, 0) + i.file_size
    dex = sorted([(i.filename, i.file_size) for i in entries if re.match(r'classes\d*\.dex$', i.filename)],
                 key=lambda x: -x[1])
    sos = [(i.filename, i.file_size, i.compress_type) for i in entries if i.filename.endswith('.so')]
    tiny = [d for d in dex if d[1] < 20000]
    r['entry_groups'] = dict(sorted(groups.items(), key=lambda kv: -kv[1])[:10])
    r['dex'] = dex
    r['so'] = sos
    r['tiny_dex'] = tiny
    r['stored_so'] = [s for s in sos if s[2] == 0]
    # manifest 包名
    pkg = ''
    try:
        man = z.read('AndroidManifest.xml')
        strs = axml_package_strings(man)
        pkg = guess_package(strs)
        r['manifest_strings_n'] = len(strs)
    except Exception as e:
        r['manifest_error'] = str(e)
    r['package'] = pkg
    # 解 dex 出来查
    os.makedirs(artdir, exist_ok=True)
    dexinfo = []
    import dexql
    for fn, sz in dex:
        p = os.path.join(artdir, fn)
        if not os.path.exists(p):
            open(p, 'wb').write(z.read(fn))
        item = {'dex': fn, 'size': sz, 'path': p}
        try:
            q = dexql.DexQ(p)
            item['classes'] = len(q.class_defs())
            item['own_prefixes'] = q.own_prefixes()
            item['static_values'] = [dict(field=f, value=str(v)[:120], cls=c) for f, v, c in q.static_values()][:20]
            item['decoders'] = [{k: v for k, v in c.items() if k != 'body'} for c in q.decoder_candidates(own_only=True, max_methods=8000)][:10]
            item['key_candidates'] = q.key_candidates()[:10]
            pfx = pkg.replace('.', '/') if pkg else ''
            gates = q.gates(limit=60, own_only=True)
            if pfx:
                # 有包名时只认该包名下的类：为 air 就不退化成三方库的闸门（否则会去反汇编 Lokio）
                gates = [g for g in gates if g['cls'].startswith('L' + pfx)]
            item['gates'] = gates[:20]
            item['field_gates'] = q.field_gates(limit=40, own_only=True)[:20]
        except Exception as e:
            item['error'] = repr(e)
        dexinfo.append(item)
    r['dex_info'] = dexinfo
    # 判决归属三问
    allstr = []
    for it in dexinfo:
        pass
    r['judgement'] = judge_apk(z, dexinfo, pkg)
    return r


SIGN_KW = ['Ed25519', 'EdDSA', 'X25519', 'HmacSHA256', 'HmacSHA1', '签名无效', 'verifyResponse', 'signCheck', 'antiTamper']
# 注: Signature / signature 在 bouncycastle / okhttp 里必然出现, 属噪声, 不收
NOTICE_KW = ['请输入卡密', '卡密', '授权', '过期', '激活', '未授权', '试用', '余额']


def judge_apk(z, dexinfo, pkg):
    """三问定性：① 判决字段有没有本地成功值 ② 提示语能否在客户端字节里搜到 ③ 有没有签名挡伪造"""
    j = {}
    # ② 提示语：整包搜 UTF-8/UTF-16
    raw = b''
    try:
        for i in z.infolist():
            if i.file_size < 8 * 1024 * 1024 and (i.filename.endswith(('.dex', '.so', '.xml', '.json', '.txt')) or i.filename.startswith('assets/')):
                raw += z.read(i.filename)
    except Exception as e:
        j['read_error'] = repr(e)
    hits = {}
    for kw in NOTICE_KW + SIGN_KW:
        if kw.encode('utf-8') in raw:
            hits[kw] = 'utf8'
        elif kw.encode('utf-16le') in raw:
            hits[kw] = 'utf16'
    j['keyword_hits'] = hits
    j['notice_in_client'] = bool([k for k in NOTICE_KW if k in hits])
    j['signature_in_client'] = bool([k for k in SIGN_KW if k in hits])
    # ① 本地判决：能不能在本包里找到成功标志字段/状态槽
    local_flags = []
    for it in dexinfo:
        for f in it.get('field_gates', []):
            nm = f['field'].split('->')[-1].lower()
            if any(k in nm for k in ('state', 'verified', 'granted', 'unlock', 'valid', 'ok')):
                local_flags.append(f['field'])
    j['local_state_fields'] = local_flags[:12]
    j['verdict_hint'] = []
    if j['notice_in_client']:
        j['verdict_hint'].append('提示语在客户端命中 -> 文案本地，可能本地判决（不等于一定本地）')
    else:
        j['verdict_hint'].append('提示语未在客户端命中 -> 服务端逐句下发（别再找本地 jcc）')
    if j['signature_in_client']:
        j['verdict_hint'].append('出现签名相关字样 -> 响应可能不可伪造（先查是否真验签）')
    if local_flags:
        j['verdict_hint'].append('存在本地状态字段 -> 可尝试翻状态槽/改闸门')
    return j


# ---------------- 主流程 ----------------
def triage(path, case_root=None, no_case=False):
    data = open(path, 'rb').read()
    sha = hashlib.sha256(data).hexdigest()
    head = data[:16]
    kind = 'unknown'
    layer = '未知'
    if data[:4] == b'PK\x03\x04':
        kind = 'ZIP/APK'
        layer = '控制面(APK)'
    elif data[:4] == b'\x7fELF':
        kind = 'ELF'
        e_type = struct.unpack_from('<H', data, 16)[0] if data[5] == 1 else struct.unpack_from('>H', data, 16)[0]
        layer = '特权面(.ko)' if e_type == 1 else '载荷面(ELF)'
    elif data[:2] == b'#!' or re.match(rb'^(if |#!|echo |base64)', data[:8]):
        kind = 'SHELL-WRAPPER'
        layer = '载荷面(包装层)'
    r = {'sample': os.path.abspath(path), 'sha256': sha, 'size': len(data), 'head': head.hex(' '),
         'kind': kind, 'layer': layer, 'ts': TS, 'next_actions': [], 'coords': []}
    cd = None
    if not no_case and case_root:
        cd = mkcase(case_root, path, data, layer, kind)
        r['case_dir'] = cd
        art = os.path.join(cd, 'artifacts')
    else:
        art = os.path.join(os.path.dirname(os.path.abspath(path)), '_autotriage')
    os.makedirs(art, exist_ok=True)
    r['artifacts_dir'] = art

    # 分流
    if kind in ('ZIP/APK',):
        is_apk = False
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            is_apk = 'AndroidManifest.xml' in z.namelist()
        except Exception:
            pass
        if is_apk:
            r['apk'] = triage_apk(path, data, art)
            r['layer'] = '控制面(APK)'
        else:
            r['zip_entries'] = []
            try:
                z = zipfile.ZipFile(io.BytesIO(data))
                for i in z.infolist():
                    if i.filename.endswith('/'):
                        continue
                    b = z.read(i.filename)
                    ch = payload_mod.peel(b, i.filename, 0, art, [], 2)
                    r['zip_entries'].append({'name': i.filename, 'size': len(b), 'kind': ch.get('kind'),
                                             'leaf': ch.get('leaf'), 'children': len(ch.get('children') or [])})
            except Exception as e:
                r['zip_error'] = repr(e)
    elif kind == 'ELF':
        pr = elfprobe.probe(path)
        r['elf'] = pr
        if layer == '特权面(.ko)':
            r['ko'] = koprobe.probe_bytes(data, os.path.basename(path), art)
        else:
            # 运行时打桩点（五类判据）—— 决定"能不能不打磁盘就过"
            try:
                import rkprobe
                rk = rkprobe.scan(data, None, path)
                th_text = [h for h in rk['thunks'] if not h.get('suspect_cipher')]
                mech = [x for x in rk['plt'] if x['sym'] in rkprobe.CROSS_MECH]
                r['runtime'] = dict(
                    thunks_text=len(th_text), thunks_total=len(rk['thunks']),
                    plt_total=len(rk['plt']), plt_mech=[x['sym'] for x in mech][:12],
                    bss_singletons=len(rk['bss']), time_gates=len(rk['time_gates']),
                    relative_to_thunk=len(rk['relative']),
                    top_thunks=[hex(h['vaddr']) for h in th_text[:10]])
            except Exception as e:
                r['runtime'] = {'error': repr(e)}
    else:
        # 包装层：先剥
        layers = []
        tree = payload_mod.peel(data, os.path.basename(path), 0, art, layers, 3)
        r['carrier'] = tree
        r['provenance'] = layers
        # 剥出来的 ELF 再判
        leaves = []
        def walk(n):
            if n.get('leaf') == 'ELF' and n.get('path'):
                leaves.append(n['path'])
            for c in n.get('children') or []:
                walk(c)
        walk(tree)
        r['leaf_elfs'] = leaves[:10]
        if leaves:
            r['elf'] = elfprobe.probe(leaves[0])
            r['ko'] = koprobe.probe_bytes(open(leaves[0], 'rb').read(), os.path.basename(leaves[0]), art)

    # ---- 下一步动作（必须可执行）----
    r['next_actions'] = plan(r)
    r['coords'] = coords(r)
    r['verdict'] = one_line(r)

    # 落盘
    if cd:
        open(os.path.join(cd, 'AGENTS.md'), 'w', encoding='utf-8').write(
            AGENTS_TMPL.format(name=os.path.basename(path), path=r['sample'], sha=sha, size=len(data), ts=TS,
                               layer=r['layer'], verdict=r['verdict'],
                               ctrl=r['layer'], ctrl_ok='待判', ctrl_ev=kind,
                               pay='-', pay_ok='-', pay_ev='-', priv='-', priv_ev='-',
                               coords='\n'.join('- ' + c for c in r['coords']) or '- 无',
                               next='\n'.join('1. `%s`' % a for a in r['next_actions'])))
        open(os.path.join(cd, 'attempts.md'), 'w', encoding='utf-8').write(
            ATTEMPTS_TMPL.format(name=os.path.basename(path), ts=TS, path=r['sample'], sha=sha, verdict=r['verdict']))
        json.dump(r, open(os.path.join(cd, 'analysis', 'report.json'), 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=2, default=str)
        open(os.path.join(cd, 'analysis', 'REPORT.md'), 'w', encoding='utf-8').write(render(r))
    return r


def plan(r):
    out = []
    if r.get('apk'):
        a = r['apk']
        if a.get('tiny_dex'):
            out.append('- [ ] 极小 dex = 解码器：python scripts/dexql.py <dex> --strings --static --decoders')
        gate = None
        for it in a.get('dex_info', []):
            for g in it.get('gates', []):
                if g.get('or_pattern') or 'verify' in g['method'].lower():
                    gate = (it['path'], g['method'])
                    break
            if gate:
                break
        if gate:
            out.append('- [ ] 总闸门候选 %s -> python scripts/dexql.py "%s" --method "%s"' % (gate[1], gate[0], gate[1].split('->')[-1].split('(')[0]))
            out.append('- [ ] 找到 if-eqz 后：python scripts/patch_dex.py <dex> <out.dex> --offset <fo> --expect <原字节> --write <新字节>')
        for it in a.get('dex_info', []):
            for d in it.get('decoders', [])[:1]:
                out.append('- [ ] 解码器 %s -> 复现解码器前先过 FIPS-197 自检: python scripts/aesgcm.py' % d['method'])
        j = a.get('judgement') or {}
        if j.get('signature_in_client'):
            out.append('- [ ] [!] 命中签名字样：先确认是否真验签（假服务器能不能过），再决定走重放(references/server-verdict.md)')
        if not j.get('notice_in_client'):
            out.append('- [ ] [!] 运行期提示语不在客户端 -> 服务端判决：走真响应重放 / 假服务器（references/server-verdict.md）')
        for s in a.get('stored_so', [])[:1]:
            out.append('- [ ] 重打包注意：%s 是 STORED（compress_type=0），必须 4K/16K 页对齐，别用 zipfile 直接打' % s[0])
    if r.get('carrier') and r.get('provenance'):
        p = r['provenance'][0]
        out.append('- [ ] 载体链已剥：%s @%s -> %s（已落盘 artifacts）' % (p['method'], p['offset'], p['out_sha256']))
    rt = r.get('runtime') or {}
    if rt.get('thunks_text'):
        out.append('- [ ] **运行时打桩路线可用（零修改）**：明文区 thunk=%d/%d，.rela.plt 横切机制=%s，'
                   '.bss 单例标志=%d，时间门=%d，RELATIVE→跳板=%d' % (
                       rt['thunks_text'], rt['thunks_total'], ','.join(rt['plt_mech'][:6]) or '-',
                       rt['bss_singletons'], rt['time_gates'], rt['relative_to_thunk']))
        out.append('- [ ] 拿全部坐标：`python scripts\\rkprobe.py <同一文件> --json rk.json`（前 10 个 thunk: %s）' % ','.join(rt.get('top_thunks', [])[:5]))
        out.append('- [ ] 打桩纪律：8 字节等长覆盖 / 先读调用者再定返回值(cbz→0,cbnz→1) / 分阶段等输出门 / '
                   '喂狗周期<检测周期 / 走 /proc/pid/mem 不 attach / 有服务端副本的判定不要打')
    e = r.get('elf')
    if e:
        tags = ' '.join(e.get('verdict') or [])
        if 'SELF-DECRYPT-STUB' in tags or 'FILESZ0-SEGMENT' in tags:
            out.append('- [ ] 自解密/加固：动态路线 = 等它自己解完再 dump（无设备时用 unicorn 按 entry 仿真，或找解码器三件套）')
            out.append('- [ ] 静态替代：在 artifacts 里搜 DC CVAU 前后 2KB 定位解码器尾部，见 references/elf-payload.md §L5')
        if 'CIPHER' in tags or 'NOT-COMPILED' in tags:
            out.append('- [ ] 密文：别试解算法，先找"密钥源被打桩"的函数（mov w0,#imm; ret），见 references/elf-form-verdict.md')
        if e.get('embedded_elf'):
            out.append('- [ ] 有内嵌 ELF 候选：python scripts/payload.py <file> --dump artifacts --json out.json')
        if not e.get('is_elf'):
            out.append('- [ ] 未判出形态：先 python scripts/elfprobe.py <file> --json 再定')
    k = r.get('ko')
    if k and k.get('capabilities'):
        for cap in list(k['capabilities'])[:3]:
            out.append('- [ ] .ko 能力命中 %s -> 这是权限硬前提，不是授权问题；授权判决另找' % cap)
    if not out:
        out.append('- [ ] 证据不足：python scripts/elfprobe.py <file> --json 先拿形态，再决定层')
    return out


def coords(r):
    out = []
    if r.get('apk'):
        a = r['apk']
        out.append('package=%s' % a.get('package'))
        for it in a.get('dex_info', []):
            for s in it.get('static_values', [])[:3]:
                out.append('static_value %s = %r' % (s['field'].split('->')[-1], s['value'][:60]))
            for d in it.get('decoders', [])[:2]:
                out.append('decoder %s (score=%d %s)' % (d['method'], d['score'], ','.join(d['features'])))
            for g in it.get('gates', [])[:5]:
                out.append('gate %s (score=%d)' % (g['method'], g['score']))
    e = r.get('elf')
    if e and e.get('is_elf'):
        out.append('ELF %s entry=%s phnum=%d shnum=%d imports=%s' % (
            e['elf']['e_type'], e['elf']['entry'], e['elf']['phnum'], e['elf']['shnum'], e['elf']['import_count']))
        for c in (e.get('embedded_elf') or [])[:3]:
            out.append('embedded ELF @%s' % c.get('off'))
    k = r.get('ko')
    if k and k.get('modinfo'):
        for kk, vv in k['modinfo'].items():
            out.append('modinfo.%s=%s' % (kk, vv[0][:80]))
    rt = r.get('runtime') or {}
    if rt.get('thunks_text'):
        out.append('runtime thunks(明文区)=%d/%d plt_mech=%s bss_singletons=%d time_gates=%d rel2thunk=%d' % (
            rt['thunks_text'], rt['thunks_total'], ','.join(rt['plt_mech'][:5]) or '-',
            rt['bss_singletons'], rt['time_gates'], rt['relative_to_thunk']))
    return out


def one_line(r):
    if r.get('apk'):
        a = r['apk']
        j = a.get('judgement') or {}
        n_gate = sum(len(it.get('gates') or []) for it in a.get('dex_info') or [])
        return 'APK 层：包名=%s，dex=%d 个，闸门候选 %d，解码器 %d，提示语本地命中=%s，签名字样=%s' % (
            a.get('package'), len(a.get('dex') or []), n_gate,
            sum(len(it.get('decoders') or []) for it in a.get('dex_info') or []),
            j.get('notice_in_client'), j.get('signature_in_client'))
    e = r.get('elf')
    if e and e.get('is_elf'):
        rt = r.get('runtime') or {}
        extra = ('  ||  运行时打桩点: thunk=%s(明文) plt横切=%s 单例标志=%s 时间门=%s' % (
            rt.get('thunks_text'), len(rt.get('plt_mech') or []), rt.get('bss_singletons'), rt.get('time_gates'))) if rt.get('thunks_text') else ''
        return '%s：%s%s' % (r['layer'], zh_list([x[:60] for x in (e.get('verdict') or [])])[:300], extra)
    if r.get('carrier'):
        return '包装层：%s' % (r.get('provenance') or [{}])[0].get('method', '?')
    return '未知形态：%s' % r['head']


def render(r):
    L = ['# 自动分诊报告', '', '- 样本: `%s`' % r['sample'], '- sha256: `%s`' % r['sha256'],
         '- 大小: %d B' % r['size'], '- 时间: %s' % r['ts'], '- 判层: **%s**' % r['layer'], '', '## 一句话', '', r['verdict'], '']
    L.append('## 坐标（observed）')
    for c in r['coords']:
        L.append('- `%s`' % c)
    L.append('')
    L.append('## 下一步（可执行，按顺序）')
    for a in r['next_actions']:
        L.append(a)
    L.append('')
    if r.get('apk'):
        a = r['apk']
        L.append('## APK 结构')
        L.append('| 组 | 字节 |')
        L.append('|---|---|')
        for k, v in (a.get('entry_groups') or {}).items():
            L.append('| %s | %d |' % (k, v))
        L.append('')
        L.append('| dex | 大小 | 类数 | 自有前缀 |')
        L.append('|---|---|---|---|')
        for it in a.get('dex_info') or []:
            L.append('| %s | %d | %s | %s |' % (it['dex'], it['size'], it.get('classes'), ','.join(it.get('own_prefixes') or [])[:40]))
        L.append('')
        for it in a.get('dex_info') or []:
            gs = it.get('gates') or []
            if gs:
                L.append('### 闸门候选 — %s' % it['dex'])
                for g in gs[:8]:
                    L.append('- score=%d `%s` kw=%s%s' % (g['score'], g['method'], ','.join(g['kw']), ' [Or]' if g['or_pattern'] else ''))
                L.append('')
        j = a.get('judgement') or {}
        L.append('### 判决归属三问')
        L.append('- 提示语在客户端: %s（命中: %s）' % (j.get('notice_in_client'), ','.join([k for k in NOTICE_KW if k in (j.get('keyword_hits') or {})])))
        L.append('- 签名字样: %s（命中: %s）' % (j.get('signature_in_client'), ','.join([k for k in SIGN_KW if k in (j.get('keyword_hits') or {})])))
        L.append('- 本地状态字段: %s' % ', '.join((j.get('local_state_fields') or [])[:6]))
        for h in j.get('verdict_hint') or []:
            L.append('- %s' % h)
        L.append('')
    e = r.get('elf')
    if e:
        L.append('## ELF 形态')
        L.append('```')
        L.append(elfprobe.human(e))
        L.append('```')
        L.append('')
    k = r.get('ko')
    if k:
        L.append('## 内核模块能力面')
        L.append('```')
        L.append(koprobe.human(k))
        L.append('```')
        L.append('')
    rt = r.get('runtime') or {}
    if rt.get('thunks_text'):
        L.append('## 运行时打桩点（rkprobe 五类判据）')
        L.append('- 明文区 thunk: %d / 总 %d（`br x17` 跳板，返回值打桩点）' % (rt['thunks_text'], rt['thunks_total']))
        L.append('- PLT 横切机制: %s' % (', '.join(rt['plt_mech']) or '-'))
        L.append('- .bss 单例标志（喂狗候选）: %d' % rt['bss_singletons'])
        L.append('- 时间门: %d（三条写法常并存，要数全）' % rt['time_gates'])
        L.append('- RELATIVE→跳板（虚函数/有消费者）: %d' % rt['relative_to_thunk'])
        L.append('- 前 10 个 thunk: %s' % ', '.join(rt.get('top_thunks', [])))
        L.append('')
    if r.get('carrier'):
        L.append('## 载体链')
        L.append('```')
        L.append(payload_mod.human(r['carrier']))
        L.append('```')
        L.append('')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='全自动分诊：判层 → 判型 → 判决归属 → 下一步')
    ap.add_argument('target')
    ap.add_argument('--case-root', default='')
    ap.add_argument('--no-case', action='store_true')
    ap.add_argument('--json', default='')
    a = ap.parse_args()
    case_root = a.case_root or os.path.join(os.path.dirname(os.path.abspath(a.target)), 'cases')
    r = triage(a.target, case_root, a.no_case)
    print(render(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    if r.get('case_dir'):
        print('[+] 案件: %s' % r['case_dir'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
