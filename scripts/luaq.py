#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: luaq.py
# purpose: 脚本层（AppLua / GG 系 / AideLua / AndroLua）判层与解混淆 —— 卡密闸门在 .lua 里而不是 dex 里。
#   四件事：① 判层四判据 ② 找闸门（登录/心跳/环境闸）③ 抓替换密码六件套 ④ 出改法模板
# usage:
#   python luaq.py <apk|zip|.lua>            # 判层 + 找闸门 + 抓六件套
#   python luaq.py <apk> --dump-lua out/     # 把 assets 里的 .lua 全导出来
#   python luaq.py <apk> --json r.json
# 纪律: 只读。补丁只给模板与行号，不替你改文件（改脚本+重签是人的动作）。

import sys, os, re, json, zipfile, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

LUA_HDR_SRC = b'\x1bLua'          # 字节码；源码则是可读文本
GATE_PATTERNS = [
    ('login-code-eq', r'code\s*==\s*1'),
    ('login-code-ne', r'code\s*~\=\s*1'),
    ('heart', r'heart'),
    ('token', r'\btoken\b'),
    ('endtime', r'endTime|end_time|expire'),
    ('safecode', r'safeCode'),
    ('forced-update', r'forced'),
    ('stop-service', r'function\s+ko\s*\('),
]
PATCH_TARGETS = ['oo', 'Bp', 'Mo', 'co', 'Gf', 'Oo', 'ko']


def read_target(path):
    """返回 (kind, blobs) —— blobs = [(name, bytes)]"""
    if path.lower().endswith(('.apk', '.zip')):
        z = zipfile.ZipFile(path)
        lua = [(i.filename, z.read(i.filename)) for i in z.infolist() if i.filename.lower().endswith('.lua')]
        dex = [(i.filename, z.read(i.filename)) for i in z.infolist() if i.filename.endswith('.dex')]
        so = [(i.filename, i.file_size) for i in z.infolist() if i.filename.endswith('.so')]
        jsonl = [(i.filename, z.read(i.filename)) for i in z.infolist()
                 if i.filename.endswith('.json') and ('lua' in i.filename.lower() or 'agg' in i.filename.lower())]
        return 'apk', dict(lua=lua, dex=dex, so=so, json=jsonl)
    b = open(path, 'rb').read()
    return 'file', dict(lua=[(os.path.basename(path), b)], dex=[], so=[], json=[])


def judge(kind, blobs):
    """判层四判据（三条即成立）"""
    hits = []
    n_lua = len(blobs['lua'])
    tot_lua = sum(len(b) for _, b in blobs['lua'])
    if n_lua >= 5 or tot_lua > 100000:
        hits.append('① assets/脚本里有成规模 .lua：%d 个 / %d B' % (n_lua, tot_lua))
    luaj = 0
    luatable = 0
    for name, b in blobs['dex']:
        luaj += b.count(b'Lorg/luaj/vm2/')
        luatable += b.count(b'Lorg/luaj/vm2/LuaTable;')
    if luaj:
        hits.append('② dex 里 org/luaj/vm2 命中 %d 次（LuaJ）' % luaj)
    if luatable:
        hits.append('   其中 LuaTable 参数命中 %d 次 ⇒ UI/逻辑由脚本驱动' % luatable)
    eng = [n for n, _ in blobs['so'] if re.search(r'(keystone|libop\.so|libgg|agg)', n, re.I)]
    if eng:
        hits.append('③ 引擎库: %s' % ', '.join(eng[:4]))
    if blobs['json']:
        hits.append('③ 引擎配置: %s' % ', '.join(n for n, _ in blobs['json'][:3]))
    hdr = []
    for name, b in blobs['lua']:
        if b[:4] == LUA_HDR_SRC:
            hdr.append('%s=字节码(0x%02x)' % (name, b[4] if len(b) > 4 else 0))
        elif re.search(rb'[ -~]{20,}', b[:200]):
            hdr.append('%s=源码' % name)
    if hdr:
        hits.append('④ Lua 文件头: %s' % ', '.join(hdr[:4]))
    score = len({h.strip()[0] for h in hits if h.strip() and h.strip()[0] in '①②③④'})
    return dict(criteria=hits, score=score, is_script_layer=score >= 3,
                lua_count=n_lua, lua_bytes=tot_lua, luaj=luaj, luatable=luatable)


def scan_gates(text, max_hits=6):
    """Lua 常压成单行 -> 用字符偏移定位（知识库坐标就是 @274431 这种）；同一偏移只报一次"""
    out = []
    seen = set()
    for kind, pat in GATE_PATTERNS:
        rx = re.compile(pat)
        n = 0
        for m in rx.finditer(text):
            pos = m.start()
            line = text.count('\n', 0, pos) + 1
            key = (kind, pos)
            if key in seen:
                continue
            seen.add(key)
            ctx = text[max(0, pos - 40):pos + 60].replace('\n', ' ')
            out.append(dict(kind=kind, pos=pos, line=line, text=ctx))
            n += 1
            if n >= max_hits:
                break
    out.sort(key=lambda x: x['pos'])
    return out


def func_defs(text):
    """同名函数可能出现多次（闭包/分支），保留首次出现并记录全部偏移"""
    out = {}
    for m in re.finditer(r'local\s+function\s+(\w+)\s*\(([^)]*)\)', text):
        name = m.group(1)
        item = out.setdefault(name, dict(name=name, args=m.group(2), pos=m.start(),
                                         line=text.count('\n', 0, m.start()) + 1, all=[]))
        item['all'].append(m.start())
    return out


def six_piece(text):
    """抓替换密码六件套（能抓到几件报几件）"""
    r = {}
    nums = dict((m.group(1), int(m.group(2))) for m in re.finditer(r'local\s+(\w+)\s*=\s*(\d+)\b', text))
    if nums:
        r['numbers'] = nums
    alpha = re.search(r'local\s+(\w+)\s*=\s*\{\s*DG\[', text)
    if alpha:
        r['alphabet_var'] = alpha.group(1)
        # 只数"表定义内部"的 DG 引用：从 { 到匹配的 }（取 20000 字符窗口里第一个 } 前）
        seg = text[alpha.start():alpha.start() + 40000]
        head = seg[:seg.find('}')] if '}' in seg else seg
        r['alphabet_count'] = len(re.findall(r'DG\[\d+\]', head))
    tok = re.search(r'local\s+(\w+)\s*=\s*\{\s*\["(\d+)"\]\s*=', text)
    if tok:
        r['token_var'] = tok.group(1)
        r['token_example'] = tok.group(2)
    rot = re.search(r'_DS\s*=\s*\{\s*s\s*=\s*(\d+)', text) or re.search(r'(\d+)\s*%\s*(\d+)\s*\+?\s*1?\]', text)
    if rot:
        r['rotation_raw'] = rot.group(0)[:40]
    dec = re.search(r'function\s+(\w+)\s*\(\s*(\w+)\s*\)[^\n]*\n(?:.*\n){0,8}?.*%\s*(\d+)', text)
    if dec:
        r['decoder'] = dict(name=dec.group(1), arg=dec.group(2), mod=dec.group(3))
    if re.search(r'local\s+(\w+)\s*=\s*\{', text):
        r['second_table'] = True
    if re.search(r':reverse\(\)', text):
        r['has_reverse'] = True
    r['n_calls'] = len(re.findall(r'\bn\(\{', text))
    r['DG_refs'] = len(re.findall(r'DG\[\d+\]', text))
    return r


def patch_template(funcs, script_name):
    """按闸门函数名给"首行 do ... end"模板（只给模板，不改文件）"""
    tmpl = []
    for name, want in (('oo', 'do return true end'), ('Bp', 'do return end'),
                       ('Mo', "do return 1,'登录成功' end"), ('co', "do return 'ok' end")):
        if name in funcs:
            f = funcs[name]
            tmpl.append(dict(func=name, pos=f['pos'], all_pos=f.get('all', []), line=f['line'],
                             insert=want, note='%s(%s) 首行插入' % (name, f['args'])))
    tmpl.sort(key=lambda x: x['pos'])
    return tmpl


def human(r):
    L = []
    L.append('== %s  (%s)' % (r['path'], r['kind']))
    j = r['judge']
    L.append('\n[判层] 脚本层得分 %d/4  → %s' % (j['score'], '是脚本层' if j['is_script_layer'] else '不是（看其它层）'))
    for c in j['criteria']:
        L.append('   ' + c)
    if j['is_script_layer'] and not j.get('luatable'):
        L.append('   [!] 未见 LuaTable：UI 可能不是脚本渲染，闸门也可能在 dex —— 用 02 的手法再核一次')
    if r.get('bytecode_lua'):
        L.append('\n[字节码 Lua] %d 个（需 luac -l 或宿主 dump 才能读）: %s' % (
            len(r['bytecode_lua']), ', '.join('%s(0x%02x)' % (x['name'], x['ver']) for x in r['bytecode_lua'][:6])))
    for s in r['scripts']:
        L.append('\n[脚本] %s  (%d B)' % (s['name'], s['size']))
        if s.get('gates'):
            L.append('   闸门候选 %d 条:' % len(s['gates']))
            for g in s['gates'][:10]:
                L.append('     @%-8d %-13s %s' % (g['pos'], g['kind'], g['text'][:96]))
        else:
            L.append('   闸门候选: 0（可能已全量还原成别的形态，或字符串混淆未解）')
        sp = s.get('six') or {}
        if sp:
            L.append('   替换密码六件套:')
            if sp.get('numbers'):
                L.append('     ① 数字变量: %s' % ' '.join('%s=%d' % (k, v) for k, v in list(sp['numbers'].items())[:10]))
            if sp.get('alphabet_var'):
                L.append('     ② 字母表: %s（%d 项）' % (sp['alphabet_var'], sp.get('alphabet_count', 0)))
            if sp.get('token_var'):
                L.append('     ③ token 表: %s（例 "%%s"）' % (sp['token_var'], sp.get('token_example')))
            if sp.get('rotation_raw'):
                L.append('     ④ 轮转量: %s' % sp['rotation_raw'])
            if sp.get('decoder'):
                d = sp['decoder']
                L.append('     ⑤ 解码器: %s(%s)，模 %s' % (d['name'], d['arg'], d['mod']))
            L.append('     ⑥ 第二张表: %s   :reverse()=%s' % (sp.get('second_table'), sp.get('has_reverse', False)))
            L.append('     统计: n({...}) 调用 %d 处 / DG[] 引用 %d 处' % (sp.get('n_calls', 0), sp.get('DG_refs', 0)))
        if s.get('patch'):
            L.append('   [改法模板]（首行插入，等结构，不改判定表达式）:')
            for p in s['patch']:
                extra = (' (+%d 处同名)' % (len(p['all_pos']) - 1)) if len(p.get('all_pos') or []) > 1 else ''
                L.append('     @%-8d local function %s(%s)  %s%s' % (p['pos'], p['func'], p['note'].split('(')[1].rstrip(') ') if False else '...', p['insert'], extra))
            L.append('     ⚠ 有 30s 心跳时必须同改 登录闸 + 心跳闸 + 环境闸，否则 30 秒后被踢回')
    L.append('\n[下一步]')
    L.append('   1) 全量还原: 三张表复现（见 references/12 §三）→ 让闸门自己浮出来')
    L.append('   2) 改脚本 → 重打包三段式: build_apk.py → zipalign -p -f 4 → apksigner(v1/v2/v3)')
    L.append('   3) 先 apksigner verify --print-certs 原包：AOSP testkey/debug keystore 可复刻 ⇒ 覆盖安装')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='脚本层（Lua）判层与解混淆')
    ap.add_argument('target')
    ap.add_argument('--dump-lua', default='')
    ap.add_argument('--json', default='')
    ap.add_argument('--max-lua', type=int, default=6)
    a = ap.parse_args()
    kind, blobs = read_target(a.target)
    r = dict(path=os.path.abspath(a.target), kind=kind, judge=judge(kind, blobs))
    if a.dump_lua and blobs['lua']:
        os.makedirs(a.dump_lua, exist_ok=True)
        for n, b in blobs['lua']:
            open(os.path.join(a.dump_lua, os.path.basename(n)), 'wb').write(b)
    scripts = []
    bytecode = []
    src = []
    for n, b in blobs['lua']:
        if b[:4] == LUA_HDR_SRC:
            bytecode.append(dict(name=n, size=len(b), ver=b[4] if len(b) > 4 else 0))
            continue
        try:
            t = b.decode('utf-8', 'replace')
        except Exception:
            t = b.decode('latin1', 'replace')
        score = t.count('local function') + t.count('if ') + t.count('return')
        src.append((score, n, b, t))
    src.sort(key=lambda x: (-x[0], -len(x[2])))
    r['bytecode_lua'] = bytecode
    for score, n, b, text in src[:a.max_lua]:
        item = dict(name=n, size=len(b), gates=scan_gates(text))
        funcs = func_defs(text)
        item['funcs'] = {k: v['line'] for k, v in funcs.items()}
        item['six'] = six_piece(text)
        item['patch'] = patch_template(funcs, n)
        scripts.append(item)
    r['scripts'] = scripts
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
