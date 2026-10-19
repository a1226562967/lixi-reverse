#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: selftest.py
# purpose: 一条命令验证本技能 13 个脚本是否可跑（不联网、不碰真实样本）。
# usage:  python scripts/selftest.py [--py312 <interpreter>]
# 判据:  每个脚本 ① 语法编译通过 ② 能被 import ③ 关键自检（elfprobe/aesgcm）跑通。

import sys, os, io, subprocess, py_compile, tempfile, json

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = sorted([os.path.join('scripts', f) for f in os.listdir(HERE)
                    if f.endswith('.py') and f != 'selftest.py'])
_armor = os.path.join(os.path.dirname(HERE), 'armor')
if os.path.isdir(_armor):
    SCRIPTS += sorted([os.path.join('armor', f) for f in os.listdir(_armor) if f.endswith('.py')])
MODULES = sorted([os.path.basename(f)[:-3] for f in SCRIPTS if not os.path.basename(f).startswith('__')])


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except Exception as e:
        return -1, repr(e)


def main():
    py = sys.executable
    if '--py312' in sys.argv:
        py = sys.argv[sys.argv.index('--py312') + 1]
    ok = True
    print('[selftest] python = %s' % py)

    # 1) 语法编译
    bad = []
    for s in SCRIPTS:
        p = os.path.join(os.path.dirname(HERE), s) if s.startswith(('scripts', 'armor')) else os.path.join(HERE, s)
        if not os.path.exists(p):
            bad.append((s, 'MISSING'))
            continue
        try:
            py_compile.compile(p, doraise=True, cfile=os.path.join(tempfile.gettempdir(), s + 'c'))
        except Exception as e:
            bad.append((s, str(e)[:120]))
    print('[1/4] 语法编译: %s' % (('OK %d/%d' % (len(SCRIPTS), len(SCRIPTS))) if not bad else 'FAIL ' + json.dumps(bad, ensure_ascii=False)))
    ok &= not bad

    # 2) import
    sys.path.insert(0, HERE)
    _ad = os.path.join(os.path.dirname(HERE), 'armor')
    if os.path.isdir(_ad):
        sys.path.insert(0, _ad)
    fails = []
    for m in MODULES:
        try:
            __import__(m)
        except Exception as e:
            fails.append((m, repr(e)[:140]))
    print('[2/4] import: %s' % ('OK %d/%d' % (len(MODULES), len(MODULES)) if not fails else 'FAIL ' + json.dumps(fails, ensure_ascii=False)))
    ok &= not fails

    # 3) 关键自检
    rc, out = run([py, os.path.join(HERE, 'elfprobe.py'), '--selftest'])
    passed = (rc == 0 and 'PASS' in out)
    print('[3/4] elfprobe --selftest: %s' % ('PASS' if passed else 'FAIL(rc=%d)' % rc))
    if not passed:
        print('     ' + '\n     '.join(out.strip().splitlines()[-8:]))
    ok &= passed

    rc, out = run([py, '-c', 'import sys; sys.path.insert(0,%r); import aesgcm; aesgcm.self_test(); print("AES-OK")' % HERE])
    aes = ('AES-OK' in out)
    print('[4/4] aesgcm FIPS-197 自检: %s' % ('PASS' if aes else 'FAIL'))
    if not aes:
        print('     ' + out.strip()[:300])
    ok &= aes

    print('\n[selftest] %s' % ('全部通过 —— 可以开打' if ok else '有失败项，先修再开打'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
