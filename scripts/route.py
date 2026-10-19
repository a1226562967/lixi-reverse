#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: route.py
# purpose: 需求 → 路线的**单一真源**（routing.json）的查询器 + 回归测试。
#   学自 reverse-skill 的做法：路由表外置成 JSON，配回归用例，改路由必跑测试 —— 防止"越加越乱"。
# usage:
#   python route.py "绕过卡密"        # 单次路由
#   python route.py --test            # 回归测试（routing.json 的 test_cases）
#   python route.py --list            # 打印全部规则
# 纪律: 改路由只改 routing.json；测试全绿才算改完。

import sys, os, json, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTING = os.path.join(HERE, 'routing.json')


def load_rules(path=ROUTING):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def route(need, cfg=None):
    cfg = cfg or load_rules()
    if not need:
        return dict(cfg['default'], hit=[])
    low = need.lower()
    for r in cfg['rules']:
        hit = [k for k in r['kws'] if k.lower() in low]
        if hit:
            return dict(route=r['route'], label=r['label'], hit=hit)
    return dict(cfg['default'], hit=[])


def test(cfg=None):
    cfg = cfg or load_rules()
    cases = cfg.get('test_cases') or []
    bad = []
    for need, want in cases:
        got = route(need, cfg)['route']
        mark = 'OK ' if got == want else 'X  '
        print('  %s %-24s -> %-14s %s' % (mark, repr(need)[:24], got, '' if got == want else '(期望 %s)' % want))
        if got != want:
            bad.append((need, want, got))
    print('\n[route --test] %d 个用例，%d 失败' % (len(cases), len(bad)))
    return 0 if not bad else 1


def main():
    ap = argparse.ArgumentParser(description='需求 → 路线（读 routing.json）')
    ap.add_argument('need', nargs='?', default='')
    ap.add_argument('--test', action='store_true')
    ap.add_argument('--list', action='store_true')
    a = ap.parse_args()
    cfg = load_rules()
    if a.test:
        return test(cfg)
    if a.list:
        for r in cfg['rules']:
            print('  %-14s %s' % (r['route'], r['label']))
            print('     关键词: %s' % ', '.join(r['kws']))
        print('  %-14s %s' % (cfg['default']['route'], cfg['default']['label']))
        return 0
    r = route(a.need, cfg)
    print('需求: %r' % a.need)
    print('路线: %s — %s' % (r['route'], r['label']))
    if r.get('hit'):
        print('命中: %s' % ', '.join(r['hit']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
