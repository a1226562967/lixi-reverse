#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: dexql.py
# purpose: DEX 查询层 —— 在 dexlib 之上补三件事：
#   ① static_values（密钥第一藏点，<clinit> 里看不到的那种）
#   ② 解码器四特征扫描（String->String + 固定前缀 + Base64/Hex + Map 缓存）
#   ③ 授权闸门候选打分（xxxOrYyy / xxxState / verify / license / card / vip ...）
# usage:
#   python dexql.py <dex> --classes                 列自有类（按包名前缀分组）
#   python dexql.py <dex> --strings --grep 卡密      枚举字符串
#   python dexql.py <dex> --static                   dump 所有 static 字段初值（找密钥）
#   python dexql.py <dex> --decoders                 解码器候选
#   python dexql.py <dex> --gates                    闸门候选（含消费点计数）
#   python dexql.py <dex> --method 'Lx/y;->z'        反汇编一个方法
#   python dexql.py <dex> --all --json out.json      一次出全部（autotriage 用）
# 纪律: 只读。输出候选与证据，不替你下"这就是总闸门"的结论。

import sys, os, re, json, struct, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexlib import Dex, uleb, sleb, OPS, SIZE

VALUE_NAMES = {0x00: 'byte', 0x02: 'short', 0x03: 'char', 0x04: 'int', 0x06: 'long',
               0x10: 'float', 0x11: 'double', 0x15: 'method_type', 0x16: 'method_handle',
               0x17: 'string', 0x18: 'type', 0x19: 'field', 0x1a: 'method', 0x1b: 'enum',
               0x1c: 'array', 0x1d: 'annotation', 0x1e: 'null', 0x1f: 'boolean'}

# 第三方前缀：这些类占 90%+ 体积，永远不是授权判定所在。圈自有类能把搜索成本砍两个数量级。
THIRD_PARTY = ('Landroidx/', 'Landroid/', 'Ljava/', 'Ljavax/', 'Lkotlin/',
               'Ldalvik/', 'Lcom/google/', 'Lcom/android/', 'Lorg/bouncycastle/',
               'Lokhttp3/', 'Lcom/squareup/', 'Lcom/airbnb/', 'Lio/reactivex/',
               'Lorg/jetbrains/', 'Lkotlinx/', 'Lcom/tencent/', 'Lcom/tencent/mm',
               'Lorg/intellij/', 'Lorg/json/', 'Lcom/facebook/', 'Lretrofit2/',
               'Lcom/blankj/', 'Lorg/apache/', 'Lcom/alibaba/', 'Lcom/bumptech/',
               'Lokio/', 'Lcoil3/', 'Lokhttp3/', 'Lcom/reandroid/', 'Lcn/mucute/',
               'Lkotlin/reflect/', 'Landroidx/', 'Lcom/kyant/', 'Lorg/slf4j/')


class DexQ:
    def __init__(self, path):
        self.path = path
        self.dex = Dex(path)
        self.d = self.dex.d
        self._cd = None

    # ---------- 结构 ----------
    def class_defs(self):
        if self._cd is not None:
            return self._cd
        out = []
        d = self.d
        for i in range(self.dex.class_defs_size):
            o = self.dex.class_defs_off + i * 32
            ci, af, sci, ifo, sfi, ano, cdo, svo = struct.unpack_from('<8I', d, o)
            out.append(dict(class_idx=ci, desc=self.dex.type_(ci), access=af,
                            super_idx=sci, super=(self.dex.type_(sci) if sci != 0xFFFFFFFF else None),
                            source_idx=sfi, class_data_off=cdo, static_values_off=svo))
        self._cd = out
        return out

    def strings(self):
        for i in range(self.dex.string_ids_size):
            yield self.dex.string(i)

    def methods(self):
        if getattr(self, '_mcache', None) is None:
            self._mcache = list(self._iter_methods())
        return iter(self._mcache)

    def _iter_methods(self):
        """全部方法：name, flags, code_off（0=无代码）"""
        d = self.d
        for cd in self.class_defs():
            cdo = cd['class_data_off']
            if not cdo:
                continue
            o = cdo
            sf, o = uleb(d, o)
            inf, o = uleb(d, o)
            dm, o = uleb(d, o)
            vm, o = uleb(d, o)
            flds = []
            fidx = 0
            for _ in range(sf + inf):
                diff, o = uleb(d, o)
                acc, o = uleb(d, o)
                fidx += diff
                flds.append((fidx, acc, sf))
            midx = 0
            for _ in range(dm):
                diff, o = uleb(d, o)
                acc, o = uleb(d, o)
                code, o = uleb(d, o)
                midx += diff
                yield dict(cls=cd['desc'], name=self.dex.method(midx), flags=acc, code_off=code, direct=True)
            midx = 0
            for _ in range(vm):
                diff, o = uleb(d, o)
                acc, o = uleb(d, o)
                code, o = uleb(d, o)
                midx += diff
                yield dict(cls=cd['desc'], name=self.dex.method(midx), flags=acc, code_off=code, direct=False)

    def fields(self):
        if getattr(self, '_fcache', None) is None:
            self._fcache = list(self._iter_fields())
        return iter(self._fcache)

    def _iter_fields(self):
        d = self.d
        for cd in self.class_defs():
            cdo = cd['class_data_off']
            if not cdo:
                continue
            o = cdo
            sf, o = uleb(d, o)
            inf, o = uleb(d, o)
            dm, o = uleb(d, o)
            vm, o = uleb(d, o)
            fidx = 0
            for _ in range(sf):
                diff, o = uleb(d, o)
                acc, o = uleb(d, o)
                fidx += diff
                yield dict(cls=cd['desc'], name=self.dex.field(fidx), flags=acc, static=True, class_def=cd)
            fidx = 0
            for _ in range(inf):
                diff, o = uleb(d, o)
                acc, o = uleb(d, o)
                fidx += diff
                yield dict(cls=cd['desc'], name=self.dex.field(fidx), flags=acc, static=False, class_def=cd)

    # ---------- ① static_values ----------
    def read_encoded_array(self, off):
        d = self.d
        n, o = uleb(d, off)
        out = []
        for _ in range(n):
            v, o = self.read_encoded_value(o)
            out.append(v)
        return out

    def read_encoded_value(self, o):
        d = self.d
        b = d[o]; o += 1
        vtype = b & 0x1F
        varg = (b >> 5) & 0x07
        size = varg + 1
        if vtype == 0x1e:      # null
            return None, o
        if vtype == 0x1f:      # boolean
            return bool(varg), o
        if vtype == 0x1c:      # array
            return self.read_encoded_array(o)
        if vtype == 0x1d:      # annotation
            return '<annotation>', o
        raw = int.from_bytes(d[o:o + size], 'little', signed=(vtype in (0x00, 0x02, 0x04, 0x06)))
        o += size
        if vtype == 0x17:
            try:
                return self.dex.string(raw), o
            except Exception:
                return '<str#%d>' % raw, o
        if vtype == 0x18:
            return self.dex.type_(raw), o
        if vtype == 0x1a:
            return self.dex.method(raw), o
        if vtype == 0x19:
            return self.dex.field(raw), o
        return raw, o

    def static_values(self):
        """返回 [(field_desc, value, class_desc)] —— 密钥第一顺位藏点。
        注意：反编译工具显示成 `static String k = "..."`，但它不在 <clinit> 里。"""
        out = []
        for cd in self.class_defs():
            svo = cd['static_values_off']
            if not svo:
                continue
            try:
                vals = self.read_encoded_array(svo)
            except Exception as e:
                continue
            if not hasattr(self, '_static_by_cls'):
                m = {}
                for f in self.fields():
                    if f['static']:
                        m.setdefault(f['class_def']['desc'], []).append(f)
                self._static_by_cls = m
            statics = self._static_by_cls.get(cd['desc'], [])
            for i, v in enumerate(vals):
                if i < len(statics):
                    out.append((statics[i]['name'], v, cd['desc']))
        return out

    # ---------- ② 解码器四特征 ----------
    def disasm(self, code_off):
        try:
            return self.dex.disasm(code_off)[0]
        except Exception:
            return []

    def decoder_candidates(self, max_methods=100000, own_only=True):
        out = []
        n = 0
        for m in self.methods():
            if not m['code_off']:
                continue
            if own_only and not self.is_own(m['cls']):
                continue
            n += 1
            if n > max_methods:
                break
            ins = self.disasm(m['code_off'])
            if not ins:
                continue
            txt = '\n'.join(ins)
            feats = []
            if re.search(r'invoke-(virtual|static|direct).*Base64', txt):
                feats.append('base64')
            if re.search(r'(AES|GCM|Cipher|getInstance|doFinal|DES|RC4)', txt):
                feats.append('cipher')
            if re.search(r'(substring|startsWith|split|indexOf)', txt):
                feats.append('prefix')
            if re.search(r'(Map|HashMap|ConcurrentHashMap|put\(|get\()', txt) and re.search(r'sget-object', txt):
                feats.append('cache')
            if re.search(r'(parseInt|toHexString|decodeHex|URLDecoder)', txt):
                feats.append('encoding')
            if '(Ljava/lang/String;)Ljava/lang/String;' in m['name'] or m['name'].endswith(')Ljava/lang/String;'):
                feats.append('str->str')
            score = len(set(feats))
            if score >= 2:
                out.append(dict(method=m['name'], cls=m['cls'], features=sorted(set(feats)), score=score,
                                code_off=hex(m['code_off']), body=ins[:40]))
        out.sort(key=lambda x: -x['score'])
        return out

    # ---------- 自有类圈定 ----------
    def own_prefixes(self, top=8):
        from collections import Counter
        c = Counter()
        for cd in self.class_defs():
            d = cd['desc']
            if not d.startswith('L') or any(d.startswith(p) for p in THIRD_PARTY):
                continue
            seg = d[1:].split('/')
            c['/'.join(seg[:2]) if len(seg) > 1 else seg[0]] += 1
        return [k for k, v in c.most_common(top)]

    @staticmethod
    def is_own(desc):
        return desc.startswith('L') and not any(desc.startswith(p) for p in THIRD_PARTY)

    # ---------- ③ 闸门候选 ----------
    GATE_KW = ['verify', 'auth', 'licen', 'card', 'vip', 'premium', 'expire', 'activ', 'regist',
               'purchase', 'unlock', 'grant', 'check', 'valid', 'remain', 'bind', 'device', 'trial',
               'pay', 'order', 'quota', 'root', 'permission', 'login', 'token']
    STATE_KW = ['state', 'isval', 'verified', 'granted', 'logged', 'enabled', 'allowed', 'passed']

    def gates(self, limit=200, own_only=True):
        out = []
        for m in self.methods():
            if own_only and not self.is_own(m['cls']):
                continue
            nm = m['name'].split('->')[-1]
            low = nm.lower()
            hit = [k for k in self.GATE_KW if k in low]
            st = [k for k in self.STATE_KW if k in low]
            orpat = bool(re.search(r'[a-z]Or[A-Z]', nm)) and not re.search(
                r'Or(Default|Else|Null|Throw|Empty|Get|Create|Update|Insert|Replace|New)$', nm)
            if not (hit or st or orpat):
                continue
            score = len(hit) * 2 + len(st) * 2 + (6 if orpat else 0)
            out.append(dict(method=m['name'], cls=m['cls'], code_off=hex(m['code_off']) if m['code_off'] else '0',
                            kw=hit + st, or_pattern=orpat, score=score, has_code=bool(m['code_off'])))
        # 有代码的优先（无 code_off 的是 abstract/interface 声明，改不了）
        out.sort(key=lambda x: (-x['score'], not x['has_code']))
        return out[:limit]

    def field_gates(self, limit=200, own_only=True):
        out = []
        for f in self.fields():
            if own_only and not self.is_own(f['cls']):
                continue
            nm = f['name'].split(':')[0].split('->')[-1]
            low = nm.lower()
            hit = [k for k in self.GATE_KW + self.STATE_KW if k in low]
            if hit:
                out.append(dict(field=f['name'], cls=f['cls'], static=f['static'], kw=hit, score=len(hit)))
        out.sort(key=lambda x: -x['score'])
        return out[:limit]

    # ---------- 密钥候选 ----------
    def key_candidates(self):
        out = []
        for s in self.strings():
            if len(s) < 16:
                continue
            if re.fullmatch(r'[A-Za-z0-9+/=]{16,88}', s) and len(s) % 4 == 0:
                out.append(dict(kind='base64-like', value=s, len=len(s)))
            elif re.fullmatch(r'[0-9a-fA-F]{32,128}', s):
                out.append(dict(kind='hex-like', value=s, len=len(s)))
        for fn, v, cls in self.static_values():
            if isinstance(v, str) and len(v) >= 8:
                out.append(dict(kind='static-value', value=v, field=fn, cls=cls, len=len(v)))
        return out


def _cls_summary(q):
    from collections import Counter
    c = Counter()
    for cd in q.class_defs():
        desc = cd['desc']
        pkg = desc[1:].split('/')[0] if '/' in desc else desc
        c[pkg] += 1
    return c.most_common(40)


def main():
    ap = argparse.ArgumentParser(description='DEX 查询层：static_values / 解码器 / 闸门 / 密钥候选')
    ap.add_argument('dex')
    ap.add_argument('--classes', action='store_true')
    ap.add_argument('--strings', action='store_true')
    ap.add_argument('--static', action='store_true')
    ap.add_argument('--decoders', action='store_true')
    ap.add_argument('--gates', action='store_true')
    ap.add_argument('--method', default='')
    ap.add_argument('--grep', default='')
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--json', default='')
    ap.add_argument('--limit', type=int, default=40)
    ap.add_argument('--pkg', default='', help='只报这个包名下的类（如 com/painkiller/nb）')
    ap.add_argument('--all-classes', action='store_true', help='不过滤第三方类（会很吵）')
    a = ap.parse_args()

    q = DexQ(a.dex)
    if a.pkg:
        pfx = 'L' + a.pkg.strip('/') + '/'
        q.gates = (lambda f: (lambda limit=200, own_only=True: [x for x in f(limit, own_only) if x['cls'].startswith(pfx)]))(q.gates)
        q.field_gates = (lambda f: (lambda limit=200, own_only=True: [x for x in f(limit, own_only) if x['cls'].startswith(pfx)]))(q.field_gates)
    res = {}
    if a.classes or a.all:
        print('== 类总数 %d；自有包名前缀（Top）: %s' % (len(q.class_defs()), ', '.join(q.own_prefixes()) or '-'))
        print('== 类分布（按首包名）')
        for k, v in _cls_summary(q):
            print('  %5d  %s' % (v, k))
    if a.strings or a.all:
        pat = re.compile(a.grep) if a.grep else None
        ss = [s for s in q.strings() if (not pat or pat.search(s))]
        print('== 字符串 %d 条%s' % (len(ss), (' (grep=%s)' % a.grep) if a.grep else ''))
        for s in ss[:a.limit]:
            print('   %r' % s)
        res['strings'] = ss[:2000]
    if a.static or a.all:
        sv = q.static_values()
        print('== static_values %d 条（密钥第一顺位）' % len(sv))
        for fn, v, cls in sv[:a.limit]:
            print('   %s = %r   [%s]' % (fn, v, cls))
        res['static_values'] = [dict(field=f, value=v, cls=c) for f, v, c in sv]
    if a.decoders or a.all:
        dc = q.decoder_candidates(own_only=not a.all_classes)
        print('== 解码器候选 %d 个（>=2 特征）' % len(dc))
        for c in dc[:a.limit]:
            print('   score=%d %s  %s' % (c['score'], c['method'], ','.join(c['features'])))
        res['decoders'] = [{k: v for k, v in c.items() if k != 'body'} for c in dc]
    if a.gates or a.all:
        g = q.gates(own_only=not a.all_classes)
        fg = q.field_gates(own_only=not a.all_classes)
        print('== 方法闸门候选 %d（名字侧证据，需再用 find_use 看消费点）' % len(g))
        for c in g[:a.limit]:
            print('   score=%-3d %-58s kw=%s%s' % (c['score'], c['method'][:58], ','.join(c['kw']), ' [Or]' if c['or_pattern'] else ''))
        print('== 字段闸门候选 %d' % len(fg))
        for c in fg[:a.limit]:
            print('   score=%-3d %s' % (c['score'], c['field']))
        res['gates'] = g
        res['field_gates'] = fg
    if a.method:
        sub = a.method
        hit = 0
        # 精确优先：方法名必须紧跟 "->" 且后面是 "("，否则会命中 $lambda$N / <init> / 同前缀方法
        cand = [m for m in q.methods() if m['code_off']]
        exact = [m for m in cand if ('->' + sub + '(') in m['name']]
        loose = [m for m in cand if sub in m['name'] and m not in exact]
        for m in (exact + loose):
            if sub in m['name'] and m['code_off']:
                print('== %s  (code_off=%s)' % (m['name'], hex(m['code_off'])))
                for line in q.disasm(m['code_off']):
                    print('   ' + line)
                hit += 1
                if hit >= 1:
                    break
        if not hit:
            print('[!] 未找到方法（用完整描述符形式: Lx/y;->z(I)V）')
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=2, default=str)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
