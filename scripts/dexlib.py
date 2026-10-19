# -*- coding: utf-8 -*-
# language: Python 3, file: dexlib.py — 极简 DEX 结构解析 + dalvik 字节码反汇编
# 只做定向分析需要的东西: 类/方法/字段/字符串表 + 方法体反汇编

import struct, sys

# ---------------- 基础读取 ----------------
def uleb(d, o):
    r = 0; s = 0
    while True:
        b = d[o]; o += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80):
            return r, o
        s += 7

def sleb(d, o):
    r = 0; s = 0
    while True:
        b = d[o]; o += 1
        r |= (b & 0x7f) << s
        s += 7
        if not (b & 0x80):
            if b & 0x40:
                r -= (1 << s)
            return r, o

# ---------------- 操作码表 (name, format) ----------------
OPS = {}
def _t(base, names, fmt):
    for i, n in enumerate(names):
        OPS[base + i] = (n, fmt)

_t(0x00, ['nop'], '10x')
_t(0x01, ['move'], '12x'); _t(0x02, ['move/from16'], '22x'); _t(0x03, ['move/16'], '32x')
_t(0x04, ['move-wide'], '12x'); _t(0x05, ['move-wide/from16'], '22x'); _t(0x06, ['move-wide/16'], '32x')
_t(0x07, ['move-object'], '12x'); _t(0x08, ['move-object/from16'], '22x'); _t(0x09, ['move-object/16'], '32x')
_t(0x0a, ['move-result'], '11x'); _t(0x0b, ['move-result-wide'], '11x')
_t(0x0c, ['move-result-object'], '11x'); _t(0x0d, ['move-exception'], '11x')
_t(0x0e, ['return-void'], '10x'); _t(0x0f, ['return'], '11x')
_t(0x10, ['return-wide'], '11x'); _t(0x11, ['return-object'], '11x')
_t(0x12, ['const/4'], '11n'); _t(0x13, ['const/16'], '21s'); _t(0x14, ['const'], '31i')
_t(0x15, ['const/high16'], '21h'); _t(0x16, ['const-wide/16'], '21s'); _t(0x17, ['const-wide/32'], '31i')
_t(0x18, ['const-wide'], '51l'); _t(0x19, ['const-wide/high16'], '21h')
_t(0x1a, ['const-string'], '21c'); _t(0x1b, ['const-string/jumbo'], '31c')
_t(0x1c, ['const-class'], '21c'); _t(0x1d, ['monitor-enter'], '11x'); _t(0x1e, ['monitor-exit'], '11x')
_t(0x1f, ['check-cast'], '21c'); _t(0x20, ['instance-of'], '22c'); _t(0x21, ['array-length'], '12x')
_t(0x22, ['new-instance'], '21c'); _t(0x23, ['new-array'], '22c')
_t(0x24, ['filled-new-array'], '35c'); _t(0x25, ['filled-new-array/range'], '3rc')
_t(0x26, ['fill-array-data'], '31t'); _t(0x27, ['throw'], '11x')
_t(0x28, ['goto'], '10t'); _t(0x29, ['goto/16'], '20t'); _t(0x2a, ['goto/32'], '30t')
_t(0x2b, ['packed-switch'], '31t'); _t(0x2c, ['sparse-switch'], '31t')
_t(0x2d, ['cmpl-float'], '23x'); _t(0x2e, ['cmpg-float'], '23x')
_t(0x2f, ['cmpl-double'], '23x'); _t(0x30, ['cmpg-double'], '23x'); _t(0x31, ['cmp-long'], '23x')
_t(0x32, ['if-eq'], '22t'); _t(0x33, ['if-ne'], '22t'); _t(0x34, ['if-lt'], '22t')
_t(0x35, ['if-ge'], '22t'); _t(0x36, ['if-gt'], '22t'); _t(0x37, ['if-le'], '22t')
_t(0x38, ['if-eqz'], '21t'); _t(0x39, ['if-nez'], '21t'); _t(0x3a, ['if-ltz'], '21t')
_t(0x3b, ['if-gez'], '21t'); _t(0x3c, ['if-gtz'], '21t'); _t(0x3d, ['if-lez'], '21t')
_t(0x44, ['aget'], '23x'); _t(0x45, ['aget-wide'], '23x'); _t(0x46, ['aget-object'], '23x')
_t(0x47, ['aget-boolean'], '23x'); _t(0x48, ['aget-byte'], '23x'); _t(0x49, ['aget-char'], '23x')
_t(0x4a, ['aget-short'], '23x'); _t(0x4b, ['aput'], '23x'); _t(0x4c, ['aput-wide'], '23x')
_t(0x4d, ['aput-object'], '23x'); _t(0x4e, ['aput-boolean'], '23x'); _t(0x4f, ['aput-byte'], '23x')
_t(0x50, ['aput-char'], '23x'); _t(0x51, ['aput-short'], '23x')
_t(0x52, ['iget'], '22c'); _t(0x53, ['iget-wide'], '22c'); _t(0x54, ['iget-object'], '22c')
_t(0x55, ['iget-boolean'], '22c'); _t(0x56, ['iget-byte'], '22c'); _t(0x57, ['iget-char'], '22c')
_t(0x58, ['iget-short'], '22c'); _t(0x59, ['iput'], '22c'); _t(0x5a, ['iput-wide'], '22c')
_t(0x5b, ['iput-object'], '22c'); _t(0x5c, ['iput-boolean'], '22c'); _t(0x5d, ['iput-byte'], '22c')
_t(0x5e, ['iput-char'], '22c'); _t(0x5f, ['iput-short'], '22c')
_t(0x60, ['sget'], '21c'); _t(0x61, ['sget-wide'], '21c'); _t(0x62, ['sget-object'], '21c')
_t(0x63, ['sget-boolean'], '21c'); _t(0x64, ['sget-byte'], '21c'); _t(0x65, ['sget-char'], '21c')
_t(0x66, ['sget-short'], '21c'); _t(0x67, ['sput'], '21c'); _t(0x68, ['sput-wide'], '21c')
_t(0x69, ['sput-object'], '21c'); _t(0x6a, ['sput-boolean'], '21c'); _t(0x6b, ['sput-byte'], '21c')
_t(0x6c, ['sput-char'], '21c'); _t(0x6d, ['sput-short'], '21c')
_t(0x6e, ['invoke-virtual'], '35c'); _t(0x6f, ['invoke-super'], '35c')
_t(0x70, ['invoke-direct'], '35c'); _t(0x71, ['invoke-static'], '35c'); _t(0x72, ['invoke-interface'], '35c')
_t(0x74, ['invoke-virtual/range'], '3rc'); _t(0x75, ['invoke-super/range'], '3rc')
_t(0x76, ['invoke-direct/range'], '3rc'); _t(0x77, ['invoke-static/range'], '3rc')
_t(0x78, ['invoke-interface/range'], '3rc')
_t(0x7b, ['neg-int'], '12x'); _t(0x7c, ['not-int'], '12x'); _t(0x7d, ['neg-long'], '12x')
_t(0x7e, ['not-long'], '12x'); _t(0x7f, ['neg-float'], '12x'); _t(0x80, ['neg-double'], '12x')
_t(0x81, ['int-to-long'], '12x'); _t(0x82, ['int-to-float'], '12x'); _t(0x83, ['int-to-double'], '12x')
_t(0x84, ['long-to-int'], '12x'); _t(0x85, ['long-to-float'], '12x'); _t(0x86, ['long-to-double'], '12x')
_t(0x87, ['float-to-int'], '12x'); _t(0x88, ['float-to-long'], '12x'); _t(0x89, ['float-to-double'], '12x')
_t(0x8a, ['double-to-int'], '12x'); _t(0x8b, ['double-to-long'], '12x'); _t(0x8c, ['double-to-float'], '12x')
_t(0x8d, ['int-to-byte'], '12x'); _t(0x8e, ['int-to-char'], '12x'); _t(0x8f, ['int-to-short'], '12x')
_int_ops = ['add', 'sub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr']
for i, n in enumerate(_int_ops):
    OPS[0x90 + i] = (n + '-int', '23x')
for i, n in enumerate(_int_ops):
    OPS[0x9b + i] = (n + '-long', '23x')
for i, n in enumerate(_int_ops[:5]):
    OPS[0xa6 + i] = (n + '-float', '23x')
for i, n in enumerate(_int_ops[:5]):
    OPS[0xab + i] = (n + '-double', '23x')
for i, n in enumerate(_int_ops):
    OPS[0xb0 + i] = (n + '-int/2addr', '12x')
for i, n in enumerate(_int_ops):
    OPS[0xbb + i] = (n + '-long/2addr', '12x')
for i, n in enumerate(_int_ops[:5]):
    OPS[0xc6 + i] = (n + '-float/2addr', '12x')
for i, n in enumerate(_int_ops[:5]):
    OPS[0xcb + i] = (n + '-double/2addr', '12x')
for i, n in enumerate(_int_ops):
    OPS[0xd0 + i] = (n + '-int/lit16', '22s')
for i, n in enumerate(_int_ops):
    OPS[0xd8 + i] = (n + '-int/lit8', '22b')

SIZE = {'10x': 1, '12x': 1, '11n': 1, '11x': 1, '10t': 1,
        '20t': 2, '22x': 2, '21t': 2, '21s': 2, '21h': 2, '21c': 2, '23x': 2, '22b': 2, '22t': 2, '22s': 2, '22c': 2,
        '32x': 3, '30t': 3, '31i': 3, '31t': 3, '31c': 3, '35c': 3, '3rc': 3,
        '45cc': 4, '4rcc': 4, '51l': 5}


class Dex:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        assert d[:4] == b'dex\n', 'not dex'
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from('<12I', d, 0x38)
        self._strcache = {}

    def string(self, idx):
        if idx in self._strcache:
            return self._strcache[idx]
        o = struct.unpack_from('<I', self.d, self.string_ids_off + idx * 4)[0]
        n, o = uleb(self.d, o)
        e = self.d.index(b'\0', o)
        s = self.d[o:e].decode('utf-8', 'replace')
        self._strcache[idx] = s
        return s

    def type_(self, idx):
        si = struct.unpack_from('<I', self.d, self.type_ids_off + idx * 4)[0]
        return self.string(si)

    def method(self, idx):
        ci, pi, ni = struct.unpack_from('<HHI', self.d, self.method_ids_off + idx * 8)
        return '%s->%s%s' % (self.type_(ci), self.string(ni), self.proto(pi))

    def proto(self, idx):
        shorty, ret, params_off = struct.unpack_from('<III', self.d, self.proto_ids_off + idx * 12)
        r = self.type_(ret)
        ps = []
        if params_off:
            n = struct.unpack_from('<I', self.d, params_off)[0]
            for i in range(n):
                ps.append(self.type_(struct.unpack_from('<H', self.d, params_off + 4 + i * 2)[0]))
        return '(' + ''.join(ps) + ')' + r

    def field(self, idx):
        ci, ti, ni = struct.unpack_from('<HHI', self.d, self.field_ids_off + idx * 8)
        return '%s->%s:%s' % (self.type_(ci), self.string(ni), self.type_(ti))

    def classes(self):
        for i in range(self.class_defs_size):
            o = self.class_defs_off + i * 32
            ci, af, sci, ifo, sfi, ano, cdo, svo = struct.unpack_from('<8I', self.d, o)
            yield self.type_(ci), af, cdo

    def methods_of(self, class_desc):
        for desc, af, cdo in self.classes():
            if desc != class_desc:
                continue
            if not cdo:
                return []
            o = cdo
            sf, o = uleb(self.d, o)
            inf, o = uleb(self.d, o)
            dm, o = uleb(self.d, o)
            vm, o = uleb(self.d, o)
            out = []
            for _ in range(sf + inf):
                _, o = uleb(self.d, o); _, o = uleb(self.d, o)
            midx = 0
            for _ in range(dm):
                diff, o = uleb(self.d, o); midx += diff
                flags, o = uleb(self.d, o); code, o = uleb(self.d, o)
                out.append((self.method(midx), flags, code))
            midx = 0
            for _ in range(vm):
                diff, o = uleb(self.d, o); midx += diff
                flags, o = uleb(self.d, o); code, o = uleb(self.d, o)
                out.append((self.method(midx), flags, code))
            return out
        return []

    def ref(self, op, idx):
        try:
            if op in (0x1a,):
                return '"%s"' % self.string(idx)
            if op == 0x1b:
                return '"%s"' % self.string(idx)
            if op in (0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25):
                return self.type_(idx)
            if op in (0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
                return self.method(idx)
            if 0x52 <= op <= 0x6d:
                return self.field(idx)
            return '@%d' % idx
        except Exception as e:
            return '@%d<%s>' % (idx, e)

    def disasm(self, code_off, base_addr=0):
        d = self.d
        regs, ins, outs, tries, dbg, n = struct.unpack_from('<HHHHII', d, code_off)
        o = code_off + 16
        insns = struct.unpack_from('<%dH' % n, d, o)
        out = []
        i = 0
        while i < n:
            u = insns[i]
            op = u & 0xFF
            nm, fmt = OPS.get(op, ('*unused/0x%02x*' % op, '10x'))
            sz = SIZE.get(fmt, 1)
            raw = insns[i:i + sz]
            txt = self._fmt(op, fmt, raw, i, base_addr)
            out.append('%08x  %-22s %s' % ((base_addr + i), nm, txt))
            i += sz
        return out, regs

    def _fmt(self, op, fmt, w, i, base):
        if fmt == '10x':
            return ''
        if fmt == '12x':
            return 'v%d, v%d' % ((w[0] >> 8) & 0xF, (w[0] >> 12) & 0xF)
        if fmt == '11n':
            lit = (w[0] >> 12) & 0xF
            if lit & 8: lit -= 16
            return 'v%d, #%d' % ((w[0] >> 8) & 0xF, lit)
        if fmt == '11x':
            return 'v%d' % ((w[0] >> 8) & 0xFF)
        if fmt == '10t':
            off = (w[0] >> 8) & 0xFF
            if off & 0x80: off -= 0x100
            return '-> %08x' % (base + i + off)
        if fmt == '20t':
            off = struct.unpack('<h', struct.pack('<H', w[1]))[0]
            return '-> %08x' % (base + i + off)
        if fmt == '22x':
            return 'v%d, v%d' % ((w[0] >> 8) & 0xFF, w[1])
        if fmt == '21t':
            off = struct.unpack('<h', struct.pack('<H', w[1]))[0]
            return 'v%d, -> %08x' % ((w[0] >> 8) & 0xFF, base + i + off)
        if fmt == '21s':
            v = struct.unpack('<h', struct.pack('<H', w[1]))[0]
            return 'v%d, #%d' % ((w[0] >> 8) & 0xFF, v)
        if fmt == '21h':
            v = struct.unpack('<i', struct.pack('<i', w[1] << 16))[0]
            return 'v%d, #%d' % ((w[0] >> 8) & 0xFF, v)
        if fmt == '21c':
            return 'v%d, %s' % ((w[0] >> 8) & 0xFF, self.ref(op, w[1]))
        if fmt == '23x':
            return 'v%d, v%d, v%d' % ((w[0] >> 8) & 0xFF, w[1] & 0xFF, w[1] >> 8)
        if fmt == '22b':
            v = (w[1] >> 8) & 0xFF
            if v & 0x80: v -= 0x100
            return 'v%d, v%d, #%d' % ((w[0] >> 8) & 0xFF, w[1] & 0xFF, v)
        if fmt == '22t':
            off = struct.unpack('<h', struct.pack('<H', w[1]))[0]
            return 'v%d, v%d, -> %08x' % ((w[0] >> 8) & 0xF, (w[0] >> 12) & 0xF, base + i + off)
        if fmt == '22s':
            v = struct.unpack('<h', struct.pack('<H', w[1]))[0]
            return 'v%d, v%d, #%d' % ((w[0] >> 8) & 0xF, (w[0] >> 12) & 0xF, v)
        if fmt == '22c':
            return 'v%d, v%d, %s' % ((w[0] >> 8) & 0xF, (w[0] >> 12) & 0xF, self.ref(op, w[1]))
        if fmt == '32x':
            return 'v%d, v%d' % (w[1], w[2])
        if fmt == '30t':
            off = struct.unpack('<i', struct.pack('<I', w[1] | (w[2] << 16)))[0]
            return '-> %08x' % (base + i + off)
        if fmt == '31i':
            v = struct.unpack('<i', struct.pack('<I', w[1] | (w[2] << 16)))[0]
            return 'v%d, #%d' % ((w[0] >> 8) & 0xFF, v)
        if fmt == '31t':
            off = struct.unpack('<i', struct.pack('<I', w[1] | (w[2] << 16)))[0]
            return 'v%d, -> %08x' % ((w[0] >> 8) & 0xFF, base + i + off)
        if fmt == '31c':
            return 'v%d, %s' % ((w[0] >> 8) & 0xFF, self.ref(op, w[1] | (w[2] << 16)))
        if fmt == '35c':
            cnt = (w[0] >> 12) & 0xF
            g = (w[0] >> 8) & 0xF
            regs = [w[2] & 0xF, (w[2] >> 4) & 0xF, (w[2] >> 8) & 0xF, (w[2] >> 12) & 0xF, w[2] >> 12]
            rs = [regs[k] for k in range(cnt)]
            return '{%s}, %s' % (', '.join('v%d' % r for r in rs), self.ref(op, w[1]))
        if fmt == '3rc':
            cnt = (w[0] >> 8) & 0xFF
            first = w[2]
            return '{v%d..v%d}, %s' % (first, first + cnt - 1, self.ref(op, w[1]))
        if fmt == '51l':
            v = struct.unpack('<q', struct.pack('<q', w[1] | (w[2] << 16) | (w[3] << 32) | (w[4] << 48)))[0]
            return 'v%d, #%d' % ((w[0] >> 8) & 0xFF, v)
        return repr(list(w))
