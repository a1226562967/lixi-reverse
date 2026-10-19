#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only; capstone optional), file: elfprobe.py
# purpose: 一条命令把"未知二进制"判成：正常程序 / 自解密壳桩 / 强加密载荷 / 伪代码填充 /
#          内核模块 / 容器(拼接/压缩) / 未知。全部判据算法无关，数值化输出，带证据等级。
# usage:  python elfprobe.py <file> [--json out.json] [--cap 0x100000] [--quiet]
# 纪律:   只读。不下结论"这是某某壳"----壳名要靠 ≥2 证据交叉，本脚本只给形态。

import sys, os, json, math, struct, hashlib, argparse
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from zh import zh_list  # 判定标签中文化

AARCH64, ARM, X86, X64 = 183, 40, 3, 62
ET = {0: 'NONE', 1: 'REL(内核模块/可重定位)', 2: 'EXEC', 3: 'DYN(PIE/so)', 4: 'CORE'}
EM = {AARCH64: 'AARCH64', ARM: 'ARM', X86: 'X86', X64: 'X86_64', 8: 'MIPS', 243: 'RISCV'}

# ---- AArch64 精确编码（小端扫描用） ----
def u32s(d, start, end):
    end = min(end, len(d) - 3)
    return struct.unpack_from('<%dI' % ((end - start) // 4), d, start) if end > start else ()

PAT_DC_CVAU = 0xD50B7B20  # DC CVAU, X0  (capstone 实测；Rt 在 bit0..4)
PAT_IC_IVAU = 0xD50B7520  # IC IVAU, X0
PAT_DSB_ISH = 0xD5033B9F
PAT_ISB     = 0xD5033FDF
MASK_DC  = 0xFFFFFFE0    # 清 Rt (bit0..4)
MASK_BR  = 0xFFFFFC1F
BR_XN, BLR_XN = 0xD61F0000, 0xD63F0000
MASK_ADRP = 0x9F000000
ADRP = 0x90000000
ADR_ = 0x10000000


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
            p = k / n
            e -= p * math.log2(p)
    return e


def ent_profile(d, win=4096):
    vals = [entropy(d[o:o + win]) for o in range(0, max(1, len(d) - win + 1), win)]
    if not vals:
        return {'win': win, 'min': 0, 'max': 0, 'mean': 0, 'n': 0, 'hi_frac': 0}
    hi = sum(1 for v in vals if v >= 7.5)
    return {'win': win, 'min': round(min(vals), 3), 'max': round(max(vals), 3),
            'mean': round(sum(vals) / len(vals), 3), 'n': len(vals),
            'hi_frac': round(hi / len(vals), 3)}


def _norm(w):
    # 6-gram 必须归一化：把地址/偏移位掩掉，否则同一惯用法因地址不同被判成不同（KB 实测算法）
    if (w & 0x7C000000) == 0x14000000: return w & 0xFC000000      # B / BL
    if (w & 0xFF000010) == 0x54000000: return w & 0xFF00001F      # B.cond
    if (w & 0x7E000000) in (0x34000000, 0x36000000): return w & 0x7F00001F   # CBZ / CBNZ / TBZ / TBNZ
    if (w & 0x1F000000) == 0x10000000: return w & 0x9F00001F      # ADR / ADRP
    if (w & 0x1F000000) in (0x11000000, 0x51000000, 0x91000000, 0xD1000000):
        return w & 0xFFC003FF                                     # ADD/SUB imm
    if (w & 0x3B000000) in (0x39000000, 0x3D000000): return w & 0xFFC003FF   # LDR/STR imm12
    if (w & 0x3B200000) == 0x38000000: return w & 0xFFE00C00      # pre/post index
    return w


def uniq_6gram(d, n=6, cap=0x400000):
    """6-gram 归一化唯一率（指令级，非字节级）。
    <0.75 真代码 / 0.75-0.97 混合 / >0.97 不是编译产物。
    样本不足 128 条指令 → None（宁可不说，不给假数值）。"""
    b = d[:cap]
    m = len(b) // 4
    if m < 128:
        return None
    ws = []
    for i in range(m):
        w = struct.unpack_from('<I', b, i * 4)[0]
        w = _norm(w)
        if w in (0, 0xD503201F):   # 零与 NOP 是填充噪声，剔掉
            continue
        ws.append(w)
    if len(ws) < 128:
        return None
    g = set()
    for i in range(len(ws) - n):
        g.add(tuple(ws[i:i + n]))
    return round(len(g) / (len(ws) - n), 4)


def top1_profile(d, bs=4096, cap=0x100000):
    """最便宜的粗筛（秒级）：4KB 块最高频字节占比。
    真密文 ≈0.39%（理论下界），混淆指令流 2%-6%。"""
    b = d[:cap]
    tops = []
    for o in range(0, max(1, len(b) - bs + 1), bs):
        blk = b[o:o + bs]
        if not blk:
            continue
        cnt = [0] * 256
        for x in blk:
            cnt[x] += 1
        tops.append(max(cnt) / len(blk))
    if not tops:
        return None
    return {'mean': round(sum(tops) / len(tops), 4), 'max': round(max(tops), 4), 'n': len(tops)}


def zblocks_dup(d, cap=0x200000):
    # 16 字节块零重复率：~1.0 且熵~7.99 → 强加密
    b = d[:cap]
    n = len(b) // 16
    if n < 16:
        return 1.0
    s = set()
    for i in range(n):
        s.add(b[i * 16:i * 16 + 16])
    return round(len(s) / n, 4)


class Elf:
    def __init__(self, d):
        self.d = d
        self.ok = d[:4] == b'\x7fELF'
        if not self.ok:
            return
        self.cls = d[4]          # 1=32 2=64
        self.e = '<' if d[5] == 1 else '>'
        E = self.e
        self.type, self.machine, self.version, self.entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(E + 'HHIQQQIHHHHHH', d, 16)
        self.phoff, self.phnum, self.phentsize = phoff, phnum, phentsize
        self.shoff, self.shnum, self.shentsize, self.shstrndx = shoff, shnum, shentsize, shstrndx
        self.phdrs = []
        for i in range(phnum):
            o = phoff + i * phentsize
            if o + phentsize > len(d) or phentsize < 32:
                break
            if self.cls == 2:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(E + 'IIQQQQQQ', d, o)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(E + 'IIIIIIII', d, o)
            self.phdrs.append(dict(type=p_type, flags=p_flags, off=p_offset, vaddr=p_vaddr,
                                   filesz=p_filesz, memsz=p_memsz, align=p_align))
        self.sections = []
        if shnum and shoff and shoff + shnum * shentsize <= len(d):
            raw = []
            for i in range(shnum):
                o = shoff + i * shentsize
                if self.cls == 2:
                    nm, ty, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from(E + 'IIQQQQIIQQ', d, o)
                else:
                    nm, ty, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from(E + 'IIIIIIIIII', d, o)
                raw.append((nm, ty, fl, ad, of, sz))
            # shstrtab
            names = b''
            if shstrndx < len(raw):
                _, _, _, _, of, sz = raw[shstrndx]
                names = d[of:of + sz]
            for nm, ty, fl, ad, of, sz in raw:
                s = ''
                if names and nm < len(names):
                    end = names.find(b'\0', nm)
                    s = names[nm:end].decode('latin1', 'replace')
                self.sections.append(dict(name=s, type=ty, flags=fl, addr=ad, off=of, size=sz))
        self.symtab = None

    def load_segments(self):
        return [p for p in self.phdrs if p['type'] == 1]

    def rx(self):
        # 可执行段：flags PF_X=1
        return [p for p in self.phdrs if p['type'] == 1 and (p['flags'] & 1)]

    def v2o(self, v):
        for p in self.load_segments():
            if p['vaddr'] <= v < p['vaddr'] + max(p['filesz'], p['memsz']):
                return p['off'] + (v - p['vaddr'])
        return None

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def dynamic_entries(self):
        """不依赖节表读 PT_DYNAMIC（加固 ELF 常把 shnum 裁到个位数）"""
        if hasattr(self, '_dyn'):
            return self._dyn
        out = []
        cands = [p for p in self.phdrs if p['type'] == 2]
        s = self.section('.dynamic')
        if s and s['size']:
            cands.append(dict(off=s['off'], filesz=s['size']))
        ent = 16 if self.cls == 2 else 8
        for p in cands:
            off, sz = p['off'], p.get('filesz', 0)
            if not sz:
                continue
            for i in range(min(sz // ent, 4096)):
                o = off + i * ent
                if o + ent > len(self.d):
                    break
                if self.cls == 2:
                    tag, val = struct.unpack_from(self.e + 'qQ', self.d, o)
                else:
                    tag, val = struct.unpack_from(self.e + 'iI', self.d, o)
                if tag == 0:
                    break
                out.append((tag, val))
            break
        self._dyn = out
        return out

    def dyn(self, tag):
        for t, v in self.dynamic_entries():
            if t == tag:
                return v
        return None

    def strtab(self):
        """(文件偏移, 长度) —— 由 DT_STRTAB + DT_STRSZ 定位"""
        va = self.dyn(5)
        sz = self.dyn(10) or 0
        if va is None:
            s = self.section('.dynstr')
            return (s['off'], s['size']) if s else (None, 0)
        off = self.v2o(va)
        return (off, sz)

    def imports(self):
        """未定义符号数：优先 PT_DYNAMIC 的 DT_SYMTAB/DT_HASH（节表被裁也能算）。
        结论缺失时要显式标 unknown —— 别得出"应用没调用任何 libc"的荒谬结论。"""
        syms, names = 0, []
        symva = self.dyn(6)
        stroff, strsz = self.strtab()
        ent = 24 if self.cls == 2 else 16
        if symva is not None and stroff is not None:
            symoff = self.v2o(symva)
            if symoff is not None:
                # 符号表长度：优先 DT_HASH.nchain，其次用 strtab 起点反推
                n = None
                h = self.dyn(4)
                if h is not None:
                    ho = self.v2o(h)
                    if ho is not None and ho + 8 <= len(self.d):
                        nb, nchain = struct.unpack_from(self.e + 'II', self.d, ho)
                        if 0 < nchain < 500000:
                            n = nchain
                if n is None and stroff > symoff:
                    n = min((stroff - symoff) // ent, 200000)
                if n is None:
                    n = 0
                for i in range(n):
                    o = symoff + i * ent
                    if o + ent > len(self.d):
                        break
                    if self.cls == 2:
                        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(self.e + 'IBBHQQ', self.d, o)
                    else:
                        st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(self.e + 'IIIBBH', self.d, o)
                    if st_shndx == 0 and st_name and (not strsz or st_name < strsz):
                        syms += 1
                        if len(names) < 32:
                            so = stroff + st_name
                            e2 = self.d.find(b'\0', so)
                            if 0 < so < len(self.d) and e2 > so:
                                names.append(self.d[so:e2].decode('latin1', 'replace'))
        if syms == 0:
            s = self.section('.dynsym')
            if s and s['size']:
                for i in range(s['size'] // ent):
                    o = s['off'] + i * ent
                    if o + ent > len(self.d):
                        break
                    if self.cls == 2:
                        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(self.e + 'IBBHQQ', self.d, o)
                    else:
                        st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(self.e + 'IIIBBH', self.d, o)
                    if st_shndx == 0 and st_name:
                        syms += 1
        return syms, names

    def needed(self):
        out = []
        stroff, strsz = self.strtab()
        if stroff is None:
            return out
        for t, v in self.dynamic_entries():
            if t != 1:
                continue
            so = stroff + v
            if 0 < so < len(self.d):
                end = self.d.find(b'\0', so)
                if end > so:
                    out.append(self.d[so:end].decode('latin1', 'replace'))
        return out

    def strings_in(self, lo, hi, minlen=4):
        b = self.d[lo:hi]
        out = []
        for m in b.split(b'\0'):
            if len(m) >= minlen:
                try:
                    out.append(m.decode('utf-8'))
                except Exception:
                    out.append(m.decode('latin1', 'replace'))
        return out



def _adrp(w, pc):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((pc & ~0xFFF) + (imm << 12), w & 0x1F)


def data_segment_stats(elf, d, min_size=1 << 20, ent_probe=1 << 20):
    """非执行 PT_LOAD 段：大小/熵/被代码引用次数（adrp+add/ldr 配对）。
    用途：判"明文 loader + 段内大块高熵数据（载荷/密文）"这种形态。"""
    import math as _m
    def ent(b):
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
                e -= q * _m.log2(q)
        return round(e, 2)
    segs = [p for p in elf.phdrs if p['type'] == 1 and p['filesz']]
    data = [p for p in segs if not (p['flags'] & 1) and p['filesz'] >= min_size]
    if not data:
        return []
    rx = [p for p in segs if (p['flags'] & 1) and p['filesz']]
    refs = {id(x): 0 for x in data}
    for p in rx:
        off, va, sz = p['off'], p['vaddr'], min(p['filesz'], len(d) - p['off'])
        n = sz // 4
        last = None
        for i in range(n):
            try:
                w = struct.unpack_from('<I', d, off + i * 4)[0]
            except Exception:
                break
            pc = va + i * 4
            t = _adrp(w, pc)
            if t:
                last = t
                continue
            if not last:
                continue
            rn = (w >> 5) & 0x1F
            is_add = (w & 0xFF800000) == 0x91000000
            is_ld = (w & 0xFFC00000) in (0xF9400000, 0xB9400000, 0x39400000, 0x39000000)
            if rn == last[1] and (is_add or is_ld):
                tgt = last[0] + ((w >> 10) & 0xFFF)
                for x in data:
                    if x['vaddr'] <= tgt < x['vaddr'] + max(x['memsz'], x['filesz']):
                        refs[id(x)] += 1
                last = None
    out = []
    for x in data:
        blk = d[x['off']:x['off'] + min(x['filesz'], ent_probe)]
        out.append(dict(vaddr=hex(x['vaddr']), size=x['filesz'], entropy=ent(blk),
                        refs=refs[id(x)], zerobyte=round(blk.count(0) / max(1, len(blk)), 4)))
    return out


def scan_arm64(d):
    hits = {'cache_va': 0, 'dc_cvau': 0, 'ic_ivau': 0, 'dsb_ish': 0, 'isb': 0, 'br': 0, 'blr': 0,
            'adrp': 0, 'adr': 0, 'adrp_pairs': 0, 'strb': 0}
    n = len(d) // 4
    last_rd, last_i = None, -99
    for i in range(n):
        w = struct.unpack_from('<I', d, i * 4)[0]
        if (w & 0xFFFFF000) == 0xD50B7000:      # DC/IC by VA/CV 家族（宽判据，不易误报）
            hits['cache_va'] += 1
            if (w & MASK_DC) == PAT_DC_CVAU:
                hits['dc_cvau'] += 1
            elif (w & MASK_DC) == PAT_IC_IVAU:
                hits['ic_ivau'] += 1
        elif w == PAT_DSB_ISH:
            hits['dsb_ish'] += 1
        elif w == PAT_ISB:
            hits['isb'] += 1
        elif (w & 0xFFFF0000) == 0xD61F0000 or (w & 0xFFFF0000) == 0xD63F0000:
            if (w & MASK_BR) == BR_XN:
                hits['br'] += 1
            elif (w & MASK_BR) == BLR_XN:
                hits['blr'] += 1
        elif (w & MASK_ADRP) == ADRP:
            hits['adrp'] += 1
            last_rd, last_i = w & 0x1F, i          # 记下 Rd，等它的配对指令
        elif (w & 0x9F000000) == ADR_:
            hits['adr'] += 1
        else:
            # 引用密度只数"配对"：ADRP Rd + ADD/LDR/STR Rn==Rd（8 条内）。
            # 裸数 ADRP 在密文上会被随机命中污染（实测 43MB 加固体裸数 150266，全是噪声）。
            if last_rd is not None and i - last_i <= 8:
                rn = (w >> 5) & 0x1F
                is_add = (w & 0xFF800000) == 0x91000000
                is_ldst = (w & 0xFFC00000) in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000)
                if rn == last_rd and (is_add or is_ldst):
                    hits['adrp_pairs'] += 1
                    last_rd = None
            if (w & 0xFFC00000) == 0x39000000:  # STRB (imm)
                hits['strb'] += 1
    return hits


def disasm_invalid(elf, cap=0x80000):
    try:
        import capstone
    except Exception:
        return None
    try:
        segs = [p for p in elf.load_segments() if (p['flags'] & 1)] or elf.load_segments()
        tail = []
        for p in segs[:3]:
            if not p['filesz']:
                continue
            tail.append(elf.d[p['off']:p['off'] + min(p['filesz'], cap)])
        b = b''.join(tail)
        if not b:
            return None
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = False
        md.skipdata = True   # 必须：不加这句遇到非法编码会抛 CsError，密文必然触发
        ok = bad = 0
        for ins in md.disasm(b, elf.entry):
            if ins.mnemonic.startswith('.') or ins.mnemonic in ('udf', 'invalid'):
                bad += 1
            else:
                ok += 1
        tot = ok + bad
        if not tot:
            return None
        return {'invalid_frac': round(bad / tot, 4), 'n': tot}
    except Exception:
        return None


COMPRESS_MAGICS = [
    (b'\xfd7zXZ\x00', 'xz'), (b'\x1f\x8b\x08', 'gzip'), (b'BZh', 'bzip2'),
    (b'\x5d\x00\x00\x80\x00', 'lzma-alone'), (b'\x78\x01', 'zlib'), (b'\x78\x5e', 'zlib'),
    (b'\x78\x9c', 'zlib'), (b'\x78\xda', 'zlib'), (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'Rar!\x1a\x07', 'rar'), (b'PK\x03\x04', 'zip'), (b'\x28\xb5\x2f\xfd', 'zstd'),
    (b'\x04\x22\x4d\x18', 'lz4'),
]


def scan_compress(d, max_try=2000):
    """标准压缩流：命中 -> 不是加密，是压缩（可直接脱）。0 命中也是一条信息。"""
    out = []
    for off in range(0, min(len(d), 0x4000000)):
        if len(out) >= max_try:
            break
        if d[off] in (0xfd, 0x1f, 0x42, 0x5d, 0x78, 0x37, 0x52, 0x50, 0x28, 0x04):
            for mg, nm in COMPRESS_MAGICS:
                if d.startswith(mg, off):
                    out.append({'off': hex(off), 'kind': nm})
                    break
    return out


def carve_elf(d, min_size=0x1000, limit=64, skip_self=True):
    """内嵌 ELF 候选：三重边界证据（ELF 头 + phdr 可解析 + 该段文件内自洽）。"""
    out = []
    i = 0
    n = len(d)
    while True:
        i = d.find(b'\x7fELF', i)
        if i < 0 or len(out) >= limit:
            break
        if skip_self and i == 0:
            i += 4
            continue
        c = {}
        try:
            cls, enc = d[i + 4], d[i + 5]
            if cls not in (1, 2) or enc not in (1, 2):
                raise ValueError('bad class/enc')
            E = '<' if enc == 1 else '>'
            e_type, e_machine = struct.unpack_from(E + 'HH', d, i + 16)
            if e_type not in (1, 2, 3, 4):
                raise ValueError('bad e_type')
            if cls == 2:
                e_entry, phoff, shoff = struct.unpack_from(E + 'QQQ', d, i + 24)
                ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(E + 'HHHHH', d, i + 52)
                base = i
                ph_ok = 0
                for k in range(min(phnum, 32)):
                    o = base + (phoff - (0 if phoff < n else 0)) + k * phentsize
                    if o < 0 or o + 56 > n:
                        break
                    p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(E + 'IIQQQQQQ', d, o)
                    if p_type in (1,) and p_filesz and base + p_off + p_filesz <= n + 0x100000:
                        ph_ok += 1
            else:
                e_entry, phoff, shoff = struct.unpack_from(E + 'III', d, i + 24)
                ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(E + 'HHHHH', d, i + 40)
                base = i
                ph_ok = 0
                for k in range(min(phnum, 32)):
                    o = base + phoff + k * phentsize
                    if o + 32 > n:
                        break
                    p_type, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(E + 'IIIIIIII', d, o)
                    if p_type == 1 and p_filesz and base + p_off + p_filesz <= n + 0x100000:
                        ph_ok += 1
            phoff_rel = 'file-relative' if (base + phoff) < n and ph_ok else 'unknown'
            c = dict(off=hex(i), off_dec=i, cls=cls, machine=EM.get(e_machine, hex(e_machine)),
                     e_type=ET.get(e_type, e_type), entry=hex(e_entry), phnum=phnum, shnum=shnum,
                     ph_ok=ph_ok, phoff=hex(phoff), guess=phoff_rel)
        except Exception as ex:
            c = dict(off=hex(i), off_dec=i, error=str(ex))
        out.append(c)
        i += 4
    return out


def verdict(r):
    """形态定性（不是壳名）。每条都附 evidence。"""
    tags = []
    ev = {}
    d = r['header']
    etype = r['elf'].get('e_type_raw')
    if r['is_elf']:
        if etype == 1:
            tags.append('KERNEL-MODULE(REL)')
        segs = r['elf']['load_segments']
        rx = r['elf']['rx_segments']
        imp = r['elf']['import_count'] or 0
        interp = r['elf']['interp']
        dyn = r['elf']['has_dynamic']
        if etype in (2, 3) and not interp and not dyn and not segs:
            tags.append('NO-LOADER(非常规可执行: 无法被系统加载器拉起)')
        if segs and len(segs) <= 3 and not dyn and not interp:
            tags.append('SELF-LOADED-PAYLOAD(只有 LOAD 段, 无 dynamic/interp/import)')
        fz0 = r['elf'].get('filesz0_segments') or []
        if fz0:
            tot = sum(x['memsz'] for x in fz0) / 1048576.0
            tags.append('FILESZ0-SEGMENT(%d 段 filesz=0 而 memsz 合计 %.1f MB -> 磁盘上没有代码, 运行期才填: 商业加固最强判据)' % (len(fz0), tot))
        # 只有在"整块看起来是代码"时才说正常程序；45MB 加密区里也带 interp/dynamic 的 PIE 不是"正常"
        if interp and dyn and imp > 20:
            _u = r.get('uniq6')
            if _u is None or _u < 0.9:
                tags.append('NORMAL-DYNAMIC(被 linker 拉起的正常程序)')
            else:
                tags.append('HYBRID(带 interp/dynamic 但主体非代码: 明文壳+加密区混合)')
        if rx and r['elf']['entry_in_rx'] is not None:
            pos = r['elf']['entry_in_rx']
            if pos > 0.85:
                tags.append('SELF-DECRYPT-STUB(入口在 RX 段尾部 %0.2f)' % pos)
        e = r['entropy']['rx'] or r['entropy']['whole']
        if e and e['mean'] >= 7.7:
            tags.append('HIGH-ENTROPY(加密或压缩)')
        if r['zdup'] >= 0.999 and (e and e['mean'] >= 7.95):
            tags.append('STRONG-CIPHER(熵~7.99 + 16B 块几乎零重复)')
        for ds in (r.get('data_segments') or []):
            if ds['entropy'] > 7.5:
                if ds['refs'] == 0:
                    tags.append('BIG-ENTROPY-DATA(%s, %.1f MB, 熵=%s, 引用=0 -> 静态零引用: 运行期才产生/外部注入)'
                                % (ds['vaddr'], ds['size'] / 1048576.0, ds['entropy']))
                else:
                    tags.append('BIG-ENTROPY-DATA(%s, %.1f MB, 熵=%s, 引用=%d -> 数据载荷/密文, 代码在用它: 找解压/解密例程的调用点)'
                                % (ds['vaddr'], ds['size'] / 1048576.0, ds['entropy'], ds['refs']))
        if any(ds['size'] > 4 * 1048576 and ds['entropy'] > 7.5 for ds in (r.get('data_segments') or [])):
            tags.append('NO-FULL-EMULATION(有 >4MB 高熵数据段: 禁止整程序离线模拟 -> 只找消费这段的例程)')
        h = r['arm64']
        if h and (h['cache_va'] or h['dc_cvau'] or h['ic_ivau']):
            tags.append('CACHE-MAINT(cache 维护指令 -> 会改写并执行自己解出来的代码)')
        # 最便宜的一维先粗筛：top1 字节占比
        t1 = r.get('top1')
        emean = e['mean'] if e else 0
        if t1 and emean > 7.85 and t1['mean'] < 0.012:
            tags.append('CIPHER(真密文: 熵>7.85 且 top1<1.2%)')
        elif t1 and emean > 7.5 and t1['mean'] >= 0.012:
            tags.append('OBF(混淆指令流: 熵>7.5 但 top1>=1.2%)')
        # 确认维：6-gram 归一化唯一率（<0.75 代码 / 0.75-0.97 混合 / >0.97 非编译产物）
        u = r['uniq6']
        if u is not None:
            if u < 0.75:
                tags.append('CODE-LIKE(6-gram 唯一率 %.3f < 0.75)' % u)
            elif u <= 0.97:
                tags.append('MIXED(6-gram 唯一率 %.3f 落在 0.75-0.97)' % u)
            else:
                tags.append('NOT-COMPILED(6-gram 唯一率 %.3f > 0.97: 密文或逐条随机生成)' % u)
        # 引用密度：代码 ~5000/MB，伪代码填充 ~50/MB，密文 0
        if r['arm64']:
            xm = r['xref_per_mb']
            # 采信条件：uniq 未知或 <0.9，且不是高熵密文。密文区里 ADRP 配对是随机噪声。
            trusted = (u is None or u < 0.9) and emean < 7.6
            if not trusted:
                tags.append('XREF-NOT-TRUSTED(%.0f/MB 但样本是密文/混合体, 引用密度不可采信)' % xm)
                xm = None
            if xm == 0:
                tags.append('ZERO-XREF(0 条 ADRP/ADR -> 没有引用 -> 不是真代码)')
            elif xm is not None and xm < 300:
                tags.append('LOW-XREF(%.0f/MB << 代码基准 ~5000/MB -> 伪代码填充嫌疑)' % xm)
            elif xm is not None:
                tags.append('XREF-NORMAL(%.0f/MB 接近代码基准)' % xm)
        if r['compress']:
            tags.append('STANDARD-COMPRESSION(%s)' % ','.join(sorted({c['kind'] for c in r['compress']})))
    else:
        if r['zip_like']:
            tags.append('ZIP-CONTAINER(APK/JAR/ZIP)')
        if r['dex_like']:
            tags.append('DEX')
    if not tags:
        tags.append('UNKNOWN(证据不足, 继续取数)')
    return tags


def probe(path, cap_hex=None):
    d = open(path, 'rb').read()
    raw_cap = int(cap_hex, 0) if cap_hex else 0
    head = d[:16]
    r = {
        'path': os.path.abspath(path), 'size': len(d),
        'sha256': hashlib.sha256(d).hexdigest(),
        'header': head.hex(' '),
        'is_elf': d[:4] == b'\x7fELF',
        'zip_like': d[:4] == b'PK\x03\x04',
        'dex_like': d[:4] == b'dex\n',
        'gzip': d[:3] == b'\x1f\x8b\x08',
        'shell_text': (d[:2] == b'#!' or (d[:1] == b'#' and b'\n' in d[:200])),
    }
    if raw_cap:
        d = d[:raw_cap]
    if r['is_elf']:
        elf = Elf(d)
        segs = elf.load_segments()
        rx = elf.rx()
        entry = elf.entry
        entry_in_rx = None
        entry_tail_bytes = None
        for p in rx:
            if p['vaddr'] <= entry < p['vaddr'] + max(p['filesz'], p['memsz']):
                span = max(p['filesz'], p['memsz'])
                entry_in_rx = round((entry - p['vaddr']) / span, 4)
                entry_tail_bytes = p['vaddr'] + p['filesz'] - entry
                break
        imp_n, imp_names = elf.imports()
        interp = elf.section('.interp')
        interp_s = None
        if interp and interp['size']:
            interp_s = d[interp['off']:interp['off'] + interp['size']].split(b'\0')[0].decode('latin1', 'replace')
        else:
            for p in elf.phdrs:
                if p['type'] == 3 and p['filesz']:
                    interp_s = d[p['off']:p['off'] + p['filesz']].split(b'\0')[0].decode('latin1', 'replace')
                    break
        fz0 = [p for p in segs if p['filesz'] == 0 and p['memsz'] > 0x100000]
        r['elf'] = {
            'filesz0_segments': [{'vaddr': hex(p['vaddr']), 'memsz': p['memsz'], 'flags': p['flags']} for p in fz0],
            'class': {1: 'ELF32', 2: 'ELF64'}.get(elf.cls, elf.cls),
            'endian': 'LE' if elf.e == '<' else 'BE',
            'e_type': ET.get(elf.type, elf.type), 'e_type_raw': elf.type,
            'machine': EM.get(elf.machine, hex(elf.machine)),
            'entry': hex(entry),
            'phnum': elf.phnum, 'shnum': elf.shnum,
            'load_segments': [{'off': hex(p['off']), 'vaddr': hex(p['vaddr']), 'filesz': p['filesz'],
                               'memsz': p['memsz'], 'flags': p['flags'], 'exec': bool(p['flags'] & 1)} for p in segs],
            'rx_segments': [{'off': hex(p['off']), 'vaddr': hex(p['vaddr']), 'filesz': p['filesz']} for p in rx],
            'entry_in_rx': entry_in_rx, 'entry_tail_bytes': entry_tail_bytes,
            'interp': interp_s, 'has_dynamic': bool(elf.section('.dynamic')),
            'import_count': imp_n, 'needed': elf.needed(),
            'modinfo': _modinfo(d),
            'sections': [s['name'] for s in elf.sections if s['name']],
        }
        # 熵
        whole = ent_profile(d)
        rxprof = None
        if rx:
            p = max(rx, key=lambda x: x['filesz'])
            rxprof = ent_profile(d[p['off']:p['off'] + p['filesz']])
        r['entropy'] = {'whole': whole, 'rx': rxprof}
        r['uniq6'] = uniq_6gram(d)
        r['top1'] = top1_profile(d)
        r['zdup'] = zblocks_dup(d)
        r['data_segments'] = data_segment_stats(elf, d)
        r['arm64'] = scan_arm64(d) if elf.machine in (AARCH64, ARM) else None
        r['disasm'] = disasm_invalid(elf)
        refs = (r['arm64']['adrp_pairs'] + r['arm64']['adr']) if r['arm64'] else 0
        r['xref_per_mb'] = round(refs / (len(d) / 1048576.0), 1) if len(d) else 0
    else:
        r['entropy'] = {'whole': ent_profile(d), 'rx': None}
        r['uniq6'] = uniq_6gram(d)
        r['top1'] = top1_profile(d)
        r['zdup'] = zblocks_dup(d)
        r['disasm'] = None
        r['elf'] = {}
        r['arm64'] = None
    r['compress'] = scan_compress(d)
    r['embedded_elf'] = carve_elf(d)[:16]
    r['verdict'] = verdict(r)
    return r


def _modinfo(d):
    out = {}
    for key in (b'vermagic=', b'name=', b'license=', b'depends=', b'import_ns=', b'srcversion='):
        vals = []
        start = 0
        while True:
            i = d.find(key, start)
            if i < 0:
                break
            end = d.find(b'\0', i)
            vals.append(d[i:end].decode('latin1', 'replace'))
            start = i + 1
        if vals:
            out[key.decode().rstrip('=')] = vals[:4]
    return out


def human(r):
    L = []
    L.append('== %s' % r['path'])
    L.append('   size=%d  sha256=%s' % (r['size'], r['sha256'][:16] + '...'))
    L.append('   head=%s  (ELF=%s zip=%s dex=%s gzip=%s shell=%s)' % (
        r['header'], r['is_elf'], r['zip_like'], r['dex_like'], r['gzip'], r['shell_text']))
    if r['is_elf']:
        e = r['elf']
        L.append('   ELF %s %s type=%s machine=%s entry=%s phnum=%d shnum=%d' % (
            e['class'], e['endian'], e['e_type'], e['machine'], e['entry'], e['phnum'], e['shnum']))
        L.append('   interp=%s  dynamic=%s  imports=%d  needed=%s' % (
            e['interp'], e['has_dynamic'], e['import_count'], e['needed'] or '-'))
        if e['load_segments']:
            for p in e['load_segments'][:6]:
                L.append('     LOAD off=%s vaddr=%s filesz=%d memsz=%d exec=%s' % (
                    p['off'], p['vaddr'], p['filesz'], p['memsz'], p['exec']))
        if e['entry_in_rx'] is not None:
            L.append('   entry 在 RX 段内位置=%.3f  距可执行尾部=%s 字节' % (e['entry_in_rx'], e['entry_tail_bytes']))
        if e['modinfo']:
            for k, v in e['modinfo'].items():
                L.append('   modinfo %s = %s' % (k, v))
    ent = r['entropy']['whole']
    L.append('   熵(4K窗): mean=%s min=%s max=%s 高熵窗口占比=%s  n=%d' % (
        ent['mean'], ent['min'], ent['max'], ent['hi_frac'], ent['n']))
    if r['entropy']['rx']:
        e2 = r['entropy']['rx']
        L.append('   熵(RX段): mean=%s max=%s 高熵占比=%s' % (e2['mean'], e2['max'], e2['hi_frac']))
    t1 = r.get('top1') or {}
    L.append('   top1 字节占比(粗筛): mean=%s max=%s   [CIPHER 需 <0.012 / OBF 实测 >=0.012]' % (t1.get('mean'), t1.get('max')))
    dz = r.get('disasm') or {}
    L.append('   反汇编无效指令比例=%s (n=%s)   [连续合法=代码 / 定期夹坏=伪代码填充 / 全坏=密文]' % (dz.get('invalid_frac'), dz.get('n')))
    L.append('   6-gram 唯一率=%s  [<0.75 代码 / 0.75-0.97 混合 / >0.97 非编译产物]  16B块唯一率=%s  接受率=%s' % (
        r['uniq6'] if r['uniq6'] is not None else 'n/a(样本不足)', r['zdup'], dz.get('invalid_frac')))
    if r['arm64']:
        a = r['arm64']
        L.append('   AArch64 指令面: DC_CVAU=%d IC_IVAU=%d DSB=%d ISB=%d BR=%d BLR=%d ADRP=%d ADR=%d STRB=%d  (xref/MB=%s)' % (
            a['dc_cvau'], a['ic_ivau'], a['dsb_ish'], a['isb'], a['br'], a['blr'], a['adrp'], a['adr'], a['strb'], r['xref_per_mb']))
    if r.get('data_segments'):
        L.append('   非执行段里的大块数据（这是"载荷藏在数据段"的判据）:')
        for ds in r['data_segments']:
            L.append('     %s  %.2f MB  熵=%s  零字节=%s  被代码引用 %d 次%s' % (
                ds['vaddr'], ds['size'] / 1048576.0, ds['entropy'], ds['zerobyte'], ds['refs'],
                '  <- 零引用: 运行期才产生/外部注入' if ds['refs'] == 0 else '  <- 代码在用它: 找解压/解密例程'))
            if ds['size'] > 4 * 1048576 and ds['entropy'] > 7.5:
                L.append('     ⚠ 别整程序离线模拟（百万级指令跑不完）；先找"谁消费这段"：解密/解压例程的调用点、或它被 mmap/read 进内存的位置')
    if r['compress']:
        kinds = {}
        for c in r['compress']:
            kinds.setdefault(c['kind'], []).append(c['off'])
        L.append('   标准压缩流命中: %s' % {k: v[:3] for k, v in kinds.items()})
    else:
        L.append('   标准压缩流命中: 0  (-> 非标准压缩: 加密 / 自研位流 / 未压缩)')
    if r['embedded_elf']:
        for c in r['embedded_elf'][:6]:
            L.append('   内嵌 ELF 候选 @%s  %s' % (c.get('off'), {k: v for k, v in c.items() if k not in ('off', 'off_dec')}))
    L.append('   >> 形态判定: %s' % zh_list(r['verdict']))
    return '\n'.join(L)


def main():
    if '--selftest' in sys.argv:
        return selftest()
    ap = argparse.ArgumentParser(description='算法无关的二进制形态判型（ELF/APK/dex/压缩/拼接）')
    ap.add_argument('target')
    ap.add_argument('--json', default='')
    ap.add_argument('--cap', default='')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()
    r = probe(a.target, a.cap or None)
    if not a.quiet:
        print(human(r))
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump(r, f, ensure_ascii=False, indent=2)
        print('[+] JSON -> %s' % a.json)
    return 0


def selftest():
    import tempfile
    # 1) 造一个最小 ELF64 AArch64：PT_LOAD 两段，入口在 RX 尾部，带 DC CVAU
    def mkelf(path, entry_tail=True, cipher=False, rx_size=0x20000):
        # 构造一张"自解密载荷"骨架：RX 段前部是密文/代码，尾部是 stub，entry 落在尾部
        nop = struct.pack('<I', 0xd503201f)
        stub = bytearray()
        stub += struct.pack('<I', 0xD50B7B20) * 2   # DC CVAU, X1
        stub += struct.pack('<I', 0xD50B7520) * 2   # IC IVAU, X1
        stub += struct.pack('<I', 0xD5033B9F)       # DSB ISH
        stub += struct.pack('<I', 0xD5033FDF)       # ISB
        stub += struct.pack('<I', 0xD61F0020)       # BR X1
        n_src = rx_size - len(stub)
        if cipher:
            body = bytes(bytearray(os.urandom(n_src)))
        else:
            body = bytearray()
            while len(body) < n_src:
                body += nop
                body += struct.pack('<I', 0xD61F0020)
            body = bytes(body[:n_src])
        code = body + bytes(stub)
        data_off = 0x40
        code_off = data_off + 0x1000
        ehsize, phentsize, phnum = 64, 56, 3
        phoff = 64
        total = code_off + len(code)
        b = bytearray(total)
        b[0:4] = b'\x7fELF'; b[4] = 2; b[5] = 1; b[6] = 1
        struct.pack_into('<HHI', b, 16, 3, 183, 1)  # DYN/AARCH64
        entry = 0x400000 + code_off + (len(code) - len(stub) if entry_tail else 0x10)
        struct.pack_into('<QQQ', b, 24, entry, phoff, 0)
        struct.pack_into('<IHHHHHH', b, 48, 0, ehsize, phentsize, phnum, 64, 0, 0)
        base = 0x400000
        struct.pack_into('<IIQQQQQQ', b, phoff, 1, 4, data_off, base + data_off, base + data_off, 0x1000, 0x1000, 0x1000)
        struct.pack_into('<IIQQQQQQ', b, phoff + 56, 1, 5, code_off, base + code_off, base + code_off, len(code), len(code), 0x1000)
        struct.pack_into('<IIQQQQQQ', b, phoff + 112, 1, 6, data_off, base + data_off, base + data_off, 0x10, 0x10, 0x1000)
        b[code_off:code_off + len(code)] = code
        open(path, 'wb').write(bytes(b))

    tmp = tempfile.mkdtemp()
    ok = True
    p1 = os.path.join(tmp, 'stub.elf')
    mkelf(p1)
    r = probe(p1)
    print(human(r))
    has = lambda tag: any(tag in t for t in r['verdict'])
    print('\n[selftest] stub.elf')
    print('  SELF-DECRYPT-STUB :', 'OK' if has('SELF-DECRYPT-STUB') else 'FAIL')
    print('  CACHE-MAINT       :', 'OK' if has('CACHE-MAINT') else 'FAIL')
    print('  CODE-LIKE         :', 'OK' if has('CODE-LIKE') else 'FAIL')
    ok &= has('CODE-LIKE')
    ok &= has('SELF-DECRYPT-STUB') and has('CACHE-MAINT')

    p2 = os.path.join(tmp, 'cipher.elf')
    mkelf(p2, cipher=True)
    r2 = probe(p2)
    has2 = lambda tag: any(tag in t for t in r2['verdict'])
    print('[selftest] cipher.elf')
    print('  HIGH-ENTROPY      :', 'OK' if has2('HIGH-ENTROPY') else 'FAIL')
    print('  NOT-COMPILED      :', 'OK' if has2('NOT-COMPILED') else 'FAIL')
    ok &= has2('NOT-COMPILED')
    print('  熵=%s 6gram=%s' % (r2['entropy']['whole']['mean'], r2['uniq6']))
    ok &= has2('HIGH-ENTROPY')

    # 3) 拼接体：ELF 头 + 零墙 + 内嵌 ELF
    p3 = os.path.join(tmp, 'spliced.bin')
    inner = open(p1, 'rb').read()
    open(p3, 'wb').write(inner[:64] + b'\x00' * 0x2000 + inner)
    r3 = probe(p3)
    print('[selftest] spliced.bin  内嵌 ELF 候选=%d' % len(r3['embedded_elf']))
    ok &= len(r3['embedded_elf']) >= 1

    # 4) zip / dex 头
    p4 = os.path.join(tmp, 'x.apk')
    open(p4, 'wb').write(b'PK\x03\x04' + b'\x00' * 32)
    r4 = probe(p4)
    print('[selftest] x.apk  ZIP-CONTAINER :', 'OK' if any('ZIP-CONTAINER' in t for t in r4['verdict']) else 'FAIL')
    ok &= any('ZIP-CONTAINER' in t for t in r4['verdict'])
    print('\n[selftest] %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
