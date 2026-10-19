# -*- coding: utf-8 -*-
# language: Python 3, file: axml.py — 极简 Android 二进制 XML / ARSC 字符串池提取器
# 只做一件事: 把文件里所有字符串池中的字符串按顺序dump出来(带池内索引)
import sys, struct


def parse_string_pool(d, off):
    """off 指向 RES_STRING_POOL_TYPE 的 chunk 头; 返回 (strings, chunk_size)"""
    (ctype, hsize, csize) = struct.unpack_from('<HHI', d, off)
    assert ctype == 0x0001, 'not a string pool: 0x%04x' % ctype
    (scount, stcount, flags, sstart, ststart) = struct.unpack_from('<IIIII', d, off + 8)
    utf8 = bool(flags & 0x100)
    base = off + sstart
    out = []
    for i in range(scount):
        o = base + struct.unpack_from('<I', d, off + hsize + i * 4)[0]
        if utf8:
            # u8len, u8len(again in some impls) then data
            n = d[o]
            o += 2 if (n & 0x80) else 1
            n = d[o]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | d[o + 1]
                o += 2
            else:
                o += 1
            out.append(d[o:o + n].decode('utf-8', 'replace'))
        else:
            n = struct.unpack_from('<H', d, o)[0]
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', d, o + 2)[0]
                o += 4
            else:
                o += 2
            out.append(d[o:o + n * 2].decode('utf-16-le', 'replace'))
    return out, csize


def dump(path):
    d = open(path, 'rb').read()
    print('# %s  size=%d' % (path, len(d)))
    if len(d) < 8:
        return
    ctype, hsize, csize = struct.unpack_from('<HHI', d, 0)
    print('# 顶层 chunk type=0x%04x headerSize=%d size=%d' % (ctype, hsize, csize))
    o = hsize
    pools = 0
    while o + 8 <= len(d):
        t, hs, cs = struct.unpack_from('<HHI', d, o)
        if cs < 8 or o + cs > len(d):
            break
        if t == 0x0001:
            try:
                strs, _ = parse_string_pool(d, o)
            except Exception as e:
                print('# 池解析失败 @0x%x: %s' % (o, e))
                strs = []
            if strs:
                pools += 1
                print('# --- 字符串池 #%d @0x%x, %d 条 ---' % (pools, o, len(strs)))
                for i, s in enumerate(strs):
                    print('%5d  %s' % (i, s))
        o += cs
    print('# 共 %d 个字符串池' % pools)


if __name__ == '__main__':
    dump(sys.argv[1])
