#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: patch_dex.py
# purpose: 打 dex 补丁 —— 三步一体：改指令 + 重算头部 SHA-1 + 重算 Adler-32，并用解析器自证"可加载"。
#   只改指令不重算头部 ⇒ 解析器 Load failed / 装到手机点开图标瞬间退出（极易被误判成"加固自检"）。
# usage:
#   python patch_dex.py in.dex out.dex --offset 0x656e1a --expect "38 00" --write "00 00"
#   python patch_dex.py in.dex --verify          # 只校验头部两个摘要 + 解析器能否加载
#   python patch_dex.py --list-sites             # 打印内置样例坐标（仅供对照）
# 纪律: 写前校验原字节、写后读回；不做"只改指令"的半套补丁。

import sys, os, struct, zlib, hashlib, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# 样例坐标（止痛药 5.86，仅供对照；换样本一律重推）
SITES = [
    dict(note='止痛药5.86 verifyOrLaunch 的 if-eqz(0x5b) 两条 nop', off=0x656E1A, expect='38 00', write='00 00'),
    dict(note='止痛药5.86 NativeVerify.verify 的 if-ne(0x82)', off=0x7001B8, expect='33 75', write='00 00'),
]


def hexbytes(s):
    return bytes.fromhex(s.replace(' ', '').replace('0x', ''))


def fix_header(d):
    """头部两摘要：signature(0x0C,20B)=SHA1(d[32:])；checksum(0x08,4B LE)=adler32(d[12:])"""
    b = bytearray(d)
    sig = hashlib.sha1(bytes(b[32:])).digest()
    b[0x0C:0x20] = sig
    chk = zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', b, 0x08, chk)
    return bytes(b), sig.hex(), chk


def verify_header(d):
    return (d[0x0C:0x20] == hashlib.sha1(d[32:]).digest(),
            struct.unpack_from('<I', d, 0x08)[0] == (zlib.adler32(d[12:]) & 0xFFFFFFFF))


def try_parse(path):
    """硬判据：能列出类 = 可加载（等价于 jadx 能打开）"""
    try:
        from dexlib import Dex
        dx = Dex(path)
        return True, '解析器加载成功，类 %d 个' % dx.class_defs_size
    except Exception as e:
        return False, '解析器加载失败：%r' % e


def main():
    ap = argparse.ArgumentParser(description='dex 补丁（三步一体：指令 + SHA-1 + Adler-32）')
    ap.add_argument('src')
    ap.add_argument('dst', nargs='?', default='')
    ap.add_argument('--offset', default='')
    ap.add_argument('--expect', default='', help='原字节（必须校验）')
    ap.add_argument('--write', default='', help='新字节（与 expect 等长）')
    ap.add_argument('--verify', action='store_true')
    ap.add_argument('--list-sites', action='store_true')
    a = ap.parse_args()

    if a.list_sites:
        for s in SITES:
            print('  %#x  %-52s  %s -> %s' % (s['off'], s['note'], s['expect'], s['write']))
        return 0

    d = open(a.src, 'rb').read()
    if d[:4] != b'dex\n':
        print('[!] 不是 dex 文件（头=%s）' % d[:8].hex())
        return 2
    sig_ok, chk_ok = verify_header(d)
    print('[i] 原文件头部: SHA-1 %s / Adler-32 %s' % ('OK' if sig_ok else '不符', 'OK' if chk_ok else '不符'))

    if a.verify or not a.offset:
        ok, msg = try_parse(a.src)
        print('[i] %s' % msg)
        return 0 if (sig_ok and chk_ok and ok) else 1

    off = int(a.offset, 0)
    exp = hexbytes(a.expect)
    wri = hexbytes(a.write)
    if len(exp) != len(wri):
        print('[!] expect(%d) 与 write(%d) 长度不等 —— 必须等长覆盖' % (len(exp), len(wri)))
        return 3
    cur = d[off:off + len(exp)]
    if cur != exp:
        print('[X] 原字节不符：@%#x 期望 %s，实际 %s（先核对偏移，别硬写）' % (off, exp.hex(' '), cur.hex(' ')))
        return 4

    b = bytearray(d)
    b[off:off + len(wri)] = wri
    out, sig, chk = fix_header(bytes(b))
    open(a.dst, 'wb').write(out)

    d2 = open(a.dst, 'rb').read()
    back = d2[off:off + len(wri)]
    sig2, chk2 = verify_header(d2)
    ok_parse, msg = try_parse(a.dst)
    print('[+] 写入 %s：@%#x  %s -> %s' % (a.dst, off, exp.hex(' '), back.hex(' ')))
    print('[+] 头部重算: SHA-1=%s… / Adler-32=%s' % (sig[:16], hex(chk)))
    print('[%s] 读回: 字节 %s / SHA-1 %s / Adler-32 %s / %s' % (
        '+' if (back == wri and sig2 and chk2 and ok_parse) else 'X',
        'OK' if back == wri else 'FAIL', 'OK' if sig2 else 'FAIL', 'OK' if chk2 else 'FAIL', msg))
    if not (back == wri and sig2 and chk2 and ok_parse):
        return 5
    print('[i] 下一步：重打包（别手搓 v2）→ zipalign -p -f 4 → apksigner sign(v1+v2) → verify → align -c')
    return 0


if __name__ == '__main__':
    sys.exit(main())
