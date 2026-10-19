# -*- coding: utf-8 -*-
# language: Python 3, file: dexdump.py — 按类/方法 dump dalvik 反汇编
# 用法:
#   python dexdump.py <dex> --list <类名子串>
#   python dexdump.py <dex> --class <完整类描述符, 如 Lcom/painkiller/nb/NativeVerify;>
#   python dexdump.py <dex> --method <类描述符> <方法名子串>
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexlib import Dex


def list_classes(dex, sub):
    n = 0
    for desc, af, cdo in dex.classes():
        if sub and sub not in desc:
            continue
        print('%s  flags=0x%x  class_data=0x%x' % (desc, af, cdo))
        n += 1
    print('# 共 %d 个' % n)


def dump_class(dex, desc, namefilter=None):
    ms = dex.methods_of(desc)
    print('# %s  方法 %d 个' % (desc, len(ms)))
    for sig, flags, code in ms:
        print('\n===== %s  flags=0x%x code=0x%x =====' % (sig, flags, code))
        if namefilter and namefilter not in sig:
            continue
        if not code:
            print('  (无方法体)')
            continue
        try:
            lines, regs = dex.disasm(code)
        except Exception as e:
            print('  反汇编失败: %s' % e)
            continue
        print('  registers=%d' % regs)
        for l in lines:
            print('  ' + l)


if __name__ == '__main__':
    path = sys.argv[1]
    dex = Dex(path)
    if sys.argv[2] == '--list':
        list_classes(dex, sys.argv[3] if len(sys.argv) > 3 else '')
    elif sys.argv[2] == '--class':
        dump_class(dex, sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    else:
        print(__doc__)
