#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3, file: zh.py
# purpose: 把判定标签统一成"中文(英文原词)"，避免报告满屏英文标签导致回答跟着说英文。
# usage:  from zh import zh ;  zh('SELF-DECRYPT-STUB')  ->  '自解密壳桩(SELF-DECRYPT-STUB)'
# 纪律: 标签是术语，保留英文原词便于对照 references；但**说明与句子必须是中文**。

import re

MAP = {
    # ---- 形态（elfprobe）----
    'SELF-DECRYPT-STUB': '自解密壳桩',
    'SELF-LOADED-PAYLOAD': '自加载载荷(无 dynamic/interp/import)',
    'NO-LOADER': '非常规可执行(系统加载器拉不起来)',
    'NORMAL-DYNAMIC': '正常动态程序',
    'HYBRID': '混合体(明文壳+加密区)',
    'KERNEL-MODULE': '内核模块',
    'ZIP-CONTAINER': 'ZIP 容器',
    'DEX': 'DEX',
    'FILESZ0-SEGMENT': '加固特征(filesz=0 段)',
    'CACHE-MAINT': '自改码(有缓存维护指令)',
    'HIGH-ENTROPY': '高熵(加密或压缩)',
    'STRONG-CIPHER': '强加密',
    'CIPHER': '真密文',
    'OBF': '混淆指令流',
    'CODE-LIKE': '真代码',
    'MIXED': '混合',
    'NOT-COMPILED': '非编译产物(密文或伪代码)',
    'ZERO-XREF': '零引用(不是真代码)',
    'LOW-XREF': '引用密度偏低(伪代码填充嫌疑)',
    'XREF-NORMAL': '引用密度正常',
    'XREF-NOT-TRUSTED': '引用密度不可采信',
    'STANDARD-COMPRESSION': '标准压缩流',
    # ---- 容器（container）----
    'APPENDED-CONTAINER': '追加容器(明文 loader + 尾部加密容器)',
    'TEXT-PLAIN': '可执行段是明文代码',
    'TEXT-ENCRYPTED': '可执行段整体加密',
    'RESOURCE-BLOCK': '资源块(不是加密)',
    'CONTAINER-HEADER': '容器头已定位',
    'UNCOVERED-DATA': '未覆盖数据',
    'SHT-RECOVERABLE': '节表可恢复(只是字段被清零)',
    'JUNK-JUMPS': '垃圾跳转(让 IDA 建不了函数)',
    'NO-UNCOVERED': '段覆盖完整(不是追加容器)',
    'UNKNOWN': '证据不足',
    # ---- 运行时（rkprobe）----
    'thunk-return': '跳板返回值打桩',
    'plt': 'PLT 桩打桩',
    'feed-dog': '喂狗',
    'thunk': '加密跳板',
    'bss-singleton': '单例标志',
    'time-gate': '时间门',
    'relative-to-thunk': '虚表指向跳板',
}


def zh(tag, keep_en=True):
    """把一个标签转成中文；认不出来的原样返回（不瞎编）。"""
    t = str(tag)
    # 形如 "SELF-DECRYPT-STUB(入口在 RX 段尾部 0.99)"：拆出标签与括号说明
    m = re.match(r'^([A-Za-z][A-Za-z0-9_\-]*?)(\((?:.|\n)*\))?$', t.strip())
    if m:
        key, rest = m.group(1), (m.group(2) or '')[1:-1]
        name = MAP.get(key)
        if name:
            # 中文标签 + 英文原词 + 关键数字（用 · 分隔，避免三重括号）
            tail = (' · ' + rest) if rest else ''
            return ('%s(%s)%s' % (name, key, tail)) if keep_en else (name + tail)
        return t
    name = MAP.get(t)
    return ('%s(%s)' % (name, t)) if (name and keep_en) else (name or t)


def zh_list(tags, sep=' | '):
    return sep.join(zh(x) for x in (tags or []))
