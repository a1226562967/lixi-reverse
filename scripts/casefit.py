#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: casefit.py
# purpose: **案例/手法匹配** —— 回答那个最实际的问题：「这个样本会走到哪一步、缺什么前提」。
#   做法：对目标扫一组"指纹维度"（与知识库 15 维指纹矩阵同构），按规则映射到
#   「手法 / 路线 / 前提 / 预期结果」，并明确说出**这个样本注定破不了的话是为什么**。
# usage:
#   python casefit.py <目标>            # 指纹 + 判定 + 路线 + 前提
#   python casefit.py <目标> --json r.json
# 纪律: 指纹是"相对强度"（关键串出现次数），不是函数数，也不是结论；
#       命中的是"应该走哪条路"，不是"一定能破"。

import sys, os, re, json, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# 15 个维度（与知识库指纹矩阵同名；关键词是近似，用于相对强度）
DIMS = [
    ('T3平台',      ['t3yanzheng', 't3card', 't3yanzheng.so']),
    ('自建API',     ['/api/', 'api.php?action']),
    ('Unicorn仿真', ['unicorn', 'qemu', 'cpu_emulate']),
    ('replay校验',  ['replay', 'nonce', 'freshness']),
    ('内核hookmod', ['inline_hook', 'kprobe', 'hook_install', 'physical_memory']),
    ('evodriver',   ['evodriver']),
    ('XY/RT驱动',   ['xy_driver', 'rt_driver', 'xydriver']),
    ('UDP拦截',     ['udp_', 'recvfrom', 'raw_socket']),
    ('inlinehook框架', ['fishhook', 'MSHookFunction', 'substrate', 'dobby']),
    ('il2cpp/Unity', ['il2cpp', 'UnityEngine', 'global-metadata']),
    ('混淆器',      ['ollvm', 'flatten', 'control_flow', 'bcf']),
    ('反调试',      ['ptrace', 'TracerPid', 'debugger', 'frida']),
    ('设备指纹',    ['android_id', 'boot_id', 'imei', 'serialno', 'OAID']),
    ('心跳/租约',   ['heartbeat', 'keepalive', 'lease', 'alarm(']),
    ('本地绕过标志', ['isvip', 'is_licensed', 'verified', 'granted', 'card_ok']),
    ('落点路径',     ['/data/adb', '/sdcard/', '.t3card', '.km_expire', '/data/system/', 'card.txt']),
    ('签名/验签',    ['ed25519', 'verify_envelope', 'signature verify', 'aead', 'x25519']),
]

# 规则：命中条件 → (手法/同类样本, 路线, 前提, 预期)
RULES = [
    dict(when=lambda f: f.get('落点路径', 0) > 0 and f.get('签名/验签', 0) == 0,
         name='真 L1：磁盘授权落点（同类：T3 / llua 系）',
         route='**L1 优先**：先试喂文件（写 `/data/xxx` 或 `/sdcard/xxx`），二进制都不用改；'
               '细节见 `19-forms-and-layers.md` §二',
         need='可写该路径的权限（root 或 app 自己的目录）',
         expect='喂文件就能过 ⇒ 成本 ★；不行再降到 L2/L3'),
    dict(when=lambda f: f.get('落点路径', 0) > 0 and f.get('签名/验签', 0) > 0,
         name='落点只是缓存，真判决在 L4（同步：起源 10.2 / LV）',
         route='喂文件**只能免输入**，过不了判决：改打**验签器**（`verify_envelope_signature` 恒返回 1）'
               '或直接重放（`05`）；**不要伪造签名**',
         need='有卡⇒重放可全程过；无卡⇒只能改本地消费点，且要接受"过不了链 A/B"',
         expect='喂 L1 单独不够（知识库实证：8 字节只过三条链里的一条）'),
    dict(when=lambda f: f['内核hookmod'] >= 50 and f['自建API'] == 0 and f['il2cpp/Unity'] <= 2,
         name='纯内核驱动（同类：Aiultra 的 8 个驱动变体）',
         route='授权不在这层 —— 这是权限硬前提。去 APK / 主程序找闸门（`06-kernel-module.md`）',
         need='无（静态可判）', expect='只能给"能力面表"，不能给"破解"'),
    dict(when=lambda f: f['内核hookmod'] >= 300,
         name='大型内核外挂主程序（同类：起源 3.1 / VS）',
         route='运行时打桩（`11`）：thunk/PLT/喂狗；静态先 `rkprobe.py` 拿打桩点',
         need='root 设备（执行）；静态可出全部坐标', expect='能给带原字节的 pm 命令；能否起主界面需设备'),
    dict(when=lambda f: f['T3平台'] >= 5,
         name='极加密 t3yanzheng 系（同类：CG 范围 / 死伤范围）',
         route='静态啃不动：走运行时打桩，或做"重建体↔原版"结构 diff（`09` C 类）',
         need='真机（运行时）或一份可对照的重建体', expect='静态只能到判型；明文需设备或重建体'),
    dict(when=lambda f: f['Unicorn仿真'] >= 20,
         name='目标内含自研 VM/仿真器（同类：护航仔 / 神烦狗）',
         route='**只打边界不逆 VM**：入口跳板 / 返回值 / out 参数（`11` §一）',
         need='静态可定位边界；验证需设备', expect='能定位打桩点；不逆 VM 内部'),
    dict(when=lambda f: f['replay校验'] >= 1 and f['心跳/租约'] >= 1,
         name='服务端判决 + 心跳（同类：LV 追锁 / 快斗 6.8）',
         route='真响应重放（`05`）+ 时间冻结；**不要伪造签名**',
         need='**一次有效卡的抓包**（过期卡抓的没用）', expect='有卡⇒能进主界面；无卡⇒只能改消费点'),
    dict(when=lambda f: f['反调试'] >= 50,
         name='重反调试（同类：起源 / 纽约 1004）',
         route='走 `/proc/pid/mem` **不 attach**；或离线打桩（`11` §六）',
         need='root；静态可先出打桩点', expect='静态可出点；挂调试器会被杀'),
    dict(when=lambda f: f['混淆器'] >= 1,
         name='有混淆（OLLVM/平坦化）',
         route='先判形态（`04` 三分判据），别直接试解；对照"混淆四判据"决定要不要啃',
         need='无（判型静态可做）', expect='判型 + 定位消费点；不承诺还原控制流'),
]


def scan(path):
    d = open(path, 'rb').read()
    low = d.lower() if len(d) < (64 << 20) else d[:64 << 20].lower()
    fp = {}
    for name, kws in DIMS:
        n = 0
        for k in kws:
            n += low.count(k.lower().encode())
        fp[name] = n
    return fp, len(d)


def classify(fp):
    hits = []
    for r in RULES:
        try:
            if r['when'](fp):
                hits.append(r)
        except Exception:
            continue
    return hits


def human(path, fp, size, hits):
    L = ['== 案例/手法匹配  %s  (%.2f MB)' % (os.path.basename(path), size / 1048576.0)]
    L.append('\n[指纹]（关键串出现次数，只是相对强度）')
    order = sorted(fp.items(), key=lambda kv: -kv[1])
    for k, v in order:
        bar = '#' * min(30, v)
        L.append('   %-14s %5d  %s' % (k, v, bar))
    if not hits:
        zero = sum(1 for v in fp.values() if v == 0)
        L.append('\n[判定] 没有命中任何"手法"指纹（%d/15 维为 0）' % zero)
        L.append('   ⇒ 三种可能：① 是纯资源/明文脚本 ② 关键串被加密（先判型 `elfprobe`）')
        L.append('               ③ 是没见过的新形态 —— 那就老实按 `01-triage` 三问走，别硬套案例')
        return '\n'.join(L)
    L.append('\n[判定] 命中 %d 条路线，按"该先做哪个"排：' % len(hits))
    for i, h in enumerate(hits, 1):
        L.append('\n   %d) %s' % (i, h['name']))
        L.append('      路线: %s' % h['route'])
        L.append('      前提: %s' % h['need'])
        L.append('      预期: %s' % h['expect'])
    L.append('\n   ⚠ 这只是"该走哪条路"。能不能真进主程序，取决于上表"前提"——')
    L.append('     缺设备/缺有效卡/缺原版对照，就停在"计划层"，这不是 skill 失效，是前提不在。')
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='案例/手法匹配（指纹 → 路线 → 前提 → 预期）')
    ap.add_argument('target')
    ap.add_argument('--json', default='')
    a = ap.parse_args()
    if not os.path.exists(a.target):
        print('[!] 目标不存在')
        return 2
    fp, size = scan(a.target)
    hits = classify(fp)
    print(human(a.target, fp, size, hits))
    if a.json:
        json.dump(dict(path=os.path.abspath(a.target), fingerprint=fp,
                       hits=[{k: v for k, v in h.items() if k != 'when'} for h in hits]),
                  open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
