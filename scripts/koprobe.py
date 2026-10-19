#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3 (stdlib only), file: koprobe.py
# purpose: 内核模块（.ko）判型与能力面 —— 不反汇编就出一张"它能干什么"的清单。
#   判据：e_type=1(REL) + .modinfo 五字段 + 导出符号面。
#   ★ 后缀一律不信：.sh / .bin / .dat 里可能就是 AArch64 REL。
# usage: python koprobe.py <file.ko|.ko.sh|driver.zip> [--json out.json] [--dump dir]
# 纪律: 只读。能力来自符号名 + 体量，标 observed；"这是外挂"属 inference，不写进结论。

import sys, os, re, json, struct, base64, zipfile, hashlib, argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# 能力指纹表（符号名正则 -> 能力标签）
CAPS = [
    (r'physical_memory|read_phys|write_phys|do_read_mem|do_write_mem', 'PHYS-MEM(物理内存读写: 绕过 process_vm_readv 审计)'),
    (r'hook_install|install_hook|inline_hook|hook_remove|hook_uninstall|kprobe|register_kprobe', 'HOOK(内核 hook 框架)'),
    (r'decode|disasm|decode_simd|arm64_decode', 'DECODER(自带指令解码器: inline hook 的必要前置)'),
    (r'filldir|filldir64|iterate_dir|readdir', 'HIDE-PROC(伪造目录项: /proc 里看不见)'),
    (r'path_mount|mount_over|tmpfs', 'HIDE-FILE(path_mount 盖路径)'),
    (r'debugfs|proc_create|kallsyms|sysfs', 'HIDE-NODE(debugfs/sysfs 打点)'),
    (r'pacga|pacia|autia|xpaci|xpacd|ptrauth', 'PAC(读/改指针认证密钥: 过 ARM64 PAC)'),
    (r'cfi_bypass|kcfi|__cfi', 'CFI(绕过内核 CFI)'),
    (r'input_event|evdev|input_dev|gyro|accel', 'INPUT(输入事件劫持)'),
    (r'hwbp|hw_break|debug_reg|dr[0-7]\b', 'HWBP(硬件断点)'),
    (r'get_module_base|find_process|get_pid|task_struct|get_task', 'TARGET(进程/模块定位)'),
    (r'spoof|fake|patch|bypass|anti', 'EVASION(对抗/伪装)'),
    (r'netlink|socket|sendmsg|sk_buff', 'NET(内核网络通路)'),
]

MODINFO_KEYS = [b'vermagic=', b'name=', b'license=', b'depends=', b'import_ns=', b'srcversion=', b'retpoline=']


def shannon(b):
    if not b:
        return 0.0
    import math
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


def parse_elf_hdr(d):
    if d[:4] != b'\x7fELF':
        return None
    cls = d[4]
    E = '<' if d[5] == 1 else '>'
    e_type, e_machine = struct.unpack_from(E + 'HH', d, 16)
    if cls == 2:
        e_entry, phoff, shoff = struct.unpack_from(E + 'QQQ', d, 24)
        flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(E + 'IHHHHHH', d, 48)
    else:
        e_entry, phoff, shoff = struct.unpack_from(E + 'III', d, 24)
        flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(E + 'IHHHHHH', d, 40)
    return dict(cls=cls, endian=E, e_type=e_type, e_machine=e_machine, entry=e_entry,
                phoff=phoff, shoff=shoff, phnum=phnum, shnum=shnum, shentsize=shentsize, shstrndx=shstrndx)


def sections(d, h):
    out = []
    if not h['shnum'] or not h['shoff']:
        return out
    E = h['endian']
    raw = []
    for i in range(min(h['shnum'], 20000)):
        o = h['shoff'] + i * h['shentsize']
        if o + h['shentsize'] > len(d):
            break
        if h['cls'] == 2:
            nm, ty, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from(E + 'IIQQQQIIQQ', d, o)
        else:
            nm, ty, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from(E + 'IIIIIIIIII', d, o)
        raw.append((nm, ty, fl, ad, of, sz))
    names = b''
    if h['shstrndx'] < len(raw):
        _, _, _, _, of, sz = raw[h['shstrndx']]
        names = d[of:of + sz]
    for nm, ty, fl, ad, of, sz in raw:
        s = ''
        if names and nm < len(names):
            e = names.find(b'\0', nm)
            s = names[nm:e].decode('latin1', 'replace')
        out.append(dict(name=s, type=ty, size=sz, off=of))
    return out


def modinfo(d):
    out = {}
    for k in MODINFO_KEYS:
        vals, start = [], 0
        while True:
            i = d.find(k, start)
            if i < 0:
                break
            end = d.find(b'\0', i)
            if end < 0:
                break
            vals.append(d[i:end].decode('latin1', 'replace'))
            start = i + 1
        if vals:
            out[k.decode().rstrip('=')] = vals[:6]
    return out


def symbols(d, secs, h):
    """从 .symtab/.dynsym 取符号；没有节表就裸扫可打印串。返回 (names, source)"""
    names = []
    for s in secs:
        if s['name'] not in ('.symtab', '.dynsym') or not s['size']:
            continue
        ent = 24 if h['cls'] == 2 else 16
        strtab = None
        for t in secs:
            if t['name'] in ('.strtab', '.dynstr'):
                strtab = t
                break
        for i in range(min(s['size'] // ent, 200000)):
            o = s['off'] + i * ent
            if o + ent > len(d):
                break
            if h['cls'] == 2:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(h['endian'] + 'IBBHQQ', d, o)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(h['endian'] + 'IIIBBH', d, o)
            if not st_name:
                continue
            if strtab:
                so = strtab['off'] + st_name
                e = d.find(b'\0', so)
                if 0 < so < len(d) and e > so:
                    names.append((d[so:e].decode('latin1', 'replace'), st_size, st_shndx))
            else:
                names.append(('<str#%d>' % st_name, st_size, st_shndx))
        if names:
            return names, 'symtab'
    # 裸扫
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{3,60}', d):
        names.append((m.group().decode('latin1'), 0, 1))
    return names, 'raw-string-scan'


def classify(names):
    caps = {}
    for nm, size, shndx in names:
        for pat, label in CAPS:
            if re.search(pat, nm, re.I):
                caps.setdefault(label, []).append((nm, size))
    return caps


def unpack_sh_ko(d):
    """`.ko.sh` 双层：真的是 shell 脚本，里面 base64 包着 .ko"""
    txt = d.decode('latin1', 'replace')
    if d[:2] != b'#!' and 'insmod' not in txt[:4000]:
        return None
    m = re.search(r'base64\s+-d|base64\s+--decode', txt)
    b64 = re.findall(r'[A-Za-z0-9+/=\r\n]{200,}', txt)
    if not b64:
        return None
    best = max(b64, key=len)
    try:
        raw = base64.b64decode(re.sub(r'\s+', '', best))
    except Exception:
        return None
    return dict(decoded=raw, note='shell wrapper + base64 payload', has_insmod='insmod' in txt)


def probe_bytes(d, name, dump_dir=None):
    r = dict(name=name, size=len(d), sha256=hashlib.sha256(d).hexdigest()[:32],
             head=d[:16].hex(' '), entropy=round(shannon(d[:0x400000]), 3))
    if d[:4] == b'PK\x03\x04':
        r['kind'] = 'ZIP'
        return r
    h = parse_elf_hdr(d)
    if not h:
        sh = unpack_sh_ko(d)
        if sh:
            r['kind'] = 'SHELL-WRAPPER(base64 内嵌 ELF)'
            sub = probe_bytes(sh['decoded'], name + '::payload', dump_dir)
            r['inner'] = sub
            if dump_dir:
                p = os.path.join(dump_dir, os.path.basename(name) + '.decoded.ko')
                open(p, 'wb').write(sh['decoded'])
                r['inner_dump'] = p
            return r
        r['kind'] = 'NOT-ELF'
        return r
    r['elf'] = dict(cls=h['cls'], endian=h['endian'], e_type=h['e_type'], e_machine=h['e_machine'],
                    entry=hex(h['entry']), phnum=h['phnum'], shnum=h['shnum'])
    if h['e_type'] != 1:
        r['kind'] = 'ELF-NOT-KO(e_type=%d，不是可重定位目标)' % h['e_type']
        return r
    secs = sections(d, h)
    r['sections'] = [s['name'] for s in secs if s['name']][:40]
    r['modinfo'] = modinfo(d)
    names, src = symbols(d, secs, h)
    r['symbol_source'] = src
    r['symbol_count'] = len(names)
    caps = classify(names)
    r['capabilities'] = {k: v[:8] for k, v in caps.items()}
    # __versions 与 modinfo 的矛盾
    vers_size = 0
    for s in secs:
        if s['name'] == '__versions':
            vers_size = s['size']
    r['versions_section_size'] = vers_size
    r['modversions_declared'] = 'modversions' in ' '.join(r['modinfo'].get('vermagic', []))
    conflicts = []
    if r['modversions_declared'] and vers_size == 0:
        conflicts.append('vermagic 声称 modversions 但 __versions size=0 -> force-load 或内核被改过(版本对上不够)')
    if r['modinfo'].get('import_ns'):
        conflicts.append('import_ns 非空 -> 借 GKI vendor hook 内部接口，跨内核版本兼容的钥匙')
    vm = ' '.join(r['modinfo'].get('vermagic', []))
    if '-dirty' in vm or re.search(r'g[0-9a-f]{8,}', vm):
        conflicts.append('vermagic 带 -dirty/git-hash -> 针对某台机器现编，换机不能用(所以一次给多份)')
    r['conflicts'] = conflicts
    r['verdict'] = verdict(r)
    return r


def verdict(r):
    caps = r.get('capabilities') or {}
    tags = []
    has_mem = any(k.startswith('PHYS-MEM') for k in caps)
    has_hook = any(k.startswith('HOOK') for k in caps)
    has_dec = any(k.startswith('DECODER') for k in caps)
    has_hide = any(k.startswith(('HIDE-PROC', 'HIDE-FILE', 'HIDE-NODE')) for k in caps)
    has_pac = any(k.startswith('PAC') for k in caps)
    if has_mem:
        tags.append('内存读写驱动')
    if has_hook and has_dec:
        tags.append('inline hook 框架(自带解码器)')
    if has_hide:
        tags.append('反检测(藏进程/文件/模块)')
    if has_pac:
        tags.append('绕 PAC')
    if len(tags) >= 3:
        tags.append('成品化外挂驱动(不是玩具)')
    if not tags:
        tags.append('正常/工具驱动(能力面未命中指纹, 需读 IOCTL 再说)')
    return tags


def human(r, indent=''):
    L = []
    L.append('%s== %s  (%d B, sha256=%s...)' % (indent, r.get('name'), r.get('size', 0), r.get('sha256', '?')))
    L.append('%s   head=%s  entropy=%s  kind=%s' % (indent, r.get('head'), r.get('entropy'), r.get('kind')))
    if r.get('elf'):
        e = r['elf']
        L.append('%s   ELF%d %s e_type=%d machine=%d entry=%s phnum=%d shnum=%d' % (
            indent, 32 * e['cls'] // 2, e['endian'], e['e_type'], e['e_machine'], e['entry'], e['phnum'], e['shnum']))
    for k, v in (r.get('modinfo') or {}).items():
        L.append('%s   modinfo %-11s = %s' % (indent, k, v[0] + (' …(+%d)' % (len(v) - 1) if len(v) > 1 else '')))
    if r.get('capabilities'):
        L.append('%s   能力面（符号名证据）:' % indent)
        for k, v in r['capabilities'].items():
            names = ', '.join('%s%s' % (n, ('(%dB)' % s) if s else '') for n, s in v[:4])
            L.append('%s     - %-52s <- %s' % (indent, k, names))
    if r.get('conflicts'):
        for c in r['conflicts']:
            L.append('%s   [!] %s' % (indent, c))
    if r.get('verdict'):
        L.append('%s   >> 判定: %s' % (indent, ' | '.join(r['verdict'])))
    if r.get('inner'):
        L.append('%s   --> 解包后:' % indent)
        L.append(human(r['inner'], indent + '    '))
    return '\n'.join(L)


def main():
    ap = argparse.ArgumentParser(description='内核模块(.ko)判型与能力面')
    ap.add_argument('target')
    ap.add_argument('--json', default='')
    ap.add_argument('--dump', default='')
    a = ap.parse_args()
    if a.dump:
        os.makedirs(a.dump, exist_ok=True)
    if a.target.lower().endswith('.zip'):
        z = zipfile.ZipFile(a.target)
        print('== ZIP: %s  条目 %d' % (a.target, len(z.infolist())))
        out = []
        for i in z.infolist():
            if i.filename.endswith('/'):
                continue
            b = z.read(i.filename)
            r = probe_bytes(b, i.filename, a.dump)
            print(human(r))
            print()
            out.append({k: v for k, v in r.items() if k != 'inner'})
        if a.json:
            json.dump(out, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            print('[+] JSON -> %s' % a.json)
        return 0
    d = open(a.target, 'rb').read()
    r = probe_bytes(d, os.path.basename(a.target), a.dump)
    print(human(r))
    if a.json:
        json.dump(r, open(a.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print('[+] JSON -> %s' % a.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
