#!/usr/bin/env node
// lixi-reverse · xdc.mjs — 不依赖 Python 的第一响应（Node 18+ 通用）
// 用法: node xdc.mjs <目标> [需求]
// 作用: 头判型 + 大小 + SHA256 +（ZIP/APK）条目统计 + 分层判定 + 下一步命令
// 纪律: 只读；深度分析走 python3 scripts/autoexec.py
import { readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename } from 'node:path';

const target = process.argv[2];
const need = process.argv[3] || '';
if (!target) { console.error('[X] 用法: node xdc.mjs <目标> [需求]'); process.exit(2); }

let st;
try { st = statSync(target); } catch { console.error(`[X] 目标不存在: ${target}`); process.exit(2); }
if (!st.isFile()) { console.error('[X] 不是文件'); process.exit(2); }

const buf = readFileSync(target);
const head = buf.subarray(0, 16);
const hex = [...head].map(b => b.toString(16).padStart(2, '0')).join(' ');
const sha = createHash('sha256').update(buf).digest('hex');

function kindOf(b) {
  const m = (arr) => arr.every((v, i) => b[i] === v);
  if (m([0x7f, 0x45, 0x4c, 0x46])) return 'ELF';
  if (m([0x50, 0x4b])) return 'ZIP/APK/JAR';
  if (m([0x64, 0x65, 0x78])) return 'DEX';
  if (m([0x1f, 0x8b])) return 'gzip';
  if (m([0xfd, 0x37])) return 'xz';
  if (m([0x42, 0x5a, 0x68])) return 'bzip2';
  if (m([0x4d, 0x5a])) return 'PE(Windows)';
  if (m([0x25, 0x50])) return 'PDF';
  return '未知/文本/其它';
}
const kind = kindOf(head);
const MB = (st.size / 1048576).toFixed(2);

console.log('== lixi-reverse · 第一响应（Node 版）');
console.log(`   目标: ${target}`);
console.log(`   大小: ${st.size} B (${MB} MB)   SHA256: ${sha.slice(0, 16)}…`);
console.log(`   头16: ${hex}`);
console.log(`   形态: ${kind}`);

if (kind === 'ELF') {
  const eType = buf.readUInt16LE(16);
  const eMach = buf.readUInt16LE(18);
  const tm = { 1: 'REL(内核模块/可重定位)', 2: 'EXEC', 3: 'DYN(PIE/so)', 4: 'CORE' };
  const em = { 183: 'AARCH64', 62: 'X86_64', 40: 'ARM' };
  console.log(`   ELF: type=${tm[eType] || eType} machine=${em[eMach] || eMach}`);
  console.log(`   >> 下一步: python3 scripts/elfprobe.py "${target}"    # 熵/自解密四指纹/大块高熵段`);
  console.log(`             python3 scripts/container.py "${target}"   # 追加容器/节表/垃圾字`);
  console.log(`             python3 scripts/rkprobe.py "${target}"      # 运行时打桩点`);
  console.log(`             python3 scripts/jniprobe.py "${target}"     # JNI 动态注册`);
}

if (kind === 'ZIP/APK/JAR') {
  // 手读 central directory：找 EOCD → 总条目 → 扫 CD 里的文件名与压缩后大小
  let entries = [];
  const iEocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (iEocd >= 0) {
    const total = buf.readUInt16LE(iEocd + 10);
    const cdOff = buf.readUInt32LE(iEocd + 16);
    let p = cdOff, guard = 0;
    while (p + 46 <= buf.length && guard++ < total + 8) {
      if (!(buf[p] === 0x50 && buf[p + 1] === 0x4b && buf[p + 2] === 0x01 && buf[p + 3] === 0x02)) break;
      const method = buf.readUInt16LE(p + 10);
      const compSize = buf.readUInt32LE(p + 20);
      const uncompSize = buf.readUInt32LE(p + 24);
      const nameLen = buf.readUInt16LE(p + 28);
      const extraLen = buf.readUInt16LE(p + 30);
      const commentLen = buf.readUInt16LE(p + 32);
      const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
      entries.push({ name, method, compSize, uncompSize });
      p += 46 + nameLen + extraLen + commentLen;
    }
  }
  const dex = entries.filter(e => /^classes\d*\.dex$/.test(e.name));
  const so = entries.filter(e => /\.so$/.test(e.name));
  const lua = entries.filter(e => /\.lua$/.test(e.name));
  console.log(`   条目: ${entries.length}  dex: ${dex.length}  so: ${so.length}  lua: ${lua.length}`);
  for (const d of dex) console.log(`     ${d.name.padEnd(18)} ${String(d.uncompSize).padStart(12)} B`);
  const tiny = dex.filter(d => d.uncompSize < 20000);
  if (tiny.length) console.log(`   [!] 极小 dex（可能是解码器）: ${tiny.map(d => d.name).join(', ')}`);
  const stored = so.filter(s => s.method === 0);
  if (stored.length) console.log(`   [!] STORED 的 so（重打包必须页对齐）: ${stored.map(s => s.name).join(', ')}`);
  if (lua.length >= 5) console.log('   [!] 成规模 .lua ⇒ 可能是脚本壳（闸门在脚本里，不在 dex）');
  console.log(`   >> 下一步: python3 scripts/autoexec.py "${target}" --need "${need}"`);
  console.log(`             python3 scripts/luaq.py "${target}"`);
}

if (kind === 'gzip') console.log(`   >> 下一步: python3 scripts/payload.py "${target}" --dump out`);
if (kind === 'PE(Windows)') console.log('   >> Windows PE，本技能不覆盖（走 win-flow）');

if (need) console.log(`   需求: ${need}`);
console.log(`\n   深度分析: python3 scripts/autoexec.py "${target}" --need "${need}"`);
