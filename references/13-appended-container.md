# 追加容器与多层 AES 全解包（"极加密 ELF"的另一种真相）

> **很多"极加密 ELF"其实不是整文件加密，而是「一个很小的明文 loader + 追加在文件尾的加密容器」。**
> 这种结构**不需要脱壳、不需要内存 dump、不需要设备** —— 把容器的
> `footer → header → 密钥链 → 多层 AES → zlib` 读出来，就能在 PC 上纯静态还原明文 ELF，
> 并且用**壳自己的 SHA-256 终检**证明你解对了。
>
> 实证：章鱼哥 7 个版本 **7/7 一次通过**（见 `08-casebook.md`）。配套脚本 `scripts\container.py`。

---

## 0 · 三分钟判定：先看你在哪种情况

| 现象 | 走这篇吗 |
|---|---|
| 文件比程序该有的大小大很多，且**末尾一大块高熵** | ✅ 这篇 |
| `.text` 熵正常（≈6.0–6.5），只有尾段熵 7.9+ | ✅ **典型追加容器** |
| 段表 `filesz=0`、磁盘上几乎没有代码、整文件 98% 密文 | ❌ 走 `03/11`（dump / 运行时打桩） |
| 有商业壳名（VMProtect / Themida / SE / 极加密 t3yanzheng） | ❌ 先走 `03` §L2–L3 |
| 只有一块 `.rodata` 高熵、其余正常 | ⚠ **大概率是资源块**，先读 §9 误判 1 |

**唯一判据：画段覆盖图，看有没有"任何 PT_LOAD 都不覆盖"的大块。**

```
文件总长 L；所有 PT_LOAD 的 (p_offset, p_offset+p_filesz) 取并集 → 覆盖率
uncovered = L - 覆盖率
  ≈ 几 KB            → 正常（节表、对齐填充）
  ≈ 一半以上且熵>7.9 → 追加容器
```

```powershell
python scripts\container.py 章鱼哥.sh
```

实测输出（自动跑出来的，不是手算）：

```
== 章鱼哥.sh  (1916944 B)
   ELF AARCH64 entry=0x34f8  e_shoff=0x0 e_shnum=0
   PT_LOAD 并集: 0x0-0x15198, 0x151a0-0x16f85
   可执行段熵 = 6.556   (明文代码)

[uncovered] 共 1822859 B（任何 PT_LOAD 都不覆盖的部分）
   @0x16f85  1822859 B  熵=7.992  零字节=0.0117
       容器起点(熵跳变) = 0x1bf85 ...
   文件末 32B: 4d50464f4f544552c0840100...  |MPFOOTER........|

[footer] 魔数 'MPFOOTER'
   hdr_off   = 0x184c0  头魔数='ROTFLKP5'
   hdr_off2  = 0x184c0  头魔数='ROTFLKP5'
[容器头] 'ROTFLKP5' @0x184c0
   u32 = 00000005 0006dafb 002b1f78 001b8901 001b8920 00000007 ...
   疑似 chunk（分块大小） -> u32[7]=0x4000
   >> 判定: APPENDED-CONTAINER | TEXT-PLAIN | CONTAINER-HEADER
```

> **loader 完全明文**是这类壳的软肋 —— 所以你能直接反编译它、读出密钥链。本文全部价值建立在这上面。

---

## 1 · 结构测绘：五段必打印

```
① e_type / e_machine / e_entry
② 每个 PT_LOAD 的 off/vaddr/filesz/memsz/flags
③ uncovered 的 (起点, 长度, 熵, 头部 32 字节 hex)
④ 文件末 32 字节（footer 魔数 + 3×u64）
⑤ uncovered 内部的 4KB 熵剖面（找"熵跳变点"= 真正的容器起点）
```

> **魔数往往就在 uncovered 的头或文件末 32 字节里。** `container.py` 已经把 ③④⑤ 全打了。

---

## 2 · 节表恢复：`e_shoff=0` 不等于"没节表"

壳常把 `e_shoff / e_shnum / e_shstrndx` 清零，但**根本不处理节表本体** —— 它就躺在文件里。

```
① 暴搜：把后段每个 8 字节对齐偏移当 e_shoff，试着解 64 字节项
② 一致性校验：sh_name 落在 .shstrtab 内、sh_type 合法、sh_offset+sh_size <= 文件长
③ 回填三个字段，另存一份 → IDA/Ghidra 立刻能看到 .text/.rodata/.data
```

```powershell
python scripts\container.py x.elf --recover-sht x_fixed.elf
```

> 实测：表在 `0x171E0`，24 项；`.shstrtab` 在 `0x170F7`；回填后 `.text` = `0x34F8 + 0x11530`。
> **注意第一项通常是 SHT_NULL（全 0）** —— 校验时不能因此否掉整个候选（这是本脚本踩过的坑）。
>
> 两种"半抹"要分清：**清零字段、表还在** → 暴搜回填即可；**表被真的截掉** → 不影响执行
> （linker 只认 program headers），IDA 按段分析也正常，**不是解密错误**。

---

## 3 · 让 IDA 能建函数：垃圾字与不透明谓词

**现象**：`main` 明明在 `0x35F8`，但 `create_function` 恒失败、改 `e_entry` 也没用。

**真因**：线性扫描撞上**非法指令**（如 `42 00 00 00` = `UDF #2`），而它是被"不透明谓词"跳过去的死数据：

```
ADR/ADRP Xn, #imm     ; 死指令
NOP
CMP XZR, XZR          ; 恒真/恒假
B.cond  +8            ; 跳过下一条
42 00 00 00           ; ← 非法编码，线性扫描到此中断
```

**修法（语义中性）**：扫全 `.text`，**若某跳转的目标恰好是 `addr+8`，则把 `addr+4` 那 4 字节 NOP 掉**。
该字永远不会被执行，改它不改语义。只判 4 种编码：`B` / `B.cond` / `CBZ|CBNZ` / `TBZ|TBNZ`，都取 `imm==2`。

```powershell
python scripts\container.py x.elf --junkfix x_nop.elf
```

> 实测：46 处被打补丁 → 函数数 **248 → 253**，`main` 可反编译。
> **只改"被跳过的那 4 字节"**，别顺手 NOP 所有非法指令（有些是别的分支的合法目标）。

---

## 4 · 字符串：先判"哪一种编码"

同一个壳里往往并存两套，长得完全不一样：

| 形态 | 长相 | 解 |
|---|---|---|
| **A. 操作码流** | `04 5a 06 75 06 1b 06 0e …`（每两字节一个 `06 xx`） | 状态机解码 |
| **B. 平铺异或** | `bc c8 fc 6b 2b 24 25 59 …`（纯乱码，无结构） | `raw[j] ^ (0x5A + 17*j)` |

实测 A 型状态机语义（`sub_7A68`）：`key` 初值 `0x5A`，输出下标 `j`
- `04 <k>` → `key = k`
- `05` → `key = rol1(key)`
- `06 <b>` → `out[j] = b ^ ((17*j + key) & 0xFF)`，`j++`
- `03 <n>` → 批量：`out[j+k] = src[..] ^ ((key+k)&0xFF)`，共 `n-1` 字节
- `01 a b` → `out[j] = (a^b) ^ key`；`02 a b` → `(a+b) ^ key`；`00` → 结束

> **最值钱的一个陷阱**：`log(ptr,len)` / `err(ptr,len)` 会"把 ptr 的字节重新编码成 A 型流、再解码、再打印"。
> 看到这种实现，说明 `.rodata` 里那些"乱码"其实是 **B 型平铺异或**，不是"另一种密文"。
> 判据：拿 `raw[j] ^ (0x5A + 17*j)` 手算前 4 字节，出 `det`/`inte`/`确认` 这类文本就坐实了。

---

## 5 · 容器格式（记录模板，字段可对位）

```c
struct footer {              // 文件最后 32 字节
    char magic[8];           // "MPFOOTER"
    u64  hdr_off;            // 头偏移
    u64  magic_pos;          // 一致性字段（本次等于 body 长度）
    u64  hdr_off2;           // 等于 hdr_off
};

struct mang_hdr {            // 12816 字节
    char mags[8];            // +0x00 "ROTFLKP5"
    u32  ver;                // +0x08 版本
    u32  flags;              // +0x0C 位标志
    u32  out_size;           // +0x10 解压后大小
    u32  x20;                // +0x14
    u32  in_size;            // +0x18 密文长度
    u32  x28;                // +0x1C
    u32  seed;               // +0x20 参与 KTAG 哈希
    u32  chunk;              // +0x24 0x4000
    u32  nhash;              // +0x28 分块哈希条数
    u8   key_raw[16];        // +0x2C ← 关键
    u8   iv_wrapped[16];     // +0x3C ← 关键
    u8   x[64];              // +0x4C .. +0x8C
    u8   hdr_digest[32];     // +0x8C = SHA256(hdr[0x4C..0x8C] || key_raw)
    u8   ktag[32];           // +0xCC 只比较前 16 字节
    u8   out_sha256[32];     // +0xEC ← 明文终检
    u8   keymat[32];         // +0x114 主密钥的 XOR 掩码
    u8   chunk_hashes[][32]; // +0x112C 起，nhash 条
};
```

**flag 位**（实测）：`bit0` = 明文 SHA-256 终检；`bit6` = 分块哈希；`bit18(0x40000)` = 双 AES 通道。

> **位置算术别手算**：`body = d[hdr_off + 12816 : hdr_off + 12816 + in_size]`。
> 实测踩过：把 `0x1B6D0` 写成 `0x1B6ED0`（多 0x2000），zlib 报 `incorrect header check` —— **症状很像密钥错，其实是偏移错**。一律用表达式。

---

## 6 · 密钥链：域分隔符永远先找

先用 `strings` 级别的手段找**明文域分隔符**（本次全在 `.rodata`）：

```
"MANGHDR1"   头部自摘要          "KTAGV1"   密钥标签
"DUALAES1"   外层 AES 密钥       "DUALAES2" 外层 AES 的 IV
"IVWRAP"     IV 解包
```

派生公式（逆向所得，换壳要重推）：

```
MK(32)  = SHA256( hdr[0x4C..0x8C] || SHA256(SEP32 || key_raw) || key_raw ) XOR hdr[0x114..0x134]
   自校验: SHA256(hdr[0x4C..0x8C] || key_raw) == hdr[0x8C..0xAC]

IV(16)  = iv_wrapped XOR SHA256(key_raw || "IVWRAP")[0:16]
K1(32)  = SHA256("DUALAES1" || MK || key_raw)          # 外层
IV1(16) = SHA256("DUALAES2" || IV || key_raw)[0:16]
K2 = MK, IV2 = IV                                       # 内层
```

> **踩过的坑：`a4` 是输出不是输入**。第一版把主密钥当"全 0 缓冲"（因为代码里能看 `memset` + `mlock`），
> 结果 PKCS#7 校验 `pad=83` 直接露馅。真相：那个 32 字缓冲是 `sub_C030`（**10 字节字节码的微型 VM**）的输出。
> **Hex-Rays 里"缓冲区被清零"不等于"它就是 0"—— 先确认它是不是别的函数的 out 参数。**

> **微型 VM 不用怕**：字节码 `01 03 04 06 0A FB 0B B6 09 0F`，
> `op=3` → 调 `sub_133F8` 做密钥派生；`op=4` → 完整性比较；`op=6/10/11` → 干扰项。
> **先看它调了什么，不要一上来就写 VM 解释器。**

---

## 7 · 解包主循环

```python
C = d[hdr_off + 12816 : hdr_off + 12816 + in_size]
X = AES256CBC_dec(C, K1, IV1)          # 第 1 层
X = X[:-X[-1]] if 1 <= X[-1] <= 16 and len(set(X[-X[-1]:])) == 1 else X   # 去 PKCS#7
P = AES256CBC_dec(X, K2, IV2)          # 第 2 层
plain = zlib.decompress(P)
assert hashlib.sha256(plain).digest() == hdr_out_sha256      # ← 过了这条才算解对
```

> **顺序与填充位置**：loader 里是**先解外层再解内层**，去填充只发生在**最后一块**。
> 打包侧是 `X = E2(plain)+PKCS7` → `C = E1(X)`。把顺序弄反，第一层就解不出合法填充 —— 这是最快的自检信号。

---

## 8 · 五道验证（缺一道就不能说"解开了"）

| # | 校验 | 说明 |
|---|---|---|
| 1 | 头部自摘要 | `SHA256(hdr[0x4C..0x8C] ‖ key_raw) == hdr[0x8C..]` |
| 2 | 密钥标签 | `SHA256("KTAGV1"‖MK‖key_raw‖bswap32(seed)‖out_sha256)` 前 16B == `hdr[0xCC..]` |
| 3 | PKCS#7 | 末字节 ∈ 1..16，且末 `pad` 字节全相等 |
| 4 | 长度 | `len(inflate结果) == hdr.out_size` |
| 5 | **终检** | `sha256(明文) == hdr[0xEC..0x10C]` ← **壳自己的校验** |

> **第 5 条是分水岭**：前四条都可能"碰巧通过"，第 5 条是密码学意义上的"你解对了"。
> 有了它，你不是在猜密钥，而是**在用壳自己的判据自证**。交付报告必须写这条。

> **KTAG 只比前 16 字节**（`sub_13D10` 的 out 声明是 16 字节），你按 32 字节比会 `match=False` —— 正常现象，不是解错。

---

## 9 · 出"明文可执行版"：功能等价怎么证

### 9.1 载荷本身就是完整 ELF（四条判据）

1. `e_type = ET_DYN`，`PT_INTERP = /system/bin/linker64`
2. `e_entry` 落在某个 `PT_LOAD` 内，且入口是**标准 clang CRT `_start`**：
   `BTI j ; MOV X29,#0 ; MOV X30,#0 ; MOV X0,SP ; B …` → `PACIASP ; SUB SP,SP,#0x40` →
   `ADRP/LDR __init_array_start|end` → `ADRP X2,<main> ; BL __libc_init`
3. `DT_NEEDED / DT_RELA / DT_INIT_ARRAY` 都在，重定位类型全是标准集
4. `main` 自带业务（本次：`fopen("/data/local/tmp/.daemon_enabled")` → `fork/setsid` → 4 线程 → ImGui 主循环），**不依赖 loader 注入的上下文**

### 9.2 loader 最后一步是"内核启动栈模拟器"

本次 `sub_99C0` 手工构造 `argc/argv/envp` + 整套 `AT_*` auxv，然后跳入口。
**这就是"等价 execve"的证据** —— 它只是把内核该做的事手工做了一遍，没有额外传功能上下文。
⇒ 明文 ELF 直接落盘交给 `linker64`，行为与壳内运行相同。

### 9.3 差异清单要写明

| 项 | 原版 | 明文版 |
|---|---|---|
| 启动链路 | exec → loader 解密 → 手工映射 → 跳入口 | exec → `linker64` 直接加载 |
| 反取证 | `prctl(PR_SET_DUMPABLE,0)` / `mlock` / `madvise(MADV_DONTDUMP)` | 无（属壳的自我隐藏） |
| 反调试 | "检测到调试/注入环境" N 处 | 无（属壳的自我保护） |
| 业务 | — | 完全一样 |

### 9.4 交付踩坑

- **文件名保持一致**（用户按老名字投递）
- **必须放 `/data/local/tmp`** —— `/sdcard` 在 Android 10+ 是 `noexec`
- **必须 `chmod +x`** —— Windows 不带 unix 可执行位
- **依赖变化要写清**（本次 2.0~7.0 额外依赖 `libEGL/libGLESv3/libz`，1.0 只依赖 `libandroid`）

---

## 10 · 四条误判（都真实发生过）

| # | 误判 | 真相 |
|---|---|---|
| 1 | **把"资源块"当"加密"** | 熵 ≠ 加密。三条一起看：**零字节占比**（真密文 0.3–0.5% vs 资源块 3–25%）、**字节分布**（资源块严重偏向小值）、**邻接结构**（资源块常有索引表）。实测：整文件 6.645 / `.text` 6.374，只有 `.rodata` 一块 360KB~2.26MB 局部熵 7.1 → 是资源，不是第二层 |
| 2 | `uncovered` 起点算错 | `0x1B6D0` 写成 `0x1B6ED0` → zlib `incorrect header check`，**症状像密钥错** |
| 3 | `match=False` 就以为解错 | `KTAG` 只比 16 字节 |
| 4 | 拿整文件熵定性 | 必须分段：`.text` / `.rodata` / 每 64KB 窗口 |

---

## 11 · 可迁移 / 不可迁移

| 项 | 可迁移？ | 说明 |
|---|---|---|
| 先画段覆盖图再判明文/容器 | ✅ | 任何平台任何壳都成立 |
| `e_shoff` 清零但表还在 | ✅ | 极常见 |
| `B.cond +8` 后跟非法字 | ✅ | 通用不透明谓词套路 |
| 在 `.rodata` 找明文域分隔符 | ✅ | 作者命名习惯（`MANGHDR/KTAG/DUALAES/IVWRAP`） |
| `log(ptr,len)` 重编码再解码 | ✅ | 识别一次，省一整晚 |
| **具体偏移 / 密钥 / flag 位** | ❌ | **同壳不同版本都不一样**（7 版 out_size/in_size/seed 全不同） |
| `SEP32` 那 32 字节 | ⚠ | 版本间可能变，**从文件读，不要硬编码** |

> **"密钥在文件里"不是漏洞，是必然。** 客户端要能解密才能运行；这类壳保护的是"批量工具与手改"，
> 挡不住"照着文字逐条复刻的人"。你的工作不是破解密码学，是**把作者写下的那份说明书读出来**。

---


---

## 13 · 止损线：别逐 token 反推压缩格式（实测踩过）

有人在一个"7 段 + token 压缩 + 掩码"的自研容器上，**手工试 token、扫 256 个相位、反推掩码**，跑了 25 分钟没出结果。
正确顺序是：

1. **先 `strings` 搜域分隔符/魔数**：`MANG|ROTFL|MPFOOTER|DUALAES|IVWRAP|DUAL|KTAG` 这类常是作者习惯。
   命中 ⇒ 按本文五段读；**不命中 ⇒ 它不是已知格式，别写解码器**。
2. **判"是不是容器"再判"怎么解"**：段覆盖图 + 尾部 32 字节 + 头 8 字节魔数，先确认结构。
3. **解码失败 3 次 = 换路线**：转"找消费点"（谁 mmap/read 到这段）、或"入口整段跳过"
   （`14-network-hard-dependency.md` 的一条 `B`）。
4. **暴力搜索上限 1000 次**：相位/密钥/偏移组合超过就停 —— 自研容器靠猜是猜不出来的。

> 判据一句话：**能靠"读"解决的不要靠"试"**。试解的成本是 `组合数 × 单次验证`，
> 而结构判据的成本是常数。

## 12 · 命令速查

```powershell
python scripts\container.py <elf>                    # 判型：追加容器 / 整体加密 / 资源块
python scripts\container.py <elf> --recover-sht out.elf   # 回填被清零的节表
python scripts\container.py <elf> --junkfix out.elf       # NOP 掉被跳过的非法字
python scripts\container.py <elf> --json r.json
```
