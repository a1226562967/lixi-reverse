# 可复现手册 — 从一份成品走到一个补丁

> **上一轮给的是"判据"，这一篇给的是"手"**：每一步有命令、有判据、有失败分支。
> 样板 = 起源漏打追锁 10.2（25.5 MB `.sh` → **8 字节补丁**，全程静态、不需要设备）。
> 配套：`verify.py`（每步落成 claim 回判）· `rank.py`（先看哪几个函数）· `elfprobe.py`（判型）。

---

## 0 · 三条铁律（血换的）

1. **在副本上做，绝不在样本目录里建数据库。**
   IDA（含 idalib）会在**样本同目录**建 `.id0/.id1/.id2/.nam` 并持有句柄 —— 之后目录删不掉、移不动。
   ```powershell
   Copy-Item '目标.sh' 'D:\lixi\_cases_re\work\sample.bin'
   ```
2. **原件一字不改。** 判据是"目录里有没有多出文件 / 有没有被写"，不是 hash 有没有变。
3. **没有 locator 的结论不进账。** 每条结论带 `文件 / vaddr / 偏移 / 字节`，否则只是印象。

---

## 1 · 第 0 步：判型（3 分钟，别信后缀）

```powershell
python scripts\elfprobe.py 目标文件        # 或 xdc.ps1 / xdc.sh / xdc.mjs（无 Python 时）
```

| 头字节 | 真实类型 | 下一步 |
|---|---|---|
| `7f454c46` | ELF | 读 `e_type/machine`；`m183` = AArch64 |
| `504b0304` | ZIP/APK | 列内层最大条目，**再判一次类型**（有的 zip 内层还是 APK） |
| `23212f` | 真 shell | 读脚本（可能是 base64 包 `.ko`） |
| 其他 | 文本 | 直接读（有的"样本"就是 12 KB 纯文本） |

---

## 2 · 第 1 步：先测 strip 没 strip（2 分钟，决定后面全部工作量）

**这一屏就是答案的一半**：有符号 = 一张地图，工作量比无符号少一个数量级。

```powershell
python scripts\rank.py 目标 --top 10     # 有符号时直接排好序；无符号时按 JNI/调用次数排
```

| 现象 | 含义 | 路线 |
|---|---|---|
| 有 `_ZN5cloud…` / `cardinfo::` 之类 C++ 符号 | **未 strip** | 按名字找判决点，最快 |
| 全 `sub_XXXX` 但能反编译出合理 C | stripped 但明文 | 走"字符串 → xref" |
| 反汇编全 `DCB`/乱码、熵 > 7.85 | 密文 | 先脱壳（`13-appended-container.md`）/ 或走运行时（`11`） |

---

## 3 · 第 2 步：把符号读成架构（10 分钟，比读代码便宜）

不要逐个反编译。**先按名字分组**，架构自己就浮出来（样板实测 56 个符号 → 6 组）：

| 组 | 例 | 作用 / 立刻能下的结论 |
|---|---|---|
| **入口** | `login()` | 读缓存 → 要卡密 → 调 login → 打印 → 写缓存 |
| **判决** | `cloud::login` / `cardinfo()` / `reset_card_info` | 一次网络登录 + 结果解析进全局 |
| **传输** | `post_json` / `request` / `build_url` / `parse_http_json` / 自研 HTTP×7 | **自己写了 HTTP/TLS**，没走 curl |
| **密码学** | `x25519_*` / `aead_encrypt_hex` / `ed25519_verify_hex` | 会话 + 信封 + 验签 |
| **信封校验** | `is_business_envelope` / `has_exact_keys` / `verify_envelope_signature` / `*_aad` | 结构白名单 + 签名 + AAD 绑定 |
| **本地状态** | `read_file` / `getDeviceID` / `create_session` / `add_timestamp` | 卡密与设备号落盘 |

> **看到 `ed25519_verify_hex` + `verify_envelope_signature`，立刻三条结论**：
> ① 响应**不可伪造**（私钥在服务端）→ 假服务器这条路基本死；
> ② 但**验证器在客户端** → **它可以被打桩**；
> ③ 有 `*_aad` → 响应必须"结构对 + AAD 对"，自己造 JSON 也不行。
> 这三条直接决定后面只能走 **打桩 / 重放**。

---

## 4 · 第 3 步：定位判决点（两条路，选便宜的）

### 路 A · 有符号 → 直接看调用关系（5 分钟）

```c
if ( !(unsigned int)cloud::login(&v153) )      // ← 0 = 成功
    break;                                      // 跳出重试循环
// 否则：printf(last_message); remove(card_path); 继续循环
```

**这一个函数内的判决 = `cloud::login` 的返回值**，不是 `permanent` 字段、也不是那个 `if` 的任何分支。

> **但"函数内判决点" ≠ "程序判决点"。** 同一样本实际有**三条**判决链：
> ① `main` 的域名探测全失败 → `return -1`（**网络硬依赖，比卡密门更早**）
> ② `create_session`（在 `login()` 里返回值被**丢弃** ⇒ 这条路径断网不影响）
> ③ `cloud::login`（上面那条）
> **通用规则：在一个函数里找到的判决，只能声明"这个函数内的判决在这里"。**

### 路 B · 无符号 → 字符串反查（本仓多数样本只能走这条）

```python
# 中文必须先转 UTF-8 十六进制去搜字节（IDA 对中文常不建字符串表）
# "验证成功" = E9AA8CE8AF81E68890E58A9F
r = search_bytes(pattern="E9AA8CE8AF81E68890E58A9F")   # → 0x199102
xrefs = get_xrefs_to("0x199102")                       # → 0xA8DB5C（落在字符串偏移表里）
decompile_function("0xA8DB5C")                         # → 拿到所在函数
```

> **两个工具态坑**：
> ① `find_code_by_string("卡密")` 可能返回 `total_strings_scanned: 0` —— **工具没建索引**，不是"没有这条串"；
> ② 搜到的 xref 常指向**字符串偏移表**，不是代码直接引用 —— **别停在表上，反编译引用表的那段代码**。

---

## 5 · 第 4 步：算 v2o + 序言复核（1 分钟，patch 的唯一硬门槛）

`vaddr ≠ file_off` 是常见错觉（本样板恰好恒等，但**必须算**）。

```python
import struct
b = open("sample.bin","rb").read()
e_phoff = struct.unpack_from('<Q', b, 32)[0]
e_phentsize, e_phnum = struct.unpack_from('<HH', b, 54)
loads = []
for i in range(e_phnum):
    o = e_phoff + i*e_phentsize
    if struct.unpack_from('<I', b, o)[0] == 1:              # PT_LOAD
        off, vaddr, _, filesz, _ = struct.unpack_from('<QQQQQ', b, o+8)
        loads.append((off, vaddr, filesz))
v2o = lambda v: next((off+(v-va) for off, va, fs in loads if va <= v < va+fs), None)
```

**序言判据（能挡 90% 的错 patch）**：AArch64 函数入口必然是 `sub sp,sp,#imm` / `stp x29,x30,[sp,#-imm]!` / `bti`。
目标偏移上不是这几类指令 ⇒ **v2o 算错了，或那不是函数入口**。

```powershell
python scripts\verify.py 目标 --claim '{"kind":"prologue_at","vaddr":"0xA8BE9C"}'
```

| vaddr | 前 8 字节 | 判读 |
|---|---|---|
| `0xA8BE9C` `cloud::login` | `ff4304d1 fd7b0ba9` | `sub sp,sp,#0x110` / `stp x29,x30,…` ✓ |
| `0xA937E4` `verify_envelope_signature` | `ff4303d1 …` | ✓ |

---

## 6 · 第 5 步：三种方案（按"副作用从小到大"选）

| 方案 | 动作 | 优点 | 代价 |
|---|---|---|---|
| **A · 判决函数恒返回 0**（最短） | `mov w0,#0 ; ret`（8 字节） | 天然栈平衡、不碰别的字节 | `cardinfo::*` 全空 ⇒ 界面显示空到期时间；若后续要读卡密派生的密钥，可能失败 |
| **B · 打桩验签器**（更稳） | `verify_envelope_signature` 恒返回 1 | 保留真实解密路径与 `cardinfo::*` 数据 | 仍需服务端给出**结构合法**的信封（结构白名单/AAD 仍检查） |
| **C · 喂 L1 文件**（最省事但不干净） | 写 `/data/card.txt`（任意非空）+ `/data/user.txt`（设备号） | 免输入 | **单独不够**（仍会联网走 `login()`），只能配合 A/B 或重放 |

```python
OFF = 0xA8BE9C
b = bytearray(open("sample.bin","rb").read())
print("before:", b[OFF:OFF+8].hex())     # ff4304d1fd7b0ba9
b[OFF:OFF+8] = bytes.fromhex("00008052" "C0035FD6")   # mov w0,#0 ; ret
open("sample_patched.bin","wb").write(b)
```

---

## 7 · 路线选择矩阵（照打）

| 你观察到 | 判决归属 | 走哪条 | 成本 |
|---|---|---|---|
| 有 L1 落盘路径（`/data/adb/*.t3card`、`/sdcard/.km`）+ 客户端只读不联网复验 | 本地 | **喂文件** | ★ |
| 有联网登录 + `.text` 明文 + 判决函数可定位 | 服务端判决 · 客户端消费 | **打桩**（A/B） | ★★ |
| 有 `ed25519` / `verify_envelope_signature` + 响应加密 | 服务端判决 · 不可伪造 | **打桩验签器（B）** 或 **重放** | ★★–★★★ |
| 有 `uptime` + `CLOCK_REALTIME` + 编译时间三元 | 本地时间判决 | **打桩时间源**（不是改系统时间） | ★★ |
| 每个动作都要服务端现场签一次 | 服务端强绑定 | **停手**，如实报"卡在服务端强绑定" | ✗ |

---

## 8 · 失败分支表（每条都真踩过）

| 症状 | 真因 | 处理 |
|---|---|---|
| `struct.error: unpack_from requires a buffer of …` | 用 4 KB 头去解 section header | **整文件读**；只判类型才用前 4 字节 |
| `needed` 全是空串 | 解析器把 `filesz==0` 的 LOAD 也算进去了 | 修解析器（字段恒空 = 工具 bug） |
| `find_code_by_string` 返回 0 条 | IDA 没建中文串索引 | 改 `search_bytes` 搜 UTF-8 十六进制 |
| xref 为空 | 串被偏移表间接引用 | 反编译**引用表的那段代码** |
| patch 后不启动/闪退 | ①偏移算错 ②打在函数中间 ③栈没平衡 | **序言判据**复核；方案 A 的 8 字节天然平衡 |
| patch 生效但界面空白/崩溃 | 有 out 参数或全局结构没填 | 转方案 B；或连 `cardinfo::*` 一起伪造 |
| 改了时间还是过期 | 用的是 `CLOCK_MONOTONIC` / `uptime` | 打桩时间源，不是改设置 |
| 目录删不掉、"正在使用" | IDA 把 `.id0…` 建在样本目录 | 先复制到工作区（§0） |
| 字符串统计里一堆 `replay`/`heartbeat`/`verify` | 第三方库（iproute2/curl/OpenSSL） | 见 `15-defense-map.md` 与"撞车表" |

---

## 9 · 验收四级（别自欺）

| 层级 | 证据 | 够不够 |
|---|---|---|
| 字节改对了 | 读回 + 反汇编 | ❌ 过程量 |
| 语义对 | 调用者是 `if(!login()) break` | ❌ 还是推断 |
| **能跑** | 真机/模拟器上主功能出现 | ✅（无设备必须标"未验收"） |
| 被绕过方复现 | 同版本重打包仍能过 | ✅ 最强 |

> **本机没有 adb / 设备**，所以本手册所有结论停在"静态可验证"：字节、反汇编、调用链三条都硬，
> 但"能不能起主程序"没有实测 —— **报告里必须这么写，不许把"分析跑通"当"绕过成功"**。
