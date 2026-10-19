# APK 层 — 字符串混淆与授权闸门（算法无关打法）

> **字符串混淆只改变「字符串长什么样」，不改变「谁在解它、解出来给谁用、谁拿它做判断」。**
> 所以不管它是 AES-GCM、单字节 XOR、base64+RC4 还是在 native 里现算的 —— 定位解码器、取密钥、
> 找闸门、下补丁的动作**完全一样**。本文件按 A0→A6 走，每层只回答一个问题。

---

## A0 · 先认清 APK 在整条链上的地位

```
控制面  APK / dex / Kotlin/Compose   ← 授权页、更新、分发；常是本地判定 → 可破
载荷面  .so / 下载的 ELF             ← 真正的活；常是服务端判决 → 通常不可本地破
特权面  内核模块 / root 脚本          ← 拿权限；与授权无关但是硬前提
```

最常见的开局错误：花一整晚去破**载荷面**的卡密，最后发现它是 Ed25519 服务端签名，
客户端里连判定逻辑都没有；而 **APK 层的卡密是本地 JSON 字段**，两字节就过。
→ **先做 `01-triage.md` 的三问，再决定动哪一层。**

---

## A1 · 三分钟拆到"哪些文件是活的"

不要一上来反编译。先做这三步。

### 1.1 条目清单 + 分组

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z=[IO.Compression.ZipFile]::OpenRead($apk)
$z.Entries | Group-Object { ($_.FullName -split '/')[0] } | Sort-Object Count -Descending | Select Count,Name
$z.Entries | ? { $_.FullName -match '^(lib|assets|classes)' } | Select FullName,Length
```

或者直接用脚本（含判读）：

```powershell
python scripts\autotriage.py x.apk     # APK 分支会打印条目分组 / dex 表 / so 表 / 极小 dex
```

**四个信号（与加密方式无关）**：

| 信号 | 含义 |
|---|---|
| 只有一个 `classes.dex` 且很小（几十 KB） | 大概率**加固**：真代码被搬到 `libjiagu*.so` 之类 |
| dex 很大（几十 MB）、有 `classes2..N` | **没加固**，是真代码（实测：20MB+11MB+10MB+6MB） |
| 出现一个**极小的 dex**（几千字节） | **高度可疑**：混淆工具常把解码器单独打成一个小 dex（实测 2292 字节，52 条串） |
| `lib/*.so` 只有寥寥几个、名字有规律 | 自有 native 库，通常是真正的活 |

### 1.2 定位自有包名

不反编译也能拿：解 `AndroidManifest.xml` 的字符串池。

```powershell
python scripts\axml.py AndroidManifest.xml       # → 包名 / Activity / 权限 / UI 文案
python scripts\autotriage.py x.apk              # 打印 package=（公共前缀算法，避开 .fileprovider 之类子包）
```

### 1.3 把"自有类"和"第三方库"分开（**这一步决定后面快两个数量级**）

第三方（AndroidX / Compose / OkHttp / BouncyCastle / coil）占 90%+ 体积，自有代码往往只有几百个类。

```powershell
python scripts\dexql.py classes3.dex --classes
# == 类总数 7502；自有包名前缀（Top）: com/painkiller, cn/mucute, coil3/...
python scripts\dexql.py classes3.dex --method ""     # 或先 --gates 看候选
```

脚本内置三方前缀表（`androidx/android/java/javax/kotlin/kotlinx/dalvik/com.google/com.android/
org.bouncycastle/okhttp3/com.squareup/...`），`--gates/--decoders` 默认只扫自有类。
实测：7502 个类里，自有 3647 个（com.*），三方 3855 个 —— 搜索成本直接砍半以上，且噪声消失。

---

## A2 · 定位字符串解码器 —— 认形状，不认算法

> **解码器必须在客户端，所以密钥也必须在客户端。** 这不是运气，是必然：客户端要展示字符串就必须能解。
> 所以问题永远不是"能不能解"，而是"它藏在哪"。

### 2.1 解码器的四个形状特征（命中两个就锁定）

| # | 特征 | 为什么必然出现 |
|---|---|---|
| 1 | 签名是 `String → String`（或 `(String,int)`） | 要替换被混淆的字符串字面量 |
| 2 | 有**固定长度前缀**处理：`substring(N)` / `startsWith` / `split` | 用来标记"这是混淆串"（实测前缀 `f1:` 三字符） |
| 3 | 有**编码层**：`Base64.decode` / `Hex` / `URLDecoder` | 二进制密文要塞进字符串常量 |
| 4 | 有**缓存**：`Map.put` / `ConcurrentHashMap` | 同一串多处引用，不缓存性能会崩 |

```powershell
python scripts\dexql.py classes5.dex --decoders --static
# == 解码器候选 1 个（>=2 特征）
#    score=5 Lx/rd78…;->d(Ljava/lang/String;)Ljava/lang/String;  base64,cache,cipher,prefix,str->str
```

### 2.2 实测解码器原文（四个特征全中）

```java
String d(String s) {
    String v = values.get(s); if (v != null) return v;       // 特征4 缓存
    byte[] data = Base64.decode(s.substring(3), 2);          // 特征2 前缀 + 特征3 编码
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");      // 真正的算法在这里
    // iv = data[0..12); key = Base64.decode(encodedKey)
    byte[] p = c.doFinal(data, 12, data.length - 12);
    char[] cs = new char[p.length/2];
    for (...) cs[i] = (char)(((p[2i]&0xFF)<<8) | (p[2i+1]&0xFF));   // 明文按 UTF-16BE 拼 char
    return new String(cs).intern();
}
```

> **明文不是直接 UTF-8。** 解出来后再按 UTF-16BE 两字节拼 char；只按 UTF-8 解会得到乱码，
> 然后误判"解错了"。通用读法：**先看返回值的组装方式**（`new String(char[])` / `new String(bytes,charset)`），
> 再决定怎么解读明文 —— 这一步与加密算法无关。

### 2.3 密钥的四个藏点（按命中率排序）

| 顺位 | 藏点 | 怎么取 | 实测 |
|---|---|---|---|
| 1 | **静态字段初值**（`static_values_off`） | 不在 `<clinit>` 里！解 `class_def_item` 的 static values | ✅ `encodedKey` 一次命中 |
| 2 | 资源池 / assets / **小 dex 的字符串池** | dump 整个小 dex 的字符串 | ✅ 52 条串里第 39 条 |
| 3 | native 库 `.rodata` | `strings` + 交叉引用 | — |
| 4 | native 算出再回填（要跑起来） | 动态 | — |

```powershell
python scripts\dexql.py classes5.dex --static
#   Lx/rd78…;->encodedKey:Ljava/lang/String; = 'bve1ygn5pawOgM8+tCZImdKSu7XCOk/bRfuZxbIeztg='
python scripts\dexql.py classes5.dex --strings      # 52 条，一眼看完
```

> **最常被错过的一点**：`<clinit>` 里没有赋值 ≠ 字段为空。Java 静态字段初值可以存在
> `class_data_item` 的 `static_values_off`（`encoded_array`）里。反编译工具显示成
> `static String encodedKey = "..."`，但手写 DEX 解析只看 `<clinit>` 就会漏。
> `dexql.py --static` 专门解这个。

### 2.4 离线复现解码器

拿到密钥 + 算法后，**用纯 Python 复现**，比在手机上跑快一百倍：

```python
import base64, aesgcm                      # scripts/aesgcm.py：纯 Python AES-256 + GCM
key = base64.b64decode('bve1ygn5…')        # 33 字节 base64 → 32 字节 key
raw = aesgcm.gcm_decrypt(key, iv, ct)      # GCM 解密不需要校验 tag
```

> **自检是硬要求**：自实现密码算法必须先过标准测试向量（AES-256 用 FIPS-197 附录 C.3：
> key=`000102…1f`、pt=`00112233…ff`、ct=`8ea2b7ca516745bfeafc49904b496089`）。
> 过了再解目标 —— 否则你分不清"算法写错"和"密钥取错"，会浪费几个小时。
> `python scripts\aesgcm.py` 会自己跑这条向量。

---

## A3 · 解出来的字符串怎么用（造靶子，不是目的）

解字符串只是为了让后面的搜索**有靶子**。真正的目标是：**这些字段名被谁读、读来做什么判断。**

实测解出的字段名直接给出 JSON schema 与判定点：

```
ok            ← 唯一的成功标志          message / reason      ← 提示语
expiresAtMs   ← 只用于显示              remainingSeconds      ← 只用于显示
cardType cardStatus deviceId unbindCount secondaryAuth
```

**关键判断：哪些是"门禁"，哪些只是"显示"**：
- 只被 UI 读的（过期时间、剩余天数、卡类型）→ **不管它**
- 被分支消费的（`ok` / `verified` / `granted`）→ 这才是靶子

---

## A4 · 找闸门：从"总闸门"倒着找，不要逐个判定打

### 4.1 先找调用者，再找分支

```powershell
python scripts\find_use.py classes3.dex 'NativeVerify;->verify'
#   Lcom/painkiller/nb/AccessActionsKt;->verify(MainActivity;String;)V
# 再往上：谁调用 AccessActionsKt.verify / verifyOrLaunch？
python scripts\dexql.py classes3.dex --gates --pkg com/painkiller/nb
```

### 4.2 命名规律（Compose/Kotlin 项目极其好用）

```
xxxState           → 状态槽        verifiedState / rootGrantedState / busyState
xxxOrYyy           → 总闸门        verifyOrLaunch  ← 名字直接把逻辑写出来了
getXxx$app_release → 内部 getter   （$app_release 是 Kotlin internal 的混淆后缀）
```

实测 `--gates --pkg com/painkiller/nb` 的输出（score 排序）：

```
score=10  Lcom/painkiller/nb/AccessActionsKt;->verifyOrLaunch(Lcom/painkiller/nb/MainActivity;)V   [Or]
score=10  Lcom/painkiller/nb/AccessActionsKt;->verifyOrLaunch$lambda$0(MainActivity;String;)V      [Or]
score=8   Lcom/painkiller/nb/AccessActionsKt;->checkRootPermission(...)
score=8   Lcom/painkiller/nb/MainActivity;->getRootGrantedState$app_release()
```

> `verifyOrLaunch` = "验证或启动"，**它比 `verify()` 高一层，是决策点**。
> 第一次只找 `verify` 会改两处且漏路径；找到总闸门后 **一处两字节** 就结束。

### 4.3 闸门长什么样（实测原文）

```java
void verifyOrLaunch(MainActivity act) {
    if (!rootGranted) return;              // 无 root 拦住（与本主题无关的硬前提）
    if (busy) return;
    if (verified) {                        // ★ 0x5b  if-eqz verified -> 0x61
        TerminalActionsKt.a25(act);        // ★ 0x5d  直接启动
        return;
    }
    String card = act.getCardState().trim();
    if (card.isEmpty()) { showNotice(); return; }   // 没卡密 → 弹框
    ...
}
```

**`0x5b` 那一句就是全部。** 它与"卡密怎么加密、服务端怎么判"完全无关。

看这句话：

```powershell
python scripts\dexql.py classes3.dex --method "verifyOrLaunch"
```

---

## A5 · 判「这一层能不能破」—— 算法无关的三问

在动手改之前必须回答，否则可能白干（详见 `01-triage.md`）：

| 问 | 判据 | 结论 |
|---|---|---|
| ① 判决字段是本地的还是服务端下发的？ | 搜该字段在客户端有没有**本地成功值/成功分支**；只有 `optXxx(...)` 读取、没有本地赋值 → 服务端 | 本地→可破；服务端→只能绕过显示 |
| ② 客户端里有没有这个判定的**文本**？ | 把运行时看到的提示语拿去 payload 里搜字节 | 搜得到→本地；搜不到→服务端驱动 |
| ③ 有没有签名/认证挡住响应伪造？ | 搜 `Ed25519`/`EdDSA`/`X25519`/`签名无效`/证书固定 | 有→伪造死路（走 `05`）；无→可做假服务器 |

> 实测：原生二进制那层三问全中（提示语 0 命中 + Ed25519 + 验签密钥内建）→
> **该层卡密在架构上就不可本地绕过，不是难，是不存在这个入口**。
> 而 APK 层第①②问都是"本地" → 两字节解决。

---

## A6 · 补丁：五条原则 + 实际操作

### 6.1 五条原则（与加密完全无关）

| # | 原则 | 理由 |
|---|---|---|
| 1 | **越上层越好** | 改 1 条（总闸门）> 改 3 条（各判定）> 改 N 条（每个功能门） |
| 2 | **`nop` 优于 `goto`** | 不改偏移；不碰 try/catch 表、packed-switch 表；不会因跳转距离超限出错 |
| 3 | **等长优于变长** | dalvik 里改指令长度会移动后面所有分支偏移，等于重算一遍 |
| 4 | **只改必要的字节** | 实测最终只改 **2 个字节**；改动越小越容易核对 |
| 5 | **改前记原字节 + 期望字节 + 文件偏移** | 后面必须读回复核；说不清原字节的人一定会改错 |

### 6.2 三种粒度（同一个目标）

| 方案 | 位置 | 改动量 | 评价 |
|---|---|---|---|
| 逐个判定 | `NativeVerify.verify` 0x82 + `AccessActionsKt.verify` 0x54 | 2 处 ×4 字节 | 能过，但没覆盖"native 调用抛异常"的路径 |
| **总闸门** | `verifyOrLaunch` 0x5b | **1 处 ×2 字节** | ✅ 首选：`verified` 恒真 → 永远直接启动，卡密流程根本不被调用 |
| 别人成品的方案 | 注入 600KB 原生 hook 框架 | 600KB + 2 个 dex | 能过但没必要 |

### 6.3 dalvik 补丁的实际操作

```python
# code_item 结构：registers_size(u16) ins_size(u16) outs_size(u16) tries_size(u16)
#                debug_info_off(u32) insns_size(u32)  → insns 从 code_off+16 开始
fo = code_off + 16 + cu * 2                    # cu = 指令在方法体内的序号（代码单元）
assert d[fo:fo+4].hex(' ') == '38 00 06 00'    # if-eqz v0,+6  ← 必须校验原字节
d[fo:fo+4] = b'\x00\x00\x00\x00'               # if-eqz v0,+6  →  nop; nop
```

```powershell
python scripts\patch_dex.py in.dex out.dex --offset 0x5b --size 2 --expect "38 00" --write "00 00"
# 写前校验原字节；写后自动读回并再核一次
```

> **判断"这条分支改哪个方向"**：`if-eqz v0, ->X` 是 v0==0 时**跳到** X。
> - 想让"已验证"直接过去 → 把这一句整个 `nop` 掉（落到后面的成功代码）
> - 想让"失败也当成功" → 也是 `nop` 掉（失败分支是跳出去的那一边）
> **先看清 `if-eqz` 的目标是成功还是失败，再决定 nop 还是 invert。这一步最容易搞反。**

---

## A7 · 重打包两个必踩坑（纯工程）

### 7.1 `.so` 是 STORED 就必须页对齐

```
先看原 APK 里 so 的 compress_type：
  method=0 (STORED)   → 会被 mmap 直接映射，必须 4KB（新设备 16KB）页对齐
  method=8 (DEFLATE)  → 安装时解压，无所谓
```

原 APK 里 `.so` 几乎总是 **STORED**（`extractNativeLibs=false` 时必需）。
用 Python `zipfile` 重打包**不会**做对齐 → **即使签了名也装不上，或者装上就崩**。

**两个正确做法**：
1. **别自己重打包** —— 只替换单个文件，让 MT 管理器 / apktool / apksigner 处理对齐；
2. 自己做的话，给 STORED 条目的 local header 塞 padding extra field，把 data 起点顶到 4096 倍数。

```powershell
python scripts\autotriage.py x.apk    # 会打印 STORED 的 so 清单（重打包注意项）
```

### 7.2 改完必须重签名，且先确认「App 不校验自身签名」

```powershell
python scripts\find_use.py classes3.dex 'getPackageInfo'
python scripts\find_use.py classes3.dex 'signatures'
python scripts\find_use.py classes3.dex 'originalSigners'
# 三处都 0 命中，才敢换签名重装
```

换签名后**必须卸载原版**再装（同包名不同签名不能覆盖安装），会丢应用数据。

> 自查工具理解：`apksigner`（build-tools）能一把做完对齐 + v1/v2/v3 签名。
> 只有 JRE 时 `keytool` 能生成密钥但 `jarsigner` 不一定在；**v2 签名的内容摘要算法很容易写错**，
> 所以**别手搓 v2**，直接用现成工具（`v2parse.py` 只用来验证理解，不用来签名）。

---

## A8 · 拿到「别人做好的破解版」—— 性价比最高的一招

一个能跑的成品胜过十篇分析文章。但**不要反编译它全部代码**，做**逐条目 diff**。

```powershell
python scripts\diff_apk.py 原版.apk 破解版.apk
```

只看四件事：① 条目集合差异（新增/删除）② 内容哈希差异 ③ 签名差异 ④ 新增条目的用途。

实测 diff 结果（一眼看出手法）：

| 差异 | 读出来的信息 |
|---|---|
| `META-INF/ZAKA.RSA` ← 原 `APKFORGE.RSA` | 换签名了 → **App 不校验自身签名**（他能装，你也能） |
| `libyunyan.so` / `res/mj.xml` **完全一致** | 授权库和登录页一个字没改 → 破解不在 native、不在 UI |
| 新增 `classes6.dex`(6448)+`classes7.dex`(660)+`libnf<hash>.so`(600488) | 注入式方案 |
| 注入的 `.so` 里有一串 Java 方法签名 | 直接给出 hook 目标：`(MainActivity;String;)V` = `AccessActionsKt.verify`、`verifyOrLaunch$lambda$0` |

> **「没改什么」比「改了什么」信息量更大**：
> - `libyunyan.so` 没改 → 破解点不在 native
> - `res/mj.xml` 没改 → 不是改 UI 蒙混
> - 原 dex 判定逻辑也没改（体积变化来自反编译重建）→ 他是**运行时 hook**，不是字节补丁
> - 由此反推：我们要达成的效果，**改字节比 hook 更小更干净**（2 字节 vs 600KB）
>
> **破解者不一定懂判定逻辑 —— 他只要知道 hook 哪个方法。** 而我们先读了逻辑，所以能定位到更上层的一条指令。
> **diff 成品是"抄答案"，读逻辑是"会做题"，两个都要做。**

---

## A9 · Checklist

```
[ ] 头 16 字节 → 真身（不信扩展名）
[ ] 条目分组：dex 大小 / so 清单 / 有没有"极小的 dex" / so 是不是 STORED
[ ] 解 manifest 字符串池 → 包名 + 入口 + 权限
[ ] 圈自有类（dexql --classes），后面只在这几百个类里搜
[ ] 找解码器：String→String + 固定前缀 + Base64/Hex + Map 缓存（四特征两中就锁）
[ ] 找密钥：static_values / 小 dex 字符串池 / .rodata / native 现算（按此顺序）
[ ] 纯 Python 复现解码器，先过 FIPS-197 再批量解串
[ ] 解出的字段名 → find_use 找消费者 → 找"总闸门"（xxxOrYyy / xxxState）
[ ] 三问定性：本地判决？客户端有文本？有签名？ → 决定可破 / 不可破
[ ] 补丁：最上层、nop、等长、最少字节，写前记原字节，写后读回
[ ] 重打包：.so 页对齐 + 重签名（先确认不校验自身签名）+ 卸载重装
[ ] 有成品就先 diff：新增了什么 / 没改什么 / 签名差异 / hook 目标
```

## A10 · 换算法也成立的核心四条

1. **解码器在客户端 ⇒ 密钥在客户端。** 任何算法都逃不掉；问题只是"藏在哪"。
2. **找闸门不看加密，看"谁消费"。** 字符串只是靶子；分支才是目标，而分支形态由代码写死，与混淆无关。
3. **补丁优先级与算法无关。** 越上层越好、`nop` 优于 `goto`、等长优于变长、字节越少越好。
4. **能不能破由"判决归属"决定，不由"加密强度"决定。** 服务端签名判决 = 不可本地破；本地 JSON 字段 = 两字节。

---

## A11 · 壳加载器：真身在 assets，dex 只是壳

| 观察 | 结论 |
|---|---|
| dex 里搜不到授权/卡密字样，但运行时确实有卡密提示 | 真身在 **`assets/` 载荷**（ELF/.so/数据文件） |
| dex 里有 `chmod`/`su`/`insmod`/`ProcessBuilder`/`assets/`/`getFilesDir` | dex 只是**加载器**：解包 → 校验 → 提权 → 起进程 |
| `assets/payloads/**` 大文件 + `assets/catalog/*.json` 列着 `sha256/sizeBytes` | 有**清单式完整性校验** |
| `assets/**/*.ko` 成规模（按内核版本命名） | 驱动由 APK 装；**授权不在这一层** |

### 三条校验链（改载荷前必查）

| 链 | 长什么样 | 改法 |
|---|---|---|
| **清单链** | `{"program":{"sha256":"6fa1…","sizeBytes":11395320}}` | 把 `program.sha256` **等长原地替换**成新载荷哈希；`sizeBytes` 不动；驱动那几十条**一条都别碰** |
| **代码链** | dex 里 `MessageDigest` + `equalsIgnoreCase` + `throw "SHA-256 校验失败："+s` | 字节码一处 `nop` |
| **脚本链** | 拼出来的 `sha256sum "$DST.tmp"` + `exit 72` | 它用的是**同一个清单值** ⇒ 清单改对，脚本链自动过 |

> 报错里那串哈希是**它算出来的**，不是期望值。别拿它去比对 —— 它只说明"实际≠期望"。

### dex 静态补丁：三步一体（少一步 = 装得上、点开崩）

1. **改指令**（如 `38 02 35 00` → `00 00 00 00` 两条 nop）
2. **重算头部 SHA-1**：`signature` @ `0x0C`，20 字节 = `SHA1(dex[32:])`
3. **重算头部 Adler-32**：`checksum` @ `0x08`，4 字节小端 = `adler32(dex[12:])`

```powershell
python scripts\patch_dex.py in.dex out.dex --offset 0x656e1a --expect "38 00" --write "00 00"
# 脚本自动做三步并读回校验；验收硬判据 = 解析器能否加载（等价于 jadx 能打开）
```

> **验收方式不是"字节改对了"，而是"dex 解析器能不能加载"。** 只改指令不重算头部 ⇒
> 解析器直接 `Load failed! No classes for decompile`，装到手机上就是"点开图标瞬间退出" ——
> 极易被误判成"加固/自检"。

### 版本码坑（"改了好几次，装上去还是旧版"）

| 字段 | 位置 | 作用 |
|---|---|---|
| `versionName` | AXML 字符串池（UTF-16，等长可原地替换） | **只影响显示** |
| `versionCode` | AXML 属性 inline int（原地写 4 字节） | **安装器判"是否更新"的唯一依据** |

只改 `versionName` 不改 `versionCode` ⇒ 国产 ROM 安装器遇到同版本码**静默跳过**。
两个一起改、`versionCode` 递增、产物换新文件名。
