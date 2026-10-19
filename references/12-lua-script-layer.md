# 脚本层 — Lua 授权闸门与替换密码混淆

> **很多"脚本壳"（AppLua / GG 系 / AideLua / AndroLua）把授权写在一堆 `.lua` 里，dex 只是跑 Lua 的容器。**
> 这种样本的卡密闸门**不是** dex 里的 `if-eqz`，而是 Lua 里的一句 `if f.code==1 then`。
> 保护强度通常只有"字符串替换密码 + 不透明谓词"——**能解、能改、能重签**，而且改的是**源码文本**，不是字节码。
>
> 实证：王者减 CD 1.0.5（`08-casebook.md`）—— 33 MB APK，最终**只改一个 `.lua` 文件的 4 处首行**，
> 复刻原证书签名后覆盖安装，任意卡密进主界面、功能可用。

---

## 零 · 先判"是不是脚本层"（四条中三条即成立）

| # | 判据 | 看什么 |
|---|---|---|
| ① | `assets/` 里有**成规模** `.lua` | 几十个到上千个；常混随机名 `.png/.xml`（付费 UI 素材） |
| ② | dex 里出现 `org/luaj/vm2/*` | LuaJ = Java 实现的 Lua 5.2，这类壳的标配 |
| ③ | 有"给 Lua 用的引擎库" | `libkeystoneA.so`（汇编器）/ `libop.so` / `libgg*.so` / `AGG_LUA_API_*.json` |
| ④ | `.lua` 文件头 | 源码（可读文本）或字节码 `1b 4c 75 61 52 00 01 04 04 04 08`（`\x1bLua` + **0x52** = 5.2） |

**脚本层的三个先天弱点**（比任何加密分析都省时间）：
1. **脚本必须能被执行 ⇒ 它要么是源码、要么是标准字节码** —— 不可能像 native 那样整段加密（没有自解密器）。
2. **脚本是磁盘上的独立文件** ⇒ 改它不需要碰 dex/so，**不用脱壳、不用打内存补丁**。
3. **字符串混淆是"运算级"的**（拼接、查表、反转），不是密码学 ⇒ 一定能离线复现，缺的只是那几行定义。

```powershell
# 一条命令判层（有 luaq.py 时）
python scripts\luaq.py <apk>
# 手工判层
python -c "import zipfile;z=zipfile.ZipFile(r'x.apk');print([n for n in z.namelist() if n.endswith('.lua')][:20])"
```

---

## 一 · 定位：闸门在 dex 还是在 Lua（错了会白跑一整晚）

### 1.1 字符串归属分流

```
提示语在 resources.arsc  →  UI 文案在壳里，逻辑可能在 Lua
提示语只在 .lua 里        →  纯 Lua 文案
提示语哪儿都没有          →  服务端逐句下发（回 05-server-verdict.md）
```

实测：`卡密` 在 dex 里 **0 命中**，`resources.arsc` 里只有一条 `R.string.user_login = "卡密登录"`。

### 1.2 从"资源 → 调用者 → 谁在喂数据"倒推（最硬的一条）

```
R.string.user_login (0x7f13045e)
  └ 引用者：android/fix/components/ui/UserLabCardKt;->Header / SignButton
      └ 调用者：SidebarMenu;->ComposeType(..., Lorg/luaj/vm2/LuaTable; ...)
          ⇒ 这个界面是 Lua 通过宿主 API 渲染出来的
```

**只要参数里出现 `LuaTable`，就说明 UI 是脚本驱动的** —— 闸门必然在脚本里。

### 1.3 找"脚本从哪来"（决定交付形态）

```
Landroid/ext/v4;->onClick(Landroid/view/View;)V
   Tools.readAssetsFile("☁️.lua")  →  MainService.executeScript(InputStream,int,String)
```

同时确认两件事：
- **唯一性**：整个 dex 里这个文件名只有 1 处加载点（没有第二条旁路）；
- **无校验**：加载前**没有** hash/签名/长度校验分支，也没有 `loadfile/loadstring` 旁路（有就一并改）。

---

## 二 · 读混淆：脚本层三种典型形态

| 形态 | 长什么样 | 破法 |
|---|---|---|
| **A. 字面量表 + 单字符拼接** | `DG[436]="\219\156…"; local f=Zo(I[138]..n({(u..y)..Q, …}))` | 把表/变量定义抓出来，用脚本复现求值 |
| **B. 全量字节码（无源码）** | `\x1bLua` + 版本 0x52 | `luac -l` / 反编译器；或 `load()` 后在宿主里 dump 字符串 |
| **C. VM 化/自研解释器** | 字节码里只有一个大 `while` 分发表 | 按 `11-runtime-patching.md` 打桩，**不逆 VM** |

> **别被"看上去像加密"吓到**：`DG[n]` 的值是十进制转义的高位字节（`\219\156\219\133…`），第一眼像密文；
> 实际上它们是**字母表的成员** —— 174 个"单字节"，其中高位字节是中文 UTF-8 的三字节片段。
> **判据：按字节长度统计一下，绝大多数是 1 字节 ⇒ 它就是一张表，不是密文。**

---

## 三 · 这类壳的通用密码结构：数字 token + 轮转替换

### 3.1 六个定义，抓齐就能解（实测）

```lua
-- ① 数字变量（把"数字"伪装成表达式）
local C=6; local B=C-3; local Q=B+2; local V=Q-1; local t=V-4;
local F=t+2; local q=F+5; local u=q-6; local y=u+8; local r=y-1;
--   C=6 B=3 Q=5 V=4 t=0 F=2 q=7 u=1 y=9 r=8      ⇒ (u..y)..Q == "195"

-- ② 字母表（174 项，每项是 DG[n] 一个单字节）
local a={DG[274], DG[260], DG[530], …}

-- ③ token 表（"195" → 0..173）
local x={["195"]=10, ["102"]=…, …}

-- ④ 轮转量（常藏在"看着像版本号/常量"的地方）
_DS={s=875+(_DSA or 0)}
local A = _DS.s % 174                  -- 875 % 174 = 5

-- ⑤ 解码函数
local function n(d)
  local G, A = nil, _DS.s % 174
  for w=1,#d do G = G .. a[((x[d[w]] + A) % 174) + 1] end
  return G
end

-- ⑥ 第二张表（存的也是 token 序列，取用时可能再 :reverse()）
local I={{(F..V)..u}, {V..V,(F..Q)..t,…}, …}
```

### 3.2 复现（十分钟，纯 Python 三张表）

```python
# 1) 抓 DG[n]="…" → 按 Lua 转义还原成 bytes
# 2) 抓 local a={…} → 174 项；抓 local x={…} → token→值
#     token 求值：把 (u..y)..Q 这种表达式里的变量替换成数字后拼接
# 3) 求值
A = 875 % 174
dec = lambda toks: bytes(ALPHA[(X[t] + A) % 174] for t in toks)
```

**第一发验证成功的标志：解出的是有语义的东西**。实测第 3 条就是 `1.0.5`，
第 1~3 条拼起来是一个 `MIGfMA0GCSqGSIb3…` 的 **RSA 公钥**。
**解出来是乱码 ⇒ 轮转量或字母表顺序抓错了，别往下走。**

### 3.3 全量还原（把混淆脚本变成"人话脚本"）

替换四类表达式，替换完的文本可直接读：

| 原式 | 替换为 |
|---|---|
| `n({token,…})` | 解出的字符串字面量 |
| `I[k]` | 解出（按存储方向）的字面量 |
| `I[k]:reverse()` | 解出后再反转的字面量 |
| `DG[k]` | 字面量（函数引用/nil 保留不动） |

实测：305,748 B（748 处 `n()`、269 条 `I[]`、575 条 `DG[]`）→ **261,895 B 可读 Lua**。
**可读之后，闸门是一眼就能看见的一行** —— 这才是这一步的真正收益。

---

## 四 · 判决归属：签名挡得住"伪造"，挡不住"改判"

### 4.1 先做归属三问（结论可以照样是"服务端"）

| 问 | 实测答案 |
|---|---|
| 判定字段本地有没有赋值 | 没有；`code/token/endTime` 全部来自响应 |
| 客户端有没有底本提示语 | 没有 → 服务端下发 `msg` |
| 有没有签名/验签 | **有**：响应经 `ro()` 校验，RSA 公钥硬编码在脚本；`/api/expand/new-ver` 同款 |

⇒ 判决归属：**服务端**。伪造成功响应 = 死路（铁律不变）。

### 4.2 但"服务端判决" ≠ "判定不可绕过" —— 要问第二个问题

| 问题 | 由什么决定 | 本地能做吗 |
|---|---|---|
| **响应能不能伪造？** | 有没有服务端签名 | ❌ 不能（除非拿到私钥） |
| **判定能不能绕过？** | 判定结果**在哪被消费** | ✅ 能 —— 只要消费点在客户端 |

**真正的死路只有两种**：① 客户端改了也没数据可用（服务端下发必须的数据/权限）；
② 每个动作都要服务端现场签名授权（⇒ 改用 `05-server-verdict.md` 打"时效"）。

实测：`if f.code==1 then` 这个**分支**写在客户端 Lua 里，签名只保护"响应来源真实"，
不保护"分支往哪走" ⇒ **在消费点改判即可，服务器字节一个都不碰**。

### 4.3 闸门长什么样（可迁移的形状清单）

```lua
-- 登录：拿卡密换 token + 到期
local f = Zo('/api/single/login', function() return {card=d, safeCode=mf(), mac=w, timestamp=W()} end)
if f and f.code==1 then ...取 token/endTime... end

-- 心跳：定时复查（30s）
local m = D .. '/api/single/heart?' .. query        -- 'ok' / 'fail' / 'reject'
if G.code~=1 then return 'reject' end
-- 连续 5 次 fail 或一次 reject ⇒ ko() 停服

-- 环境闸：探活 + 版本闸（失败直接 exit）
if not oo() then DG[23](0) end

-- 强制更新：服务端 forced=1 时循环弹窗，直到退出
```

> 见到 `code==1` / `token` / `endTime` / `heart` / `safeCode` 这一组，就停止找"本地字段"。
> 闸门就三处：**登录 / 心跳 / 环境闸**（外加可选强制更新）。
> **只改登录 → 30 秒后心跳把用户踢回来；三处一起改才是完整绕过。**

---

## 五 · 补丁：脚本层独有的"等结构早退插入"

### 5.1 为什么选"函数首行插 `do … end`"

| 方案 | 改动量 | 风险 |
|---|---|---|
| **① 闸门函数首行 `do return … end`** | 一行文本 | 最小；不影响其余字节；`return` 在 `do` 块末位语法合法 |
| ② 响应解析后塞假表 `f={code=1,data={…}}` | 一行 | 需知道下游读哪些字段 |
| ③ hook HTTP 返回假 JSON | 宿主层 | 覆盖面大、污染别的接口；host 函数名依赖壳 |
| ④ 改 `code==1` 判定表达式 | 表达式 | 容易改反方向；混淆后难对齐 |

### 5.2 写法模板（实测四处，各一次唯一命中）

```lua
local function oo()  do return true end  …                -- 环境闸恒真（断网也能进）
local function Bp()  do return end       …                -- 跳过强制更新
local function Mo(d,G,A) do return 1,'登录成功' end …      -- 卡密任意输入直接通过
local function co()  do return 'ok' end  …                -- 心跳恒 ok，不再停服
```

> **两处容易漏的语义**：
> - `Mo()` 短路会**顺带跳过心跳的启动点**（原成功分支里才调 `Oo()`）。心跳只做授权监控、不影响业务载荷 ⇒ 无副作用；
>   但要确认"业务载荷"确实不依赖它。
> - `oo()` 恒真后，原本被它挡住的版本检查/远程变量会开始真的发请求；它们内部都有 `if not oo() then return end` +
>   `Zo()→nil` 的容错，不会因断网抛错。**唯一要防的是"强制更新"分支，所以 `Bp()` 必须一起改。**

### 5.3 语法自检（没有 Lua 解释器时）

```
用关键字 token 计数做"块平衡"：function / do / then / repeat +1，end −1
原文件 (17,4) == 补丁后 (17,4)   ⇒ 插入没破坏结构
```

`do … end` 内单个 `return` 是 Lua 语法允许的早退惯用法（5.1–5.4 与 LuaJ 都成立），
且**不需要**改 `if`/缩进/后续语句 —— 这就是"等结构"的意义。

---

## 六 · 重打包与签名：把"签名身份"一起复刻

### 6.1 三段式

```powershell
# 1) 逐条目复制重建（保留压缩方式/顺序），只换目标文件，剔除旧 META-INF 签名文件
python scripts\build_apk.py 原.apk 新目录\out.apk assets\☁️.lua=补丁版.lua
# 2) 对齐（-p 让 .so 按页对齐）
zipalign.exe -p -f 4 in.apk aligned.apk
# 3) 签名（v1+v2+v3 全开；min-sdk 取 manifest 的 minSdkVersion）
java -jar apksigner.jar sign --key testkey.pk8 --cert testkey.x509.pem ^
     --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true ^
     --min-sdk-version 15 --out out.apk aligned.apk
# 4) 验签
java -jar apksigner.jar verify -v --print-certs out.apk
```

### 6.2 关键一招：先读原包用的哪张证书，能复刻就复刻

```powershell
apksigner verify -v --print-certs 原包.apk
#   Signer #1 certificate DN: EMAILADDRESS=android@android.com, CN=Android, OU=Android, …
#   Signer #1 certificate SHA-256: a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc
```

`a40da80a…` + `CN=Android` = **AOSP testkey**（AOSP 源码里就有 `testkey.pk8` / `testkey.x509.pem`）。
用同一张 key 签 ⇒ **证书指纹与原包完全一致** ⇒ 同包名+同 versionCode+同签名 ⇒ **可直接覆盖安装、不丢数据**，
且任何"比对自身签名"的逻辑都不会被触发。

> **反过来说这也是判据**：社区壳里大量样本是 **AOSP testkey / debug.keystore** 签的。
> **先看证书再动手**：能复刻签名身份，交付形态就从"卸载重装"升级为"覆盖安装"。

### 6.3 交付验证清单（无设备也能做）

```
[ ] apksigner verify -v：v1/v2/v3 全 true，cert SHA-256 与原包一致
[ ] zipalign -c -p 4：rc=0
[ ] 产物内目标文件 == 本地补丁文件（sha256 逐字节）
[ ] 条目数一致，内容差异只有 2 条：目标脚本 + 重生成的 MANIFEST.MF
[ ] classes.dex / AndroidManifest.xml 与原包字节相同
[ ] 真机装、看到"登录成功 + 功能可用"（这一步只能由人完成）
```

---

## 七 · 失败教训（如实记）

> **手搓 v2 签名，第二次栽在同一处**：块结构能解析、能用样本自带证书验签成功，
> 但**内容摘要复算不出来** —— 3 个样本各试 10 余种组合（压缩/未压缩、CD 序/偏移序、EOCD 偏移替换…）**全对不上**。
> 结论：**不要手搓 v2，直接上官方 `apksigner`**。手搓 2 小时且不可信；下载 build-tools + 一条命令 = 5 分钟且一定对。

> **"无 Android SDK"不是不能签**：没有 SDK/adb/设备也能产出可安装的签名包 ——
> `build-tools_r34-windows.zip` 里只取 `lib/apksigner.jar` + `zipalign.exe` 两个文件（~1.8 MB），不必装整套。

> **一个容易误判的中间态**：原包 v2 签名块里只有 1 个摘要（正常 3 个），且 alg 写成 `0x0103`（签名算法号）。
> 这不代表包是坏的 —— `apksigner verify` 三档全过。**别拿"结构不规范"当"没签名"的证据。**

---

## 八 · 可迁移清单（遇到脚本壳照这个顺序）

```
1. 判层：assets/*.lua + org/luaj + keystone/汇编器 + AGG_LUA_API_* ⇒ 脚本层
2. 找脚本文件的唯一加载点，确认加载前无 hash/签名校验（有就一并改）
3. 字符串归属分流：CJK 提示语在 arsc ⇒ UI 在壳、逻辑在脚本；反查 R.string → Composable → LuaTable
4. 抓六个定义（数字变量/字母表/token表/轮转量/解码函数/第二张表）→ 三张表复现解码
5. 全量还原成可读 Lua，让闸门自己浮出来（748 处 n() 的样本 10 分钟可还原）
6. 归属三问 + 第二问：响应能否伪造（签名）／判定能否绕过（消费点在哪）
7. 三处一起改：登录闸 + 心跳 + 环境闸（+ 强制更新）；用 `do return … end` 等结构插入
8. 重打包三段式：逐条重建 → zipalign -p → apksigner v1+v2+v3；能复刻原证书就复刻
9. 验签 + 逐条目 diff（只允许脚本和 MANIFEST 变），再交付
10. 别做的：伪造/重放签名、改 dex 找 if-eqz（本例根本没有）、对没加固没加密的脚本先脱壳
```

---

## 九 · 与其它文件的关系

| 文件 | 关系 |
|---|---|
| `02-apk-layer.md` | 同样是"控制面"，但那边闸门在 **dex 字节码**（改字节），这边在 **Lua 源码**（改文本） |
| `05-server-verdict.md` | 服务端判决的出口；本文 §4.2 是"消费点可改判"的分支 |
| `11-runtime-patching.md` | 脚本被 VM 化时的退路（打宿主，不逆 VM） |
| `07-verification.md` | 脚本层的"过门"= 装机后任意卡密进主界面 + 心跳活过 2 个周期 |
