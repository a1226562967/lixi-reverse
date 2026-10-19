# 工具链 — 本机实测、脚本串联、缺件纪律

> **能自己写 400 行解决的，就别去装一个工具链。**
> 这一页记录：本机到底有什么、13 个脚本各解决什么问题、怎么串、以及"缺工具时该怎么报"。

---

## 一 · 本机环境实测（2026-10-19 复测，动手前先跑一遍）

| 项 | 状态 |
|---|---|
| **系统 Python 3.12.10** | `C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe`；有 `capstone 5.0.7`、`cryptography 50.0.2`；**无** `elftools/unicorn/numpy` |
| **DSH 内置 Python** | `~\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe`；有 `elftools 0.33`、`unicorn 2.1.4`、`numpy`；**无** capstone |
| IDA Pro 9.3 | ✅ 已安装已授权（含 `HEXARM64`）+ `idalib` + `re-mcp-ida v3.0.3` |
| x64dbg / x32dbg 0.0.2.5 | ✅ `C:\x64dbg\release\{x64,x32}` + MCP 插件（9094/9095） |
| DIE / diec / diel | ✅ 随 `xiaotao-win-flow` 分发（`tools\die\`） |
| JRE 17 | ✅ `D:\Tools\jre17`（有 `java` + `keytool`；**缺** `javac`/`jarsigner`） |
| **缺**：`adb` / `apksigner` / `zipalign` / `jadx` / `apktool` / `baksmali` | ❌ 全缺（所以自写 DEX 解析；重签名要靠外部工具） |
| **缺**：`frida` / `gdb-multiarch` / `qemu-aarch64` / `ghidra` / `r2` | ❌ 全缺 |
| 设备 / 模拟器 | ❌ 无 —— **动态侧仍空** |

一键探测：

```powershell
$py312='C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe'
$pydsh="$env:USERPROFILE\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
foreach($n in @('python','node','uv','git','java','adb','apksigner','jadx','apktool')){ $c=Get-Command $n -EA SilentlyContinue; if($c){"OK   $n -> $($c.Source)"}else{"--   $n 缺"} }
# 注意：pyelftools 提供的模块名是 elftools（写 pyelftools 的探针永远报"缺"）
foreach($p in @($py312,$pydsh)){ & $p -c "import sys,importlib.util as u;print('==',sys.executable);[print('  OK ' if u.find_spec(m) else '  -- ',m) for m in ['elftools','unicorn','capstone','cryptography','numpy','idapro']]" }
```

> **两个 Python 的分工**：`v2parse.py`（验签）用系统 3.12；要 `unicorn` 仿真用 DSH 内置；
> 其余脚本两种都能跑（stdlib-only，capstone 缺失自动降级，不报错也不假装有结果）。

---

## 二 · 13 个脚本

| 脚本 | 解决什么 | 关键点 |
|---|---|---|
| `autotriage.py` | **总入口**：判层→判型→判决归属→下一步命令 | 立案 + 报告 + NEXT，3.6s 跑完 38MB APK |
| `elfprobe.py` | ELF 形态判型 | 熵/top1/6-gram/引用密度配对/自解密四指纹/`filesz=0`/内嵌 ELF/capstone 无效比例 |
| `payload.py` | 载体链剥离 | shell头+尾随压缩流 / base64 heredoc / 多 ELF / 内嵌 ELF；带 provenance |
| `koprobe.py` | `.ko` 判型与能力面 | `e_type` + modinfo 五字段 + 13 类符号指纹；支持 `.ko.sh` / `driver.zip` |
| `verify.py` | **断言裁决层** | claim → VERIFIED/REFUTED/INCONCLUSIVE + **信息量权重**；ledger 按 sha256 记账、refuted 变 KNOWN FALSE；`--min-information` 是 grounded 门槛 |
| `jniprobe.py` | **JNI 动态注册还原** | 扫 `JNINativeMethod` 三指针表（先应用 R_AARCH64_RELATIVE）；输出「Java 方法名 → 原生地址」，补上符号表里看不到 `Java_*` 的死角 |
| `rkprobe.py` | **运行时打桩点侦察** | thunk(`br x17`) / `.rela.plt` 横切 / `.bss` 单例标志 / 时间门 / `RELATIVE→跳板`；15s 扫 67MB |
| `dexql.py` | DEX 查询层 | `static_values` / 解码器四特征 / 闸门候选 / 密钥候选 / 单方法反汇编 / 自有类过滤 |
| `dexlib.py` | DEX 结构 + dalvik 反汇编 | opcode 表 + 指令长度表（约 400 行） |
| `dexdump.py` | 按类/方法 dump | `--list` 圈类 → `--class` 精读 |
| `find_use.py` | 谁引用了某方法/字段 | **定位消费者**最快手段 |
| `patch_dex.py` | 打补丁 + 读回复核 | 写前校验原字节 |
| `axml.py` | AXML/ARSC 字符串池 | 包名 / Activity / 权限 / UI 文案 |
| `aesgcm.py` | 纯 Python AES-256-GCM | 自带 FIPS-197 自检 |
| `diff_apk.py` | 逐条目 diff | 看"没改什么"信息量更大 |
| `v2parse.py` | APK v2 签名块解析与验签 | 自证对签名格式的理解（**不用它签名**） |

---

## 三 · 典型串联

### 3.1 未知样本（默认走这条）

```powershell
python scripts\autotriage.py "D:\目标\样本"
# → analysis\REPORT.md（判层+判型+坐标+下一步）+ artifacts\ + AGENTS.md + attempts.md
```

### 3.2 APK 卡密（控制面）

```powershell
$case = "…\cases\<名>-<sha8>"
python scripts\dexql.py $case\artifacts\classes3.dex --classes                  # 圈自有类
python scripts\dexql.py $case\artifacts\classes5.dex --strings --static --decoders  # 极小 dex = 解码器
python scripts\dexql.py $case\artifacts\classes3.dex --gates --pkg com/xxx       # 总闸门
python scripts\dexql.py $case\artifacts\classes3.dex --method verifyOrLaunch     # 看那句 if-eqz
python scripts\find_use.py $case\artifacts\classes3.dex 'Xxx;->verify'           # 消费点
python scripts\patch_dex.py in.dex out.dex --offset 0x5b --size 2 --expect "38 00" --write "00 00"
python scripts\diff_apk.py 原版.apk 破解版.apk                                   # 有成品就先 diff
```

### 3.3 载荷（载荷面）

```powershell
python scripts\elfprobe.py x.sh                      # 先判形态（含载体链线索）
python scripts\payload.py x.zip --all --dump out     # 剥出真 ELF + provenance
python scripts\elfprobe.py out\01_x.elf --json o.json
python scripts\koprobe.py  driver.zip                # 若拷出的东西是 .ko
```

### 3.4 运行时打桩（零修改）

```powershell
python scripts\rkprobe.py <载荷 ELF> --json rk.json     # 五类打桩点一次列全
# 然后按 references\11-runtime-patching.md 分段打桩 + 喂狗；工具 = /proc/pid/mem（不要 ptrace）
```

### 3.5 服务端判决（先用假服务器侦察，再重放）

```powershell
# 侦察阶段目标是拿到 SNI 与请求形态；重放阶段要的是原样字节
# 详见 references\05-server-verdict.md（含 iptables 四条 + 758 字节万能 JSON + PTM2 格式）
```

---

## 四 · 缺件纪律（硬版本）

任何一步发现缺依赖/缺工具/缺权限/缺文件/缺样本：

```
① 当场停下来说清三件事：缺什么（名字+版本）、卡在哪一步、有哪几种拿到它的办法
② 或者直接装 —— 仅限本技能的自动安装通道（无：本技能不装第三方工具）
③ 禁止：侥幸绕过（假装不需要）、跳过继续、用"应该可以/大概能"替代验证、把缺件写成"已完成"
```

**本轮真实缺件**（记录下来，别再问第二遍）：
- `apksigner` / `jarsigner` → 改用 MT 管理器签名（或让用户提供 build-tools）
- 动态侧（adb / 设备 / frida / gdb-multiarch / qemu）→ 静态替代：unicorn 仿真 + 找解码器骨架
- IDA 若某天授权失效 → 静态退化到 `capstone` 自建管线（`elfprobe.py` 已内置，无需 IDA）

---

## 五 · 能力边界（别错配）

| 任务 | 能做到 | 做不到 |
|---|---|---|
| 读 dex 字节码 | `dexdump.py` / `dexql.py`（够看逻辑） | 不是反编译器，没有 Java 源码形态 |
| 读二进制 XML | `axml.py`（字符串池） | 不还原 XML 树/属性绑定 |
| 静态反汇编 AArch64 | `elfprobe.py`（capstone）+ IDA `re-mcp-ida` | 伪代码填充区无法反编译（那不是可编译代码） |
| 动态调试 Android 原生 | ❌ 本机无设备/模拟器/frida/gdb | 只能静态 + unicorn 仿真 |
| APK 重签名 | ❌ 本机无 apksigner | 交外部工具（MT 管理器） |
| `.ko` 加载验证 | ❌ 无 root 设备 | 只能静态能力面 |

---

## 六 · 案件目录规范

```
<目标目录>\cases\<样本名>-<sha8>\
  AGENTS.md            ← 锚点：三层账 / 坐标 / 下一步 / 读档顺序（每次会话先读它）
  attempts.md          ← 流水：每轮动作 + 结果 + 证据等级
  analysis\
    REPORT.md          ← autotriage 生成的报告
    report.json        ← 机器可读（供后续脚本消费）
  artifacts\           ← 剥出来的产物（dex / elf / 抓包），带 sha256
```

> **上下文丢失后的读档顺序**：`AGENTS.md` → `attempts.md` 尾部 → `analysis/report.json`。
> 案件目录**不在工作目录链上**，不会被自动注入 —— 必须显式 `read`。

---

## 九 · 外部项目吸收台账（学什么 / 刻意不学什么）

参考了 5 个开源项目，**只吸收 4 条**，其余明确排除 —— 这就是本技能不臃肿的机制。

| 来源 | 学到的（已落地） | 为什么值得 |
|---|---|---|
| **SOMCP**（手机端 SO 逆向 MCP，46 工具） | ① `jniprobe.py`：JNI 动态注册还原 ② 盲扫把「可打印率」一起回传的证据纪律 ③ 加固/混淆/反调试按 **import / string / code_pattern 三级证据**分级 | 安卓 native 卡密几乎都走 `RegisterNatives`，符号表看不到 `Java_*` —— 这是我们原来的真空白 |
| **software-decard**（Electron 去卡密实战） | ⑥ `16-js-runtime-shim.md`：**「替身模块」手法族** + JS 运行时层判据（asar / .jsc / Hermes / WebView） | 「不改本体一字节，换个诚实的替身模块」——这个思路在 Lua/native/Java 上都同构 |
| **reverify**（AI 结论确定性裁决层） | ⑦ `verify.py`：claim 裁决 + **信息量权重**（防"验证废话"）+ **负面记忆**（refuted → KNOWN FALSE）+ 按 sha256 的账本 | 实测它把 AI 教科书答案的 97% 错误全抓出来；我们的 skill 正缺这一层"工具回判" |
| **MobileRE-Skill**（移动端逆向 Agent 技能集） | ⑨ `rank.py`：候选函数排序（名字/JNI/调用次数/大小）；⑩ `11` §六.5 **"反 hook → 降层"阶梯**（Java→JNI→Native→libc→syscall） | 它的"分层下钻"是反制反 hook 的通用答案；"候选排序"解决"上千个函数先看哪个" |
| **android-native-auto-reverse**（Codex skill） | ⑪ `05` §8.7 **注入点选"签名之前那一层"**（mPaaS 的 packet vs HttpCaller 实证）；⑫ JNI 证据链 → 已并入 `jniprobe.py` | "改内容要改在签名之前"是一条跨协议栈都成立的判据 |
| **awesome-ai-reverse**（工具清单） | ⑧ 无设备动态的**三条替代路线**（见 §十） | 我们长期缺口是"没有设备"，这个清单里有现成思路 |
| **b0wDi/software-engineering-security**（防守方「防破解」规范 + 验收清单） | ⑤ `15-defense-map.md`：**把每条防守项翻译成攻击切入点**（含他们自曝"挡不住"的四条：代码段外 Hook / 手工映射 / 改检测器 / TOCTOU） | 对手把验收清单公开了，等于给了我们一张作战地图 |
| **reverse-skill**（技能路由包：44 规则 + 175 回归用例） | ④ `routing.json` **单一真源** + `route.py --test` 回归（21 用例） | 路由越加越乱是这类技能的通病；外置 + 回归是唯一防漂移的办法 |

**刻意不学的（附理由）**：

| 不学 | 理由 |
|---|---|
| jadx-ai-mcp / apktool-mcp-server 集成 | 依赖 JDK + jadx/apktool + GUI，会破坏本技能「纯 Python 零依赖、可整包搬走」的强项；它们的工具面（列类/取方法/取 smali）`dexql.py` 已覆盖 |
| rea 的平台化（Hopper/Ghidra/IDA/JADX/adb 全家桶） | 那是「平台」不是「判据」；我们已有证据三级 + 十四个案例，不需要再叠一层依赖 |
| SOMCP 的 unidbg / frida / Flutter / Cloudflare Tunnel | 需要真机 + 装 APK；本技能定位是 Windows 侧静态为主，动态只保留「运行时打桩」这一条低成本路线 |
| SOMCP 的子代理编排（角色白名单 / 配额 / 嵌套深度） | DSH 自带 subagent，重复建设 |
| SOMCP 的 46 工具面 | 工具越多越难选；保持 21 个脚本 + 一个 `autoexec` 总入口 |
| **Frida 25 模块 / adb 整套 / jadx-mcp / ghidra-mcp / Burp 桥接**（那两个项目的重依赖部分） | 需要真机 + GUI + 代理；本技能保持「纯 Python 可整包搬走」，只吸收它们的**判据**不搬工具链 |
| **Android-Clown**（安卓逆向 skill） | 与本技能同层重叠，且抓不到正文内容 ⇒ **不猜不抄**；同类方法论我们已有 16 篇 |
| OLLVM 平坦化的 CFG dispatcher 检测 | 我们已有「混淆四判据」（间接分支 / 两级表 / 运行时种子 / 函数边界消失）；再加一套 CFG 分析要引入反汇编器依赖，收益不抵成本。先用 `rkprobe.py` 的 `br x17` 与引用密度定位，够了 |

> **判据：加一个工具/一篇文档之前先问 —— 它补的是「我们真没有的能力」，还是「更漂亮的实现」？**
> 前者加，后者不加。

---

## 十 · 无设备时怎么做动态（三条替代，按成本排序）

我们长期没 adb / 没真机。别因此停在静态 —— 有三条路：

| # | 路线 | 怎么做 | 代价 | 能回答什么 |
|---|---|---|---|---|
| 1 | **单函数仿真**（unicorn） | 只把"那一个函数"按 entry 映射进模拟内存，给它构造参数、跑几百条指令就停 | 低；DSH 内置 Python 已有 `unicorn` | 这个函数**返回什么**、读了哪些全局（够判桩/密钥） |
| 2 | **离线模拟器**（VortexDBG 类思路） | 设备外同时模拟 native `.so` 与 DEX/Java（Unicorn2 / Dynarmic），走 JNI 边界 | 中；需另装，且版本敏感 | JNI 注册表、`RegisterNatives` 后续调用链 |
| 3 | **真机 / 模拟器**（用户提供） | adb + frida / 运行时打桩 | 高（要设备） | 反调试、自解密、心跳真实时序 |

**判据**：只要你要的是"某函数的返回值 / 某地址的内容 / 某段解出来的字节"，**路线 1 就够**
（`11-runtime-patching.md` 的整套打桩思路可以在仿真里先验证一遍，再上真机）。
只有当目标是**反调试/时序**时，才必须路线 3。

> 别把"没设备"当结论 —— 它只限制你能验证到哪一步，不限制你给出下一步动作。
