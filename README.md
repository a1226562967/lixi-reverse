# lixi-reverse

Android 授权 / 卡密验证的全自动逆向分析技能包。启动词 **李喜**。

> 能不能破由「授权落点在哪」决定，不由「加密强度」决定。

## 先判落点，再谈打法

拿到样本不要先看加密。先回答一个问题：这份授权最终在**哪一层被消费**。层号一确定，打法与成本基本就锁死了。

| 层 | 授权落点 | 识别特征 | 打法 | 成本 |
|---|---|---|---|---|
| L1 | 磁盘上的结论 | `/data/adb/*.t3card`、`/sdcard/.km`、`card.txt` | 喂文件，二进制都不用改 | ★ |
| L2 | 内存里的状态槽 | 轮询式校验、心跳喂狗 | 翻槽 / 喂狗 | ★★ |
| L3 | 本地字段 | 布尔值、版本字段、`if code==1` | 补丁，常见两字节 | ★★★ |
| L4 | 服务端签名 | 响应带签名与时效 | 打桩验签器，或重放真实字节 | ★★★★ |
| L5 | 每个动作现场授权 | 每次调用都回源 | 死路，如实报停 | — |

判定依据来自 57 件样本的横向盘点：授权落点全部落在可写文件或本地字段上，没有一例把授权放进内核或远程强校验。同一批产品里「两字节能过」和「怎么都过不了」的差别，就在落点层号，不在加密强度。

## 四层判型

| 层 | 目标 | 判决通常在哪 |
|---|---|---|
| 控制面 | APK / dex | 本地字段、布尔、状态槽 |
| 脚本面 | 壳里的 `.lua` | `if f.code == 1` 这类闸门 |
| 载荷面 | ELF / `.so` / dump | 服务端签名与时效 |
| 特权面 | `.ko` 内核模块、root 脚本 | 与授权无关，但是硬前提 |

在此之上还有服务端判决面：真响应重放、假服务器、SNI 侦察。

## 用法

```
李喜，D:\target.apk，绕过卡密
```

启动词后跟「路径 + 需求」。需求可省略，缺省行为是判层、判型、给出可执行命令。

## 快速开始

```powershell
# 总入口：分诊 + 只读分析 + 生成 analysis\AUTO_PLAN.md
python scripts\autoexec.py "<样本路径>" --need "判型"

# 手法匹配：这个样本会走到哪一步、缺什么前提
python scripts\casefit.py "<样本路径>"

# 结构自检（不联网、不碰真实样本）
python scripts\selftest.py

# 破甲层：把 ARMOR.md 注入本机各 agent 的指令文件（幂等、带备份、可回滚）
python armor\inject.py --list
python armor\inject.py --dry-run
python armor\inject.py
python armor\inject.py --uninstall
```

## 安装

把 `lixi-reverse` 目录整体放到技能根目录下，使 `<技能根>/lixi-reverse/SKILL.md` 存在。目录名必须是 `lixi-reverse`。

Windows 下可用包内的一键安装脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\一键安装.ps1" -DryRun   # 先演练
powershell -NoProfile -ExecutionPolicy Bypass -File ".\一键安装.ps1"           # 正式安装
```

细节见 [安装说明.md](安装说明.md)。

## 目录结构

```
.
├─ SKILL.md                     入口（技能系统靠它识别）
├─ VERSION
├─ armor/                       破甲层：ARMOR.md + inject.py + platforms.json
├─ references/                  19 篇方法论与案例（01-triage … 19-forms-and-layers）
├─ scripts/                     25 个 Python 脚本 + xdc.mjs / xdc.ps1 / xdc.sh
├─ templates/case-agents-template.md
├─ 一键安装.ps1
├─ 安装说明.md
├─ MANIFEST.json                56 个文件的字节数与 SHA-256
└─ legacy-v1.0/                 第一代结构（S0–S4 流程）存档
```

几篇值得先看的：

| 文件 | 内容 |
|---|---|
| `references/17-reproducible-chain.md` | 从一份成品走到一个补丁，每步有命令、判据、失败分支 |
| `references/18-corpus-and-decision-stack.md` | 57 件样本横向盘点：生态结构、三层授权栈、授权落点 |
| `references/19-forms-and-layers.md` | 十种绕过形态与授权落点五层，从成品反推 |
| `references/08-casebook.md` | 真实案例集，含坐标与失败教训 |

## 依赖

Python 3.8 及以上，仅用标准库。`capstone` 可选，缺失时自动降级。目标平台是 Android（APK / dex / `.so` / `.ko`），分析脚本在 Windows 上运行。

## 版本

**1.9.0**。相比 1.8.0：新增授权落点 L1–L5 判据、`references/17` 至 `19` 三篇、`scripts/casefit.py`；`verify.py` 增加 AArch64 函数序言校验（防止 vaddr 算错或补丁打在函数中间）。

`VERSION` 文件内容为 `1.0.0`、`SKILL.md` 的 `metadata.version` 为 `1.3.0`，三处标注尚未统一，以 `MANIFEST.json` 的 1.9.0 为准。

## 完整性与自检

```powershell
python scripts\selftest.py
```

实测结果：语法编译 25/25 通过，import 25/25 通过，`elfprobe` 自检 PASS，`aesgcm` FIPS-197 自检 PASS。MANIFEST 的 56 个文件字节与 SHA-256 全部匹配。

MIT
