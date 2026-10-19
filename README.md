# lixi-nixiang-skill

Android 授权 / 卡密验证的全自动逆向分析技能包。启动词 **李喜**。

> 一句话判据：能不能破由「判决归属」决定，不由「加密强度」决定。

## 能力概览

四层判型加一个服务端判决面：

| 层 | 目标 | 判决通常在哪 |
|---|---|---|
| 控制面 | APK / dex | 本地字段、布尔、状态槽 |
| 脚本面 | 壳里的 `.lua` | `if f.code == 1` 这类闸门 |
| 载荷面 | ELF / `.so` / dump | 服务端签名与时效 |
| 特权面 | `.ko` 内核模块、root 脚本 | 与授权无关，但是硬前提 |
| 服务端 | 抓包与重放 | 真响应重放、假服务器 |

一个入口脚本跑完只读分析，输出带原字节的可执行命令。不依赖 jadx、apktool、frida。

## 用法

```
李喜，D:\target.apk，绕过卡密
```

启动词后跟「路径 + 需求」。需求可省略，缺省行为是判层、判型、给出可执行命令。

## 快速开始

```powershell
# 总入口：分诊 + 只读分析 + 生成 analysis\AUTO_PLAN.md
python scripts\autoexec.py "<样本路径>" --need "判型"

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
├─ references/                  16 篇方法论与案例（01-triage … 16-js-runtime-shim）
├─ scripts/                     24 个 Python 脚本 + xdc.mjs / xdc.ps1 / xdc.sh
├─ templates/case-agents-template.md
├─ 一键安装.ps1
├─ 安装说明.md
├─ MANIFEST.json                52 个文件的字节数与 SHA-256
└─ legacy-v1.0/                 第一代结构（S0–S4 流程）存档
```

## 依赖

Python 3.8 及以上，仅用标准库。`capstone` 可选，缺失时自动降级；`cryptography` 只被 `v2parse.py` 使用。目标平台是 Android（APK / dex / `.so` / `.ko`），分析脚本在 Windows 上运行。

## 版本

包内标注为 **1.8.0**（`MANIFEST.json` 与压缩包文件名一致）。注意 `VERSION` 文件内容为 `1.0.0`、`SKILL.md` 的 `metadata.version` 为 `1.3.0`，三处标注尚未统一，以 1.8.0 为准。

## 完整性与自检

```powershell
python scripts\selftest.py
```

实测结果：语法编译 24/24 通过，`elfprobe` 自检 PASS，`aesgcm` FIPS-197 自检 PASS；`v2parse` 因本机未安装 `cryptography` 跳过（不影响其余脚本）。

MIT
