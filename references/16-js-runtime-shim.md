# JS 运行时层（Electron / asar / jsc / WebView）与"替身模块"手法族

> 前四层是 控制面 dex · 脚本面 Lua · 载荷面 ELF · 特权面 .ko。
> 这一层是**第五层**：授权逻辑活在 **JavaScript 运行时**里 —— Electron（PC）、
> Tauri/Capacitor/WebView（安卓混合应用）、React Native（Hermes 字节码）。
> 它的破解形态与前面四层都不同：**不是改字节、也不是打桩，而是"换掉那个模块"**。

---

## 一 · 先判：这是不是 JS 运行时壳

| 判据 | 看什么 |
|---|---|
| APK 里有 `assets/public/**`、`assets/www/**`、`index.android.bundle` | Capacitor / Cordova / WebView 壳 |
| `index.android.bundle` 头是 `0x0A 0x0D 0x0A 0x0D`（Hermes magic） | **React Native + Hermes 字节码** |
| PC 目录里有 `resources/app.asar` 或 `resources/app/` | **Electron**（asar 是打包后的源码树） |
| 有 `.jsc` 文件 / `bytenode` 字样 / `require('bytenode')` | Electron 的 **V8 字节码**（源码被编译成 `.jsc`） |
| 有 `app.asar.unpacked/` | 原生模块（.node）没打进 asar ⇒ 那是**明文可改区** |

```powershell
# asar 就是 tar 变体：用 node 或 python 直接读
python -c "import struct;d=open('app.asar','rb').read();print(d[:16].hex())"
```

---

## 二 · 三个入口，按成本排序

| # | 入口 | 做法 | 适用 |
|---|---|---|---|
| **1** | **未打包区** | `app.asar.unpacked/`、`resources/app/`（开发版）、`assets/public/` 里直接是明文 JS | 直接改 + 换回去 |
| **2** | **asar 解包 → 改 → 重打包** | 解 asar → 改目标 JS → 重新 pack（Electron 自带 `asar` 工具） | 授权逻辑在明文 JS 里 |
| **3** | **替身模块（shim）** | 不动原文件：提供一个**同接口的实现**，用注入/替换/预加载让它顶替原模块 | 逻辑在 `.jsc` 字节码里、或不想动原始字节 |

> **`.jsc` 不是死路**：V8 字节码只保护"逻辑不易读"，**不保护"模块边界"** ——
> 只要能被 `require()`，就能被替换。

---

## 三 · 「替身模块」是通用手法族（不只在 Electron）

核心思想（从一份自购软件去卡密的实践里提炼）：

> **不改本体一个字节，写一个"诚实的替身"换掉授权校验那个模块，让程序自己判定"已激活"。**

这个思路在安卓上有四个同构落点：

| 平台/形态 | 替身方式 | 接口边界在哪 |
|---|---|---|
| Electron / Node | 预加载脚本（`--require`、`NODE_OPTIONS`）、`app.asar` 里同名文件、`node_modules` 同名包 | 模块导出（`exports.verify`） |
| 安卓 **Lua 脚本壳** | 直接替换 `assets/*.lua`（我们做过：`12-lua-script-layer.md`） | Lua 函数（`Mo()`/`oo()`/`co()`） |
| 安卓 **native** | 同名 `.so` + `LD_PRELOAD`，或 `dlopen` 前替换库 | 导出符号（`JNI_OnLoad` / `nativeXxx`） |
| 安卓 **Java 层** | Frida 替换实现、Xposed 模块、动态代理 | Java 方法签名 |

**判据（三问）**：
1. 目标模块的**接口**是什么（导出名 / 方法签名 / 全局符号）？
2. 谁调用它、期望什么返回（`true`/对象/抛异常）？
3. 有没有**完整性校验**盯着这个模块的文件（有就同步清单，见 `02` §A11 三链）？

> **替身必须"诚实"**：只实现被调用到的接口，返回值要和真实实现语义一致（别返回 `{}` 糊弄）。
> 伪造签名/伪造"服务器已激活"凭证 = 本技能的红线（`05` 一等原则：签名不可伪造）。

---

## 四 · 交付验证清单（12 项压成 6 条）

```
[ ] 目标模块被真正替换（打印一次替身入口，确认加载的是它）
[ ] 主功能可用（不是只有授权页变绿）
[ ] 断网 / 离线场景表现一致（若是网络依赖型授权）
[ ] 原文件哈希/清单未被破坏（若动了打包，重算清单）
[ ] 没触碰签名私钥、没伪造服务端凭证
[ ] 用户亲眼看到功能可用
```

---

## 五 · 与其它文件的关系

| 文件 | 关系 |
|---|---|
| `12-lua-script-layer.md` | 同为"改脚本"，但那是 Lua 引擎；本文是 JS 引擎 |
| `11-runtime-patching.md` | 想去"内存里"改就用它；想"换模块"就用本文 |
| `02-apk-layer.md` §A11 | 换文件必须处理三条校验链（清单/代码/脚本） |
| `15-defense-map.md` | "模块完整性检查"是他们的防守项 ⇒ 对应本文 §三 第三问 |

**一句话**：**能用"替身"解决的，不要去打补丁** —— 替身改的是"谁被调用"，与加密强度无关。
