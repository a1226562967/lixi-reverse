# 特权面 — Android 内核模块（.ko）判型与能力面

> **`.ko` 不用反汇编就能读出它的全部能力 —— 符号表自己招了。**
> 导出函数名 + `.modinfo` 五个字段，足够判出它是"读写驱动 / hook 框架 / 反作弊 / 正常驱动"，
> 以及它能覆盖哪些内核版本。这一步十分钟，比啃 `ioctl` 分发器快一百倍。
>
> **它跟卡密授权没关系** —— 它是"权限硬前提"。别在这一层找授权判断。
> 配套：`scripts\koprobe.py`（一条命令出能力面表）。

---

## 一 · 先判型：它到底是不是内核模块

`file` 不信后缀，只信 `e_type`：

```python
import struct
d = open(p,'rb').read()
assert d[:4] == b'\x7fELF'
E = '<' if d[5] == 1 else '>'
e_type, e_machine = struct.unpack_from(E+'HH', d, 16)
# e_type: 1=REL(可重定位目标=内核模块) 2=EXEC 3=DYN(PIE/so) 4=CORE
# e_machine: 183=AARCH64 62=X86_64 40=ARM
```

| `e_type` | 含义 | 典型后缀 |
|---|---|---|
| **1 (REL)** | **可重定位目标 —— 内核模块就是这个** | `.ko`（常伪装成 `.ko.sh` / `.bin` / `.dat`） |
| 2 (EXEC) | 可执行程序 | 无后缀 / `.sh`（伪装） |
| 3 (DYN) | PIE 或 `.so` | `.so` / `.sh`（伪装） |

> 一个"后缀是 `.sh` 的脚本"如果是 `e_type=1` 的 AARCH64 ELF，它就是内核模块，不是脚本。
> 反过来：某些 `.ko.sh` **真的是 shell 脚本** —— 里面 base64 包着 `.ko`（见 §六）。

---

## 二 · 五个字段就能定性（全在 `.modinfo` 里）

```powershell
python scripts\koprobe.py target.ko
# 或纯手工：
python - <<'PY'
import re, sys
d = open(sys.argv[1],'rb').read()
for k in (b'vermagic=', b'name=', b'license=', b'depends=', b'import_ns=', b'srcversion='):
    for m in re.finditer(re.escape(k) + rb'[^\x00]{0,200}', d):
        print(m.group().decode('latin1'))
PY
```

| 字段 | 读法 | 实测（paradise） |
|---|---|---|
| **`vermagic`** | 内核版本 + SMP/preempt/modversions + 架构。**必须与目标内核精确匹配**才能 `insmod` | `6.1.166-dirty SMP preempt mod_unload modversions aarch64` |
| **`name`** | 模块名，出现在 `/proc/modules`、`/sys/module/` | `paradise` |
| **`license`** | `GPL` 才能用 `EXPORT_SYMBOL_GPL` 的内核 API（很多 hook 框架需要） | `GPL` |
| **`depends`** | 依赖的其他模块 | 空（自包含） |
| **`import_ns`** | **★ 最能说明问题的字段** —— 见 §五 | `VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver` |
| `__versions` size | `modversions` 的名字解析表。`size=0` 却声称 `modversions` = 矛盾 | 0（矛盾，见 §七） |

> **`vermagic` 里藏着"现编还是通用编译"**：
> `6.1.166-dirty` / `6.6.127-4k-g46a034eca005-dirty` 这种带 **`-dirty` + 具体 git hash** 的，
> 说明是针对某台机器/某个内核源码树**现编**的，不是通用 GKI 头文件交叉编译的。
> 对分析者的意义：**它跟内核版本绑死，换机就不能用** —— 所以对方才会一次给 5 个版本。

---

## 三 · 符号面：能力清单（最省事的读法）

```python
import re
d = open('target.ko','rb').read()
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{3,60}', d):
    s = m.group().decode('latin1')
    if re.search(r'(do_|hook|hide|read|write|process|module|kprobe|pacga|cfi|phys)', s, re.I):
        print(s)
```

**判决表（实测 paradise 全套，可直接对照）**：

| 符号 | 体量 | 能力 | 说明 |
|---|---|---|---|
| `do_read_physical_memory` | 1,764 B | **物理内存直读** | 绕开 `process_vm_readv`，反作弊的"读进程内存"检测全部失效 |
| `do_write_physical_memory` | 1,480 B | **物理内存直写** | 同上，反向 |
| `do_find_process` / `do_get_module_base` | — | 进程/模块定位 | 拿游戏基址 |
| `do_get_main_thread_elf0` | — | 主线程/ELF 信息 | |
| `arm64_decode_simd` | **8,432 B** | **自带 AArch64 指令解码器** | inline hook 的必要前置：要判断指令长度/类型，不能调内核的 |
| `inline_hook_install_count` | 1,584 B | inline hook 安装 | 带计数，方便卸载 |
| `do_hwbp_*` 全套 | — | 硬件断点 | 读写/执行断点 |
| `filldir64` | — | **隐藏①：伪造目录项** | 让进程在 `/proc` 里看不见 |
| `kgsl_process_init_debugfs` | — | **隐藏②：KGSL 节点打点** | 绕过更深的枚举路径 |
| `path_mount` | — | **隐藏③：tmpfs mount-over** | 把路径盖住 |
| `input_event` kprobe | — | **陀螺仪输入劫持** | 串：`gyro: register kprobe on %s registered` |
| `do_get_thread_pacga_key` / `do_bind_thread_pacga_key` | — | **读/改线程 PACGA 密钥** | 绕过 ARM64 指针认证 |
| `cfi_bypass` | — | 绕过内核 CFI 检查 | |

**判"这驱动想干什么"的最快路径**（只看三个符号就能定性）：

```
有 *_read_physical_memory / *_write_physical_memory → 内存读写驱动
有 *_hook_install* + 自带指令解码器               → inline hook 框架
有 filldir64 / path_mount / *_debugfs             → 反检测(藏进程/藏文件/藏模块)
三者同时出现 = 成品化外挂驱动，不是玩具
```

---

## 四 · "能力 × 实现手法" 对照表（换任何 .ko 都能套）

| 想要的能力 | 常见实现点 | 为什么这么选 |
|---|---|---|
| 读别的进程内存 | `do_read_physical_memory`（走物理地址） | 绕开 `process_vm_readv` 的审计点 |
| 改别人代码 | inline hook + **自带解码器** | 内核不能调用户态库，解码器必须自带 |
| 抢输入 | `input_event` kprobe | 在 evdev 层截，比 hook 游戏更底层 |
| 藏进程 | `filldir64` + 第二个文件系统回调 | 双点覆盖，防单点检测 |
| 藏文件 | `path_mount` tmpfs mount-over | 文件系统视角看不到 |
| 过 ARM64 PAC | 读/改线程 `PACGA` 密钥 | 用户态可自己签指针 |
| 过 CFI | `cfi_bypass` | 改了函数指针还想调用 |
| 跨内核版本 | GKI vendor hook `import_ns` | 见 §五 |

---

## 五 · 跨内核版本靠什么 —— `import_ns` 是钥匙

实测 `import_ns = ['VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver']`。

这是 **Android GKI 的 vendor hook 命名空间**。名字本身是个玩笑（"这真的是文件系统不是驱动"），
机制是：内核把某些**内部结构体/函数**暴露给声明了这个命名空间的模块，即使它们没有 `EXPORT_SYMBOL`。

> **为什么这招关键**：Android 5.10 → 6.12 之间，内核内部结构体字段一直在变。一份正常 `.ko` 换版本必崩；
> 但拿到 vendor hook 命名空间的模块，可以**只写一遍业务代码，编 5 次**覆盖 Android 12–16。
> 实测就是这样：`5.10.252` / `5.15.202-android13` / `6.1.166` / `6.6.127-4k` / `6.12.76-4k`，五份，业务同源。

**判据：`import_ns` 非空 ⇒ 它在"合法地借用内核内部接口" ⇒ 它要动的东西在 GKI 抽象层以下。**

---

## 六 · 它是怎么被装上去的 —— `.ko.sh` 双层自解包

某些 `.ko.sh` **真的是 shell 脚本**：

```sh
#!/system/bin/sh
# ... base64 -d <<'EOF' > /data/local/tmp/paradise.ko
# <几万行 base64>
EOF
insmod /data/local/tmp/paradise.ko
```

**5 份 wrapper 逐字节完全相同**，只有 base64 段不同。

| 收益 | 说明 |
|---|---|
| 躲审查 | 后缀是 `.sh`，扫可执行文件的规则不命中 |
| 一键部署 | 用户 `sh 5.10.ko.sh` 就自动解包 + `insmod`，不用教他 |
| 版本管理 | wrapper 一份，只换 payload，维护成本近零 |

还有一种：**shell 头 + 尾随 gzip**（实测 VS 驱动包的形态）：

```sh
if [ ! -d "/data/local/tmp/" ]; then mkdir -p "/data/local/tmp/";fi;
random_folder="/data/local/tmp/";
wenjmz="driver:$(date +%s | sha256sum | base64 | head -c 32)";
sed -n "$((LINENO+1)),$ p" < "$0" | gzip -cd > "${random_folder}/$wenjmz";
chmod 700 "$zhixilp";
(sleep 1;rm -fr "$zhixilp") & "$zhixilp" ${1+"$@"}; res=$?; exit $res
<gzip 二进制从这里开始，偏移 366>
```

> **分析时怎么处理**：别把 `.sh` 当脚本读 —— 直接剥（`payload.py` 已支持这两种：
> `trailing-gzip@366` 与 `base64-heredoc`），取 payload 再按 §一 判 `e_type`。
> **自删载荷的抓拍点在被执行之前**（`(sleep 1; rm -fr)`）；拿静态样本就无所谓，抓运行时要注意。

---

## 七 · 两个必须先排除的"假矛盾"

| 现象 | 别急着下结论 | 正确读法 |
|---|---|---|
| `vermagic` 声称 `modversions`，但 **`__versions` 节 size=0** | 不是"文件坏了" | 要么 force-load（`insmod -f`），要么目标内核被改过（关掉了 version 校验）。**意味着"版本对上"不够，还要看加载器** |
| 导出符号带 `__cfi_check`（5.10）vs `__kcfi_typeid_`（5.15+） | 不是两套代码 | 同一份业务代码，**按内核的 CFI 机制分别编**。看到前缀就能判它编给哪个内核代 |

---

## 八 · 检测侧（写防御时直接用）

| 检测点 | 看什么 |
|---|---|
| `/proc/modules` | 有没有陌生模块名 |
| `/sys/module/<name>/` | 同上，且这里更难隐藏 |
| `kallsyms` 完整性 | hook 后函数地址会偏离原始值 |
| **`filldir64` 双点不一致** | `/proc` 读到的进程数 vs `syscall` 枚举到的数量 |
| 内核符号 CRC | 关键函数前几个字节是否被改（inline hook 会留 `b`/`adrp`） |
| 物理内存直读的痕迹 | 很难；只能靠异常的 `/dev/mem` 式访问或行为风控 |
| `dmesg` | kprobe 注册、模块加载痕迹 |

> **老实说**：一个成熟的 `.ko` 外挂驱动在用户态几乎**不可检测** —— 上面这些点它都做了对抗。
> 真正有效的防线是**服务端行为风控**（命中率/预瞄/穿墙视线/移动轨迹），不是客户端检测。

---

## 九 · 换任何 `.ko` 都成立的九条

1. **`e_type=1` 才是内核模块。** 后缀一律不信。
2. **`vermagic` 是硬门槛。** 带 `-dirty` + git hash = 现编，绑死某台机器。
3. **`import_ns` 非空 ⇒ 它在借内核内部接口。** 这是跨版本兼容的钥匙，也是"它不老实"的强信号。
4. **符号表就是能力清单。** 有 `*_physical_memory` = 读写；有 `*_hook_install` + 解码器 = hook 框架；有 `filldir64`/`path_mount` = 反检测。
5. **自带指令解码器（8 KB 级）说明它要改代码。** 只读内存的驱动不需要解码器。
6. **三个隐藏点要一起看**（`/proc` + 第二文件系统回调 + `path_mount`），只藏一处等于没藏。
7. **PACGA key 的读写 = 绕过 ARM64 指针认证。** 见到就说明目标是"有 PAC 保护的游戏"。
8. **`__versions` size=0 却声称 modversions = 加载侧有猫腻。**
9. **检测有效性排序：服务端行为风控 > 内核符号校验 > `/proc` 枚举。** 别指望前两个抓得到成熟驱动。

---

## Checklist（拿到一个 `.ko`）

```
[ ] 1. e_type 是不是 1（REL）—— 先确认它是内核模块
[ ] 2. .modinfo：vermagic / name / license / depends / import_ns
[ ] 3. 导出符号扫 do_ / hook / hide / read / write / pacga / cfi
[ ] 4. 有 *_physical_memory 吗 → 内存读写
[ ] 5. 自带指令解码器吗（> 4 KB 的 decode 类函数）→ inline hook
[ ] 6. 有 filldir64 / path_mount / *debugfs 吗 → 反检测
[ ] 7. import_ns 非空 → 跨版本 + 借内部接口
[ ] 8. __versions 和 vermagic 一致吗 → 加载可行性
[ ] 9. 写成"能力面表" + 证据等级，不写"我觉得它是外挂"
```

一条命令：

```powershell
python scripts\koprobe.py driver.zip          # zip 内逐条目判型（支持 .ko.sh / gzip 包）
python scripts\koprobe.py paradise.ko --json out.json
```
