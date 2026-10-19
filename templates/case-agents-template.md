# 案件锚点 — {样本名}

- 样本: `{绝对路径}`
- sha256: `{sha256}`
- 大小: {size} B
- 立案时间: {YYYY-MM-DD HH:MM:SS} (Asia/Shanghai)
- 判层: 控制面(APK) / 载荷面(ELF) / 特权面(.ko) / 包装层(shell+gzip) / 未知
- 结论: 一句话（通过 / 未通过 / 卡在第 N 层）

## 三层账

| 层 | 载体 | 判决在哪 | 能不能本地破 | 证据（observed） |
|---|---|---|---|---|
| 控制面 | APK/dex | 本地字段 / 服务端 | ✅ / ❌ | 例：`verifyOrLaunch` 0x5b `if-eqz` |
| 载荷面 | ELF/.so | 服务端签名 / 本地 | ❌ / ✅ | 例：提示语 0 命中 + Ed25519 内建 |
| 特权面 | .ko/root | 与授权无关 | — | 例：`vermagic 6.1.166-dirty` + `do_read_physical_memory` |

## 已确认坐标（observed）

- 文件 / 偏移 / 原字节 → 新字节（例：`classes3.dex @0x5b "38 00" → "00 00"`）
- 方法描述符（例：`Lcom/painkiller/nb/AccessActionsKt;->verifyOrLaunch(Lcom/painkiller/nb/MainActivity;)V`）
- 密钥 / 常量（例：`encodedKey = bve1ygn5…`，AES-256-GCM，iv=data[0..12)）
- ELF 坐标（例：`RX [0x100000,0x1613e5) entry 0x16091c 距段尾 2817`）

## 未确认 / 推断（inference，未作为下一步前提）

- …

## 缺口（unknown）

- 缺哪个输入：设备 / 有效卡 / 一次抓包 / 某个 `.so` / 某版本的驱动包

## 改动台账（每条都要还原方案）

| 时间 | 改了什么 | 污染哪些测量 | 还原方案 | 还原验收 |
|---|---|---|---|---|
| | | | | |

## 下一次动作（唯一）

```
python scripts\dexql.py …  --method verifyOrLaunch
```

## 读档顺序（上下文丢失时）

1. 本文件
2. `attempts.md` 尾部三条
3. `analysis\report.json`
