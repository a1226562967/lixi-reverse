# 服务端判决 — 真响应重放 + 假服务器（加密无关）

> **加密保护"不可伪造"，不保护"不可复用"。**
> 客户端对响应的信任分三段：① 来源真实（签名）② 传输完整（MAC）③ **时效有效（时间/随机数）**。
> 签名锁死 ①②；重放只打 ③ —— 而 ③ 通常只跟本机时钟和一次 nonce 有关。

适用条件（三条同时成立才用）：
- 判出「判决在服务端」，且"签名不可伪造"让人以为无解；
- 手上有**一张还能用的卡密**，或别人给过一份可运行的成品；
- 壳太重（加固 / VM / 平坦化），补丁成本高到不划算。

---

## 一 · 五问前置判据（先答，再看壳）

| # | 问题 | 怎么看 | 若命中 |
|---|---|---|---|
| 1 | 响应里有没有**客户端生成的随机数**（challenge/nonce）？ | 请求体有无随机串，响应是否回显/签名它 | 需**随机数回放**（冻结随机源） |
| 2 | 响应里有没有**时间/有效期**，客户端是否拿它和本机时间比？ | 搜 `expire/到期/剩余`，看比较对象 | 需**时间冻结** |
| 3 | 是否**绑定设备指纹/卡密/会话**？ | 换机是否失效；抓包里有 IMEI/ANDROID_ID/卡密 | 同机同卡可重放；换机需重抓 |
| 4 | 客户端是否**本地二次验签**（内置公钥重算）？ | 搜 `verify/Ed25519/EVP_` | **不影响重放**（重放的是真签名），只影响伪造 |
| 5 | 服务端是否记录**一次性 token 已消费**？ | 同一会话重放第二次是否被拒 | 见坑表第 6 条 |

**决策顺序（反直觉但正确）**：

```
if 手上有"合法时刻"的流量:
    重放优先于改判决
理由: 重放成本是常数(抓一次 + 一个 hook 库)
      改判决成本随保护强度指数上升
```

---

## 二 · 抓三样（不是一样）

| 抓什么 | 为什么 |
|---|---|
| 请求全文（含 header） | 回放库要按请求顺序/类型匹配包 |
| 响应全文（**原样字节**，含 chunked 分块） | 回放时逐字节喂回，不要解析后重编码 |
| 当时的时间（秒 + 纳秒） | 时间冻结的锚点；也是"卡密还剩多久"的真实来源 |
| （可选）随机数流 | 若客户端用 `/dev/urandom` 生成本次 nonce，要连这串一起录 |

**选抓法（优先 LD_PRELOAD）**：

| 抓法 | 拿到什么 | 代价 |
|---|---|---|
| `LD_PRELOAD` 拦 libc 收发 | 明文字节 + 可直接演化成回放库 | 需 root 或无限制 exec；需躲反注入检测 |
| `tcpdump` / 抓包 App | 原始字节；TLS 下是密文 | 要拿 session key 才可用 |
| 中间人代理（mitmproxy） | 明文 | 证书固定基本必踩；**改网络配置影响整机** |

选 LD_PRELOAD 的核心理由：**同一个库既能记也能放**，抓包版和回放版是同一份骨架，只换"数据来源"。

---

## 三 · 四件套（与算法完全无关）

### 3.1 收发 hook

```c
static int (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
static ssize_t (*real_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*);

ssize_t sendto(int fd, const void *buf, size_t len, int flags, ...) {
    if (len >= 5 && memcmp(buf, "POST ", 5) == 0) {
        enter_replay(fd, next_packet_index());   // 记下"这个 fd 从第 N 个包开始放"
    }
    return real_sendto(fd, buf, len, flags, ...);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, ...) {
    if (is_replay_fd(fd)) return replay_read(fd, buf, len);  // 从抓包文件按偏移吐
    return real_recvfrom(fd, buf, len, flags, ...);
}
```

**必须补的两个洞**：
- **裸 `syscall()`**：程序可能绕过 libc 直接 `svc`。要同时拦 `syscall()` 或改 `svc` 指令。
- **`read` / `recvmsg` / `sendfile`**：同一个 socket 可能走别的读接口。四件套要覆盖全。

### 3.2 顺序匹配（别按内容匹配）

加密协议下请求内容不可读，匹配只能靠"顺序 + 类型"：

```
第 1 个 POST → output/1.bin
第 2 个 POST → output/2.bin
...
```

**顺序错一个，整条链就断** —— 抓包时必须完整录一次登录流程，不能只录其中一段。

### 3.3 随机数回放（最容易翻车的一环）

- 只重放响应 → 客户端比对"我这次生成的 nonce ≠ 响应里的 nonce" → 校验失败
- 正解：**把客户端的随机源也钉死** —— 让它每次读到的"随机数"和录制那次一模一样
- 抓包时除 request/response 外，还要录客户端读 `/dev/urandom` 的字节流（或等价 hook）

### 3.4 时间冻结

```c
int clock_gettime(clockid_t id, struct timespec *ts) {
    int r = real_clock_gettime(id, ts);
    if (r == 0 && id == CLOCK_REALTIME && in_replay_mode()) {
        ts->tv_sec  = packet_time_sec(current_packet());
        ts->tv_nsec = packet_time_nsec(current_packet());
    }
    return r;
}
```

**要一起盖住的取时入口（少一个都会漏）**：

| 入口 | 备注 |
|---|---|
| `clock_gettime` | 现代 Android 主入口；注意 vDSO 路径 |
| `gettimeofday` | 老代码常用 |
| `time()` | 样本里没盖；若目标只用 `time()`，必须补 |
| `mktime`/`localtime`/`strftime` | 只影响"显示剩余天数"，不影响判决，但影响你看到的现象 |
| `pthread_cond_timedwait`/`nanosleep` 换算 | 影响心跳/重试节奏 |
| 裸 `syscall(SYS_clock_gettime)` | 需 syscall 层拦截 |

### 3.5 反检测（不做这步，前四步全白费）

| 检测点 | 对策 |
|---|---|
| `/proc/self/maps` 里出现你的 `.so` | 过滤返回内容，抹掉自己 |
| `dl_iterate_phdr` 枚举模块 | 在 `dl_phdr_info` 回调里过滤 |
| 读 `/proc/self/environ` 里的 `LD_PRELOAD=` | 启动后清空该环境串 |
| 读自身 exe 做完整性校验 | 拦截 `open`/`read`，给内存文件或拒绝 |
| 校验 `.so` 签名/路径 | 用内存文件 + 抹路径 |

---

## 四 · 落盘格式（PTM2）

每包时间存成 `PTM2` 结构（实测二进制布局）：

```
"PTM2" | u16 ver=2 | u16 hdr=0x20 | u64 tv_sec | u32 tv_nsec | u32 len | payload
```

- `tv_sec` 与抓包时 HTTP `Date` 头**一秒不差** —— 这就是"限时卡密变永久"的开关本身。

---

## 五 · 移植 checklist（换任何新目标照着走）

1. **判层**：扫 `.plt`/导入表，数网络 API 的调用点数。
   - 每个 API 只有 **1 个调用点** → 单点可 hook，成本最低（实测快斗 6.8 就是这样）
2. **判协议形态**：HTTP? JSON? 私有二进制? —— 只影响匹配条件（如 `memcmp(buf,"POST ",5)`）
3. **抓一次真流量**（卡必须有效）：请求 + 响应 + 时间 + 随机数流
4. **找新鲜度绑定点**：按五问逐条回答
5. **装四件套**：收发 hook / 顺序匹配 / 随机数回放 / 时间冻结（+ 反检测）
6. **验证**：断网或指向不存在的服务器，**能进主界面 = 成功**
7. **落盘存档**：抓包文件 + 时间文件 + hook 库 + 抓包时的卡密状态，一起存

---

## 六 · 加密无关性矩阵（本页核心）

| 保护形态 | 对"改客户端判决" | 对"真响应重放" | 说明 |
|---|---|---|---|
| 无加密 | 容易 | 不影响 | — |
| 单字节 XOR / 轮转 key | 便宜 | 不影响 | 只是数据样子 |
| AES-GCM / ChaCha20 | 贵 | 不影响 | 复用密文对应的**明文响应**，不解密实现 |
| TLS + 证书固定 | 极贵 | 不影响 | hook 在应用层，拿的就是解密后的字节 |
| **服务端 Ed25519/RSA 签名** | **不可行** | 不影响 | 重放的是真签名，不是伪造 |
| 控制流平坦化 / 自研 VM | 极贵 | 不影响 | 根本不读代码 |
| 自校验 / CRC / 完整性 | 要额外绕 | **完全不需要** | 不改文件，指纹天然一致 |
| 字符串全加密 | 要解 | 不影响 | 不需要读它的 UI 文案 |
| 反调试 / 反注入 | 要绕 | 要绕（但轻量） | 只需躲开 LD_PRELOAD 检测 |
| 设备指纹绑定 | 本地可伪 | 同机可过 | 换机/刷机需重抓 |

**取舍一句话**：

```
判决在服务端 + 手上有有效卡 ⇒ 重放;
判决在本地 ⇒ 两字节补丁;
判决在服务端 + 卡已过期 ⇒ 只能回去啃客户端(负面结论)
```

---

## 七 · 坑表（全 7 条）

| # | 失败模式 | 是否有解 |
|---|---|---|
| 1 | 响应含客户端 nonce，且客户端比对 | ✅ 冻结随机源 |
| 2 | 响应有效期和本机时间比 | ✅ 时间冻结 |
| 3 | 绑定设备指纹 + 卡密 | ⚠️ 同机同卡可；换机必须重抓 |
| 4 | 客户端本地**重算**签名而非验签 | ❌ 需要拿到密钥 → 回改判决 |
| 5 | 客户端检测到注入就退出 | ✅ 反检测，但工作量上升 |
| 6 | 服务端记录一次性 token 已消费 | ⚠️ 首次校验可过；后续要服务器数据时才会断 |
| 7 | 抓包时卡密**已过期** | ❌ 抓到的就是"不行"，重放一万次还是"不行" |

**第 7 条是唯一硬前提**：必须有一次"合法通过"的流量。过期之后没有第二次机会。

---

## 八 · 假服务器（结构完全未知时的第一枪）

> **不知道客户端在验什么，就把所有可能的正确答案一次性给它**；并把它当侦察工具跑一轮 ——
> TLS 握手里的 SNI 是**明文**，客户端会自己报告它在验谁。

### 8.1 三个前提（全否才做）

1. 客户端确实联网验证吗？（不是纯本地）
2. 有 iptables 权限吗？（root / 有网络控制权）
3. 客户端没做证书固定（pinning）吗？

反直觉但关键：**不需要**先知道验证域名、路径、字段名、签名算法。全套成本 = 一个 iptables 规则 + 一个固定 JSON + 一张自签证书。

### 8.2 四段结构

```
① 劫持层   iptables NAT REDIRECT —— 把出站 80/443/8080/8000 全打进本机
② HTTP 层  任何路径都回同一份万能 JSON（含所有字段别名）
③ HTTPS 层 自签 RSA-2048 证书（CN 随便，10 年）
④ 日志     把 body + TLS SNI 全记下来 —— 这是第二轮精确化的依据
```

```sh
# 上（幂等：先删再加，避免重复规则）
iptables -t nat -A OUTPUT -p tcp --dport 80   -j REDIRECT --to-ports 8899
iptables -t nat -A OUTPUT -p tcp --dport 443  -j REDIRECT --to-ports 8443
iptables -t nat -A OUTPUT -p tcp --dport 8080 -j REDIRECT --to-ports 8899
iptables -t nat -A OUTPUT -p tcp --dport 8000 -j REDIRECT --to-ports 8899
# 下（顺序反过来）
iptables -t nat -D OUTPUT -p tcp --dport 80   -j REDIRECT --to-ports 8899
iptables -t nat -D OUTPUT -p tcp --dport 443  -j REDIRECT --to-ports 8443
iptables -t nat -D OUTPUT -p tcp --dport 8080 -j REDIRECT --to-ports 8899
iptables -t nat -D OUTPUT -p tcp --dport 8000 -j REDIRECT --to-ports 8899
```

> **卫生纪律（真实翻车点）**：脚本必须带 `trap 'net_down; exit 0' INT TERM`。
> 但 `kill -9`／断电／App 崩溃时 trap **不执行** → 规则残留 → 用户"手机没网了"。
> 排查"装完外挂没网了"，第一嫌疑就是这个。

### 8.3 SNI 侦察（一轮就够）

```go
tlsCfg := &tls.Config{GetConfigForClient: sniSpy}

func sniSpy(chi *tls.ClientHelloInfo) (*tls.Config, error) {
    fmt.Fprintf(logf, "[TLS-HANDSHAKE] sni=%s alpn=%v\n", chi.ServerName, chi.SupportedProtos)
    return nil, nil       // 不改配置，继续用默认
}
```

输出示例：

```
[TLS-HANDSHAKE] sni=api.xxxxxx.com alpn=[h2 http/1.1]
```

> SNI 在证书校验**之前**发送且必为明文 —— 所以"客户端在验哪个域名"这件事，一轮就是答案，不需要抓包中间人。

### 8.4 万能响应体（758 字节，可直接抄）

时间戳 = **`4102444800`** = 2100-01-01 00:00:00 UTC。
**为什么不给 `9999999999`**（2286 年）：很多客户端把 `expire` 转成 int32 或 32 位时间，溢出变负数 → 反而判"已过期"。`4102444800` 是 32 位有符号时间戳的安全上限附近。

```json
{"code":200,"status":200,"statusCode":200,"success":true,"ok":true,"result":true,
 "msg":"ok","message":"ok","error":"","err":"","info":"ok",
 "token":"D5258C40C3A73A4DBBD70A4183CF0E0A",
 "access_token":"D5258C40C3A73A4DBBD70A4183CF0E0A",
 "time":4102444800,"end_time":4102444800,"endTime":4102444800,
 "expire":4102444800,"expire_time":4102444800,"expireTime":4102444800,
 "expires":4102444800,"deadline":4102444800,
 "vip":true,"level":5,"grade":5,"type":1,"user":"premium","name":"premium",
 "auth":true,"valid":true,
 "data":{"code":200,"success":true,"token":"D5258C40C3A73A4DBBD70A4183CF0E0A",
         "time":4102444800,"end_time":4102444800,"endTime":4102444800,
         "expire":4102444800,"expire_time":4102444800,"expireTime":4102444800,
         "level":5,"vip":true,"auth":true,"valid":true,"status":200,"msg":"ok"}}
```

**字段别名穷举表**（拿不到协议时的正确姿势不是猜，是穷举所有可能的命名）：

| 维度 | 要覆盖的变体 |
|---|---|
| 状态码 | `code` / `status` / `statusCode` / `ret` / `errcode` |
| 布尔判定 | `success` / `ok` / `result` / `auth` / `valid` / `pass` / `isVip` |
| 文本 | `msg` / `message` / `info` / `error:""` / `err:""` |
| 令牌 | `token` / `access_token` / `sign` |
| **时间（最容易漏）** | `time` / `end_time` / `endTime` / `expire` / `expire_time` / `expireTime` / `expires` / `deadline` / `expiry` / `validUntil` |
| 等级套餐 | `vip` / `level` / `grade` / `type` / `user` / `name` |
| **容器** | 外层平铺 + **再套一层 `data` 重放全套**（有些客户端读 `resp.data.xxx`） |

固定常量：端口 HTTP `8899` / HTTPS `8443`；请求体读取上限 `io.LimitReader(r.Body, 8192)`；
响应头 `Content-Type: application/json` + `Server: nginx` + `WriteHeader(200)`；
证书自签 RSA-2048、有效期 10 年；响应体 758 字节。

### 8.5 五种同层替换手法（只防一种等于没防）

| 手法 | 动不动 hosts | 客户端查 hosts 能不能发现 |
|---|---|---|
| 改 `/etc/hosts` | ✅ 动 | **能** |
| 改 DNS（自定义 resolver） | ❌ | 不能 |
| **NAT REDIRECT** | ❌ | **不能** |
| 进程内 hook（`connect`/`SSL_read`） | ❌ | 不能 |
| 换 CA / 证书替换 | ❌ | 不能 |

> 实证反例：某客户端自己会读 `/etc/hosts` 做重定向自查 → 作者知道这一招并防了；
> 但破解走的是 `iptables -t nat`，**完全不动 hosts** → 自检连触发的机会都没有。
> **防御的假设错了，防线就是纸。** 写校验时要问的不是"破解者会不会用我知道的那招"，而是"这个校验覆盖所有同层替换手段吗"。

### 8.6 什么时候它一定失败 + 降级顺序

| 客户端做了 | 现象 | 下一步 |
|---|---|---|
| 证书固定（pinning） | 443 握手失败，日志里连 ClientHello 都没有 | 转 hook / 改包 |
| 双向认证（mTLS） | 服务端要客户端证书 | 基本无解（除非拿到客户端证书） |
| 响应验签 | 返回 200 但客户端报"签名错误" | **转真响应重放** |
| 新鲜度 / nonce 校验 | 第一次能用，第二次失效 | 三次都不行 → 真·不可复用 |
| 关键判定在服务器且永不返回 | 客户端只拿到"能用/不能用"的布尔 | 这个布尔就是本地判决 → 改它 |

降级顺序（成本从低到高）：
**假服务器万能响应 → 真响应重放 → 解析器 hook（只改消费字段）→ 消费点改写 / 缓存注入**。

---

## 九 · 环境红线（本工位）

- 抓包/改包**只动进程级**：目标自己的 config / 目标命令行参数 `--proxy` / 进程内 hook（拦 socket）。
- **禁止**改 hosts / DNS / 系统代理 / 路由表 / 防火墙 / 网卡 —— 影响整机。
- 手机侧 iptables 只在**你自己的测试机**上做，且脚本必带 trap + 一条"网络恢复"提示。

### 8.7 注入点选择：**签名/完整性校验之前**那一层（mPaaS 实证的可迁移判据）

改请求/响应时，不是"哪个类好 hook 就 hook 哪个"，而是看**它处在签名链的哪一段**：

| 层 | 例子（mPaaS） | 适合 |
|---|---|---|
| 序列化/打包层（**签名之前**） | `Serializer.packet()` / `JsonSerializerV2.packet()` | **改内容**（改完再让它自己签名） |
| 传输层 | `HttpCaller` | 观察最终 URL/请求/响应对象 |
| 调用编排层 | `RpcInvoker` | 关联方法名、线程、请求 ID |

**通用判据**：找"**内容刚成形、还没被签名/完整性摘要覆盖**"的那一层。
在签名之后改 = 自己制造签名失败；在序列化之前改 = 结构还没成，容易改坏。

> 同一逻辑适用于任何协议栈：先画出 `明文 → 序列化 → 签名 → 加密 → 发送` 的链，
> 把 hook 点放在**签名之前、序列化之后**。
