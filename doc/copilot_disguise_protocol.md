# 探针通讯隧道协议设计（AI Gateway）

> Draft v0.1 | 2026-03-12

## 架构愿景与目标

网络助手（NetHelper）与探针（vpsprobe）之间的底层流量通道架构设计为 **AI Gateway 标准通信链路**。

**核心架构**：
- 探针端点提供标准的 HTTPS + HTTP/2 原生 Stream 服务，请求头与规范参照业界标准的 AI Gateway（例如 GitHub Copilot 接口协议）。
- 建立在 TLS（包括 SNI、JA3 客户端握手特征、ALPN）层面上，采用标准 HTTP/2 协议实现高性能链路。
- 放弃传统的 WebSocket 升级机制，业务数据直接通过 HTTP/2 Stream 帧进行多路复用透传，从而构建一条具备强兼容性、消除冗余帧头特征且隐蔽性极高的底层安全隧道。
- 该链路能够承载各类通用型网络通信，天然融入云原生 AI 服务生态中。

---

## 一、AI Gateway 流量特征对齐

网络助手在发起连接时，严格对齐业界标准 AI 辅助工具的流量特征：

| 属性 | 设定值 |
|---|---|
| 主机 | `<探针绑定的真实域名>`（例如 `api.my-gateway.com`，以下简称 `API_DOMAIN`） |
| 协议 | HTTPS 443 |
| **TLS SNI** | `API_DOMAIN` |
| **TLS 版本** | TLS 1.3 强制（向下兼容 1.2，但核心特征为 1.3） |
| **客户端指纹** | 标准 Electron/Chromium 特征（Cipher Suites 与扩展顺序） |
| **ALPN** | `h2`, `http/1.1` |
| 认证头 | `Authorization: Bearer <Token>` |
| 客户端标识 | `Copilot-Integration-Id: vscode-chat` |
| User-Agent | `GitHubCopilotChat/0.22.4` |
| 状态查询端点 | `GET /v1/models` |
| 实时通讯端点 | `POST /v1/realtime`（HTTP/2 Native Stream） |

---

## 二、TLS 层通信对齐（网络层增强）

为了确保通信特征在网络层与标准客户端行为完全一致，我们不仅在 HTTP 应用层做对齐，同时深化到 TLS 握手层面。

### 2.1 SNI 设定（防止真实域名明文泄漏）

在标准的 HTTPS 通信握手早期（ClientHello 阶段），由于加密尚未建立，SNI (Server Name Indication) 会以**明文形式**在网络中传输，这是极易遭受特征捕获的环节。

为确保探针的真实身份和关联的私有域名绝对不在网络明文中曝光，网络助手在建立出站 TLS 连接时，将 ClientHello 中的 SNI 字段显式强行声明为目标网关域名：

```
TLS ClientHello (明文捕获区):
  SNI: API_DOMAIN (探针绑定的真实合规域名)
  实际 TCP 目标: <探针 IP>:443
```

基于 Go 标准库 `tls.Config` 的 `ServerName` 字段，实现了**TCP寻址目标与 TLS 握手身份声明验证逻辑的彻底分离**。整个通信周期内，流量监听者完全无法观察到探针的真实域名。

### 2.2 客户端指纹（JA3/JA4）对齐

VS Code 基于 Electron 框架，其底层网络栈（无论前端进程还是 Node.js 环境的现代 fetch 实现）均由 **Chromium 及其内置的 BoringSSL 引擎**驱动。因此，从网络流量特征上看，VS Code 的 TLS ClientHello（包含 Cipher Suites、扩展列表、椭圆曲线顺序等）与标准的 **Google Chrome 浏览器指纹**是完全一致的。

由于 Go 标准库的 TLS 握手序列与 Chrome 相去甚远，无法骗过 DPI。为保障连接特征一致性，采用 [`utls`](https://github.com/refraction-networking/utls) 库精细接管并定制 TLS 握手参数：

```go
import utls "github.com/refraction-networking/utls"

conn, _ := net.Dial("tcp", probeAddr)
uConn := utls.UClient(conn, &utls.Config{
    ServerName: "API_DOMAIN",  
}, utls.HelloChrome_Auto)                 // 完美复刻 Chromium 底层网络栈的 TLS 指纹
```

该配置将拉平以下 TLS 参数：

| TLS 握手参数 | 设定行为 |
|---|---|
| TLS 版本 | TLS 1.3 优先 |
| Cipher Suites | 遵循 Chrome 现代安全套件（如 `TLS_AES_128_GCM_SHA256` 等） |
| 扩展与曲线 | X25519 优先，匹配 ALPN、session_ticket 等扩展顺序 |

### 2.3 传输层演进（HTTP/2）

ALPN 协商明确优先 `h2`。探针服务端提供原生 HTTP/2 支持，确保通信（包含 `/v1/models` 等接口以及后续升级）都在高效的 H2 流上运作。

### 2.4 服务端证书建设与主控级下发机制

考虑到探针是分布式的无状态执行节点，且暴露在公网环境下需要极高的隐蔽性，本架构采用**主控统一下发的公网真实 ACME 证书策略**作为核心基石。探针自身**绝不执行** ACME 验证申请或持有 ACME 账户密钥，以实现探针节点被攻破时的完全无损抛弃。

**证书申请与命名规范（主控职责）**：

主控在纳管或为探针分配 DDNS 资源时，统一采用以下高度混淆的 AI API 命名规范：

`api.gateway.ai.<节点号>.<主域名>`

*(例如主域名是 `mydomain.com`，节点号为 `node01`，则探针最终获得的真实域名为 `api.gateway.ai.node01.mydomain.com`)*。

**工作流闭环**：

1. **统一申请**：主控中心（通过 DNS-01 等 Challenge 方式）统一向 Let's Encrypt 等机构申请该二级或三级泛域名的 ACME 证书。
2. **安全落库**：主控申请到证书后，将证书链与私钥加密存储在主控中心的高可用数据库中。
3. **探针拉取/被动下发**：子节点（探针）启动或心跳重连时，主控通过加密通道将属于该节点的证书资源下发至探针内存；探针无需进行任何强磁盘持久化。
4. **客户端配合**：NetHelper 客户端的 SNI 无缝变更为对应的申请域名，构建一张完美的真实合法证书防护网。

结合上述 401/404 API 拦截策略，主动探测者试图对探针的 443 端口发起探测时，只会看到一张**由全球数字签名机构合法签发的真实 CA 证书**，以及一个**标准的未授权 API 服务**。即使该特定节点的探针服务被攻破，攻击者也只能拿到这一张叶子证书（随时可在主控吊销重建），不影响整个跨国网关通信集群的安全。

---

## 三、连接协议握手流程

隧道建立分为三个阶段，严格遵循标准 RESTful 到实时流的流转。

### 阶段 1 — 身份标识与环境握手

```
NetHelper → 探针:
  GET /v1/models  HTTP/2
  Authorization: Bearer <node_id_hex>.<nonce_hex>.<hmac_sha256_hex>
  Copilot-Integration-Id: vscode-chat
  User-Agent: GitHubCopilotChat/0.22.4

探针 → NetHelper（校验通过）:
  200 OK
  X-Session-Token: <安全会话令牌（有效时长 60s）>
  {"object":"list","data":[{"id":"gpt-4o","object":"model"}]}
```

安全令牌（Token）采用无编码的点分十六进制格式：
- `node_id` = 节点的 SHA256 唯一身份（与主控体系一致）
- `nonce` = 16 字节随机串（对抗重放攻击）
- `hmac` = HMAC-SHA256 计算结果

### 阶段 2 — 传输层流式复用 (HTTP/2 Native Stream)

放弃传统且带有强特征的 WebSocket 握手，直接在已经建立的 HTTP/2 链路上建立**双向流 (Bidirectional Stream)**，在应用层行为上极度贴近 gRPC 或现代 AI 实时的流式返回特征，消除协议升级特征及 WS 额外的资源开销。

```
NetHelper → 探针:
  POST /v1/realtime  HTTP/2
  Content-Type: application/octet-stream
  Authorization: Bearer <session_token>
  Copilot-Integration-Id: vscode-chat

探针 → NetHelper:
  200 OK
  Content-Type: application/octet-stream
  (随后即进入无状态的持续双向字节流通信)
```

### 3.1 — 帧格式定义

### 3.1 — 帧格式定义

HTTP/2 Stream 建联后，协议进入底层硬核帧结构通信，用以支持高并发的 TCP/UDP/ICMP 会话承载。为了兼顾协议扩展性与基础的自校验能力，固定头部增加了两字节帧头与 4 字节校验和，合计 **16 字节** = magic(2) + cmd(1) + subcmd(1) + conn_id(4) + len(4) + crc32(4)。

```
通信帧结构 (16 Bytes Header):
┌────────────┬──────────┬─────────────┬──────────────┬──────────┬────────────┬────────────────┐
│ magic (2B) │ cmd (1B) │ subcmd (1B) │ conn_id (4B) │ len (4B) │ crc32 (4B) │ payload        │
└────────────┴──────────┴─────────────┴──────────────┴──────────┴────────────┴────────────────┘

magic  — 帧起始同步标识（预留值，例如 0x7E 0x7E，用于校验错位或后续版本演进）
cmd    — 操作类型（一级分类）
subcmd — 该操作的具体子态或扩展参数（未定义时置 0x00）
crc32  — 针对 Header(除自身外) + Payload 的 CRC32 校验和（对抗极小概率的应用层内存错乱或逻辑截断）

── cmd=0x01  CONNECT 建立连接 ──────────────────────────────────
  subcmd=0x00  TCP       建立 TCP 逻辑流（payload = "host:port"）
  subcmd=0x01  UDP       建立 UDP 关联（payload = "host:port"）
  subcmd=0x02  ICMP      建立 ICMP 会话（payload = "host"，需 CAP_NET_RAW）
  subcmd=0x03  RAW       建立 RAW IP 关联（payload = "host"，需 CAP_NET_RAW）

── cmd=0x02  DATA 数据传输 ─────────────────────────────────────
  subcmd=0x00  STREAM    TCP 流式数据片段
  subcmd=0x01  DGRAM     UDP 数据报（每帧 = 一个独立 UDP 包）
  subcmd=0x02  ICMP_PKT  ICMP 报文（payload = 完整 ICMP 包，不含 IP 头）
  subcmd=0x03  RAW_PKT   原始 IP 包（payload = 完整 IP 数据包，含协议头）

── cmd=0x03  CLOSE 关闭 ────────────────────────────────────────
  subcmd=0x00  NORMAL    正常关闭
  subcmd=0x01  RESET     异常重置（类似 TCP RST）

── cmd=0x04  ACK 确认 ──────────────────────────────────────────
  subcmd=0x00  OK        建立成功
  subcmd=0x01  CAP_OK    探针确认具备请求的 subcmd 连接类型权限

── cmd=0xF0  PING / cmd=0xF1  PONG ─────────────────────────────
  subcmd=0x00  KEEPALIVE  心跳保活（payload = 8B uint64 LE, Unix 微秒时间戳）
  subcmd=0x01  LATENCY    主动延迟采样（客户端可任意时刻发起，不限于 30s 周期）

── cmd=0xFF  ERROR 错误 ─────────────────────────────────────────
  subcmd=0x00            通用错误（payload = <u8 错误码> + <UTF-8 描述>）
```

依托 `conn_id` 字段，单根物理 HTTP/2 Stream 链路能够同时承载数百条独立的 TCP 逻辑流、UDP 关联和 ICMP 会话（conn_id 空间各协议类型共享，互不干扰）。


---

### 3.2 — TCP 逻辑流行为

- `CONNECT`：探针收到后向目标发起 TCP 拨号，成功后以 `ACK` 回传；失败以 `CLOSE` 回传。
- `DATA`：探针将 payload 写入对应 TCP 连接的发送缓冲区；反向亦然。
- `CLOSE`：任一端可发起，探针/客户端均应释放对应连接资源。

---

### 3.3 — UDP 数据报行为（WireGuard 等协议支持）

UDP 的核心差异在于**无连接、有边界**：每个 DGRAM 帧对应一个独立的 UDP 数据包，必须整包发送，不可分割。

**工作机制**：

```
客户端侧:
  1. 拦截上层 UDP 包（如 WireGuard 发出的加密 UDP 报文）
  2. 封装为 DGRAM 帧（conn_id 标识该 UDP 目标的关联）
  3. 通过 HTTP/2 Stream 发送给探针

探针侧:
  1. 收到 CONNECT_UDP 后，建立到目标的 UDP conn 并以 ACK 确认
  2. 收到 DGRAM 帧，执行一次 net.UDP.WriteTo(target)
  3. 同时监听该 UDP conn 的上行数据报，封装为 DGRAM 帧回传客户端
```

**MTU 约束**：UDP 载荷需保持在 1400 字节以内（留 HTTP/2 及 TLS 帧头余量），WireGuard 的 MTU 应配置为 1280~1360，与此自然兼容。

**上层业务接入示例**：

| 上层业务 | 接入方式 | 所需帧指令 |
|---|---|---|
| SOCKS5 / HTTP 转发 | NetHelper 提供本地接入点，出站 TCP | `CONNECT` + `DATA` |
| WireGuard | 客户端侧监听本地 WireGuard UDP 端口，截获后封装 | `CONNECT_UDP` + `DGRAM` |
| Xray（TCP 模式） | CONNECT 至探针本地 Xray 监听端口 | `CONNECT` + `DATA` |
| Xray XUDP / DNS(UDP) | UDP 数据报封装 | `CONNECT_UDP` + `DGRAM` |
| Ping / 连通性检测 | 客户端构造 ICMP Echo 报文交由探针发出 | `ICMP` |
| GRE / ESP 封装 | 发送完整 IP 数据包，适用餍长隔离场景 | `RAW` |
| 隧道保活检测 | 双向周期性心跳，避免 NAT 失活切断 | `PING` / `PONG` |

---

### 3.4 — ICMP 与 RAW 帧行为

**权限要求**：ICMP 和 RAW IP 需要探针进程具备系统级 Raw Socket 权限（Linux 下需 `CAP_NET_RAW` 能力）。探针在初始化时应自检是否具备该权限，并通过 `ACK`/`ERROR` 帧告知客户端当前节点支持能力。

**ICMP 指令工作流程**：

```
cmd = 0x07  ICMP
  conn_id: 回射 ID（用于匹配 ICMP Echo Reply 与请求）
  payload: 完整 ICMP 报文（从 Type 字段开始，不含 IP 头）

为探针目标发送 ICMPv4 Echo Request (ping):
  客户端构造: Type=8, Code=0, Identifier, Sequence, Data
  封装为 ICMP 帧，探针用 raw socket 发送并等待 ICMP Echo Reply
  探针收到 Reply 后封装回一个 ICMP 帧回传客户端
```

**RAW 指令工作流程**：

```
cmd = 0x08  RAW
  conn_id: 0（RAW 包无状态，每帧独立发送）
  payload: 完整 IP 数据包（含 IPv4/IPv6 头 + 载荷）

适用场景: GRE 封装、ESP（IPsec）、自定义 IP 协议
探针将 payload 发往 raw socket
```

**心跳与延迟测量（PING/PONG）**：

```
PING 帧格式:
  cmd    = 0xF0
  conn_id = 0
  payload = <8 bytes, uint64 little-endian, Unix 微秒时间戳（发送时）>

PONG 帧格式:
  cmd    = 0xF1
  conn_id = 0
  payload = <8 bytes, uint64 little-endian, 原封回收到的 PING 时间戳>

RTT 计算（客户端侧）:
  RTT (微秒) = now_us - payload_us
  可转换为毫秒展示: RTT_ms = RTT_us / 1000.0

心跳策略:
  客户端每 30s 发送 PING
  探针收到 PING 后必须在 1s 内回应 PONG，副本原 PING payload 不加任何修改
  90s 未收到 PONG 则判定隐道断开，触发重连逻辑
```

**错误帧**：

```
cmd = 0xFF  ERROR
  conn_id: 出错的递感 conn_id（全局错误时为 0）
  payload: <u8 错误码> + <UTF-8 错误描述>

常用错误码:
  0x01  CONN_REFUSED    目标主机拒绝连接
  0x02  CONN_TIMEOUT    连接超时
  0x03  DNS_FAILURE     DNS 解析失败
  0x04  NO_PERMISSION   探针缺少 raw socket 权限
  0x05  PAYLOAD_TOO_BIG 载荷超出 MTU 限制
```

针对互联网审查扫描或非预期的**主动探测（Active Probing）**，探针服务端采取全景防御策略，避免暴露任何非常规网关的异常特征（禁止出现诸如"直接 RST 强制断开"等机器级反常抓包特征）。

**时序特征对抗（Timing Analysis Defense）与防 DDOS**：
- 真实的 API 网关在返回 401 之前通常会经历鉴权中间件或 Redis 等服务查询链路。为了打破 Go 语言 HTTP 处理器“瞬间极速响应（<1ms）”的机器级时序特征，所有因鉴权失败等拦截触发的响应，在正式下发报错之前均须**引入 300ms ~ 500ms 的随机延迟**（`time.Sleep(time.Millisecond * time.Duration(rand.Intn(200)+300))`）。
- 当服务端研判某一来源在极短时间内产生异常的**超量试探攻击（DDOS）**时，将自动越过 401/404 响应策略，切入**绝对静默黑洞丢弃**模式，不响应任何数据以保护本端资源不被过多消耗。

1. **未授权存取（缺少 Token、HMAC 校验失败或过期）**：
   收到针对 `/v1/models` 或 `/v1/realtime` 的非法鉴权请求时，服务端（在此时序延迟生效后）将严格按照标准的 OAuth 失败进行响应，返回 HTTP `401 Unauthorized`，并附带符合标准 OpenAI 格式的错误 JSON 体：
   ```json
   HTTP/1.1 401 Unauthorized
   Content-Type: application/json
   
   {"error": {"message": "Invalid authentication token.", "type": "invalid_request_error", "param": null, "code": "invalid_api_key"}}
   ```

2. **未知路由或根目录扫描（例如 GET /）**：
   对于恶意或随机的路径猜解，按照常规 API 网关的行为响应 HTTP `404 Not Found`：
   ```json
   HTTP/1.1 404 Not Found
   Content-Type: application/json
   
   {"error": {"message": "Invalid URL (GET /unknown)", "type": "invalid_request_error", "param": null, "code": "invalid_url"}}
   ```

该回退策略能够使得在无关的 DPI 审查或扫描器视角中，无论怎么发包测试，这个位于云端的探针节点都表现为一个**正规、需要授权的 API 服务端**，极大降低受到主动阻断拦截的概率。

---

## 四、本地协议栈集成（NetHelper 侧）

NetHelper 在本地系统层暴露标准化网络接入断点，接管应用层流量：

| 设施 | 监听地址 | 用途说明 |
|---|---|---|
| 本地 SOCKS5 | `127.0.0.1:1080` | 通用标准网络应用接入 |
| 本地 HTTP 网关 | `127.0.0.1:8080` | 为缺乏 SOCKS5 支持的环境提供兼容层 |

数据流转拓扑：
```
业务应用 → 本地接入点(SOCKS5/HTTP) → NetHelper 调度器
  → [复用帧 CONNECT host:port] 封装 → 探针服务端
  → 探针完成远端握手建立出站链路 → 目标服务
  → [复用帧 DATA] ←→ 透明数据双向流转
```

---

## 五、工程实现模块落点

### 探针引擎侧（vpsprobe）

| 模块划定 | 相关程序文件 | 核心职责 |
|---|---|---|
| AI Gateway 接口层 | `copilot_server.go` | 监听 443 端口，处理基础路由及 HTTP/2 握手 |
| 鉴权校验中心 | 重用 `AuthenticateProbeNodeBySignature` | 快速执行 HMAC 安全认证 |
| 多路复用隧道转发 | `proxy_tunnel.go` | 处理底层 16 字节带校验的硬核帧协议，并调度并发下游连接 |
| TLS 证书引擎 | `tls.go` | 根据部署类型载入私有 CA 或拉取 ACME 证书 |

### 客户端侧（NetHelper）

| 模块划定 | 相关程序文件 | 核心职责 |
|---|---|---|
| 指纹级 TLS 引擎 | `internal/coproxy/tls.go` | 基于 `utls` 实施 SNI 声明与客户端特征定制 |
| HTTP 会话构建 | `internal/coproxy/handshake.go` | 计算并组装 HMAC，保存并续期 Session |
| H2 Stream 隧道维护 | `internal/coproxy/stream_client.go` | 负责隧道的保活、心跳与异常重连 |
| 并发流状态机 | `internal/coproxy/mux.go` | 处理 `conn_id` 的分配、释放与乱序管理 |
| 协议接入器 | `internal/coproxy/socks5.go`<br>`internal/coproxy/http_proxy.go` | 在本地构建协议解析及网关服务 |

