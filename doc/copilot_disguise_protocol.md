# 探针通讯隧道协议设计（AI Gateway）

> Draft v0.1 | 2026-03-12

## 架构愿景与目标

网络助手（NetHelper）与探针（vpsprobe）之间的底层流量通道架构设计为 **AI Gateway 标准通信链路**。

**核心架构**：
- 探针端点提供标准的 HTTPS + WebSocket 服务，请求头与规范参照业界标准的 AI Gateway（例如 GitHub Copilot 接口协议）。
- 建立在 TLS（包括 SNI、JA3 客户端握手特征、ALPN）层面上，采用标准 HTTP/2 协议实现高性能链路。
- 业务数据通过高频 WebSocket 帧进行多路复用透传，从而构建一条具备强兼容性和高并发能力的底层安全隧道。
- 该链路能够承载各类通用型网络通信，天然融入云原生 AI 服务生态中。

---

## 一、AI Gateway 流量特征对齐

网络助手在发起连接时，严格对齐业界标准 AI 辅助工具的流量特征：

| 属性 | 设定值 |
|---|---|
| 主机 | `api.githubcopilot.com`（作为示例对齐端点） |
| 协议 | HTTPS 443 |
| **TLS SNI** | `api.githubcopilot.com` |
| **TLS 版本** | TLS 1.3（向下兼容 1.2） |
| **客户端指纹** | 标准 Electron/Chromium 特征（Cipher Suites 与扩展顺序） |
| **ALPN** | `h2`, `http/1.1` |
| 认证头 | `Authorization: Bearer <Token>` |
| 客户端标识 | `Copilot-Integration-Id: vscode-chat` |
| User-Agent | `GitHubCopilotChat/0.22.4` |
| 状态查询端点 | `GET /v1/models` |
| 实时通讯端点 | `GET /v1/realtime`（WebSocket Upgrade） |

---

## 二、TLS 层通信对齐（网络层增强）

为了确保通信特征在网络层与标准客户端行为完全一致，我们不仅在 HTTP 应用层做对齐，同时深化到 TLS 握手层面。

### 2.1 SNI 设定

网络助手在建立建立出站 TLS 连接时，将 ClientHello 中的 SNI 字段显式声明为目标网关域名：

```
TLS ClientHello:
  SNI: api.githubcopilot.com
  实际 TCP 目标: <探针 IP 或内网入口>:443
```

基于 Go 标准库 `tls.Config` 的 `ServerName` 字段，实现了寻址与 SNI 验证逻辑的分离。

### 2.2 客户端指纹（JA3/JA4）对齐

由于 Go 标准库的 TLS ClientHello 握手序列与真实 Electron（Chromium 内核）客户端相去甚远。为保障连接质量与特征一致性，采用 [`utls`](https://github.com/refraction-networking/utls) 库精细定制 TLS 握手参数：

```go
import utls "github.com/refraction-networking/utls"

conn, _ := net.Dial("tcp", probeAddr)
uConn := utls.UClient(conn, &utls.Config{
    ServerName: "api.githubcopilot.com",  
}, utls.HelloChrome_Auto)                 // 自动拉平 Chrome 系列指纹
```

该配置将拉平以下 TLS 参数：

| TLS 握手参数 | 设定行为 |
|---|---|
| TLS 版本 | TLS 1.3 优先 |
| Cipher Suites | 遵循 Chrome 现代安全套件（如 `TLS_AES_128_GCM_SHA256` 等） |
| 扩展与曲线 | X25519 优先，匹配 ALPN、session_ticket 等扩展顺序 |

### 2.3 传输层演进（HTTP/2）

ALPN 协商明确优先 `h2`。探针服务端提供原生 HTTP/2 支持，确保通信（包含 `/v1/models` 等接口以及后续升级）都在高效的 H2 流上运作。

### 2.4 服务端证书建设

对于探针侧的证书建设方案：

| 方案 | 细节 | 适用环境 |
|---|---|---|
| **私有根签发 (mTLS)** | 主控作为私有 CA，签发主题包含目标域名的证书，客户端预置根证书 | 通用节点、内网隔离环境 |
| **公网 ACME 证书** | 探针绑定真实域名，自动签发 Let's Encrypt 证书，服务端解除严格入站 SNI 验证 | 边缘公网暴露节点 |

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

### 阶段 2 — 传输层升级 (WebSocket)

```
NetHelper → 探针:
  GET /v1/realtime  HTTP/1.1
  Upgrade: websocket
  Connection: Upgrade
  Authorization: Bearer <session_token>
  Copilot-Integration-Id: vscode-chat

探针 → NetHelper:
  101 Switching Protocols
```

### 阶段 3 — 隧道多路复用帧协议

WebSocket 建立后，协议转入底层帧结构通信，用以支持高并发的 TCP/UDP 会话承载。

```
通信帧结构:
┌──────────┬──────────────┬──────────┬───────────────────────┐
│ cmd (1B) │ conn_id (4B) │ len (4B) │ payload               │
└──────────┴──────────────┴──────────┴───────────────────────┘

控制指令 (cmd):
  0x01  CONNECT   申请建立逻辑流（payload 为目标通信地址 "host:port"）
  0x02  DATA      双向数据传输流
  0x03  CLOSE     逻辑流结束指令
  0x04  ACK       建立确认（探针分配并回传流状态）
```

依托 `conn_id` 字段，单根物理 WebSocket 链接能够完美支撑成百上千的独立并发逻辑流。

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
| 多路复用隧道转发 | `proxy_tunnel.go` | 处理 WebSocket 帧，并调度并发下游连接 |
| TLS 证书引擎 | `tls.go` | 根据部署类型载入私有 CA 或拉取 ACME 证书 |

### 客户端侧（NetHelper）

| 模块划定 | 相关程序文件 | 核心职责 |
|---|---|---|
| 指纹级 TLS 引擎 | `internal/coproxy/tls.go` | 基于 `utls` 实施 SNI 声明与客户端特征定制 |
| HTTP 会话构建 | `internal/coproxy/handshake.go` | 计算并组装 HMAC，保存并续期 Session |
| WS 隧道维护 | `internal/coproxy/ws_client.go` | 负责隧道的保活、心跳与异常重连 |
| 并发流状态机 | `internal/coproxy/mux.go` | 处理 `conn_id` 的分配、释放与乱序管理 |
| 协议接入器 | `internal/coproxy/socks5.go`<br>`internal/coproxy/http_proxy.go` | 在本地构建协议解析及网关服务 |

