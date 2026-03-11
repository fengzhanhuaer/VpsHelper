## 探针 (Server Probe) 架构规划

### 1. 分布式探针与服务发现 (Distributed Probe Architecture)
- **探针独立部署**: 探针作为独立的被控端（Agent），运行在不暴露端口的内网或任意其他 VPS 上。
- **动态寻址**: 探针启动后，首先通过调用受 CDN 保护的常规控制中心 API，动态获取控制中心用于建立长链接的“真实 IP”与“私有通讯端口”。

### 2. 双端口隔离访问设计 (Dual-Port Access)
- **常规服务端口 (经 CDN)**:
  - 承载所有的 Web UI 控制面板前端展示与常规 API 请求。
  - 通过 CDN (如 Cloudflare) 隐藏并保护源站 IP，实现 Web 界面的就近加速访问与基本的 DDoS 防御。
- **私有服务端口 (不经 CDN)**:
  - 专为探针与控制中心的高频、持久化底层通信保留，客户端直连此端口。
  - 绕过 CDN 对 WebSocket 长连接的严苛时长限制（通常为 100s 断开）与大流量过滤，保障极低延迟与高稳定性。

### 3. 多路复用的 WebSocket 长连隧道 (Multiplexed WebSockets Tunnel)
- **内网友好型隧道**: 探针采用 WebSocket 协议**主动**穿透绝大多数防火墙，向控制中心的私有服务端口发起单向连接申请，建立双向通信的底层加密隧道。
- **隧道可复用性 (Multiplexing)**:
  - 控制中心与每台探针（被控端）**仅维持唯一一条长连接的物理底层隧道**。
  - 借由多路复用技术（如 `yamux` / `smux` 等 Go 原生生态强库）在上述唯一物理隧道之内，根据需求逻辑上并发出无数个“流 (Stream)”。
  - 无论探针每秒高频上报服务器状态、下发即时 Shell 终端指令，亦或执行定时任务，彼此互不干扰，均在一条单一底层安全通道上极低资源损耗地流转。

### 4. 探针内网穿透与流量转发隧道 (Probe-to-Probe Tunneling)
- **统一信令流转**: 控制中心作为中枢，不强制承载所有的海量业务数据流量，而是首先作为信令服务器（Signaling Server），负责协调下发组网指令。
- **动态隧道与流量转发**:
  - 控制中心可以定向下发指令，协调任意指定探针（Node A 与 Node B）之间基于需求建立**正向 (Forward)** 或 **反向 (Reverse)** 代理链接。
  - 这种反向连接/正向代理将被包裹在安全的信道或者上述提到的 WebSocket 多路复用流内，完美实现诸如**内网穿透**、**端口映射**乃至**跨国/跨区内网的无缝网络桥接**。
  - 通过此架构，探针间相互透明，仅凭一套 Go 服务体系，即在面板上搭建起了轻量化的安全网络虚拟化设施（类似轻量化的 FRP / Netmaker），实现节点与节点间的流量隧道转发与跳板编排。

### 5. 探针端 OTA 升级与静默回滚 (OTA Updates & Rollback)
- **多渠道升级分发**:
  - 控制中心支持向指定的一个或批量全部探针下发 OTA 升级指令。
  - 探针解析信令后，可受控选择从公开的 GitHub Releases 拉取最新预编译二进制固件，或者从控制中心直接下载更新包（完美适配内网或无法访问外部网络的纯隔离环境）。
- **容灾与自动回滚机制 (Failsafe & Rollback)**:
  - 为应对重大版本迭代或网络原因可能导致的探针“失联碎砖”风险，探针守护进程在执行升级前必须无感冷备当前主进程二进制文件。
  - 新版本拉起后，须在预设超时窗口（如 60 秒）内立刻尝试寻源并与控制中心系统重建多路复用的 WebSocket 连接。
  - 若发生程序 Crash、心跳超时或重连持续失败等任意严重异常，守护进程将立刻接管斩断新版本进程，自动覆盖并回滚至备份的稳定固件版本，以确保远程节点处于“永不失管”状态。

### 6. 底层通信隧道与网络接入 (AI Gateway 协议族)

- **协议选型（已定）**：
  - **网络助手（GUI 客户端）↔ 探针** 采用**对齐业界标准 AI Gateway 通信**的底层隧道协议（详见 `proxy_client.md` §七）。
  - 探针端点提供标准的 HTTPS + WebSocket 服务，路径与请求头全面适配 `api.githubcopilot.com` 流转规范（`GET /v1/models` 握手验证、`GET /v1/realtime` 建立 WS 链路），实际承载高并发多路复用会话，为本地应用提供安全网络接入支持。
  - 接入认证复用现有 HMAC-SHA256 Challenge-Response 体系，以 Bearer Token 格式安全挂载（`node_id.nonce.hmac`）。

- **备选方案（未采用）**：
  - Trojan / Vmess-WS / Shadowsocks-WS：需依赖 Clash Verge / v2rayN 等第三方客户端导入订阅，无法原生集成进网络助手，不纳入首期。
  - 如未来有向第三方代理客户端提供订阅的需求，可在探针侧额外开启标准 Trojan-WS 监听作为补充入口。

- **本地暴露**：网络助手对外暴露 `127.0.0.1:1080`（SOCKS5）和 `127.0.0.1:8080`（HTTP 代理）供系统及应用使用。


---

## 通用代理管理 需求规划

> Draft v0.2 | 2026-03-09

### 背景

现有 `/tg/proxy` 仅为 Telegram 模块提供单条 `ALL_PROXY` 配置，本次新增**通用代理模块**与 TG 完全解耦，供所有模块（AI、Cloudflare、更新检测等）复用。

### 层次 A — 代理池管理（优先）

路由前缀 `/proxy`，支持多条代理地址的增删改查 + 连通性测速 + 全局默认选择。

**数据库表（新）**:
```sql
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    url         TEXT    NOT NULL,           -- socks5://user:pass@host:port
    enabled     INTEGER NOT NULL DEFAULT 1,
    is_default  INTEGER NOT NULL DEFAULT 0,
    latency_ms  INTEGER,
    tested_at   TEXT,
    note        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL
);
```

**路由**:

| 方法 | 路由 | 说明 |
|------|------|------|
| GET | `/proxy` | 代理列表主页 |
| POST | `/proxy/add` | 新增代理 |
| POST | `/proxy/edit/:id` | 编辑代理 |
| POST | `/proxy/delete/:id` | 删除代理 |
| POST | `/proxy/test/:id` | 立即测速（JSON） |
| POST | `/proxy/set_default/:id` | 设为全局默认 |

### 层次 B — 全局出站代理注入（中期）

在 `net/http` Transport 层统一注入全局默认代理，各模块（AI、CF）可在自身设置页单独覆盖。

### 层次 C — 底层网络路由引擎管理（低优）

在界面内管理 VPS 上系统级的网络通信内核进程（如 Xray / Sing-box 路由设施），包括生命周期启停、底层配置下发与流量监控。需 root/sudo 权限，受限环境需给出 UI 提示。

> **兼容性**：现有 `tg_all_proxy`（`app_settings` key）保留不动，新模块完全独立。

