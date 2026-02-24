# VpsHelper

VpsHelper 是一个功能强大、轻量级的基于 Go (Gin + SQLite/Cloudflare API) 编写的服务器节点管理、分布式监控探针和 Telegram Bot 整合工具包。

## ✨ 核心功能

- **🚀 探针节点与拨测大屏 (重磅功能)**
  - **主副节点架构**：通过 WebSocket 安全隧道机制，将多台分布在全球各地的 VPS 纳管为轻量级的探针节点。
  - **服务器状态大屏**：集中实时监控所有节点的 CPU、内存、存储使用率以及实时上下行网速，直观展示离线/在线心跳。
  - **任务拨测 (Ping) 大屏**：灵活下发自定义 IP/域名 拨测任务给受控探针，后端主动绘制展示各探针最近 24 小时的历史时延与丢包率图表。
  - **一键静默发版**：探测主备地址降级容灾，支持在主控端一键下发指令触发所有受控探针节点静默拉取更新与重启。

- **☁️ Cloudflare 高级联动体系**
  - **动态域名解析 (DDNS)**：主动探测主机真实路由的公网 IPv4 / IPv6 地址，随时向 Cloudflare 推送最新解析记录，防失联。
  - **分离式高危防火墙**：直接在 Web 面板操作与拦截 Cloudflare WAF Firewall 白名单/黑名单流量规则。
  - **ZeroTrust 白名单**：集中管理受信任的内网重度 IP 来源池，同步推翻 Cloudflare Access 零信任策略放行列表。
  - **D1 异地灾备同步**：无缝将 VpsHelper 本地核心的 SQLite 关系型数据库结构快照加密后热备上传到 Cloudflare D1 边缘网络。

- **🤖 Telegram 会话助手与通知联动**
  - **Userbot 矩阵管理**：深度集成 `gotd` MTProto 底层库，支持使用短信验证码及二维码登入多个 TG 客户端接管自身会话。
  - **自动化任务组件**：配置模拟 Cron 式计划任务：自动参与指定频道的活动抽奖/签到、触发关键词过滤回信以及群发探测。
  - **被动通知 Bot**：挂载你的私人 Telegram Bot 接收面板内诸如节点离线、服务巡检等各项重大告警推送。

- **🛡️ 深度运维管控与安保**
  - **原生 Shell 免密交互**：Web 底层虚拟终端，支持打开原生交互式的 Bash Shell 或预先定义保存自动化动作流 (Shell Pipeline)。
  - **UFW与SSH入侵监控**：联动操作系统封杀恶意端口嗅探与密码暴破请求。
  - **程序热更新模块**：面板自动追踪当前仓库最新 Release 版本并开启在线滚动安装，实现零宕机自我更迭。

## 📥 安装与快速部署

### 1. Linux 服务器一键部署主控端 (推荐级别)
该脚本能利用 API 检测并为你自动拉去与系统硬件体系匹配的新版二进制内核，释放配置文件和进程守护规则：
```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash
```
> 系统进程名称注册为 `vpshelper.service`，后续更新和重启均可以在配套的 Web 面板内部全自动完成。

### 2. 子节点服务器部署被控探针 (VpsProbe)
若需要将手里的其余挂机 VPS 算力接管进来作为观测探针，请确保先登入主控端的 **“探针节点”** 页面：
点击页面内的 “添加节点生成密钥” 获得一串独立专属密钥字符串后，复制平台显示的专配命令在子节点 Shell 机器中黏贴执行：
```bash
curl -sSL https://raw.githubusercontent.com/fengzhanhuaer/VpsHelper/main/install-probe.sh | bash -s -- --secret YOUR_SECRET_KEY --host https://your-main-panel.com
```

### 3. 系统级安全卸载
需要清退系统和迁移时进行彻底卸载 (包含所有历史数据卷的销毁)：
```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash -s uninstall
```

### 4. 交互式管理菜单
如果你需要查看服务状态、重启、停止或呼出管理菜单（并不触发重新安装），可以使用 `menu` 参数：
```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash -s menu
```


## 💻 源码调试与编译构建

**针对 Windows (PowerShell 开发与测试环境)**:
```powershell
.\VpsHelper.bat
# 或是直接定位进源码目录后：
cd goapp
go run ./cmd/server
```

**针对 Linux/macOS (开发与测试环境)**:
```bash
chmod +x VpsHelper.sh
./VpsHelper.sh
# 或是直接定位进源码目录后：
cd goapp
go run ./cmd/server
```

**手工指定架构出包编译 (Release)**:
```bash
cd goapp
go build -o ../bin/vpshelper ./cmd/server
```

## 🔧 运行时核心系统环境变量配置

容器化或 Systemd 包装运行时可能会传入外部环境变量定制，您可以复写这些主要预留参数修改引擎工作：

| 定义名称 | 功能描述 | 缺省行为值 |
|-------------|-------------|---------|
| `VPSHELPER_LISTEN` | Web 服务层网关向对外暴露监听的具体地址范围与默认服务端口 | `:15018` |
| `VPSHELPER_DATA_DIR` | 整个平台运行时的 SQLite 归档、监控时序数据存储目录与证书热层 | `./userdata` |
| `TZ` 或 `VPSHELPER_TZ` | 为应用进程提供覆盖性质的系统地理时区纠偏参考 | `Asia/Shanghai` |

- **面板首次安装完毕默认访问协议与地址**: `http://面板所在VPS公网IP:15018` 或者走反代绑定自己的玉米。
- **本地落盘的数据库挂载点默认位置**: `${VPSHELPER_DATA_DIR}/VpsHelper.db` (配置数据) 和 `probe_data.db` (长时序监控指标数据)。

## 🛡️ Git 源码贡献守则 (代码乱码防崩)
为了防止在各语言不同操作系统、终端以及 IDE 编辑处理文件时由于 Unix LF与 Windows CRLF 不小心引入的魔改损坏和含中文字符编码爆破断层，向主仓库递交任何功能模块前，务必保证预先加载挂载代码守护 Git 验证钩子：

**Windows 用户的指令处理**：
```powershell
git config core.hooksPath .githooks
sh ./scripts/check_text_integrity.sh --all
```

**Linux / macOS 用户的指令处理**:
```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit scripts/check_text_integrity.sh
```
