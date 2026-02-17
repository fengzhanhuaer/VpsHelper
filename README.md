# VpsHelper

当前仓库已开始迁移到 Go（Gin）全栈版本，新的实现位于 goapp/。

- Go 版默认访问地址：http://127.0.0.1:15018
- 旧 Python 版仍保留在仓库根目录，但后续功能以 Go 版为主

## 当前状态（重要）

Go 版目前尚未完全覆盖 Python 版所有功能：
- 已迁移：注册/登录/改密、程序更新（GitHub Release）、服务器状态、Shell 交互、防火墙、SSH 设置（端口/登录方式/Fail2ban/诊断，需 root 才能应用）、TG 登录（验证码/可选 2FA）、TG 账号管理/代理设置、dialogs 刷新与选择目标、自动发送任务（基础版）、自动回复（基础版：实时 Updates 监听 + 关键词包含匹配）、签到任务（含每日自动签到）、数据库 D1 备份/拉取与每日自动备份。
- TG 补充：/tg/accounts 页面支持选择账号后“一键刷新 dialogs”，并可在同页配置/执行签到任务。

### 自动签到（Go 版）

Go 版提供每日自动签到后台任务（默认关闭）。通过数据库表 `app_settings` 配置：
- `tg_sign_auto_enabled=1` 开启
- `tg_sign_auto_time=HH:MM` 设置每天执行时间（默认 03:30，依赖系统时区/`TZ`）

执行结果会写入 `tg_sign_auto_last_result`，并在 `/tg/sign` 页面展示“最近自动签到”。

### 自动回复（Go 版）

自动回复支持基础规则（包含匹配，忽略大小写）与后台实时监听。为防刷屏，默认对“同一会话 + 同一规则”做冷却。
可通过数据库表 `app_settings` 配置：
- `tg_auto_reply_cooldown_seconds=15` 冷却秒数（默认 15；设置为 0 或负数表示关闭冷却）

运行统计（用于排障，后台每 30 秒写入一次）：
- `tg_auto_reply_stats_<owner>_<accountID>`（例如 `tg_auto_reply_stats_admin_1`）

## 仍待完善（示例）

- 自动回复的高级规则引擎（目前已提供基础版：实时监听 + 关键词包含匹配）

### 页面结构
- **一级页面**: 主菜单，显示各功能模块入口（Tg助手、防火墙等）
- **二级页面**: 各功能模块的详细操作界面

## 安装与使用（Go 版）

### Windows 快速启动

```powershell
cd goapp
go run ./cmd/server
```

### Linux 一键安装为服务（Go 版，基于 Release）

```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install-go.sh | sudo bash
```

说明：脚本会下载 GitHub Releases 的最新二进制并安装 systemd 服务（默认服务名 `vpshelper`，安装目录 `/opt/vpshelper`）。
说明：默认会替换旧的 Python 服务 `vpshelper.service`（会先 stop/disable，并备份 unit）。

### 生产运行（建议）

```powershell
cd goapp
go build -o .\bin\vpshelper.exe .\cmd\server
.\bin\vpshelper.exe
```

## 安装与使用（Python 版，旧）

### Windows 快速启动
双击运行 `VpsHelper.bat`

### Linux 快速启动
```bash
chmod +x VpsHelper.sh
./VpsHelper.sh
```

### Linux 一键安装为服务
复制一条命令即可下载安装并自动安装/启动服务：
```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash
```
说明：脚本会在 Debian/Ubuntu 上自动尝试安装 `python3-venv`，并重试创建虚拟环境。
说明：安装完成后会自动输出该服务最近 50 行日志，便于确认启动状态。
无 curl 时可用：
```bash
wget -qO- https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash
```
指定安装目录（可选）：
```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash -s -- https://github.com/fengzhanhuaer/VpsHelper /opt/vpshelper
```

### 手动安装依赖
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python VpsHelper.py
```

## 使用说明

1. 启动服务后，打开 [http://127.0.0.1:15018](http://127.0.0.1:15018)
2. 首次进入先注册本地管理员账号
3. 登录后进入主菜单，选择需要的功能模块
4. 主菜单可直接进入“数据库管理”：配置 Cloudflare Token，执行备份/拉取
5. 进入 Tg助手 可以：
   - 设置 API：配置 Telegram API ID 和 Hash
   - 设置代理：配置网络代理
   - 管理帐号：添加 TG 账号并刷新会话
   - 自动发送：新建任务、管理任务、手动触发

## 目录说明

- `VpsHelper.py`: 主程序入口与全部后端逻辑
- `pyprogram/TgHelper.py`: Tg助手子程序（TG操作、配置、调度、云备份）
- `templates/`: 前端模板
- `requirements.txt`: Python 依赖
- `VpsHelper.bat`: Windows 启动脚本
- `VpsHelper.sh`: Linux 启动脚本
- `install.sh`: Linux 一键下载更新、安装 systemd 服务并启动（单脚本）

## 备注

- 用户数据统一存放在安装目录 `./userdata/`
- 本地数据库文件名统一为 `./userdata/VpsHelper.db`（单库多表）
- 主程序表：`users`、`sessions`
- Tg助手表：`tg_accounts`、`tg_dialogs`、`tg_sign_tasks`、`tg_auto_send_tasks`、`tg_login_flows`、`app_settings`
- 端口默认 15018
- 默认时区为 UTC+8（Asia/Shanghai）；如需覆盖可设置环境变量 `TZ` 或 `VPSHELPER_TZ`
