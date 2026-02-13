# VpsHelper

VpsHelper 是一个基于 Flask 的 VPS 管理工具集，包含多个功能模块：

- **Tg助手**: 基于 Telethon 的 Telegram 管理工具，支持多账号管理、自动发送任务、数据库备份等
- **防火墙**: 防火墙管理功能（开发中）
- 更多功能模块待添加...

默认访问地址：[http://127.0.0.1:15018](http://127.0.0.1:15018)

## 特性

### Tg助手功能
- 首次注册/登录
- 多 TG 账号管理
- 自动发送任务（每日时间 + 随机延时）
- 本地数据库与 Cloudflare D1 备份/拉取

### 页面结构
- **一级页面**: 主菜单，显示各功能模块入口（Tg助手、防火墙等）
- **二级页面**: 各功能模块的详细操作界面

## 安装与使用

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
- 自动任务时间展示为 UTC+8
