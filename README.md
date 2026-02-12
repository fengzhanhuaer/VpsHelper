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
4. 进入 Tg助手 可以：
   - 设置 API：配置 Telegram API ID 和 Hash
   - 设置代理：配置网络代理
   - 管理帐号：添加 TG 账号并刷新会话
   - 自动发送：新建任务、管理任务、手动触发
   - 数据库管理：配置 Cloudflare Token，执行备份/拉取

## 目录说明

- `VpsHelper.py`: 主程序入口与全部后端逻辑
- `templates/`: 前端模板
- `requirements.txt`: Python 依赖
- `VpsHelper.bat`: Windows 启动脚本
- `VpsHelper.sh`: Linux 启动脚本

## 备注

- 本地数据库文件名为 `VpsHelper.db`
- 端口默认 15018
- 自动任务时间展示为 UTC+8
