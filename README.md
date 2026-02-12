# VpsHelper

VpsHelper 是一个基于 Flask 的 VPS 管理工具，采用两级菜单结构，集成了 Telegram 助手、防火墙管理等功能。

## 功能特点

### 一级菜单（主页）
- **TG助手** - Telegram 自动化管理工具
- **防火墙** - 防火墙配置管理（开发中）
- 其他功能（待扩展）

### 二级菜单（TG助手）
- **账号管理** - 添加和管理 Telegram 账号
- **自动发送** - 配置定时自动发送消息任务
- **自动回复** - 自动回复设置（开发中）
- **API设置** - 配置 Telegram API ID 和 Hash
- **代理设置** - 配置代理服务器
- **数据库管理** - 本地数据库与 Cloudflare D1 同步

默认访问地址：
- http://127.0.0.1:15018

**安全提示**：应用默认绑定到 127.0.0.1，仅本机访问。如需远程访问，请设置环境变量 `FLASK_HOST=0.0.0.0` 并配置防火墙规则。

---

## 安装说明

### Linux 系统

1. 确保已安装 Python 3.8+ 和 pip

2. 运行安装脚本：
```bash
chmod +x install
./install
```

3. 服务将自动启动在 http://127.0.0.1:15018

### Windows 系统

1. 确保已安装 Python 3.8+

2. 双击运行 `VpsHelper.bat`

或在命令行中运行：
```cmd
VpsHelper.bat
```

---

## 手动安装（可选）

如果不使用自动安装脚本：

```bash
# 创建虚拟环境
python3 -m venv .venv

# 激活虚拟环境
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 启动服务
python VpsHelper.py
```

---

## 使用方法

### 初次使用

1. 启动服务后，浏览器访问 http://127.0.0.1:15018
2. 首次访问会提示注册管理员账号
3. 注册并登录后进入主页（一级菜单）

### TG助手功能

1. 点击"TG助手"进入 TG 助手菜单（二级菜单）
2. 配置 Telegram API：
   - 点击"API设置"
   - 填入从 https://my.telegram.org 获取的 API ID 和 API Hash
3. （可选）配置代理：
   - 如需要使用代理连接 Telegram，点击"代理设置"
   - 填入 SOCKS5 代理信息
4. 添加 TG 账号：
   - 点击"账号管理"
   - 点击"添加账号"
   - 按提示输入手机号、验证码等信息
5. 配置自动发送任务：
   - 点击"自动发送"
   - 创建新任务，设置发送内容、时间和频率

---

## 配置环境变量（可选）

可以通过环境变量配置 Telegram API：

```bash
export TELEGRAM_API_ID="your_api_id"
export TELEGRAM_API_HASH="your_api_hash"
export FLASK_SECRET_KEY="your_secret_key"
```

---

## 项目结构

```
VpsHelper/
├── VpsHelper.py          # 主程序入口
├── templates/            # HTML 模板文件
│   ├── base.html        # 基础模板
│   ├── home.html        # 主页（一级菜单）
│   ├── tg_helper.html   # TG助手菜单（二级菜单）
│   ├── tg_accounts.html # TG账号管理
│   └── ...
├── requirements.txt      # Python 依赖
├── VpsHelper.bat        # Windows 启动脚本
├── install              # Linux 安装脚本
└── VpsHelper.db         # 本地 SQLite 数据库（自动创建）
```

---

## 注意事项

- 本地数据库文件名为 `VpsHelper.db`
- 默认端口为 15018
- 请妥善保管 Telegram API ID 和 Hash
- 建议在生产环境中修改 FLASK_SECRET_KEY

---

## 参考项目

本项目参照 [TgHelper](https://github.com/fengzhanhuaer/TgHelper) 的功能和架构，采用两级菜单设计，保持了 TG 助手的完整功能。

---

## 技术栈

- **后端**: Flask + SQLite
- **异步任务**: APScheduler
- **Telegram**: Telethon
- **前端**: HTML + CSS (内嵌样式)

---

## 许可证

本项目仅供学习和个人使用。