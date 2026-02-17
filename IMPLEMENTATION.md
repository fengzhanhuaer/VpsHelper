# VpsHelper 实现说明

## 项目概述（重要）

本仓库目前同时包含：
- Go/Gin 版本（主线）：goapp/
- Python/Flask 版本（旧）：仓库根目录

本文档最初描述的是 Python/Flask 的 2 级页面结构，当前仅作为“旧实现参考”。Go 版的路由与模板实现已在 goapp/ 中逐步对齐，但尚未完全覆盖所有 Python 功能。

## 2 级页面结构设计（Python 旧版）

### 第一级：主菜单 (/)
- **路由**: `/home`
- **模板**: `templates/home.html`
- **功能**: 显示所有可用的功能模块入口
- **当前模块**:
  - 数据库管理 (`/settings/database`)
  - Tg助手 (`/tg_helper`)
  - 防火墙 (`/firewall`)

### 第二级：功能模块页面
每个功能模块都有自己的二级页面，包含该模块的所有子功能。

#### Tg助手模块
- **路由**: `/tg_helper`
- **模板**: `templates/tg_helper.html`
- **子功能**:
  - 设置 API (`/tg/settings`)
  - 设置代理 (`/tg/proxy`)
  - 管理帐号 (`/tg/accounts`)
  - dialogs 刷新 (`/tg/dialogs`)
  - 自动发送 (`/tg/auto/send`)
  - 签到任务 (`/tg/sign`)
  - 自动回复（基础版）(`/tg/auto/reply`)

#### 防火墙模块
- **路由**: `/firewall`
- **模板**: `templates/firewall.html`
- **状态**: 预留接口，功能开发中

## 导航设计

### 导航流程
```
登录 → 主菜单(一级) → 功能模块(二级) → 具体功能(三级)
                        ↓                    ↓
                    [返回主菜单]          [返回Tg助手]
```

### 面包屑导航
- **数据库管理页面**: 显示"返回主菜单"按钮，返回到一级菜单
- **Tg三级页面**: 显示"返回Tg助手"按钮，返回到对应的功能模块页面
- **二级页面**: 显示"返回主菜单"按钮，返回到主菜单
- **一级页面**: 显示"退出登录"按钮

## 技术实现

### Tg 子程序拆分
- Tg 相关操作已拆分至 `pyprogram/TgHelper.py` 子程序文件。
- 主程序 `VpsHelper.py` 保留一级菜单、登录认证与模块入口，Tg 业务逻辑由子程序接管。

### 路由结构
```python
# 一级页面
@app.route("/home")
def home():
    # 显示主菜单，包含各功能模块入口

# 二级页面
@app.route("/tg_helper")
def tg_helper():
    # 显示 Tg助手 的所有子功能

@app.route("/firewall")
def firewall():
    # 显示防火墙功能（预留）

# 三级页面（Tg助手子功能）
@app.route("/settings/api")
def api_settings():
    # API 设置页面

@app.route("/accounts")
def accounts():
    # 账号管理页面

# ... 其他子功能路由
```

说明：以上代码片段为 Python/Flask 旧版示例。Go 版请以 goapp/ 下的路由与模板为准（例如 `/tg/settings`、`/tg/accounts`、`/tg/dialogs` 等）。

### 模板更新
所有三级页面的导航链接已更新：
- 原来的"返回首页"链接改为"返回Tg助手"
- 链接目标从 `url_for('home')` 改为 `url_for('tg_helper')`

## 扩展指南

### 添加新功能模块

1. **在 VpsHelper.py 中添加路由**:
```python
@app.route("/new_module")
def new_module():
    username = require_login()
    if not username:
        return redirect(url_for("login"))
  return render_template("new_module.html", username=username)
```

2. **创建模板 templates/new_module.html**:
```html
{% extends "base.html" %}
{% block content %}
  <div class="top-actions">
    <a class="ghost" href="{{ url_for('home') }}">返回主菜单</a>
    <a class="ghost" href="{{ url_for('logout') }}" style="margin-left: auto;">退出登录</a>
  </div>
  <h1>新模块名称</h1>
  <p>模块描述</p>
  <div style="margin-top: 12px; display: grid; gap: 10px;">
    <!-- 模块的具体功能按钮 -->
  </div>
{% endblock %}
```

3. **在 templates/home.html 中添加入口**:
```html
<a class="btn" href="{{ url_for('new_module') }}">新模块</a>
```

### 添加模块子功能

1. 在对应模块的模板中添加功能按钮
2. 创建子功能的路由和模板
3. 在子功能模板中添加"返回[模块名]"按钮

## 数据库
- 用户数据目录: `./userdata/`
- 统一数据库文件: `./userdata/VpsHelper.db`（单库多表）
- 主程序表: `users`
- Tg助手表: `tg_accounts`、`tg_dialogs`、`tg_sign_tasks`、`tg_auto_send_tasks`、`tg_login_flows`、`app_settings`
- Cloudflare D1 数据库名: `TgHelper`
- 端口: 15018

## 迁移状态（Go 版）

当前 Go 版已覆盖：
- 登录/注册/改密
- 程序更新（Git 拉取构建 + 重启、以及 GitHub Release 下载更新）
- TG 用户登录（验证码/可选 2FA，会话入库）
- 服务器状态、Shell 交互、防火墙
- Cloudflare D1 备份/拉取与每日自动备份

仍待迁移（不完全列表）：
- TG 账号管理列表/删除、代理设置
- 自动发送/自动回复/签到任务与调度
- SSH 设置页面与相关运维能力

## 安全性
- 使用 Flask session 管理用户登录状态
- 密码使用 werkzeug.security 进行哈希存储
- Token 机制支持跨页面认证
- 通过 .gitignore 排除敏感数据文件
