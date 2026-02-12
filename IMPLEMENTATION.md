# VpsHelper 实现说明

## 项目概述
VpsHelper 是一个基于 Flask 的 VPS 管理工具集，采用 2 级页面结构设计，便于扩展和管理多个功能模块。

## 2 级页面结构设计

### 第一级：主菜单 (/)
- **路由**: `/home`
- **模板**: `templates/home.html`
- **功能**: 显示所有可用的功能模块入口
- **当前模块**:
  - Tg助手 (`/tg_helper`)
  - 防火墙 (`/firewall`)

### 第二级：功能模块页面
每个功能模块都有自己的二级页面，包含该模块的所有子功能。

#### Tg助手模块
- **路由**: `/tg_helper`
- **模板**: `templates/tg_helper.html`
- **子功能**:
  - 设置 API (`/settings/api`)
  - 设置代理 (`/settings/proxy`)
  - 数据库管理 (`/settings/database`)
  - 管理帐号 (`/accounts`)
  - 自动发送 (`/auto/send`)
  - 自动回复 (`/auto/reply`)

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
- **三级页面**: 显示"返回Tg助手"按钮，返回到对应的功能模块页面
- **二级页面**: 显示"返回主菜单"按钮，返回到主菜单
- **一级页面**: 显示"退出登录"按钮

## 技术实现

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
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("new_module.html", username=username, token=token)
```

2. **创建模板 templates/new_module.html**:
```html
{% extends "base.html" %}
{% block content %}
  <div class="top-actions">
    <a class="ghost" href="{{ url_for('home', token=token) }}">返回主菜单</a>
    <a class="ghost" href="{{ url_for('logout', token=token) }}" style="margin-left: auto;">退出登录</a>
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
<a class="btn" href="{{ url_for('new_module', token=token) }}">新模块</a>
```

### 添加模块子功能

1. 在对应模块的模板中添加功能按钮
2. 创建子功能的路由和模板
3. 在子功能模板中添加"返回[模块名]"按钮

## 数据库
- 数据库文件: `VpsHelper.db`
- Cloudflare D1 数据库名: `VpsHelper`
- 端口: 15018

## 从 TgHelper 迁移的功能
所有 TgHelper 的原有功能都已完整保留：
- 用户认证系统
- 多 Telegram 账号管理
- 自动发送任务调度
- Cloudflare D1 数据库备份
- API 和代理配置

## 安全性
- 使用 Flask session 管理用户登录状态
- 密码使用 werkzeug.security 进行哈希存储
- Token 机制支持跨页面认证
- 通过 .gitignore 排除敏感数据文件
