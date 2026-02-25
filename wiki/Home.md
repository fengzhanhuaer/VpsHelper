# 欢迎来到 VpsHelper 官方文档

VpsHelper 是一个功能强大、轻量级的服务器节点管理、分布式监控探针和 Telegram Bot 整合工具包，纯后端的 Go (Gin + SQLite/Cloudflare API) 构建。

## 📖 目录导读

这是本项目的完整知识库，您可以根据下方的快速跳转，找到所需的操作指引或高级架构设计说明：

### 快速入门
- [[安装与环境要求|Installation]]
- [[使用主副节点探针架构|Probe-Architecture]]

### 高级功能 & Cloudflare 联动
- [[探针TLS加密与D1数据库灾备高级说明|探针TLS与D1容灾指南]]
- [[ZeroTrust 零信任与防火墙联动|Cloudflare-Integration]]
- [[Telegram 会话助手与通知机制|Telegram-Integration]]
- [[深度运维管控与防护热更|System-Security]]

### 开发与深入原理
- [[源码调试与编译构建|Development]]
- [[后端运行机制及架构设计|Architecture]]
- [[程序免宕机更新与 Github 鉴权配置|Update-Mechanism]]

---
> 💡 提示：所有的 Wiki 数据均自动在仓库主分支通过 Github Action 强同步和部署映射。如果你希望修改文档内容，请向主仓库中的 `wiki/` 目录提交 Pull Request。
