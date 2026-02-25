# 📦 安装与挂载指引

VpsHelper 主控端及子节点被控探针 (VpsProbe) 通过我们维护的线上脚本可快速安装、卸载。

## 1. Linux 服务器部署主控端 (推荐级别)
该脚本能利用 API 自动拉取最新的预编译可用二进制内核版本，释放到 `/usr/local/bin` 并拉取 `systemd` 守护进程：

```bash
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash
```

- **访问端口**: `http://你的主控节点IP:15018`
- **后台驻留名称**: `vpshelper.service`（可通过 `systemctl status vpshelper` 查看详情）。

## 2. 子节点机器挂载 (探针架构)
对于受控的辅助服务器节点，需登入主控端的 **“探针节点”** 页面，先点击页面右上角生成专属配网密钥。复制系统自动为你拼写的 `curl` 命令到受控机器：

```bash
curl -sSL https://raw.githubusercontent.com/fengzhanhuaer/VpsHelper/main/install-probe.sh | bash -s -- --secret 你的独立SECRET_KEY --host https://你的主控端面版公网地址
```
此操作将自动在子机中化为 `vpsprobe.service` 的精简内存态受控端静默长连。


## 3. 调试与手工卸载操作
若日后打算全面移除所有配置信息和历史归档时序数据库，或者通过菜单面板操作服务启停：

```bash
# 进入管理菜单：
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash -s menu

# 发起核平卸载 (销毁主控面板所有的服务和数据)：
curl -fsSL https://github.com/fengzhanhuaer/VpsHelper/raw/refs/heads/main/install.sh | sudo bash -s uninstall
```
