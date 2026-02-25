# 🛡️ Cloudflare 进阶防护及 ZeroTrust 零信任

为了实现更高的运维级别容灾与网络安全管理，VpsHelper 无缝对接到你 Cloudflare 账户，通过全局 API Token 提供一套完备的控制台替代。

---

## 一、DDNS 动态寻址推流
即使主控端架设在家宽或者非固定公网 IP 的环境下，只要在**Cloudflare 管理**板块绑定 API，后台驻留进程就会：
1. 以特定触发频次对本机外面的出站 IP（IPv4 以及 IPv6 双栈）进行侦缉。
2. 发现改变时立即推送给您的域名解析池完成 A 记录级修改。以避免您的设备脱落。

## 二、分离式高危白名单/黑名单
直接通过本控制面下达 WAF 高阶规则指令：

- **BlockList (阻断名单)**: 您可定制特定 URL 目录、特定的路由动作，并在 Web UI 内增删指定的封停 IP 过滤网络中的流窜爬虫、嗅探机。
- **ZeroTrust 白名单放行**: 当您的 Cloudflare Access 配置了极端的应用反向代理保护，但你需要允许某个受信任的家里/公司办公室节点随时避开登录验证阻击直连应用时。
- 可以复用多个现成的 IP 将其加入“VpsHelper 信任池”，同步向云端的 ZeroTrust 策略中注入放行通过标识。

## 三、相关说明
使用任意子模块前都需要录入有效的 **Cloudflare API Token**。在 CF 面板中申请时请赋予 `Zone WAF Edit` 和 `Zero Trust Edit` 等相对应的组件控制权，其余的路由标识例如 `Account ID`, `Zone ID`, `Policy ID` VpsHelper 后端都会替您全自动嗅探捕捉并持久化，免除所有复制粘贴这些毫无可读性的 GUID 工作量。
