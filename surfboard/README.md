# Surfboard 节点安全加固

针对中国网络环境下 Surfboard（Surge 配置格式的 Android 客户端）的节点安全硬化。
解决的是三类具体问题：**流量特征被识别**、**流量被中间人解密**、**真实 IP / DNS 泄漏**。

## 目录

| 文件 | 用途 |
| --- | --- |
| `surfboard/surfboard.conf` | 硬化过的配置模板，替换占位符后直接可用 |
| `scripts/audit_surfboard_conf.py` | 扫描现有配置，逐条报出问题与修法 |

## 先扫一遍你现在在用的配置

```bash
# 从 Surfboard 里导出当前配置，或找到你的 .conf 文件
python3 scripts/audit_surfboard_conf.py /path/to/your.conf

# 把 MEDIUM 也当成必须修
python3 scripts/audit_surfboard_conf.py /path/to/your.conf --strict
```

有 HIGH / CRITICAL 时退出码为 1，可以挂到 CI 或 pre-commit 上。

> 如果你的节点全部来自机场订阅，本地 `.conf` 里可能没有 `[Proxy]` 段。
> 先把订阅内容导出成明文再扫，否则扫不到真正在用的节点参数。

## 威胁模型：这些配置到底在防什么

| 威胁 | 具体手法 | 对应加固 |
| --- | --- | --- |
| 被动流量指纹 | 按端口（8388/1080）、TLS 握手特征、包长分布识别代理 | 443 端口 + 真实域名证书 + 正确 SNI |
| 主动探测 | 向可疑 IP:Port 重放/构造请求，看服务端响应是否像代理 | 只用 AEAD（`2022-blake3-*`、`chacha20-ietf-poly1305`）与 AEAD VMess（alterId=0） |
| 中间人解密 | 劫持链路后用伪造证书接管 TLS | `skip-cert-verify=false`（这一条单独就能毁掉整条链路） |
| DNS 污染 / 监听 | 明文 53 端口注入伪造应答、记录你查了什么 | `doh-server` 加密 DNS；被代理域名交给服务端远程解析 |
| 真实 IP 泄漏 | 兜底直连、UDP 回落、IPv6 绕过规则 | `FINAL,Proxy`、`udp-policy-not-supported-behaviour=REJECT`、`ipv6=false` |
| 订阅投毒 | 明文 http 订阅在传输中被替换成攻击者的节点 | 订阅与规则集一律 https |
| 节点被封即断网 | 单节点被 ban 后客户端仍死磕 | `fallback` 故障转移组 + 境外探测 URL |

## 节点四条硬规则

任何一条不满足，这个节点就不该继续用：

1. **传输层必须有真实 TLS** —— `trojan` / `hysteria2` / `vmess+ws+tls`，
   或 AEAD 加密的 Shadowsocks。裸 VMess、明文 http/socks5 一律淘汰。
2. **`skip-cert-verify` 必须是 `false`** —— 设 `true` 等于主动关掉证书校验。
   很多机场给的配置默认写 `true`（因为他们用自签证书图省事），这是最常见的严重问题。
3. **用真实域名 + 受信任证书，不要裸 IP + 自签** —— 裸 IP 上的 TLS 无法用 SNI 伪装成
   正常网站流量，而且 IP 被 ban 之后你没有任何迁移余地。
4. **端口用 443 / 8443** —— 混在正常 HTTPS 流量里。`8388`、`1080`、`10086` 这类
   默认端口等于自报身份。

## DNS 为什么这样配

模板里本地 DNS 用的是**国内**加密 DoH（阿里 `223.5.5.5` + 腾讯 `1.12.12.12`），
这看起来反直觉，但是对的：

- 命中代理策略的域名，Surfboard 把域名整个交给代理服务器去解析，**本地根本不查**，
  所以污染对这部分流量天然无效。
- 本地 DNS 只服务于 `DIRECT` 流量和 `GEOIP` 之类的 IP 类规则。这部分用国内 DoH
  既准确又快，同时避免明文 53 端口被运营商劫持和记录。
- 反过来把本地 DNS 全指向境外服务器，会让国内网站解析到远端 CDN 节点，速度变差，
  而且明文 UDP 到境外 DNS 本身就是高危特征。

## 客户端管不到的部分

配置文件只能保证**客户端这一侧**不出错。下面这些取决于服务端，如果你用的是机场，
只能换供应商；自建的话需要一并处理：

- 服务端证书是否是真实域名签发（Let's Encrypt 即可），有没有正确配置回落
- 有没有对未授权探测请求做伪装回落（比如 trojan 回落到一个真实网站）
- 是否禁用了老协议入口（旧版 SS 流加密、alterId>0 的 VMess）
- 密码 / UUID 是否每节点独立，长度是否够（`openssl rand -base64 32`）

## 关于配置里的标注

模板中每行都标了来源：

- `[已验证]` —— Surfboard 官方文档或真实可用配置中确认存在的字段
- `[Surge]` —— Surge 语法，Surfboard 是否支持未经确认，**默认注释掉**。
  取消注释后如果 App 报解析错误，删掉该行即可。

## 凭据不要进 git

`.gitignore` 已忽略 `*.local.conf` / `*.private.conf` / `secrets/`。
建议把模板另存为 `surfboard.local.conf` 再填真实节点。

## 参考

- [Surfboard Manual — Profile Format](https://getsurfboard.com/docs/profile-format/overview/)
- [Surfboard Manual — dns-server](https://getsurfboard.com/docs/profile-format/general/dns_server/)
- [Surfboard Manual — doh-server](https://getsurfboard.com/docs/profile-format/general/doh_server/)
- [Surfboard Manual — proxy-test-url](https://getsurfboard.com/docs/profile-format/general/proxy_test_url/)
- [Surfboard Manual — Proxy Group / Fallback](https://getsurfboard.com/docs/profile-format/proxygroup/fallback/)
- [getsurfboard/surfboard on GitHub](https://github.com/getsurfboard/surfboard)
