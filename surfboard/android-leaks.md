# Android 上的 DNS 与 WebRTC 泄漏：实际状况与修复

先给检查结论，再给修复步骤。有些你担心的东西已经被覆盖了，
而真正的漏点在配置文件之外。

## 检查结论

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| 代理域名的 DNS | **已覆盖** | 命中代理策略的域名交给服务端远程解析，本地不查，无从泄漏 |
| 直连域名的 DNS | **已覆盖** | `doh-server` 加密到国内 DoH，不走明文 53 |
| 兜底流量 | **已覆盖** | `FINAL,Proxy`，未命中规则的请求不会直连出去 |
| UDP 回落 | **已覆盖** | `udp-policy-not-supported-behaviour = REJECT` |
| WebRTC 公网 IP | **基本已覆盖** | 见第 2 节，原因和多数教程说的不一样 |
| **系统私人 DNS** | **需你手动处理** | 系统级设置，配置文件管不到 |
| **浏览器自带 DoH** | **需你手动处理** | Chrome / Firefox 自己绕过系统解析 |
| **VPN 断开瞬间** | **需你手动处理** | 需要开启系统的 VPN 终止开关 |
| **分应用绕过列表** | **需你检查** | 列表里的 App 完全不走隧道 |
| STUN 在 `always-real-ip` 里 | **已修复** | 见第 4 节，这是本次检查发现的一处自相矛盾 |

**一句话总结：配置层面该做的都做了，剩下的四项只能在手机系统设置里改。**

## 1. DNS：手机上真正的漏点

配置文件里的 DNS 设置只对「经过 Surfboard 的解析请求」生效。
下面这些路径根本不经过它：

### 1.1 系统「私人 DNS」（Private DNS / DoT）

Android 9 以上有一个系统级的加密 DNS 开关。它工作在系统解析器层面，
和 Surfboard 的规则型 DNS 是两套东西。不同 Android 版本和厂商 ROM 上，
两者的优先级行为并不一致 —— 这种不确定性本身就是风险。

**改法**：设置 → 网络和互联网 → 私人 DNS → **选「关闭」**。
（部分 ROM 在「更多连接设置」或「其他网络设置」里。）

关掉之后 DNS 由 Surfboard 统一管：直连域名走你配的国内 DoH（仍是加密的），
代理域名走服务端远程解析。既不明文，也不会和分流规则打架。

### 1.2 浏览器自带的 DoH

Chrome 和 Firefox 有各自的加密 DNS，**绕过系统解析器**，
也就绕过了 Surfboard 的分流逻辑。

- **Chrome**：设置 → 隐私和安全 → 安全 → **「使用安全 DNS」关闭**
- **Firefox**：设置 → 隐私 → DNS over HTTPS → **关闭**

关掉不会让你变得更不安全 —— 解析仍然由 Surfboard 加密送到 DoH 服务器。

### 1.3 分应用代理 / 绕过列表

Surfboard 支持按应用选择是否走代理。**绕过列表里的 App 完全不经过隧道**，
它的 DNS 和流量都直接走运营商网络。

**检查**：打开 Surfboard 的分应用设置，确认浏览器、以及任何你在意的 App
都不在绕过列表里。国内 App（银行、打车、外卖）放进去是合理的，
但要清楚它们的流量确实是裸奔状态。

### 1.4 VPN 断开的那几秒

隧道重连、切换 Wi-Fi/移动网络、App 被系统杀掉的瞬间，
流量会短暂地直接走本地网络。这是最容易被忽略的泄漏窗口。

**改法**（这是本文最重要的一条设置）：

设置 → 网络和互联网 → VPN → Surfboard 右侧齿轮 →
开启 **「始终开启的 VPN」** 和 **「阻止不使用 VPN 的连接」**

第二项就是 kill switch：隧道不通时**一切网络请求直接失败**，
而不是悄悄改走本地网络。它同时也解决了下一节的 IPv6 问题。

### 1.5 IPv6

配置里 `ipv6 = false` 让 Surfboard 不处理 IPv6。
如果你的运营商给了 IPv6 地址，理论上存在 IPv6 流量绕过隧道的可能。

开了上面的 kill switch 就已经堵住了。想更彻底的话，
移动网络可以在 APN 设置里把「APN 协议」改成 **IPv4**（Wi-Fi 侧改不了，靠 kill switch）。

## 2. WebRTC：为什么你在 Android 上基本不用担心

网上绝大多数 WebRTC 泄漏教程针对的是**桌面浏览器插件式代理**的场景：
浏览器的 HTTP 走代理，但 WebRTC 的 UDP 不走，于是 STUN 直接从本机发出去，
把真实公网 IP 暴露给网页。

**你的情况不是这样。** Surfboard 在 Android 上以 VpnService 运行，
接管的是整个系统的网络流量，**UDP 也在隧道里**。所以 WebRTC 通过 STUN
探到的「公网 IP」就是你的代理出口 IP，不是你的真实 IP。

唯一的真实漏点是：**节点不支持 UDP 时，客户端把 UDP 悄悄回落成直连** ——
那样 STUN 就真的从本地发出去了。而这一条已经被配置堵死：

```
udp-policy-not-supported-behaviour = REJECT
```

宁可让 UDP 失败，也不让它偷偷走本地网络。这一行同时保护了 WebRTC、
QUIC 和 DNS-over-QUIC。

**还会看到什么**：网页可能仍然能拿到 `192.168.x.x` 这类局域网地址。
这只暴露你的内网结构，不暴露你是谁，而且现代 Chrome 默认用 mDNS 随机主机名
（形如 `xxxx.local`）遮蔽了它。这不构成去匿名化风险。

**要不要彻底掐死 STUN**：`examples/single-origin.conf` 里给了注释掉的规则。
代价是所有网页版语音/视频通话全部不能用（Meet、Zoom 网页版、Discord 网页版）。
**我的建议是不要开** —— 它挡的是一个已经被覆盖的风险，代价却是实打实的。

想换浏览器层面的保险：Firefox 可以在 `about:config` 里把
`media.peerconnection.enabled` 设为 `false`；Brave 在设置里有 WebRTC IP
处理策略。Android 版 Chrome 没有这个开关，也装不了插件。

## 3. 验证：改完之后自己测一遍

连着 Surfboard，用手机浏览器依次打开：

| 测什么 | 地址 | 期望结果 |
| --- | --- | --- |
| 出口 IP | `ip.sb` 或 `ipinfo.io` | 显示代理出口的 IP 和地区，不是你所在地 |
| DNS 泄漏 | `browserleaks.com/dns` | 解析服务器不应出现你的运营商（电信/联通/移动） |
| WebRTC | `browserleaks.com/webrtc` | **Public IP 应等于上面的代理出口 IP**；Local IP 显示 `.local` 随机名属正常 |
| IPv6 | `test-ipv6.com` | 理想是没有 IPv6 连接，或 IPv6 也显示代理出口 |

**关键判据是 WebRTC 页面的 Public IP 和 `ip.sb` 显示的是否一致。**
一致就说明 WebRTC 没有绕过隧道 —— 这比任何配置检查都直接。

再做一次断线测试：开着测试页面，把 Surfboard 关掉，
如果 kill switch 生效，页面应该**直接加载失败**，而不是显示你的真实 IP。

## 4. 本次检查修掉的一处矛盾

原 `surfboard.conf` 的 `always-real-ip` 里包含 `stun.l.google.com`、
`*.stun.playstation.net`、`*.srv.nintendo.net`。

`always-real-ip` 的作用是让这些域名返回真实解析结果。这本来是为了主机游戏
的 NAT 穿透，但它和「不让 WebRTC 探到真实网络位置」的目标直接冲突 ——
等于亲手给 STUN 开了绿灯。

手机场景用不到主机 NAT 穿透，已经移除，并在配置里注释说明了什么情况下才加回来。

## 5. 优先级

按收益排序，前两条五分钟就能做完：

1. **开启「始终开启的 VPN」+「阻止不使用 VPN 的连接」** —— 一条设置堵住断线泄漏和 IPv6 泄漏
2. **关闭系统「私人 DNS」** —— 消除和 Surfboard DNS 的行为冲突
3. **关闭 Chrome「使用安全 DNS」** —— 让浏览器解析回到分流规则里
4. **检查分应用绕过列表** —— 确认在意的 App 不在里面
5. **按第 3 节测一遍** —— 不要相信配置写对了就等于生效了
