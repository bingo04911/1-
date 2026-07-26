#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成一份零占位符、可直接加载的 Surfboard 配置。

自动生成 UUID、密码和随机 WebSocket 路径，填进模板，
同时打印出服务端需要的对应参数。

最小用法（只修泄漏，节点用现有订阅，不需要服务器）：

    python3 scripts/gen_surfboard_conf.py --sub "https://你的订阅地址" \
        -o ~/surfboard.local.conf

带自建节点（CDN 保底层 + 直连冷备）：

    python3 scripts/gen_surfboard_conf.py \
        --sub "https://你的订阅地址" \
        --domain example.com \
        -o ~/surfboard.local.conf

生成的文件默认带 .local.conf 后缀，已被 .gitignore 忽略，不会误提交。
"""

from __future__ import annotations

import argparse
import secrets
import sys
import uuid
from pathlib import Path

CF_PORTS = (443, 8443, 2053, 2083, 2087, 2096)
DIRECT_PORT = 8443
RULESET_DIRECT = (
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules"
    "/release/ruleset/direct.txt"
)

GENERAL = """[General]

# 直连域名用国内加密 DoH；代理域名由服务端远程解析，本地不查
dns-server = 223.5.5.5, 119.29.29.29
doh-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query

# 不处理 IPv6，避免 IPv6 流量绕过规则（配合手机上的 kill switch）
ipv6 = false

skip-proxy = 127.0.0.1, localhost, *.local, 10.0.0.0/8, 172.16.0.0/12, \
192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 224.0.0.0/4, 17.0.0.0/8

# 这里绝不放 stun 域名，否则等于给 WebRTC 探测开绿灯
always-real-ip = *.msftconnecttest.com, *.msftncsi.com, captive.apple.com, \
connectivitycheck.gstatic.com

# 节点不支持 UDP 时直接拒绝，绝不静默回落直连
udp-policy-not-supported-behaviour = REJECT

internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204
proxy-test-url = http://cp.cloudflare.com/generate_204
test-timeout = 5
"""

RULES = """[Rule]

# 内网直连，no-resolve 避免为内网地址发起 DNS 查询
IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
IP-CIDR,169.254.0.0/16,DIRECT,no-resolve

# 国内域名直连：字符串匹配，不触发任何本地 DNS 解析。
# 这一行替代 GEOIP 的大部分职责，是消除 DNS 泄漏的关键。
RULE-SET,{ruleset},DIRECT

# 强制 STUN / TURN 走隧道，必须在 GEOIP 之前
DOMAIN-KEYWORD,stun,Proxy
DOMAIN-KEYWORD,turn,Proxy

# GEOIP 带 no-resolve：只对 IP 目标生效，域名跳过不解析
GEOIP,CN,DIRECT,no-resolve

FINAL,Proxy
"""


def build(sub_url: str, domain: str | None) -> tuple[str, dict[str, str]]:
    """返回 (配置内容, 服务端参数)。"""
    # 两个入口用各自独立的 UUID 和路径：一个泄露不牵连另一个
    creds = {
        "uuid": str(uuid.uuid4()),
        "ws_path": "/" + secrets.token_urlsafe(12),
        "standby_uuid": str(uuid.uuid4()),
        "standby_ws_path": "/" + secrets.token_urlsafe(12),
    }

    parts = [
        "# 由 scripts/gen_surfboard_conf.py 生成，凭据为随机值。",
        "# 这个文件含真实凭据 —— 不要提交到 git，不要分享。",
        "",
        GENERAL,
    ]

    groups = ["[Proxy Group]", ""]
    probe = "url=http://cp.cloudflare.com/generate_204"

    if domain:
        cdn_host = f"cdn.{domain}"
        direct_host = f"direct.{domain}"
        common = (
            f"username={creds['uuid']}, ws=true, tls=true, "
            f"ws-path={creds['ws_path']}, ws-headers=Host:{cdn_host}, "
            f"sni={cdn_host}, skip-cert-verify=false, vmess-aead=true, "
            f"udp-relay=true"
        )
        parts += [
            "[Proxy]",
            "",
            "# CDN 保底层：客户端连 Cloudflare，源站 IP 不出现在本文件中。",
            "# 放心天天用 —— 国内只看得到 CF 的 anycast IP。",
            f"CDN-443 = vmess, {cdn_host}, 443, {common}",
            f"CDN-8443 = vmess, {cdn_host}, 8443, {common}",
            "",
            "# 直连冷备：平时零流量，只在前面全挂时手动切过来。",
            "# 刻意不进自动探测链 —— 探测本身就会消耗这个 IP 的干净度。",
            "# 用独立的 UUID 和路径，和 CDN 入口互不牵连。",
            f"Direct-Standby = vmess, {direct_host}, {DIRECT_PORT}, "
            f"username={creds['standby_uuid']}, ws=true, tls=true, "
            f"ws-path={creds['standby_ws_path']}, ws-headers=Host:{direct_host}, "
            f"sni={direct_host}, skip-cert-verify=false, vmess-aead=true, "
            f"udp-relay=true",
            "",
        ]
        groups += [
            "Proxy     = select, Resilient, Relay, CDN, Standby",
            "",
            "# 订阅挂了自动落到你自己的 CDN 层",
            f"Resilient = fallback, Relay, CDN, {probe}, interval=180, timeout=3",
            "",
            f"Relay     = url-test, policy-path={sub_url}, update-interval=86400, "
            f"{probe}, interval=180, tolerance=80, timeout=3",
            "",
            f"CDN       = fallback, CDN-443, CDN-8443, {probe}, "
            "interval=180, timeout=3",
            "",
            "# 冷备：不进自动链，手动切换",
            "Standby   = select, Direct-Standby",
        ]
    else:
        groups += [
            "Proxy = select, Relay",
            "",
            f"Relay = url-test, policy-path={sub_url}, update-interval=86400, "
            f"{probe}, interval=180, tolerance=80, timeout=3",
        ]

    parts += ["\n".join(groups), "", RULES.format(ruleset=RULESET_DIRECT)]
    return "\n".join(parts), creds


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="生成可直接加载的 Surfboard 配置")
    ap.add_argument("--sub", required=True, help="你的订阅地址（https）")
    ap.add_argument("--domain", help="你的域名，如 example.com。省略则只生成修漏配置")
    ap.add_argument("-o", "--output", required=True, help="输出路径")
    args = ap.parse_args(argv)

    if not args.sub.startswith("https://"):
        print("订阅地址必须是 https —— http 订阅可被中间人替换成恶意节点。",
              file=sys.stderr)
        return 2

    content, creds = build(args.sub, args.domain)
    out = Path(args.output).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    out.chmod(0o600)

    print(f"已生成：{out}")
    if not args.domain:
        print("\n只含修漏配置，节点全部来自订阅。填好后直接导入 Surfboard 即可。")
        print("等自建 CDN 层搭好后，加 --domain 重新生成。")
        return 0

    print("\n把下面这行直接贴到服务器上执行（参数已对齐本配置）：\n")
    print(
        f"  sudo bash server/setup.sh \\\n"
        f"    --cdn-domain cdn.{args.domain} \\\n"
        f"    --direct-domain direct.{args.domain} \\\n"
        f"    --uuid {creds['uuid']} \\\n"
        f"    --ws-path {creds['ws_path']} \\\n"
        f"    --standby-uuid {creds['standby_uuid']} \\\n"
        f"    --standby-ws-path {creds['standby_ws_path']}"
    )
    print("\nCloudflare 上把 cdn.* 记录开橙色小黄云，direct.* 保持灰色。")
    print(f"CDN 可用端口：{', '.join(map(str, CF_PORTS))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
