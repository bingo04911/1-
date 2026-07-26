#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Surfboard / Surge 配置安全审计器。

扫描一份 .conf，找出会削弱节点安全性、或让流量在中国网络环境下泄漏、
被识别、被中间人的配置项。纯标准库，无第三方依赖。

    python3 scripts/audit_surfboard_conf.py surfboard.local.conf
    python3 scripts/audit_surfboard_conf.py *.conf --strict

退出码：0 = 无 HIGH/CRITICAL 问题；1 = 存在需要修的问题；2 = 用法错误。
--strict 下 MEDIUM 也计入失败。
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# --- 加密套件分级 -----------------------------------------------------------
# AEAD 才有完整性校验；流加密既能被主动探测识别，也能被中间人篡改密文。
AEAD_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
BROKEN_CIPHERS = {"none", "plain", "table", "rc4", "rc4-md5"}

# 需要真实 TLS 的协议，出现即要求证书校验开启
TLS_PROTOCOLS = {"trojan", "hysteria", "hysteria2", "tuic", "https", "socks5-tls", "snell"}
# 明文出站协议
CLEARTEXT_PROTOCOLS = {"http", "socks5"}

# 协议特征端口：直接暴露"这是代理"，是被动指纹的第一识别位
FINGERPRINT_PORTS = {
    8388: "Shadowsocks 默认端口",
    1080: "SOCKS5 默认端口",
    8080: "常见明文代理端口",
    8118: "Privoxy 默认端口",
    9050: "Tor 默认端口",
    10086: "常见 V2Ray 示例端口",
}
SANE_TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PLACEHOLDER_RE = re.compile(
    r"REPLACE|YOUR|EXAMPLE|CHANGE_?ME|xxx+|placeholder|<.+>|你的", re.IGNORECASE
)


@dataclass
class Finding:
    severity: str
    line: int
    node: str
    issue: str
    fix: str


@dataclass
class ProxyNode:
    name: str
    kind: str
    host: str
    port: int | None
    opts: dict[str, str]
    positional: list[str]
    line: int


def _strip_inline_comment(line: str) -> str:
    """去掉行尾注释（仅识别「空白 + #」，避免误伤密码里的 #）。"""
    match = re.search(r"\s+#", line)
    return line[: match.start()].rstrip() if match else line


def parse(text: str) -> tuple[dict[str, list[tuple[int, str]]], list[ProxyNode]]:
    """返回 (按 section 分组的行, 解析出的节点列表)。"""
    sections: dict[str, list[tuple[int, str]]] = {}
    nodes: list[ProxyNode] = []
    current = "General"

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith((";", "//")):
            continue
        if line.startswith("#") and not line.startswith("#!"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        line = _strip_inline_comment(line)
        if not line:
            continue
        sections.setdefault(current, []).append((lineno, line))
        if current.lower() == "proxy" and "=" in line:
            node = _parse_proxy_line(lineno, line)
            if node:
                nodes.append(node)

    return sections, nodes


def _parse_proxy_line(lineno: int, line: str) -> ProxyNode | None:
    name, _, rhs = line.partition("=")
    fields = [f.strip() for f in rhs.split(",") if f.strip()]
    if not fields:
        return None

    kind = fields[0].lower()
    opts: dict[str, str] = {}
    positional: list[str] = []
    for field in fields[1:]:
        if "=" in field:
            k, _, v = field.partition("=")
            opts[k.strip().lower()] = v.strip()
        else:
            positional.append(field)

    host = positional[0] if positional else ""
    port: int | None = None
    if len(positional) > 1 and positional[1].isdigit():
        port = int(positional[1])

    return ProxyNode(name.strip(), kind, host, port, opts, positional, lineno)


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in {"true", "1", "yes"}


def audit_nodes(nodes: list[ProxyNode]) -> list[Finding]:
    out: list[Finding] = []
    seen_secrets: dict[str, str] = {}

    for n in nodes:
        tls_on = n.kind in TLS_PROTOCOLS or _is_true(n.opts.get("tls"))

        # 1. 关闭证书校验 —— 单条即可让整条链路可被无声解密
        if _is_true(n.opts.get("skip-cert-verify")):
            out.append(Finding(
                CRITICAL, n.line, n.name,
                "skip-cert-verify=true，TLS 证书完全不校验",
                "改为 skip-cert-verify=false，并给节点配一张真实域名证书"
                "（Let's Encrypt 即可）；任何能劫持链路的一方都能中间人解密全部流量",
            ))

        # 2. 明文出站协议
        if n.kind in CLEARTEXT_PROTOCOLS:
            out.append(Finding(
                CRITICAL, n.line, n.name,
                f"{n.kind} 为明文协议，账号密码与全部流量无加密",
                "换成 trojan / hysteria2 / vmess+ws+tls；"
                "必须用 socks5 时改 socks5-tls，必须用 http 时改 https",
            ))

        # 3. Shadowsocks 加密套件
        cipher = (n.opts.get("encrypt-method") or n.opts.get("method") or "").lower()
        if n.kind == "ss" or cipher:
            if cipher in BROKEN_CIPHERS:
                out.append(Finding(
                    CRITICAL, n.line, n.name,
                    f"加密套件 {cipher} 无加密或已完全破解",
                    "改用 2022-blake3-aes-256-gcm 或 chacha20-ietf-poly1305",
                ))
            elif cipher and cipher not in AEAD_CIPHERS:
                out.append(Finding(
                    HIGH, n.line, n.name,
                    f"加密套件 {cipher} 是流加密，无完整性校验（可被主动探测识别与重放）",
                    "改用 2022-blake3-aes-256-gcm（首选）或 chacha20-ietf-poly1305",
                ))
            elif not cipher and n.kind == "ss":
                out.append(Finding(
                    MEDIUM, n.line, n.name,
                    "未显式指定 encrypt-method，将回落到客户端默认值",
                    "显式写明 encrypt-method=2022-blake3-aes-256-gcm",
                ))

        # 4. VMess alterId
        alter = n.opts.get("alterid") or n.opts.get("alter-id")
        if alter and alter.strip().isdigit() and int(alter) > 0:
            out.append(Finding(
                HIGH, n.line, n.name,
                f"VMess alterId={alter}（非 AEAD 的旧 MD5 认证，已被证实可主动探测）",
                "服务端与客户端都改为 alterId=0，并确认 vmess-aead=true",
            ))
        if n.kind == "vmess" and not _is_true(n.opts.get("vmess-aead")) and not alter:
            out.append(Finding(
                LOW, n.line, n.name,
                "VMess 未显式声明 vmess-aead=true",
                "显式加上 vmess-aead=true，避免客户端回落到旧认证方式",
            ))

        # 5. VMess / SS 未套 TLS
        if n.kind == "vmess" and not _is_true(n.opts.get("tls")):
            out.append(Finding(
                HIGH, n.line, n.name,
                "VMess 未启用 TLS，裸 VMess 流量特征明显",
                "加 tls=true 并配合 ws=true + 真实域名，最好走 CDN",
            ))

        # 6. TLS 但缺 SNI
        if tls_on and not n.opts.get("sni"):
            out.append(Finding(
                MEDIUM, n.line, n.name,
                "启用了 TLS 但未指定 sni",
                "显式设置 sni=<你的真实域名>；缺失或与 host 不一致时 "
                "TLS 握手特征异常，容易被挑出来",
            ))

        # 7. 裸 IP + TLS
        if tls_on and IPV4_RE.match(n.host):
            out.append(Finding(
                MEDIUM, n.line, n.name,
                f"直接用 IP {n.host} 建立 TLS 连接（通常意味着自签或无 SNI 证书）",
                "换成指向该 IP 的真实域名 + 受信任证书；裸 IP 上的 TLS "
                "既无法通过 SNI 伪装，IP 被 ban 后也无法快速迁移",
            ))

        # 8. 端口特征
        if n.port in FINGERPRINT_PORTS:
            out.append(Finding(
                HIGH, n.line, n.name,
                f"端口 {n.port} 是 {FINGERPRINT_PORTS[n.port]}，等于自报身份",
                "改用 443（最优，混在正常 HTTPS 流量里）或 8443",
            ))
        elif tls_on and n.port and n.port not in SANE_TLS_PORTS:
            out.append(Finding(
                LOW, n.line, n.name,
                f"TLS 节点使用非常规端口 {n.port}，与真实 HTTPS 流量分布不符",
                "尽量迁到 443/8443",
            ))

        # 9. UDP 中继
        if "udp-relay" not in n.opts and n.kind in {"ss", "vmess", "trojan", "hysteria2"}:
            out.append(Finding(
                LOW, n.line, n.name,
                "未声明 udp-relay，UDP 行为取决于默认值",
                "显式写 udp-relay=true，并在 [General] 设 "
                "udp-policy-not-supported-behaviour = REJECT 防止回落直连",
            ))

        # 10. 凭据复用
        secret = n.opts.get("password") or n.opts.get("username")
        if secret and not PLACEHOLDER_RE.search(secret):
            if secret in seen_secrets and seen_secrets[secret] != n.name:
                out.append(Finding(
                    MEDIUM, n.line, n.name,
                    f"与节点 {seen_secrets[secret]} 复用同一组凭据",
                    "每个节点用独立密码/UUID，单点泄露不至于全线沦陷",
                ))
            seen_secrets.setdefault(secret, n.name)
            if len(secret) < 16:
                out.append(Finding(
                    MEDIUM, n.line, n.name,
                    f"密码长度仅 {len(secret)} 位，可被离线爆破/字典命中",
                    "改用 32 位以上随机串：openssl rand -base64 32",
                ))

    return out


def audit_general(lines: list[tuple[int, str]]) -> list[Finding]:
    out: list[Finding] = []
    kv = {}
    for lineno, line in lines:
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        kv[k.strip().lower()] = (lineno, v.strip())

    def get(key: str) -> tuple[int, str] | None:
        return kv.get(key)

    # DNS：没有加密 DNS = 解析请求明文可见、可被投毒
    if not get("doh-server") and not get("encrypted-dns-server"):
        lineno = get("dns-server")[0] if get("dns-server") else 1
        out.append(Finding(
            HIGH, lineno, "[General]",
            "未配置加密 DNS（doh-server），DIRECT 流量的解析请求以明文 53 端口发出",
            "加一行 doh-server = https://223.5.5.5/dns-query, "
            "https://1.12.12.12/dns-query",
        ))

    # IPv6 泄漏面
    ipv6 = get("ipv6")
    if ipv6 and _is_true(ipv6[1]):
        out.append(Finding(
            MEDIUM, ipv6[0], "[General]",
            "ipv6 = true，若节点或规则未覆盖 IPv6，该部分流量会绕过代理直连",
            "确认所有节点支持 IPv6 且规则含 IP6-CIDR，否则设为 false",
        ))

    # UDP 回落
    udp = get("udp-policy-not-supported-behaviour")
    if not udp:
        out.append(Finding(
            MEDIUM, 1, "[General]",
            "未设置 udp-policy-not-supported-behaviour，节点不支持 UDP 时可能静默直连",
            "设为 REJECT，避免 QUIC / 游戏 / DoQ 流量带着真实 IP 走国内出口",
        ))
    elif udp[1].strip().upper() != "REJECT":
        out.append(Finding(
            MEDIUM, udp[0], "[General]",
            f"udp-policy-not-supported-behaviour = {udp[1]}，存在回落直连风险",
            "改为 REJECT",
        ))

    # 本地监听暴露面
    for key in ("http-listen", "socks5-listen", "http-api"):
        item = get(key)
        if item and (item[1].startswith("0.0.0.0") or item[1].startswith(":")):
            out.append(Finding(
                HIGH, item[0], "[General]",
                f"{key} 绑定到 0.0.0.0，同一网络内任何人都能白嫖/嗅探你的代理",
                "改为绑定 127.0.0.1",
            ))

    # 测速 URL
    proxy_test = get("proxy-test-url")
    if proxy_test and re.search(r"baidu|qq\.com|taobao|aliyun|hicloud|vivo|xiaomi",
                                proxy_test[1], re.IGNORECASE):
        out.append(Finding(
            MEDIUM, proxy_test[0], "[General]",
            "proxy-test-url 指向国内可达地址，节点即使已被墙也会被测成「可用」",
            "改为 http://cp.cloudflare.com/generate_204 "
            "或 http://www.gstatic.com/generate_204",
        ))

    return out


def audit_rules(lines: list[tuple[int, str]]) -> list[Finding]:
    out: list[Finding] = []
    has_final = False

    for lineno, line in lines:
        upper = line.upper()
        if upper.startswith("FINAL"):
            has_final = True
            target = line.split(",")[1].strip() if "," in line else ""
            if target.upper() == "DIRECT":
                out.append(Finding(
                    HIGH, lineno, "[Rule]",
                    "FINAL,DIRECT —— 所有未命中规则的请求（含被墙站点的新域名/新 CDN）"
                    "都会带着真实 IP 明文直连",
                    "改为 FINAL,<你的代理策略组>，让兜底走代理",
                ))
        # 明文的规则集/策略订阅可被中间人替换，等于把分流规则交给对方控制
        if ("RULE-SET" in upper or "DOMAIN-SET" in upper) and "HTTP://" in upper:
            out.append(Finding(
                HIGH, lineno, "[Rule]",
                "通过明文 http:// 拉取规则集，内容可被中间人替换",
                "改用 https:// 地址",
            ))

    if not has_final:
        out.append(Finding(
            MEDIUM, 0, "[Rule]",
            "未找到 FINAL 规则，兜底行为取决于客户端默认值",
            "显式添加 FINAL,<你的代理策略组>",
        ))

    return out


def audit_misc(text: str, sections: dict[str, list[tuple[int, str]]]) -> list[Finding]:
    out: list[Finding] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("#!MANAGED-CONFIG") and "http://" in line:
            out.append(Finding(
                CRITICAL, lineno, "订阅",
                "MANAGED-CONFIG 使用明文 http://，整份配置（含全部节点凭据）"
                "在传输中可被读取和替换",
                "换成 https:// 订阅地址；若机场只提供 http，换机场",
            ))
        if re.search(r"\bpolicy-path\s*=\s*http://", line, re.IGNORECASE):
            out.append(Finding(
                HIGH, lineno, "订阅",
                "policy-path 使用明文 http://，节点列表可被中间人投毒",
                "改用 https://",
            ))

    # 策略组冗余度：只有一个节点 = 被 ban 即断网
    groups = sections.get("Proxy Group", [])
    has_auto = any(re.search(r"=\s*(url-test|fallback)", g[1], re.IGNORECASE) for g in groups)
    if groups and not has_auto:
        out.append(Finding(
            LOW, groups[0][0], "[Proxy Group]",
            "没有 url-test / fallback 策略组，节点被封时不会自动切换",
            "加一个 fallback 组做故障转移，"
            "url 用境外探测地址（http://cp.cloudflare.com/generate_204）",
        ))

    if not sections.get("Proxy"):
        out.append(Finding(
            INFO, 0, "[Proxy]",
            "未在本文件中找到节点定义（可能全部来自远程订阅）",
            "把订阅内容导出后再扫一遍，才能覆盖真正在用的节点参数",
        ))

    return out


def audit(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    sections, nodes = parse(text)
    findings: list[Finding] = []
    findings += audit_nodes(nodes)
    findings += audit_general(sections.get("General", []))
    findings += audit_rules(sections.get("Rule", []))
    findings += audit_misc(text, sections)
    findings.sort(key=lambda f: (_ORDER[f.severity], f.line))
    return findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Surfboard 配置安全审计")
    ap.add_argument("paths", nargs="+", help="要扫描的 .conf 文件")
    ap.add_argument("--strict", action="store_true", help="MEDIUM 也算失败")
    args = ap.parse_args(argv)

    worst_hit = False
    total = 0

    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.is_file():
            print(f"跳过（不是文件）：{path}", file=sys.stderr)
            continue

        findings = audit(path)
        total += len(findings)
        print(f"\n=== {path} ===")
        if not findings:
            print("  未发现问题。")
            continue

        for f in findings:
            where = f"L{f.line}" if f.line else "—"
            print(f"  [{f.severity:8}] {where:>6}  {f.node}")
            print(f"             问题：{f.issue}")
            print(f"             修法：{f.fix}")

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print("  小计：" + ", ".join(f"{k} {v}" for k, v in
                                    sorted(counts.items(), key=lambda x: _ORDER[x[0]])))

        fail_levels = {CRITICAL, HIGH} | ({MEDIUM} if args.strict else set())
        if any(f.severity in fail_levels for f in findings):
            worst_hit = True

    print(f"\n共 {total} 条发现。")
    return 1 if worst_hit else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
