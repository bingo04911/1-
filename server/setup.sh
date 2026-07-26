#!/usr/bin/env bash
# ============================================================================
# 服务端一键部署：Caddy(TLS/WS 反代 + 伪装站) + sing-box(VMess 后端)
# ----------------------------------------------------------------------------
# 目标：把一台 Debian/Ubuntu VPS 配成
#   cdn.<域名>:443      → 只允许 Cloudflare 回源，源站 IP 对外不可见（保底层）
#   direct.<域名>:8443  → 直连入口，独立 UUID 和路径（冷备）
#   两个域名的根路径都是一个正常静态站，主动探测看到的是普通网站
#
# 参数由 scripts/gen_surfboard_conf.py 生成，两边严格对齐。
#
# ⚠️ 未经真机验证。脚本每一步都会打印它要做什么，防火墙那步需要你确认。
#    在生产机上跑之前，先确认你有 VPS 面板的控制台（KiwiVM 有），
#    万一 SSH 被挡住还能从面板进去救。
# ============================================================================

set -euo pipefail

CDN_DOMAIN=""; DIRECT_DOMAIN=""; UUID=""; WS_PATH=""
STANDBY_UUID=""; STANDBY_WS_PATH=""
SKIP_FIREWALL=0

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

用法：
  sudo bash server/setup.sh --cdn-domain cdn.example.com \
      --direct-domain direct.example.com \
      --uuid <UUID> --ws-path /<路径> \
      --standby-uuid <UUID> --standby-ws-path /<路径> \
      [--skip-firewall]

--skip-firewall  跳过防火墙配置（想自己用云厂商安全组时用）
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cdn-domain)       CDN_DOMAIN="$2"; shift 2 ;;
        --direct-domain)    DIRECT_DOMAIN="$2"; shift 2 ;;
        --uuid)             UUID="$2"; shift 2 ;;
        --ws-path)          WS_PATH="$2"; shift 2 ;;
        --standby-uuid)     STANDBY_UUID="$2"; shift 2 ;;
        --standby-ws-path)  STANDBY_WS_PATH="$2"; shift 2 ;;
        --skip-firewall)    SKIP_FIREWALL=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage; exit 2 ;;
    esac
done

for var in CDN_DOMAIN DIRECT_DOMAIN UUID WS_PATH STANDBY_UUID STANDBY_WS_PATH; do
    if [[ -z "${!var}" ]]; then
        echo "缺少参数：--${var,,}" | tr '_' '-' >&2
        usage; exit 2
    fi
done

[[ $EUID -eq 0 ]] || { echo "需要 root 权限，请用 sudo 运行。" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "本脚本只支持 Debian / Ubuntu。" >&2; exit 1; }

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# --- 1. 依赖 ----------------------------------------------------------------
say "安装基础依赖"
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates debian-keyring \
    debian-archive-keyring apt-transport-https ufw

# --- 2. Caddy ---------------------------------------------------------------
if ! command -v caddy >/dev/null; then
    say "安装 Caddy（负责 TLS 证书、WebSocket 反代、伪装站）"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
else
    say "Caddy 已安装，跳过"
fi

# --- 3. sing-box ------------------------------------------------------------
if ! command -v sing-box >/dev/null; then
    say "安装 sing-box（VMess 后端，只监听 127.0.0.1）"
    curl -fsSL https://sing-box.app/install.sh | sh
else
    say "sing-box 已安装，跳过"
fi

# --- 4. sing-box 配置：两个入口，各自独立凭据 -------------------------------
say "写入 sing-box 配置"
install -d -m 755 /etc/sing-box
cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "vmess",
      "tag": "cdn-in",
      "listen": "127.0.0.1",
      "listen_port": 10000,
      "users": [ { "uuid": "${UUID}", "alterId": 0 } ],
      "transport": { "type": "ws", "path": "${WS_PATH}" }
    },
    {
      "type": "vmess",
      "tag": "standby-in",
      "listen": "127.0.0.1",
      "listen_port": 10001,
      "users": [ { "uuid": "${STANDBY_UUID}", "alterId": 0 } ],
      "transport": { "type": "ws", "path": "${STANDBY_WS_PATH}" }
    }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF
chmod 600 /etc/sing-box/config.json

# --- 5. 伪装站 --------------------------------------------------------------
say "生成伪装用的静态站点"
install -d -m 755 /var/www/site
if [[ ! -f /var/www/site/index.html ]]; then
    cat > /var/www/site/index.html <<'EOF'
<!doctype html>
<meta charset="utf-8">
<title>Personal Notes</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;
padding:0 1rem;line-height:1.7;color:#333}</style>
<h1>Personal Notes</h1>
<p>A small place for reading notes and occasional writing. Nothing here yet.</p>
EOF
fi
# 换成你自己的内容更好 —— 探测者看到的应该是一个有人用的普通站点

# --- 6. Caddy 配置 ----------------------------------------------------------
say "写入 Caddyfile"
cat > /etc/caddy/Caddyfile <<EOF
# CDN 入口：Cloudflare 回源到这里
${CDN_DOMAIN} {
	handle ${WS_PATH} {
		reverse_proxy 127.0.0.1:10000
	}
	handle {
		root * /var/www/site
		file_server
	}
}

# 直连冷备入口：独立域名 + 非标准端口 + 独立凭据
${DIRECT_DOMAIN}:8443 {
	handle ${STANDBY_WS_PATH} {
		reverse_proxy 127.0.0.1:10001
	}
	handle {
		root * /var/www/site
		file_server
	}
}
EOF
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

# --- 7. 防火墙：443 只放行 Cloudflare -----------------------------------------
if [[ $SKIP_FIREWALL -eq 0 ]]; then
    SSH_PORT="$(sed -n 's/^[[:space:]]*Port[[:space:]]\+\([0-9]\+\).*/\1/p' \
        /etc/ssh/sshd_config | tail -1)"
    SSH_PORT="${SSH_PORT:-22}"

    say "配置防火墙"
    cat <<EOF
即将执行：
  - 放行 SSH 端口 ${SSH_PORT}（先做这一步，避免把自己关在门外）
  - 放行 80/443 仅来自 Cloudflare IP 段（ACME 验证 + CDN 回源）
  - 放行 8443 给所有来源（直连冷备入口）
  - 拒绝其它入站

⚠️ 如果你的 SSH 端口不是 ${SSH_PORT}，现在按 Ctrl-C 停下，
   否则启用防火墙后可能无法再登录。
EOF
    read -r -p "确认继续？输入 yes： " confirm
    [[ "$confirm" == "yes" ]] || { echo "已取消。"; exit 0; }

    ufw allow "${SSH_PORT}/tcp" >/dev/null

    CF_V4="$(curl -fsS https://www.cloudflare.com/ips-v4)"
    CF_V6="$(curl -fsS https://www.cloudflare.com/ips-v6 || true)"
    for ip in $CF_V4 $CF_V6; do
        ufw allow from "$ip" to any port 80 proto tcp  >/dev/null
        ufw allow from "$ip" to any port 443 proto tcp >/dev/null
    done
    ufw allow 8443/tcp >/dev/null

    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw --force enable
    echo "防火墙已启用。443 现在只有 Cloudflare 能访问 —— 源站扫不出来。"
else
    say "已跳过防火墙配置"
    echo "⚠️ 记得自行限制 443 只允许 Cloudflare IP 段，"
    echo "   否则全网扫 443 仍能直接摸到源站，CDN 的隐藏效果归零。"
fi

# --- 8. 启动 ----------------------------------------------------------------
say "启动服务"
systemctl enable --now sing-box
systemctl restart caddy
sleep 2
systemctl --no-pager --lines=0 status sing-box caddy || true

cat <<EOF

============================================================================
部署完成。接下来自己验证这四项：

1. 证书是否签发成功（Caddy 首次申请需要几十秒）
     journalctl -u caddy -n 30 --no-pager

2. 伪装站是否正常
     curl -sI https://${CDN_DOMAIN} | head -1        # 期望 200

3. 源站是否真的藏住了 —— 从别的机器直连你的 IP
     curl -sI --max-time 5 https://<你的源站IP>       # 期望超时/拒绝

4. Cloudflare 后台确认
     cdn.*    橙色小黄云（代理开启）
     direct.* 灰色（仅 DNS）
     SSL/TLS 模式设为 Full (strict)

然后在手机上加载生成的配置，按 surfboard/android-leaks.md 第 4 节测泄漏。
============================================================================
EOF
