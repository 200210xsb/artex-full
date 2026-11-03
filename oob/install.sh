#!/usr/bin/env bash
# OOB 回连监听器安装脚本（裸机 / systemd）。
#
# 容器部署不用跑这个——docker-compose 里的 oob 服务直接挂载 oob_mcp.py 运行。
#
#   ./install.sh                      装到 /opt/artex
#   ARTEX_DIR=/data/artex ./install.sh 装到别的目录
#   OOB_UNIT=/etc/systemd/system/oob2.service ./install.sh   装成另一个服务名（多实例/试装）
#   ./install.sh --uninstall          卸掉
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

ARTEX_DIR="${ARTEX_DIR:-/opt/artex}"
BIN_DIR="$ARTEX_DIR/bin"
DATA_DIR="$ARTEX_DIR/data/oob"
CONF="$DATA_DIR/oob.conf"
# 单元路径可覆盖：试装到临时目录时不至于把线上那套服务定义冲掉
UNIT="${OOB_UNIT:-/etc/systemd/system/oob-listen.service}"
SERVICE="$(basename "$UNIT" .service)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  ok "已卸载 $SERVICE（$BIN_DIR/oob_mcp.py 和 $DATA_DIR 保留，需要的话手动删）"
  exit 0
fi

# ── 0. 前置检查 ────────────────────────────────
[ -d "$ARTEX_DIR" ] || die "找不到 $ARTEX_DIR，用 ARTEX_DIR=/your/artex ./install.sh 指定"
command -v python3 >/dev/null || die "需要 python3（监听器是纯标准库实现，3.8+ 即可）"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
  || die "Python 版本过低，需要 3.8+"
ok "python3 $(python3 -V 2>&1 | awk '{print $2}')"

mkdir -p "$BIN_DIR" "$DATA_DIR"
install -m 0755 oob_mcp.py "$BIN_DIR/oob_mcp.py"
ok "监听器 → $BIN_DIR/oob_mcp.py"

# ── 1. 生成配置 ────────────────────────────────
detect_public_ip() {
  # 云主机网卡常是 NAT 内网地址，直接读网卡会拿到 10.x，这里问外部服务要出口 IP
  for u in https://api.ipify.org https://ifconfig.me/ip https://ipinfo.io/ip; do
    ip=$(curl -s --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]')
    if printf '%s' "$ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
      printf '%s' "$ip"; return 0
    fi
  done
  return 1
}

if [ -f "$CONF" ]; then
  info "沿用已存在的 $CONF"
else
  detected="$(detect_public_ip || true)"
  echo
  echo "回连地址（目标要访问的公网 IP 或域名）。"
  echo "填错这个值，功能就是死的——页面永远收不到回连。"
  host="$(ask 'OOB_PUBLIC_HOST' "$detected")"
  [ -n "$host" ] || die "必须填一个目标可达的地址"
  ports="$(ask 'OOB_PORTS（逗号分隔）' '8889,18666,18667')"

  cat > "$CONF" <<CONF_EOF
# OOB 回连带外信道配置（由 install.sh 生成）
OOB_PUBLIC_HOST=$host
OOB_PORTS=$ports
OOB_DB=$DATA_DIR/oob.db
OOB_LOG=/var/log/oob-mcp.log
OOB_RETENTION_DAYS=7
CONF_EOF
  chmod 600 "$CONF"
  ok "配置 → $CONF"
fi

# ── 2. systemd 单元 ────────────────────────────
cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=OOB Listener (ARTEX out-of-band callback receiver)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BIN_DIR
Environment=OOB_CONF=$CONF
ExecStart=/usr/bin/python3 $BIN_DIR/oob_mcp.py --listen-only
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 2

if systemctl is-active --quiet "$SERVICE"; then
  ok "$SERVICE 已启动"
else
  journalctl -u "$SERVICE" -n 20 --no-pager || true
  die "$SERVICE 启动失败"
fi

# ── 3. 自检 ────────────────────────────────────
ports=$(grep -E '^OOB_PORTS=' "$CONF" | cut -d= -f2)
host=$(grep -E '^OOB_PUBLIC_HOST=' "$CONF" | cut -d= -f2)
echo
info "自检：本机回连一次自己"
first_port=$(echo "$ports" | cut -d, -f1)
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$first_port/" || true)
if [ "$code" = "200" ] || [ "$code" = "404" ]; then
  ok "端口 $first_port 已在监听（HTTP $code）"
else
  warn "端口 $first_port 没响应，检查：journalctl -u $SERVICE -n 30"
fi

echo
ok "安装完成"
echo "   回连地址：http://$host:$first_port/"
echo "   数据目录：$DATA_DIR"
echo "   ARTEX 需要能读到 $DATA_DIR/oob.db；容器部署用 OOB_DATA_DIR 指过去"

# ── 4. 注册 MCP ────────────────────────────────
# 只起监听器还不够：会话是 agent 用 oob_new_session 建的，MCP 不注册就没有会话，
# 所有回连都会被当成噪音丢掉，页面永远是空的。
if [ "${OOB_SKIP_REGISTER:-0}" != "1" ] && [ -x ./register-mcp.sh ]; then
  echo
  info "把 OOB MCP 注册进 ARTEX"
  ./register-mcp.sh --mcp-path "$BIN_DIR/oob_mcp.py" --db "$DATA_DIR/oob.db" \
    || warn "注册没成功，稍后可手工执行：./register-mcp.sh --mcp-path $BIN_DIR/oob_mcp.py"
else
  warn "跳过 MCP 注册 —— agent 侧不会有 oob_* 工具，页面也收不到会话"
fi
echo
echo "   在 ARTEX 里看数据：左侧「功能」→「回连监听」"
