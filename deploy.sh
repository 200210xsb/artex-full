#!/usr/bin/env bash
#
# ARTEX 一键部署脚本（Linux）
#
#   curl -fsSL https://raw.githubusercontent.com/200210xsb/artex-full/main/deploy.sh | sudo bash
#
# 幂等：重跑即升级，配置与数据都保留。
#   1. 检查系统、补依赖（curl unzip）
#   2. 需要时装 Docker（只用来跑 PostgreSQL，ARTEX 本体是单二进制）
#   3. 从 GitHub Releases 下对应架构的包，有 SHA256SUMS 就校验
#   4. 铺到 /opt/artex（已有的 config.json / data / skills 一律保留）
#   5. 起 PostgreSQL（复用已有容器，或新建一个、密码随机、端口冲突自动避让）
#   6. 写 systemd 服务并启动，等 /api/health 通过
#   7. 打印访问地址与后续步骤
#
# 常用参数（都可省略）：
#   --dir DIR          安装目录           默认 /opt/artex
#   --port PORT        对外端口           默认 8787（代理端口自动取 PORT+1）
#   --version VER      指定版本           默认 latest
#   --dsn DSN          用已有 PostgreSQL，不再起容器
#   --zip PATH|URL     不从 GitHub 下，用本地/内网镜像的包
#   --with-mcp         装完顺手执行 mcp/install-mcp.sh（铺 MCP 工具链）
#   --no-start         只铺文件，不注册服务、不启动
#   --uninstall        停止并卸载服务（加 --purge 连目录一起删）
#   -h, --help         看帮助
#
set -Eeuo pipefail

# ─────────────────────────── 输出 ───────────────────────────
if [ -t 1 ]; then
	C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
	C_R=; C_G=; C_Y=; C_B=; C_D=; C_0=
fi
step() { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '  %s+\033[0m %s\n' "$C_G" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
trap 'die "第 ${LINENO} 行失败：${BASH_COMMAND}"' ERR

# ─────────────────────────── 参数 ───────────────────────────
DIR=/opt/artex
PORT=8787
VERSION=latest
DSN=""
ZIP_SRC=""
SERVICE=artex
WITH_MCP=0
DO_START=1
UNINSTALL=0
PURGE=0
REPO=200210xsb/artex-full

usage() { sed -n '3,28p' "${BASH_SOURCE[0]:-deploy.sh}" 2>/dev/null | sed 's/^# \{0,1\}//' || echo "用法见 README"; }

while [ $# -gt 0 ]; do
	case "$1" in
		--dir)       DIR="${2:?}"; shift 2 ;;
		--port)      PORT="${2:?}"; shift 2 ;;
		--version)   VERSION="${2:?}"; shift 2 ;;
		--dsn)       DSN="${2:?}"; shift 2 ;;
		--zip)       ZIP_SRC="${2:?}"; shift 2 ;;
		--service)   SERVICE="${2:?}"; shift 2 ;;
		--with-mcp)  WITH_MCP=1; shift ;;
		--no-start)  DO_START=0; shift ;;
		--uninstall) UNINSTALL=1; shift ;;
		--purge)     PURGE=1; shift ;;
		-h|--help)   usage; exit 0 ;;
		*)           die "未知参数：$1（--help 看用法）" ;;
	esac
done

[ "$(id -u)" = 0 ] || die "需要 root：curl -fsSL ... | sudo bash"
[ "$(uname -s)" = Linux ] || die "本脚本只支持 Linux；macOS 请用 README 的本地编译方式"

case "$(uname -m)" in
	x86_64|amd64)  GOARCH=amd64 ;;
	aarch64|arm64) GOARCH=arm64 ;;
	*) die "不支持的架构：$(uname -m)" ;;
esac

PROXY_PORT=$((PORT + 1))
UNIT="/etc/systemd/system/${SERVICE}.service"

# ─────────────────────────── 卸载 ───────────────────────────
if [ "$UNINSTALL" = 1 ]; then
	step "卸载 ARTEX（服务名 ${SERVICE}）"
	if [ -f "$UNIT" ]; then
		systemctl disable --now "$SERVICE" 2>/dev/null || true
		rm -f "$UNIT"
		systemctl daemon-reload
		ok "已停止并移除 systemd 服务"
	fi
	if [ "$PURGE" = 1 ]; then
		docker rm -f "${SERVICE}-pg" >/dev/null 2>&1 || true
		docker volume rm "${SERVICE}-pgdata" >/dev/null 2>&1 || true
		rm -rf "$DIR"
		ok "已删除 $DIR、数据库容器 ${SERVICE}-pg 与数据卷 ${SERVICE}-pgdata"
	else
		warn "保留 $DIR 与数据库；要一起删加 --purge"
	fi
	exit 0
fi

# ─────────────────────────── 依赖 ───────────────────────────
step "检查系统依赖"
need=()
for b in curl unzip tar; do command -v "$b" >/dev/null 2>&1 || need+=("$b"); done
if [ ${#need[@]} -gt 0 ]; then
	if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq "${need[@]}" >/dev/null
	elif command -v dnf     >/dev/null 2>&1; then dnf install -y "${need[@]}" >/dev/null
	elif command -v yum     >/dev/null 2>&1; then yum install -y "${need[@]}" >/dev/null
	elif command -v apk     >/dev/null 2>&1; then apk add --no-cache "${need[@]}" >/dev/null
	else die "缺少 ${need[*]}，且不认识包管理器，请手工装一下"
	fi
	ok "已装：${need[*]}"
else
	ok "curl / unzip / tar 齐备"
fi

ensure_docker() {
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
		ok "Docker 可用"; return
	fi
	step "安装 Docker（只用于跑 PostgreSQL）"
	command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh >/dev/null
	systemctl enable --now docker >/dev/null 2>&1 || true
	docker info >/dev/null 2>&1 || die "Docker 装上了但起不来：systemctl status docker"
	ok "Docker 就绪"
}

# ─────────────────────────── 取包 ───────────────────────────
step "准备安装包"
if [ -z "$VERSION" ] || [ "$VERSION" = latest ]; then
	VERSION=$(curl -fsSL -m 20 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
		| grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)
	[ -n "${VERSION:-}" ] || die "取不到最新版本号（网络受限？改用 --version v0.4.0 --zip <本地包>）"
fi
VER_NUM=${VERSION#v}
PKG="artex-${VER_NUM}-linux-${GOARCH}.zip"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ZIP="$TMP/$PKG"

if [ -n "$ZIP_SRC" ]; then
	case "$ZIP_SRC" in
		http://*|https://*) curl -fL --progress-bar -o "$ZIP" "$ZIP_SRC" ;;
		*) [ -f "$ZIP_SRC" ] || die "找不到文件：$ZIP_SRC"; cp "$ZIP_SRC" "$ZIP" ;;
	esac
	ok "使用指定包：$ZIP_SRC"
else
	BASE="https://github.com/${REPO}/releases/download/${VERSION}"
	step "下载 ${PKG}"
	curl -fL --progress-bar -o "$ZIP" "${BASE}/${PKG}" || die "下载失败：${BASE}/${PKG}"
	if curl -fsSL -m 20 -o "$TMP/SHA256SUMS" "${BASE}/SHA256SUMS" 2>/dev/null \
		&& grep -qE "[[:space:]]${PKG}\$" "$TMP/SHA256SUMS"; then
		( cd "$TMP" && grep -E "[[:space:]]${PKG}\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
			|| die "SHA256 校验失败，包可能不完整，重试或改走 --zip"
		ok "SHA256 校验通过"
	else
		warn "取不到 SHA256SUMS，跳过校验"
	fi
fi

unzip -q -o "$ZIP" -d "$TMP/x" || die "解压失败：$ZIP"
SRC=$(find "$TMP/x" -maxdepth 3 -type f -name artex | head -1)
[ -n "$SRC" ] || die "包里没找到 artex 可执行文件"
SRC_DIR=$(dirname "$SRC")
ok "包就绪（$(du -sh "$SRC_DIR" | cut -f1)）"

# ─────────────────────────── 铺文件 ───────────────────────────
step "安装到 $DIR"
UPGRADE=0
[ -x "$DIR/artex" ] && UPGRADE=1
mkdir -p "$DIR"

if [ "$DO_START" = 1 ] && [ "$UPGRADE" = 1 ] && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
	systemctl stop "$SERVICE" || true
	ok "已停旧服务，准备换装"
fi

install -m 0755 "$SRC" "$DIR/artex"
[ -f "$SRC_DIR/start.sh" ] && install -m 0755 "$SRC_DIR/start.sh" "$DIR/start.sh"
# 只补不覆盖：升级时保留用户改过的 skills / mcp / config / data
for d in skills mcp; do
	[ -d "$SRC_DIR/$d" ] || continue
	if [ -d "$DIR/$d" ]; then cp -a "$SRC_DIR/$d/." "$DIR/$d/" 2>/dev/null || true
	else cp -a "$SRC_DIR/$d" "$DIR/"; fi
done
[ -f "$DIR/config.example.json" ] || cp -f "$SRC_DIR/config.example.json" "$DIR/" 2>/dev/null || true
mkdir -p "$DIR/data"
if [ "$UPGRADE" = 1 ]; then ok "已升级到 ${VERSION}（配置与数据保留）"; else ok "已安装 ${VERSION}"; fi

# ─────────────────────────── 数据库 ───────────────────────────
if [ -z "$DSN" ]; then
	ensure_docker
	PG_NAME="${SERVICE}-pg"
	step "准备 PostgreSQL"
	if docker inspect "$PG_NAME" >/dev/null 2>&1; then
		docker start "$PG_NAME" >/dev/null 2>&1 || true
		PG_PASS=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$PG_NAME" \
			| sed -n 's/^POSTGRES_PASSWORD=//p' | head -1)
		PG_HOSTPORT=$(docker port "$PG_NAME" 5432/tcp 2>/dev/null | head -1 | sed 's/.*://')
		[ -n "${PG_HOSTPORT:-}" ] || PG_HOSTPORT=5432
		ok "复用已有容器 $PG_NAME（127.0.0.1:${PG_HOSTPORT}）"
	else
		PG_PASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
		HOSTPORT=""
		for p in 5432 5433 5434 5435 5436 5437; do
			busy=0
			command -v ss      >/dev/null 2>&1 && ss -ltn 2>/dev/null      | grep -q ":${p} " && busy=1
			command -v netstat >/dev/null 2>&1 && netstat -ltn 2>/dev/null | grep -q ":${p} " && busy=1
			[ "$busy" = 0 ] && { HOSTPORT=$p; break; }
		done
		[ -n "$HOSTPORT" ] || die "5432-5437 都占着，请用 --dsn 指定已有数据库"
		docker run -d --name "$PG_NAME" --restart unless-stopped \
			-e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=artex \
			-p "127.0.0.1:${HOSTPORT}:5432" \
			-v "${SERVICE}-pgdata:/var/lib/postgresql/data" postgres:16-alpine >/dev/null
		PG_HOSTPORT=$HOSTPORT
		ok "已启动 $PG_NAME（127.0.0.1:${PG_HOSTPORT}，密码随机生成）"
	fi
	for i in $(seq 1 60); do
		docker exec "$PG_NAME" pg_isready -U artex -d artex >/dev/null 2>&1 && break
		[ "$i" = 60 ] && die "PostgreSQL 60 秒没起来：docker logs $PG_NAME"
		sleep 1
	done
	ok "PostgreSQL 就绪"
	DSN="postgres://artex:${PG_PASS}@127.0.0.1:${PG_HOSTPORT}/artex?sslmode=disable"
else
	ok "使用指定数据库"
fi

# ─────────────────────────── 配置 ───────────────────────────
if [ ! -f "$DIR/config.json" ]; then
	( umask 077; printf '{\n  "database": {\n    "dsn": "%s"\n  }\n}\n' "$DSN" > "$DIR/config.json" )
	ok "已写 $DIR/config.json（含密码，权限 0600）"
else
	ok "沿用已有 $DIR/config.json"
fi

# ─────────────────────────── 服务 ───────────────────────────
if [ "$DO_START" = 1 ] && ! command -v systemctl >/dev/null 2>&1; then
	# 容器 / WSL 里没有 systemd：退化成 nohup，不耽误能用
	warn "没有 systemctl，改用 nohup 后台启动（开机自启需自行配置）"
	( cd "$DIR" && nohup ./start.sh -addr ":${PORT}" -proxy ":${PROXY_PORT}" >> "$DIR/artex.log" 2>&1 & echo $! > "$DIR/artex.pid" )
	ok "已后台启动，日志 $DIR/artex.log"
fi

if [ "$DO_START" = 1 ] && command -v systemctl >/dev/null 2>&1; then
	step "注册 systemd 服务 ${SERVICE}"
	cat > "$UNIT" <<UNITEOF
[Unit]
Description=ARTEX (AI 自主渗透测试系统, ${SERVICE})
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DIR}
ExecStart=${DIR}/start.sh -addr :${PORT} -proxy :${PROXY_PORT}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNITEOF
	systemctl daemon-reload
	systemctl enable "$SERVICE" >/dev/null 2>&1 || true
	systemctl restart "$SERVICE"
	ok "服务已启动"
fi

if [ "$DO_START" = 1 ]; then
	step "等健康检查"
	OK=0
	for i in $(seq 1 60); do
		if curl -fsS -m 2 "http://127.0.0.1:${PORT}/api/health" 2>/dev/null | grep -q '"ok"'; then OK=1; break; fi
		sleep 1
	done
	if [ "$OK" = 1 ]; then
		ok "$(curl -fsS "http://127.0.0.1:${PORT}/api/health")"
	elif command -v systemctl >/dev/null 2>&1; then
		die "60 秒仍不健康：journalctl -u ${SERVICE} -n 100 --no-pager"
	else
		die "60 秒仍不健康：看 ${DIR}/artex.log"
	fi
fi

# ─────────────────────────── MCP ───────────────────────────
if [ "$WITH_MCP" = 1 ]; then
	if [ -x "$DIR/mcp/install-mcp.sh" ]; then
		step "安装 MCP 工具链（nuclei / subfinder / 模板）"
		( cd "$DIR/mcp" && ARTEX_DIR="$DIR" ./install-mcp.sh ) || warn "MCP 安装失败，稍后可手工跑 $DIR/mcp/install-mcp.sh"
	else
		warn "包里没有 mcp/install-mcp.sh，跳过"
	fi
fi

# ─────────────────────────── 收尾 ───────────────────────────
IP=$(curl -fsS -m 5 https://api.ipify.org 2>/dev/null || true)
[ -n "${IP:-}" ] || IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if command -v systemctl >/dev/null 2>&1; then
	LOGS_CMD="journalctl -u ${SERVICE} -f"
	RESTART_CMD="systemctl restart ${SERVICE}"
else
	LOGS_CMD="tail -f ${DIR}/artex.log"
	RESTART_CMD="kill \$(cat ${DIR}/artex.pid) 后重跑本脚本"
fi
cat <<EOF

$(printf '%s' "$C_G")ARTEX ${VERSION} 部署完成$(printf '%s' "$C_0")

  访问地址   http://${IP:-<本机IP>}:${PORT}
             首次打开会跳 /setup 设管理员密码
  代理端口   ${PROXY_PORT}（流量录制用，建议只在内网放行）
  安装目录   ${DIR}
  配置文件   ${DIR}/config.json（含数据库密码，0600）
  数据库     ${DSN%%\?*}
  服务名     ${SERVICE}

  看日志   ${LOGS_CMD}
  重启     ${RESTART_CMD}
  升级     重跑本脚本（配置与数据都保留）
  卸载     bash deploy.sh --uninstall [--purge]

  下一步
   1. 放行端口：ufw allow ${PORT}/tcp  或  firewall-cmd --add-port=${PORT}/tcp --permanent && firewall-cmd --reload
      （云主机还要在安全组里开 ${PORT}）
   2. 页面「系统设置」填 LLM Key（Anthropic / OpenAI 任一）。不填也能登录建任务，但探索跑不动。
   3. 要扫描/子域能力：bash deploy.sh --with-mcp

EOF
