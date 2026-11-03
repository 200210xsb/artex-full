#!/usr/bin/env bash
# 把 OOB MCP 注册进 ARTEX 数据库，并给已有 agent 授权。
#
# 监听器跑起来只是"收得到包"。要让它真正可用还差两步：
#   1) 在 mcp_servers 里登记这个 MCP，agent 才有 oob_* 工具；
#   2) 在 agent_visibility 里给 agent 授权，工具才会出现在它的工具列表里。
# 少了任何一步，页面永远是空的 —— 因为会话是 agent 用 oob_new_session 建的，
# 没有会话，所有回连都会按"噪音"丢弃。
#
#   ./register-mcp.sh                    自动探测（容器/裸机），注册 + 授权全部 agent
#   ./register-mcp.sh --no-grant         只注册，不授权
#   ./register-mcp.sh --mcp-path /x.py --db /y/oob.db   手工指定
#   ./register-mcp.sh --dry-run          只打印将要执行的 SQL
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

MCP_PATH=""
DB_PATH=""
GRANT=1
DRY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mcp-path) MCP_PATH="$2"; shift 2 ;;
    --db)       DB_PATH="$2";  shift 2 ;;
    --no-grant) GRANT=0; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  sed -n '2,18p' "$0"; exit 0 ;;
    *) printf '[x] 未知参数：%s\n' "$1" >&2; exit 1 ;;
  esac
done

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. 判断是容器部署还是裸机，据此定默认路径 ──────────────
# 容器里 artex 的工作目录是 /app，数据在 /app/data；裸机默认 /opt/artex。
# 注意别用"有 artex 字样的容器"来判断——主库 postgres 的容器名常叫 artex-postgres-1，
# 裸机跑 ARTEX + docker 跑数据库的部署很常见，按那个判断会把路径指错。
IN_CONTAINER=0
if [ -f /.dockerenv ]; then
  IN_CONTAINER=1                                  # 自己就在容器里
elif docker compose ps --services 2>/dev/null | grep -qx artex; then
  IN_CONTAINER=1                                  # 在仓库根目录、compose 起着 artex 服务
elif [ -x /opt/artex/artex ] || [ -d /opt/artex/bin ]; then
  IN_CONTAINER=0                                  # 有裸机安装目录，优先按裸机算
elif docker ps --format '{{.Image}}' 2>/dev/null | grep -qE 'artex(:|/)'; then
  IN_CONTAINER=1
fi

if [ -z "$MCP_PATH" ]; then
  if [ "$IN_CONTAINER" = "1" ]; then
    MCP_PATH=/app/oob/oob_mcp.py
  else
    MCP_PATH=/opt/artex/bin/oob_mcp.py
  fi
fi
if [ -z "$DB_PATH" ]; then
  if [ "$IN_CONTAINER" = "1" ]; then
    DB_PATH=/app/data/oob/oob.db
  else
    DB_PATH=/opt/artex/data/oob/oob.db
  fi
fi

# ── 2. 找一条能进数据库的路 ────────────────────────────────
# 主库是 PostgreSQL（不是 SQLite），三种情况都遇到过：DSN 直连、本机 psql、docker 里的 pg。
PSQL_MODE=""
PSQL_CMD=()

find_psql() {
  if [ -n "${ARTEX_PG_DSN:-}" ] && command -v psql >/dev/null 2>&1; then
    PSQL_MODE="dsn"; PSQL_CMD=(psql "$ARTEX_PG_DSN" -v ON_ERROR_STOP=1); return 0
  fi
  if [ -f /opt/artex/artex.env ]; then
    local dsn
    dsn=$(grep -E '^ARTEX_PG_DSN=' /opt/artex/artex.env 2>/dev/null | cut -d= -f2- || true)
    if [ -n "$dsn" ] && command -v psql >/dev/null 2>&1; then
      PSQL_MODE="dsn"; PSQL_CMD=(psql "$dsn" -v ON_ERROR_STOP=1); return 0
    fi
  fi
  # docker compose 里的 postgres 服务（优先按服务名，避开项目名前缀差异）
  local c
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'postgres|pg' || true); do
    if docker exec "$c" pg_isready -U artex >/dev/null 2>&1; then
      PSQL_MODE="docker:$c"; PSQL_CMD=(docker exec -i "$c" psql -U artex -d artex -v ON_ERROR_STOP=1); return 0
    fi
  done
  if command -v psql >/dev/null 2>&1; then
    PSQL_MODE="local"; PSQL_CMD=(psql -U artex -d artex -v ON_ERROR_STOP=1); return 0
  fi
  return 1
}

# 刚 docker compose up 完时 postgres 还在初始化，容器起来了但 ready 还没到 ——
# 直接判定"找不到 psql"会让人误以为环境有问题。给 30 秒窗口。
for attempt in 1 2 3 4 5 6; do
  find_psql && break
  [ "$attempt" = 6 ] && die "找不到可用的 psql（也连不上 docker 里的 postgres）。
手工执行 oob/README.md「接入 ARTEX」那一节里的 SQL 也可以。"
  [ "$attempt" = 1 ] && info "等数据库就绪…"
  sleep 5
done

info "数据库入口：$PSQL_MODE"
info "MCP 脚本路径：$MCP_PATH"
info "命中库路径  ：$DB_PATH"
[ -f "$MCP_PATH" ] || warn "$MCP_PATH 不存在 —— 先跑 oob/install.sh，或容器部署时确认挂载了 ./oob"

# ── 3. 生成 SQL ────────────────────────────────────────────
SQL=$(cat <<SQLEOF
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, insecure)
VALUES ('OOB', 'stdio', '/usr/bin/python3',
        jsonb_build_array('$MCP_PATH'),
        jsonb_build_object('OOB_DB', '$DB_PATH'),
        true, false)
ON CONFLICT (name) DO UPDATE
  SET args = EXCLUDED.args,
      env  = EXCLUDED.env,
      command = EXCLUDED.command,
      transport = EXCLUDED.transport,
      enabled = true;
SQLEOF
)

if [ "$GRANT" = "1" ]; then
  # mcp_tool_name 用空串不用 NULL：唯一索引里有 NULL 就不去重，重跑会堆出一堆重复行。
  SQL="$SQL
INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled)
SELECT a.id, 'mcp', s.id, '', true
FROM agents a
CROSS JOIN mcp_servers s
WHERE s.name = 'OOB'
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE
  SET enabled = true;"
fi

SQL="$SQL
SELECT s.id AS server_id, s.name, s.enabled,
       (SELECT count(*) FROM agent_visibility v
         WHERE v.resource_kind = 'mcp' AND v.resource_id = s.id AND v.enabled) AS granted_agents
FROM mcp_servers s WHERE s.name = 'OOB';"

if [ "$DRY" = "1" ]; then
  echo "----- 将要执行的 SQL -----"
  printf '%s\n' "$SQL"
  exit 0
fi

printf '%s\n' "$SQL" | "${PSQL_CMD[@]}"
ok "OOB MCP 已注册"
echo "   验证：ARTEX → 智能体 → 工具列表里应出现 oob_new_session 等工具（新开会话生效）"
