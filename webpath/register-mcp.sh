#!/usr/bin/env bash
# 把 WebPath MCP（站点路径枚举）注册进 ARTEX 数据库，并给所有 agent 授权。
#
# 注册只是让 agent「看得见」工具；工具真正可用还需要：
#   1) 脚本在本机可执行（裸机 /opt/artex/bin/webpath_mcp.py，容器 /app/webpath/webpath_mcp.py）
#   2) agent_visibility 里授权（下面这一步）
#   3) 目标 agent 领到下一个意图时，MCP 子进程才会 spawn 并把工具写入 mcp_tools_cache
#      （验证：select tool_name from mcp_tools_cache where server_id=<id>）
#
#   ./register-mcp.sh              注册 + 授权全部 agent
#   ./register-mcp.sh --no-grant   只注册
#   ./register-mcp.sh --dry-run    只打印将要执行的 SQL
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

MCP_PATH=""
GRANT=1
DRY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mcp-path) MCP_PATH="$2"; shift 2 ;;
    --no-grant) GRANT=0; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  sed -n '2,13p' "$0"; exit 0 ;;
    *) printf '[x] 未知参数：%s\n' "$1" >&2; exit 1 ;;
  esac
done

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. 部署形态：容器里还是裸机 ────────────────────────────
# 别用「有 artex 字样的容器」判断：主库 postgres 的容器名常叫 artex-postgres-1，
# 裸机跑 ARTEX + docker 跑数据库的组合很常见，按那个判断会把路径指错。
IN_CONTAINER=0
if [ -f /.dockerenv ]; then
  IN_CONTAINER=1
elif [ -x /opt/artex/artex ] || [ -d /opt/artex/bin ]; then
  IN_CONTAINER=0
elif docker compose ps --services 2>/dev/null | grep -qx artex; then
  IN_CONTAINER=1
fi

if [ -z "$MCP_PATH" ]; then
  if [ "$IN_CONTAINER" = "1" ]; then
    MCP_PATH=/app/webpath/webpath_mcp.py
  else
    MCP_PATH=/opt/artex/bin/webpath_mcp.py
  fi
fi

# ── 2. 找一条能进数据库的路 ────────────────────────────────
# 主库是 PostgreSQL（不是 SQLite）。三种情况都遇到过：DSN 直连、本机 psql、docker 里的 pg。
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

# 刚 compose up 完时 postgres 可能还在初始化，给 30 秒窗口。
for attempt in 1 2 3 4 5 6; do
  find_psql && break
  [ "$attempt" = "6" ] && die "找不到可用的 psql（也连不上 docker 里的 postgres）。"
  [ "$attempt" = "1" ] && info "等数据库就绪…"
  sleep 5
done

info "数据库入口：$PSQL_MODE"
info "MCP 脚本路径：$MCP_PATH"
[ -f "$MCP_PATH" ] || warn "$MCP_PATH 不存在 —— 裸机部署先执行：install -m 0755 webpath/webpath_mcp.py $MCP_PATH"

# ── 3. 注册 + 授权 ─────────────────────────────────────────
SQL=$(cat <<SQLEOF
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, insecure)
VALUES ('WebPath', 'stdio', '/usr/bin/python3',
        jsonb_build_array('$MCP_PATH'),
        jsonb_build_object('WEBPATH_LOG', '$MCP_PATH.log'),
        true, false)
ON CONFLICT (name) DO UPDATE
  SET args = EXCLUDED.args,
      env  = EXCLUDED.env,
      enabled = true,
      updated_at = now();
SQLEOF
)

if [ "$GRANT" = "1" ]; then
  SQL="$SQL
INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled)
SELECT a.id, 'mcp', s.id, '', true
FROM agents a CROSS JOIN (SELECT id FROM mcp_servers WHERE name='WebPath') s
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled = true;"
fi

if [ "$DRY" = "1" ]; then
  printf '%s\n' "$SQL"
  exit 0
fi

"${PSQL_CMD[@]}" <<< "$SQL" >/dev/null
ok "已注册 WebPath MCP"

if [ "$GRANT" = "1" ]; then
  N=$("${PSQL_CMD[@]}" -t -A -c "SELECT count(*) FROM agent_visibility av JOIN mcp_servers s ON s.id=av.resource_id WHERE s.name='WebPath' AND av.enabled")
  ok "已授权 $N 个 agent"
fi

cat <<EOF

下一步：
  1) 确认脚本可执行：ls -l $MCP_PATH
  2) 让某个 agent 领一个意图（MCP 随意图 spawn），再查工具是否真的挂上：
       select tool_name from mcp_tools_cache where server_id =
         (select id from mcp_servers where name='WebPath');
     期望三行：mcp__WebPath__path_enum / path_baseline / webpath_selftest
  3) 自检（不碰任何目标）：
       printf '%s\\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \\
         '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"webpath_selftest","arguments":{}}}' \\
         | python3 $MCP_PATH
EOF
