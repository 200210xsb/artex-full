#!/usr/bin/env bash
# 把 WebShell MCP（会话管理 + 内置 payload 库）注册进 ARTEX 数据库，并给所有 agent 授权。
#
# 这个 MCP 和网页「功能 → WebShell」共用同一个会话库文件，两边必须指同一个路径：
#   裸机   /opt/artex/data/webshells.json
#   容器   /app/data/webshells.json
# 指错了页面上登记的会话 agent 看不到，反之亦然。
#
#   ./register-mcp.sh                     注册 + 授权全部 agent（路径自动探测）
#   ./register-mcp.sh --store /x/webshells.json --payload-dir /y/payloads/webshell
#   ./register-mcp.sh --dry-run | --no-grant
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

MCP_PATH=""; STORE=""; PAYLOAD_DIR=""; GRANT=1; DRY=0; ENV_PAIRS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mcp-path)    MCP_PATH="$2"; shift 2 ;;
    --store)       STORE="$2"; shift 2 ;;
    --payload-dir) PAYLOAD_DIR="$2"; shift 2 ;;
    --env)         ENV_PAIRS+=("$2"); shift 2 ;;
    --no-grant)    GRANT=0; shift ;;
    --dry-run)     DRY=1; shift ;;
    -h|--help)     sed -n '2,13p' "$0"; exit 0 ;;
    *) printf '[x] 未知参数：%s\n' "$1" >&2; exit 1 ;;
  esac
done

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

IN_CONTAINER=0
if [ -f /.dockerenv ]; then
  IN_CONTAINER=1
elif [ -x /opt/artex/artex ] || [ -d /opt/artex/bin ]; then
  IN_CONTAINER=0
elif docker compose ps --services 2>/dev/null | grep -qx artex; then
  IN_CONTAINER=1
fi

if [ -z "$MCP_PATH" ]; then
  if [ "$IN_CONTAINER" = "1" ]; then MCP_PATH=/app/webshell/webshell_mcp.py; else MCP_PATH=/opt/artex/bin/webshell_mcp.py; fi
fi
if [ -z "$STORE" ]; then
  if [ "$IN_CONTAINER" = "1" ]; then STORE=/app/data/webshells.json; else STORE=/opt/artex/data/webshells.json; fi
fi
if [ -z "$PAYLOAD_DIR" ]; then
  if [ "$IN_CONTAINER" = "1" ]; then PAYLOAD_DIR=/app/payloads/webshell; else PAYLOAD_DIR=/opt/artex/payloads/webshell; fi
fi

sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }
build_env_sql() {
  local parts=() kv k v
  parts+=("'ARTEX_WEBSHELL_STORE'" "'$(sql_escape "$STORE")'")
  parts+=("'ARTEX_WEBSHELL_PAYLOAD_DIR'" "'$(sql_escape "$PAYLOAD_DIR")'")
  for kv in ${ENV_PAIRS[@]+"${ENV_PAIRS[@]}"}; do
    k="${kv%%=*}"; v="${kv#*=}"
    parts+=("'$(sql_escape "$k")'" "'$(sql_escape "$v")'")
  done
  local IFS=,; printf 'jsonb_build_object(%s)' "${parts[*]}"
}

PSQL_MODE=""; PSQL_CMD=()
find_psql() {
  if [ -n "${ARTEX_PG_DSN:-}" ] && command -v psql >/dev/null 2>&1; then
    PSQL_MODE="dsn"; PSQL_CMD=(psql "$ARTEX_PG_DSN" -v ON_ERROR_STOP=1); return 0
  fi
  if [ -f /opt/artex/artex.env ] && command -v psql >/dev/null 2>&1; then
    local dsn
    dsn=$(grep -E '^ARTEX_PG_DSN=' /opt/artex/artex.env 2>/dev/null | cut -d= -f2- || true)
    if [ -n "$dsn" ]; then PSQL_MODE="dsn"; PSQL_CMD=(psql "$dsn" -v ON_ERROR_STOP=1); return 0; fi
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
for attempt in 1 2 3 4 5 6; do
  find_psql && break
  [ "$attempt" = "6" ] && die "找不到可用的 psql（也连不上 docker 里的 postgres）。"
  [ "$attempt" = "1" ] && info "等数据库就绪…"
  sleep 5
done

info "数据库入口  ：$PSQL_MODE"
info "MCP 脚本路径：$MCP_PATH"
info "会话库      ：$STORE"
info "payload 库  ：$PAYLOAD_DIR"
[ -f "$MCP_PATH" ] || warn "$MCP_PATH 不存在 —— 先跑 mcp/install-mcp.sh"
[ -d "$PAYLOAD_DIR" ] || warn "$PAYLOAD_DIR 不存在 —— payload_list/payload_get 会是空的"
[ -d "$(dirname "$STORE")" ] || warn "会话库目录 $(dirname "$STORE") 不存在 —— MCP 写会话会失败"

SQL=$(cat <<SQLEOF
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, insecure)
VALUES ('Webshell', 'stdio', '/usr/bin/python3',
        jsonb_build_array('$(sql_escape "$MCP_PATH")'),
        $(build_env_sql),
        true, false)
ON CONFLICT (name) DO UPDATE
  SET args = EXCLUDED.args,
      env  = EXCLUDED.env,
      command = EXCLUDED.command,
      transport = EXCLUDED.transport,
      enabled = true,
      updated_at = now();
SQLEOF
)

if [ "$GRANT" = "1" ]; then
  SQL="$SQL
INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled)
SELECT a.id, 'mcp', s.id, '', true
FROM agents a CROSS JOIN (SELECT id FROM mcp_servers WHERE name='Webshell') s
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled = true;"
fi

if [ "$DRY" = "1" ]; then printf '%s\n' "$SQL"; exit 0; fi

"${PSQL_CMD[@]}" <<< "$SQL" >/dev/null
ok "已注册 Webshell MCP"

if [ "$GRANT" = "1" ]; then
  N=$("${PSQL_CMD[@]}" -t -A -c "SELECT count(*) FROM agent_visibility av JOIN mcp_servers s ON s.id=av.resource_id WHERE s.name='Webshell' AND av.enabled")
  ok "已授权 $N 个 agent"
fi

cat <<EOF

下一步：
  1) 让某个 agent 领一个意图后查工具：
       select tool_name from mcp_tools_cache where server_id =
         (select id from mcp_servers where name='Webshell');
  2) 自检（不碰任何目标）：
       printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \\
         '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"payload_list","arguments":{}}}' \\
         | python3 $MCP_PATH
EOF
