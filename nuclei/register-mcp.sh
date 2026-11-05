#!/usr/bin/env bash
# 把 Nuclei MCP（POC 模板库 + 漏洞验证）注册进 ARTEX 数据库，并给所有 agent 授权。
#
# 注册只是让 agent「看得见」工具。工具真正可用还需要：
#   1) nuclei 二进制与模板库在位（默认 /opt/artex/bin/nuclei + /opt/artex/nuclei-templates）
#   2) agent_visibility 里授权（下面这一步）
#   3) agent 领到下一个意图时，MCP 子进程才会 spawn 并把工具写进 mcp_tools_cache
#
#   ./register-mcp.sh                         注册 + 授权全部 agent（路径自动探测）
#   ./register-mcp.sh --bin /x/nuclei --templates /y/nuclei-templates
#   ./register-mcp.sh --mcp-path /x/nuclei_mcp.py --env ARTEX_NUCLEI_INDEX=/z
#   ./register-mcp.sh --no-grant              只注册
#   ./register-mcp.sh --dry-run               只打印将要执行的 SQL
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

MCP_PATH=""; BIN=""; TEMPLATES=""; GRANT=1; DRY=0; ENV_PAIRS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mcp-path)  MCP_PATH="$2"; shift 2 ;;
    --bin)       BIN="$2"; shift 2 ;;
    --templates) TEMPLATES="$2"; shift 2 ;;
    --env)       ENV_PAIRS+=("$2"); shift 2 ;;
    --no-grant)  GRANT=0; shift ;;
    --dry-run)   DRY=1; shift ;;
    -h|--help)   sed -n '2,16p' "$0"; exit 0 ;;
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
  if [ "$IN_CONTAINER" = "1" ]; then MCP_PATH=/app/nuclei/nuclei_mcp.py; else MCP_PATH=/opt/artex/bin/nuclei_mcp.py; fi
fi
[ -n "$BIN" ] || BIN="$(dirname "$MCP_PATH")/nuclei"
[ -n "$TEMPLATES" ] || TEMPLATES="$(cd "$(dirname "$MCP_PATH")/.." && pwd)/nuclei-templates"

sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }
build_env_sql() {
  local parts=() kv k v
  [ -n "$BIN" ] && parts+=("'ARTEX_NUCLEI_BIN', '$(sql_escape "$BIN")'")
  [ -n "$TEMPLATES" ] && parts+=("'ARTEX_NUCLEI_TEMPLATES', '$(sql_escape "$TEMPLATES")'")
  for kv in ${ENV_PAIRS[@]+"${ENV_PAIRS[@]}"}; do
    k="${kv%%=*}"; v="${kv#*=}"
    parts+=("'$(sql_escape "$k")'", "'$(sql_escape "$v")'")
  done
  if [ "${#parts[@]}" -eq 0 ]; then printf "'{}'::jsonb"; else
    local IFS=,; printf 'jsonb_build_object(%s)' "${parts[*]}"
  fi
}

# ── 2. 找一条能进数据库的路 ────────────────────────────────
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
info "nuclei 二进制：$BIN"
info "模板库      ：$TEMPLATES"
[ -f "$MCP_PATH" ] || warn "$MCP_PATH 不存在 —— 先跑 mcp/install-mcp.sh"
[ -x "$BIN" ]      || warn "$BIN 不可执行 —— Nuclei MCP 会起不来（缺 nuclei 二进制）"
[ -d "$TEMPLATES" ]|| warn "$TEMPLATES 不存在 —— poc_* 工具会报模板库缺失"

# ── 3. 注册 + 授权 ─────────────────────────────────────────
SQL=$(cat <<SQLEOF
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, insecure)
VALUES ('Nuclei', 'stdio', '/usr/bin/python3',
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
FROM agents a CROSS JOIN (SELECT id FROM mcp_servers WHERE name='Nuclei') s
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled = true;"
fi

if [ "$DRY" = "1" ]; then printf '%s\n' "$SQL"; exit 0; fi

"${PSQL_CMD[@]}" <<< "$SQL" >/dev/null
ok "已注册 Nuclei MCP"

if [ "$GRANT" = "1" ]; then
  N=$("${PSQL_CMD[@]}" -t -A -c "SELECT count(*) FROM agent_visibility av JOIN mcp_servers s ON s.id=av.resource_id WHERE s.name='Nuclei' AND av.enabled")
  ok "已授权 $N 个 agent"
fi

cat <<EOF

下一步：
  1) 让某个 agent 领一个意图（MCP 随意图 spawn），再查工具是否真的挂上：
       select tool_name from mcp_tools_cache where server_id =
         (select id from mcp_servers where name='Nuclei');
     期望 9 行：poc_stats / poc_search / poc_get / poc_run / poc_dangerous /
               poc_update / fingerprint_probe / poc_match / poc_auto_run
  2) 自检（不碰任何目标）：
       printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \\
         '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"poc_stats","arguments":{}}}' \\
         | python3 $MCP_PATH
EOF
