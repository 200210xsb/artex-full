#!/usr/bin/env bash
# ARTEX 守护脚本：发现后端已经不可用就重启它。
#
# 背景：ARTEX 会给每个 agent 起一套 stdio MCP 子进程（npx/playwright/python）。
# 一旦子进程收不干净，它们会越攒越多，把 cgroup 内存打满、进程拖进 swap，
# 结果就是 /api/health 都不响应、页面只剩"无法连接到后端服务"。
# 进程组回收已经修了，这里再兜一层：真出事时不必等人发现，自己恢复。
#
# 用法：配成 systemd timer 每 2 分钟跑一次（见 docs/运维-守护与自愈.md）。
set -uo pipefail

UNIT="${ARTEX_UNIT:-artex}"
HEALTH_URL="${ARTEX_HEALTH_URL:-http://127.0.0.1:8787/api/health}"
STATE_DIR="${ARTEX_WATCHDOG_STATE:-/run/artex-watchdog}"
MAX_HEALTH_FAILS="${ARTEX_MAX_HEALTH_FAILS:-3}"   # 连续失败几次判定为死
MAX_PROCS="${ARTEX_MAX_PROCS:-120}"               # cgroup 进程数上限（正常 30 内）
MAX_MEM_RATIO="${ARTEX_MAX_MEM_RATIO:-90}"        # 内存占 MemoryMax 的百分比

mkdir -p "$STATE_DIR"
fails_file="$STATE_DIR/health_fails"
fails=$(cat "$fails_file" 2>/dev/null || echo 0)

log() { printf '[artex-watchdog] %s\n' "$*"; }

restart() {
  log "重启 $UNIT：$1"
  systemctl restart "$UNIT"
  echo 0 > "$fails_file"
  exit 0
}

# ① 健康检查：只有连续失败才算数，避免一次抖动就重启。
if curl -fsS -m 8 -o /dev/null "$HEALTH_URL" 2>/dev/null; then
  echo 0 > "$fails_file"
else
  fails=$((fails + 1))
  echo "$fails" > "$fails_file"
  log "健康检查失败（$fails/$MAX_HEALTH_FAILS）"
  [ "$fails" -ge "$MAX_HEALTH_FAILS" ] && restart "健康检查连续 $fails 次失败"
  exit 0
fi

# ② 进程数：MCP 子进程泄漏的第一征兆。
procs="?"
cg=$(systemctl show -p ControlGroup --value "$UNIT" 2>/dev/null)
if [ -n "$cg" ] && [ -r "/sys/fs/cgroup$cg/cgroup.procs" ]; then
  procs=$(wc -l < "/sys/fs/cgroup$cg/cgroup.procs")
  [ "$procs" -gt "$MAX_PROCS" ] && restart "cgroup 进程数 $procs 超过上限 $MAX_PROCS（疑似 MCP 子进程泄漏）"

  # ③ 内存：逼近 MemoryMax 就说明已经在失控边缘。
  if [ -r "/sys/fs/cgroup$cg/memory.current" ] && [ -r "/sys/fs/cgroup$cg/memory.max" ]; then
    cur=$(cat "/sys/fs/cgroup$cg/memory.current")
    max=$(cat "/sys/fs/cgroup$cg/memory.max")
    if [ "$max" != "max" ] && [ "$max" -gt 0 ]; then
      pct=$(( cur * 100 / max ))
      [ "$pct" -ge "$MAX_MEM_RATIO" ] && restart "cgroup 内存占用 ${pct}%（$((cur/1048576))MB / $((max/1048576))MB）"
    fi
  fi
fi

log "正常（procs=$procs, health=ok）"
