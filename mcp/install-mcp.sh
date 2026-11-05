#!/usr/bin/env bash
# ARTEX MCP 工具链一键安装：把 5 个 stdio MCP（Nuclei / Subfinder / Webshell / WebPath / OOB）
# 铺到安装目录、按需下载 nuclei + nuclei-templates + subfinder，并注册进数据库。
#
# 为什么需要它：ARTEX 本体是一个单二进制（前端已内嵌），但「扫描 / 拿 shell / 子域枚举」
# 这些能力由外挂的 MCP 子进程提供。少了它们平台能开、但功能是残的。
#
#   ./install-mcp.sh                        装齐五个（已存在的跳过），装完自动注册
#   ./install-mcp.sh --only nuclei,recon    只装指定几个
#   ./install-mcp.sh --no-download          离线：只铺脚本 + 注册，扫描器自备
#   ./install-mcp.sh --no-register          只铺文件，不动数据库
#   ./install-mcp.sh --bin-dir ./bin --data-dir .      装到解压目录（免 root）
#   ./install-mcp.sh --github-base https://ghfast.top/https://github.com   国内镜像
#   ./install-mcp.sh --dry-run              只打印计划，不落盘
#
# 依赖：python3（MCP 本体）、curl 或 wget、unzip、git（拉模板库）。缺哪个只跳过对应步骤。
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"
HERE="$(pwd)"
PKG="$(dirname "$HERE")"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

BIN_DIR=""; DATA_DIR=""; ONLY=""; DOWNLOAD=1; REGISTER=1; DRY=0
GH_BASE="${ARTEX_GITHUB_BASE:-https://github.com}"
NUCLEI_VERSION="${ARTEX_NUCLEI_VERSION:-3.11.1}"
SUBFINDER_VERSION="${ARTEX_SUBFINDER_VERSION:-2.16.0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin-dir)      BIN_DIR="$2"; shift 2 ;;
    --data-dir)     DATA_DIR="$2"; shift 2 ;;
    --only)         ONLY="$2"; shift 2 ;;
    --no-download)  DOWNLOAD=0; shift ;;
    --no-register)  REGISTER=0; shift ;;
    --github-base)  GH_BASE="$2"; shift 2 ;;
    --dry-run)      DRY=1; shift ;;
    -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
    *) die "未知参数：$1" ;;
  esac
done
GH_BASE="${GH_BASE%/}"

# ── 1. 定位：工具目录（仓库内 ../<tool>，安装包内 ./<tool>）与安装位置 ─────────
find_tool_dir() {
  local t="$1"
  for cand in "$HERE/$t" "$PKG/$t"; do
    [ -d "$cand" ] && { printf '%s' "$cand"; return 0; }
  done
  return 1
}

if [ -z "$BIN_DIR" ]; then
  if [ -n "${ARTEX_BIN_DIR:-}" ]; then BIN_DIR="$ARTEX_BIN_DIR"
  elif [ -d /opt/artex/bin ]; then BIN_DIR=/opt/artex/bin
  else BIN_DIR="$PKG/bin"; fi
fi
# 数据根：/opt/artex/bin -> /opt/artex；其它情况同目录
if [ -z "$DATA_DIR" ]; then
  case "$BIN_DIR" in
    */bin) DATA_DIR="${BIN_DIR%/bin}" ;;
    *)     DATA_DIR="$BIN_DIR" ;;
  esac
fi
BIN_DIR="$BIN_DIR"; DATA_DIR="$DATA_DIR"

# 默认安装集合。webshell 的脚本随包发，但它的 payload 库（可直接落地的马）不入库，
# 需要自己把 payload 放进数据目录的 payloads/webshell/<php|jsp|aspx>/。
if [ -z "$ONLY" ]; then ONLY="nuclei,recon,webshell,webpath,oob"; fi

want() {  # 未指定 --only 时按上面的默认集合
  case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

info "安装目录：$BIN_DIR"
info "数据根  ：$DATA_DIR"
info "GitHub  ：$GH_BASE"
[ -w "$BIN_DIR" ] || [ ! -d "$BIN_DIR" ] || warn "$BIN_DIR 不可写（试试 sudo 或 --bin-dir）"

# ── 2. 铺脚本 ───────────────────────────────────────────────
install_script() {  # $1=工具目录名 $2=脚本文件名
  local dir src dst
  dir="$(find_tool_dir "$1")" || { warn "找不到 $1/ 目录，跳过"; return 1; }
  src="$dir/$2"; dst="$BIN_DIR/$2"
  [ -f "$src" ] || { warn "$src 不存在，跳过"; return 1; }
  if [ "$DRY" = "1" ]; then info "[dry-run] cp $src -> $dst"; return 0; fi
  mkdir -p "$BIN_DIR"
  install -m 0755 "$src" "$dst"
  ok "脚本  $dst"
}

install_payloads() {
  local dir
  dir="$(find_tool_dir webshell)" || return 0
  [ -d "$dir/payloads/webshell" ] || return 0
  local dst="$DATA_DIR/payloads/webshell"
  if [ "$DRY" = "1" ]; then info "[dry-run] cp -R $dir/payloads/webshell -> $dst"; return 0; fi
  mkdir -p "$(dirname "$dst")"
  cp -R "$dir/payloads/webshell/." "$dst/"
  ok "payload 库 $dst（$(ls "$dst"/*/* 2>/dev/null | wc -l) 个文件）"
}

# ── 3. 下载外部组件 ─────────────────────────────────────────
os_arch() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in darwin|linux) ;; *) die "仅支持 linux/darwin（Windows 请用 WSL）" ;; esac
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "不支持的架构：$arch" ;;
  esac
  printf '%s %s' "$os" "$arch"
}

fetch() {  # $1=url $2=输出文件
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 20 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "需要 curl 或 wget 才能下载"
  fi
}

download_pd_binary() {  # $1=项目名 $2=版本 $3=输出名
  local proj="$1" ver="$2" out="$3" os arch url tmp
  read -r os arch < <(os_arch)
  [ -x "$BIN_DIR/$out" ] && { ok "已存在 $BIN_DIR/$out，跳过下载"; return 0; }
  url="$GH_BASE/projectdiscovery/$proj/releases/download/v$ver/${proj}_${ver}_${os}_${arch}.zip"
  if [ "$DRY" = "1" ]; then info "[dry-run] 下载 $url"; return 0; fi
  command -v unzip >/dev/null 2>&1 || die "解压需要 unzip"
  tmp="$(mktemp -d)"
  info "下载 $proj v$ver …"
  fetch "$url" "$tmp/$proj.zip" || { warn "下载失败（网络？可换 --github-base 镜像）"; rm -rf "$tmp"; return 1; }
  unzip -q -o "$tmp/$proj.zip" -d "$tmp/x" || { warn "解压失败"; rm -rf "$tmp"; return 1; }
  install -m 0755 "$tmp/x/$out" "$BIN_DIR/$out"
  rm -rf "$tmp"
  ok "安装 $BIN_DIR/$out"
}

download_templates() {
  local dst="$DATA_DIR/nuclei-templates"
  [ -d "$dst" ] && { ok "已存在 $dst，跳过（更新用 Nuclei MCP 的 poc_update）"; return 0; }
  command -v git >/dev/null 2>&1 || { warn "没有 git，跳过模板库（poc_* 会不可用）"; return 0; }
  if [ "$DRY" = "1" ]; then info "[dry-run] git clone --depth 1 $GH_BASE/projectdiscovery/nuclei-templates.git $dst"; return 0; fi
  info "拉取 nuclei-templates（约 100 MB）…"
  git clone --depth 1 "$GH_BASE/projectdiscovery/nuclei-templates.git" "$dst" \
    && ok "模板库 $dst" \
    || warn "模板库拉取失败，稍后可手工 git clone 到 $dst"
}

ensure_provider_config() {
  local pc="${HOME:-/root}/.config/subfinder/provider-config.yaml"
  [ -f "$pc" ] && { ok "provider-config 已存在：$pc"; return 0; }
  if [ "$DRY" = "1" ]; then info "[dry-run] 写入 $pc"; return 0; fi
  mkdir -p "$(dirname "$pc")"
  cat > "$pc" <<'YAML'
# subfinder 被动源 key（按需填，不填只能用无 key 的源）
# ARTEX 的 hunter_enum 从这里读 hunter 的 key，格式必须保持 "hunter:" 顶格 + 缩进 "- key"
chaos: []
fofa:
  - ""
hunter:
  - ""
quake: []
YAML
  chmod 600 "$pc"
  ok "生成 $pc（把 hunter key 填进去后 hunter_enum 才可用）"
}

# ── 4. 注册 ─────────────────────────────────────────────────
register_tool() {  # $1=工具目录名 $2=脚本名 $3...=额外参数
  local dir t="$1" script="$2"; shift 2
  dir="$(find_tool_dir "$t")" || return 0
  [ -f "$dir/register-mcp.sh" ] || { warn "$t/register-mcp.sh 不存在，跳过注册"; return 0; }
  bash "$dir/register-mcp.sh" --mcp-path "$BIN_DIR/$script" "$@"
}

# ── 5. 主流程 ───────────────────────────────────────────────
if want nuclei;   then install_script nuclei   nuclei_mcp.py   || true; fi
if want recon;    then install_script recon    recon_mcp.py    || true
                       install_script recon    subs.txt        || true; fi
# webshell：脚本随包，payload 库不入库（install_payloads 找不到目录就跳过）
if want webshell; then install_script webshell webshell_mcp.py || true; install_payloads; fi
if want webpath;  then install_script webpath  webpath_mcp.py  || true; fi
if want oob;      then install_script oob      oob_mcp.py      || true; fi

if [ "$DOWNLOAD" = "1" ]; then
  if want nuclei; then
    download_pd_binary nuclei "$NUCLEI_VERSION" nuclei || true
    download_templates || true
  fi
  if want recon; then
    download_pd_binary subfinder "$SUBFINDER_VERSION" subfinder || true
    ensure_provider_config || true
  fi
fi

if [ "$REGISTER" = "1" ]; then
  if want nuclei;   then register_tool nuclei   nuclei_mcp.py \
      --bin "$BIN_DIR/nuclei" --templates "$DATA_DIR/nuclei-templates" || warn "Nuclei 注册失败"; fi
  if want recon;    then register_tool recon    recon_mcp.py \
      --bin "$BIN_DIR/subfinder" --wordlist "$BIN_DIR/subs.txt" || warn "Subfinder 注册失败"; fi
  if want webshell; then register_tool webshell webshell_mcp.py \
      --store "$DATA_DIR/data/webshells.json" --payload-dir "$DATA_DIR/payloads/webshell" \
      || warn "Webshell 注册失败（需先在仓库 webshell/ 目录就位）"; fi
  if want webpath;  then register_tool webpath  webpath_mcp.py || warn "WebPath 注册失败"; fi
  if want oob;      then warn "OOB 还需要先起监听器（见 oob/README.md 的 install.sh），这里只注册"; \
                           register_tool oob oob_mcp.py || warn "OOB 注册失败"; fi
fi

cat <<EOF

完成。验证顺序：
  1) 页面「系统 → MCP」应能看到 Nuclei / Subfinder / Webshell / WebPath / OOB 五个，
     且已启用；
  2) 让某个 agent 领一个意图后查工具是否挂上：
       select name, enabled from mcp_servers order by name;
       select s.name, count(*) from mcp_tools_cache c
         join mcp_servers s on s.id=c.server_id group by s.name;
  3) 缺 key 的只是对应工具：hunter_enum 要 provider-config 里的 hunter key，
     fofa/quake/chaos 同理；subfinder_enum / bruteforce_enum 无 key 可用。
EOF
