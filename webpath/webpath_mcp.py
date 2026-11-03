#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebPath MCP —— ARTEX 站点路径枚举 MCP 服务器（纯 Python 标准库实现）

为什么需要它
------------
平台原先只有 DNS 层的子域爆破（Subfinder.bruteforce_enum 拼 <前缀>.<根域>），
**没有站点路径/目录枚举工具**。于是想摸清一个站点有哪些目录与接口的执行者只能
手写 `for` 循环 curl 去猜——这有三个真实代价：

1. 请求速率不受控。2026-11-03 的事故就是这么来的：执行者在枚举前端 JS chunk
   文件名，请求速率涨到每秒几十个，录制代理排队、内存顶到 cgroup 上限，
   **整机失联（连 sshd 都不再发 banner）**。
2. 判定粗糙。只看状态码会把「软 404」（所有路径都回 200 + 同一个页面）误判成
   处处有内容，整站报满假阳性。
3. 容易被 WAF 当成扫描器直接封禁，而且没有留下可复核的证据。

本工具把这三件事一次做对：软 404 基线判定、硬限速、请求默认走录制代理
（流量会进流量库，可以事后 bind_finding_traffic 当证据）。

核心判定
--------
先请求一个随机不存在的路径取得**基线**（状态码 / 正文长度 / 正文哈希），之后
每个候选路径与基线比对：

- 状态码不同            → 命中（status_diff）
- 状态码相同、长度差超阈值 → 命中（len_diff）—— 这就是软 404 的破绽
- 状态码长度都像、哈希不同 → 命中（hash_diff）
- 三者都一致            → 视为不存在（soft404）

403 / 401 / 500 / 3xx 单独标为「高价值」，因为它们通常意味着「资源存在但需要
别的条件」——目录存在却禁止访问、跳登录、参数触发异常，都是有价值的线索。

设计要点
--------
1. 传输：MCP stdio，自适应「行分隔 JSON」与「Content-Length」两种帧（与 ARTEX
   现有 recon/nuclei/webshell/oob MCP 一致）。stdout 只允许协议帧，日志写文件。
2. 出口：启动时探测本机 8788（录制代理）是否在监听；在监听就走它并信任其 CA，
   这样枚举到的流量会进流量库；不在监听就直连，不因代理不可用而整体失败。
3. 限速：令牌桶（rate 个/秒，默认 20）+ 并发上限（默认 8）。这是硬约束，
   不要放开——平台机器内存有限，一次全速枚举能把整机拖死。
4. 失败一律返回 isError 文本，绝不抛异常崩掉 MCP 进程。
"""

import concurrent.futures
import hashlib
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

SERVER_NAME = "webpath"
SERVER_VERSION = "1.0.0"
SUPPORTED_PROTOCOLS = ["2024-11-05", "2025-03-26"]
DEFAULT_PROTOCOL = "2024-11-05"

LOG_PATH = os.environ.get("WEBPATH_LOG") or "/opt/artex/data/webpath/webpath.log"

# 录制代理（MITM）地址与 CA。存在就走它，让流量进流量库。
CAPTURE_PROXY = os.environ.get("WEBPATH_CAPTURE_PROXY") or "http://127.0.0.1:8788"
CAPTURE_CA = (os.environ.get("WEBPATH_CA")
              or "/opt/artex/data/traffic/_ca/mitmproxy-ca-cert.pem")

# 单次调用的硬上限，防止一个请求把机器打爆。
MAX_PATHS_TOTAL = 3000
MAX_BODY_BYTES = 512 * 1024

# ---------------------------------------------------------------------------
# 内置路径字典：按「词 × 前缀」组合，不做全量爆破。
# ---------------------------------------------------------------------------

DEFAULT_WORDS = """
admin administrator manage manager panel console login signin sign-in logout register
api apis app apps v1 v2 v3 rest service services rpc graphql swagger swagger-ui
openapi doc docs documentation api-docs redoc health healthz status ping ready alive
metrics prometheus grafana actuator actuator/env actuator/health actuator/info
actuator/beans actuator/configprops actuator/mappings actuator/heapdump
config configs configuration settings env envs properties application
upload uploads file files download downloads media image images static assets
backup backups bak old dump dumps db database sql data export exports
debug trace test tests internal private secret secrets key keys token tokens
debug/vars debug/pprof pprof .env .git .svn .DS_Store wp-admin wp-login.php
phpinfo server-status server-info robots.txt sitemap.xml .well-known
proxy gateway gw upstream ws wss socket callback webhook notify
debug/console elixir phpmyadmin adminer grafana/login kibana
"""

DEFAULT_PREFIXES = (
    "/api/", "/v1/", "/v2/", "/rest/", "/service/", "/services/", "/console/",
    "/admin/", "/manage/", "/internal/", "/private/", "/debug/", "/test/", "/dev/",
    "/app/", "/open/", "/public/", "/web/", "/ws/", "/rpc/",
)

DEFAULT_EXTENSIONS = ("", ".json", ".html", ".php", ".jsp", ".asp", ".aspx")


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

class ToolError(Exception):
    """工具执行失败，消息会原样返回给 agent。"""


def log(msg):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


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


def as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def split_words(raw):
    if not raw:
        return []
    return [w.strip() for w in re.split(r"[\s,;]+", str(raw)) if w.strip()]


def title_of(body):
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    try:
        return re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:120]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 出口：优先走录制代理（流量入库），否则直连
# ---------------------------------------------------------------------------

def capture_proxy_alive(addr, timeout=1.5):
    """8788 是否在监听。"""
    try:
        host_port = addr.split("://", 1)[-1]
        host, _, port = host_port.partition(":")
        with socket.create_connection((host, int(port or 80)), timeout=timeout):
            return True
    except Exception:
        return False


def build_opener(follow_redirects=False):
    """构造 opener：有录制代理就走代理并信任其 CA，否则直连。

    默认**不跟随重定向**：301/302 本身就是线索（目录存在但跳登录、重定向到别处），
    跟随后就只剩最终页面的状态码，等于把这个信息丢了。要跟随时显式开启。
    """
    handlers = []
    used_proxy = False
    if capture_proxy_alive(CAPTURE_PROXY):
        handlers.append(urllib.request.ProxyHandler(
            {"http": CAPTURE_PROXY, "https": CAPTURE_PROXY}))
        used_proxy = True
    else:
        handlers.append(urllib.request.ProxyHandler({}))

    ctx = ssl.create_default_context()
    if os.path.isfile(CAPTURE_CA):
        try:
            ctx.load_verify_locations(CAPTURE_CA)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        except Exception:
            pass
    else:
        # 没有录制 CA 时无法验证 MITM 证书；此时若走代理只能放宽校验。
        if used_proxy:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if follow_redirects:
        handlers.append(urllib.request.HTTPRedirectHandler())
    else:
        # 不装重定向处理器：3xx 会以 HTTPError 形式冒出来，正好拿到原始状态码与 Location。
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    return opener, used_proxy


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """阻止 urllib 自动跟随 3xx——3xx 的状态码与 Location 本身就是枚举结果。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------------------
# 限速：令牌桶
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, per_second):
        self.per_second = max(0.5, float(per_second))
        self.capacity = max(1.0, self.per_second)
        self.tokens = self.capacity
        self.lock = threading.Lock()
        self.last = time.monotonic()

    def acquire(self):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity,
                                  self.tokens + (now - self.last) * self.per_second)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.per_second
            time.sleep(min(wait, 0.25))


# ---------------------------------------------------------------------------
# 单次请求
# ---------------------------------------------------------------------------

class Probe:
    __slots__ = ("code", "length", "hash", "title", "location", "error", "elapsed")

    def __init__(self):
        self.code = 0
        self.length = 0
        self.hash = ""
        self.title = ""
        self.location = ""
        self.error = ""
        self.elapsed = 0.0


def fetch(opener, url, method, headers, timeout, max_body=MAX_BODY_BYTES):
    """发一个请求，只读元数据与正文指纹，不留正文。"""
    p = Probe()
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        try:
            req.add_header(str(k), str(v))
        except Exception:
            pass
    started = time.monotonic()
    try:
        resp = opener.open(req, timeout=timeout)
        p.code = getattr(resp, "status", None) or resp.getcode()
        p.location = resp.headers.get("Location", "") or ""
        body = resp.read(max_body)
        p.length = len(body)
        p.hash = hashlib.sha256(body).hexdigest()
        p.title = title_of(body)
        resp.close()
    except urllib.error.HTTPError as e:
        p.code = e.code
        p.location = (e.headers.get("Location", "") if e.headers else "") or ""
        try:
            body = e.read(max_body)
            p.length = len(body)
            p.hash = hashlib.sha256(body).hexdigest()
            p.title = title_of(body)
        except Exception:
            pass
    except Exception as e:
        p.error = "%s: %s" % (type(e).__name__, e)
    p.elapsed = time.monotonic() - started
    return p


def len_diff_is_signal(base_len, cur_len):
    """长度差多大才算「内容不同」。

    基线长度为 0 时无法用长度判断（有些站点 404 返回空体），此时只信状态码与哈希。
    阈值取 max(24, 基线长度的 8%)：足以滤掉页脚、时间戳、随机 nonce 造成的抖动，
    又不会漏掉「同一个 404 模板但正文不同」这种真信号。
    """
    if base_len <= 0:
        return False
    delta = abs(cur_len - base_len)
    return delta >= max(24, int(base_len * 0.08))


# ---------------------------------------------------------------------------
# 候选路径生成
# ---------------------------------------------------------------------------

def build_candidates(base_url, words, prefixes, extensions, limit):
    """生成候选路径。顺序：前缀 × 词 × 后缀，保证先命中高价值组合。"""
    out = []
    seen = set()
    words = words or split_words(DEFAULT_WORDS)
    prefixes = prefixes if prefixes is not None else list(DEFAULT_PREFIXES)
    extensions = extensions if extensions is not None else list(DEFAULT_EXTENSIONS)

    def push(p):
        if p in seen:
            return
        seen.add(p)
        out.append(p)

    # 1) 前缀 × 词
    for pre in prefixes:
        pre = pre if pre.startswith("/") else "/" + pre
        for w in words:
            push(pre + w)
            if len(out) >= limit:
                return out
    # 2) 词 + 后缀（根路径下）
    for w in words:
        for ext in extensions:
            push("/" + w + ext)
            if len(out) >= limit:
                return out
    # 3) 前缀下的裸目录
    for pre in prefixes:
        push(pre.rstrip("/"))
        if len(out) >= limit:
            return out
    return out


def random_baseline_path():
    return "/__webpath_baseline_%s__" % ("%x" % random.getrandbits(48))


# ---------------------------------------------------------------------------
# 工具一：path_enum
# ---------------------------------------------------------------------------

def tool_path_enum(args):
    args = args or {}
    base_url = str(args.get("base_url") or "").strip()
    if not base_url:
        raise ToolError("缺少 base_url（如 https://open.ys7.com）")
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    words = split_words(args.get("words")) or None
    prefixes = split_words(args.get("prefixes")) if args.get("prefixes") is not None else None
    extensions = split_words(args.get("extensions")) if args.get("extensions") is not None else None

    concurrency = as_int(args.get("concurrency"), 8, 1, 32)
    rate = as_int(args.get("rate"), 20, 1, 100)
    timeout = as_int(args.get("timeout"), 10, 2, 60)
    max_paths = as_int(args.get("max_paths"), 200, 1, MAX_PATHS_TOTAL)
    method = str(args.get("method") or "GET").upper()
    if method not in ("GET", "HEAD", "POST"):
        method = "GET"
    follow = as_bool(args.get("follow_redirects"), False)
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}

    opener, used_proxy = build_opener(follow_redirects=follow)

    candidates = build_candidates(base_url, words, prefixes, extensions, max_paths)
    if not candidates:
        raise ToolError("候选路径为空：检查 words / prefixes / extensions 参数")

    limiter = RateLimiter(rate)
    started = time.monotonic()

    # --- 步骤 1：取基线（随机不存在路径）---
    base_probe = fetch(opener, base_url + random_baseline_path(), method, headers, timeout)
    if base_probe.error:
        raise ToolError("取基线失败（%s）：%s" % (base_url, base_probe.error))

    # --- 步骤 2：并发枚举（线程池大小=并发上限，别为每个路径创建一个线程）---
    results = []
    errors = 0
    lock = threading.Lock()

    def worker(path):
        nonlocal errors
        limiter.acquire()
        pr = fetch(opener, base_url + path, method, headers, timeout)
        with lock:
            if pr.error:
                errors += 1
            else:
                results.append((path, pr))

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)
    try:
        futures = [executor.submit(worker, p) for p in candidates]
        for fut in concurrent.futures.as_completed(futures, timeout=timeout + 30):
            try:
                fut.result()
            except Exception:
                with lock:
                    errors += 1
    except concurrent.futures.TimeoutError:
        with lock:
            errors += len(candidates) - len(results)
    finally:
        executor.shutdown(wait=False)

    elapsed = time.monotonic() - started

    # --- 步骤 3：与基线比对 ---
    # 判定分两类，别混为一谈：
    #   命中          —— 这个路径**很可能存在**（2xx/3xx/401/403/405/5xx，或与基线长度
    #                   明显不同 = 软 404 的破绽）
    #   差异化错误页  —— 状态码是 404，与基线不同只说明「这个前缀被后端接管了」。
    #                   路径本身多半不存在，但错误页内容常泄露技术栈/版本，单独归类，
    #                   免得把一堆 Tomcat 404 当成「发现的端点」。
    hits = []
    errpages = []
    soft404_suspect = 0
    for path, pr in results:
        reason = ""
        if pr.code != base_probe.code:
            reason = "status_diff"
        elif len_diff_is_signal(base_probe.length, pr.length):
            reason = "len_diff"
        elif pr.hash and base_probe.hash and pr.hash != base_probe.hash:
            reason = "hash_diff"
        if not reason:
            if pr.code == base_probe.code:
                soft404_suspect += 1
            continue
        item = {
            "path": path,
            "status": pr.code,
            "length": pr.length,
            "title": pr.title,
            "location": pr.location[:200],
            "reason": reason,
        }
        if pr.code == 404 and reason == "status_diff":
            item["interesting"] = False
            errpages.append(item)
            continue
        item["interesting"] = pr.code in (401, 403, 405, 500, 501, 502, 503) or (
            300 <= pr.code < 400)
        hits.append(item)

    hits.sort(key=lambda h: (not h["interesting"], h["status"], h["path"]))
    soft404_warning = ""
    if base_probe.code == 200 and results and soft404_suspect >= max(3, len(results) * 0.6):
        soft404_warning = ("该站疑似「软 404」：随机不存在路径也返回 %d，%d/%d 个候选与基线一致。"
                          "本次结果不可靠，请改用 JS 逆向拿真实接口路径。"
                          % (base_probe.code, soft404_suspect, len(results)))

    lines = []
    lines.append("目标: %s   出口: %s   候选: %d   实际请求: %d   耗时: %.1fs"
                 % (base_url, "录制代理(流量已入库)" if used_proxy else "直连",
                    len(candidates), len(results), elapsed))
    lines.append("软404 基线: 状态码=%s 长度=%s 哈希=%s"
                 % (base_probe.code, base_probe.length, (base_probe.hash or "")[:12]))
    if soft404_warning:
        lines.append("⚠️ " + soft404_warning)
    lines.append("命中 %d 条（路径很可能存在）:" % len(hits))
    for h in hits[:60]:
        tag = " ★高价值" if h["interesting"] else ""
        loc = ("  → " + h["location"]) if h["location"] else ""
        lines.append("  %s  [%s] len=%s%s%s%s 依据=%s"
                     % (h["path"], h["status"], h["length"], tag,
                        ("  " + h["title"]) if h["title"] else "", loc, h["reason"]))
    if len(hits) > 60:
        lines.append("  …另有 %d 条未列出" % (len(hits) - 60))
    if not hits:
        lines.append("  （无。可能是字典不匹配，也可能是该站所有路径都回同一个 404 模板）")

    if errpages:
        feats = {}
        for e in errpages:
            key = e["title"] or ("HTTP %d" % e["status"])
            feats.setdefault(key, []).append(e["path"])
        lines.append("")
        lines.append("差异化错误页 %d 条（路径多半不存在，但错误页本身泄露信息）：" % len(errpages))
        for feat, paths in sorted(feats.items(), key=lambda kv: -len(kv[1]))[:6]:
            lines.append("  「%s」×%d，例：%s"
                         % (feat, len(paths), ", ".join(paths[:4])))
    if errors:
        lines.append("请求失败 %d 次（超时/网络问题）" % errors)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 工具二：path_baseline
# ---------------------------------------------------------------------------

def tool_path_baseline(args):
    """只建立/查看基线，用于已知站点的软 404 判定，供人工或后续比对。"""
    args = args or {}
    base_url = str(args.get("base_url") or "").strip()
    if not base_url:
        raise ToolError("缺少 base_url")
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")
    opener, used_proxy = build_opener()
    pr = fetch(opener, base_url + random_baseline_path(), "GET", {}, 10)
    if pr.error:
        raise ToolError("取基线失败：%s" % pr.error)
    return ("%s 的软404基线：状态码=%s 长度=%s 哈希=%s 标题=%s（出口=%s）\n"
            "判定规则：与基线三者全同 = 视为不存在；长度差≥24 或哈希不同 = 真实资源。"
            % (base_url, pr.code, pr.length, (pr.hash or "")[:16], pr.title,
               "录制代理" if used_proxy else "直连"))


# ---------------------------------------------------------------------------
# 工具三：webpath_selftest
# ---------------------------------------------------------------------------

def tool_webpath_selftest(_args):
    """本地自检：起一个假的软 404 服务，验证基线判定确实能区分。"""
    import http.server
    import threading as th

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/__webpath_baseline"):
                body = b"<html><body>not found</body></html>"
                self.send_response(404)
            elif self.path == "/real":
                body = b"<html><title>Real Admin Panel</title><body>" + b"A" * 5000 + b"</body></html>"
                self.send_response(200)
            else:
                body = b"<html><body>not found</body></html>"
                self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    th.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        opener, _ = build_opener()
        base = fetch(opener, "http://127.0.0.1:%d/__webpath_baseline_x__" % port, "GET", {}, 5)
        real = fetch(opener, "http://127.0.0.1:%d/real" % port, "GET", {}, 5)
        miss = fetch(opener, "http://127.0.0.1:%d/nope" % port, "GET", {}, 5)
        ok = (base.code == 404 and real.code == 200 and miss.code == 404
              and len_diff_is_signal(base.length, real.length))
        return ("selftest %s：基线 404/len=%s，真实资源 200/len=%s，"
                "不存在路径 404/len=%s → 长度差异判定 %s"
                % ("PASS" if ok else "FAIL", base.length, real.length, miss.length,
                   "生效" if len_diff_is_signal(base.length, real.length) else "未生效"))
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# 工具表
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "path_enum",
        "description": (
            "站点路径/目录枚举（渗透测试里的「目录扫描」），**已内置软 404 判定**。"
            "先请求一个随机不存在的路径取基线（状态码+正文长度+正文哈希），再把每个"
            "候选路径与基线比对：状态码不同、或长度差超阈值、或哈希不同 → 判定为真实"
            "资源并给出依据（status_diff/len_diff/hash_diff）；三者全同 → 视为不存在。"
            "403/401/500/3xx 会单独标为★高价值（目录存在但禁止访问、跳登录、参数触发异常）。"
            "请求默认走录制代理（流量会进流量库，可事后作为漏洞证据绑定），并有硬限速"
            "（默认 20 次/秒、并发 8），不会把机器打爆。"
            "**用法**：传站点根 URL + 可选字典；不要用 curl 循环自己猜路径。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "站点根地址，如 https://open.ys7.com"},
                "words": {"type": "string", "description": "路径词字典（空格或逗号分隔）；不给用内置"},
                "prefixes": {"type": "string", "description": "路径前缀字典，如 '/api/ /v1/'；不给用内置"},
                "extensions": {"type": "string", "description": "扩展名列表，如 '.json .php'；不给用内置"},
                "concurrency": {"type": "integer", "description": "并发数，默认 8，最大 32"},
                "rate": {"type": "integer", "description": "每秒请求上限，默认 20，最大 100"},
                "timeout": {"type": "integer", "description": "单请求超时秒，默认 10"},
                "max_paths": {"type": "integer", "description": "本次最多试多少路径，默认 200，上限 3000"},
                "method": {"type": "string", "description": "HTTP 方法，默认 GET"},
                "headers": {"type": "object", "description": "附加请求头（JSON 对象）"},
            },
            "required": ["base_url"],
        },
    },
    {
        "name": "path_baseline",
        "description": ("只取某站点的软 404 基线（随机不存在路径的状态码/长度/哈希/标题），"
                        "用于人工判断该站是否所有路径都返回同一个页面。"),
        "inputSchema": {
            "type": "object",
            "properties": {"base_url": {"type": "string", "description": "站点根地址"}},
            "required": ["base_url"],
        },
    },
    {
        "name": "webpath_selftest",
        "description": "自检：起一个本地假软 404 服务，验证基线判定能区分「真资源」与「模板 404」。",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ---------------------------------------------------------------------------
# 调用分发
# ---------------------------------------------------------------------------

def call_tool(name, args):
    try:
        if name == "path_enum":
            return tool_path_enum(args), False
        if name == "path_baseline":
            return tool_path_baseline(args), False
        if name == "webpath_selftest":
            return tool_webpath_selftest(args), False
        return "未知工具: %s" % name, True
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


# ---------------------------------------------------------------------------
# 帧读写（与 ARTEX 其它 MCP 一致）
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
                return self._read_header_frame(first_header=stripped)
            self.mode = "line"
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


def main():
    reader = FramedReader(sys.stdin.buffer)
    writer = FramedWriter(sys.stdout.buffer)
    log("=== %s MCP 启动 (pid=%d) ===" % (SERVER_NAME, os.getpid()))
    while True:
        raw = reader.read_message()
        if raw is None:
            break
        writer.sync(reader.mode)
        if not raw.strip():
            continue
        try:
            msg = json.loads(raw)
        except Exception as e:
            writer.send({"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32700, "message": "parse error: %s" % e}})
            continue
        method = msg.get("method", "")
        mid = msg.get("id")
        params = msg.get("params") or {}
        try:
            result = dispatch(method, params)
            if mid is not None:
                writer.send({"jsonrpc": "2.0", "id": mid, "result": result})
        except KeyError as e:
            if mid is not None:
                writer.send({"jsonrpc": "2.0", "id": mid,
                             "error": {"code": -32601, "message": "method not found: %s" % e}})
        except Exception as e:
            log("分发异常 %s: %s: %s" % (method, type(e).__name__, e))
            if mid is not None:
                writer.send({"jsonrpc": "2.0", "id": mid,
                             "error": {"code": -32603, "message": "%s: %s" % (type(e).__name__, e)}})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        log("MCP 崩溃: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
