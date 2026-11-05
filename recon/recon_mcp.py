#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subfinder MCP —— ARTEX 子域名收集 MCP 服务器（纯 Python 标准库实现）

设计要点
--------
1. 传输：MCP stdio。ARTEX 的 Go 客户端走「每行一个 JSON-RPC 报文」，本脚本
   首次收到报文时自动判定帧格式（行分隔 / Content-Length），并按同一格式回复，
   两种客户端都能兼容。stdout 只允许出现协议帧，日志一律写文件。
2. 工具：
   - subfinder_enum  被动枚举（chaos / quake 等被动源），主工具
   - bruteforce_enum 主动字典爆破（多线程 getaddrinfo），主工具
   - hunter_enum     Hunter（奇安信）资产测绘，积分制，pages 上限 3
   - dns_resolve     DNS 批量解析（可选辅助）
   - http_probe      HTTP 存活探测（可选辅助）
3. 健壮性：所有工具失败都返回 isError=true 的文本结果，绝不抛异常崩掉进程；
   subfinder 调用带硬超时，避免 agent 卡死。

环境注意事项
------------
ARTEX 进程环境里没有 HOME 变量，因此必须显式给 subfinder 传 -pc 指定
provider-config，并把 HOME 显式塞进子进程环境，否则读不到 chaos/fofa 的 key。
"""

import base64
import concurrent.futures
import json
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SERVER_NAME = "Subfinder"
SERVER_VERSION = "1.0.0"

# 路径解析：环境变量 > 脚本同级（Release 解压即用）> 传统安装位 /opt/artex > PATH。
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve(env_key, *candidates):
    """按优先级取路径：环境变量优先，其次第一个存在的候选，都不存在时取最后一个。"""
    value = os.environ.get(env_key)
    if value:
        return value
    for path in candidates[:-1]:
        if path and os.path.exists(path):
            return path
    return candidates[-1] if candidates else ""


SUBFINDER_BIN = _resolve(
    "ARTEX_SUBFINDER_BIN",
    os.path.join(_SCRIPT_DIR, "subfinder"),
    "/opt/artex/bin/subfinder",
    shutil.which("subfinder") or "subfinder",
)
# provider-config 里存 chaos/fofa/hunter 的 key；按调用方 HOME 找，找不到再回落 /root。
SUBFINDER_PC = _resolve(
    "ARTEX_SUBFINDER_PC",
    os.path.join(os.path.expanduser("~"), ".config", "subfinder", "provider-config.yaml"),
    "/root/.config/subfinder/provider-config.yaml",
)
WORDLIST_PATH = _resolve(
    "ARTEX_WORDLIST",
    os.path.join(_SCRIPT_DIR, "subs.txt"),
    "/opt/artex/bin/subs.txt",
)

# 兼容多种 MCP 协议版本：客户端报什么就回什么（在支持集内），否则回 2025-06-18
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
DEFAULT_PROTOCOL = "2025-06-18"

# 日志目录同样要可写：非 root 或只读 /var/log 时退到临时目录。
_STATE_DIR = "/var/log" if os.access("/var/log", os.W_OK) else tempfile.gettempdir()
LOG_PATH = os.environ.get("ARTEX_RECON_LOG") or os.path.join(_STATE_DIR, "subfinder-mcp.log")
MAX_SUBFINDER_RESULTS_DEFAULT = 2000
MAX_BRUTEFORCE_ATTEMPTS = 20000

# Hunter（奇安信）openApi —— 积分制付费接口，必须省着用
HUNTER_API = "https://hunter.qianxin.com/openApi/search"
HUNTER_PAGE_SIZES = (10, 20, 50, 100)   # Hunter 接口只接受这几种页大小
HUNTER_MAX_PAGES = 3                    # 单次调用最多查 3 页，避免烧积分
HUNTER_DEFAULT_PAGE_SIZE = 10
HUNTER_PAGE_INTERVAL = 1.0              # 页间隔（秒），降低触发 429 限流的概率

# JSON-RPC 错误码
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603

# 主机名合法性（防注入 / 过滤脏输出）
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_log_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 日志：只写文件，绝不污染 stdout（stderr 仅致命错误）
# ---------------------------------------------------------------------------

def log(msg):
    """把运行日志追加到文件；写失败也不能影响主流程。"""
    line = "%s [%d] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid(), msg)
    try:
        with _log_lock:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# stdio 帧读写：自适应「行分隔 JSON」与「Content-Length + JSON」
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


def as_bool(value, default):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ("false", "0", "no", "off", "")
    return bool(value)


def norm_domain(raw):
    """校验并规范化根域名；防止以 - 开头被 subfinder 当成 flag。"""
    d = (raw or "").strip().lower().rstrip(".")
    if not d:
        raise ToolError("缺少必填参数 domain")
    # 允许用户直接粘 URL
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    if d.startswith("-"):
        raise ToolError("domain 不能以 '-' 开头: %s" % raw)
    if not HOSTNAME_RE.match(d):
        raise ToolError("domain 不是合法域名: %s" % raw)
    return d


def to_host_list(value, field="hosts"):
    """把数组 / 换行 / 逗号分隔的字符串统一成去重列表。"""
    items = []
    if isinstance(value, str):
        items = re.split(r"[\s,;]+", value)
    elif isinstance(value, (list, tuple)):
        for v in value:
            if isinstance(v, str):
                items.extend(re.split(r"[\s,;]+", v))
    else:
        raise ToolError("参数 %s 必须是字符串数组或换行分隔的字符串" % field)
    out, seen = [], set()
    for it in items:
        h = (it or "").strip().lower().rstrip(".")
        if not h or h in seen:
            continue
        seen.add(h)
        out.append(h)
    if not out:
        raise ToolError("参数 %s 为空，没有可处理的目标" % field)
    if len(out) > 5000:
        raise ToolError("参数 %s 条数过多（%d），上限 5000" % (field, len(out)))
    return out


def subfinder_env():
    """构造 subfinder 子进程环境：显式补 HOME，避免读不到 provider-config。"""
    return {
        "HOME": os.environ.get("HOME") or os.path.expanduser("~") or "/root",
        "PATH": os.environ.get("PATH")
        or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": tempfile.gettempdir(),
    }


def brief(text, limit=600):
    """截断长文本用于错误摘要。"""
    t = (text or "").strip()
    t = ANSI_RE.sub("", t)
    if len(t) > limit:
        t = t[:limit] + "…(已截断)"
    return t


# ---------------------------------------------------------------------------
# 工具一（主）：subfinder_enum —— 被动枚举
# ---------------------------------------------------------------------------

def _run_subfinder(cmd, hard_seconds):
    """执行 subfinder，带兜底硬超时；返回 (stdout 行, stderr 文本, 是否被强杀)。

    注意：subfinder 只在枚举窗口结束时一次性写出结果（-o 也不增量落盘），
    所以 hard_seconds 必须晚于它自己的 -max-time 窗口，否则会丢掉全部结果。
    """
    out_f = tempfile.NamedTemporaryFile(prefix="sf_out_", suffix=".txt", delete=False)
    err_f = tempfile.NamedTemporaryFile(prefix="sf_err_", suffix=".txt", delete=False)
    out_path, err_path = out_f.name, err_f.name
    proc = None
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=out_f,
            stderr=err_f,
            stdin=subprocess.DEVNULL,
            env=subfinder_env(),
            cwd=tempfile.gettempdir(),
            close_fds=True,
        )
        deadline = time.time() + hard_seconds
        while True:
            if proc.poll() is not None:
                break
            if time.time() > deadline:
                timed_out = True
                log("subfinder 超出兜底硬超时 %ss，强制终止" % hard_seconds)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        pass
                break
            time.sleep(0.2)
    finally:
        try:
            out_f.close()
        except Exception:
            pass
        try:
            err_f.close()
        except Exception:
            pass
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass

    try:
        with open(out_path, "r", encoding="utf-8", errors="replace") as f:
            out_text = f.read()
    except Exception:
        out_text = ""
    try:
        with open(err_path, "r", encoding="utf-8", errors="replace") as f:
            err_text = f.read()
    except Exception:
        err_text = ""
    for p in (out_path, err_path):
        try:
            os.unlink(p)
        except Exception:
            pass
    return out_text.splitlines(), err_text, timed_out


def tool_subfinder_enum(args):
    """被动子域名枚举：包装 /opt/artex/bin/subfinder。"""
    started = time.time()
    domain = norm_domain(args.get("domain"))
    use_all = as_bool(args.get("all"), True)
    recursive = as_bool(args.get("recursive"), False)
    timeout = as_int(args.get("timeout"), 60, 5, 900)
    max_out = as_int(args.get("max"), MAX_SUBFINDER_RESULTS_DEFAULT, 1, 50000)

    if not os.path.isfile(SUBFINDER_BIN):
        raise ToolError("找不到 subfinder 可执行文件: %s" % SUBFINDER_BIN)

    # subfinder 的 -timeout 是单次请求超时，-max-time 的单位是「分钟」
    # 关键：subfinder 只在枚举窗口结束后一次性写出结果，所以
    #   1) 枚举窗口必须按分钟向上取整（30s 请求 → 实际窗口 60s）
    #   2) 兜底硬超时必须晚于该窗口，否则会丢掉全部结果
    per_req = clamp(timeout, 10, 60)
    window_minutes = max(1, int(math.ceil(timeout / 60.0)))
    window_seconds = window_minutes * 60
    hard_seconds = window_seconds + 45

    cmd = [
        SUBFINDER_BIN,
        "-d", domain,
        "-silent",            # 只输出子域名
        "-nc",                # 关闭 ANSI 颜色
        "-duc",               # 关闭自动更新检查（避免额外网络阻塞）
        "-timeout", str(per_req),
        "-max-time", str(window_minutes),
    ]
    if use_all:
        cmd.append("-all")
    if recursive:
        cmd.append("-recursive")
    if os.path.isfile(SUBFINDER_PC):
        cmd += ["-pc", SUBFINDER_PC]

    log("subfinder_enum 执行: %s (请求超时 %ss, 枚举窗口 %ss, 兜底硬超时 %ss)"
        % (" ".join(cmd), timeout, window_seconds, hard_seconds))
    lines, err_text, timed_out = _run_subfinder(cmd, hard_seconds)

    # 清洗：去 ANSI、去空行、去非法主机名、去重、排序
    seen = {}
    dropped = 0
    for raw in lines:
        s = ANSI_RE.sub("", raw).strip()
        if not s or " " in s or "\t" in s:
            continue
        s = s.lower().rstrip(".")
        if not HOSTNAME_RE.match(s):
            dropped += 1
            continue
        # 只保留与目标域同域的结果，避免个别源返回越界数据
        if s != domain and not s.endswith("." + domain):
            dropped += 1
            continue
        seen[s] = True

    hosts = sorted(seen)
    total = len(hosts)
    elapsed = time.time() - started
    shown = hosts[:max_out]

    # 一条汇总，方便 agent 直接解析列表
    summary_bits = ["共 %d 条（已去重排序）" % total]
    if total > len(shown):
        summary_bits.append("本次返回前 %d 条" % len(shown))
    summary_bits.append("耗时 %.1fs" % elapsed)
    summary_bits.append("枚举窗口 %ss" % window_seconds)
    if timed_out:
        summary_bits.append("subfinder 未在窗口内自行退出，已被强制终止，结果可能不完整")
    if dropped:
        summary_bits.append("已过滤 %d 条越界/非法条目" % dropped)
    summary = "--- 汇总: " + "，".join(summary_bits)

    if not shown:
        # 空结果按失败上报，把 stderr 摘要带出来，避免 agent 误判为「无子域名」
        err = brief(err_text) or "（subfinder 无 stderr 输出）"
        raise ToolError(
            "subfinder 未返回任何子域名。\n"
            "目标: %s\n"
            "耗时: %.1fs（枚举窗口 %ss）%s\n"
            "常见原因: provider key 缺失/失效、网络不通、源限流、域名确实无被动记录。\n"
            "stderr 摘要: %s"
            % (domain, elapsed, window_seconds,
               "，且已被强制终止" if timed_out else "",
               err)
        )

    body = "\n".join(shown)
    text = body + "\n" + summary
    log("subfinder_enum 完成: %s 共 %d 条，返回 %d 条，耗时 %.1fs%s"
        % (domain, total, len(shown), elapsed, "（超时截断）" if timed_out else ""))
    return text, False


# ---------------------------------------------------------------------------
# 工具二（主）：bruteforce_enum —— 主动字典爆破
# ---------------------------------------------------------------------------

# subs.txt 不存在时的兜底字典（常用前缀）
BUILTIN_WORDLIST = """
www mail smtp pop pop3 imap webmail mx mx1 mx2 ns ns1 ns2 ns3 dns dns1 dns2
api apis gateway gw app apps admin administrator manage manager console panel
cpanel whm dashboard portal login sso auth oauth id identity account accounts
dev develop developer development test testing tests stage staging stg uat pre
preprod prod production demo sandbox lab beta alpha rc canary edge origin
cdn static assets img image images pic pics media video videos file files fs
download downloads upload uploads ftp sftp ftps nfs backup backups bak archive
db database mysql postgres pgsql mssql oracle redis mongo mongodb es elastic
kibana grafana prometheus alertmanager zabbix nagios monitor monitoring status
log logs logger elk splunk metrics trace jaeger zipkin sentry
git gitlab github gitea bitbucket svn hg ci cd jenkins drone argo build
repo registry harbor nexus artifactory maven npm pypi docker k8s kube
rancher consul vault nomad etcd zookeeper kafka rabbitmq mq queue
wiki docs doc help support kb faq blog news forum bbs community
shop store mall pay payment payments checkout cart order orders
oa crm erp hrm hr finance billing invoice cms sso2 vpn vpn1 vpn2 remote
proxy gw1 gw2 lb lb1 lb2 ha haproxy nginx web web1 web2 web3
m mobile wap touch h5 pc client
intranet internal office corp extranet lan wan
mail1 mail2 mail3 mailgw relay spam antivirus
search solr lucene sphinx
chat im rtc meet conference zoom jitsi
map maps geo gis
report reports bi dw etl data
ssh jump bastion jumphost
ns4 ns5 dns3 dns4
mailer newsletter
ssh2 telnet
autodiscover autoconfig imap2
sso1 idp sp
style styles css js scripts
crm2
service services micro microservice
open closed
speed test2
tools tool utils
new old temp tmp
dev1 dev2 dev3 test1 test2 test3 staging1 staging2
v1 v2 v3 api1 api2 api3
a b c d e f g h i j k l m n o p q r s t u v w x y z
""".split()


def _load_wordlist(custom_path):
    """载入字典前缀；返回 (前缀列表, 来源说明)。"""
    if custom_path:
        p = os.path.expanduser(str(custom_path).strip())
        if not os.path.isfile(p):
            raise ToolError("指定的字典文件不存在: %s" % p)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read().splitlines()
        except Exception as e:
            raise ToolError("读取字典失败: %s (%s)" % (p, e))
        source = p
    elif os.path.isfile(WORDLIST_PATH):
        try:
            with open(WORDLIST_PATH, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read().splitlines()
        except Exception as e:
            raise ToolError("读取内置字典失败: %s (%s)" % (WORDLIST_PATH, e))
        source = WORDLIST_PATH
    else:
        raw = BUILTIN_WORDLIST
        source = "脚本内置兜底字典"

    prefixes, seen = [], set()
    for line in raw:
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        # 字典里只允许单段前缀，含点或空格的视为脏数据
        if not re.match(r"^[a-z0-9_][a-z0-9_-]{0,62}$", s):
            continue
        if s in seen:
            continue
        seen.add(s)
        prefixes.append(s)
    if not prefixes:
        raise ToolError("字典为空或格式不合法（每行一个子域名前缀）: %s" % source)
    return prefixes, source


def _resolve_quick(host):
    """解析单个主机名；命中返回 (host, [ip...])，未命中返回 (host, [])。"""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return host, []
    ips = []
    for fam, _, _, _, sockaddr in infos:
        if fam in (socket.AF_INET, socket.AF_INET6) and sockaddr:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    return host, ips


def tool_bruteforce_enum(args):
    """主动字典爆破：多线程 getaddrinfo 解析 <prefix>.<domain>。"""
    started = time.time()
    domain = norm_domain(args.get("domain"))
    custom = args.get("wordlist")
    concurrency = as_int(args.get("concurrency"), 50, 1, 200)
    timeout = as_int(args.get("timeout"), 120, 5, 600)

    prefixes, source = _load_wordlist(custom)
    if len(prefixes) > MAX_BRUTEFORCE_ATTEMPTS:
        raise ToolError(
            "字典条数过多（%d），单次爆破上限 %d 条，请拆分字典" % (len(prefixes), MAX_BRUTEFORCE_ATTEMPTS)
        )

    targets = ["%s.%s" % (p, domain) for p in prefixes]
    deadline = time.time() + timeout
    hits, done = {}, 0
    unfinished = 0

    log("bruteforce_enum 开始: %s 字典 %d 条（%s），并发 %d，超时 %ss"
        % (domain, len(targets), source, concurrency, timeout))

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)
    try:
        futures = {executor.submit(_resolve_quick, t): t for t in targets}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=max(0.1, deadline - time.time())):
                done += 1
                try:
                    host, ips = fut.result()
                except Exception:
                    continue
                if ips:
                    hits[host] = ips
        except concurrent.futures.TimeoutError:
            unfinished = len(futures) - done
            log("bruteforce_enum 触达总超时 %ss，已尝试 %d/%d" % (timeout, done, len(futures)))
    finally:
        # 不等待残留线程，避免超出总超时
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)

    hosts = sorted(hits)
    elapsed = time.time() - started

    summary_bits = [
        "命中 %d 个" % len(hosts),
        "尝试 %d 个" % done,
        "耗时 %.1fs" % elapsed,
    ]
    if unfinished:
        summary_bits.append("达 timeout=%ss 上限，%d 个未尝试完" % (timeout, unfinished))
    summary_bits.append("字典: %s" % source)
    summary = "--- 汇总: " + "，".join(summary_bits)

    if not hosts:
        # 0 命中不算协议错误，但要说清原因，避免被当成工具坏了
        return (
            "域名 %s 的主动爆破未命中任何子域名。\n%s" % (domain, summary),
            False,
        )

    return "\n".join(hosts) + "\n" + summary, False


# ---------------------------------------------------------------------------
# 工具三（主）：hunter_enum —— Hunter（奇安信）资产测绘
# ---------------------------------------------------------------------------

def _scrub_secret(text, secret):
    """把文本里的密钥抹掉，避免密钥随错误信息返回给 agent 或写进日志。"""
    if not text:
        return text
    t = str(text)
    if secret:
        t = t.replace(secret, "<HUNTER_KEY>")
        try:
            t = t.replace(urllib.parse.quote(secret), "<HUNTER_KEY>")
        except Exception:
            pass
    return re.sub(r"(api-key=)[^&\s\"']+", r"\1<HUNTER_KEY>", t)


def _load_hunter_key():
    """从 subfinder 的 provider-config.yaml 读取 hunter 的 key。

    只解析形如
        hunter:
          - <key>
    的片段，因此无需引入 YAML 依赖；同时避免在代码里重复存放密钥
    （密钥仍只存在于用户既有的配置文件里）。
    """
    try:
        with open(SUBFINDER_PC, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception as e:
        raise ToolError("读取 provider-config 失败: %s (%s)" % (SUBFINDER_PC, e))

    keys = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indented = line[:1] in (" ", "\t")
        if not in_block:
            if not indented and stripped.startswith("hunter:"):
                inline = stripped[len("hunter:"):].strip()
                if inline and inline != "[]":
                    # 支持行内写法 hunter: [key]
                    for part in inline.strip("[]").split(","):
                        v = part.strip().strip('"').strip("'")
                        if v:
                            keys.append(v)
                in_block = True
            continue
        # 已进入 hunter 块：缩进行属于该块，出现下一个顶层键即结束
        if not indented:
            break
        if stripped.startswith("-"):
            v = stripped[1:].strip().strip('"').strip("'")
            if v:
                keys.append(v)

    if not keys:
        raise ToolError(
            "provider-config 里没有可用的 hunter key: %s（期望格式 hunter:\\n  - <key>）"
            % SUBFINDER_PC
        )
    return keys[0]


def tool_hunter_enum(args):
    """Hunter（奇安信）资产测绘：查 domain="<域名>"，聚合去重子域名。

    积分制接口：每页查询消耗积分，因此 pages 上限锁死 3；
    返回文本的汇总行必须带 rest_quota，让 agent 和人直观看到消耗。
    """
    started = time.time()
    domain = norm_domain(args.get("domain"))

    # pages：超上限直接拒绝（不做静默夹紧，避免用户误以为查了 10 页）
    try:
        pages = int(args.get("pages")) if args.get("pages") is not None else 1
    except (TypeError, ValueError):
        raise ToolError("pages 必须是整数，收到: %r" % (args.get("pages"),))
    if pages < 1:
        raise ToolError("pages 必须 >= 1，收到: %d" % pages)
    if pages > HUNTER_MAX_PAGES:
        raise ToolError(
            "pages=%d 超过上限 %d。Hunter 每页查询都消耗积分，为省积分已限制为最多 %d 页。"
            "需要更大覆盖面请改用免费的 subfinder_enum（chaos/quake 等被动源）或 bruteforce_enum。"
            % (pages, HUNTER_MAX_PAGES, HUNTER_MAX_PAGES)
        )

    # page_size：Hunter 接口只接受 10/20/50/100
    try:
        page_size = int(args.get("page_size")) if args.get("page_size") is not None else HUNTER_DEFAULT_PAGE_SIZE
    except (TypeError, ValueError):
        raise ToolError("page_size 必须是整数，收到: %r" % (args.get("page_size"),))
    if page_size not in HUNTER_PAGE_SIZES:
        raise ToolError(
            "page_size 只允许 %s（Hunter 接口限制），收到: %d"
            % ("/".join(str(x) for x in HUNTER_PAGE_SIZES), page_size)
        )

    timeout = as_int(args.get("timeout"), 30, 5, 120)
    key = _load_hunter_key()
    deadline = time.time() + timeout

    expr = 'domain="%s"' % domain
    query_b64 = base64.b64encode(expr.encode("utf-8")).decode("ascii")
    quoted_q = urllib.parse.quote(query_b64)

    domains, assets, used_pages = {}, 0, 0
    rest_quota, err_msg = "", None

    log("hunter_enum 开始: %s pages=%d page_size=%d timeout=%ss"
        % (domain, pages, page_size, timeout))

    for page in range(1, pages + 1):
        left = deadline - time.time()
        if left <= 1.0:
            err_msg = "总超时 %ss 用尽，只查到 %d/%d 页" % (timeout, used_pages, pages)
            break

        # 不把 URL 写进日志（URL 里带 api-key）
        url = ("%s?api-key=%s&search=%s&page=%d&page_size=%d&is_web=3&is_domain=true"
               % (HUNTER_API, urllib.parse.quote(key), quoted_q, page, page_size))
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with _OPENER.open(req, timeout=min(left, 20)) as resp:
                raw = resp.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(600).decode("utf-8", "replace")
            except Exception:
                pass
            err_msg = _scrub_secret("HTTP %s: %s" % (e.code, body or e.reason), key)
            break
        except socket.timeout:
            err_msg = "请求超时（page=%d）" % page
            break
        except Exception as e:
            err_msg = _scrub_secret("%s: %s" % (type(e).__name__, e), key)
            break

        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            err_msg = "Hunter 返回非 JSON: %s" % brief(raw.decode("utf-8", "replace"), 300)
            break

        code = obj.get("code")
        if code != 200:
            # 429=限流、401=key 无效、积分不足等，一律带原文上报
            err_msg = _scrub_secret(
                "Hunter 返回 code=%s message=%s" % (code, obj.get("message")), key)
            break

        data = obj.get("data") or {}
        used_pages += 1
        assets += len(data.get("arr") or [])
        if data.get("rest_quota"):
            rest_quota = str(data.get("rest_quota"))
        for item in (data.get("arr") or []):
            d = (item.get("domain") or "").strip().lower().rstrip(".")
            if d and HOSTNAME_RE.match(d):
                domains[d] = True

        if page < pages:
            time.sleep(HUNTER_PAGE_INTERVAL)  # 页间隔，降低 429 概率

    hosts = sorted(domains)
    elapsed = time.time() - started

    # 完全失败（一条都没拿到）→ isError + 原文错误
    if err_msg and not hosts:
        raise ToolError(
            "hunter_enum 查询失败。\n目标: %s\n剩余积分: %s\n原文错误: %s"
            % (domain, rest_quota or "未知", err_msg)
        )

    summary_bits = [
        "共 %d 个子域名（已去重排序）" % len(hosts),
        "查询 %d 页 × %d 条" % (used_pages, page_size),
        "资产记录 %d 条" % assets,
        "剩余积分 %s" % (rest_quota or "未知"),
        "耗时 %.1fs" % elapsed,
    ]
    if err_msg:
        summary_bits.append("中途出错: %s" % err_msg)
    summary = "--- 汇总: " + "，".join(summary_bits)

    body = "\n".join(hosts) if hosts else "（未命中任何子域名）"
    log("hunter_enum 完成: %s 拿到 %d 个子域名，查询 %d 页，剩余积分 %s%s"
        % (domain, len(hosts), used_pages, rest_quota or "?", "（有错误）" if err_msg else ""))

    # 中途出错时把已拿到的列表一起返回，但明确标记 isError
    return body + "\n" + summary, bool(err_msg)


# ---------------------------------------------------------------------------
# 工具四（辅助）：dns_resolve
# ---------------------------------------------------------------------------

def tool_dns_resolve(args):
    """批量 DNS 解析，返回 host -> [ip,...]。"""
    started = time.time()
    hosts = to_host_list(args.get("hosts"))
    timeout = as_int(args.get("timeout"), 30, 3, 120)
    concurrency = as_int(args.get("concurrency"), 30, 1, 64)

    deadline = time.time() + timeout

    def one(h):
        """带独立异常处理的单机解析。"""
        try:
            infos = socket.getaddrinfo(h, None)
        except socket.gaierror as e:
            # -2/-3 一般是 NXDOMAIN
            if getattr(e, "errno", None) in (-2, -3, -5):
                return h, None, "NXDOMAIN"
            return h, None, "error: %s" % brief(str(e), 120)
        except Exception as e:
            return h, None, "error: %s" % brief(str(e), 120)
        ips = []
        for fam, _, _, _, sa in infos:
            if fam in (socket.AF_INET, socket.AF_INET6) and sa:
                ip = sa[0]
                if ip not in ips:
                    ips.append(ip)
        if not ips:
            return h, None, "NXDOMAIN"
        return h, ips, None

    results, resolved = {}, 0
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)
    try:
        futures = {executor.submit(one, h): h for h in hosts}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=max(0.1, deadline - time.time())):
                key, ips, err = fut.result()
                results[key] = {"ips": ips, "err": err}
                if ips:
                    resolved += 1
        except concurrent.futures.TimeoutError:
            log("dns_resolve 超时，已解析 %d/%d" % (len(results), len(hosts)))
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)

    lines = []
    for h in hosts:  # 保持输入顺序
        r = results.get(h)
        if r is None:
            lines.append("%s -> timeout" % h)
        elif r["ips"]:
            lines.append("%s -> [%s]" % (h, ", ".join(r["ips"])))
        else:
            lines.append("%s -> %s" % (h, r["err"]))

    elapsed = time.time() - started
    lines.append("--- 汇总: 解析成功 %d/%d，耗时 %.1fs" % (resolved, len(hosts), elapsed))
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具五（辅助）：http_probe
# ---------------------------------------------------------------------------

# 跳过证书错误（探测场景常见自签/过期证书）
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
_OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CTX))

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
CHARSET_HDR_RE = re.compile(r"charset\s*=\s*[\"']?([\w\-]+)", re.I)
CHARSET_META_RE = re.compile(rb"charset\s*=\s*[\"']?([\w\-]+)", re.I)
BODY_LIMIT = 65536
USER_AGENT = "Mozilla/5.0 (compatible; ARTEX-Subfinder-MCP/1.0)"


def _decode_body(raw, content_type):
    """按响应头/HTML meta 猜测编码来解码，兜底 gb18030 / latin-1。"""
    candidates = []
    if content_type:
        m = CHARSET_HDR_RE.search(content_type)
        if m:
            candidates.append(m.group(1))
    m = CHARSET_META_RE.search(raw[:4096])
    if m:
        try:
            candidates.append(m.group(1).decode("ascii", "ignore"))
        except Exception:
            pass
    candidates += ["utf-8", "gb18030", "latin-1"]
    for enc in candidates:
        if not enc:
            continue
        try:
            return raw.decode(enc, "strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _probe_one(url, deadline):
    """探测单个 URL，返回结构化字典（不抛异常）。"""
    out = {"url": url, "status": None, "title": "", "server": "", "length": None, "err": None}
    remaining = deadline - time.time()
    if remaining <= 0.5:
        out["err"] = "timeout"
        return out
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "identity",  # 不请求压缩，简化长度/标题解析
        "Connection": "close",
    })
    try:
        resp = _OPENER.open(req, timeout=min(remaining, 20))
        try:
            body = resp.read(BODY_LIMIT)
        except Exception:
            body = b""
        headers = resp.headers
        out["status"] = getattr(resp, "status", None) or resp.getcode()
        out["server"] = (headers.get("Server") or "").strip()
        out["title"] = _extract_title(body, headers.get("Content-Type"))
        cl = headers.get("Content-Length")
        if cl and cl.strip().isdigit():
            out["length"] = int(cl.strip())
        else:
            # 头部没给长度：给出已读取字节数，超过阈值标记为 >=
            out["length"] = len(body) if len(body) < BODY_LIMIT else None
            if out["length"] is None:
                out["length"] = ">=%d" % BODY_LIMIT
        try:
            resp.close()
        except Exception:
            pass
    except urllib.error.HTTPError as e:
        # 4xx/5xx 也是有效响应，继续取信息
        try:
            body = e.read(BODY_LIMIT) or b""
        except Exception:
            body = b""
        out["status"] = e.code
        out["server"] = (e.headers.get("Server") or "").strip() if e.headers else ""
        out["title"] = _extract_title(body, e.headers.get("Content-Type") if e.headers else None)
        cl = e.headers.get("Content-Length") if e.headers else None
        out["length"] = int(cl) if (cl and cl.strip().isdigit()) else len(body)
    except urllib.error.URLError as e:
        out["err"] = brief("URLError: %s" % getattr(e, "reason", e), 160)
    except socket.timeout:
        out["err"] = "timeout"
    except Exception as e:
        out["err"] = brief("%s: %s" % (type(e).__name__, e), 160)
    return out


def _extract_title(raw, content_type):
    """从 HTML 字节里抠 <title>，做实体还原与空白折叠。"""
    if not raw:
        return ""
    m = TITLE_RE.search(raw)
    if not m:
        return ""
    text = _decode_body(m.group(1), content_type)
    text = re.sub(r"\s+", " ", text).strip()
    # 常见实体还原（不引入 html 模块以外的依赖，这里直接用标准库 html）
    try:
        import html as _html
        text = _html.unescape(text)
    except Exception:
        pass
    return text[:200]


def tool_http_probe(args):
    """并发 HTTP 探测（并发上限 8，总超时默认 60s）。"""
    started = time.time()
    raw_urls = args.get("urls")
    urls = []
    if isinstance(raw_urls, str):
        urls = [u.strip() for u in re.split(r"[\s,;]+", raw_urls) if u.strip()]
    elif isinstance(raw_urls, (list, tuple)):
        for u in raw_urls:
            if isinstance(u, str) and u.strip():
                urls.append(u.strip())
    if not urls:
        raise ToolError("参数 urls 为空，需要至少一个 URL")

    # 补协议头
    fixed = []
    for u in urls:
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
            u = "http://" + u
        fixed.append(u)
    urls, seen = [], set()
    for u in fixed:
        if u not in seen:
            seen.add(u)
            urls.append(u)
    if len(urls) > 200:
        raise ToolError("urls 条数过多（%d），上限 200" % len(urls))

    timeout = as_int(args.get("timeout"), 60, 5, 300)
    concurrency = as_int(args.get("concurrency"), 8, 1, 8)  # 并发不超过 8
    deadline = time.time() + timeout

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)
    try:
        futures = [executor.submit(_probe_one, u, deadline) for u in urls]
        rows = []
        for fut in futures:
            try:
                rows.append(fut.result(timeout=max(0.1, deadline - time.time())))
            except concurrent.futures.TimeoutError:
                rows.append({"url": "?", "err": "timeout", "status": None,
                             "title": "", "server": "", "length": None})
            except Exception as e:
                rows.append({"url": "?", "err": brief(str(e), 120), "status": None,
                             "title": "", "server": "", "length": None})
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)

    lines, alive = [], 0
    for r in rows:
        if r.get("err"):
            lines.append("%s -> ERROR %s" % (r["url"], r["err"]))
            continue
        alive += 1
        title = r.get("title") or "-"
        server = r.get("server") or "-"
        length = r.get("length")
        length = "-" if length is None else str(length)
        lines.append('%s -> status=%s title="%s" server=%s content_length=%s'
                     % (r["url"], r["status"], title, server, length))

    elapsed = time.time() - started
    lines.append("--- 汇总: 存活 %d/%d，耗时 %.1fs" % (alive, len(urls), elapsed))
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具注册表（tools/list 的定义）
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "subfinder_enum",
        "description": (
            "子域名收集（subfinder，含 chaos/quake 等被动源；fofa 因缺少邮箱前缀暂不可用）。"
            "从 chaos / quake / crt.sh 等被动源枚举指定根域名的子域名。"
            "返回去重排序后的子域名列表（每行一个），并以一行「--- 汇总:」给出总数与耗时。"
            "无结果或源不可用时返回 isError 并附带 stderr 摘要。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "根域名，例如 example.com（也接受直接粘贴 URL）",
                },
                "all": {
                    "type": "boolean",
                    "default": True,
                    "description": "是否使用全部被动源（更全但更慢），默认 true",
                },
                "recursive": {
                    "type": "boolean",
                    "default": False,
                    "description": "仅使用支持递归查询的源，默认 false",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "minimum": 5,
                    "maximum": 900,
                    "description": (
                        "总耗时上限（秒），默认 60。注意 subfinder 的枚举窗口以整分钟为粒度，"
                        "实际生效窗口会向上取整（如传 30 实际跑 60s），汇总行会注明真实窗口"
                    ),
                },
                "max": {
                    "type": "integer",
                    "default": 2000,
                    "minimum": 1,
                    "maximum": 50000,
                    "description": "最多返回条数，默认 2000（汇总里会给出真实总数）",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "bruteforce_enum",
        "description": (
            "子域名收集（subfinder，主动字典爆破）。用字典对根域名做 DNS 爆破：多线程解析 <前缀>.<域名>，"
            "只返回解析到 A/AAAA 记录的主机。返回去重排序后的列表，并以一行「--- 汇总:」给出命中数、"
            "尝试数与耗时。与 subfinder_enum 互补：被动源覆盖不到的内部/边缘子域常靠爆破发现。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "根域名，例如 example.com",
                },
                "wordlist": {
                    "type": "string",
                    "description": "自定义字典文件路径（每行一个前缀）；留空则用内置常见子域名字典",
                },
                "concurrency": {
                    "type": "integer",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 200,
                    "description": "并发解析线程数，默认 50，上限 200",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "minimum": 5,
                    "maximum": 600,
                    "description": "总耗时上限（秒），默认 120",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "hunter_enum",
        "description": (
            "子域名收集（Hunter 奇安信资产测绘，消耗积分）。查询 domain=\"<域名>\" 并聚合去重 "
            "domain 字段，返回「列表 + 汇总」，汇总含剩余积分（rest_quota）。"
            "积分制付费接口：默认 1 页 10 条（约 1 积分），pages 上限 3。"
            "大范围采集请优先用免费的 subfinder_enum（chaos/quake）或 bruteforce_enum。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "根域名，例如 example.com",
                },
                "pages": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 3,
                    "description": "查询页数，默认 1，上限 3（每页消耗积分，超过 3 会被直接拒绝）",
                },
                "page_size": {
                    "type": "integer",
                    "default": 10,
                    "enum": [10, 20, 50, 100],
                    "description": "每页条数，只允许 10/20/50/100，默认 10",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "minimum": 5,
                    "maximum": 120,
                    "description": "总耗时上限（秒），默认 30",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "dns_resolve",
        "description": (
            "【辅助·可选】批量 DNS 解析，用于判断 subfinder_enum / bruteforce_enum 拿到的子域名"
            "哪些真正有解析记录。返回 host -> [ip,...]，无记录则为 NXDOMAIN/error。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": ["array", "string"],
                    "description": "主机名数组，或换行/逗号分隔的字符串",
                    "items": {"type": "string"},
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "minimum": 3,
                    "maximum": 120,
                    "description": "总耗时上限（秒），默认 30",
                },
                "concurrency": {
                    "type": "integer",
                    "default": 30,
                    "minimum": 1,
                    "maximum": 64,
                    "description": "并发解析数，默认 30",
                },
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "http_probe",
        "description": (
            "【辅助·可选】并发 HTTP/HTTPS 探测，返回每个 URL 的 status / title / server / content_length，"
            "用于快速确认哪些子域名起了 Web 服务。跳过 TLS 证书错误。并发上限 8，总超时默认 60s。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": ["array", "string"],
                    "description": "URL 数组，或换行/逗号分隔的字符串；未带协议的自动补 http://",
                    "items": {"type": "string"},
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "minimum": 5,
                    "maximum": 300,
                    "description": "总耗时上限（秒），默认 60",
                },
                "concurrency": {
                    "type": "integer",
                    "default": 8,
                    "minimum": 1,
                    "maximum": 8,
                    "description": "并发数，默认 8，上限 8",
                },
            },
            "required": ["urls"],
        },
    },
]

TOOL_HANDLERS = {
    "subfinder_enum": tool_subfinder_enum,
    "bruteforce_enum": tool_bruteforce_enum,
    "hunter_enum": tool_hunter_enum,
    "dns_resolve": tool_dns_resolve,
    "http_probe": tool_http_probe,
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
    except subprocess.TimeoutExpired as e:
        log("工具 %s 子进程超时: %s" % (name, e))
        return ("%s 执行失败: 子进程超时（%s）" % (name, e)), True
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
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        },
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
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_err,
    }


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
    log("=== %s MCP 服务器启动 (pid=%d, python=%s) ===" % (SERVER_NAME, os.getpid(), sys.version.split()[0]))

    while True:
        raw = reader.read_message()
        if raw is None:
            log("stdin 已关闭，退出")
            break
        # 帧格式判定后同步给写端
        writer.sync(reader.mode)
        if not raw.strip():
            continue

        # 解析报文
        try:
            msg = json.loads(raw)
        except Exception as e:
            log("报文 JSON 解析失败: %s | 原文: %s" % (e, brief(raw, 200)))
            writer.send({
                "jsonrpc": "2.0",
                "id": None,
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
            sys.stderr.write("recon_mcp 致命错误: %s: %s\n" % (type(e).__name__, e))
        except Exception:
            pass
        log("致命错误: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
