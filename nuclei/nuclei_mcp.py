#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuclei MCP —— ARTEX 的 Nuclei POC 模板库管理 + 漏洞验证 MCP 服务器（纯 Python 标准库）

设计要点
--------
1. 传输：MCP stdio。ARTEX 的 Go 客户端走「每行一个 JSON-RPC 报文」，本脚本首次
   收到报文时自动判定帧格式（行分隔 / Content-Length），并按同一格式回复。
   stdout 只允许出现协议帧，日志一律写文件。
2. 工具（9 个）：
   - poc_stats     模板库概况（总数 / severity 分布 / tag TOP20 / 最后更新）
   - poc_search    按 keyword / tags / severity 过滤，列出模板
   - poc_get       取单个模板 YAML 全文 + 解析出的 info
   - poc_run       对目标跑模板，解析 JSONL 返回命中与汇总
   - poc_dangerous 只列「可能拿到 RCE / 命令执行 / 文件上传」的高价值模板并给拿 shell 建议
   - poc_update    拉取模板库更新，返回更新前后模板数与新提交数
   - fingerprint_probe 探测目标指纹（tech 模板；无命中时用 HTTP 头/标题粗判）
   - poc_match     按指纹反查候选 POC（只留 critical/high/medium 且可落地的）
   - poc_auto_run  一站式：探测指纹 → 匹配 POC → 实弹验证（命中结果标注可落马）
3. 与 Webshell MCP 联动：poc_run / poc_dangerous / poc_get / poc_search 的描述与结果
   末尾都会提示「打点 → 拿 shell → 管 shell」闭环，即命中后接着用 Webshell MCP 的
   payload_list / payload_get 取马、shell_add 登记、shell_exec 执行。
4. 不做模板 YAML 的第三方依赖解析：只用标准库做行级解析，索引落盘缓存，
   避免每次调用都全量扫 1 万+ 文件。

环境注意事项
------------
- ARTEX 进程环境里没有 HOME，nuclei 需要它来找配置/缓存目录，因此子进程显式塞 HOME。
- nuclei 首次加载模板要编译，比较慢；poc_run 带硬超时兜底，绝不把 agent 卡死。
"""

import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SERVER_NAME = "Nuclei"
SERVER_VERSION = "1.0.0"

# 路径解析：环境变量 > 脚本同级（Release 解压即用）> 传统安装位 /opt/artex > PATH。
# 同一份脚本要能在裸机 /opt/artex/bin、容器 /app、以及任意解压目录里都跑起来。
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


NUCLEI_BIN = _resolve(
    "ARTEX_NUCLEI_BIN",
    os.path.join(_SCRIPT_DIR, "nuclei"),
    "/opt/artex/bin/nuclei",
    shutil.which("nuclei") or "nuclei",
)
TEMPLATES_DIR = _resolve(
    "ARTEX_NUCLEI_TEMPLATES",
    os.path.join(_SCRIPT_DIR, "nuclei-templates"),
    os.path.join(os.path.dirname(_SCRIPT_DIR), "nuclei-templates"),
    "/opt/artex/nuclei-templates",
)
# 索引与日志必须落在可写目录：/var/cache 与 /var/log 在非 root 或只读挂载下写不进去。
_STATE_DIR = "/var/cache" if os.access("/var/cache", os.W_OK) else tempfile.gettempdir()
_LOG_DIR = "/var/log" if os.access("/var/log", os.W_OK) else _STATE_DIR
INDEX_DIR = os.environ.get("ARTEX_NUCLEI_INDEX") or os.path.join(_STATE_DIR, "nuclei-mcp")
INDEX_PATH = os.path.join(INDEX_DIR, "template_index.json")
LOG_PATH = os.environ.get("ARTEX_NUCLEI_LOG") or os.path.join(_LOG_DIR, "nuclei-mcp.log")

# 兼容多种 MCP 协议版本：客户端报什么就回什么（在支持集内），否则回 2025-06-18
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
DEFAULT_PROTOCOL = "2025-06-18"

# JSON-RPC 错误码
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603

# 索引缓存版本：解析逻辑变更时改它，强制重建
INDEX_VERSION = 3

# 模板 id 合法性（防止把奇怪的东西当 id 拼进命令行）
TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

MAX_SEARCH_LIMIT = 500
MAX_HITS_RETURN = 200

# poc_dangerous：tag -> 拿 shell 危险度分值（越高越可能直接落地）
DANGER_TAGS = {
    "rce": 100,
    "remote-code-execution": 100,
    "command-injection": 96,
    "os-command-injection": 96,
    "code-injection": 92,
    "file-upload": 88,
    "arbitrary-file-upload": 88,
    "unrestricted-file-upload": 88,
    "file-write": 84,
    "arbitrary-file-write": 84,
    "deserialization": 72,
    "deserialize": 72,
    "insecure-deserialization": 72,
    "rfi": 62,
    "ssti": 60,
    "sqli": 48,
    "sql-injection": 48,
    "lfi": 42,
}

# poc_dangerous：描述关键词兜底（有些模板 tag 不规范，只能看描述）
DANGER_DESC_WORDS = (
    ("remote code execution", 100),
    ("arbitrary command execution", 96),
    ("command injection", 96),
    ("os command", 94),
    ("code execution", 90),
    ("file upload", 86),
    ("arbitrary file write", 84),
    ("write file", 80),
    ("deserialization", 72),
    ("outfile", 55),
    ("sql injection", 46),
)

# 按分值分档，给出「拿 shell 概率」与使用建议
DANGER_TIERS = (
    (90, "A", "直接命令执行/代码执行 —— 命中即等于拿到了命令通道",
     "用 poc_get 看完整请求，把命令参数改成你要的命令直接复现；"
     "要稳定持久化就接着 Webshell MCP：payload_list 挑马 → payload_get 取全文 → "
     "用同一处注入点写文件 → shell_add 登记"),
    (80, "B", "文件上传/任意文件写 —— 命中即等于能落地文件",
     "确认上传目录能否解析脚本、有没有重命名/白名单；能解析就 payload_get 取对应类型"
     "（php/jsp/aspx）的马子直接传，然后 shell_add 登记"),
    (60, "C", "反序列化 / SSTI / RFI —— 可执行代码但需要构造 payload",
     "先用模板自带 payload 确认可利用，再按目标中间件版本换 gadget 链；"
     "SSTI 可直接用模板的表达式执行命令，成功后落马并用 shell_add 登记"),
    (45, "D", "SQL 注入 —— 只有满足条件才能转成文件写入",
     "重点看能否写文件：需要 FILE 权限 / secure_file_priv 可写 / 堆叠查询；"
     "能用 outfile 或日志写马时再 payload_get，否则只当信息泄露"),
    (0, "E", "文件读取 / 其他 —— 一般拿不到 shell",
     "当辅助信息（读配置、读密钥、找内网）用，别指望直接拿 shell"),
)

_log_lock = threading.Lock()
_index_lock = threading.Lock()
_INDEX = None


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


def opt_str(args, key, default=""):
    v = args.get(key)
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip()
    return str(v).strip()


def brief(text, limit=600):
    """截断长文本用于错误摘要。"""
    t = ANSI_RE.sub("", (text or "").strip())
    if len(t) > limit:
        t = t[:limit] + "…(已截断)"
    return t


def split_csv(value):
    """把 "a,b" / ["a","b"] 统一成去重小写列表。"""
    items = []
    if isinstance(value, str):
        items = re.split(r"[,\s;]+", value)
    elif isinstance(value, (list, tuple)):
        for v in value:
            if isinstance(v, str):
                items.extend(re.split(r"[,\s;]+", v))
    out, seen = [], set()
    for it in items:
        s = (it or "").strip().strip(",").lower()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def nuclei_env():
    """构造 nuclei 子进程环境：显式补 HOME，避免找不到配置/缓存目录。"""
    # 沿用调用方的 HOME/PATH：容器里 HOME 常是 /home/非root，写死 /root 会让
    # nuclei 把配置与缓存写到不存在的目录。
    return {
        "HOME": os.environ.get("HOME") or os.path.expanduser("~") or "/root",
        "PATH": os.environ.get("PATH")
        or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": tempfile.gettempdir(),
    }


def normalize_target(raw):
    """校验 target：URL 或 host，禁止以 '-' 开头（避免被当成 flag）。"""
    t = (raw or "").strip()
    if not t:
        raise ToolError("缺少必填参数 target（URL 或 host，例如 https://example.com）")
    if t.startswith("-"):
        raise ToolError("target 不能以 '-' 开头: %s" % t)
    if len(t) > 2048:
        raise ToolError("target 过长（%d 字符）" % len(t))
    if any(c in t for c in "\r\n\t "):
        raise ToolError("target 不能包含空白/换行: %s" % raw)
    return t


# ---------------------------------------------------------------------------
# 模板 YAML 的轻量解析（纯标准库，不用 PyYAML）
# ---------------------------------------------------------------------------

BLOCK_SCALAR_RE = re.compile(r"^[|>][-+0-9]*$")
INFO_KEY_RE = re.compile(r"^([A-Za-z0-9_.\-]+):\s*(.*)$")


def _scalar(v):
    """去掉 YAML 引号 / 注释式尾巴，返回裸标量。"""
    v = (v or "").strip()
    if not v:
        return ""
    if v[0] in ("'", '"'):
        q = v[0]
        if len(v) >= 2 and v.endswith(q):
            return v[1:-1]
        return v[1:]
    return v


def parse_template_yaml(text):
    """解析模板的 id 与 info 块。

    只做两级映射的行级解析：足够覆盖 nuclei 模板的头部结构，
    且不引入任何第三方依赖。返回 (id, info_dict)。
    """
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    tid = ""
    for ln in lines[:300]:
        m = re.match(r"^id:\s*(.+?)\s*$", ln)
        if m:
            tid = _scalar(m.group(1))
            break

    info = {}
    start = None
    for i, ln in enumerate(lines[:300]):
        if re.match(r"^info:\s*$", ln):
            start = i + 1
            break
    if start is None:
        return tid, info

    cur_key = None
    cur_block = False
    fold = False
    key_indent = 1
    block_lines = []

    def flush_block():
        if cur_key and cur_block:
            if fold:
                info[cur_key] = " ".join(x.strip() for x in block_lines if x.strip()).strip()
            else:
                info[cur_key] = "\n".join(block_lines).strip()

    for raw in lines[start:]:
        if not raw.strip():
            if cur_block:
                block_lines.append("")
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            break  # info 块结束，进入 http/requests 等部分
        stripped = raw.strip()

        # 块标量的续行：必须比所属 key 缩进更深，否则是新 key 或列表项
        if cur_block and indent > key_indent:
            block_lines.append(stripped)
            continue

        # 列表项：归属上一个 key（作者 / tags / reference 常见写法）
        if stripped.startswith("- ") and cur_key:
            item = _scalar(stripped[2:])
            if item:
                prev = info.get(cur_key)
                if isinstance(prev, list):
                    prev.append(item)
                elif prev:
                    info[cur_key] = [prev, item]
                else:
                    info[cur_key] = [item]
            continue

        m = INFO_KEY_RE.match(stripped)
        if not m:
            continue

        flush_block()
        cur_block = False
        block_lines = []
        key_indent = indent
        key = m.group(1).lower()
        val = m.group(2).strip()

        if BLOCK_SCALAR_RE.match(val):
            cur_key = key
            cur_block = True
            fold = val.startswith(">")
            info[key] = ""
            continue

        cur_key = key
        info[key] = _scalar(val) if val else ""

    flush_block()
    return tid, info


def norm_authors(value):
    """作者字段可能是 "a,b"、列表、或带 @ 的邮箱，统一成 "a, b"。"""
    if isinstance(value, list):
        parts = value
    else:
        parts = re.split(r"[,\n]", value if isinstance(value, str) else str(value or ""))
    out, seen = [], set()
    for p in parts:
        s = (p or "").strip().strip(",;")
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return ", ".join(out)


def norm_tags(value):
    """tags 可能是 "a,b" 或列表，统一成小写逗号串。"""
    if isinstance(value, list):
        parts = value
    else:
        parts = re.split(r"[,\n]", value if isinstance(value, str) else str(value or ""))
    out, seen = [], set()
    for p in parts:
        s = (p or "").strip().strip(",").lower()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return ",".join(out)


def norm_references(value):
    if isinstance(value, list):
        return [x for x in value if x]
    if not value:
        return []
    return [x.strip() for x in str(value).split() if x.strip()]


# ---------------------------------------------------------------------------
# 模板索引：全量扫描 + 落盘缓存
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", ".github", "helpers", "profiles"}


def _iter_template_files(root):
    """遍历模板文件；跳过非模板目录（helpers 是 payload，workflows 是工作流）。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in filenames:
            if fn.endswith((".yaml", ".yml")):
                yield os.path.join(dirpath, fn)


def _git(args, cwd=TEMPLATES_DIR, timeout=60):
    """执行 git 命令，返回 (退出码, stdout, stderr)。"""
    try:
        p = subprocess.run(
            ["git"] + args, cwd=cwd, env=nuclei_env(), timeout=timeout,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", "%s: %s" % (type(e).__name__, e)


def _templates_head():
    rc, out, _ = _git(["rev-parse", "HEAD"], timeout=20)
    return out.strip() if rc == 0 else ""


def _build_index():
    """全量扫描模板目录建索引；返回 (items, meta)。"""
    t0 = time.time()
    if not os.path.isdir(TEMPLATES_DIR):
        raise ToolError("模板目录不存在: %s（先用 poc_update 或手工 git clone）" % TEMPLATES_DIR)

    items = []
    scanned = 0
    for path in _iter_template_files(TEMPLATES_DIR):
        scanned += 1
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)   # info 块基本都在文件头部，只读前 8K 提速
        except Exception:
            continue
        tid, info = parse_template_yaml(head)
        if not tid or not info:
            continue  # 不是模板（payload / 配置 / workflow）
        rel = os.path.relpath(path, TEMPLATES_DIR)
        items.append({
            "id": tid,
            "name": (info.get("name") or "") if isinstance(info.get("name"), str) else "",
            "severity": norm_tags(info.get("severity")).lower() or "unknown",
            "tags": norm_tags(info.get("tags")),
            "path": rel,
            "desc": (info.get("description") or "")[:240] if isinstance(info.get("description"), str) else "",
        })

    items.sort(key=lambda x: (x["severity"] != "critical", x["id"]))
    meta = {
        "built_at": int(time.time()),
        "scanned": scanned,
        "total": len(items),
        "head": _templates_head(),
    }
    log("模板索引构建完成: %d 个模板（扫描 %d 文件，耗时 %.1fs）"
        % (len(items), scanned, time.time() - t0))
    return items, meta


def _load_index_cache():
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != INDEX_VERSION:
            return None, None
        items = data.get("items") or []
        meta = data.get("meta") or {}
        if not items:
            return None, None
        return items, meta
    except Exception:
        return None, None


def _save_index_cache(items, meta):
    try:
        os.makedirs(INDEX_DIR, exist_ok=True)
        tmp = INDEX_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": INDEX_VERSION, "meta": meta, "items": items},
                      f, ensure_ascii=False)
        os.replace(tmp, INDEX_PATH)
    except Exception as e:
        log("索引缓存写入失败（不影响使用）: %s" % e)


def get_index(force=False):
    """取模板索引（内存 → 磁盘缓存 → 重建）。"""
    global _INDEX
    with _index_lock:
        if _INDEX is not None and not force and _INDEX.get("items"):
            return _INDEX

        head = _templates_head()
        items, meta = (None, None) if force else _load_index_cache()
        if items and meta:
            # git HEAD 变了说明模板库更新过，缓存作废
            if head and meta.get("head") and head != meta["head"]:
                log("模板库 HEAD 变化（%s → %s），重建索引"
                    % ((meta.get("head") or "")[:8], head[:8]))
                items, meta = None, None
        if items and meta:
            _INDEX = {"items": items, "meta": meta}
            return _INDEX

        items, meta = _build_index()
        _save_index_cache(items, meta)
        _INDEX = {"items": items, "meta": meta}
        return _INDEX


def resolve_template(ref):
    """把模板 id / 相对路径 / 绝对路径解析成真实文件路径。"""
    ref = (ref or "").strip()
    if not ref:
        raise ToolError("模板引用为空")
    if ref.startswith("/"):
        p = os.path.abspath(ref)
        if not (p == TEMPLATES_DIR or p.startswith(TEMPLATES_DIR + os.sep)):
            raise ToolError("绝对路径必须位于 %s 下: %s" % (TEMPLATES_DIR, ref))
        if not os.path.isfile(p):
            raise ToolError("模板文件不存在: %s" % ref)
        return p

    # 去掉误加的 ./ 前缀
    ref = ref.lstrip("./")
    p = os.path.abspath(os.path.join(TEMPLATES_DIR, ref))
    if p.startswith(TEMPLATES_DIR + os.sep):
        if os.path.isfile(p) and ref.endswith((".yaml", ".yml")):
            return p

    # 按 id 查索引
    idx = get_index()
    matches = [it for it in idx["items"] if it["id"] == ref]
    if not matches:
        # 容忍大小写差异
        low = ref.lower()
        matches = [it for it in idx["items"] if it["id"].lower() == low]
    if not matches:
        # 容忍只给文件名的一部分（唯一匹配才用）
        low = ref.lower()
        fuzzy = [it for it in idx["items"]
                 if low in it["path"].lower() or low in it["id"].lower()]
        if len(fuzzy) == 1:
            matches = fuzzy
        elif len(fuzzy) > 1:
            examples = ", ".join(x["id"] for x in fuzzy[:5])
            raise ToolError("模板引用不唯一（%d 个候选，例如 %s）；请用 poc_search 精确查 id"
                            % (len(fuzzy), examples))
    if not matches:
        raise ToolError("找不到模板: %s（用 poc_search 查询可用模板）" % ref)
    full = os.path.join(TEMPLATES_DIR, matches[0]["path"])
    if not os.path.isfile(full):
        raise ToolError("模板文件缺失: %s" % full)
    return full


# ---------------------------------------------------------------------------
# 工具一：poc_stats
# ---------------------------------------------------------------------------

def tool_poc_stats(args):
    idx = get_index()
    items, meta = idx["items"], idx["meta"]

    sev_count = {}
    tag_count = {}
    for it in items:
        s = it["severity"] or "unknown"
        sev_count[s] = sev_count.get(s, 0) + 1
        for t in (it["tags"] or "").split(","):
            t = t.strip()
            if t:
                tag_count[t] = tag_count.get(t, 0) + 1

    order = ["critical", "high", "medium", "low", "info", "unknown"]
    lines = ["Nuclei 模板库概况（目录 %s）" % TEMPLATES_DIR, ""]
    lines.append("模板总数: %d" % len(items))
    lines.append("")
    lines.append("按 severity 分布:")
    for s in order:
        if s in sev_count:
            lines.append("  %-9s %6d" % (s, sev_count.pop(s)))
    for s in sorted(sev_count):
        lines.append("  %-9s %6d" % (s, sev_count[s]))
    lines.append("")
    lines.append("按 tag TOP 20:")
    top = sorted(tag_count.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
    for i, (t, c) in enumerate(top, 1):
        lines.append("  %2d. %-28s %5d" % (i, t, c))
    lines.append("")

    rc, out, _ = _git(["log", "-1", "--format=%cd"], timeout=20)
    last_commit = out.strip() if rc == 0 else ""
    rc2, out2, _ = _git(["rev-parse", "--short", "HEAD"], timeout=20)
    head = out2.strip() if rc2 == 0 else ""

    lines.append("最后更新时间:")
    lines.append("  模板库最后一次提交: %s" % (last_commit or "（未知，非 git 仓库或 git 不可用）"))
    lines.append("  当前提交: %s" % (head or "（未知）"))
    lines.append("  本机索引构建于: %s（扫描 %d 个 yaml 文件）"
                 % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta.get("built_at", 0))),
                    meta.get("scanned", 0)))
    lines.append("")
    lines.append("用 poc_search 过滤模板，poc_get 看全文，poc_run 实打，poc_dangerous 找能拿 shell 的。")

    if len(items) < 5000:
        lines.append("")
        lines.append("⚠ 模板数偏少（%d < 5000），模板库可能没下全，建议跑 poc_update 检查。" % len(items))
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具二：poc_search
# ---------------------------------------------------------------------------

def tool_poc_search(args):
    keyword = opt_str(args, "keyword").lower()
    tags = split_csv(args.get("tags"))
    sev = split_csv(args.get("severity"))
    limit = as_int(args.get("limit", 30), 30, 1, MAX_SEARCH_LIMIT)

    idx = get_index()
    hits = []
    for it in idx["items"]:
        if sev and it["severity"] not in sev:
            continue
        if tags:
            tset = set((it["tags"] or "").split(","))
            if not tags_any(tags, tset):
                continue
        if keyword:
            blob = "%s %s %s %s" % (it["id"], it["name"], it["path"], it["tags"])
            if keyword not in blob.lower():
                continue
        hits.append(it)

    head = ["模板检索结果（keyword=%s tags=%s severity=%s）"
            % (keyword or "-", ",".join(tags) or "-", ",".join(sev) or "-"),
            "共匹配 %d 个，返回前 %d 个：" % (len(hits), min(limit, len(hits))),
            ""]
    body = []
    for it in hits[:limit]:
        body.append("%s | %s | %s | %s | %s"
                    % (it["id"], it["name"] or "-", it["severity"],
                       it["tags"] or "-", it["path"]))
    if not body:
        body.append("（无匹配；放宽 keyword/tags/severity 再试，或用 poc_stats 看 tag 分布）")
    lines = head + body
    lines.append("")
    lines.append("格式: 模板id | 名称 | severity | tags | 路径")
    lines.append("取全文用 poc_get(id)；直接打用 poc_run(target, templates=id)；"
                 "想找能拿 shell 的用 poc_dangerous。")
    return "\n".join(lines), False


def tags_any(want, have):
    """tags 过滤：命中任意一个即算匹配（支持主 tag 前缀匹配，如 sqli 命中 sqli-error）。"""
    if not want:
        return True
    for w in want:
        if w in have:
            return True
        for h in have:
            if h.startswith(w + "-"):
                return True
    return False


# ---------------------------------------------------------------------------
# 工具三：poc_get
# ---------------------------------------------------------------------------

def tool_poc_get(args):
    ref = opt_str(args, "id_or_path")
    if not ref:
        raise ToolError("缺少必填参数 id_or_path（模板 id 或路径，可先用 poc_search 查）")
    path = resolve_template(ref)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception as e:
        raise ToolError("读取模板失败: %s: %s" % (path, e))

    tid, info = parse_template_yaml(text)
    name = info.get("name") if isinstance(info.get("name"), str) else ""
    severity = norm_tags(info.get("severity")) or "unknown"
    authors = norm_authors(info.get("author"))
    desc = info.get("description") if isinstance(info.get("description"), str) else ""
    refs = norm_references(info.get("reference"))
    tags = norm_tags(info.get("tags"))
    rel = os.path.relpath(path, TEMPLATES_DIR)

    lines = [
        "模板: %s" % (tid or "(未解析到 id)"),
        "  文件: %s" % rel,
        "  名称: %s" % (name or "-"),
        "  作者: %s" % (authors or "-"),
        "  severity: %s" % severity,
        "  tags: %s" % (tags or "-"),
        "  classification: %s" % (info.get("classification") if isinstance(info.get("classification"), str) else "-"),
        "",
        "  description:",
    ]
    for ln in (desc or "（无）").split("\n"):
        lines.append("    %s" % ln)
    lines.append("")
    lines.append("  reference:")
    if refs:
        for r in refs[:20]:
            lines.append("    - %s" % r)
    else:
        lines.append("    （无）")
    lines.append("")
    lines.append("使用建议:")
    score, tier, tier_desc, advice = classify_danger(tid, name, tags, desc)
    if score > 0:
        lines.append("  [%s 级] %s" % (tier, tier_desc))
        lines.append("  %s" % advice)
    else:
        lines.append("  本模板未命中 RCE/上传类的特征，多半只能拿到信息泄露或指纹，"
                     "拿 shell 概率低。")
    lines.append("")
    lines.append("----- 模板 YAML 全文 -----")
    lines.append(text.rstrip("\n"))
    lines.append("----- 全文结束 -----")
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具四：poc_run
# ---------------------------------------------------------------------------

# extra_args 里禁止出现的参数：会破坏 JSONL 解析或写到我们控制不到的地方
FORBIDDEN_EXTRA_ARGS = {
    "-u", "-l", "-jsonl", "-json", "-o", "-config", "-t", "-templates",
    "-store-resp", "-store-resp-dir", "-store-resp-json", "-update-templates",
    "-ud", "-ut",
}


def _build_run_cmd(target, templates, tags, severity, timeout, rate_limit, extra_args,
                   paths=None):
    """组装 nuclei 命令行；返回 (cmd 列表, 策略说明)。

    paths 是「已经解析成绝对路径」的模板列表（poc_auto_run 用），templates 是
    还没解析的 id/相对路径（poc_run 用）。两者给谁都行，但 paths 优先，
    这样就避免了同一份模板再解析一遍。
    """
    if not os.path.isfile(NUCLEI_BIN):
        raise ToolError("nuclei 可执行文件不存在: %s（先用官方 zip 安装）" % NUCLEI_BIN)

    cmd = [NUCLEI_BIN, "-u", target, "-jsonl", "-silent", "-disable-update-check", "-nc"]
    parts = []

    # 并发与限速：默认限速 50 请求/秒，避免把目标打挂
    cmd += ["-rl", str(rate_limit)]
    parts.append("限速 %d req/s" % rate_limit)

    if paths:
        for p in paths:
            cmd += ["-t", p]
        parts.append("模板 %d 个" % len(paths))
    elif templates:
        for t in templates:
            cmd += ["-t", resolve_template(t)]
        parts.append("模板 %d 个" % len(templates))
    else:
        # 必须显式给 -t 模板目录：nuclei 默认去 ~/nuclei-templates 找，
        # 找不到会直接报 "no templates found in path" 而不报错退出。
        cmd += ["-t", TEMPLATES_DIR]
        parts.append("全库按条件筛选")
    if tags:
        cmd += ["-tags", ",".join(tags)]
        parts.append("tags=%s" % ",".join(tags))
    if severity:
        cmd += ["-severity", ",".join(severity)]
        parts.append("severity=%s" % ",".join(severity))

    if extra_args:
        try:
            extra = shlex.split(extra_args)
        except ValueError as e:
            raise ToolError("extra_args 解析失败: %s" % e)
        bad = [x for x in extra if x.split("=", 1)[0].lower() in FORBIDDEN_EXTRA_ARGS]
        if bad:
            raise ToolError("extra_args 不允许出现这些参数（会破坏结果解析或越权落盘）: %s"
                            % ", ".join(sorted(set(bad))))
        cmd += extra
        parts.append("额外参数: %s" % extra_args)

    # 统计请求数（stderr）：-stats-json 在扫描结束时会打一条汇总，进程退出前一定能拿到
    cmd += ["-stats", "-stats-interval", "1", "-stats-json"]
    return cmd, "，".join(parts)


def _exec_nuclei(cmd, timeout):
    """执行一条 nuclei 命令，返回 (stdout, stderr, 耗时秒, 是否超时, 退出码)。

    poc_run / poc_auto_run / fingerprint_probe 共用这一份发包逻辑：
    stdin 必须给 DEVNULL（nuclei 会读 stdin 找目标，继承 MCP 协议管道会吞报文
    而且扫描结束后仍阻塞在 read 上不退出）。
    """
    t0 = time.time()
    timed_out = False
    try:
        p = subprocess.Popen(cmd, env=nuclei_env(), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/tmp")
    except Exception as e:
        raise ToolError("启动 nuclei 失败: %s: %s" % (type(e).__name__, e))

    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        p.kill()
        try:
            out, err = p.communicate(timeout=15)
        except Exception:
            out, err = b"", b""

    elapsed = time.time() - t0
    return ((out or b"").decode("utf-8", "replace"),
            (err or b"").decode("utf-8", "replace"),
            elapsed, timed_out, p.returncode)


def _parse_nuclei_jsonl(stdout_text):
    """解析 nuclei -jsonl 输出，返回 (命中列表, 坏行数)。"""
    hits = []
    bad = 0
    for line in stdout_text.split("\n"):
        line = line.strip()
        if not line or not line.startswith("{"):
            if line:
                bad += 1
            continue
        try:
            obj = json.loads(line)
        except Exception:
            bad += 1
            continue
        info = obj.get("info") or {}
        hits.append({
            "template-id": obj.get("template-id") or obj.get("templateID") or "",
            "name": info.get("name") or "",
            "severity": (info.get("severity") or "").lower(),
            "tags": info.get("tags") or "",
            "type": obj.get("type") or "",
            "matched-at": obj.get("matched-at") or obj.get("host") or "",
            "extracted-results": obj.get("extracted-results") or [],
            "matcher-name": obj.get("matcher-name") or "",
            "curl-command": obj.get("curl-command") or "",
        })
    return hits, bad


def _parse_request_count(stderr_text):
    """从 -stats-json / -stats 的 stderr 里取请求数（取最大值）。"""
    n = 0
    # -stats-json 形如 {"requests":"37","templates":"19",...}（数字是字符串）
    for m in re.finditer(r'"requests"\s*:\s*"?(\d+)"?', stderr_text):
        try:
            n = max(n, int(m.group(1)))
        except Exception:
            pass
    # 文本版 -stats 形如 Requests: 37
    for m in re.finditer(r"Requests:\s*(\d+)", stderr_text):
        try:
            n = max(n, int(m.group(1)))
        except Exception:
            pass
    return n


def tool_poc_run(args):
    target = normalize_target(args.get("target"))
    templates = split_csv_keepcase(args.get("templates"))
    tags = split_csv(args.get("tags"))
    severity = split_csv(args.get("severity"))
    timeout = as_int(args.get("timeout", 180), 180, 5, 3600)
    rate_limit = as_int(args.get("rate_limit", 50), 50, 1, 500)
    extra_args = opt_str(args, "extra_args")

    if not templates and not tags and not severity and not extra_args:
        raise ToolError("至少要给 templates / tags / severity 之一，否则会跑全部 1 万+ 模板"
                        "（对目标伤害太大）。建议先 poc_search / poc_dangerous 选模板")

    cmd, strategy = _build_run_cmd(target, templates, tags, severity,
                                   timeout, rate_limit, extra_args)
    log("poc_run 启动: %s" % " ".join(shlex.quote(c) for c in cmd))

    stdout_text, stderr_text, elapsed, timed_out, rc = _exec_nuclei(cmd, timeout)

    hits, bad = _parse_nuclei_jsonl(stdout_text)
    reqs = _parse_request_count(stderr_text)

    log("poc_run 完成: 命中 %d，请求 %d，耗时 %.1fs，超时=%s，exit=%s"
        % (len(hits), reqs, elapsed, timed_out, rc))

    lines = ["Nuclei 扫描结果", "  目标: %s" % target, "  策略: %s" % strategy, ""]

    if hits:
        lines.append("命中 %d 条%s：" % (len(hits), "（已截断，只显示前 %d 条）" % MAX_HITS_RETURN
                                        if len(hits) > MAX_HITS_RETURN else ""))
        for i, h in enumerate(hits[:MAX_HITS_RETURN], 1):
            lines.append("")
            lines.append("[%d] %s   (%s)" % (i, h["template-id"] or "?", h["severity"] or "-"))
            lines.append("    名称: %s" % (h["name"] or "-"))
            lines.append("    匹配位置: %s" % (h["matched-at"] or "-"))
            if h["matcher-name"]:
                lines.append("    matcher: %s" % h["matcher-name"])
            if h["extracted-results"]:
                ext = h["extracted-results"]
                show = ext[:20] if isinstance(ext, list) else [str(ext)]
                lines.append("    提取结果: %s" % " | ".join(str(x)[:200] for x in show))
            if h["curl-command"]:
                lines.append("    curl: %s" % h["curl-command"])
    else:
        lines.append("未命中任何模板。")
        tail = brief(stderr_text, 800)
        if tail:
            lines.append("")
            lines.append("nuclei stderr 摘要:")
            for ln in tail.split("\n")[-10:]:
                lines.append("  %s" % ln)
        if bad:
            lines.append("（另有 %d 行输出不是合法 JSON，已跳过）" % bad)

    lines.append("")
    lines.append("--- 汇总: 命中 %d | 请求 %s | 耗时 %.1fs%s"
                 % (len(hits), reqs if reqs else "未统计", elapsed,
                    " | 已达 %.0fs 上限被中断，结果不完整" % timeout if timed_out else ""))
    lines.append("")

    # 命中里是否有能拿 shell 的，决定要不要提示闭环
    likely = []
    for h in hits:
        sc, tier, _, _ = classify_danger(h["template-id"], h["name"], h["tags"], "")
        if sc >= 80:
            likely.append((tier, h["template-id"]))
    if likely:
        often = sorted(set(x[0] for x in likely))[0]
        lines.append("⚡ 本次命中里有 %d 条属于 [%s 级] 可直接命令执行/文件写入的模板。" % (len(likely), often))
        lines.append("   下一步（打点 → 拿 shell → 管 shell 闭环）：")
        lines.append("   1) poc_get(<上面命中的 template-id>) 看完整请求，复现拿到命令执行或上传点；")
        lines.append("   2) 调 Webshell MCP 的 payload_list 看内置马子，payload_get(\"php/eval.php\") 之类取全文；")
        lines.append("   3) 把马子写到可解析目录（上传漏洞直接用返回的 curl 复现改包）；")
        lines.append("   4) Webshell MCP 的 shell_add 登记会话，之后 shell_exec / shell_upload 直接用。")
    elif hits:
        lines.append("提示: 本次命中看起来偏信息类，拿 shell 概率不高；"
                     "想找能落地的用 poc_dangerous 挑模板再来一轮。")
    return "\n".join(lines), False


def split_csv_keepcase(value):
    """模板引用要保留大小写（id 里有大写），只按逗号/空白切分。"""
    items = []
    if isinstance(value, str):
        items = re.split(r"[,\n;]+", value)
    elif isinstance(value, (list, tuple)):
        for v in value:
            if isinstance(v, str):
                items.extend(re.split(r"[,\n;]+", v))
    out, seen = [], set()
    for it in items:
        s = (it or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# 工具五：poc_dangerous
# ---------------------------------------------------------------------------

def classify_danger(tid, name, tags, desc):
    """按 tags / 名称 / 描述打分，返回 (score, tier, tier_desc, advice)。"""
    score = 0
    tset = set((tags or "").split(",")) if isinstance(tags, str) else set(tags or [])
    for t in tset:
        t = t.strip()
        if t in DANGER_TAGS:
            score = max(score, DANGER_TAGS[t])

    blob = ("%s %s" % (name or "", desc or "")).lower()
    for word, sc in DANGER_DESC_WORDS:
        if word in blob:
            score = max(score, sc)

    for threshold, tier, tdesc, advice in DANGER_TIERS:
        if score >= threshold:
            return score, tier, tdesc, advice
    return 0, "-", "无危险特征", ""


def tool_poc_dangerous(args):
    tags = split_csv(args.get("tags"))
    severity = split_csv(args.get("severity"))
    limit = as_int(args.get("limit", 30), 30, 1, MAX_SEARCH_LIMIT)

    idx = get_index()
    ranked = []
    for it in idx["items"]:
        if severity and it["severity"] not in severity:
            continue
        if tags:
            tset = set((it["tags"] or "").split(","))
            if not tags_any(tags, tset):
                continue
        score, tier, tdesc, advice = classify_danger(it["id"], it["name"], it["tags"], it["desc"])
        if score <= 0:
            continue
        ranked.append((score, tier, tdesc, advice, it))

    ranked.sort(key=lambda x: (-x[0], x[4]["id"]))

    counts = {}
    for score, tier, _, _, _ in ranked:
        counts[tier] = counts.get(tier, 0) + 1

    lines = ["可能拿到 RCE / 命令执行 / 文件上传的模板（按「拿 shell 概率」排序）", ""]
    lines.append("共筛出 %d 个；分档统计: %s" % (
        len(ranked),
        "，".join("%s 级 %d 个" % (t, counts[t]) for t in sorted(counts)) or "无"))
    lines.append("")
    lines.append("档位说明:")
    for threshold, tier, tdesc, advice in DANGER_TIERS:
        if threshold == 0:
            continue
        lines.append("  [%s] %s" % (tier, tdesc))
    lines.append("")
    lines.append("返回前 %d 个：" % min(limit, len(ranked)))
    lines.append("")

    cur_tier = None
    for score, tier, tdesc, advice, it in ranked[:limit]:
        if tier != cur_tier:
            cur_tier = tier
            lines.append("── [%s 级] %s" % (tier, tdesc))
            lines.append("   拿 shell 建议: %s" % advice)
            lines.append("")
        lines.append("  %s | %s | %s | %s | %s"
                     % (it["id"], it["name"] or "-", it["severity"],
                        it["tags"] or "-", it["path"]))

    if not ranked:
        lines.append("（没有匹配；放宽 tags/severity，或先 poc_update 更新模板库）")

    lines.append("")
    lines.append("格式: 模板id | 名称 | severity | tags | 路径")
    lines.append("")
    lines.append("闭环用法（打点 → 拿 shell → 管 shell）：")
    lines.append("  1) poc_get(id) 看完整请求与参考链接，确认利用条件；")
    lines.append("  2) poc_run(target, templates=id) 实打验证（对公网目标务必保持低 rate_limit）；")
    lines.append("  3) A/B 档命中后，调 Webshell MCP：payload_list 选马 → payload_get 取全文 → 落地；")
    lines.append("  4) Webshell MCP 的 shell_add 登记，之后 shell_exec / shell_upload / shell_download 管理。")
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具六：poc_update
# ---------------------------------------------------------------------------

def tool_poc_update(args):
    if not os.path.isdir(TEMPLATES_DIR):
        raise ToolError("模板目录不存在: %s，请先 git clone" % TEMPLATES_DIR)
    if not os.path.isdir(os.path.join(TEMPLATES_DIR, ".git")):
        raise ToolError("模板目录不是 git 仓库（%s），无法 git pull；"
                        "请重新 git clone 一份" % TEMPLATES_DIR)

    before = len(get_index()["items"])
    head_before = _templates_head()

    rc, out, err = _git(["pull", "--ff-only"], timeout=600)
    log("poc_update: git pull 退出码 %d" % rc)
    if rc != 0:
        # --ff-only 失败（本地有改动/分叉）时给出可执行提示，不静默
        raise ToolError("git pull 失败（退出码 %d）: %s"
                        % (rc, brief(err or out, 500)))

    head_after = _templates_head()
    new_commits = 0
    if head_before and head_after and head_before != head_after:
        rc2, out2, _ = _git(["rev-list", "--count", "%s..%s" % (head_before, head_after)],
                            timeout=60)
        if rc2 == 0:
            try:
                new_commits = int(out2.strip())
            except Exception:
                new_commits = 0

    # git HEAD 变了，强制重建索引拿新模板数
    idx = get_index(force=True)
    after = len(idx["items"])

    lines = ["Nuclei 模板库更新完成（git pull）", ""]
    lines.append("仓库: %s" % TEMPLATES_DIR)
    lines.append("更新前模板数: %d" % before)
    lines.append("更新后模板数: %d（%+d）" % (after, after - before))
    lines.append("新提交数: %d" % new_commits)
    lines.append("当前提交: %s" % (head_after or "（未知）"))
    changed = after - before
    if changed > 0:
        lines.append("")
        lines.append("新增 %d 个模板，可用 poc_search / poc_dangerous 找新的可打点。" % changed)
    elif changed == 0 and new_commits == 0:
        lines.append("")
        lines.append("模板库已是最新，无需更新。")
    else:
        lines.append("")
        lines.append("提交有变化但模板数没变（多为元数据/文档改动）。")
    git_out = brief(out, 400)
    if git_out:
        lines.append("")
        lines.append("git 输出摘要: %s" % git_out.replace("\n", " | "))
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具七/八/九：按指纹自动匹配并验证 POC
#
# 链路：fingerprint_probe（探测指纹） → poc_match（反查候选 POC）
#       → poc_auto_run（匹配 + 实弹验证）
#
# 设计约束（与页面侧 server/nuclei.go 保持一致）：
#  - 指纹匹配只认 info.tags（辅以 id/name/path），大小写不敏感，
#    分隔符（- / _ / 空格 / .）归一后再比；
#  - 只保留 severity ∈ {critical, high, medium} 且「带落地类标签或带 CVE 号」的模板；
#  - 按「拿 shell 概率」排序：rce > 文件上传 > 反序列化 > 命令注入 > SQLi 写文件 > 弱配置；
#  - 匹配不到就明说，绝不退化成盲扫全库（1 万+ 模板会把目标打挂）。
# ---------------------------------------------------------------------------

# 指纹里出现的分隔符统一成空格，再做大小写不敏感比较
FP_SEP_RE = re.compile(r"[-_/\\.]+")
FP_WS_RE = re.compile(r"\s+")
FP_NONWORD_RE = re.compile(r"[^a-z0-9]+")
# 模板词表切分：连续字母 / 连续数字各算一个词（Apache Tomcat → apache / tomcat）
FP_WORD_RE = re.compile(r"[A-Za-z]+|[0-9]+")
CVE_ID_RE = re.compile(r"cve[-_\s]*\d{4}[-_\s]*\d{3,}", re.I)
VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")

# tech 模板里没有信息量的通用 tag，探测指纹时要剔掉
GENERIC_TECH_TAGS = {
    "tech", "intrusive", "discovery", "dos", "fuzzing", "headless",
    "network", "ssl", "http", "web",
}

# 模板名尾巴里的 "Detection / Detect" 去掉，得到干净的指纹名
TECH_NAME_TAIL_RE = re.compile(r"\s*[-‐-―_]?\s*(detection|detect)\s*$", re.I)

# poc_match：只保留这些严重性
MATCH_SEVERITIES = ("critical", "high", "medium")

# poc_match：拿 shell 概率分档（数组顺序即优先级：rce > 上传 > 反序列化 > 命令注入 > SQLi）
MATCH_DANGER_CLASSES = (
    ("rce", ("rce", "remote-code-execution"),
     "A", "直接命令执行 —— 命中即等于拿到了命令通道", 100),
    ("file-upload", ("file-upload", "arbitrary-file-upload",
                     "unrestricted-file-upload", "file-write",
                     "arbitrary-file-write"),
     "B", "文件上传 / 任意文件写 —— 命中即等于能落地文件", 90),
    ("deserialization", ("deserialization", "deserialize",
                         "insecure-deserialization"),
     "C", "反序列化 —— 可执行代码，但需要构造 payload", 78),
    ("command-injection", ("command-injection", "os-command-injection",
                            "code-injection"),
     "D", "命令注入 —— 参数可控即可回显命令", 68),
    ("sqli", ("sqli", "sql-injection"),
     "E", "SQL 注入 —— 满足写文件条件时才能落地", 45),
)

# 弱配置类：拿 shell 概率低，但常是入口信息
MATCH_MISCONFIG_TAGS = ("misconfig", "misconfiguration", "default-login",
                        "default-password", "weak-password", "unauth",
                        "unauthorized", "exposure", "exposed")
MATCH_MISCONFIG_TIER = "F"
MATCH_MISCONFIG_LABEL = "弱配置 / 默认口令 —— 一般拿不到 shell，只能当辅助信息"
MATCH_MISCONFIG_SCORE = 20
MATCH_CVE_ONLY_TIER = "F"
MATCH_CVE_ONLY_LABEL = "命中 CVE 号，但模板标签看不出直接落地 —— 需人工确认可利用性"
MATCH_CVE_ONLY_SCORE = 25

# 每个档位给一句可执行的建议（拿 shell 闭环）
MATCH_TIER_ADVICE = {
    "A": "命中即等于拿到命令通道：用 poc_get 看完整请求，把命令参数换成 id/whoami 复现；"
         "要持久化就接 Webshell MCP：payload_list 挑马 → payload_get 取全文 → 写文件落地 → shell_add 登记。",
    "B": "先确认上传目录能否解析脚本、有没有重命名/白名单；能解析就用 payload_get 取对应类型"
         "（php/jsp/aspx）的马子直接传，再用 shell_add 登记。",
    "C": "先用模板自带 payload 确认可利用，再按目标中间件版本换 gadget 链；"
         "成功后落马并用 shell_add 登记。",
    "D": "确认注入参数与回显是否可控；命中后把命令换成 id/whoami 验证，"
         "成功即可落马并用 shell_add 登记。",
    "E": "重点看能否写文件：需要 FILE 权限 / secure_file_priv 可写 / 堆叠查询；"
         "能用 outfile 或日志写马时再 payload_get，否则只当信息泄露。",
    "F": "多半是弱配置/默认口令或只匹配到 CVE 号；当辅助信息用（读配置、找内网），"
         "想拿 shell 请换 A/B 档模板。",
}

# poc_match / poc_auto_run 的硬上限
MATCH_MAX_LIMIT = 200
MATCH_DEFAULT_LIMIT = 50
MATCH_MAX_RATE = 150

# 指纹探测：一次 tech 全扫会打上千个请求，超时给足
PROBE_DEFAULT_TIMEOUT = 180
PROBE_MAX_TIMEOUT = 600


def _fp_norm(s):
    """指纹归一：小写 + 分隔符统一成空格。"""
    s = FP_SEP_RE.sub(" ", (s or "").lower())
    return FP_WS_RE.sub(" ", s).strip()


def _fp_compact(s):
    """指纹/标签去掉所有非字母数字后的紧凑形式（用于子串匹配）。"""
    return FP_NONWORD_RE.sub("", (s or "").lower())


def _fp_tokens(s):
    """指纹切成词元；纯数字和单字符（版本号碎片）丢掉。

    先按空白切块，再把块内的 -/_/. 拆开；同时保留块的整体紧凑形式，
    这样 "tom_cat" 既能得到 "tom"、"cat"，也能得到 "tomcat"。
    """
    out = []
    for chunk in (s or "").lower().split():
        for p in FP_SEP_RE.split(chunk):
            p = p.strip()
            if len(p) < 2 or p.isdigit():
                continue
            if p not in out:
                out.append(p)
        compact = _fp_compact(chunk)
        if len(compact) >= 4 and compact not in out:
            out.append(compact)
    return out


def _fp_cve_ids(s):
    """从指纹里抽出 CVE 编号（CVE-2021-44228 这种）。"""
    out = []
    for m in CVE_ID_RE.finditer(s or ""):
        cid = re.sub(r"[^a-z0-9]", "", m.group(0).lower())
        if cid and cid not in out:
            out.append(cid)
    return out


def _match_keywords(fingerprints):
    """把一组指纹整理成 (CVE 编号列表, 普通关键词列表)。

    指纹里带完整 CVE 编号时（如 CVE-2021-44228），那个编号本身就是最准的关键词，
    此时不再用裸的 "cve" 去泛匹配（否则会命中全库所有 CVE 模板）。
    """
    cve_ids = []
    tokens = []
    for fp in fingerprints:
        for cid in _fp_cve_ids(fp):
            if cid not in cve_ids:
                cve_ids.append(cid)
        for t in _fp_tokens(fp):
            if cve_ids and t == "cve":
                continue  # 有精确 CVE 号时不泛匹配 cve
            if t not in tokens:
                tokens.append(t)
    return cve_ids, tokens


def _tpl_blob(tpl):
    """模板的可匹配文本：id + name + tags + path。"""
    return "%s %s %s %s" % (tpl.get("id") or "", tpl.get("name") or "",
                            tpl.get("tags") or "", tpl.get("path") or "")


def _tpl_words(tpl):
    """模板的词表：id / name / tags / path 按「连续字母」「连续数字」切分。

    用词表而不是裸子串，是为了避免 "scope" 命中 "laravel-telescope" 这种
    假阳性（子串出现在词中间），同时也天然支持 "Apache Tomcat" → apache/tomcat。
    """
    words = set()
    for w in FP_WORD_RE.findall(_tpl_blob(tpl)):
        if w:
            words.add(w.lower())
    return words


def _tpl_match_keywords(tpl, cve_ids, tokens):
    """模板是否命中这些关键词；返回命中的关键词列表（空 = 不匹配）。

    规则：
      - 关键词与模板的某个词完全相等，或该词以关键词开头（spring → springboot、
        ms → ms17），算命中；
      - CVE 编号按去分隔符后的子串匹配（cve20214428 能命中 CVE-2021-44228）。
    """
    hits = []
    blob_compact = _fp_compact(_tpl_blob(tpl))
    words = _tpl_words(tpl)

    for cid in cve_ids:
        if cid in blob_compact and cid not in hits:
            hits.append(cid)
    for tk in tokens:
        if tk in hits:
            continue
        for w in words:
            if w == tk or w.startswith(tk):
                hits.append(tk)
                break
    return hits


def _classify_match(tpl):
    """判定模板的「拿 shell 概率」档位。

    返回 (tier, tier_label, score, class_name, advice)；class_name 为空表示
    不属于任何落地类（此时只有 CVE 号才允许入选）。
    """
    tags = set((tpl.get("tags") or "").split(","))
    desc_blob = ("%s %s" % (tpl.get("name") or "", tpl.get("desc") or "")).lower()

    for cls, keys, tier, label, score in MATCH_DANGER_CLASSES:
        if any(k in tags for k in keys):
            return tier, label, score, cls, MATCH_TIER_ADVICE.get(tier, "")
    # 标签没写出来时，用名称/描述兜底（很多模板描述里直说了 RCE）
    for cls, keys, tier, label, score in MATCH_DANGER_CLASSES:
        for k in keys:
            if k.replace("-", " ") in desc_blob:
                return tier, label, score, cls, MATCH_TIER_ADVICE.get(tier, "")
    if any(k in tags for k in MATCH_MISCONFIG_TAGS):
        return (MATCH_MISCONFIG_TIER, MATCH_MISCONFIG_LABEL, MATCH_MISCONFIG_SCORE,
                "misconfig", MATCH_TIER_ADVICE.get(MATCH_MISCONFIG_TIER, ""))
    return ("", "", 0, "", "")


def _match_candidates(fingerprints, limit):
    """按指纹反查候选 POC，返回 (候选列表, 命中总数)。

    候选列表已按「拿 shell 概率」排序（同分按 severity、再按 id 稳定排序）。
    """
    cve_ids, tokens = _match_keywords(fingerprints)
    if not cve_ids and not tokens:
        return [], 0

    idx = get_index()
    scored = []
    for it in idx["items"]:
        if (it.get("severity") or "") not in MATCH_SEVERITIES:
            continue
        kw = _tpl_match_keywords(it, cve_ids, tokens)
        if not kw:
            continue
        tier, label, score, cls, advice = _classify_match(it)
        cve_hit = False
        if cve_ids:
            blob_compact = _fp_compact(_tpl_blob(it))
            cve_hit = any(cid in blob_compact for cid in cve_ids)
        if not cls:
            # 没有落地类标签：只有明确命中 CVE 号才允许入选
            if not cve_hit:
                continue
            tier, label = MATCH_CVE_ONLY_TIER, MATCH_CVE_ONLY_LABEL
            score, cls, advice = MATCH_CVE_ONLY_SCORE, "cve", MATCH_TIER_ADVICE.get("F", "")
        scored.append({
            "id": it["id"],
            "name": it.get("name") or "",
            "severity": it.get("severity") or "unknown",
            "tags": it.get("tags") or "",
            "path": it.get("path") or "",
            "matched": kw,
            "tier": tier,
            "tier_label": label,
            "score": score,
            "class": cls,
            "advice": advice,
            "landable": tier in ("A", "B"),
        })

    sev_rank = {"critical": 0, "high": 1, "medium": 2}
    scored.sort(key=lambda c: (-c["score"], sev_rank.get(c["severity"], 9), c["id"]))
    total = len(scored)
    return scored[:max(1, limit)], total


# ---------------------------------------------------------------------------
# 指纹探测
# ---------------------------------------------------------------------------

def _probe_cmd(target, rate_limit):
    """指纹探测命令：tech 标签模板自带指纹检测。"""
    if not os.path.isfile(NUCLEI_BIN):
        raise ToolError("nuclei 可执行文件不存在: %s（先用官方 zip 安装）" % NUCLEI_BIN)
    # -t 必须显式给模板目录；-silent 会吞掉 -stats 文本版，请求数靠 -stats-json
    return [NUCLEI_BIN, "-u", target, "-tags", "tech", "-jsonl", "-silent",
            "-disable-update-check", "-nc",
            "-rl", str(rate_limit), "-t", TEMPLATES_DIR,
            "-stats", "-stats-interval", "1", "-stats-json"]


def _clean_tech_name(name):
    """把模板名洗成指纹名："Tomcat Detection" → "Tomcat"。"""
    n = (name or "").strip()
    prev = None
    while prev != n:
        prev = n
        n = TECH_NAME_TAIL_RE.sub("", n).strip()
    return n


def _hit_version(hit):
    """从提取结果里找一个像版本号的字符串。"""
    for v in (hit.get("extracted-results") or []):
        s = str(v).strip()
        m = VERSION_RE.search(s)
        if m:
            return m.group(0)
    return ""


def _fps_from_hits(hits):
    """把 nuclei 的 tech 命中整理成指纹列表（去重）。"""
    out = []
    seen = {}
    for h in hits:
        tid = h.get("template-id") or ""
        at = h.get("matched-at") or ""
        ver = _hit_version(h)
        name = _clean_tech_name(h.get("name") or "")
        if name:
            key = name.lower()
            if key not in seen:
                seen[key] = True
                out.append({"tech": name, "matched_at": at, "template_id": tid,
                            "source": "nuclei-tech", "version": ver})
        # 模板 tag 里除了通用词，多半就是产品名（tech,tomcat,apache,intrusive,discovery）
        for t in (h.get("tags") or "").split(","):
            t = t.strip().lower()
            if not t or t in GENERIC_TECH_TAGS:
                continue
            if t in seen:
                continue
            seen[t] = True
            out.append({"tech": t, "matched_at": at, "template_id": tid,
                        "source": "nuclei-tech-tag", "version": ""})
    return out


def _ssl_ctx():
    """指纹粗判要能访问自签证书的目标，因此不校验证书（仅做指纹识别用）。"""
    try:
        return ssl._create_unverified_context()
    except Exception:
        return None


def _http_fallback(target, timeout=8):
    """没有 tech 命中时，用 HTTP 头/标题做粗判指纹。

    返回 (指纹列表, 说明文字)。
    """
    url = target if "://" in target else "http://" + target
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; ARTEX-Nuclei-Fingerprint/1.0)"})
    try:
        ctx = _ssl_ctx()
        if ctx is not None:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout)
        try:
            status = getattr(resp, "status", 0)
            headers = resp.headers
            body = resp.read(65536)
        finally:
            resp.close()
    except urllib.error.HTTPError as e:
        status = e.code
        headers = e.headers
        try:
            body = e.read(65536)
        except Exception:
            body = b""
    except Exception as e:
        return [], "HTTP 粗判失败: %s: %s" % (type(e).__name__, e)

    out = []
    hdr = {}
    try:
        for k, v in headers.items():
            hdr[k.lower()] = v
    except Exception:
        pass

    for hname, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"),
                         ("x-aspnet-version", "X-AspNet-Version"),
                         ("x-generator", "X-Generator"),
                         ("x-runtime-version", "X-Runtime-Version")):
        val = (hdr.get(hname) or "").strip()
        if val:
            out.append({"tech": val, "matched_at": url, "template_id": "",
                        "source": "http-header", "version": "",
                        "note": label})

    text = ""
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        pass
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        if title:
            out.append({"tech": title, "matched_at": url, "template_id": "",
                        "source": "http-title", "version": "", "note": "HTML <title>"})

    note = "HTTP 粗判（来源：响应头/标题，状态码 %s）" % status
    if not out:
        note = "HTTP 粗判也没有取到 Server / X-Powered-By / <title>（状态码 %s）" % status
    return out, note


def tool_fingerprint_probe(args):
    """工具七：探测目标指纹。"""
    target = normalize_target(args.get("target"))
    timeout = as_int(args.get("timeout", PROBE_DEFAULT_TIMEOUT),
                     PROBE_DEFAULT_TIMEOUT, 10, PROBE_MAX_TIMEOUT)
    rate_limit = as_int(args.get("rate_limit", 50), 50, 1, MATCH_MAX_RATE)

    cmd = _probe_cmd(target, rate_limit)
    log("fingerprint_probe 启动: %s" % " ".join(shlex.quote(c) for c in cmd))

    stdout_text, stderr_text, elapsed, timed_out, _rc = _exec_nuclei(cmd, timeout)
    hits, _bad = _parse_nuclei_jsonl(stdout_text)
    reqs = _parse_request_count(stderr_text)

    fps = _fps_from_hits(hits)
    source = "nuclei-tech"
    note = "nuclei tech 模板命中 %d 条" % len(hits)
    if not fps:
        # tech 没命中 → 回退到 HTTP 头/标题粗判，并明确标注来源
        fallback, fb_note = _http_fallback(target)
        fps = fallback
        source = "http-header" if fallback else "none"
        note = "nuclei tech 模板未命中；%s" % fb_note

    log("fingerprint_probe 完成: 指纹 %d，命中 %d，请求 %d，耗时 %.1fs"
        % (len(fps), len(hits), reqs, elapsed))

    lines = ["Nuclei 指纹探测结果", "  目标: %s" % target, "  来源: %s" % source, ""]
    lines.append("【指纹】%s" % (" / ".join(f["tech"] for f in fps) if fps else "（无指纹命中）"))
    lines.append("")
    if fps:
        lines.append("共 %d 条指纹：" % len(fps))
        for f in fps:
            extra = []
            if f.get("version"):
                extra.append("版本 %s" % f["version"])
            if f.get("template_id"):
                extra.append("模板 %s" % f["template_id"])
            if f.get("note"):
                extra.append(f["note"])
            lines.append("  - %s  [%s]%s"
                         % (f["tech"], f["source"],
                            ("  " + "，".join(extra)) if extra else ""))
    else:
        lines.append("没有识别出任何指纹：nuclei 的 tech 模板没命中，"
                     "HTTP 头/标题也没给出可用线索。")
        lines.append("可以人工确认目标技术栈后再调 poc_match(fingerprints=[...])。")

    lines.append("")
    lines.append("--- 汇总: 指纹 %d | 命中 %d | 请求 %s | 耗时 %.1fs%s"
                 % (len(fps), len(hits), reqs if reqs else "未统计", elapsed,
                    " | 已达 %.0fs 上限被中断，结果不完整" % timeout if timed_out else ""))
    lines.append("")
    lines.append("下一步: poc_match(fingerprints=[上面的指纹]) 反查候选 POC，"
                 "或直接 poc_auto_run(target) 一站式跑完。")
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具八：poc_match
# ---------------------------------------------------------------------------

def _tool_fingerprints(args):
    """从参数里取指纹列表（兼容 list 与逗号分隔字符串）。"""
    for key in ("fingerprints", "fingerprints[]", "fingerprint", "tech"):
        v = args.get(key)
        if v:
            out = split_csv_keepcase(v)
            if out:
                return out
    return []


def tool_poc_match(args):
    """工具八：按指纹反查候选 POC。"""
    fps = _tool_fingerprints(args)
    if not fps:
        raise ToolError("缺少必填参数 fingerprints（指纹列表，例如 "
                        '["Apache Tomcat 9.0", "Java"]；先用 fingerprint_probe 探测）')
    limit = as_int(args.get("limit", MATCH_DEFAULT_LIMIT), MATCH_DEFAULT_LIMIT, 1, MATCH_MAX_LIMIT)

    cands, total = _match_candidates(fps, limit)
    if not cands:
        return ("未匹配到与该指纹相关的 POC（指纹: %s）。\n"
                "说明：只保留 severity ∈ {critical, high, medium} 且带 "
                "rce / file-upload / deserialization / command-injection / sqli / misconfig "
                "标签或带 CVE 号的模板；当前库里没有符合条件的候选。\n"
                "可以换更精确的指纹（例如带版本号的产品名或 CVE 编号）再试，"
                "或用 poc_search / poc_dangerous 手工找模板。"
                % "、".join(fps)), False

    counts = {}
    for c in cands:
        counts[c["tier"]] = counts.get(c["tier"], 0) + 1

    lines = ["Nuclei 指纹 → POC 匹配结果", ""]
    lines.append("【指纹】%s" % " / ".join(fps))
    lines.append("【候选 POC】共 %d 个（按拿 shell 概率排序，已截断到 %d）" % (total, limit))
    lines.append("")
    lines.append("档位统计: %s" % ("，".join("%s 级 %d 个" % (t, counts[t])
                                        for t in sorted(counts)) or "无"))
    lines.append("")
    for i, c in enumerate(cands, 1):
        lines.append("[%d] %s   (%s)" % (i, c["id"], c["severity"]))
        lines.append("    名称: %s" % (c["name"] or "-"))
        lines.append("    命中的指纹词: %s" % "、".join(c["matched"]))
        lines.append("    拿 shell 概率: [%s 级] %s" % (c["tier"], c["tier_label"]))
        lines.append("    建议: %s" % c["advice"])
    lines.append("")
    lines.append("用 poc_get(id) 看完整请求；用 poc_auto_run(target, fingerprints=[...]) "
                 "自动匹配并实弹验证。")
    lines.append("命中 RCE/上传类后接 Webshell MCP：payload_list → payload_get → 落地 → shell_add。")
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具九：poc_auto_run
# ---------------------------------------------------------------------------

def tool_poc_auto_run(args):
    """工具九：一站式「探测指纹 → 匹配 POC → 实弹验证」。"""
    target = normalize_target(args.get("target"))
    fps = _tool_fingerprints(args)
    tpls = split_csv_keepcase(args.get("templates"))
    limit = as_int(args.get("limit", MATCH_DEFAULT_LIMIT), MATCH_DEFAULT_LIMIT, 1, MATCH_MAX_LIMIT)
    rate_limit = as_int(args.get("rate_limit", 50), 50, 1, MATCH_MAX_RATE)
    timeout = as_int(args.get("timeout", 180), 180, 5, 600)

    # 1) 指纹：没给就现探测
    probe_note = ""
    if not fps and not tpls:
        probe_args = {"target": target, "timeout": min(timeout, PROBE_DEFAULT_TIMEOUT),
                      "rate_limit": rate_limit}
        probe_text, _ = tool_fingerprint_probe(probe_args)
        fps = []
        for line in probe_text.split("\n"):
            if line.startswith("【指纹】"):
                raw = line[len("【指纹】"):].strip()
                if raw and not raw.startswith("（"):
                    fps = [x.strip() for x in raw.split(" / ") if x.strip()]
        probe_note = "（本次指纹由 fingerprint_probe 自动探测得到）"
        if not fps:
            return ("【指纹】（未识别到指纹）%s\n"
                    "【候选 POC】未匹配到与该指纹相关的 POC —— 已停止，未对目标发起任何 POC 请求。\n"
                    "建议：人工确认目标技术栈后，用 poc_auto_run(target, fingerprints=[...]) "
                    "或 poc_match(fingerprints=[...]) 继续。" % probe_note), False

    # 2) 候选 POC：显式给了 templates 就直接用，否则按指纹反查
    cands = []
    total = 0
    if tpls:
        lines_used = list(tpls[:limit])
    else:
        cands, total = _match_candidates(fps, limit)
        if not cands:
            return ("【指纹】%s\n"
                    "【候选 POC】未匹配到与该指纹相关的 POC —— 已停止，未对目标发起任何 POC 请求。\n"
                    "说明：只保留 severity ∈ {critical, high, medium} 且带 "
                    "rce / file-upload / deserialization / command-injection / sqli / misconfig "
                    "标签或带 CVE 号的模板。\n"
                    "可以换更精确的指纹（例如带版本号的产品名或 CVE 编号）再试，"
                    "或用 poc_search / poc_dangerous 手工挑模板。"
                    % ("、".join(fps) if fps else "-"), False)
        lines_used = [c["id"] for c in cands]

    # 3) 实弹：复用 poc_run 的参数拼装与 JSONL 解析
    paths = []
    if not tpls:
        for c in cands:
            abs_path = os.path.join(TEMPLATES_DIR, c["path"])
            if os.path.isfile(abs_path):
                paths.append(abs_path)
        if not paths:
            raise ToolError("候选模板文件都缺失，无法验证（模板库路径异常）")
    else:
        for t in lines_used:
            paths.append(resolve_template(t))

    cmd, strategy = _build_run_cmd(target, None, None, None, timeout, rate_limit, "",
                                   paths=paths)
    log("poc_auto_run 启动: %s" % " ".join(shlex.quote(c) for c in cmd))

    stdout_text, stderr_text, elapsed, timed_out, rc = _exec_nuclei(cmd, timeout)
    hits, _bad = _parse_nuclei_jsonl(stdout_text)
    reqs = _parse_request_count(stderr_text)

    log("poc_auto_run 完成: 候选 %d，实跑 %d，命中 %d，请求 %d，耗时 %.1fs"
        % (total or len(lines_used), len(paths), len(hits), reqs, elapsed))

    lines = ["Nuclei 自动匹配并验证 POC", "  目标: %s" % target, ""]
    lines.append("【指纹】%s%s" % ("、".join(fps) if fps else "（未提供，直接跑指定模板）",
                                   probe_note))
    lines.append("【候选 POC】共 %d 个（按拿 shell 概率排序%s）"
                 % (total if cands else len(lines_used),
                    "，已截断到 %d" % limit if cands else ""))
    if cands:
        for i, c in enumerate(cands, 1):
            lines.append("  [%d] %s (%s) | 命中指纹词: %s | 拿 shell 概率: %s 级"
                         % (i, c["id"], c["severity"], "、".join(c["matched"]), c["tier"]))
    lines.append("")
    lines.append("【命中】%s" % ("共 %d 条" % len(hits) if hits else "无"))
    landable = []
    for i, h in enumerate(hits[:MAX_HITS_RETURN], 1):
        sc, tier, tdesc, _adv = classify_danger(h["template-id"], h["name"], h["tags"], "")
        can_land = sc >= 88
        lines.append("")
        lines.append("[%d] %s   (%s)%s" % (i, h["template-id"] or "?", h["severity"] or "-",
                                          "   ⚡ 该命中可用于落马" if can_land else ""))
        lines.append("    名称: %s" % (h["name"] or "-"))
        lines.append("    匹配位置: %s" % (h["matched-at"] or "-"))
        if h["extracted-results"]:
            ext = h["extracted-results"]
            show = ext[:20] if isinstance(ext, list) else [str(ext)]
            lines.append("    提取结果: %s" % " | ".join(str(x)[:200] for x in show))
        if h["curl-command"]:
            lines.append("    curl: %s" % h["curl-command"])
        if can_land:
            landable.append((h["template-id"], tier, tdesc))

    lines.append("")
    lines.append("--- 汇总: 候选 %d | 实跑模板 %d | 请求 %s | 命中 %d | 耗时 %.1fs%s"
                 % (total if cands else len(lines_used), len(paths),
                    reqs if reqs else "未统计", len(hits), elapsed,
                    " | 已达 %.0fs 上限被中断，结果不完整" % timeout if timed_out else ""))
    lines.append("--- 策略: %s" % strategy)
    lines.append("")

    if landable:
        lines.append("⚡ 本次命中里有 %d 条属于「可用于落马」的模板（%s）。"
                     % (len(landable), "、".join(x[0] for x in landable[:5])))
        lines.append("   落地闭环（Webshell MCP）：")
        lines.append("   1) payload_list → 按目标类型（php/jsp/aspx）挑马子；")
        lines.append("   2) payload_get(\"php/eval.php\") 取马子全文；")
        lines.append("   3) 通过上面的 curl/上传点把马子落地到可解析目录；")
        lines.append("   4) shell_add 登记会话，之后 shell_exec / shell_upload 管理。")
    elif hits:
        lines.append("提示：本次命中不属于「可直接落地」类，拿 shell 概率不高；"
                     "想落地请换 A/B 档模板（poc_match 结果里的档位）。")
    else:
        lines.append("未命中任何候选模板：指纹匹配到的 POC 在目标上没有复现成功。")
        lines.append("可以提高 limit、补充更精确的指纹（如产品版本号 / CVE 编号）后重试。")
    return "\n".join(lines), False


# ---------------------------------------------------------------------------
# 工具注册表（tools/list 的定义）
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "poc_stats",
        "description": (
            "Nuclei 模板库概况：模板总数、按 severity 的分布、按 tag 的 TOP20、最后更新时间。"
            "开局先跑它了解本机可用的 POC 覆盖面（例如有多少 critical / 有没有 rce、file-upload 类 tag），"
            "再决定用 poc_search 还是 poc_dangerous 选模板。"
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "poc_search",
        "description": (
            "检索 Nuclei 模板（按文件路径/名称/tags/severity 过滤）。"
            "keyword 会匹配模板 id、名称、路径与 tags；tags/severity 支持逗号分隔多值（命中任意一个即可）。"
            "返回每行 `模板id | 名称 | severity | tags | 路径`。"
            "典型用法：poc_search(keyword=auth)、poc_search(tags=file-upload)、"
            "poc_search(severity=critical,high)。拿到 id 后用 poc_get 看全文、poc_run 实战。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "关键词，匹配模板 id/名称/路径/tags，例如 auth、log4j、thinkphp"},
                "tags": {"type": "string", "description": "tag 过滤，逗号分隔，例如 rce,file-upload（命中任意一个）"},
                "severity": {"type": "string", "description": "严重性过滤，逗号分隔，例如 critical,high"},
                "limit": {"type": "integer", "default": 30, "minimum": 1, "maximum": 500, "description": "最多返回条数，默认 30"},
            },
        },
    },
    {
        "name": "poc_get",
        "description": (
            "取单个 Nuclei 模板的 YAML 全文，并给出解析出的 info（名称/作者/severity/tags/description/reference）。"
            "参数 id_or_path 可以是模板 id（如 CVE-2021-44228），也可以是相对/绝对路径。"
            "会顺带给出该模板的「拿 shell 概率」分档与使用建议。"
            "拿到全文后照着改请求参数即可复现；复现成功拿到上传点或命令执行后，"
            "接着用 Webshell MCP 的 payload_list/payload_get 取马、shell_add 登记，形成闭环。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id_or_path": {"type": "string", "description": "模板 id 或路径，例如 CVE-2021-44228 或 http/cves/2021/CVE-2021-44228.yaml"},
            },
            "required": ["id_or_path"],
        },
    },
    {
        "name": "poc_run",
        "description": (
            "对目标执行 Nuclei 模板验证（N-day 快速打点）。target 必填（URL 或 host）。"
            "必须至少给 templates / tags / severity 之一，避免误跑全量 1 万+ 模板把目标打挂。"
            "执行 `nuclei -u <target> -jsonl -silent -disable-update-check` 加过滤参数，"
            "解析 JSONL 返回命中列表（template-id/name/severity/matched-at/extracted-results/curl-command）"
            "与汇总（命中数、请求数、耗时）。rate_limit 默认 50 请求/秒，对公网目标别调高。"
            "【与 Webshell MCP 联动】命中 RCE / 命令执行 / 文件上传类模板后，"
            "本 MCP 只负责「打点」；接着请调用 Webshell MCP 的 payload_list / payload_get 取内置马子，"
            "通过模板给出的上传点或写入点落地，再用 shell_add 登记会话，之后 shell_exec / shell_upload "
            "管理。即完整链路：打点(poc_run) → 拿 shell(payload_list/payload_get + 落地) → 管 shell(shell_add/shell_exec)。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 URL 或 host，例如 https://1.2.3.4:8443 或 example.com"},
                "templates": {"type": "string", "description": "模板 id 或路径，逗号分隔，例如 CVE-2021-44228 或 http/cves/2021/xxx.yaml"},
                "tags": {"type": "string", "description": "按 tag 选模板，逗号分隔，例如 rce,file-upload"},
                "severity": {"type": "string", "description": "按严重性选模板，逗号分隔，例如 critical,high"},
                "timeout": {"type": "integer", "default": 180, "minimum": 5, "maximum": 3600, "description": "整体运行硬超时（秒），默认 180；超时会中断并返回已拿到的部分结果"},
                "rate_limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500, "description": "每秒请求数上限，默认 50；对公网目标不要调高，避免把别人打挂"},
                "extra_args": {"type": "string", "description": "额外 nuclei 参数（字符串，例如 \"-H 'X-Forwarded-For: 127.0.0.1' -timeout 10\"）；-u/-l/-o/-jsonl/-t 等会破坏解析的参数会被拒绝"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "poc_dangerous",
        "description": (
            "只列出「可能拿到 RCE / 命令执行 / 文件上传 / 反序列化 / SQL 写文件」的模板，"
            "并按「拿 shell 概率」分档（A 直接命令执行、B 文件上传/任意写、C 反序列化/SSTI、D SQL 注入、E 仅读取）"
            "给出使用建议，是攻防演练里快速挑打点的入口。"
            "选好 id 后走 poc_run 实打；命中 A/B 档就切到 Webshell MCP："
            "payload_list 选马 → payload_get 取全文 → 落地 → shell_add 登记 → shell_exec 管理，"
            "形成 打点 → 拿 shell → 管 shell 的闭环。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tags": {"type": "string", "description": "在危险模板里再按 tag 过滤，逗号分隔"},
                "severity": {"type": "string", "description": "按严重性过滤，逗号分隔，例如 critical,high"},
                "limit": {"type": "integer", "default": 30, "minimum": 1, "maximum": 500, "description": "最多返回条数，默认 30"},
            },
        },
    },
    {
        "name": "poc_update",
        "description": (
            f"更新 Nuclei 模板库：执行 git -C {TEMPLATES_DIR} pull --ff-only，"
            "返回更新前后模板数与新增提交数，并自动重建模板索引。"
            "演练前建议跑一次拿最新 N-day 模板；失败会明确报错（不会静默）。"
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "fingerprint_probe",
        "description": (
            "探测目标指纹（技术栈识别）。用 nuclei 的 tech 模板扫目标"
            f"（`nuclei -u <target> -tags tech -jsonl -silent -t {TEMPLATES_DIR}`），"
            "返回命中的技术名与匹配位置；若 tech 模板没命中，会回退用 HTTP 响应头"
            "（Server / X-Powered-By / X-AspNet-Version 等）与 HTML <title> 做粗判，"
            "并在结果里明确标注来源（nuclei-tech / http-header / http-title）。"
            "拿到指纹后用 poc_match 反查候选 POC，或直接 poc_auto_run 一站式跑完。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 URL 或 host，例如 https://10.0.0.5:8443"},
                "timeout": {"type": "integer", "default": PROBE_DEFAULT_TIMEOUT, "minimum": 10, "maximum": PROBE_MAX_TIMEOUT, "description": "整体硬超时（秒），默认 180；tech 全扫请求较多，别调太小"},
                "rate_limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": MATCH_MAX_RATE, "description": "每秒请求数上限，默认 50，上限 150"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "poc_match",
        "description": (
            "按指纹反查候选 POC（不发起任何请求）。在模板库里扫描 info.tags，"
            "把指纹名与 tag 做大小写不敏感、去分隔符（-/_/空格）的匹配，"
            "只保留 severity ∈ {critical, high, medium} 且带 "
            "rce / file-upload / deserialization / command-injection / sqli / misconfig "
            "类标签或带 CVE 号的模板，并按「拿 shell 概率」排序"
            "（A 直接命令执行 > B 文件上传 > C 反序列化 > D 命令注入 > E SQLi 写文件 > F 弱配置）。"
            "返回：模板 id、名称、severity、命中的指纹词、拿 shell 概率档位与使用建议。"
            "limit 默认 50、硬上限 200。匹配不到会明确说「未匹配到相关 POC」，不会盲扫全库。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "fingerprints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "指纹列表，例如 [\"Apache Tomcat 9.0\", \"Java\", \"CVE-2021-44228\"]；"
                                   "先用 fingerprint_probe 探测得到",
                },
                "limit": {"type": "integer", "default": MATCH_DEFAULT_LIMIT, "minimum": 1, "maximum": MATCH_MAX_LIMIT, "description": "最多返回条数，默认 50，硬上限 200"},
            },
            "required": ["fingerprints"],
        },
    },
    {
        "name": "poc_auto_run",
        "description": (
            "一站式「探测指纹 → 匹配 POC → 实弹验证」。target 必填。"
            "fingerprints 可选：不传就自动先跑 fingerprint_probe，再用探测到的指纹调 poc_match，"
            "最后用 poc_run 的同一套发包逻辑执行候选模板（限速默认 50 req/s，上限 150）。"
            "templates 可显式指定要跑的模板（此时跳过匹配）。"
            "返回分三段：【指纹】探测到的技术栈、【候选 POC】按拿 shell 概率排序的候选、"
            "【命中】逐条命中（matched-at / 提取结果 / curl 命令），"
            "并额外标注「该命中可用于落马」+ Webshell MCP 落地提示"
            "（payload_list → payload_get → 落地 → shell_add）。"
            "汇总给出：匹配到的候选数、实际跑的模板数、请求数、命中数、耗时。"
            "匹配不到候选时会明确说明并停止，不会盲扫全库模板。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 URL 或 host，例如 http://127.0.0.1:18082"},
                "fingerprints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "可选指纹列表；不传则自动探测（探测 → 匹配 → 验证 全自动）",
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "可选：直接指定要跑的模板 id（此时跳过指纹匹配）",
                },
                "limit": {"type": "integer", "default": MATCH_DEFAULT_LIMIT, "minimum": 1, "maximum": MATCH_MAX_LIMIT, "description": "候选模板上限，默认 50，硬上限 200"},
                "rate_limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": MATCH_MAX_RATE, "description": "每秒请求数上限，默认 50，上限 150"},
                "timeout": {"type": "integer", "default": 180, "minimum": 5, "maximum": 600, "description": "整体硬超时（秒），默认 180"},
            },
            "required": ["target"],
        },
    },
]

TOOL_HANDLERS = {
    "poc_stats": tool_poc_stats,
    "poc_search": tool_poc_search,
    "poc_get": tool_poc_get,
    "poc_run": tool_poc_run,
    "poc_dangerous": tool_poc_dangerous,
    "poc_update": tool_poc_update,
    "fingerprint_probe": tool_fingerprint_probe,
    "poc_match": tool_poc_match,
    "poc_auto_run": tool_poc_auto_run,
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
    log("=== %s MCP 服务器启动 (pid=%d, python=%s) ==="
        % (SERVER_NAME, os.getpid(), sys.version.split()[0]))

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
                "error": {"code": ERR_INTERNAL,
                          "message": "%s: %s" % (type(e).__name__, e)},
            })


if __name__ == "__main__":
    main()
