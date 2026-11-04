#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在真实 MCP 进程里端到端验证删马/摘登记护栏。

前面的单元测试是 import 源码直接调 tool_shell_del；这个脚本起一个真的 MCP stdio
进程，走 JSON-RPC 协议调用 shell_del / shell_exec，验证「agent 通过 MCP 自删马」
这条真实路径上护栏确实生效。

跑法（服务器上）：
    python3 /root/artex-publish/webshell/test_shell_del_gate_e2e.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

# MCP 源码：优先用环境变量，其次同目录的仓库源码，最后生产部署路径
MCP = (os.environ.get("ARTEX_WEBSHELL_MCP") or "").strip() or (
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "webshell_mcp.py")
    if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "webshell_mcp.py"))
    else "/opt/artex/bin/webshell_mcp.py"
)
PY = "/usr/bin/python3"

HORSE = "/var/www/html/static_e2e.php"


def call(proc, method, params=None, _id=[0]):
    _id[0] += 1
    msg = {"jsonrpc": "2.0", "id": _id[0], "method": method}
    if params is not None:
        msg["params"] = params
    proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
    proc.stdin.flush()
    # 读到一行响应（跳过通知）
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP 进程无响应（可能已退出）")
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if obj.get("id") == _id[0]:
            return obj


def tool_call(proc, name, args):
    return call(proc, "tools/call", {"name": name, "arguments": args})


def text_of(resp):
    try:
        return "\n".join(
            c.get("text", "") for c in resp.get("result", {}).get("content", [])
        )
    except Exception:
        return json.dumps(resp, ensure_ascii=False)


def write_store(path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "e2e-guard-sess": {
                "url": "http://127.0.0.1:9/e2e.php",
                "type": "php",
                "password": "ptest",
                "method": "POST",
                "header": {},
                "note": "e2e 护栏测试",
                "remote_path": HORSE,
                "artifacts": [],
            }
        }, f)
    os.chmod(path, 0o600)


def main():
    tmp = tempfile.mkdtemp(prefix="e2e-gate-")
    store = os.path.join(tmp, "webshells.json")
    write_store(store)

    # 用环境变量把 MCP 的会话库指到临时目录（不碰真数据）
    env = dict(os.environ)
    env["ARTEX_WEBSHELL_STORE"] = store

    proc = subprocess.Popen(
        [PY, MCP],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env,
    )
    fails = []

    def check(cond, msg, detail=""):
        if cond:
            print("  PASS %s" % msg)
        else:
            print("  FAIL %s %s" % (msg, detail))
            fails.append(msg)

    try:
        init = call(proc, "initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "1"},
        })
        check("result" in init, "MCP initialize 成功")
        call(proc, "notifications/initialized", {})

        # 1) 默认调用：只清临时件，马与登记都保留
        r = tool_call(proc, "shell_del", {"name": "e2e-guard-sess"})
        t = text_of(r)
        check(r.get("result", {}).get("isError") is not True,
              "MCP 真实调用：默认 shell_del 放行（只清临时件）", t[:200])
        with open(store, encoding="utf-8") as f:
            after = json.load(f)
        check("e2e-guard-sess" in after, "默认调用后本机登记保留（页面仍看得到）")
        check(after.get("e2e-guard-sess", {}).get("remote_path") == HORSE,
              "默认调用后落地马路径仍在")

        # 2) shell_del 带 remove_remote 但没有 human_approved → 必须拒绝
        r = tool_call(proc, "shell_del", {"name": "e2e-guard-sess", "remove_remote": True})
        t = text_of(r)
        check("人工授权" in t, "MCP 真实调用：无 human_approved 被拒绝", t[:200])
        check(r.get("result", {}).get("isError") is True, "返回 isError=true")

        # 3) 登记必须还在
        with open(store, encoding="utf-8") as f:
            after = json.load(f)
        check("e2e-guard-sess" in after, "拒绝后本机登记保留")

        # 4) drop_registration 但没有 human_approved → 必须拒绝
        r = tool_call(proc, "shell_del", {"name": "e2e-guard-sess", "drop_registration": True})
        t = text_of(r)
        check("人工授权" in t, "MCP 真实调用：无 human_approved 摘登记被拒绝", t[:200])
        with open(store, encoding="utf-8") as f:
            after = json.load(f)
        check("e2e-guard-sess" in after, "拒绝后本机登记保留")

        # 5) shell_exec 直接 rm 落地马 → 必须被拦（不能绕开 shell_del）
        r = tool_call(proc, "shell_exec", {"name": "e2e-guard-sess", "cmd": "rm -f %s" % HORSE})
        t = text_of(r)
        check("落地马" in t, "MCP 真实调用：shell_exec 删落地马被拦", t[:200])
        check(r.get("result", {}).get("isError") is True, "shell_exec 删马返回 isError=true")

        # 6) tools/list 里能看到规则（agent 看得见）
        lst = call(proc, "tools/list", {})
        tools = lst.get("result", {}).get("tools", [])
        sd = None
        for t2 in tools:
            if t2.get("name") == "shell_del":
                sd = t2
        check(sd is not None, "tools/list 里有 shell_del")
        if sd:
            props = sd.get("inputSchema", {}).get("properties", {})
            check("human_approved" in props, "shell_del 的入参含 human_approved",
                  str(list(props.keys())))
            check("drop_registration" in props, "shell_del 的入参含 drop_registration",
                  str(list(props.keys())))
            check("clean_uploads" in props, "shell_del 的入参含 clean_uploads",
                  str(list(props.keys())))
            desc = sd.get("description", "")
            check("human_approved" in desc, "shell_del 的描述写明人工授权位")
            check("保留" in desc, "shell_del 的描述写明默认保留马与登记")
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    if fails:
        print("\nFAILED: %d" % len(fails))
        return 1
    print("\nALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
