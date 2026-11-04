# -*- coding: utf-8 -*-
"""webshell_mcp.py 人工授权闸的回归测试。

直接 import 部署用的 MCP 源码，调 tool_shell_del：
  - remove_remote=true 但没 human_approved  -> 必须报错，远端不能动
  - remove_remote=true 且 human_approved=true -> 允许（这一步只验闸门放行，
    实际远端清理依赖目标可达，这里用一个不存在的会话避免真发请求）
  - 只摘登记（不带 remove_remote）          -> 允许
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

SRC = "/root/artex-publish/webshell/webshell_mcp.py"

spec = importlib.util.spec_from_file_location("wsm", SRC)
wsm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wsm)


def _mk_store(tmpdir, name):
    p = os.path.join(tmpdir, "webshells.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({
            name: {
                "url": "http://127.0.0.1:9/x.php",
                "type": "php",
                "password": "ptest",
                "method": "POST",
                "header": {},
                "note": "test",
            }
        }, f)
    os.chmod(p, 0o600)
    return p


def run():
    fails = []

    def check(cond, msg):
        if cond:
            print("  PASS %s" % msg)
        else:
            print("  FAIL %s" % msg)
            fails.append(msg)

    tmp = tempfile.mkdtemp(prefix="wsm-guard-")
    try:
        name = "guard-test-sess"
        path = _mk_store(tmp, name)
        wsm.STORE_PATH = path
        wsm._MODE_CACHE.clear()

        # 1) remove_remote=true 但没有人工授权 -> 必须拒绝
        try:
            wsm.tool_shell_del({"name": name, "remove_remote": True})
            check(False, "无授权时 remove_remote 应被拒绝")
        except wsm.ToolError as e:
            check("人工授权" in str(e), "无授权时拒绝并提示需人工授权")
        except Exception as e:  # noqa
            check(False, "无授权时应抛 ToolError，实际 %r" % (e,))

        # 拒绝后登记必须还在
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
        check(name in store, "拒绝后本机登记保留")

        # 2) 只摘登记（不带 remove_remote）-> 允许
        try:
            wsm.tool_shell_del({"name": name})
            check(True, "只摘登记放行")
        except Exception as e:  # noqa
            check(False, "只摘登记应放行，实际 %r" % (e,))

        # 3) 授权位齐全 -> 闸门放行（走远端清理分支，目标是不可达地址，
        #    预期会因远端没清干净报错，但那是清理阶段的错，不是闸门的错）
        _mk_store(tmp, name)
        wsm._MODE_CACHE.clear()
        err = None
        try:
            wsm.tool_shell_del({
                "name": name,
                "remove_remote": True,
                "human_approved": True,
                "timeout": 2,
            })
        except Exception as e:  # noqa
            err = e
        check(
            err is None or "人工授权" not in str(err),
            "带 human_approved 时闸门放行（错误若出现应来自远端清理阶段）",
        )

        # 4) 闸门总开关能关掉
        old = wsm.ALLOW_REMOTE_DELETE
        wsm.ALLOW_REMOTE_DELETE = False
        try:
            wsm.tool_shell_del({"name": name, "remove_remote": True, "timeout": 2})
            check(True, "ALLOW_REMOTE_DELETE=False 时闸门关闭")
        except Exception as e:  # noqa
            check("人工授权" not in str(e), "ALLOW_REMOTE_DELETE=False 时闸门关闭")
        finally:
            wsm.ALLOW_REMOTE_DELETE = old
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if fails:
        print("FAILED: %d" % len(fails))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(run())
