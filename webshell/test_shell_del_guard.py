# -*- coding: utf-8 -*-
"""webshell_mcp.py 删马/摘登记护栏的回归测试。

对应 0.3.40 的口径（远端留不留由人决定，agent 一律不主动删）：
  - 默认调用 shell_del      -> 只清本次分析上传的临时探针，马与登记都保留
  - remove_remote=true 无授权 -> 拒绝（远端不动、登记保留）
  - drop_registration=true 无授权 -> 拒绝（登记保留）
  - 两个破坏性动作带 human_approved=true -> 闸门放行
  - shell_exec 删本会话已登记的落地马 -> 拒绝（不能绕开 shell_del 直接 rm）
  - shell_exec 删别的路径 / 删临时探针 -> 放行
  - 闸门总开关 ALLOW_REMOTE_DELETE=False -> 两条守卫都关
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


def _mk_store(tmpdir, name, remote_path="", artifacts=None):
    p = os.path.join(tmpdir, "webshells.json")
    sess = {
        "url": "http://127.0.0.1:9/x.php",
        "type": "php",
        "password": "ptest",
        "method": "POST",
        "header": {},
        "note": "test",
    }
    if remote_path:
        sess["remote_path"] = remote_path
    if artifacts is not None:
        sess["artifacts"] = list(artifacts)
    with open(p, "w", encoding="utf-8") as f:
        json.dump({name: sess}, f)
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
        horse = "/var/www/html/static_de02d181.php"
        path = _mk_store(tmp, name, remote_path=horse, artifacts=[])
        wsm.STORE_PATH = path
        wsm._MODE_CACHE.clear()

        # 1) 默认调用：只清临时件，马与登记都保留
        try:
            wsm.tool_shell_del({"name": name})
            check(True, "默认调用放行（只清临时件）")
        except Exception as e:  # noqa
            check(False, "默认调用应放行，实际 %r" % (e,))
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
        check(name in store, "默认调用后本机登记保留（页面仍看得到）")
        check(store.get(name, {}).get("remote_path") == horse, "默认调用后落地马路径仍在")

        # 2) remove_remote=true 但没有人工授权 -> 必须拒绝
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

        # 3) drop_registration=true 但没有人工授权 -> 必须拒绝
        try:
            wsm.tool_shell_del({"name": name, "drop_registration": True})
            check(False, "无授权时 drop_registration 应被拒绝")
        except wsm.ToolError as e:
            check("人工授权" in str(e), "无授权时拒绝摘登记并提示需人工授权")
        except Exception as e:  # noqa
            check(False, "无授权时应抛 ToolError，实际 %r" % (e,))
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
        check(name in store, "拒绝后本机登记保留")

        # 4) 授权位齐全 -> 闸门放行（走远端清理分支，目标是不可达地址，
        #    预期会因远端没清干净报错，但那是清理阶段的错，不是闸门的错）
        _mk_store(tmp, name, remote_path=horse, artifacts=[])
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

        # 5) 授权摘登记：带 human_approved 时应真的摘掉
        _mk_store(tmp, name, remote_path=horse, artifacts=[])
        wsm._MODE_CACHE.clear()
        try:
            wsm.tool_shell_del({
                "name": name,
                "drop_registration": True,
                "human_approved": True,
            })
            check(True, "带 human_approved 时允许摘登记")
        except Exception as e:  # noqa
            check(False, "带 human_approved 时应允许摘登记，实际 %r" % (e,))
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
        check(name not in store, "授权后本机登记已摘除")

        # 6) shell_exec 删已登记的落地马（或其父目录）-> 拒绝
        _mk_store(tmp, name, remote_path=horse, artifacts=[])
        wsm._MODE_CACHE.clear()
        for cmd in (
            "rm -f %s" % horse,
            "rm -rf /var/www/html && echo done",
            "unlink('%s')" % horse,
            "del /f /q \"C:\\inetpub\\static_de02d181.php\"",
        ):
            try:
                wsm.tool_shell_exec({"name": name, "cmd": cmd})
                check(False, "shell_exec 删落地马应被拒绝: %s" % cmd)
            except wsm.ToolError as e:
                # 守卫拦下的消息里含「落地马」；网络错误（目标不可达）不算拦
                check("落地马" in str(e), "shell_exec 删落地马被拒绝: %s" % cmd)
            except Exception as e:  # noqa
                check(False, "shell_exec 删落地马应抛 ToolError，实际 %r" % (e,))

        # 7) shell_exec 删别的路径 / 常规命令 -> 不被守卫拦
        #    （目标不可达会报网络错误，那是正常的，只要不是守卫拦的即可）
        for cmd in (
            "rm -f /tmp/probe_tmp.php",
            "ls -la /var/www/html",
            "id",
        ):
            try:
                wsm.tool_shell_exec({"name": name, "cmd": cmd, "timeout": 2})
                check(True, "shell_exec 常规命令放行: %s" % cmd)
            except wsm.ToolError as e:
                check("落地马" not in str(e),
                      "shell_exec 常规命令不该被守卫拦: %s（%s）" % (cmd, e))
            except Exception as e:  # noqa
                check("落地马" not in str(e),
                      "shell_exec 常规命令不该被守卫拦: %s（%r）" % (cmd, e))

        # 8) 闸门总开关能关掉：delete 守卫随之关闭
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
