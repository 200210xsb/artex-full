# WebShell — 会话管理 MCP

`webshell_mcp.py` 是 ARTEX 的 WebShell 会话服务端，部署在 `/opt/artex/bin/webshell_mcp.py`，
以 stdio 方式挂成 MCP（服务名 `Webshell`），控制台左侧「功能 → WebShell」页面
（`server/webshell.go`）与它共用同一份会话库：

```
/opt/artex/data/webshells.json   # 0600，字段名两侧必须逐字一致
```

两边是同一套载荷协议的两份实现：Go 侧给页面用（点一下就有响应），Python 侧给 agent 用。
**任何一侧改了协议，另一侧必须同步**，否则同一匹马在页面和 MCP 上的行为会不一致。

## 工具

| 工具 | 做什么 |
|---|---|
| `payload_list` / `payload_get` | 取内置载荷（`/opt/artex/payloads/webshell/{php,jsp,aspx}`） |
| `shell_add` | 登记会话（`name/url/type/password/method/header/note/remote_path`） |
| `shell_list` | 列会话（不返回参数名与 header 值） |
| `shell_exec` | 执行命令 / 代码，自动剥标记与 base64 包装 |
| `shell_upload` / `shell_download` | 分块写文件 / 读文件 |
| `shell_del` | 删会话。**默认只摘登记**，`remove_remote=true` 才动远端 |

## 两个容易踩的点

**1. 删会话默认不动远端。** 马留不留由人决定，工具不替人做主。`remove_remote=true`
时才走：删马文件（php 用 `unlink` 自删，jsp/aspx 用 `rm -f` / `del`）→ 删该会话
`shell_upload` 上传过的残留（`artifacts` 清单）→ 再请求一次 URL 复查打不通 → 摘登记。
远端没清干净会报错并保留登记，确认要丢弃登记得再传 `force=true`。

**2. 马自身路径不能用 `__FILE__`。** 马是 eval 执行的，`__FILE__` 会变成
`/var/www/x.php(17) : eval()'d code` 这种伪路径，`unlink` 静默失败。改用
`$_SERVER['SCRIPT_FILENAME']` → `get_included_files()[0]` → `__FILE__` 三级回退加
`realpath`。命令型（jsp/aspx）拿不到这个，所以 `remote_path` 必须登记时填对。

## 载荷与说明注释

库里每个载荷文件开头都有一段 `@summary / @scene / @perm / @bypass / @param / @mcp`
注释，那是给本机的人和 agent 看的。`payload_get` 下发前会把这段剥掉（只留 `<?php`），
`payload_list` 仍从库里读它当元信息——**落到目标上的文件不带说明书**。

## 部署

```bash
install -m 0755 webshell_mcp.py /opt/artex/bin/webshell_mcp.py
python3 -c "import py_compile;py_compile.compile('/opt/artex/bin/webshell_mcp.py',doraise=True)"
```

改完不用重启 ARTEX：MCP 子进程随 worker 生命周期起落，下一轮任务就是新代码；
页面侧（`server/webshell.go`）改动才需要重新编译部署。
