# MCP 工具链 — 一条命令补齐扫描与拿 shell 的能力

ARTEX 本体是一个单二进制（前端已内嵌），**但「扫描 / 子域枚举 / 拿 shell / 路径爆破」
这些能力不在二进制里**——它们由外挂的 stdio MCP 子进程提供。本目录就是把这套东西
一次装齐的入口：

| MCP | 脚本 | 提供的能力 |
|---|---|---|
| `Nuclei` | `nuclei_mcp.py` | POC 模板库检索、指纹探测、实弹验证、一键「指纹→匹配→验证」 |
| `Subfinder` | `recon_mcp.py` | 被动子域枚举、字典爆破、Hunter 测绘、DNS 解析、HTTP 探活 |
| `Webshell` | `webshell_mcp.py` | 会话登记、命令执行、文件管理（脚本随包，payload 自备） |
| `WebPath` | `webpath_mcp.py` | 站点路径枚举（软 404 基线 + 硬限速） |
| `OOB` | `oob_mcp.py` | 带外回连会话（需要公网可达的监听端口） |

> `Webshell` 的脚本随包分发，但它的 payload 库（可直接落地的马）不入库、也不进 Release 包：
> `payload_list` 初始为空。把自有 payload 放到 `payloads/webshell/<php|jsp|aspx>/`，
> 或用 `ARTEX_WEBSHELL_PAYLOAD_DIR` 指到别处。

> 只装 ARTEX 不装这些：平台能开、能建任务、能对话，但 agent 手里没有扫描与实战工具。

## 一键安装

解压 Release 包后（或从仓库根目录）：

```bash
# 裸机：装到 /opt/artex/bin + /opt/artex，自动下载 nuclei/subfinder/模板库，并注册进数据库
# 默认装五个（Webshell 只装脚本，payload 自备）
sudo ./mcp/install-mcp.sh

# 装到任意目录（免 root，适合单机试用）
./mcp/install-mcp.sh --bin-dir ./bin --data-dir .

# 离线：只铺脚本并注册，扫描器自备
./mcp/install-mcp.sh --no-download

# 只装其中几个
./mcp/install-mcp.sh --only nuclei,recon

# 只铺文件、不动数据库
./mcp/install-mcp.sh --no-register
```

安装完成后到页面「系统 → MCP」应能看到五个服务且已启用；首次使用时 MCP 子进程
由 agent 领到意图时拉起，工具才会写进 `mcp_tools_cache`。

## 前置依赖

| 依赖 | 用途 | 缺失时的影响 |
|---|---|---|
| `python3` | 5 个 MCP 本体都是纯标准库 Python | 全部 MCP 起不来 |
| `nuclei` + `nuclei-templates` | Nuclei MCP | `poc_*` 工具报错（约 137 MB + 100 MB） |
| `subfinder` | Subfinder MCP 的被动枚举 | `subfinder_enum` 失败（爆破/解析仍可用） |
| `curl`/`wget`、`unzip`、`git` | 下载与解包 | 对应步骤跳过，可改用 `--no-download` |
| `~/.config/subfinder/provider-config.yaml` | chaos/fofa/hunter 的 key | 只影响需要 key 的源 |

## 国内网络

`github.com` 直连常常超时，脚本支持换基址（前缀镜像也行）：

```bash
./mcp/install-mcp.sh --github-base https://ghfast.top/https://github.com
# 或
ARTEX_GITHUB_BASE=https://ghproxy.net/https://github.com ./mcp/install-mcp.sh
```

## 目录结构（Release 包内）

```
mcp/
├── install-mcp.sh          # 一键安装
├── nuclei/                 # Nuclei MCP + register-mcp.sh + README
├── recon/                  # Subfinder MCP + subs.txt 字典 + register-mcp.sh
├── webshell/               # WebShell MCP + register-mcp.sh（payload 自备，不入库）
├── oob/                    # OOB MCP + 监听器安装脚本
└── webpath/                # WebPath MCP + register-mcp.sh
```

每个子目录都能独立使用：`./mcp/nuclei/register-mcp.sh --dry-run` 只打印要执行的 SQL，
适合先看清再落地。

## 常见问题

- **装完页面里看不到工具**：MCP 是「随意图 spawn」的，先让某个 agent 领一条意图，再查
  `select name, count(*) from mcp_tools_cache group by name`。
- **容器部署**：进容器执行 `./mcp/install-mcp.sh --bin-dir /app/bin --data-dir /app`，
  注册脚本会自动识别 `/app` 路径（`/.dockerenv`）。
- **Windows**：脚本是 bash，请用 WSL；Windows 原生请手工把 `*_mcp.py` 铺好并按各
  子目录 README 里的 SQL 注册。
- **卸载**：删掉 `mcp_servers` 里对应行（或页面里禁用），脚本与扫描器手工删除即可。
