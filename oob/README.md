# OOB — 回连带外信道

SSRF、XXE、盲 RCE、盲 SQLi 这类漏洞有个共同点：**响应里看不出来**。目标到底有没有替你发出那个请求，
只能靠它主动连回来证明。这个目录就是那个"连回来的地方"。

ARTEX 里有两处会用到它：

| 使用者 | 怎么用 |
|---|---|
| **agent**（MCP 工具） | `oob_new_session` → 拿载荷 → 投到目标 → `oob_wait` 等回连 |
| **人**（控制台页面） | 左侧「功能」→「回连监听」，看谁连来了、能做什么 |

两边读写的是同一份 `oob.db`，所以 agent 打出来的回连，人在页面上立刻能看到。

---

## 为什么单独一个进程

监听器必须**一直在**。而 ARTEX 的 MCP 子进程是随 worker 生命周期起落的——worker 干完活被回收，
端口就没人接了，回连打进来直接丢。所以这里拆成独立的常驻服务（`oob-listen`），
和 ARTEX 主服务互不依赖：

- ARTEX 重启 → 监听器照常收包，不丢数据
- 监听器挂了 → ARTEX 页面还能翻历史记录
- agent 没在跑 → 页面照样能看

`oob_mcp.py` 一份代码两种模式：

```bash
python3 oob_mcp.py                 # MCP server，走 stdio，给 agent 用
python3 oob_mcp.py --listen-only   # 纯监听，常驻，给 systemd / docker 用
```

---

## 裸机部署

```bash
cd oob
./install.sh                      # 默认装到 /opt/artex
ARTEX_DIR=/data/artex ./install.sh  # 装到别处
./install.sh --uninstall          # 卸载
```

脚本会：装 `oob_mcp.py` 到 `$ARTEX_DIR/bin/`、生成 `oob.conf`、写 systemd 单元、启动、自检。

想先试装一遍、不想动线上那套服务定义，用 `OOB_UNIT` 换个单元路径（服务名跟着变）：

```bash
ARTEX_DIR=/tmp/try OOB_UNIT=/etc/systemd/system/oob-try.service ./install.sh
```

```bash
systemctl status oob-listen
journalctl -u oob-listen -f
```

## 容器部署

`docker-compose.yml` 里已经带了 `oob` 服务，`docker compose up -d` 一起起来，
不用单独装。需要在 `.env` 里至少设一项：

```bash
OOB_PUBLIC_HOST=1.2.3.4        # 你的公网 IP 或域名
```

compose 里 artex 服务会把仓库的 `./oob` 只读挂到 `/app/oob`——MCP 是 stdio 子进程，
脚本得在 artex 容器里够得着。所以容器部署注册 MCP 时路径是 `/app/oob/oob_mcp.py`，
命中库是 `/app/data/oob/oob.db`（和 oob 容器写的是同一份文件）。

---

## 配置

`oob.conf`，或同名环境变量（环境变量优先级更高）：

| 键 | 默认 | 说明 |
|---|---|---|
| `OOB_PUBLIC_HOST` | 自动探测 | **最重要**。回连方要访问的地址。填成 NAT 内网地址（10.x）功能就是死的 |
| `OOB_PORTS` | `8889,18666,18667` | 监听端口，逗号分隔。多开几个是为了应对只放行特定出站端口的目标 |
| `OOB_DB` | `/opt/artex/data/oob/oob.db` | 命中库。**必须和 ARTEX 侧的 `OOB_DATA_DIR` 指到同一个文件** |
| `OOB_LOG` | `/var/log/oob-mcp.log` | 日志。容器里建议 `/dev/stderr` |
| `OOB_RETENTION_DAYS` | `7` | 命中保留天数 |
| `OOB_RECORD_NOISE` | `0` | 是否记录监听器自身的探测请求（调试用） |

> 云主机网卡的地址常是 `10.x` 内网地址，脚本自动探测的是**出口公网 IP**，
> 但如果装了 NAT 网关或有多个出口，还是要人工确认一遍。

---

## 能力分级是怎么判的

光有回连只能说明"目标能出网"，这跟"能把内网内容带回来"是两件事。所以投的不是一条普通载荷，
而是一条 **302 重定向链**，看回连方能走到第几跳：

```
cap_a1 ──302──▶ cap_a2 ──302──▶ cap_a3 ──401──▶ cap_a3 ──302──▶ cap_a4
                                                            (1MB 响应体)
```

| 走到哪 | 等级 | 含义 |
|---|---|---|
| 只到 a1 | L1 | 单向回连，典型盲 SSRF，拿不到响应内容 |
| 到 a2 | L3 | 会跟随一次重定向 |
| 到 a3 | L4 | 链式跟随，能被引到任意 http 下一跳 |
| 带凭证重试 a3 并到 a4 | L5 | 渲染型客户端：处理认证挑战 + 完整读取大响应，具备把内容带回来的条件 |

判定逻辑在 `server/oob.go` 的 `oobAssess()`，页面和 MCP 工具用的是同一套口径。

### 测不出来的东西

- **纯 DNS 查询、UDP 外发**：只有 HTTP 通道，看不到。要测这个得有自己的域名并放行 53/UDP。
- **能不能读目标本地文件**：`file:///etc/passwd` 本来就不会产生回连。收不到既是"不支持"、
  也是"支持但没回显"，**无法单向证明**。只认有回显的证据。
- **能不能执行命令**：那是反连 shell 的活儿，不是带外信道能回答的。

---

## 接入 ARTEX

监听器跑起来只是"收得到包"。要让 agent 能用，还得在 ARTEX 里注册这个 MCP 并给 agent 授权：

```bash
./register-mcp.sh                 # 自动探测容器/裸机，注册 + 授权给所有已有 agent
./register-mcp.sh --no-grant      # 只注册，授权自己在界面上点
./register-mcp.sh --dry-run       # 只打印将要执行的 SQL
```

裸机 `install.sh` 和仓库根的 `install.sh`（两种模式）都会自动调它，一般不用手跑。

**为什么这步不能省**：会话是 agent 用 `oob_new_session` 建的，监听器只认已经存在的会话
token；没有会话，所有回连都会按"噪音"丢弃。表现就是监听器日志有流量、页面却一片空白。

脚本干的事（手工执行等价）：

```sql
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, insecure)
VALUES ('OOB', 'stdio', '/usr/bin/python3',
        jsonb_build_array('/opt/artex/bin/oob_mcp.py'),      -- 容器里是 /app/oob/oob_mcp.py
        jsonb_build_object('OOB_DB', '/opt/artex/data/oob/oob.db'),  -- 容器里是 /app/data/oob/oob.db
        true, false)
ON CONFLICT (name) DO UPDATE
  SET args = EXCLUDED.args, env = EXCLUDED.env, enabled = true;
```

授权走 `agent_visibility`，`mcp_tool_name` 必须是空串而不是 NULL（唯一索引里带 NULL 就不去重，
重跑会堆重复行）。ARTEX 在下一次拉起 worker 时自动发现这个 server，不用重启主服务。

页面那边不需要额外配置——`server/oob.go` 只读打开库文件，路径由 `OOB_DATA_DIR` / `OOB_DB` 决定。
