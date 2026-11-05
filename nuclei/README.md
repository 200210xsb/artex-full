# Nuclei — POC 模板库 + 漏洞验证 MCP

`nuclei_mcp.py` 是纯标准库实现的 stdio MCP，把 Nuclei 的模板库检索与实弹验证
包装成 agent 可直接调用的工具，服务名 `Nuclei`。

## 工具（9 个）

| 工具 | 做什么 |
|---|---|
| `poc_stats` | 模板库概况：总数、severity 分布、tag TOP20、最后更新时间 |
| `poc_search` | 按 keyword / tags / severity 过滤模板 |
| `poc_get` | 取单个模板 YAML 全文 + 解析出的 info |
| `poc_run` | 对目标跑指定模板，解析 JSONL 返回命中与汇总 |
| `poc_dangerous` | 只列「可能拿到 RCE / 命令执行 / 文件上传」的高价值模板 |
| `poc_update` | 拉模板库更新（`git pull --ff-only`），重建索引 |
| `fingerprint_probe` | 指纹探测：tech 模板优先，未命中回退 HTTP 头/标题粗判 |
| `poc_match` | 按指纹反查候选 POC（只留 critical/high/medium 且可落地） |
| `poc_auto_run` | 一站式：探测指纹 → 匹配 POC → 实弹验证（命中标注可落马） |

## 依赖

- `nuclei` 二进制：默认 `./nuclei`（脚本同级）→ `/opt/artex/bin/nuclei` → `PATH`
- 模板库：默认 `./nuclei-templates` → `../nuclei-templates` → `/opt/artex/nuclei-templates`
- 索引/日志：`/var/cache/nuclei-mcp`、`/var/log/nuclei-mcp.log`（不可写时自动退到临时目录）

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `ARTEX_NUCLEI_BIN` | 自动探测 | nuclei 二进制路径 |
| `ARTEX_NUCLEI_TEMPLATES` | 自动探测 | 模板库目录 |
| `ARTEX_NUCLEI_INDEX` | `/var/cache/nuclei-mcp` | 模板索引缓存目录 |
| `ARTEX_NUCLEI_LOG` | `/var/log/nuclei-mcp.log` | 日志文件 |

## 注册

```bash
./register-mcp.sh                        # 注册 + 授权全部 agent
./register-mcp.sh --bin /x/nuclei --templates /y/nuclei-templates
./register-mcp.sh --dry-run              # 只打印 SQL
```

注册只写 `mcp_servers` 与 `agent_visibility`；工具真正挂上要等 agent 领到下一个意图。

## 自检

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"poc_stats","arguments":{}}}' \
  | python3 nuclei_mcp.py
```
