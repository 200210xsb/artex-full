# Subfinder — 子域名收集 + 资产测绘 MCP

`recon_mcp.py` 是纯标准库实现的 stdio MCP，把 subfinder、字典爆破、Hunter 测绘、
DNS 解析与 HTTP 探活包装成 5 个工具，服务名 `Subfinder`。

## 工具

| 工具 | 做什么 | 需要 key |
|---|---|---|
| `subfinder_enum` | 被动枚举（chaos/quake 等被动源） | 视源而定 |
| `bruteforce_enum` | 主动字典爆破（多线程 getaddrinfo） | 否 |
| `hunter_enum` | Hunter（奇安信）资产测绘，积分制，pages 上限 3 | **是** |
| `dns_resolve` | DNS 批量解析 | 否 |
| `http_probe` | HTTP 存活探测（状态码/标题/指纹） | 否 |

## 依赖

- `subfinder` 二进制：默认 `./subfinder`（脚本同级）→ `/opt/artex/bin/subfinder` → `PATH`
- `subs.txt` 爆破字典：默认脚本同级（本目录自带）
- `provider-config.yaml`：`~/.config/subfinder/provider-config.yaml`，形如

  ```yaml
  chaos: []
  fofa:
    - "<key>"
  hunter:
    - "<key>"
  quake: []
  ```

  `hunter_enum` 只认 `hunter:` 顶格 + 缩进 `- <key>` 的写法；没 key 时只有
  无 key 的源可用。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `ARTEX_SUBFINDER_BIN` | 自动探测 | subfinder 二进制路径 |
| `ARTEX_SUBFINDER_PC` | `~/.config/subfinder/provider-config.yaml` | 被动源 key 配置 |
| `ARTEX_WORDLIST` | 脚本同级 `subs.txt` | 爆破字典 |
| `ARTEX_RECON_LOG` | `/var/log/subfinder-mcp.log` | 日志文件 |

## 注册

```bash
./register-mcp.sh
./register-mcp.sh --bin /x/subfinder --provider-config /y/provider-config.yaml
./register-mcp.sh --dry-run
```

## 自检

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dns_resolve","arguments":{"domains":["example.com"]}}}' \
  | python3 recon_mcp.py
```
