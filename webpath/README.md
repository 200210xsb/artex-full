# WebPath —— 站点路径枚举 MCP

给 ARTEX 的执行者一套**带软 404 判定、带限速、走录制代理**的目录扫描能力。

## 为什么需要

平台原先只有 DNS 层的子域爆破（`Subfinder.bruteforce_enum` 拼 `<前缀>.<根域>`），
**没有站点路径/目录枚举工具**。想摸清一个站点有哪些目录与接口的执行者只能手写
`for` 循环 curl 去猜，代价有三个：

1. **请求速率不受控**。2026-11-03 的事故就是这么来的：执行者在枚举前端 JS chunk
   文件名，速率涨到每秒几十个，录制代理排队、内存顶到 cgroup 上限，
   **整机失联**（连 sshd 都不再发 banner），只能去控制台重启。
2. **判定粗糙**。只看状态码会把「软 404」（所有路径都回 200 + 同一个页面）误判成
   处处有内容，整站报满假阳性。
3. **没有证据**。手工 curl 的请求如果绕开代理，就没法绑成漏洞证据。

## 工具

| 工具 | 作用 |
|---|---|
| `mcp__WebPath__path_enum` | 站点路径枚举（主工具） |
| `mcp__WebPath__path_baseline` | 只取某站点的软 404 基线 |
| `mcp__WebPath__webpath_selftest` | 自检（起本地假站验证判定，不碰任何目标） |

## 判定逻辑

先请求一个随机不存在的路径取**基线**（状态码 / 正文长度 / 正文哈希），再逐条比对：

| 情形 | 判定 |
|---|---|
| 状态码与基线不同，且不是 404 | **命中**（路径很可能存在） |
| 状态码与基线相同、长度差 ≥ max(24, 基线长度×8%) | **命中**（`len_diff`，软 404 的破绽） |
| 状态码长度都像、哈希不同 | **命中**（`hash_diff`） |
| 三者全同 | 视为不存在 |
| 状态码是 404 且与基线不同 | 归入「**差异化错误页**」——路径多半不存在，但错误页常泄露技术栈 |

403 / 401 / 405 / 5xx 与 3xx 会单独标 ★，并给出 `Location`（跳登录页的 `returnUrl`
通常直接暴露内部路由结构）。

**软 404 全站命中时会明确警告**：基线是 200 且六成以上候选与基线一致 → 输出
「该站疑似软 404，本次结果不可靠，请改用 JS 逆向」。

## 安全与稳定

- **硬限速**：令牌桶，默认 20 次/秒、并发 8、单次最多 200 条路径（上限 3000）。
  这是硬约束，不要放开——平台机器内存有限，全速枚举能把整机拖死。
- **走录制代理**：启动时探测 `127.0.0.1:8788` 是否在监听；在监听就走它并信任其 CA，
  枚举到的流量会进流量库，可事后 `bind_finding_traffic` 当证据；不在监听就直连，
  不因代理不可用而整体失败。
- **默认不跟随重定向**：3xx 的状态码与 `Location` 本身就是枚举结果，跟随就丢了。
- 只读正文指纹（长度 + 哈希 + 标题），不留正文，单响应最多读 512KB。

## 安装

裸机：

```bash
install -m 0755 webpath/webpath_mcp.py /opt/artex/bin/webpath_mcp.py
./webpath/register-mcp.sh
```

容器：把 `./webpath` 挂进 `/app/webpath`，再执行 `./webpath/register-mcp.sh`。

验证：

```bash
# 自检（不碰任何目标）
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"webpath_selftest","arguments":{}}}' \
  | python3 /opt/artex/bin/webpath_mcp.py

# 确认工具真的挂到 agent 上了
select tool_name from mcp_tools_cache where server_id =
  (select id from mcp_servers where name='WebPath');
```

## 实测效果

对 `https://open.ys7.com` 用 40 条候选、10 次/秒：

```
目标: https://open.ys7.com   出口: 录制代理(流量已入库)   候选: 40   实际请求: 40   耗时: 3.1s
软404 基线: 状态码=200 长度=43 哈希=5c9a2dc1af86
命中 12 条（路径很可能存在）:
  /console/upload  [302] len=73 ★高价值  → /auth?r=...&returnUrl=/console/upload 依据=status_diff
  ...
差异化错误页 14 条（路径多半不存在，但错误页本身泄露信息）：
  「Apache Tomcat - Error report」×14，例：/api/file, /api/upload.php, /api/upload
```

两个结论直接落地：`/console/` 是受认证网关保护的 SPA 路由前缀（302 跳 `/auth` 且带
`returnUrl`）；`/api/` 由 Tomcat 接管——**后端技术栈就这样泄露了**。
