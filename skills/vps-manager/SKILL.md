---
name: vps-manager
description: 远程 VPS 运维。当需要连接、查看状态或操作远程服务器（SSH、Docker、systemd、磁盘/内存排查、ARL 资产侦察平台运维）时调用本 skill。
mcps: ScopeSentry, browser
---

# VPS 远程运维管理

统一管理远程服务器：SSH 连接、系统信息、服务状态、常用运维命令。

---

## 边界与禁止（Agent 必读）

| 禁止 | 说明 |
|---|---|
| 不得在未获用户明确指令时执行破坏性操作 | `rm -rf`、`dd`、`mkfs`、`shutdown`、清库 |
| 不得把私钥、密码、Token 打印到终端输出或写入报告 | 只引用密钥路径，不回显内容 |
| 不得主动重启生产容器或修改防火墙规则 | 需用户在本轮对话中显式要求 |
| 不得将本 skill 中的凭据用于 ARTEX 授权范围之外的资产 | 仅限下方「资产清单」列出的主机 |
| 连续 2 次命令失败即停止重试 | 换策略：看日志 / 查状态 / 报告用户 |

---

## 资产清单

### 1. 主力 VPS（laodn）

| 项目 | 值 |
|---|---|
| **别名** | `laodn` |
| **IP** | `106.54.218.129` |
| **端口** | 22 |
| **用户** | `root` |
| **系统** | OpenCloudOS 9.6 x86_64 |
| **内核** | 6.6.119-49.23.oc9.x86_64 |
| **认证** | 仅公钥（密码认证已禁用） |
| **私钥路径（容器内）** | `/app/skills/vps-manager/keys/laodn123.pem` |
| **内存 / 磁盘** | 3.6G / 60G |

#### 开放端口

| 端口 | 服务 | 说明 |
|---|---|---|
| 22 | SSH | 仅公钥认证 |
| 5003 | HTTPS | Docker ARL Web |
| 8888 | HTTP | ARL-Next updater（python3） |

> 防火墙为 `YJ-FIREWALL-INPUT` 黑名单链（只 REJECT 扫描 IP），INPUT 策略 ACCEPT。
> 实际开放端口 = 监听端口。另有 5173 ACCEPT 遗留规则。

#### 运行服务

| 服务 | 类型 | 用途 |
|---|---|---|
| `arl_web` | Docker | ARL 资产侦察平台，5003→443 |
| `arl_worker` | Docker | ARL Celery 工作节点 |
| `arl_scheduler` | Docker | ARL 任务调度 |
| `arl_rabbitmq` | Docker | ARL 消息队列（rabbitmq:3.8.19） |
| `arl_mongodb` | Docker | ARL 数据库（mongo:4.0.27） |
| `arl-updater` | Systemd | ARL-Next 更新服务，监听 8888 |

> Docker 镜像：`honmashironeko/arl-docker-all`
> 部署目录：`/opt/ARL-docker`（当前运行）、`/opt/ARL-Next`（新版，仅 updater 运行）

---

## 连接方式

**统一用 `ssh` 加 `-i` 指定私钥，禁止交互式密码。**

```bash
# 单条命令
ssh -i /app/skills/vps-manager/keys/laodn123.pem \
    -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
    root@106.54.218.129 "<command>"

# 多条命令（分号分隔）
ssh -i /app/skills/vps-manager/keys/laodn123.pem -o StrictHostKeyChecking=no \
    root@106.54.218.129 'echo "=== Docker ==="; docker ps; echo "=== 磁盘 ==="; df -h'
```

> **首次使用前**必须设置私钥权限，否则 ssh 会拒绝：
> ```bash
> chmod 600 /app/skills/vps-manager/keys/laodn123.pem
> ```
> 若报 `UNPROTECTED PRIVATE KEY FILE`，先执行上面的 chmod。

---

## 常用运维命令

### 系统状态

```bash
SSH="ssh -i /app/skills/vps-manager/keys/laodn123.pem -o StrictHostKeyChecking=no root@106.54.218.129"

$SSH 'cat /etc/os-release | head -3; uname -r'
$SSH 'uptime; echo ---; cat /proc/loadavg'
$SSH 'df -h; echo ---; free -h'
$SSH 'uptime -p'          # 开机时长
```

### Docker 管理

```bash
$SSH 'docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"'
$SSH 'docker logs --tail 50 arl_web'
$SSH 'docker exec -it arl_web bash'        # 进容器
$SSH 'docker restart arl_web'              # 重启（需用户明确要求）
$SSH 'docker stats --no-stream'
$SSH 'docker images'
```

### ARL 专项

```bash
$SSH 'docker exec arl_web cat /app/version 2>/dev/null'
$SSH 'docker exec arl_mongodb mongo --eval "db.adminCommand({listDatabases:1})"'
$SSH 'docker exec arl_rabbitmq rabbitmqctl list_queues'
$SSH 'docker exec arl_worker ps aux'
$SSH 'systemctl status arl-updater --no-pager | head -10'
$SSH 'journalctl -u arl-updater --since "1 hour ago" | tail -50'
```

### 端口与防火墙

```bash
$SSH 'ss -tlnp'                                            # 所有监听端口
$SSH 'ss -tlnp | grep python3'
$SSH 'iptables -L YJ-FIREWALL-INPUT -n --line-numbers | head -50'
$SSH 'iptables -L INPUT -n --line-numbers'                # 修改前必须先看
```

> OpenCloudOS 9.6 未启用 firewalld/nftables，使用 iptables 自定义链。

### 文件传输

```bash
# 上传
scp -i /app/skills/vps-manager/keys/laodn123.pem -o StrictHostKeyChecking=no \
    /path/to/local_file root@106.54.218.129:/root/

# 下载
scp -i /app/skills/vps-manager/keys/laodn123.pem -o StrictHostKeyChecking=no \
    root@106.54.218.129:/root/remote_file /tmp/
```

---

## 故障排查

| 现象 | 排查步骤 |
|---|---|
| `Permission denied` | 1) 确认私钥路径存在 2) `chmod 600` 3) 确认用 `-i` 指定 |
| `UNPROTECTED PRIVATE KEY FILE` | `chmod 600 <keypath>` |
| `Connection timed out` | 1) `ping 106.54.218.129` 2) 确认服务器在线 3) 云安全组是否放行 22 |
| 命令无输出 | 1) 加 `-v` 调试 2) 改用单条命令模式 3) 确认非交互 shell 可执行 |
| 服务未运行 | `systemctl status <svc>` → `journalctl -u <svc> -n 100` → 查最近变更 |

---

## 完成定义

一次运维任务完成的判据：
1. 已确认目标主机可达（命令有明确返回，非空）
2. 已获取目标服务的**真实状态**（`docker ps` / `systemctl status` 实测输出，非推测）
3. 若有变更，变更后**再次验证**状态
4. 向用户报告时给出**实测证据**（关键输出行），不夸大、不猜测

未满足以上任一条时，在报告中明确标注「未验证」。
