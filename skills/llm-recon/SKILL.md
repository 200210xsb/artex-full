---
name: llm-recon
description: 做「大模型（LLM）资产测绘 / 未授权验证 / 密钥泄露排查」时调用。用于发现暴露的 Ollama、vLLM、ComfyUI、Dify、Langflow、Open WebUI 等推理与编排服务，按已知漏洞做版本比对，并在授权目标自身资产里排查泄露的 API Key。
mcps: ScopeSentry, browser
---

# LLM Recon（大模型资产与密钥测绘）

## 边界与红线（先读，违反即越界）

| 项 | 允许 | 禁止 |
|---|---|---|
| 目标范围 | 任务清单里明确列出的域名/IP/接口 | 清单外主机、云厂商共享域名、CDN 回源、关联公司 |
| 推理调用 | 每个服务**最多 2 次**、`max_tokens ≤ 16`、prompt 固定为 `hi`，只为证明"未授权可用" | 批量刷、跑基准、测额度、长上下文、流式轰炸、生成内容当战果 |
| 模型/权重 | 只读元数据（模型名、参数量、量化方式） | 下载权重、导出 GGUF/safetensors、整目录拉取 |
| 密钥 | 只**识别并登记**（类型、位置、掩码指纹） | **使用**、验证有效性、列模型、换积分、发给任何第三方、贴全文进报告 |
| 破坏性 | 版本比对、只读 GET | 写文件、装插件、执行命令、改配置、删模型 |
| 判定不清 | 按"禁止"处理，先问操作者 | 猜着打 |

命中以下任一情况**立即停止该方向**并上报：WAF 418/403 IpBlack、返回 401/403 的鉴权挑战、任何"命令执行成功"的迹象、任何真实凭据明文。

## 阶段 0：先联网做功课（不碰目标）

用 web_search 查最新情况，再动目标：
- 组件近 12 个月的 CVE 与利用条件（关键词：`ComfyUI RCE`、`Langflow CVE`、`Dify unauthorized`、`Open WebUI auth bypass`、`Ollama unauthorized`）
- 默认端口与指纹是否变化
- 官方 issue 里"未授权可访问"的报告

产出：一张「组件 → 版本 → 已知问题 → 只读验证方式」的表，写进任务产物后再开始探测。

## 阶段 1：发现暴露的推理 / 编排服务

指纹优先用**只读 GET**，不要一上来 POST。判定看状态码 + 响应体特征，命中记一条 fact。

| 组件 | 常见端口 | 只读判据 | 说明 |
|---|---|---|---|
| Ollama | 11434 | `GET /api/tags` → `{"models":[...]}`；`GET /api/version` | 未鉴权即可列模型是最常见暴露面 |
| vLLM / OpenAI 兼容 | 8000 / 8080 | `GET /v1/models` → `{"data":[{"id":...}]}` | 与 TGI、LM Studio 同构 |
| LM Studio | 1234 | `GET /v1/models` | 桌面端默认开在 0.0.0.0 的情况不少 |
| text-generation-webui | 7860 | `GET /` 标题含 `text-generation-webui` | |
| Open WebUI | 3000 / 8080 | `GET /api/config` → JSON 含 `features` | 常与 Ollama 成对出现 |
| ComfyUI | 8188 | `GET /system_stats` → `{"system":{...}}` | 工作流 RCE 历史多 |
| Dify | 80 / 5001 | `GET /console/api/setup` → `{"step":"finished"}` | 未初始化实例可直接建管理员 |
| Langflow | 7860 | `GET /api/v1/flows/` → 列表或 401 | 历史 RCE 多 |
| Flowise | 3000 | `GET /api/v1/chatflows` | 未鉴权可读工作流（含密钥节点） |
| FastChat | 8000 / 21002 | `GET /v1/models` | |
| Xinference | 9997 | `GET /v1/models`、`/api/v1/cluster/version` | |
| n8n | 5678 | `GET /rest/login` | 工作流里常硬编码 key |

线索来源（按优先级）：子域枚举（Subfinder/recon）→ 目标 JS/文档里出现的 `11434`/`8188`/`5001` 等端口 → 资产库已有 IP 的端口测绘（Nuclei）→ 页面里"AI 助手 / 知识库 / 工作流"功能反查后端。

## 阶段 2：未授权可用性验证（每个服务 ≤2 次推理）

按"最轻证明"顺序，命中即停：
1. `GET /v1/models` 或 `/api/tags` 能列模型 → **已构成未授权访问**，记录即可，不必再推理
2. 需要证明"能真的推理"时，发 **1 次** `POST /v1/chat/completions`：
   ```json
   {"model":"<上一步列出的模型名>","messages":[{"role":"user","content":"hi"}],"max_tokens":16}
   ```
   拿到 `choices[].message.content` 即证明，**不再发第二次**
3. Ollama 用 `POST /api/generate` `{"model":"...","prompt":"hi","stream":false,"options":{"num_predict":16}}`

证据只留：请求路径、状态码、响应里的 `model` 字段与**前 80 字符**输出，不贴全量返回。

## 阶段 3：已知漏洞（版本比对优先）

顺序：**取版本 → 比对影响范围 → 只读验证 → 才考虑最小利用证明**。
- 取版本：`/api/version`（Ollama）、`/system_stats`（ComfyUI）、`/api/v1/version`（Langflow）、页面 footer、静态资源 hash 反查
- 版本落在受影响区间才继续；不在区间就写"经版本比对不适用"并收尾
- 需要证明 RCE 时**只允许官方 PoC 的最小只读动作**（如 `id` / 读 1 个文件），**禁止**写文件、反弹 shell、装后门、留驻留
- 命中即停，把自己当成"证明到此为止"，不做横向

## 阶段 4：密钥测绘（只报不用）

**只在授权目标自身的资产里找**，不扫 GitHub、不查第三方泄露库（那属于跨目标）。

来源清单：
- 前端 bundle / sourcemap（`*.js.map` 常有源码与内联配置）
- `/.env`、`/config.json`、`/appsettings.json`、`/actuator/env`、`/actuator/heapdump`（只读响应头，不下载 dump）
- 暴露的 `.git/config`、`/.svn/`、`/backup.zip`、日志页
- 未鉴权的工作流接口（Flowise/Langflow/n8n 的 workflow JSON 里常直接写着 key）
- 错误页/调试页回显的环境变量

识别正则（命中即登记，**不要**把匹配到的整串写进报告）：

| 类型 | 模式 | 掩码写法 |
|---|---|---|
| OpenAI | `sk-[A-Za-z0-9]{20,}`、`sk-proj-` | `sk-abc…wxyz` |
| Anthropic | `sk-ant-[A-Za-z0-9_-]{20,}` | 同上 |
| AWS | `AKIA[0-9A-Z]{16}`（配对 secret 看 `aws_secret_access_key`） | `AKIA…WXYZ` |
| 阿里云 | `LTAI[0-9A-Za-z]{12,}` | |
| 腾讯云 | `AKID[0-9A-Za-z]{13,}` | |
| GitHub | `ghp_[A-Za-z0-9]{36}`、`github_pat_[A-Za-z0-9_]{22,}` | |
| HuggingFace | `hf_[A-Za-z0-9]{30,}` | |
| Google | `AIza[0-9A-Za-z_-]{35}` | |
| Azure | `AccountKey=[A-Za-z0-9+/=]{40,}` | |
| 通用私钥 | `-----BEGIN (RSA )?PRIVATE KEY-----` | 只记"存在私钥" |

**处理规则**：类型 + 文件/接口位置 + 掩码指纹 + 可能影响（如"该 key 具备模型调用权限"仅按类型推断，不验证）。**绝不**发起任何使用该 key 的请求；在结论里明确写"未使用、未验证有效性"。

## 判定与产出

- 每个服务一条 fact：`URL / 组件 / 版本 / 未授权能力 / 证据路径 / 停止原因`
- 漏洞一条 finding：只写"未授权可列模型/可推理"这类**可复现的最小事实**，不夸大
- 密钥单独列一节：类型、位置、掩码、建议轮换方
- 未测的写清原因（不可达 / WAF / 需凭据 / 超出范围）

## 常见误报

| 现象 | 别急着报 |
|---|---|
| 返回 200 但是 HTML 登录页 | 是前端壳，未鉴权不等于可用；看 API 路径 |
| `/v1/models` 返回空数组 | 可能鉴权后才有模型，或网关占位；结合 `/v1/chat/completions` 401 判断 |
| 418/403 IpBlack | WAF 风控/黑名单，**不是漏洞**，按规范终止 |
| 页面里出现 `sk-` 但长度/字符集不符 | 可能是示例串或 hash，必须过正则再报 |
| ComfyUI 能进 `/` 页面 | 只说明 UI 可达，RCE 要看版本与工作流接口 |
