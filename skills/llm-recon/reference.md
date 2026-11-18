# llm-recon — 参考手册

配合 `SKILL.md` 使用。这里放可直接复制的探测片段与判定样例。

## 1. 一屏指纹（只读，逐条打，命中即记）

```bash
# 把 BASE 换成目标，逐个组件试
BASE=https://target.example.com

# OpenAI 兼容（vLLM / TGI / LM Studio / FastChat / Xinference）
curl -s -m 8 "$BASE/v1/models" | head -c 300

# Ollama
curl -s -m 8 "$BASE/api/tags"    | head -c 300
curl -s -m 8 "$BASE/api/version"

# ComfyUI
curl -s -m 8 "$BASE/system_stats" | head -c 300

# Open WebUI
curl -s -m 8 "$BASE/api/config"  | head -c 300

# Dify（未初始化实例）
curl -s -m 8 "$BASE/console/api/setup"

# Langflow / Flowise / n8n 工作流
curl -s -m 8 "$BASE/api/v1/flows/" | head -c 300
curl -s -m 8 "$BASE/api/v1/chatflows" | head -c 300
curl -s -m 8 "$BASE/rest/login"
```

判定要点：**先看 content-type**。返回 `text/html` 的多半是前端壳或登录页，不能据此判定未授权。

## 2. 最小推理证明（每个服务最多 1 次）

```bash
# OpenAI 兼容
curl -s -m 20 "$BASE/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d '{"model":"MODEL_FROM_MODELS","messages":[{"role":"user","content":"hi"}],"max_tokens":16}'

# Ollama
curl -s -m 20 "$BASE/api/generate" \
  -H 'content-type: application/json' \
  -d '{"model":"MODEL_FROM_TAGS","prompt":"hi","stream":false,"options":{"num_predict":16}}'
```

证据只留：状态码、`model` 字段、输出前 80 字符。**不要**再发第二次，不要换 prompt 试能力。

## 3. 端口线索从哪来

1. 目标页面里的配置：搜 `11434`、`8188`、`5001`、`7860`、`3000`、`9997`、`1234`、`5678`
2. 前端 bundle 里的 baseURL：`grep -oE 'https?://[^"'\'' ]+(11434|8188|3000|5001|7860|9997)' js/*.js`
3. 子域：`ollama.`、`llm.`、`ai.`、`chat.`、`gpu.`、`workflow.`、`n8n.`、`dify.`、`comfy.`
4. 资产库里已有的 IP，用 Nuclei 的端口/指纹模板做一遍（限速，别打挂）

## 4. 密钥来源的具体路径

```
/.env
/.env.local
/config.json
/appsettings.json
/actuator/env
/actuator/configprops
/.git/config
/.git/HEAD
/static/js/*.js.map
/main.*.js
/backup.zip
/debug/vars
/console/api/setup
/api/v1/chatflows        # Flowise：节点里常直接存 key
/api/v1/flows/           # Langflow
/rest/workflows          # n8n
```

只读**前 4KB**，`head -c 4096`；命中 key 就停，不要继续翻。

## 5. 掩码与报告样例

```
类型    : OpenAI API Key
位置    : /static/js/main.4f2c.js（第 1 行，偏移 10233）
掩码    : sk-abc…wxyz
影响    : 若有效则可调用该组织的模型并计入账单（未验证）
处置    : 建议轮换；未使用、未验证
```

## 6. 与平台限制的交互

- 浏览器类工具走**平台捕获代理**（不是任务 VPN 出口），对"必须从指定 IP 出去"的项目，改用 curl/httpx 走任务出口
- 隧道内 DNS 已固定 IPv4（0.5.11+），域名偶发失败多为目标侧，不要据此判死
- 目标是共享出口 IP 时，`403 IpBlack` 属于 IP 信誉，不是你的链路问题
