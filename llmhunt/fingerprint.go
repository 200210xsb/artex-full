package llmhunt

import (
	"regexp"
	"strings"
)

// 组件指纹：只读 GET 命中即判定，不做任何写操作。
type probe struct {
	vendor   string
	path     string
	wantBody string // 响应体需包含（空=只要 200 + JSON 即可）
	version  string // 从该路径另取版本
}

// probes 的顺序有意义：先打最轻、最确定的（列模型），再打页面级指纹。
var probes = []probe{
	{vendor: "ollama", path: "/api/tags", wantBody: `"models"`, version: "/api/version"},
	{vendor: "openai-compatible", path: "/v1/models", wantBody: `"data"`, version: ""},
	{vendor: "comfyui", path: "/system_stats", wantBody: `"system"`, version: ""},
	{vendor: "open-webui", path: "/api/config", wantBody: `"features"`, version: ""},
	{vendor: "dify", path: "/console/api/setup", wantBody: `"step"`, version: ""},
	{vendor: "langflow", path: "/api/v1/flows/", wantBody: "", version: ""},
	{vendor: "flowise", path: "/api/v1/chatflows", wantBody: "", version: ""},
	{vendor: "n8n", path: "/rest/login", wantBody: "", version: ""},
	// 下面这些是"模型服务/网关"：它们跑的就是 DeepSeek / GLM / Qwen 这类模型，
	// 未授权时能直接列模型（甚至直接推理），是这类项目里最有价值的一类暴露。
	{vendor: "librechat", path: "/api/config", wantBody: "", version: ""},
	{vendor: "lobechat", path: "/api/config", wantBody: "", version: ""},
	{vendor: "fastgpt", path: "/api/system/getInitData", wantBody: "", version: ""},
	{vendor: "ragflow", path: "/v1/system/version", wantBody: "", version: ""},
	{vendor: "anythingllm", path: "/api/ping", wantBody: "", version: ""},
}

// 密钥模式：命中即登记，报告只给掩码。
type keyPattern struct {
	name string
	re   *regexp.Regexp
}

var keyPatterns = []keyPattern{
	{"OpenAI", regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{20,}`)},
	{"Anthropic", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{"AWS AccessKey", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"阿里云 AccessKey", regexp.MustCompile(`LTAI[0-9A-Za-z]{12,}`)},
	{"腾讯云 SecretId", regexp.MustCompile(`AKID[0-9A-Za-z]{13,}`)},
	{"GitHub Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}`)},
	{"HuggingFace Token", regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Azure AccountKey", regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{40,}`)},
	{"私钥", regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)},
}

// mask 把密钥变成"前6…后4"，用于界面展示与人工核对，不泄露全文。
func mask(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s[:min(3, len(s))] + "…"
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 各平台"自身就会漏 key"的接口：这是现实中密钥泄漏的主渠道 —— 变量表、凭据表、
// 工作流定义里通常明文存着模型 key，而这些接口在不少部署里没有鉴权。全部只读 GET。
var vendorKeyPaths = map[string][]string{
	"flowise":     {"/api/v1/variables", "/api/v1/credentials", "/api/v1/apikey", "/api/v1/chatflows", "/api/v1/tools"},
	"langflow":    {"/api/v1/variables", "/api/v1/credentials", "/api/v1/flows/", "/api/v1/api_key/"},
	"dify":        {"/console/api/workspaces/current/members", "/console/api/apps", "/console/api/workspaces/current"},
	"n8n":         {"/rest/settings", "/rest/workflows", "/rest/credentials", "/rest/active-workflows"},
	"librechat":   {"/api/config", "/api/endpoints", "/api/models"},
	"open-webui":  {"/api/config", "/api/models", "/api/v1/auths/"},
	"fastgpt":     {"/api/system/getInitData", "/api/core/dataset/list"},
	"ragflow":     {"/v1/system/version", "/v1/user/info"},
	"anythingllm": {"/api/ping", "/api/v1/admin/workspaces"},
	// 网关：渠道列表里直接是上游 key（未鉴权版本大量存在）
	"openai-compatible": {"/api/status", "/api/channel/", "/api/user/self", "/v1/models"},
}

// 通用路径：不管什么组件都值得看一眼的误暴露文件。
var keyPaths = []string{
	"/.env",
	"/config.json",
	"/appsettings.json",
	"/actuator/env",
	"/.git/config",
	"/api/v1/chatflows",
	"/api/v1/flows/",
	"/rest/workflows",
}
