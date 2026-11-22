package db

import (
	"encoding/json"
	"strings"
)

// MCP 的 env 是一整块 JSON 的键值对（远程模式里就是请求头，stdio 模式里就是环境变量），
// 里面既有密钥（X-API-Key / Authorization / token…）也有路径（ARTEX_WORDLIST…）。
//
// 这里解决两件事：
//
//  1. 读出去时，密钥不该明文出现在浏览器里。LLM profile 走的是 api_key_hint（只回
//     「…末四位」），MCP 的 env 是个 blob，没有专门字段可借道，于是按**键名**判定
//     哪些值算密钥，替换成占位符；路径之类的普通值照原样回，编辑框仍然有用。
//
//  2. 写回去时，占位符要还原成库里存的真值。编辑框是「读出来什么就原样提交什么」，
//     不还原就会把占位符存进库，把真密钥顶掉——所以 SaveMCP 更新时按占位符逐键
//     保留旧值。同理，整块 env 为空（没带 env 的部分更新，例如 agent 的 update_mcp
//     工具只改了名字）时保留库里整块 env，而不是写成 {} 把密钥清空。
//
// 判定依据是键名，所以自定义的密钥名请带上 KEY/TOKEN/SECRET/PASSWORD/AUTH/CREDENTIAL
// 之类的字样；非密钥的键（如 ARTEX_NUCLEI_BIN）不受影响。

// MCPSecretMask 是回给前端、代替密钥真值的占位符。写入时见到它即表示「该键保持原值」。
// 它刻意长得不像任何真实凭据，避免与用户自己填的值撞车。
const MCPSecretMask = "••••••（已保存，未回显）"

// mcpSecretKeyHints 是判定「这个 env 键装的是密钥」的关键词（键名大写后匹配）。
var mcpSecretKeyHints = []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "AUTH", "CREDENTIAL"}

// isSecretEnvKey 报告这个 env 键的值是否属于不该明文回显的凭据。
func isSecretEnvKey(key string) bool {
	k := strings.ToUpper(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	for _, hint := range mcpSecretKeyHints {
		if strings.Contains(k, hint) {
			return true
		}
	}
	return false
}

// maskMCPEnv 返回一份 env 副本，其中疑似密钥的值被换成占位符。
// 解析失败时原样返回：宁可不动，也不要因为格式怪就把配置弄坏。
func maskMCPEnv(env []byte) []byte {
	if len(env) == 0 {
		return env
	}
	var m map[string]any
	if err := json.Unmarshal(env, &m); err != nil {
		return env
	}
	changed := false
	for k, v := range m {
		if !isSecretEnvKey(k) {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		m[k] = MCPSecretMask
		changed = true
	}
	if !changed {
		return env
	}
	out, err := json.Marshal(m)
	if err != nil {
		return env
	}
	return out
}

// mergeMCPEnv 把前端提交上来的 env 与库里存的 env 合并，返回最终要落库的那份：
//
//   - incoming 为空（没带 env 的部分更新）→ 保留库里整块 env；
//   - incoming 里某个键的值是占位符 → 该键保留库里存的值；
//   - 其余键以 incoming 为准（新增/修改/删除都按前端的意思来）。
//
// 前提：stored 与 incoming 都是 JSON 对象。
func mergeMCPEnv(stored, incoming []byte) []byte {
	if len(incoming) == 0 {
		return stored
	}
	var inc map[string]any
	if err := json.Unmarshal(incoming, &inc); err != nil {
		// 解析不了就按原样写：调用方传的就是非 JSON，保留调用方的语义。
		return incoming
	}
	if len(inc) == 0 {
		// 明确传了空对象：视为「本次不打算改 env」，保留库里那份。
		if len(stored) == 0 {
			return []byte("{}")
		}
		return stored
	}
	var old map[string]any
	if len(stored) > 0 {
		_ = json.Unmarshal(stored, &old)
	}
	if old == nil {
		old = map[string]any{}
	}
	for k, v := range inc {
		if s, ok := v.(string); ok && s == MCPSecretMask {
			if prev, exists := old[k]; exists {
				old[k] = prev // 占位符 = 保持原值
			}
			continue
		}
		old[k] = v
	}
	out, err := json.Marshal(old)
	if err != nil {
		return incoming
	}
	return out
}
