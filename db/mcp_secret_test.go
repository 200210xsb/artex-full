package db

import (
	"encoding/json"
	"testing"
)

// TestMaskMCPEnv 只掩掉看起来像密钥的键，普通值（路径等）照旧回显——编辑框还要靠它们
// 显示这个 MCP 配了哪些东西。
func TestMaskMCPEnv(t *testing.T) {
	in := []byte(`{"X-API-Key":"ssk_realsecret","ARTEX_NUCLEI_BIN":"/opt/artex/bin/nuclei","NODE_EXTRA_CA_CERTS":"/opt/artex/ca.pem"}`)
	out := maskMCPEnv(in)
	var m map[string]string
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["X-API-Key"] != MCPSecretMask {
		t.Fatalf("secret not masked: %q", m["X-API-Key"])
	}
	if m["ARTEX_NUCLEI_BIN"] != "/opt/artex/bin/nuclei" {
		t.Fatalf("non-secret value changed: %q", m["ARTEX_NUCLEI_BIN"])
	}
	// NODE_EXTRA_CA_CERTS 名字里没有密钥字样 → 不掩。
	if m["NODE_EXTRA_CA_CERTS"] != "/opt/artex/ca.pem" {
		t.Fatalf("non-secret value changed: %q", m["NODE_EXTRA_CA_CERTS"])
	}
}

// TestMergeMCPEnvKeepsStoredSecrets 覆盖三种回写场景：占位符保留旧值、没带 env
// 保留整块、以及普通修改以提交为准。这是 MCP 密钥不被「顺手保存」顶掉的关键。
func TestMergeMCPEnvKeepsStoredSecrets(t *testing.T) {
	stored := []byte(`{"X-API-Key":"ssk_real","ARTEX_BIN":"/bin/x"}`)

	// 1) 占位符 → 还原成库里的真值
	got := mergeMCPEnv(stored, []byte(`{"X-API-Key":"`+MCPSecretMask+`"}`))
	var m map[string]string
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["X-API-Key"] != "ssk_real" {
		t.Fatalf("placeholder did not keep stored secret: %q", m["X-API-Key"])
	}

	// 2) 没带 env（部分更新，如 agent 的 update_mcp 只改名字）→ 整块保留
	got = mergeMCPEnv(stored, []byte(`{}`))
	if string(got) != string(stored) {
		t.Fatalf("empty env did not keep stored env:\n got %s\nwant %s", got, stored)
	}

	// 3) 普通修改以提交为准，新键也进得去
	got = mergeMCPEnv(stored, []byte(`{"ARTEX_BIN":"/bin/new","NEW":"1"}`))
	m = map[string]string{}
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["ARTEX_BIN"] != "/bin/new" || m["NEW"] != "1" {
		t.Fatalf("incoming values not applied: %v", m)
	}
	if m["X-API-Key"] != "ssk_real" {
		t.Fatalf("stored secret lost on normal edit: %q", m["X-API-Key"])
	}
}

// TestIsSecretEnvKey 锁住「哪些键算密钥」的判定：键名带关键词才算，纯路径不算。
func TestIsSecretEnvKey(t *testing.T) {
	for _, k := range []string{"X-API-Key", "Authorization", "MY_TOKEN", "db_password", "AUTH_HEADER"} {
		if !isSecretEnvKey(k) {
			t.Fatalf("%q should be treated as secret", k)
		}
	}
	for _, k := range []string{"ARTEX_NUCLEI_BIN", "NODE_EXTRA_CA_CERTS", "ARTEX_WORDLIST", ""} {
		if isSecretEnvKey(k) {
			t.Fatalf("%q should NOT be treated as secret", k)
		}
	}
}
