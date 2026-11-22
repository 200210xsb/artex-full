package db

import (
	"encoding/json"
	"testing"
)

// TestSaveMCPPreservesSecretsOnUpdate 走真实数据库验证「不丢密钥」：先存一条带密钥的
// MCP，再分别用「不传 env」和「传掩码占位符」更新，确认库里的密钥都还在。
// （不传 env 的那条对应 agent 的 update_mcp 工具只改名字的场景。）
func TestSaveMCPPreservesSecretsOnUpdate(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.SaveMCP(&MCPServer{
		Name: "t-mcp-secret", Transport: "http", URL: "http://127.0.0.1:9/x",
		Env: json.RawMessage(`{"X-API-Key":"ssk_realvalue"}`), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM mcp_servers WHERE id=$1`, id) })

	read := func() string {
		var env string
		if err := d.QueryRow(`SELECT env FROM mcp_servers WHERE id=$1`, id).Scan(&env); err != nil {
			t.Fatal(err)
		}
		return env
	}
	secret := func() string {
		var m map[string]string
		if err := json.Unmarshal([]byte(read()), &m); err != nil {
			t.Fatalf("unmarshal %q: %v", read(), err)
		}
		return m["X-API-Key"]
	}

	if got := secret(); got != "ssk_realvalue" {
		t.Fatalf("insert lost secret: %q", got)
	}

	// 1) 部分更新：只改名字，不带 env —— 密钥必须还在（原来会被写成 {}）。
	if _, err := d.SaveMCP(&MCPServer{
		ID: id, Name: "t-mcp-secret-2", Transport: "http", URL: "http://127.0.0.1:9/x",
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := secret(); got != "ssk_realvalue" {
		t.Fatalf("partial update wiped secret: %q (env=%s)", got, read())
	}

	// 2) 回显掩码后原样保存 —— 密钥必须还原成真值，而不是把占位符存进去。
	if _, err := d.SaveMCP(&MCPServer{
		ID: id, Name: "t-mcp-secret-2", Transport: "http", URL: "http://127.0.0.1:9/x",
		Env: json.RawMessage(`{"X-API-Key":"` + MCPSecretMask + `"}`), Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := secret(); got != "ssk_realvalue" {
		t.Fatalf("masked round-trip did not restore secret: %q (env=%s)", got, read())
	}

	// 3) 显式改密钥 —— 以提交值为准。
	if _, err := d.SaveMCP(&MCPServer{
		ID: id, Name: "t-mcp-secret-2", Transport: "http", URL: "http://127.0.0.1:9/x",
		Env: json.RawMessage(`{"X-API-Key":"ssk_newvalue"}`), Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := secret(); got != "ssk_newvalue" {
		t.Fatalf("explicit new secret not applied: %q", got)
	}
}

// TestListMCPForDisplayMasksSecrets 验证读出去的那份已掩码，而库里那份没被动过。
func TestListMCPForDisplayMasksSecrets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.SaveMCP(&MCPServer{
		Name: "t-mcp-display", Transport: "http", URL: "http://127.0.0.1:9/y",
		Env: json.RawMessage(`{"X-API-Key":"ssk_displaysecret","ARTEX_BIN":"/bin/x"}`), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM mcp_servers WHERE id=$1`, id) })

	list, err := d.ListMCPForDisplay()
	if err != nil {
		t.Fatal(err)
	}
	var found *MCPServer
	for _, m := range list {
		if m.ID == id {
			found = m
		}
	}
	if found == nil {
		t.Fatal("server not in display list")
	}
	var m map[string]string
	if err := json.Unmarshal(found.Env, &m); err != nil {
		t.Fatal(err)
	}
	if m["X-API-Key"] != MCPSecretMask {
		t.Fatalf("display list leaked secret: %q", m["X-API-Key"])
	}
	if m["ARTEX_BIN"] != "/bin/x" {
		t.Fatalf("non-secret value changed in display list: %q", m["ARTEX_BIN"])
	}
	// 库里那份必须仍是真值（掩码只发生在出口）。
	raw, err := d.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range raw {
		if s.ID == id {
			var raw map[string]string
			if err := json.Unmarshal(s.Env, &raw); err != nil {
				t.Fatal(err)
			}
			if raw["X-API-Key"] != "ssk_displaysecret" {
				t.Fatalf("stored secret changed: %q", raw["X-API-Key"])
			}
		}
	}
}
