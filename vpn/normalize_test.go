package vpn

import (
	"strings"
	"testing"
)

func TestNormalizeRewritesRemovedOptions(t *testing.T) {
	raw := strings.Join([]string{
		"client",
		"dev tun",
		"proto udp",
		"remote 106.75.32.220 1194",
		"ns-cert-type server",
		"comp-lzo",
		"auth-user-pass",
	}, "\n")

	out, notes := Normalize(raw, "/tmp/auth.txt")

	if strings.Contains(out, "ns-cert-type") {
		t.Error("ns-cert-type 仍然存在，OpenVPN 2.6+ 会拒绝该选项")
	}
	if !strings.Contains(out, "remote-cert-tls server") {
		t.Error("缺少 remote-cert-tls server 替代")
	}
	if strings.Contains(out, "comp-lzo") {
		t.Error("comp-lzo 仍然存在：服务端不压缩时会导致全部丢包")
	}
	if !strings.Contains(out, "allow-compression no") {
		t.Error("缺少 allow-compression no")
	}
	if !strings.Contains(out, "auth-user-pass /tmp/auth.txt") {
		t.Errorf("账号文件未注入：\n%s", out)
	}
	if !strings.Contains(out, "remote 106.75.32.220 1194") {
		t.Error("remote 行被破坏")
	}
	if len(notes) < 3 {
		t.Errorf("应记录 3 条修正说明，实际 %v", notes)
	}
}

func TestNormalizeAddsDataCiphersForLegacyCBC(t *testing.T) {
	raw := "client\ndev tun\nproto tcp\nremote 123.57.208.95 1192\ncipher AES-128-CBC\nauth-user-pass\n"
	out, notes := Normalize(raw, "/tmp/a")

	if !strings.Contains(out, "data-ciphers AES-128-CBC") {
		t.Errorf("CBC 未进 data-ciphers，2.6+ 协商会失败：\n%s", out)
	}
	if !strings.Contains(out, "cipher AES-128-CBC") {
		t.Error("原有 cipher 行不应被删掉")
	}
	if !hasNote(notes, "data-ciphers") {
		t.Errorf("未记录 data-ciphers 修正：%v", notes)
	}
}

func TestNormalizeKeepsExistingDataCiphers(t *testing.T) {
	raw := "cipher AES-128-CBC\ndata-ciphers AES-128-CBC:CHACHA20-POLY1305\n"
	out, _ := Normalize(raw, "")
	if strings.Count(out, "data-ciphers") != 1 {
		t.Errorf("不应重复添加 data-ciphers：\n%s", out)
	}
}

func TestNormalizeDoesNotInjectAuthForCertOnlyConfig(t *testing.T) {
	// 纯证书配置里没有 auth-user-pass，注入反而会让 openvpn 去等一份服务端
	// 根本不会索取的账号。
	out, _ := Normalize("client\ndev tun\nremote 1.2.3.4 1194\n", "/tmp/a")
	if strings.Contains(out, "auth-user-pass") {
		t.Errorf("纯证书配置不应注入 auth-user-pass：\n%s", out)
	}
}

func TestRemoteAddr(t *testing.T) {
	if h, ok := RemoteAddr("# comment\nremote 106.75.32.220 1194\n"); !ok || h != "106.75.32.220" {
		t.Errorf("RemoteAddr() = %q,%v", h, ok)
	}
	if _, ok := RemoteAddr("client\ndev tun\n"); ok {
		t.Error("没有 remote 行时应返回 false")
	}
}

func hasNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}
