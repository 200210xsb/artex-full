package vpn

import (
	"fmt"
	"strings"
)

// Normalize rewrites an operator-supplied .ovpn so OpenVPN 2.6+ accepts it.
//
// The configs the bounty platforms hand out were generated years ago, and the
// options they rely on have since been removed or changed meaning. Feeding one
// straight to a modern openvpn either refuses to start (unrecognized option) or
// — worse — connects while silently dropping every packet, because the client
// still expects LZO framing the server never sends. Both failures look like
// "the VPN is broken" from the outside, so the rewrite happens here, once, and
// the notes are surfaced in the UI instead of being buried in a log file.
//
// authPath replaces the bare `auth-user-pass` (which would prompt on a tty) with
// a file the supervisor writes from the stored credentials.
func Normalize(raw, authPath string) (out string, notes []string) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	res := make([]string, 0, len(lines)+4)
	haveDataCiphers := false
	legacyCipher := ""
	sawAuthUserPass := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		field := ""
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			field = strings.ToLower(strings.Fields(trimmed)[0])
		}

		switch {
		case field == "ns-cert-type":
			// Removed in OpenVPN 2.6; remote-cert-tls is the supported spelling.
			res = append(res, "remote-cert-tls server")
			notes = append(notes, "ns-cert-type server → remote-cert-tls server（2.6 已移除该选项）")
			continue
		case strings.HasPrefix(field, "comp-lzo"):
			// These servers do not compress. A client that still expects LZO
			// decodes ordinary packets as compressed frames and drops them all.
			res = append(res, "allow-compression no")
			notes = append(notes, "comp-lzo → allow-compression no（服务端不压缩，保留会导致全丢包）")
			continue
		case field == "data-ciphers":
			haveDataCiphers = true
		case field == "cipher":
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				legacyCipher = fields[1]
			}
		case field == "auth-user-pass":
			sawAuthUserPass = true
			if authPath != "" {
				res = append(res, "auth-user-pass "+authPath)
				notes = append(notes, "auth-user-pass → 注入账号文件（避免交互式提示）")
				continue
			}
		}
		res = append(res, line)
	}

	// OpenVPN 2.6 negotiates data channels from data-ciphers, whose default list
	// has no CBC modes. A config pinning e.g. AES-128-CBC therefore fails to
	// negotiate unless the cipher is added to that list explicitly.
	if legacyCipher != "" && !haveDataCiphers {
		res = append(res, "data-ciphers "+legacyCipher)
		notes = append(notes, fmt.Sprintf("补齐 data-ciphers %s（2.6 默认列表不含 CBC）", legacyCipher))
	}
	if authPath != "" && !sawAuthUserPass {
		// No auth-user-pass at all means cert-only: adding one would make
		// openvpn wait for credentials the server never asks for.
		notes = append(notes, "配置自带证书认证，未注入账号")
	}
	return strings.Join(res, "\n"), notes
}

// RemoteAddr extracts the "remote host port" line, which the supervisor needs to
// pin a host route to the VPN server. Returns ok=false when the config has none
// (e.g. it pulls remotes from a separate file).
func RemoteAddr(raw string) (host string, ok bool) {
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "remote") {
			return fields[1], true
		}
	}
	return "", false
}
