package server

// 代理订阅 + sing-box 边车。
//
// 操作员在前端粘贴 Clash 订阅链接，服务端拉取并解析出节点（Clash YAML 的
// proxies: 列表，或 base64 编码的分享链接），选一个节点作为 ARTEX 的出口：
// 生成 sing-box 配置（inbound mixed 监听 127.0.0.1:7890，outbound 就是该节点），
// 拉起本地 sing-box 进程，再把全局出口设成 socks5://127.0.0.1:7890。
//
// 这样 agent 的 bash / WebFetch / 流量录制上游都走订阅节点，而单节点协议细节
// （vmess/vless/trojan/ss/hysteria2…）由 sing-box 处理，ARTEX 自己只认一个
// socks5 出口地址——和手动填 globalProxy 的语义完全一致。

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
	"gopkg.in/yaml.v3"
)

const (
	// proxyListenHost/Port 是边车 mixed inbound 的监听地址（http + socks 同端口）。
	proxyListenHost = "127.0.0.1"
	proxyListenPort = 7890
	// proxyOutboundTag 是 sing-box 的节点 outbound tag。
	proxyOutboundTag = "proxy"
	// proxySubUA 仿 Clash.Meta（mihomo）：多数机场按 UA 决定下发 Clash 还是 base64。
	proxySubUA = "clash.meta/v1.19.7"
	// proxyFetchLimit 是订阅正文的读取上限（8 MB），防止误填大文件链接。
	proxyFetchLimit = 8 << 20
	// proxyStartWait 是边车启动后等待端口可连的最长时间。
	proxyStartWait = 5 * time.Second
	// proxyMaxRestarts 是进程意外退出后的自动重启次数（只重启一次）。
	proxyMaxRestarts = 1
)

// proxyListenAddr / proxyEgressURL 由上面两个常量推导：前者是监听地址，
// 后者是写进 globalProxy 的出口地址（http/socks 都能用 mixed 端口）。
var (
	proxyListenAddr = net.JoinHostPort(proxyListenHost, strconv.Itoa(proxyListenPort))
	proxyEgressURL  = "socks5://" + proxyListenAddr
)

// ---------- 节点与订阅模型 ----------

// ProxyNode 是一个订阅节点。Extra 保存生成 sing-box outbound 所需的协议细节
// （method/password/uuid/tls/sni/ws path…），不同协议用到的键不同；来源可能是
// Clash YAML，也可能是分享链接，这里统一归一化成同一套键名。
type ProxyNode struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Server string         `json:"server"`
	Port   int            `json:"port"`
	Region string         `json:"region,omitempty"`
	Extra  map[string]any `json:"extra,omitempty"`
}

// ProxySubscription 是一条订阅（附带最近一次成功解析出的节点）。
type ProxySubscription struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	URL       string      `json:"url"`
	Nodes     []ProxyNode `json:"nodes"`
	UpdatedAt int64       `json:"updated_at"`
}

// ---------- 订阅拉取与解析 ----------

// FetchSubscription 拉取并解析一个订阅链接。支持两种常见格式：
//   - Clash / Clash.Meta YAML（读 proxies: 列表）；
//   - base64 编码的分享链接（ss/vmess/vless/trojan/hysteria2/socks5/http）。
//
// 拉取失败、HTTP 非 200、内容里认不出任何节点都会返回可直接展示给用户的中文错误。
func FetchSubscription(rawURL string) ([]ProxyNode, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("订阅链接为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("订阅链接必须是 http(s) 地址: %q", rawURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造订阅请求失败: %w", err)
	}
	req.Header.Set("User-Agent", proxySubUA)
	req.Header.Set("Accept", "*/*")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取订阅失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, proxyFetchLimit))
	if err != nil {
		return nil, fmt.Errorf("读取订阅内容失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅返回 HTTP %d：%s", resp.StatusCode, firstLine(string(body), 120))
	}
	return parseSubscriptionBody(string(body))
}

// parseSubscriptionBody 依次尝试 Clash YAML → base64 分享链接 → 明文分享链接。
func parseSubscriptionBody(body string) ([]ProxyNode, error) {
	text := strings.TrimSpace(body)
	if text == "" {
		return nil, errors.New("订阅内容为空")
	}
	// yamlFound 记录「确实是 Clash YAML，但里面的节点一个都没解析出来」这种情况，
	// 好给出比「不是订阅」更准确的原因（多为协议暂不支持）。
	yamlFound := false
	tryYAML := func(doc string) []ProxyNode {
		if !looksLikeClashYAML(doc) {
			return nil
		}
		nodes, err := parseClashYAML([]byte(doc))
		if err != nil {
			return nil
		}
		yamlFound = true
		return nodes
	}
	if nodes := tryYAML(text); len(nodes) > 0 {
		return nodes, nil
	}
	if decoded, ok := decodeBase64Loose(text); ok {
		decoded = strings.TrimSpace(decoded)
		if nodes := tryYAML(decoded); len(nodes) > 0 {
			return nodes, nil
		}
		if nodes := parseShareLinks(decoded); len(nodes) > 0 {
			return nodes, nil
		}
	}
	if nodes := parseShareLinks(text); len(nodes) > 0 {
		return nodes, nil
	}
	if yamlFound {
		return nil, errors.New("订阅是 Clash YAML，但里面的节点都解析失败（协议可能暂不支持，详见服务端日志）")
	}
	return nil, errors.New("订阅里没有解析出任何节点：既不是 Clash YAML（缺 proxies:），也不是 base64 分享链接")
}

// looksLikeClashYAML 判断是不是 Clash 配置：任意一行以 proxies: 开头即可
// （机场常在前面写 port:/mixed-port:/proxy-groups:，也可能加注释）。
func looksLikeClashYAML(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxies:") {
			return true
		}
	}
	return false
}

// clashDoc 是 Clash 配置里我们关心的那一部分。
type clashDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// parseClashYAML 解析 Clash YAML 的 proxies: 列表。
func parseClashYAML(body []byte) ([]ProxyNode, error) {
	var doc clashDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("解析 Clash YAML 失败: %w", err)
	}
	nodes := make([]ProxyNode, 0, len(doc.Proxies))
	for _, m := range doc.Proxies {
		node, err := normalizeClashNode(m)
		if err != nil {
			log.Printf("[proxy] 跳过 Clash 节点: %v", err)
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

// normalizeClashNode 把 Clash 的节点字段归一化成 ProxyNode（Extra 与分享链接同键名）。
func normalizeClashNode(m map[string]any) (ProxyNode, error) {
	name := mapStr(m, "name")
	typ := strings.ToLower(strings.TrimSpace(mapStr(m, "type")))
	server := mapStr(m, "server")
	port := mapInt(m["port"])
	if server == "" || port <= 0 {
		return ProxyNode{}, fmt.Errorf("节点 %q 缺少 server/port", name)
	}
	if name == "" {
		name = server + ":" + strconv.Itoa(port)
	}
	extra := map[string]any{}
	switch typ {
	case "ss", "shadowsocks":
		typ = "ss"
		extra["method"] = mapStr(m, "cipher")
		extra["password"] = mapStr(m, "password")
		if plugin := mapStr(m, "plugin"); plugin != "" {
			extra["plugin"] = plugin
		}
	case "vmess":
		extra["uuid"] = mapStr(m, "uuid")
		extra["alter_id"] = mapInt(m["alterId"])
		extra["security"] = firstNonEmpty(mapStr(m, "cipher"), mapStr(m, "security"))
		extra["tls"] = mapBool(m["tls"])
		extra["sni"] = firstNonEmpty(mapStr(m, "servername"), mapStr(m, "sni"))
		extra["insecure"] = mapBool(m["skip-cert-verify"])
		normalizeClashTransport(extra, m)
	case "vless":
		extra["uuid"] = mapStr(m, "uuid")
		extra["flow"] = mapStr(m, "flow")
		reality := mapOf(m["reality-opts"])
		extra["reality_public_key"] = mapStr(reality, "public-key")
		extra["reality_short_id"] = mapStr(reality, "short-id")
		extra["tls"] = mapBool(m["tls"]) || mapBool(m["reality"]) || extra["reality_public_key"] != ""
		extra["sni"] = firstNonEmpty(mapStr(m, "servername"), mapStr(m, "sni"))
		extra["insecure"] = mapBool(m["skip-cert-verify"])
		extra["client_fingerprint"] = mapStr(m, "client-fingerprint")
		normalizeClashTransport(extra, m)
	case "trojan":
		extra["password"] = mapStr(m, "password")
		extra["sni"] = firstNonEmpty(mapStr(m, "sni"), mapStr(m, "servername"))
		extra["insecure"] = mapBool(m["skip-cert-verify"])
		extra["tls"] = true
		normalizeClashTransport(extra, m)
	case "hysteria2", "hy2":
		typ = "hysteria2"
		extra["password"] = firstNonEmpty(mapStr(m, "password"), mapStr(m, "auth"))
		extra["sni"] = firstNonEmpty(mapStr(m, "sni"), mapStr(m, "servername"))
		extra["insecure"] = mapBool(m["skip-cert-verify"])
		extra["obfs"] = mapStr(m, "obfs")
		extra["obfs_password"] = mapStr(m, "obfs-password")
		extra["tls"] = true
	case "socks5", "socks":
		typ = "socks5"
		extra["username"] = mapStr(m, "username")
		extra["password"] = mapStr(m, "password")
	case "http", "https":
		typ = "http"
		extra["username"] = mapStr(m, "username")
		extra["password"] = mapStr(m, "password")
		extra["tls"] = strings.EqualFold(mapStr(m, "type"), "https") || mapBool(m["tls"])
	case "tuic":
		extra["uuid"] = mapStr(m, "uuid")
		extra["password"] = mapStr(m, "password")
		extra["sni"] = firstNonEmpty(mapStr(m, "sni"), mapStr(m, "servername"))
		extra["insecure"] = mapBool(m["skip-cert-verify"])
		extra["tls"] = true
	case "anytls":
		extra["password"] = mapStr(m, "password")
		extra["sni"] = firstNonEmpty(mapStr(m, "sni"), mapStr(m, "servername"))
		extra["insecure"] = mapBool(m["skip-cert-verify"])
	case "":
		return ProxyNode{}, fmt.Errorf("节点 %q 缺少 type", name)
	default:
		// ssr / hysteria(v1) / 未知协议：解析阶段就跳过，别让操作员选到一个必然失败的节点。
		return ProxyNode{}, fmt.Errorf("节点 %q 的协议 %q 暂不支持", name, typ)
	}
	return ProxyNode{Name: name, Type: typ, Server: server, Port: port, Region: regionOf(name), Extra: extra}, nil
}

// normalizeClashTransport 把 Clash 的 network / ws-opts / grpc-opts / h2-opts 归一化。
func normalizeClashTransport(extra, m map[string]any) {
	network := strings.ToLower(mapStr(m, "network"))
	extra["network"] = network
	switch network {
	case "ws", "websocket":
		ws := mapOf(m["ws-opts"])
		extra["path"] = mapStr(ws, "path")
		extra["host"] = mapStr(mapOf(ws["headers"]), "Host")
		if extra["host"] == "" {
			extra["host"] = mapStr(mapOf(ws["headers"]), "host")
		}
	case "grpc":
		grpcOpts := mapOf(m["grpc-opts"])
		extra["service_name"] = mapStr(grpcOpts, "grpc-service-name")
	case "h2", "http":
		h2 := mapOf(m["h2-opts"])
		extra["path"] = mapStr(h2, "path")
		if hosts, ok := h2["host"].([]any); ok && len(hosts) > 0 {
			extra["host"] = fmt.Sprint(hosts[0])
		}
	}
}

// parseShareLinks 逐行解析分享链接；认不出的行直接跳过（订阅里常混着说明文字）。
func parseShareLinks(text string) []ProxyNode {
	var nodes []ProxyNode
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if node, ok := parseShareLink(line); ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// parseShareLink 解析一条分享链接。
func parseShareLink(line string) (ProxyNode, bool) {
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok {
		return ProxyNode{}, false
	}
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "ss":
		return parseSSLink(rest)
	case "vmess":
		return parseVmessLink(rest)
	case "vless", "trojan", "hysteria2", "hy2", "socks5", "socks", "http", "https":
		return parseURLStyleLink(strings.ToLower(strings.TrimSpace(scheme)), rest)
	}
	return ProxyNode{}, false
}

// parseSSLink 解析 ss:// 两种形态：
//   - SIP002：ss://base64(method:password)@host:port#name
//   - 旧版：  ss://base64(method:password@host:port)#name
func parseSSLink(rest string) (ProxyNode, bool) {
	rest, name := splitFragment(rest)
	rest, query := splitQuery(rest)
	extra := map[string]any{}
	if plugin := query.Get("plugin"); plugin != "" {
		extra["plugin"] = plugin
	}
	var method, password, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo, hp := rest[:at], rest[at+1:]
		if decoded, ok := decodeBase64Loose(userinfo); ok && strings.Contains(decoded, ":") {
			method, password, _ = strings.Cut(decoded, ":")
		} else {
			decoded, _ := url.QueryUnescape(userinfo)
			method, password, _ = strings.Cut(decoded, ":")
		}
		hostport = hp
	} else {
		decoded, ok := decodeBase64Loose(rest)
		if !ok {
			return ProxyNode{}, false
		}
		methodPass, hp, ok := strings.Cut(decoded, "@")
		if !ok {
			return ProxyNode{}, false
		}
		method, password, _ = strings.Cut(methodPass, ":")
		hostport = hp
	}
	host, port := splitHostPort(hostport)
	if host == "" || port <= 0 || method == "" {
		return ProxyNode{}, false
	}
	extra["method"] = method
	extra["password"] = password
	return ProxyNode{Name: nodeName(name, host, port), Type: "ss", Server: host, Port: port, Region: regionOf(name), Extra: extra}, true
}

// parseVmessLink 解析 vmess://base64(JSON)。
func parseVmessLink(rest string) (ProxyNode, bool) {
	rest, _ = splitFragment(rest)
	decoded, ok := decodeBase64Loose(rest)
	if !ok {
		return ProxyNode{}, false
	}
	var v struct {
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		ID   string `json:"id"`
		AID  any    `json:"aid"`
		Scy  string `json:"scy"`
		Net  string `json:"net"`
		TLS  string `json:"tls"`
		Host string `json:"host"`
		Path string `json:"path"`
		SNI  string `json:"sni"`
	}
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return ProxyNode{}, false
	}
	port := mapInt(v.Port)
	if v.Add == "" || port <= 0 || v.ID == "" {
		return ProxyNode{}, false
	}
	extra := map[string]any{
		"uuid":     v.ID,
		"alter_id": mapInt(v.AID),
		"security": firstNonEmpty(v.Scy, "auto"),
		"tls":      strings.EqualFold(v.TLS, "tls"),
		"sni":      firstNonEmpty(v.SNI, v.Host),
		"network":  strings.ToLower(v.Net),
		"path":     v.Path,
		"host":     v.Host,
	}
	return ProxyNode{Name: nodeName(v.PS, v.Add, port), Type: "vmess", Server: v.Add, Port: port, Region: regionOf(v.PS), Extra: extra}, true
}

// parseURLStyleLink 解析 vless/trojan/hysteria2/socks5/http 这类 userinfo@host:port?query#name。
func parseURLStyleLink(scheme, rest string) (ProxyNode, bool) {
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil {
		return ProxyNode{}, false
	}
	typ := scheme
	switch scheme {
	case "hy2":
		typ = "hysteria2"
	case "socks":
		typ = "socks5"
	case "https":
		typ = "http"
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if host == "" || port <= 0 {
		return ProxyNode{}, false
	}
	name := u.Fragment
	q := u.Query()
	extra := map[string]any{}
	password := ""
	if u.User != nil {
		password, _ = u.User.Password()
		if password == "" {
			password = u.User.Username()
		}
	}
	switch typ {
	case "vless":
		extra["uuid"] = u.User.Username()
	case "trojan", "hysteria2":
		extra["password"] = password
	case "socks5", "http":
		extra["username"] = u.User.Username()
		extra["password"] = password
	}
	// 传输层与 TLS 参数（各家客户端字段名略有差异，这里都收）。
	if net := firstNonEmpty(q.Get("type"), q.Get("net")); net != "" {
		extra["network"] = strings.ToLower(net)
	}
	extra["path"] = firstNonEmpty(q.Get("path"), q.Get("serviceName"))
	extra["service_name"] = q.Get("serviceName")
	extra["host"] = firstNonEmpty(q.Get("host"), q.Get("sni"))
	extra["sni"] = firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host"))
	extra["flow"] = q.Get("flow")
	security := strings.ToLower(q.Get("security"))
	extra["tls"] = security == "tls" || security == "reality" || typ == "trojan" || typ == "hysteria2"
	extra["reality_public_key"] = q.Get("pbk")
	extra["reality_short_id"] = q.Get("sid")
	extra["client_fingerprint"] = q.Get("fp")
	extra["insecure"] = q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("insecure"), "true")
	if typ == "http" {
		extra["tls"] = scheme == "https"
	}
	return ProxyNode{
		Name:   nodeName(name, host, port),
		Type:   typ,
		Server: host,
		Port:   port,
		Region: regionOf(name),
		Extra:  extra,
	}, true
}

// nodeName 优先用订阅里给的名字，没有就用 host:port。
func nodeName(name, host string, port int) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return host + ":" + strconv.Itoa(port)
}

// splitFragment 切出 #name（并做 URL 解码）。
func splitFragment(s string) (string, string) {
	if i := strings.LastIndex(s, "#"); i >= 0 {
		name, _ := url.QueryUnescape(s[i+1:])
		return s[:i], name
	}
	return s, ""
}

// splitQuery 切出 ?query。
func splitQuery(s string) (string, url.Values) {
	if i := strings.Index(s, "?"); i >= 0 {
		q, _ := url.ParseQuery(s[i+1:])
		return s[:i], q
	}
	return s, url.Values{}
}

// decodeBase64Loose 宽松地解 base64：忽略空白、自动补齐 padding，std/url 两种字母表都试。
func decodeBase64Loose(s string) (string, bool) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', ' ', '\t':
			return -1
		}
		return r
	}, s)
	if cleaned == "" {
		return "", false
	}
	if m := len(cleaned) % 4; m != 0 {
		cleaned += strings.Repeat("=", 4-m)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(cleaned); err == nil && len(b) > 0 {
			return string(b), true
		}
	}
	return "", false
}

// splitHostPort 拆 host:port（容忍带方括号的 IPv6）。
func splitHostPort(hostport string) (string, int) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return "", 0
	}
	return strings.Trim(host, "[]"), port
}

// regionOf 从节点名猜地区（中文名、城市名、两位国家码、国旗 emoji 都认）。
func regionOf(name string) string {
	lower := strings.ToLower(name)
	tokens := map[string]bool{}
	for _, t := range strings.FieldsFunc(lower, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		tokens[t] = true
	}
	for _, hint := range proxyRegionHints {
		for _, key := range hint.keys {
			if isASCII(key) {
				if tokens[key] {
					return hint.region
				}
				continue
			}
			if strings.Contains(lower, key) {
				return hint.region
			}
		}
	}
	return ""
}

// proxyRegionHints 是地区关键词表：ASCII 短码按 token 全等匹配，中文/长名按子串匹配。
var proxyRegionHints = []struct {
	region string
	keys   []string
}{
	{"香港", []string{"香港", "hongkong", "hong kong", "hk", "🇭🇰"}},
	{"台湾", []string{"台湾", "台灣", "taiwan", "🇹🇼", "tw"}},
	{"日本", []string{"日本", "japan", "tokyo", "osaka", "🇯🇵", "jp"}},
	{"韩国", []string{"韩国", "韓國", "korea", "seoul", "🇰🇷", "kr"}},
	{"新加坡", []string{"新加坡", "singapore", "🇸🇬", "sg"}},
	{"美国", []string{"美国", "美國", "united states", "usa", "america", "🇺🇸", "us"}},
	{"英国", []string{"英国", "united kingdom", "london", "🇬🇧", "uk"}},
	{"德国", []string{"德国", "germany", "frankfurt", "🇩🇪", "de"}},
	{"法国", []string{"法国", "france", "paris", "🇫🇷", "fr"}},
	{"荷兰", []string{"荷兰", "netherlands", "amsterdam", "🇳🇱", "nl"}},
	{"俄罗斯", []string{"俄罗斯", "russia", "moscow", "🇷🇺", "ru"}},
	{"加拿大", []string{"加拿大", "canada", "toronto", "🇨🇦", "ca"}},
	{"澳大利亚", []string{"澳大利亚", "australia", "sydney", "🇦🇺", "au"}},
	{"印度", []string{"印度", "india", "mumbai", "🇮🇳", "in"}},
	{"土耳其", []string{"土耳其", "turkey", "istanbul", "🇹🇷", "tr"}},
	{"巴西", []string{"巴西", "brazil", "🇧🇷", "br"}},
	{"马来西亚", []string{"马来西亚", "malaysia", "🇲🇾", "my"}},
	{"泰国", []string{"泰国", "thailand", "bangkok", "🇹🇭", "th"}},
	{"越南", []string{"越南", "vietnam", "🇻🇳", "vn"}},
	{"菲律宾", []string{"菲律宾", "philippines", "🇵🇭", "ph"}},
	{"阿根廷", []string{"阿根廷", "argentina", "🇦🇷", "ar"}},
	{"阿联酋", []string{"阿联酋", "emirates", "dubai", "🇦🇪", "ae"}},
}

// isASCII 判断是否纯 ASCII（决定地区关键词按 token 还是子串匹配）。
func isASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// ---------- 生成 sing-box 配置 ----------

// buildSingBoxOutbound 把一个节点翻译成 sing-box 1.13 的 outbound 对象。
func buildSingBoxOutbound(node ProxyNode) (map[string]any, error) {
	if node.Server == "" || node.Port <= 0 {
		return nil, fmt.Errorf("节点 %q 缺少服务器或端口", node.Name)
	}
	extra := node.Extra
	if extra == nil {
		extra = map[string]any{}
	}
	ob := map[string]any{
		"tag":         proxyOutboundTag,
		"server":      node.Server,
		"server_port": node.Port,
	}
	typ := strings.ToLower(node.Type)
	switch typ {
	case "ss", "shadowsocks":
		method := mapStr(extra, "method")
		if method == "" {
			return nil, fmt.Errorf("节点 %q 缺少加密方式(method)", node.Name)
		}
		if plugin := mapStr(extra, "plugin"); plugin != "" {
			return nil, fmt.Errorf("节点 %q 使用了 ss 插件 %q，暂不支持", node.Name, plugin)
		}
		ob["type"] = "shadowsocks"
		ob["method"] = method
		ob["password"] = mapStr(extra, "password")
	case "vmess":
		uuid := mapStr(extra, "uuid")
		if uuid == "" {
			return nil, fmt.Errorf("节点 %q 缺少 uuid", node.Name)
		}
		ob["type"] = "vmess"
		ob["uuid"] = uuid
		ob["security"] = firstNonEmpty(mapStr(extra, "security"), "auto")
		ob["alter_id"] = mapInt(extra["alter_id"])
		applySingBoxTLS(ob, extra, false)
		if err := applySingBoxTransport(ob, extra); err != nil {
			return nil, fmt.Errorf("节点 %q: %w", node.Name, err)
		}
	case "vless":
		uuid := mapStr(extra, "uuid")
		if uuid == "" {
			return nil, fmt.Errorf("节点 %q 缺少 uuid", node.Name)
		}
		ob["type"] = "vless"
		ob["uuid"] = uuid
		if flow := mapStr(extra, "flow"); flow != "" {
			ob["flow"] = flow
		}
		applySingBoxTLS(ob, extra, false)
		if err := applySingBoxTransport(ob, extra); err != nil {
			return nil, fmt.Errorf("节点 %q: %w", node.Name, err)
		}
	case "trojan":
		password := mapStr(extra, "password")
		if password == "" {
			return nil, fmt.Errorf("节点 %q 缺少 password", node.Name)
		}
		ob["type"] = "trojan"
		ob["password"] = password
		applySingBoxTLS(ob, extra, true)
		if err := applySingBoxTransport(ob, extra); err != nil {
			return nil, fmt.Errorf("节点 %q: %w", node.Name, err)
		}
	case "hysteria2":
		password := mapStr(extra, "password")
		if password == "" {
			return nil, fmt.Errorf("节点 %q 缺少 password", node.Name)
		}
		ob["type"] = "hysteria2"
		ob["password"] = password
		if obfs := mapStr(extra, "obfs"); obfs != "" {
			ob["obfs"] = map[string]any{"type": obfs, "password": mapStr(extra, "obfs_password")}
		}
		applySingBoxTLS(ob, extra, true)
	case "socks5", "socks":
		ob["type"] = "socks"
		ob["version"] = "5"
		if u := mapStr(extra, "username"); u != "" {
			ob["username"] = u
			ob["password"] = mapStr(extra, "password")
		}
	case "http":
		ob["type"] = "http"
		if u := mapStr(extra, "username"); u != "" {
			ob["username"] = u
			ob["password"] = mapStr(extra, "password")
		}
		applySingBoxTLS(ob, extra, false)
	case "tuic":
		uuid := firstNonEmpty(mapStr(extra, "uuid"), mapStr(extra, "password"))
		if uuid == "" {
			return nil, fmt.Errorf("节点 %q 缺少 uuid", node.Name)
		}
		ob["type"] = "tuic"
		ob["uuid"] = uuid
		if p := mapStr(extra, "password"); p != "" && p != uuid {
			ob["password"] = p
		}
		applySingBoxTLS(ob, extra, true)
	case "anytls":
		password := mapStr(extra, "password")
		if password == "" {
			return nil, fmt.Errorf("节点 %q 缺少 password", node.Name)
		}
		ob["type"] = "anytls"
		ob["password"] = password
		applySingBoxTLS(ob, extra, true)
	default:
		return nil, fmt.Errorf("暂不支持节点类型 %q（节点 %q）", node.Type, node.Name)
	}
	return ob, nil
}

// applySingBoxTLS 按 extra 里的 tls/sni/insecure/reality 字段生成 tls 块。
// force=true 表示协议本身就要求 TLS（trojan/hysteria2/tuic/anytls）。
func applySingBoxTLS(ob, extra map[string]any, force bool) {
	tls := map[string]any{}
	if force || mapBool(extra["tls"]) {
		tls["enabled"] = true
	}
	if sni := mapStr(extra, "sni"); sni != "" {
		tls["server_name"] = sni
	}
	if mapBool(extra["insecure"]) {
		tls["insecure"] = true
	}
	if fp := mapStr(extra, "client_fingerprint"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if pk := mapStr(extra, "reality_public_key"); pk != "" {
		tls["enabled"] = true
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": pk,
			"short_id":   mapStr(extra, "reality_short_id"),
		}
	}
	if len(tls) > 0 {
		ob["tls"] = tls
	}
}

// applySingBoxTransport 生成 ws/grpc/http 传输层；不认识的传输方式直接报错，
// 免得写出一个 sing-box 启动时才报错的配置。
func applySingBoxTransport(ob, extra map[string]any) error {
	network := strings.ToLower(mapStr(extra, "network"))
	path := mapStr(extra, "path")
	host := mapStr(extra, "host")
	switch network {
	case "", "tcp":
		return nil
	case "ws", "websocket":
		tr := map[string]any{"type": "ws"}
		if path != "" {
			tr["path"] = path
		}
		if host != "" {
			tr["headers"] = map[string]any{"Host": host}
		}
		ob["transport"] = tr
		return nil
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if sn := mapStr(extra, "service_name"); sn != "" {
			tr["service_name"] = sn
		}
		ob["transport"] = tr
		return nil
	case "h2", "http":
		tr := map[string]any{"type": "http"}
		if path != "" {
			tr["path"] = path
		}
		if host != "" {
			tr["host"] = []string{host}
		}
		ob["transport"] = tr
		return nil
	default:
		return fmt.Errorf("暂不支持传输方式 %q", network)
	}
}

// singBoxConfigJSON 生成完整配置：mixed inbound + 节点 outbound + 直连 outbound。
// 刻意保持最小配置（不带 route/sniff 规则），对 sing-box 1.13 稳定有效。
func singBoxConfigJSON(outbound map[string]any) ([]byte, error) {
	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type":        "mixed",
			"tag":         "artex-mixed",
			"listen":      proxyListenHost,
			"listen_port": proxyListenPort,
		}},
		"outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}},
	}
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("生成 sing-box 配置失败: %w", err)
	}
	return append(buf, '\n'), nil
}

// singBoxBinPath 返回 sing-box 可执行文件路径：ARTEX_SINGBOX_BIN 优先，
// 否则用 VPS 上的 /opt/artex/bin/sing-box，最后退回 <datadir>/bin/sing-box。
func singBoxBinPath(dir string) string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_SINGBOX_BIN")); v != "" {
		return v
	}
	primary := "/opt/artex/bin/sing-box"
	if st, err := os.Stat(primary); err == nil && !st.IsDir() {
		return primary
	}
	fallback := filepath.Join(dir, "bin", "sing-box")
	if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
		return fallback
	}
	return primary
}

// ---------- sing-box 边车 ----------

// ProxySidecar 是 sing-box 边车的进程句柄与状态（进程级单例）。它自己不实现
// 代理功能：只负责生成配置、守护进程、并把 globalProxy 指向/还原。
type ProxySidecar struct {
	mu        sync.Mutex
	dir       string             // ARTEX 数据目录（配置写到 <dir>/proxy/）
	egressSet func(string) error // Manager.SetGlobalProxy
	egressGet func() string      // Manager.GlobalProxy

	cmd       *exec.Cmd
	node      ProxyNode
	running   bool
	gen       int64 // 每次启动/停止自增，旧守护 goroutine 据此失效
	restarts  int
	lastErr   string
	startedAt int64
	prevProxy string // 边车接管前的出口，失败/停止时回滚
	cfgPath   string
}

// ProxySidecarStatus 是 GET /api/proxy/status 的主体。
type ProxySidecarStatus struct {
	Running     bool   `json:"running"`
	Node        string `json:"node"`
	NodeType    string `json:"node_type"`
	Listen      string `json:"listen"`
	Egress      string `json:"egress"`
	PID         int    `json:"pid"`
	StartedAt   int64  `json:"started_at"`
	Restarts    int    `json:"restarts"`
	LastError   string `json:"last_error"`
	ConfigPath  string `json:"config_path"`
	Binary      string `json:"binary"`
	BinaryReady bool   `json:"binary_ready"`
}

// ProxyStatus 是 /api/proxy/status 的完整返回：边车状态 + 持久化的选择 + 订阅统计。
type ProxyStatus struct {
	ProxySidecarStatus
	Selected      string `json:"selected"`
	Subscriptions int    `json:"subscriptions"`
	Nodes         int    `json:"nodes"`
}

var (
	proxySidecarOnce sync.Once
	proxySidecarInst *ProxySidecar
)

// proxySidecar 返回边车句柄（惰性创建并绑定数据目录与出口读写）。
func (s *Server) proxySidecar() *ProxySidecar {
	proxySidecarOnce.Do(func() { proxySidecarInst = &ProxySidecar{} })
	sc := proxySidecarInst
	sc.mu.Lock()
	if s.m != nil {
		sc.dir = s.m.dir
		sc.egressSet = s.m.SetGlobalProxy
		sc.egressGet = s.m.GlobalProxy
	}
	sc.mu.Unlock()
	return sc
}

// StartSidecar 生成配置并拉起边车，等端口可连后把全局出口指向它。
// 任一步失败都会杀掉进程并把出口回滚到启动前的值。
func (sc *ProxySidecar) StartSidecar(node ProxyNode) error {
	sc.mu.Lock()
	err := sc.startLocked(node, false)
	var prev string
	if err != nil {
		prev = sc.prevProxy
		sc.prevProxy = ""
		sc.running = false
		sc.lastErr = err.Error()
	}
	sc.mu.Unlock()
	if err != nil {
		// 回滚放在锁外：SetGlobalProxy 会重建 MCP 代理配置，别再叠一层锁。
		sc.restoreEgress(prev)
	}
	return err
}

// startLocked 是 StartSidecar 的实现，调用方必须持有 sc.mu。
// restart=true 表示这是守护 goroutine 的自动重启（不重置计数、不动 prevProxy）。
func (sc *ProxySidecar) startLocked(node ProxyNode, restart bool) error {
	if sc.dir == "" {
		return errors.New("ARTEX 数据目录未知，无法写 sing-box 配置")
	}
	if node.Name == "" {
		node.Name = node.Server + ":" + strconv.Itoa(node.Port)
	}
	outbound, err := buildSingBoxOutbound(node)
	if err != nil {
		return err
	}
	cfg, err := singBoxConfigJSON(outbound)
	if err != nil {
		return err
	}
	dir := filepath.Join(sc.dir, "proxy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建代理配置目录 %s 失败: %w", dir, err)
	}
	cfgPath := filepath.Join(dir, "sing-box.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return fmt.Errorf("写入 sing-box 配置失败: %w", err)
	}
	bin := singBoxBinPath(sc.dir)
	if st, statErr := os.Stat(bin); statErr != nil || st.IsDir() {
		return fmt.Errorf("sing-box 未安装: %s", bin)
	}
	// 第一次接管时记下原出口（可能为空=直连），失败或取消时回滚。
	if !restart && !sc.running {
		sc.prevProxy = sc.currentEgress()
	}
	// 换节点或守护重启：先停旧进程；再清理 ARTEX 重启后遗留的僵尸边车。
	sc.killLocked()
	sc.killStale()
	if err := waitPortFree(proxyListenAddr, 3*time.Second); err != nil {
		return err
	}

	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Dir = dir
	tail := &tailWriter{max: 4096}
	cmd.Stdout = tail
	cmd.Stderr = tail
	log.Printf("[proxy] 启动 sing-box 边车: %s run -c %s（节点 %s / %s）", bin, cfgPath, node.Name, node.Type)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}
	sc.gen++
	gen := sc.gen
	sc.cmd = cmd
	sc.cfgPath = cfgPath
	_ = writeProxyPID(sc.dir, cmd.Process.Pid)
	exited := make(chan struct{})
	go sc.watch(gen, cmd, node, tail, exited)

	if err := waitPortOpen(proxyListenAddr, proxyStartWait, exited); err != nil {
		msg := err.Error()
		if out := strings.TrimSpace(tail.String()); out != "" {
			msg += "：" + lastLine(out, 300)
		}
		sc.killLocked()
		return errors.New(msg)
	}
	sc.running = true
	sc.node = node
	sc.startedAt = time.Now().Unix()
	sc.lastErr = ""
	if !restart {
		sc.restarts = 0
	}
	if sc.egressSet != nil {
		if err := sc.egressSet(proxyEgressURL); err != nil {
			sc.killLocked()
			return fmt.Errorf("边车已就绪，但把出口设为 %s 失败: %w", proxyEgressURL, err)
		}
	}
	log.Printf("[proxy] 边车就绪：%s → 节点 %s，出口已设为 %s", proxyListenAddr, node.Name, proxyEgressURL)
	return nil
}

// watch 守护一个边车进程：意外退出先自动重启一次，连续失败就停下并回滚出口。
func (sc *ProxySidecar) watch(gen int64, cmd *exec.Cmd, node ProxyNode, tail *tailWriter, exited chan struct{}) {
	defer close(exited)
	waitErr := cmd.Wait()

	sc.mu.Lock()
	if gen != sc.gen {
		// 已被显式停止或替换，不再管这次退出。
		sc.mu.Unlock()
		return
	}
	sc.running = false
	sc.cmd = nil
	sc.startedAt = 0
	reason := "sing-box 已退出"
	if waitErr != nil {
		reason += ": " + waitErr.Error()
	}
	if out := strings.TrimSpace(tail.String()); out != "" {
		reason += "；" + lastLine(out, 300)
	}
	if sc.restarts < proxyMaxRestarts {
		sc.restarts++
		sc.lastErr = reason + "（正在自动重启）"
		sc.mu.Unlock()
		log.Printf("[proxy] 边车退出，自动重启（第 %d 次）: %s", proxyMaxRestarts, reason)
		time.Sleep(500 * time.Millisecond)
		sc.mu.Lock()
		err := sc.startLocked(node, true)
		if err != nil {
			sc.lastErr = "边车自动重启失败: " + err.Error()
		}
		sc.mu.Unlock()
		if err != nil {
			log.Printf("[proxy] 边车自动重启失败: %v", err)
		}
		return
	}
	sc.lastErr = reason + "（已自动重启过仍失败，边车已停止）"
	prev := sc.prevProxy
	sc.prevProxy = ""
	sc.mu.Unlock()
	log.Printf("[proxy] 边车停止: %s", reason)
	// 连续失败 → 出口回滚，避免 ARTEX 的流量全打到死端口上。
	sc.restoreEgress(prev)
}

// StopSidecar 停掉边车并把出口回滚到接管前的值。可重复调用。
func (sc *ProxySidecar) StopSidecar() error {
	sc.mu.Lock()
	sc.killLocked()
	prev := sc.prevProxy
	sc.prevProxy = ""
	sc.restarts = 0
	sc.node = ProxyNode{}
	sc.startedAt = 0
	wasErr := sc.lastErr
	sc.mu.Unlock()
	sc.restoreEgress(prev)
	if wasErr != "" {
		log.Printf("[proxy] 边车已停止（上次错误: %s）", wasErr)
	}
	sc.mu.Lock()
	sc.lastErr = ""
	sc.mu.Unlock()
	return nil
}

// Status 返回边车当前状态（含进程号、上次错误、配置路径、二进制是否就绪）。
func (sc *ProxySidecar) Status() ProxySidecarStatus {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	st := ProxySidecarStatus{
		Running:    sc.running,
		Node:       sc.node.Name,
		NodeType:   sc.node.Type,
		Listen:     proxyListenAddr,
		StartedAt:  sc.startedAt,
		Restarts:   sc.restarts,
		LastError:  sc.lastErr,
		Egress:     sc.currentEgress(),
		ConfigPath: sc.cfgPath,
		Binary:     singBoxBinPath(sc.dir),
	}
	if st.ConfigPath == "" && sc.dir != "" {
		st.ConfigPath = filepath.Join(sc.dir, "proxy", "sing-box.json")
	}
	if sc.cmd != nil && sc.cmd.Process != nil {
		st.PID = sc.cmd.Process.Pid
	}
	if _, err := os.Stat(st.Binary); err == nil {
		st.BinaryReady = true
	}
	return st
}

// killLocked 杀掉当前边车进程并作废它的守护 goroutine（不动出口配置）。
func (sc *ProxySidecar) killLocked() {
	sc.gen++
	if sc.cmd != nil && sc.cmd.Process != nil {
		_ = sc.cmd.Process.Kill()
	}
	sc.cmd = nil
	sc.running = false
	if sc.dir != "" {
		_ = os.Remove(proxyPIDPath(sc.dir))
	}
}

// killStale 清理 ARTEX 重启后遗留的 sing-box（pid 文件里的进程），
// 否则新边车会因 7890 被占而启动失败。
func (sc *ProxySidecar) killStale() {
	if sc.dir == "" {
		return
	}
	path := proxyPIDPath(sc.dir)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || pid == os.Getpid() {
		_ = os.Remove(path)
		return
	}
	// 只杀确实是 sing-box 的进程，避免 pid 复用误伤。
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || !strings.Contains(string(cmdline), "sing-box") {
		_ = os.Remove(path)
		return
	}
	if proc, findErr := os.FindProcess(pid); findErr == nil {
		_ = proc.Kill()
		log.Printf("[proxy] 已清理遗留的 sing-box 进程 pid=%d", pid)
	}
	_ = os.Remove(path)
}

// currentEgress 读当前全局出口。
func (sc *ProxySidecar) currentEgress() string {
	if sc.egressGet == nil {
		return ""
	}
	return sc.egressGet()
}

// restoreEgress 把出口回滚到 prev，但只在「当前出口仍指向边车」时动手，
// 免得覆盖用户后来在系统配置里手动设置的出口。
func (sc *ProxySidecar) restoreEgress(prev string) {
	if sc.egressGet == nil || sc.egressSet == nil {
		return
	}
	if cur := sc.egressGet(); cur != proxyEgressURL {
		return
	}
	if err := sc.egressSet(prev); err != nil {
		log.Printf("[proxy] 回滚出口到 %q 失败: %v", prev, err)
		return
	}
	log.Printf("[proxy] 出口已回滚为 %q", prev)
}

// proxyPIDPath 是边车 pid 文件路径。
func proxyPIDPath(dir string) string {
	return filepath.Join(dir, "proxy", "sing-box.pid")
}

// writeProxyPID 记录边车 pid，供下次启动清理僵尸进程。
func writeProxyPID(dir string, pid int) error {
	return os.WriteFile(proxyPIDPath(dir), []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

// tailWriter 只保留最后 max 字节的输出，用于把 sing-box 的报错带回状态里。
type tailWriter struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Write(p)
	if t.buf.Len() > t.max {
		trimmed := t.buf.Bytes()[t.buf.Len()-t.max:]
		rest := append([]byte(nil), trimmed...)
		t.buf.Reset()
		t.buf.Write(rest)
	}
	return len(p), nil
}

func (t *tailWriter) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.String()
}

// lastLine 取多行输出的最后一条非空行（sing-box 的错误通常在末尾）。
func lastLine(s string, max int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return firstLine(line, max)
		}
	}
	return ""
}

// portOpen 报告 addr 是否可以连上。
func portOpen(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitPortOpen 等 addr 可连；进程提前退出则立刻失败。
func waitPortOpen(addr string, timeout time.Duration, exited <-chan struct{}) error {
	deadline := time.Now().Add(timeout)
	for {
		if portOpen(addr) {
			return nil
		}
		select {
		case <-exited:
			return errors.New("sing-box 启动后立即退出")
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待 %s 可连接超时(%s)", addr, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitPortFree 等 addr 释放；旧边车没退干净就明确报错。
func waitPortFree(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if !portOpen(addr) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("端口 %s 已被占用，无法启动 sing-box 边车（可能有旧的 sing-box 在跑）", addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---------- 持久化（proxy_subscriptions / proxy_selected） ----------

// errProxyNotFound 表示订阅或节点不存在。
var errProxyNotFound = errors.New("订阅或节点不存在")

// listProxySubscriptions 按 id 列出全部订阅（含解析好的节点）。
func listProxySubscriptions(pg *db.DB) ([]ProxySubscription, error) {
	rows, err := pg.Query(`SELECT id, name, url, nodes, updated_at FROM proxy_subscriptions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]ProxySubscription, 0, 8)
	for rows.Next() {
		var sub ProxySubscription
		var raw []byte
		var updated time.Time
		if err := rows.Scan(&sub.ID, &sub.Name, &sub.URL, &raw, &updated); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &sub.Nodes); err != nil {
				return nil, fmt.Errorf("解析订阅 %d 的节点失败: %w", sub.ID, err)
			}
		}
		if sub.Nodes == nil {
			sub.Nodes = []ProxyNode{}
		}
		sub.UpdatedAt = updated.Unix()
		out = append(out, sub)
	}
	return out, rows.Err()
}

// getProxySubscription 读一条订阅。
func getProxySubscription(pg *db.DB, id int64) (*ProxySubscription, error) {
	var sub ProxySubscription
	var raw []byte
	var updated time.Time
	err := pg.QueryRow(`SELECT id, name, url, nodes, updated_at FROM proxy_subscriptions WHERE id=$1`, id).
		Scan(&sub.ID, &sub.Name, &sub.URL, &raw, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errProxyNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &sub.Nodes); err != nil {
			return nil, fmt.Errorf("解析订阅 %d 的节点失败: %w", id, err)
		}
	}
	if sub.Nodes == nil {
		sub.Nodes = []ProxyNode{}
	}
	sub.UpdatedAt = updated.Unix()
	return &sub, nil
}

// createProxySubscription 新增一条订阅。
func createProxySubscription(pg *db.DB, name, rawURL string, nodes []ProxyNode) (*ProxySubscription, error) {
	if nodes == nil {
		nodes = []ProxyNode{}
	}
	raw, err := json.Marshal(nodes)
	if err != nil {
		return nil, err
	}
	var sub ProxySubscription
	var updated time.Time
	err = pg.QueryRow(`INSERT INTO proxy_subscriptions (name, url, nodes) VALUES ($1,$2,$3)
		RETURNING id, name, url, updated_at`, name, rawURL, string(raw)).
		Scan(&sub.ID, &sub.Name, &sub.URL, &updated)
	if err != nil {
		return nil, err
	}
	sub.Nodes = nodes
	sub.UpdatedAt = updated.Unix()
	return &sub, nil
}

// updateProxySubscriptionNodes 覆盖一条订阅的节点并刷新 updated_at。
func updateProxySubscriptionNodes(pg *db.DB, id int64, nodes []ProxyNode) (*ProxySubscription, error) {
	if nodes == nil {
		nodes = []ProxyNode{}
	}
	raw, err := json.Marshal(nodes)
	if err != nil {
		return nil, err
	}
	var sub ProxySubscription
	var updated time.Time
	err = pg.QueryRow(`UPDATE proxy_subscriptions SET nodes=$2, updated_at=now() WHERE id=$1
		RETURNING id, name, url, updated_at`, id, string(raw)).
		Scan(&sub.ID, &sub.Name, &sub.URL, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errProxyNotFound
	}
	if err != nil {
		return nil, err
	}
	sub.Nodes = nodes
	sub.UpdatedAt = updated.Unix()
	return &sub, nil
}

// deleteProxySubscription 删除一条订阅。
func deleteProxySubscription(pg *db.DB, id int64) (bool, error) {
	res, err := pg.Exec(`DELETE FROM proxy_subscriptions WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// allProxyNodes 汇总所有订阅的节点；同名节点只保留第一个（选择是按名字的）。
func allProxyNodes(pg *db.DB) ([]ProxyNode, error) {
	subs, err := listProxySubscriptions(pg)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]ProxyNode, 0, 64)
	for _, sub := range subs {
		for _, node := range sub.Nodes {
			if seen[node.Name] {
				continue
			}
			seen[node.Name] = true
			out = append(out, node)
		}
	}
	return out, nil
}

// findProxyNode 按名字在所有订阅里找节点。
func findProxyNode(pg *db.DB, name string) (*ProxyNode, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("节点名必填")
	}
	subs, err := listProxySubscriptions(pg)
	if err != nil {
		return nil, err
	}
	for _, sub := range subs {
		for i := range sub.Nodes {
			if sub.Nodes[i].Name == name {
				node := sub.Nodes[i]
				return &node, nil
			}
		}
	}
	return nil, fmt.Errorf("节点 %q 不存在，请先刷新订阅", name)
}

// proxySelectedName 读当前选中的节点名（空=未选）。
func proxySelectedName(pg *db.DB) (string, error) {
	var name string
	err := pg.QueryRow(`SELECT node_name FROM proxy_selected WHERE id=1`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return name, nil
}

// setProxySelected 记录选中的节点（单行表，id=1）。
func setProxySelected(pg *db.DB, name string) error {
	_, err := pg.Exec(`INSERT INTO proxy_selected (id, node_name, updated_at) VALUES (1,$1,now())
		ON CONFLICT (id) DO UPDATE SET node_name=EXCLUDED.node_name, updated_at=now()`, name)
	return err
}

// clearProxySelected 清除选择。
func clearProxySelected(pg *db.DB) error {
	_, err := pg.Exec(`DELETE FROM proxy_selected WHERE id=1`)
	return err
}

// ---------- HTTP handlers ----------

// pgProxyListSubscriptions 处理 GET /api/proxy/subscriptions。
func (s *Server) pgProxyListSubscriptions(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	subs, err := listProxySubscriptions(pg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取订阅失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": subs})
}

// pgProxyCreateSubscription 处理 POST /api/proxy/subscriptions：拉取 + 解析 + 落库。
func (s *Server) pgProxyCreateSubscription(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" {
		writeErr(w, http.StatusBadRequest, "订阅链接必填")
		return
	}
	nodes, err := FetchSubscription(rawURL)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = proxySubscriptionName(rawURL)
	}
	sub, err := createProxySubscription(pg, name, rawURL, nodes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存订阅失败: "+err.Error())
		return
	}
	log.Printf("[proxy] 新增订阅 %q，解析到 %d 个节点", sub.Name, len(sub.Nodes))
	writeJSON(w, http.StatusCreated, sub)
}

// pgProxyDeleteSubscription 处理 DELETE /api/proxy/subscriptions/{id}。
func (s *Server) pgProxyDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "订阅 id 无效")
		return
	}
	deleted, err := deleteProxySubscription(pg, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "删除订阅失败: "+err.Error())
		return
	}
	if !deleted {
		writeErr(w, http.StatusNotFound, "订阅不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// pgProxyRefreshSubscription 处理 POST /api/proxy/subscriptions/{id}/refresh。
func (s *Server) pgProxyRefreshSubscription(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "订阅 id 无效")
		return
	}
	sub, err := getProxySubscription(pg, id)
	if errors.Is(err, errProxyNotFound) {
		writeErr(w, http.StatusNotFound, "订阅不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取订阅失败: "+err.Error())
		return
	}
	nodes, err := FetchSubscription(sub.URL)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "刷新失败: "+err.Error())
		return
	}
	updated, err := updateProxySubscriptionNodes(pg, id, nodes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "更新订阅失败: "+err.Error())
		return
	}
	log.Printf("[proxy] 刷新订阅 %q，解析到 %d 个节点", updated.Name, len(updated.Nodes))
	writeJSON(w, http.StatusOK, updated)
}

// pgProxyNodes 处理 GET /api/proxy/nodes：汇总所有订阅的节点。
func (s *Server) pgProxyNodes(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	nodes, err := allProxyNodes(pg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取节点失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}

// pgProxySelect 处理 POST /api/proxy/select：选中节点 → 起边车 → 设出口。
func (s *Server) pgProxySelect(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Node string `json:"node"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	node, err := findProxyNode(pg, req.Node)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	sc := s.proxySidecar()
	if err := sc.StartSidecar(*node); err != nil {
		writeErr(w, http.StatusBadGateway, "启动 sing-box 边车失败: "+err.Error())
		return
	}
	if err := setProxySelected(pg, node.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, "边车已启动，但保存选择失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.proxyStatus(pg))
}

// pgProxyDeselect 处理 POST /api/proxy/deselect：停边车 → 清选择 → 出口回滚。
func (s *Server) pgProxyDeselect(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := s.proxySidecar().StopSidecar(); err != nil {
		writeErr(w, http.StatusInternalServerError, "停止边车失败: "+err.Error())
		return
	}
	if err := clearProxySelected(pg); err != nil {
		writeErr(w, http.StatusInternalServerError, "清除选择失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.proxyStatus(pg))
}

// pgProxyStatus 处理 GET /api/proxy/status。
func (s *Server) pgProxyStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.proxyStatus(pg))
}

// ResumeSidecar 在服务启动后恢复上次选中的代理节点。
//
// 选中的节点名持久化在库里，但 sing-box 边车是子进程：进程一退，127.0.0.1:7890
// 就没人监听了。此前只有「手动点选节点」这一个入口会拉起边车，于是每次重启——
// 尤其是一键更新完成后的那次重启——都会变成「库里选着节点、实际没有代理」：
// 检查更新、LLM 调用、子域名收集一起报 connection refused，而页面上的状态看着
// 一切正常（选中项还在）。用户只能靠重新点一次节点救回来。
//
// 这里只做恢复，不改动选中值；拉不起来只记日志，绝不影响服务启动。
func (s *Server) ResumeSidecar() {
	// 数据库可能还在建连（管理数据源是异步接上的），给它一点时间。
	var pg *db.DB
	for i := 0; i < 30; i++ {
		if pg = s.m.pg; pg != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if pg == nil {
		log.Printf("[proxy] 启动恢复跳过：数据库未就绪")
		return
	}
	name, err := proxySelectedName(pg)
	if err != nil {
		log.Printf("[proxy] 启动恢复跳过：读选中节点失败: %v", err)
		return
	}
	if name == "" {
		return // 从没选过节点，正常的初始状态
	}
	sc := s.proxySidecar()
	if sc.Status().Running {
		return // 已经有一份在跑，别重复拉
	}
	node, err := findProxyNode(pg, name)
	if err != nil {
		log.Printf("[proxy] 启动恢复失败：找不到上次选中的节点 %q: %v", name, err)
		return
	}
	if err := sc.StartSidecar(*node); err != nil {
		log.Printf("[proxy] 启动恢复失败：节点 %q 拉起边车出错: %v", name, err)
		return
	}
	log.Printf("[proxy] 已恢复上次选中的节点 %q，出口 %s", name, sc.Status().Egress)
}

// proxyStatus 组装状态返回：边车运行态 + 当前出口 + 上次错误 + 选择与统计。
func (s *Server) proxyStatus(pg *db.DB) ProxyStatus {
	status := ProxyStatus{ProxySidecarStatus: s.proxySidecar().Status()}
	if pg == nil {
		return status
	}
	if name, err := proxySelectedName(pg); err == nil {
		status.Selected = name
	} else {
		status.LastError = firstNonEmpty(status.LastError, "读取当前出口选择失败: "+err.Error())
	}
	subs, err := listProxySubscriptions(pg)
	if err == nil {
		status.Subscriptions = len(subs)
		for _, sub := range subs {
			status.Nodes += len(sub.Nodes)
		}
	}
	return status
}

// proxySubscriptionName 在用户没给名字时用域名当订阅名。
func proxySubscriptionName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err == nil && u.Host != "" {
		return u.Host
	}
	return firstLine(rawURL, 32)
}

// ---------- 小工具 ----------

// mapStr 读 map 里的字符串字段。
func mapStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return v.String()
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

// mapInt 读 map 里的整数字段（YAML/JSON 里可能是 int、float 或字符串）。
func mapInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return 0
}

// mapBool 读 map 里的布尔字段（YAML 里可能是 true/"true"/1）。
func mapBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(strings.TrimSpace(b), "true") || b == "1"
	case int:
		return b != 0
	case float64:
		return b != 0
	}
	return false
}

// mapOf 读 map 里的嵌套对象。
func mapOf(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// firstNonEmpty 返回第一个非空值。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
