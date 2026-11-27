package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// findingDiscoveryPath 把一条漏洞的溯源链渲染成**人能读的白话时间线**：
// 目标入口（方法/URL/参数/来自哪个资产）→ 溯源 → 目标判定 → 实测请求 → 决定性证据。
//
// 数据全部来自已有记录，不重新探测：
//   - 图谱：exploration_edges 的 yields（意图 → 漏洞）/ derived_from（事实 → 意图）
//   - 意图文本：说明"为什么盯上这个入口"
//   - activity：该意图的 Bash 工具调用，抽出真实发过的请求（含 query 与 body）
//   - 资产表：endpoint 资产带 method + params（参数名/类型/位置），回答"接口从哪来"
//   - 已绑定的流量快照：命中请求与决定性证据（method/url/status）
type discoveryItem struct {
	Kind   string   `json:"kind"`             // asset|fact|intent|finding|probe|evidence
	Ref    string   `json:"ref,omitempty"`    // #32100
	Method string   `json:"method,omitempty"` // GET/POST…
	URL    string   `json:"url,omitempty"`
	Status int      `json:"status,omitempty"`
	Text   string   `json:"text"`
	Hit    bool     `json:"hit,omitempty"`
	Query  []string `json:"query,omitempty"` // query string 里的键值
	Body   string   `json:"body,omitempty"`  // POST 请求体（从工具命令里抽）
}

// discoveryParam 是接口参数（来自 endpoint 资产的 params）。
type discoveryParam struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	Location string `json:"location,omitempty"` // path/query/body/header
}

// discoveryTarget 描述"这条漏洞打的是哪个入口、参数是什么、这个接口是哪来的"。
type discoveryTarget struct {
	Method      string           `json:"method"`
	URL         string           `json:"url"`
	Params      []discoveryParam `json:"params,omitempty"`
	AssetID     int64            `json:"asset_id,omitempty"`
	AssetDomain string           `json:"asset_domain,omitempty"`
	AssetTasks  []int64          `json:"asset_tasks,omitempty"`
	Source      string           `json:"source,omitempty"`
}

type discoveryStep struct {
	Phase string          `json:"phase"`
	Title string          `json:"title"`
	Items []discoveryItem `json:"items"`
	Note  string          `json:"note,omitempty"`
}

var (
	discURLRE    = regexp.MustCompile(`https?://[^\s"'\\<>|;)]+`)
	discMethodRE = regexp.MustCompile(`(?i)-X\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)`)
	discNameRE   = regexp.MustCompile(`(?i)\b(GET|POST|PUT|DELETE|PATCH)\s+(/[A-Za-z0-9_\-./{}$%:*?=&]+)`)
	// 工具命令里用单引号包住的 JSON body（probe2.sh tag "url" '{"k":"v"}'）。
	// 注意 RE2 的重复上限是 1000——写成 {2,4000} 会在 init 阶段 panic 把服务
	// 打成崩溃循环（实测踩过）。请求体最终只展示 600 字符，900 足够。
	discBodyRE = regexp.MustCompile(`'(\{(?:[^'\\]|\\.){2,900}\})'`)
	// evidence 首段的原始请求报文：`POST /path HTTP/1.1` + `Host: xxx`
	discReqLineRE = regexp.MustCompile(`(?m)^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/1`)
	discHostRE    = regexp.MustCompile(`(?mi)^\s*Host:\s*([^\s]+)`)
)

// GET /api/exploration/findings/{id}/discovery-path
func (s *Server) findingDiscoveryPath(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}

	out := map[string]any{
		"finding": map[string]any{
			"id": f.ID, "name": f.Name, "vulnclass": f.VulnClass,
			"severity": f.Severity, "summary": f.Summary,
		},
	}
	steps := make([]discoveryStep, 0, 6)

	target := s.resolveFindingTarget(r.Context(), f)
	out["target"] = target
	out["target_method"] = target.Method
	out["target_url"] = target.URL

	var story *db.ExplorationStore
	if f.TaskID != nil {
		if t := s.m.ResolveTask(i64s(*f.TaskID)); t != nil {
			story = t.Store
		}
	}

	// ① 溯源链（由远及近）
	var intentID int64
	if story != nil && f.NodeID != nil {
		if nodes, edges, lerr := story.FindingLineage(*f.NodeID); lerr == nil {
			if chain := discoveryChain(nodes, edges, *f.NodeID); len(chain) > 0 {
				steps = append(steps, discoveryStep{
					Phase: "溯源", Title: "这条漏洞是从哪条线索长出来的",
					Items: chain,
					Note:  "由远及近：最早的采集/事实 → 派生的意图 → 本条漏洞",
				})
			}
			intentID = intentYielding(nodes, edges, *f.NodeID)
		}
	}

	// ② 目标判定 + ③ 实测请求（含参数与 body）
	if intentID > 0 && story != nil && story.ID() > 0 {
		if n, nerr := story.GetNode(intentID); nerr == nil && n != nil {
			steps = append(steps, discoveryStep{
				Phase: "目标判定",
				Title: "为什么要打这个入口",
				Items: []discoveryItem{{Kind: "intent", Ref: "#" + i64s(n.ID), Text: clip(nodeOneLine(n), 600)}},
			})
			if probes := s.discoveryProbes(story.ID(), intentID, target.Method, target.URL); len(probes) > 0 {
				steps = append(steps, discoveryStep{
					Phase: "实测",
					Title: "实际发了哪些请求（含参数与请求体，按时间顺序）",
					Items: probes,
					Note:  "命中那条高亮显示；随机路径的基线请求用于证明门禁是按路由生效的",
				})
			}
		}
	}

	// ④ 决定性证据：已绑定的流量快照（proof 在前）
	if traffic, terr := s.m.pg.GetFindingTraffic(r.Context(), f.ID); terr == nil && traffic != nil && len(traffic.Bindings) > 0 {
		items := make([]discoveryItem, 0, len(traffic.Bindings))
		for _, pass := range []bool{true, false} {
			for _, b := range traffic.Bindings {
				if (b.Role == "proof") != pass {
					continue
				}
				items = append(items, discoveryItem{
					Kind: "evidence", Method: b.Snapshot.Method, URL: b.Snapshot.URL,
					Status: b.Snapshot.Status, Hit: pass,
					Text: clip(b.Note, 260), Query: queryPairs(b.Snapshot.URL),
				})
			}
		}
		if len(items) > 12 {
			items = items[:12]
		}
		steps = append(steps, discoveryStep{
			Phase: "证据", Title: "证明它的原始请求/响应",
			Items: items,
		})
	}

	if len(steps) == 0 {
		steps = append(steps, discoveryStep{
			Phase: "无链路",
			Title: "这条漏洞没有可展示的发现路径",
			Note:  "常见原因：漏洞不是探索流程产生的（人工登记/继承/导入），或所属任务已删除。",
		})
	}
	out["steps"] = steps
	writeJSON(w, 200, out)
}

// resolveFindingTarget 解析「打的是哪个接口、参数是什么、接口是哪来的」。
// 优先级：endpoint 资产（带 method/params，能回答来源）> 绑定流量 > 摘要里的 URL > 名字里的 METHOD /path。
func (s *Server) resolveFindingTarget(ctx context.Context, f *db.DBFinding) discoveryTarget {
	var t discoveryTarget

	// 先拿到 URL（证据优先），再回查有没有对应的 endpoint 资产。
	if tr, err := s.m.pg.GetFindingTraffic(ctx, f.ID); err == nil && tr != nil {
		var fallback *db.TrafficEvidenceSnapshot
		for i := range tr.Bindings {
			b := &tr.Bindings[i]
			if b.Snapshot.URL == "" {
				continue
			}
			if b.Role == "proof" {
				t.Method, t.URL = b.Snapshot.Method, b.Snapshot.URL
				break
			}
			if fallback == nil {
				snap := b.Snapshot
				fallback = &snap
			}
		}
		if t.URL == "" && fallback != nil {
			t.Method, t.URL = fallback.Method, fallback.URL
		}
	}
	if t.URL == "" {
		if u := discURLRE.FindString(f.Summary); u != "" {
			t.URL = strings.TrimRight(u, ".,;)]}")
		}
	}
	// 兜底 2：evidence 里的原始请求报文（POST 漏洞常常只有这里写着完整路径）。
	if t.URL == "" {
		if m := discReqLineRE.FindStringSubmatch(f.Evidence); len(m) == 3 {
			method, path := strings.ToUpper(m[1]), m[2]
			host := ""
			if h := discHostRE.FindStringSubmatch(f.Evidence); len(h) == 2 {
				host = h[1]
			}
			if host == "" {
				host = s.findingAssetHost(f.AssetIDs)
			}
			switch {
			case host == "":
				t.Method, t.URL = method, path
			case strings.HasPrefix(path, "http"):
				t.Method, t.URL = method, path
			default:
				scheme := "https://"
				if strings.HasPrefix(host, "http://") {
					scheme = "http://"
				}
				host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
				t.Method, t.URL = method, scheme+host+path
			}
		}
	}
	if t.URL == "" {
		if m := discNameRE.FindStringSubmatch(f.Name); len(m) == 3 {
			t.Method, t.URL = strings.ToUpper(m[1]), m[2]
			if host := s.findingAssetHost(f.AssetIDs); host != "" {
				if strings.Contains(host, "://") {
					if i := strings.Index(host, "/"); i > 0 {
						host = host[:i]
					}
					t.URL = host + m[2]
				} else {
					t.URL = "https://" + host + m[2]
				}
			}
		}
	}

	// 回查 endpoint 资产：方法、参数、所属任务、域名——把"接口哪来的"说清楚。
	if t.URL != "" {
		t.AssetID, t.AssetDomain, t.AssetTasks, t.Params = s.matchEndpointAsset(t.URL)
		if t.AssetID > 0 {
			t.Source = "资产 #" + i64s(t.AssetID) + "（endpoint 资产，由能力测绘/JS 逆向登记）"
		}
	}
	if t.Source == "" && t.URL != "" {
		t.Source = "本意图实测命中（未登记为 endpoint 资产）"
	}
	return t
}

// parseAssetParams 把 assets.params（text[] 里每条是一段 JSON 串）摊平成参数列表。
func parseAssetParams(raw []byte) []discoveryParam {
	if len(raw) == 0 {
		return nil
	}
	// params 是 jsonb[]：to_json(params) 得到的是「对象数组」。也兼容元素是
	// JSON 字符串的旧形态（text[]）。
	var objs []discoveryParam
	if err := json.Unmarshal(raw, &objs); err == nil && len(objs) > 0 {
		out := make([]discoveryParam, 0, len(objs))
		for _, p := range objs {
			if p.Name == "" {
				continue
			}
			out = append(out, p)
			if len(out) >= 30 {
				break
			}
		}
		return out
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return nil
	}
	out := make([]discoveryParam, 0, len(arr))
	for _, item := range arr {
		var p discoveryParam
		if json.Unmarshal([]byte(item), &p) != nil {
			continue
		}
		if p.Name == "" {
			continue
		}
		out = append(out, p)
		if len(out) >= 30 {
			break
		}
	}
	return out
}

// findingAssetHost 取该漏洞关联资产里的主机（优先 endpoint 的 URL，其次域名/IP）。
func (s *Server) findingAssetHost(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	rows, err := s.m.pg.Query(
		`SELECT COALESCE(NULLIF(url,''), domain, ip) FROM assets
		 WHERE id = ANY($1) AND COALESCE(NULLIF(url,''), domain, ip) <> ''
		 ORDER BY (type='endpoint') DESC LIMIT 1`, ids)
	if err != nil {
		return ""
	}
	defer rows.Close()
	if rows.Next() {
		var host string
		if rows.Scan(&host) == nil {
			return host
		}
	}
	return ""
}

// discoveryProbes 从某意图的 Bash 调用里抽取真实的 HTTP 请求序列（含 query 与 body）。
func (s *Server) discoveryProbes(expID, intentID int64, targetMethod, targetURL string) []discoveryItem {
	rows, err := s.m.pg.Query(
		`SELECT COALESCE(detail,''), COALESCE(summary,'') FROM activity
		 WHERE exploration_id=$1 AND node_id=$2 AND kind='tool_use' AND tool='Bash'
		 ORDER BY id LIMIT 600`, expID, intentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	targetPath := urlPath(targetURL)
	targetHost := urlHost(targetURL)
	seen := map[string]bool{}
	out := make([]discoveryItem, 0, 24)
	for rows.Next() {
		var detail, summary string
		if rows.Scan(&detail, &summary) != nil {
			continue
		}
		cmd := bashCommand(detail)
		if cmd == "" {
			cmd = bashCommand(summary)
		}
		if cmd == "" {
			cmd = tolerantCommand(summary)
		}
		if cmd == "" {
			continue
		}
		body := extractBody(cmd)
		for _, raw := range discURLRE.FindAllString(cmd, 4) {
			u := strings.TrimRight(raw, ".,;)]}")
			if targetHost != "" && urlHost(u) != targetHost {
				continue // 只看打在目标主机上的请求
			}
			if seen[u] {
				continue
			}
			seen[u] = true
			method := "GET"
			if m := discMethodRE.FindStringSubmatch(cmd); len(m) == 2 {
				method = strings.ToUpper(m[1])
			} else if strings.Contains(cmd, "probe2.sh") {
				method = "POST"
			}
			hit := targetPath != "" && urlPath(u) == targetPath
			if hit && targetMethod != "" {
				method = targetMethod
			}
			item := discoveryItem{Kind: "probe", Method: method, URL: u, Hit: hit, Query: queryPairs(u)}
			if method != "GET" && body != "" {
				item.Body = body
			}
			out = append(out, item)
			if len(out) >= 24 {
				return out
			}
		}
	}
	return out
}

// extractBody 从命令里抽出 JSON 请求体（单引号包住的 {...}），取最长的一段。
func extractBody(cmd string) string {
	ms := discBodyRE.FindAllStringSubmatch(cmd, -1)
	best := ""
	for _, m := range ms {
		if len(m) == 2 && len(m[1]) > len(best) {
			best = m[1]
		}
	}
	if len(best) > 600 {
		best = best[:600] + "…"
	}
	return best
}

// queryPairs 把 URL 的 query 拆成 k=v 列表（值过长截断）。
func queryPairs(raw string) []string {
	i := strings.Index(raw, "?")
	if i < 0 || i == len(raw)-1 {
		return nil
	}
	q := raw[i+1:]
	if j := strings.Index(q, "#"); j >= 0 {
		q = q[:j]
	}
	parts := strings.Split(q, "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if len(p) > 90 {
			p = p[:90] + "…"
		}
		out = append(out, p)
		if len(out) >= 12 {
			break
		}
	}
	return out
}

// discoveryChain 把祖先节点里真正构成「发现路径」的那些摊平（由远及近）。
func discoveryChain(nodes []*db.Node, edges []db.Edge, findingNode int64) []discoveryItem {
	byID := make(map[int64]*db.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	prefer := map[int64]int64{}
	for _, e := range edges {
		if e.Rel != "yields" && e.Rel != "derived_from" && e.Rel != "spawns" {
			continue
		}
		if _, ok := prefer[e.To]; !ok {
			prefer[e.To] = e.From
		}
	}
	var path []int64
	cur := findingNode
	for i := 0; i < 10; i++ {
		path = append(path, cur)
		next, ok := prefer[cur]
		if !ok {
			break
		}
		cur = next
	}
	out := make([]discoveryItem, 0, len(path))
	for i := len(path) - 1; i >= 0; i-- {
		n := byID[path[i]]
		if n == nil {
			continue
		}
		out = append(out, discoveryItem{
			Kind: n.Kind, Ref: "#" + i64s(n.ID), Text: clip(nodeOneLine(n), 240),
		})
	}
	return out
}

// intentYielding 找到「产出了这条漏洞」的意图节点（yields 边的源）。
func intentYielding(nodes []*db.Node, edges []db.Edge, findingNode int64) int64 {
	kinds := make(map[int64]string, len(nodes))
	for _, n := range nodes {
		kinds[n.ID] = n.Kind
	}
	for _, e := range edges {
		if e.Rel == "yields" && e.To == findingNode && kinds[e.From] == db.KindIntent {
			return e.From
		}
	}
	for _, e := range edges {
		if e.To == findingNode && kinds[e.From] == db.KindIntent {
			return e.From
		}
	}
	return 0
}

// bashCommand 从 activity 的工具入参 JSON 里取出命令正文。
func bashCommand(summary string) string {
	i := strings.Index(summary, "{")
	if i < 0 {
		return ""
	}
	var payload struct {
		Command string `json:"command"`
	}
	if json.Unmarshal([]byte(summary[i:]), &payload) != nil {
		return ""
	}
	return payload.Command
}

// tolerantCommand 在 JSON 被截断（activity.summary 只存前缀）时，从残缺文本里
// 硬刮出命令正文：取 "command": " 之后的内容，逐个反转义常见序列。
func tolerantCommand(raw string) string {
	const marker = `"command":`
	i := strings.Index(raw, marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(raw[i+len(marker):])
	rest = strings.TrimPrefix(rest, `"`)
	if j := strings.LastIndex(rest, `"`); j > 0 {
		rest = rest[:j]
	}
	r := strings.NewReplacer(`\\n`, "\\n", `\\"`, `"`, `\\\\`, `\\`, `\\t`, "\\t")
	return r.Replace(rest)
}

// nodeOneLine 取节点的一句话摘要（payload 的 summary/text/title/name 里第一个非空的）。
func nodeOneLine(n *db.Node) string {
	if n == nil || len(n.Payload) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(n.Payload, &m) != nil {
		return ""
	}
	for _, k := range []string{"summary", "text", "title", "name", "detail"} {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func urlPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if j := strings.Index(u, "/"); j >= 0 {
			u = u[j:]
		} else {
			return "/"
		}
	}
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

// urlHost 取 URL 的主机（去掉 scheme/端口/路径）。
func urlHost(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, ":"); i >= 0 {
		u = u[:i]
	}
	return u
}

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// matchEndpointAsset 在资产表里找这条请求对应的 endpoint 资产。
//
// 资产 URL 里的路径参数是**占位符**（`/FrontRep/%7Bseltype%7D/%7Bstrdate%7D`），
// 而实测 URL 是真实取值（`/FrontRep/confirm/20240101`）——精确匹配永远对不上。
// 做法：从目标 URL 尾部逐段剥离路径，用前缀 LIKE 查候选，再按字面前缀长度打分。
// 这样 `/FrontRep/confirm/1794/1795 AND 1=1` 会一路剥到 `/FrontRep/` 命中占位符资产。
func (s *Server) matchEndpointAsset(targetURL string) (id int64, domain string, tasks []int64, params []discoveryParam) {
	if targetURL == "" {
		return 0, "", nil, nil
	}
	prefix := targetURL
	if i := strings.IndexAny(prefix, "?#"); i > 0 {
		prefix = prefix[:i]
	}
	bestScore := 0
	var bestParams []byte
	for hop := 0; hop < 6; hop++ {
		if prefix == "" || strings.HasSuffix(prefix, "://") {
			break
		}
		rows, err := s.m.pg.Query(`
SELECT id, COALESCE(url,''), COALESCE(domain,''), COALESCE(to_json(params)::text,'[]'),
       COALESCE(array_to_string(task_ids, ','), '')
FROM assets
WHERE type = 'endpoint' AND url LIKE $1 || '%'
ORDER BY length(url) DESC LIMIT 50`, prefix)
		if err != nil {
			break
		}
		for rows.Next() {
			var (
				aid     int64
				aurl    string
				adomain string
				araw    []byte
				atasks  string
			)
			if rows.Scan(&aid, &aurl, &adomain, &araw, &atasks) != nil {
				continue
			}
			if score := literalPrefixScore(aurl, targetURL); score > bestScore {
				bestScore = score
				id, domain, bestParams = aid, adomain, araw
				tasks = parseIDList(atasks)
			}
		}
		rows.Close()
		if id > 0 {
			break
		}
		// 剥掉最后一段路径继续找。注意先去掉结尾的 "/"，否则 LastIndex 命中的
		// 就是它自己，prefix 永远不变（实测踩过：只剥了一层就卡住）。
		trimmed := strings.TrimSuffix(prefix, "/")
		if i := strings.LastIndex(trimmed, "/"); i > 8 {
			prefix = trimmed[:i+1]
		} else {
			break
		}
	}
	if id == 0 {
		return 0, "", nil, nil
	}
	return id, domain, tasks, parseAssetParams(bestParams)
}

// literalPrefixScore 返回资产 URL 与目标 URL 的字面前缀匹配长度（占位符之前的部分）。
// 0 表示不匹配。
func literalPrefixScore(assetURL, targetURL string) int {
	cut := len(assetURL)
	for _, marker := range []string{"%7B", "%7b", "{"} {
		if i := strings.Index(assetURL, marker); i >= 0 && i < cut {
			cut = i
		}
	}
	if cut == 0 {
		return 0
	}
	lit := assetURL[:cut]
	if len(lit) > len(targetURL) || targetURL[:len(lit)] != lit {
		return 0
	}
	return len(lit)
}

// parseIDList 解析 "17,615" 这样的 id 列表。
func parseIDList(raw string) []int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if v, err := strconv.ParseInt(p, 10, 64); err == nil {
			out = append(out, v)
		}
	}
	return out
}
