package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// findingDiscoveryPath 把一条漏洞的溯源链渲染成**人能读的白话时间线**：
// 源头（静态采集/资产）→ 目标判定（为什么选这个入口）→ 实测请求 → 决定性证据。
//
// 数据全部来自已有记录，不重新探测：
//   - 图谱：exploration_edges 的 yields（意图 → 漏洞）/ derived_from（事实 → 意图）
//   - 意图文本：说明"为什么盯上这个入口"
//   - activity：该意图的 Bash 工具调用，从中抽出真实发过的 HTTP 请求
//   - 已绑定的流量快照：命中请求与决定性证据（method/url/status）
type discoveryItem struct {
	Kind   string `json:"kind"`             // asset|fact|intent|finding|probe|evidence
	Ref    string `json:"ref,omitempty"`    // #32100
	Method string `json:"method,omitempty"` // GET/POST…
	URL    string `json:"url,omitempty"`
	Status int    `json:"status,omitempty"`
	Text   string `json:"text"`
	Hit    bool   `json:"hit,omitempty"`
}

type discoveryStep struct {
	Phase string          `json:"phase"`
	Title string          `json:"title"`
	Items []discoveryItem `json:"items"`
	Note  string          `json:"note,omitempty"`
}

// 从 Bash 命令里抽取真实发过的 HTTP 请求。
var (
	discURLRE    = regexp.MustCompile(`https?://[^\s"'\\<>|;)]+`)
	discMethodRE = regexp.MustCompile(`(?i)-X\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)`)
	discNameRE   = regexp.MustCompile(`(?i)\b(GET|POST|PUT|DELETE|PATCH)\s+(/[A-Za-z0-9_\-./{}$%:*?=&]+)`)
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
		"steps": []discoveryStep{},
	}
	steps := make([]discoveryStep, 0, 6)

	// 目标入口：优先取已绑定的流量证据（proof 优先），其次从漏洞名里解析
	// 「METHOD /path」并与受影响资产的域名拼起来。
	targetMethod, targetURL := s.resolveFindingTarget(r.Context(), f)
	out["target_method"] = targetMethod
	out["target_url"] = targetURL

	var story *db.ExplorationStore
	if f.TaskID != nil {
		if t := s.m.ResolveTask(i64s(*f.TaskID)); t != nil {
			story = t.Store
		}
	}

	// ① 溯源链（由远及近）
	var chain []discoveryItem
	var intentID int64
	if story != nil && f.NodeID != nil {
		if nodes, edges, lerr := story.FindingLineage(*f.NodeID); lerr == nil {
			chain = discoveryChain(nodes, edges, *f.NodeID)
			intentID = intentYielding(nodes, edges, *f.NodeID)
		}
	}
	if len(chain) > 0 {
		steps = append(steps, discoveryStep{
			Phase: "溯源", Title: "这条漏洞是从哪条线索长出来的",
			Items: chain,
			Note:  "由远及近：最早的采集/事实 → 派生的意图 → 本条漏洞",
		})
	}

	// ② 目标判定 + ③ 实测请求序列
	if intentID > 0 && story != nil && story.ID() > 0 {
		if n, nerr := story.GetNode(intentID); nerr == nil && n != nil {
			steps = append(steps, discoveryStep{
				Phase: "目标判定",
				Title: "为什么要打这个入口",
				Items: []discoveryItem{{Kind: "intent", Ref: "#" + i64s(n.ID), Text: clip(nodeOneLine(n), 420)}},
			})
			if probes := s.discoveryProbes(story.ID(), intentID, targetMethod, targetURL); len(probes) > 0 {
				steps = append(steps, discoveryStep{
					Phase: "实测",
					Title: "实际发了哪些请求（按时间顺序）",
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
					Status: b.Snapshot.Status, Text: clip(b.Note, 260), Hit: pass,
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

// resolveFindingTarget 解析「打的是哪个接口」：绑定流量 > 漏洞名里的 METHOD /path + 资产域名。
func (s *Server) resolveFindingTarget(ctx context.Context, f *db.DBFinding) (method, url string) {
	if tr, err := s.m.pg.GetFindingTraffic(ctx, f.ID); err == nil && tr != nil {
		var fallback *db.TrafficEvidenceSnapshot
		for i := range tr.Bindings {
			b := &tr.Bindings[i]
			if b.Snapshot.URL == "" {
				continue
			}
			if b.Role == "proof" {
				return b.Snapshot.Method, b.Snapshot.URL
			}
			if fallback == nil {
				snap := b.Snapshot
				fallback = &snap
			}
		}
		if fallback != nil {
			return fallback.Method, fallback.URL
		}
	}
	// 回退 2：summary 里直接写了完整 URL。
	if u := discURLRE.FindString(f.Summary); u != "" {
		return "", strings.TrimRight(u, ".,;)]}")
	}
	// 回退：从名字里解析「METHOD /path」，挂到受影响资产的主机上。
	if m := discNameRE.FindStringSubmatch(f.Name); len(m) == 3 {
		method, path := strings.ToUpper(m[1]), m[2]
		var host string
		if len(f.AssetIDs) > 0 {
			rows, err := s.m.pg.Query(
				`SELECT COALESCE(NULLIF(url,''), domain, ip) FROM assets
				 WHERE id = ANY($1) AND COALESCE(NULLIF(url,''), domain, ip) <> '' LIMIT 1`,
				f.AssetIDs)
			if err == nil {
				defer rows.Close()
				if rows.Next() {
					_ = rows.Scan(&host)
				}
			}
		}
		switch {
		case host == "":
			return method, path
		case strings.Contains(host, "://"):
			if i := strings.Index(host, "/"); i > 0 {
				host = host[:i]
			}
			return method, host + path
		default:
			return method, "https://" + host + path
		}
	}
	return "", ""
}

// discoveryProbes 从某意图的 Bash 调用里抽取真实的 HTTP 请求序列。
func (s *Server) discoveryProbes(expID, intentID int64, targetMethod, targetURL string) []discoveryItem {
	// detail 存的是完整的工具入参，summary 只留前缀（实测被截断到 ~206 字符，
	// JSON 不完整 → 直接解析会丢掉大半请求）。两者都要，优先 detail。
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
			cmd = tolerantCommand(summary) // JSON 被截断时兜底
		}
		if cmd == "" {
			continue
		}
		for _, raw := range discURLRE.FindAllString(cmd, 4) {
			u := strings.TrimRight(raw, ".,;)]}")
			// 只看打在目标主机上的请求：同一意图里常夹带 CA 下载、旁站验证等
			// 无关 URL，混进来会把"实测序列"读成噪声。
			if targetHost != "" && urlHost(u) != targetHost {
				continue
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
			out = append(out, discoveryItem{Kind: "probe", Method: method, URL: u, Hit: hit})
			if len(out) >= 24 {
				return out
			}
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
			Kind: n.Kind, Ref: "#" + i64s(n.ID), Text: clip(nodeOneLine(n), 200),
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

// bashCommand 从 activity.summary（形如 `Bash {"command":"..."}`）里取出命令正文。
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

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// tolerantCommand 在 JSON 被截断（activity.summary 只存前缀）时，从残缺文本里
// 硬刮出命令正文：取 "command": " 之后的内容，逐个反转义常见序列。够用来抽 URL
// 和方法（-X POST / probe2.sh），不需要完整 JSON。
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
	r := strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\\`, `\`, `\t`, "\t")
	return r.Replace(rest)
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
