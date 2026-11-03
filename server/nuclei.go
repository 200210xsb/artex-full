package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Nuclei POC 能力的页面侧后端。
//
// 这里直接调用 /opt/artex/bin/nuclei 与 /opt/artex/nuclei-templates，**不经过 MCP
// 子进程**（和 webshell 页面同样的取舍）：页面点一下就有响应，也不用为每次查询
// 起一个 Python 进程。MCP（/opt/artex/bin/nuclei_mcp.py）与本文件共用同一份模板
// 目录，两边能力一致。
//
// 三个必须注意的坑（实测踩出来的，改这里之前先看）：
//  1. nuclei 会读 stdin 找目标。exec.Cmd 的 Stdin 必须留空（nil→/dev/null），
//     否则可能阻塞不退出；
//  2. 只给 -tags/-severity 而不给 -t 时，nuclei 会去 ~/nuclei-templates 找并
//     直接报 "no templates found in path" 退出，所以必须显式 -t 模板目录；
//  3. -silent 会把 -stats 一起吞掉，请求数只能靠 -stats-json（退出前打一条
//     {"requests":"37",...}，注意数字是字符串）。

const (
	nucleiBinPath   = "/opt/artex/bin/nuclei"
	nucleiTplRoot   = "/opt/artex/nuclei-templates"
	nucleiIndexTTL  = 10 * time.Minute
	nucleiMaxHits   = 300
	nucleiMaxBody   = 256 << 10
	nucleiHeadBytes = 8192 // 只读模板头部：info 块基本都在前 8K

	// 「按指纹自动匹配并验证 POC」的封顶值
	nucleiMatchMaxLimit   = 200
	nucleiMatchDefLimit   = 50
	nucleiMatchMaxRate    = 150
	nucleiMatchDefRate    = 50
	nucleiProbeDefTimeout = 180
	nucleiProbeMaxTimeout = 600
)

// NucleiTemplate 是模板索引里的一行，够页面列表用。
type NucleiTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Tags        string `json:"tags"`
	Author      string `json:"author"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

var (
	nucleiIdxMu   sync.Mutex
	nucleiIdxAt   time.Time
	nucleiIdxList []NucleiTemplate

	nucleiIDLine = regexp.MustCompile(`^id:\s*(.+?)\s*$`)
	nucleiKVLine = regexp.MustCompile(`^([A-Za-z0-9_.\-]+):\s*(.*)$`)
	nucleiBlock  = regexp.MustCompile(`^[|>][-+0-9]*$`)
	nucleiReqCnt = regexp.MustCompile(`"requests"\s*:\s*"?(\d+)"?`)

	nucleiSeverityRank = map[string]int{
		"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
	}
)

// ---------------------------------------------------------------------------
// 模板索引（内存缓存，10 分钟过期）
// ---------------------------------------------------------------------------

func nucleiIndex() ([]NucleiTemplate, error) {
	nucleiIdxMu.Lock()
	defer nucleiIdxMu.Unlock()
	if len(nucleiIdxList) > 0 && time.Since(nucleiIdxAt) < nucleiIndexTTL {
		return nucleiIdxList, nil
	}
	if _, err := os.Stat(nucleiTplRoot); err != nil {
		return nil, fmt.Errorf("模板目录不可用: %s", nucleiTplRoot)
	}
	list, err := buildNucleiIndex()
	if err != nil {
		return nil, err
	}
	nucleiIdxList, nucleiIdxAt = list, time.Now()
	return list, nil
}

func buildNucleiIndex() ([]NucleiTemplate, error) {
	out := make([]NucleiTemplate, 0, 8192)
	skip := map[string]bool{".git": true, ".github": true, "helpers": true, "profiles": true}
	err := filepath.WalkDir(nucleiTplRoot, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // 单个文件读不到就跳过，不整体失败
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		buf := make([]byte, nucleiHeadBytes)
		n, _ := f.Read(buf)
		_ = f.Close()
		if n <= 0 {
			return nil
		}
		id, info, _ := parseNucleiYAMLHead(string(buf[:n]))
		if id == "" || len(info) == 0 {
			return nil // payload / workflow / 配置，不是模板
		}
		rel, err := filepath.Rel(nucleiTplRoot, p)
		if err != nil {
			return nil
		}
		out = append(out, NucleiTemplate{
			ID:          id,
			Name:        info["name"],
			Severity:    nucleiNormSeverity(info["severity"]),
			Tags:        nucleiNormTags(info["tags"]),
			Author:      nucleiNormAuthor(info["author"]),
			Path:        filepath.ToSlash(rel),
			Description: nucleiTruncate(info["description"], 260),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := nucleiSeverityRank[out[i].Severity], nucleiSeverityRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// parseNucleiYAMLHead 只解析模板头部的 id 与 info 块：够用且不引入 YAML 依赖。
func parseNucleiYAMLHead(raw string) (string, map[string]string, []string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	info := map[string]string{}
	var refs []string

	id := ""
	scan := len(lines)
	if scan > 300 {
		scan = 300
	}
	for i := 0; i < scan; i++ {
		if m := nucleiIDLine.FindStringSubmatch(lines[i]); m != nil {
			id = nucleiYAMLScalar(m[1])
			break
		}
	}

	start := -1
	for i := 0; i < scan; i++ {
		if lines[i] == "info:" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return id, info, refs
	}

	curKey := ""
	curIndent := 1
	inBlock := false
	fold := false
	var block []string

	flush := func() {
		if inBlock && curKey != "" {
			if fold {
				parts := make([]string, 0, len(block))
				for _, b := range block {
					if s := strings.TrimSpace(b); s != "" {
						parts = append(parts, s)
					}
				}
				info[curKey] = strings.TrimSpace(strings.Join(parts, " "))
			} else {
				info[curKey] = strings.TrimSpace(strings.Join(block, "\n"))
			}
		}
		inBlock = false
		block = nil
	}

	for _, ln := range lines[start:] {
		if strings.TrimSpace(ln) == "" {
			if inBlock {
				block = append(block, "")
			}
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " \t"))
		if indent == 0 {
			break // info 块结束，后面是 http/requests
		}
		trimmed := strings.TrimSpace(ln)

		// 块标量续行：必须比所属 key 缩进更深，否则是新 key 或列表项
		if inBlock && indent > curIndent {
			block = append(block, trimmed)
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && curKey != "" {
			item := nucleiYAMLScalar(strings.TrimPrefix(trimmed, "- "))
			if item == "" {
				continue
			}
			if curKey == "reference" {
				refs = append(refs, item)
				continue
			}
			if info[curKey] == "" {
				info[curKey] = item
			} else {
				info[curKey] += ", " + item
			}
			continue
		}
		m := nucleiKVLine.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		flush()
		curKey = strings.ToLower(m[1])
		curIndent = indent
		val := strings.TrimSpace(m[2])
		if nucleiBlock.MatchString(val) {
			inBlock = true
			fold = strings.HasPrefix(val, ">")
			block = nil
			info[curKey] = ""
			continue
		}
		info[curKey] = nucleiYAMLScalar(val)
	}
	flush()
	return id, info, refs
}

func nucleiYAMLScalar(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if v[0] == '\'' || v[0] == '"' {
		q := v[0]
		if len(v) >= 2 && v[len(v)-1] == q {
			return v[1 : len(v)-1]
		}
		return v[1:]
	}
	return v
}

func nucleiNormSeverity(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return "unknown"
	}
	return s
}

func nucleiNormTags(v string) string {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' })
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		s := strings.ToLower(strings.TrimSpace(p))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

func nucleiNormAuthor(v string) string {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' })
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		s := strings.TrimSpace(strings.Trim(p, ",;"))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func nucleiTruncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// 按 rune 截断，避免把中文切坏
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// nucleiGitInfo 取模板库当前提交与最后提交时间，拿不到就返回空串（不报错）。
func nucleiGitInfo() (head, commitTime string) {
	run := func(args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", nucleiTplRoot}, args...)...)
		cmd.Stdin, cmd.Env = nil, append(os.Environ(), "HOME=/root")
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return run("rev-parse", "--short", "HEAD"), run("log", "-1", "--format=%cd", "--date=format:%Y-%m-%d %H:%M")
}

// resolveNucleiTemplate 把 id / 相对路径 / 绝对路径 解析成真实文件路径。
func resolveNucleiTemplate(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("模板引用为空")
	}
	if strings.HasPrefix(ref, "/") {
		abs := filepath.Clean(ref)
		if !strings.HasPrefix(abs, nucleiTplRoot+string(os.PathSeparator)) {
			return "", fmt.Errorf("绝对路径必须位于 %s 下", nucleiTplRoot)
		}
		if st, err := os.Stat(abs); err != nil || st.IsDir() {
			return "", fmt.Errorf("模板文件不存在: %s", ref)
		}
		return abs, nil
	}
	if strings.HasSuffix(ref, ".yaml") || strings.HasSuffix(ref, ".yml") {
		abs := filepath.Join(nucleiTplRoot, filepath.Clean("/"+ref))
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return abs, nil
		}
	}
	list, err := nucleiIndex()
	if err != nil {
		return "", err
	}
	low := strings.ToLower(ref)
	var fuzzy []NucleiTemplate
	for _, t := range list {
		if t.ID == ref {
			return filepath.Join(nucleiTplRoot, filepath.FromSlash(t.Path)), nil
		}
		if t.ID == low || strings.ToLower(t.ID) == low {
			return filepath.Join(nucleiTplRoot, filepath.FromSlash(t.Path)), nil
		}
		if strings.Contains(strings.ToLower(t.ID), low) || strings.Contains(strings.ToLower(t.Path), low) {
			fuzzy = append(fuzzy, t)
		}
	}
	if len(fuzzy) == 1 {
		return filepath.Join(nucleiTplRoot, filepath.FromSlash(fuzzy[0].Path)), nil
	}
	if len(fuzzy) > 1 {
		examples := make([]string, 0, 5)
		for i, f := range fuzzy {
			if i >= 5 {
				break
			}
			examples = append(examples, f.ID)
		}
		return "", fmt.Errorf("模板引用不唯一（%d 个候选，例如 %s），请用搜索精确选一个", len(fuzzy), strings.Join(examples, ", "))
	}
	return "", fmt.Errorf("找不到模板: %s", ref)
}

// ---------------------------------------------------------------------------
// GET /api/nuclei/stats
// ---------------------------------------------------------------------------

func (s *Server) nucleiStats(w http.ResponseWriter, r *http.Request) {
	list, err := nucleiIndex()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	severity := map[string]int{}
	tagCount := map[string]int{}
	for _, t := range list {
		severity[t.Severity]++
		for _, tg := range strings.Split(t.Tags, ",") {
			if tg = strings.TrimSpace(tg); tg != "" {
				tagCount[tg]++
			}
		}
	}
	type tagRow struct {
		Tag   string `json:"tag"`
		Count int    `json:"count"`
	}
	tags := make([]tagRow, 0, len(tagCount))
	for k, v := range tagCount {
		tags = append(tags, tagRow{Tag: k, Count: v})
	}
	sort.Slice(tags, func(i, j int) bool {
		if tags[i].Count != tags[j].Count {
			return tags[i].Count > tags[j].Count
		}
		return tags[i].Tag < tags[j].Tag
	})
	if len(tags) > 20 {
		tags = tags[:20]
	}
	head, commit := nucleiGitInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":       len(list),
		"severity":    severity,
		"top_tags":    tags,
		"last_commit": commit,
		"head":        head,
		"dir":         nucleiTplRoot,
	})
}

// ---------------------------------------------------------------------------
// GET /api/nuclei/search
// ---------------------------------------------------------------------------

func nucleiTagsMatch(want []string, have string) bool {
	if len(want) == 0 {
		return true
	}
	set := map[string]bool{}
	for _, h := range strings.Split(have, ",") {
		if h = strings.TrimSpace(h); h != "" {
			set[h] = true
		}
	}
	for _, w := range want {
		if set[w] {
			return true
		}
		for h := range set {
			if strings.HasPrefix(h, w+"-") {
				return true
			}
		}
	}
	return false
}

func splitCSVLower(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n'
	}) {
		v := strings.ToLower(strings.TrimSpace(p))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (s *Server) nucleiSearch(w http.ResponseWriter, r *http.Request) {
	list, err := nucleiIndex()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	q := r.URL.Query()
	keyword := strings.ToLower(strings.TrimSpace(q.Get("keyword")))
	tags := splitCSVLower(q.Get("tags"))
	severity := splitCSVLower(q.Get("severity"))
	limit := atoiDefault(q.Get("limit"), 30)
	if limit < 1 {
		limit = 1
	}
	if limit > 300 {
		limit = 300
	}

	sevSet := map[string]bool{}
	for _, v := range severity {
		sevSet[v] = true
	}

	matched := make([]NucleiTemplate, 0, 64)
	total := 0
	for _, t := range list {
		if len(sevSet) > 0 && !sevSet[t.Severity] {
			continue
		}
		if !nucleiTagsMatch(tags, t.Tags) {
			continue
		}
		if keyword != "" {
			blob := strings.ToLower(t.ID + " " + t.Name + " " + t.Path + " " + t.Tags + " " + t.Author)
			if !strings.Contains(blob, keyword) {
				continue
			}
		}
		total++
		if len(matched) < limit {
			matched = append(matched, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total,
		"items": matched,
		"limit": limit,
	})
}

// ---------------------------------------------------------------------------
// GET /api/nuclei/template?id=
// ---------------------------------------------------------------------------

func (s *Server) nucleiTemplateDetail(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.URL.Query().Get("id"))
	if ref == "" {
		writeErr(w, http.StatusBadRequest, "缺少 id 参数（模板 id 或路径）")
		return
	}
	abs, err := resolveNucleiTemplate(ref)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取模板失败: "+err.Error())
		return
	}
	text := string(raw)
	id, info, refs := parseNucleiYAMLHead(text)
	rel, _ := filepath.Rel(nucleiTplRoot, abs)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          id,
		"name":        info["name"],
		"severity":    nucleiNormSeverity(info["severity"]),
		"tags":        nucleiNormTags(info["tags"]),
		"author":      nucleiNormAuthor(info["author"]),
		"description": strings.TrimSpace(info["description"]),
		"reference":   refs,
		"path":        filepath.ToSlash(rel),
		"yaml":        text,
		"size":        len(raw),
	})
}

// ---------------------------------------------------------------------------
// POST /api/nuclei/run
// ---------------------------------------------------------------------------

type nucleiRunRequest struct {
	Target    string   `json:"target"`
	Templates []string `json:"templates"`
	Tags      string   `json:"tags"`
	Severity  string   `json:"severity"`
	Rate      int      `json:"rate"`
	Timeout   int      `json:"timeout"`
	Stream    bool     `json:"stream"`
}

type NucleiHit struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Tags        string   `json:"tags"`
	Type        string   `json:"type"`
	MatchedAt   string   `json:"matched_at"`
	MatcherName string   `json:"matcher_name"`
	Extracted   []string `json:"extracted_results"`
	CurlCommand string   `json:"curl_command"`
}

func nucleiValidateTarget(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", fmt.Errorf("缺少必填参数 target（URL 或 host）")
	}
	if strings.HasPrefix(t, "-") {
		return "", fmt.Errorf("target 不能以 '-' 开头")
	}
	if len(t) > 2048 {
		return "", fmt.Errorf("target 过长")
	}
	if strings.ContainsAny(t, " \t\r\n") {
		return "", fmt.Errorf("target 不能包含空白或换行")
	}
	return t, nil
}

// nucleiRunExec 跑一次 nuclei，命中逐条回调（onHit 为 nil 时只收集）。
func nucleiRunExec(ctx context.Context, args []string, onHit func(NucleiHit)) ([]NucleiHit, int, bool, error) {
	if _, err := os.Stat(nucleiBinPath); err != nil {
		return nil, 0, false, fmt.Errorf("nuclei 未安装: %s", nucleiBinPath)
	}
	cmd := exec.CommandContext(ctx, nucleiBinPath, args...)
	cmd.Dir = "/tmp"
	cmd.Env = append(os.Environ(), "HOME=/root")
	cmd.Stdin = nil // 关键：nuclei 会读 stdin，必须留空

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, false, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, 0, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, false, fmt.Errorf("启动 nuclei 失败: %w", err)
	}

	hits := make([]NucleiHit, 0, 16)
	var stderrBuf strings.Builder
	var hitMu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// 用 Reader 而不是 Scanner：JSONL 里带 request/response，单行可能超过 64K
		br := bufio.NewReaderSize(stdout, 64<<10)
		for {
			line, readErr := br.ReadString('\n')
			line = strings.TrimSpace(line)
			if line != "" && strings.HasPrefix(line, "{") {
				if h, ok := parseNucleiHit(line); ok {
					hitMu.Lock()
					if len(hits) < nucleiMaxHits {
						hits = append(hits, h)
					}
					hitMu.Unlock()
					if onHit != nil {
						onHit(h)
					}
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, readErr := stderr.Read(buf)
			if n > 0 {
				hitMu.Lock()
				if stderrBuf.Len() < nucleiMaxBody {
					stderrBuf.Write(buf[:n])
				}
				hitMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()

	wg.Wait()
	waitErr := cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded

	requests := 0
	for _, m := range nucleiReqCnt.FindAllStringSubmatch(stderrBuf.String(), -1) {
		if v, err := strconv.Atoi(m[1]); err == nil && v > requests {
			requests = v
		}
	}
	// 超时/被杀不算致命错误：把已经拿到的结果返回给页面
	if waitErr != nil && !timedOut {
		if strings.Contains(stderrBuf.String(), "no templates") {
			return hits, requests, timedOut, fmt.Errorf("nuclei 没有加载到模板（检查模板目录）")
		}
	}
	return hits, requests, timedOut, nil
}

func parseNucleiHit(line string) (NucleiHit, bool) {
	var raw struct {
		TemplateID  string   `json:"template-id"`
		Template    string   `json:"template"`
		Type        string   `json:"type"`
		MatchedAt   string   `json:"matched-at"`
		Host        string   `json:"host"`
		MatcherName string   `json:"matcher-name"`
		Extracted   []string `json:"extracted-results"`
		CurlCommand string   `json:"curl-command"`
		Info        struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Tags     string `json:"tags"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return NucleiHit{}, false
	}
	id := raw.TemplateID
	if id == "" {
		id = raw.Template
	}
	if id == "" {
		return NucleiHit{}, false
	}
	at := raw.MatchedAt
	if at == "" {
		at = raw.Host
	}
	return NucleiHit{
		TemplateID:  id,
		Name:        raw.Info.Name,
		Severity:    strings.ToLower(raw.Info.Severity),
		Tags:        raw.Info.Tags,
		Type:        raw.Type,
		MatchedAt:   at,
		MatcherName: raw.MatcherName,
		Extracted:   raw.Extracted,
		CurlCommand: raw.CurlCommand,
	}, true
}

func (s *Server) nucleiRun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, nucleiMaxBody)
	var req nucleiRunRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	target, err := nucleiValidateTarget(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// 模板：显式 id/路径 → 解析成绝对路径；否则退回整个模板目录
	tplPaths := make([]string, 0, len(req.Templates))
	for _, ref := range req.Templates {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		abs, err := resolveNucleiTemplate(ref)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		tplPaths = append(tplPaths, abs)
	}
	tags := strings.Join(splitCSVLower(req.Tags), ",")
	severity := strings.Join(splitCSVLower(req.Severity), ",")
	if len(tplPaths) == 0 && tags == "" && severity == "" {
		writeErr(w, http.StatusBadRequest,
			"至少要选模板、tags 或 severity 之一，否则会跑全部 1 万+ 模板，对目标伤害太大")
		return
	}

	rate := req.Rate
	if rate <= 0 {
		rate = 50
	}
	if rate > 150 {
		rate = 150
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 180
	}
	if timeout < 5 {
		timeout = 5
	}
	if timeout > 600 {
		timeout = 600
	}

	args := []string{
		"-u", target, "-jsonl", "-silent", "-disable-update-check", "-nc",
		"-rl", strconv.Itoa(rate), "-stats", "-stats-interval", "1", "-stats-json",
	}
	strategy := fmt.Sprintf("限速 %d req/s", rate)
	if len(tplPaths) > 0 {
		for _, p := range tplPaths {
			args = append(args, "-t", p)
		}
		strategy += fmt.Sprintf("，模板 %d 个", len(tplPaths))
	} else {
		args = append(args, "-t", nucleiTplRoot)
		strategy += "，全库按条件筛选"
	}
	if tags != "" {
		args = append(args, "-tags", tags)
		strategy += "，tags=" + tags
	}
	if severity != "" {
		args = append(args, "-severity", severity)
		strategy += "，severity=" + severity
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()

	started := time.Now()
	if req.Stream {
		s.nucleiRunStream(w, r, ctx, args, strategy, target, started)
		return
	}

	hits, requests, timedOut, runErr := nucleiRunExec(ctx, args, nil)
	if runErr != nil {
		writeErr(w, http.StatusInternalServerError, runErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hits": hits,
		"summary": map[string]any{
			"matched":    len(hits),
			"requests":   requests,
			"elapsed_ms": time.Since(started).Milliseconds(),
			"timed_out":  timedOut,
			"strategy":   strategy,
			"target":     target,
		},
	})
}

// nucleiRunStream 用 SSE 把命中逐条推给页面：打完一条就能看到一条。
func (s *Server) nucleiRunStream(w http.ResponseWriter, r *http.Request, ctx context.Context,
	args []string, strategy, target string, started time.Time) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	var mu sync.Mutex
	send := func(event string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		flusher.Flush()
	}

	send("start", map[string]any{"target": target, "strategy": strategy})

	// 心跳：模板多的时候可能几十秒没命中，避免中间层断连
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				mu.Lock()
				fmt.Fprint(w, ": ping\n\n")
				flusher.Flush()
				mu.Unlock()
			}
		}
	}()

	hits, requests, timedOut, runErr := nucleiRunExec(ctx, args, func(h NucleiHit) {
		send("hit", h)
	})
	close(done)

	if runErr != nil {
		send("error", map[string]any{"error": runErr.Error()})
		return
	}
	send("summary", map[string]any{
		"matched":    len(hits),
		"requests":   requests,
		"elapsed_ms": time.Since(started).Milliseconds(),
		"timed_out":  timedOut,
		"strategy":   strategy,
		"target":     target,
	})
}

// ---------------------------------------------------------------------------
// 「按指纹自动匹配并验证 POC」
//
// 三段式链路：指纹探测（tech 模板 / HTTP 头粗判） → 按指纹反查候选 POC →
// 用候选模板实弹验证。匹配规则与 MCP 侧 nuclei_mcp.py 保持一致：
//  1. 指纹名与模板 info.tags 做大小写不敏感、去分隔符（-/_/空格）的匹配；
//  2. 只保留 severity ∈ {critical, high, medium} 且带 rce / file-upload /
//     deserialization / command-injection / sqli / misconfig 类标签或带 CVE 号的模板；
//  3. 按「拿 shell 概率」排序：A 直接命令执行 > B 文件上传 > C 反序列化 >
//     D 命令注入 > E SQLi 写文件 > F 弱配置；
//  4. 匹配不到就明说，绝不退化成盲扫全库（1 万+ 模板会把目标打挂）。
// ---------------------------------------------------------------------------

// NucleiFingerprint 一条技术指纹。
type NucleiFingerprint struct {
	Tech       string `json:"tech"`
	MatchedAt  string `json:"matched_at"`
	TemplateID string `json:"template_id"`
	// 来源：nuclei-tech（tech 模板命中）/ nuclei-tech-tag（模板 tag）/
	// http-header（响应头）/ http-title（HTML 标题）
	Source  string `json:"source"`
	Version string `json:"version,omitempty"`
	Note    string `json:"note,omitempty"`
}

// NucleiMatchCandidate 一个候选 POC。
type NucleiMatchCandidate struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Severity  string   `json:"severity"`
	Tags      string   `json:"tags"`
	Path      string   `json:"path"`
	Matched   []string `json:"matched"` // 命中的指纹词
	Tier      string   `json:"tier"`    // A/B/C/D/E/F
	TierLabel string   `json:"tier_label"`
	Score     int      `json:"score"`
	Class     string   `json:"class"`
	Advice    string   `json:"advice"`
	Landable  bool     `json:"landable"` // A/B 档 = 命中即可用于落马
}

var (
	nucleiFpSepRe    = regexp.MustCompile(`[-_/\\.]+`)
	nucleiFpWordRe   = regexp.MustCompile(`[^a-z0-9]+`)
	nucleiWordRe     = regexp.MustCompile(`[A-Za-z]+|[0-9]+`)
	nucleiCveIDRe    = regexp.MustCompile(`(?i)cve[-_\s]*\d{4}[-_\s]*\d{3,}`)
	nucleiVersionRe  = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	nucleiTitleRe    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	nucleiTechTailRe = regexp.MustCompile(`(?i)\s*[-_]?\s*(detection|detect)\s*$`)
	nucleiSpaceRe    = regexp.MustCompile(`\s+`)
)

// nucleiGenericTechTags 是 tech 模板里没有信息量的通用 tag，探测指纹时剔掉。
var nucleiGenericTechTags = map[string]bool{
	"tech": true, "intrusive": true, "discovery": true, "dos": true,
	"fuzzing": true, "headless": true, "network": true, "ssl": true,
	"http": true, "web": true,
}

// nucleiDangerClasses 定义「拿 shell 概率」分档，数组顺序即优先级。
type nucleiDangerClass struct {
	Name      string
	Tags      []string
	DescHints []string
	Tier      string
	Label     string
	Score     int
}

var nucleiDangerClasses = []nucleiDangerClass{
	{
		Name: "rce",
		Tags: []string{"rce", "remote-code-execution"},
		DescHints: []string{
			"remote code execution", "arbitrary command execution",
			"code execution", "command execution",
		},
		Tier:  "A",
		Label: "直接命令执行 —— 命中即等于拿到了命令通道",
		Score: 100,
	},
	{
		Name: "file-upload",
		Tags: []string{"file-upload", "arbitrary-file-upload",
			"unrestricted-file-upload", "file-write", "arbitrary-file-write"},
		DescHints: []string{"file upload", "arbitrary file write", "write file"},
		Tier:      "B",
		Label:     "文件上传 / 任意文件写 —— 命中即等于能落地文件",
		Score:     90,
	},
	{
		Name:      "deserialization",
		Tags:      []string{"deserialization", "deserialize", "insecure-deserialization"},
		DescHints: []string{"deserialization", "deserialize"},
		Tier:      "C",
		Label:     "反序列化 —— 可执行代码，但需要构造 payload",
		Score:     78,
	},
	{
		Name:      "command-injection",
		Tags:      []string{"command-injection", "os-command-injection", "code-injection"},
		DescHints: []string{"command injection", "os command injection", "os command"},
		Tier:      "D",
		Label:     "命令注入 —— 参数可控即可回显命令",
		Score:     68,
	},
	{
		Name:      "sqli",
		Tags:      []string{"sqli", "sql-injection"},
		DescHints: []string{"sql injection", "outfile"},
		Tier:      "E",
		Label:     "SQL 注入 —— 满足写文件条件时才能落地",
		Score:     45,
	},
}

var nucleiMisconfigTags = []string{
	"misconfig", "misconfiguration", "default-login", "default-password",
	"weak-password", "unauth", "unauthorized", "exposure", "exposed",
}

const (
	nucleiMisconfigLabel = "弱配置 / 默认口令 —— 一般拿不到 shell，只能当辅助信息"
	nucleiMisconfigTier  = "F"
	nucleiMisconfigScore = 20
	nucleiCveOnlyLabel   = "命中 CVE 号，但模板标签看不出直接落地 —— 需人工确认可利用性"
	nucleiCveOnlyTier    = "F"
	nucleiCveOnlyScore   = 25
)

// nucleiTierAdvice 是每个档位对应的「拿 shell」落地建议。
var nucleiTierAdvice = map[string]string{
	"A": "命中即等于拿到命令通道：用模板详情看完整请求，把命令参数换成 id/whoami 复现；" +
		"要持久化就去 WebShell 页面：payload_list 挑马 → payload_get 取全文 → 写文件落地 → shell_add 登记。",
	"B": "先确认上传目录能否解析脚本、有没有重命名/白名单；能解析就用 payload_get 取对应类型" +
		"（php/jsp/aspx）的马子直接传，再用 shell_add 登记。",
	"C": "先用模板自带 payload 确认可利用，再按目标中间件版本换 gadget 链；成功后落马并用 shell_add 登记。",
	"D": "确认注入参数与回显是否可控；命中后把命令换成 id/whoami 验证，成功即可落马并用 shell_add 登记。",
	"E": "重点看能否写文件：需要 FILE 权限 / secure_file_priv 可写 / 堆叠查询；" +
		"能用 outfile 或日志写马时再取 payload，否则只当信息泄露。",
	"F": "多半是弱配置/默认口令或只匹配到 CVE 号；当辅助信息用（读配置、找内网），" +
		"想拿 shell 请换 A/B 档模板。",
}

// ---------------------------------------------------------------------------
// 指纹归一与匹配
// ---------------------------------------------------------------------------

// nucleiFpCompact 去掉所有非字母数字并小写（用于子串匹配）。
func nucleiFpCompact(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// nucleiAllDigits 判断是不是纯数字（版本号碎片要丢掉）。
func nucleiAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// nucleiFpTokens 把指纹切成词元：先按空白切块，块内按 -/_/. 拆开，
// 同时保留块的整体紧凑形式（这样 "tom_cat" 既能得到 tom/cat，也能得到 tomcat）。
func nucleiFpTokens(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, chunk := range strings.Fields(strings.ToLower(s)) {
		for _, p := range nucleiFpSepRe.Split(chunk, -1) {
			p = strings.TrimSpace(p)
			if len(p) < 2 || nucleiAllDigits(p) {
				continue
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		c := nucleiFpCompact(chunk)
		if len(c) >= 4 && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// nucleiFpCveIDs 从指纹里抽出 CVE 编号（cve20214428 这种紧凑形式）。
func nucleiFpCveIDs(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, m := range nucleiCveIDRe.FindAllString(s, -1) {
		id := nucleiFpCompact(m)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// nucleiMatchKeywords 把一组指纹整理成 (CVE 编号列表, 普通关键词列表)。
// 指纹里带完整 CVE 编号时，那个编号本身就是最准的关键词，此时不再用裸 "cve"
// 泛匹配（否则会命中全库所有 CVE 模板）。
func nucleiMatchKeywords(fps []string) ([]string, []string) {
	cveIDs := []string{}
	tokens := []string{}
	seenCVE := map[string]bool{}
	seenTok := map[string]bool{}
	for _, fp := range fps {
		for _, cid := range nucleiFpCveIDs(fp) {
			if !seenCVE[cid] {
				seenCVE[cid] = true
				cveIDs = append(cveIDs, cid)
			}
		}
		for _, t := range nucleiFpTokens(fp) {
			if len(cveIDs) > 0 && t == "cve" {
				continue
			}
			if !seenTok[t] {
				seenTok[t] = true
				tokens = append(tokens, t)
			}
		}
	}
	return cveIDs, tokens
}

// nucleiTplBlob 模板的可匹配文本：id + name + tags + path。
func nucleiTplBlob(t NucleiTemplate) string {
	return t.ID + " " + t.Name + " " + t.Tags + " " + t.Path
}

// nucleiTplMatchKeywords 返回模板命中的关键词列表（空 = 不匹配）。
//
// 规则：关键词与模板的某个词完全相等，或该词以关键词开头（spring → springboot、
// ms → ms17），算命中；CVE 编号按去分隔符后的子串匹配。
// 用词表而不是裸子串，是为了避免 "scope" 命中 "laravel-telescope" 这类假阳性。
func nucleiTplMatchKeywords(t NucleiTemplate, cveIDs, tokens []string) []string {
	blob := nucleiTplBlob(t)
	blobCompact := nucleiFpCompact(blob)
	blobWords := map[string]bool{}
	for _, w := range nucleiWordRe.FindAllString(blob, -1) {
		if w != "" {
			blobWords[strings.ToLower(w)] = true
		}
	}
	hits := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			hits = append(hits, s)
		}
	}
	for _, cid := range cveIDs {
		if strings.Contains(blobCompact, cid) {
			add(cid)
		}
	}
	for _, tk := range tokens {
		if seen[tk] {
			continue
		}
		for w := range blobWords {
			if w == tk || strings.HasPrefix(w, tk) {
				add(tk)
				break
			}
		}
	}
	return hits
}

// nucleiClassifyMatch 判定模板的「拿 shell 概率」档位。
// 返回 (tier, label, class, score)；class 为空表示不属于任何落地类。
func nucleiClassifyMatch(t NucleiTemplate) (string, string, string, int) {
	tags := map[string]bool{}
	for _, tg := range strings.Split(t.Tags, ",") {
		tg = strings.TrimSpace(tg)
		if tg != "" {
			tags[tg] = true
		}
	}
	for _, c := range nucleiDangerClasses {
		for _, k := range c.Tags {
			if tags[k] {
				return c.Tier, c.Label, c.Name, c.Score
			}
		}
	}
	// 标签没写出来时，用名称/描述兜底（很多模板描述里直说了 RCE）
	desc := strings.ToLower(t.Name + " " + t.Description)
	for _, c := range nucleiDangerClasses {
		for _, hint := range c.DescHints {
			if strings.Contains(desc, hint) {
				return c.Tier, c.Label, c.Name, c.Score
			}
		}
	}
	for _, k := range nucleiMisconfigTags {
		if tags[k] {
			return nucleiMisconfigTier, nucleiMisconfigLabel, "misconfig", nucleiMisconfigScore
		}
	}
	return "", "", "", 0
}

// nucleiMatchCandidates 按指纹反查候选 POC，返回 (命中总数, 候选列表)。
// 候选已按「拿 shell 概率」排序（同分按 severity、再按 id 稳定排序）。
func nucleiMatchCandidates(fps []string, limit int) (int, []NucleiMatchCandidate, error) {
	list, err := nucleiIndex()
	if err != nil {
		return 0, nil, err
	}
	cveIDs, tokens := nucleiMatchKeywords(fps)
	if len(cveIDs) == 0 && len(tokens) == 0 {
		return 0, []NucleiMatchCandidate{}, nil
	}
	sevOK := map[string]bool{"critical": true, "high": true, "medium": true}
	out := make([]NucleiMatchCandidate, 0, 64)
	for _, t := range list {
		if !sevOK[t.Severity] {
			continue
		}
		kw := nucleiTplMatchKeywords(t, cveIDs, tokens)
		if len(kw) == 0 {
			continue
		}
		tier, label, cls, score := nucleiClassifyMatch(t)
		if cls == "" {
			// 没有落地类标签：只有明确命中 CVE 号才允许入选
			cveHit := false
			if len(cveIDs) > 0 {
				blobCompact := nucleiFpCompact(nucleiTplBlob(t))
				for _, cid := range cveIDs {
					if strings.Contains(blobCompact, cid) {
						cveHit = true
						break
					}
				}
			}
			if !cveHit {
				continue
			}
			tier, label, cls, score = nucleiCveOnlyTier, nucleiCveOnlyLabel, "cve", nucleiCveOnlyScore
		}
		out = append(out, NucleiMatchCandidate{
			ID:        t.ID,
			Name:      t.Name,
			Severity:  t.Severity,
			Tags:      t.Tags,
			Path:      t.Path,
			Matched:   kw,
			Tier:      tier,
			TierLabel: label,
			Score:     score,
			Class:     cls,
			Advice:    nucleiTierAdvice[tier],
			Landable:  tier == "A" || tier == "B",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		ri, rj := nucleiSeverityRank[out[i].Severity], nucleiSeverityRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	total := len(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return total, out, nil
}

// ---------------------------------------------------------------------------
// 指纹探测
// ---------------------------------------------------------------------------

// nucleiCleanTechName 把模板名洗成指纹名："Tomcat Detection" → "Tomcat"。
func nucleiCleanTechName(name string) string {
	s := strings.TrimSpace(name)
	for {
		n := strings.TrimSpace(nucleiTechTailRe.ReplaceAllString(s, ""))
		if n == s {
			return s
		}
		s = n
	}
}

// nucleiHitVersion 从提取结果里找一个像版本号的字符串。
func nucleiHitVersion(hit NucleiHit) string {
	for _, v := range hit.Extracted {
		if m := nucleiVersionRe.FindString(v); m != "" {
			return m
		}
	}
	return ""
}

// nucleiFingerprintsFromHits 把 nuclei 的 tech 命中整理成指纹列表（去重）。
func nucleiFingerprintsFromHits(hits []NucleiHit) []NucleiFingerprint {
	out := []NucleiFingerprint{}
	seen := map[string]bool{}
	for _, h := range hits {
		ver := nucleiHitVersion(h)
		if name := nucleiCleanTechName(h.Name); name != "" {
			key := strings.ToLower(name)
			if !seen[key] {
				seen[key] = true
				out = append(out, NucleiFingerprint{
					Tech: name, MatchedAt: h.MatchedAt, TemplateID: h.TemplateID,
					Source: "nuclei-tech", Version: ver,
				})
			}
		}
		// 模板 tag 里除了通用词，多半就是产品名（tech,tomcat,apache,intrusive,discovery）
		for _, t := range strings.Split(h.Tags, ",") {
			t = strings.TrimSpace(strings.ToLower(t))
			if t == "" || nucleiGenericTechTags[t] || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, NucleiFingerprint{
				Tech: t, MatchedAt: h.MatchedAt, TemplateID: h.TemplateID,
				Source: "nuclei-tech-tag",
			})
		}
	}
	return out
}

// nucleiHTTPFingerprint 没有 tech 命中时，用 HTTP 头/标题做粗判指纹。
// 返回 (指纹列表, 说明文字)。
func nucleiHTTPFingerprint(target string, timeout time.Duration) ([]NucleiFingerprint, string) {
	url := target
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	client := &http.Client{
		Timeout: timeout,
		// 自签证书的目标也要能识别：这里只做指纹读取，不校验证书
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return []NucleiFingerprint{}, "HTTP 粗判失败: " + err.Error()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-Nuclei-Fingerprint/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return []NucleiFingerprint{}, "HTTP 粗判失败: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	out := []NucleiFingerprint{}
	for _, h := range []struct{ key, label string }{
		{"Server", "Server"},
		{"X-Powered-By", "X-Powered-By"},
		{"X-Aspnet-Version", "X-AspNet-Version"},
		{"X-Generator", "X-Generator"},
		{"X-Runtime-Version", "X-Runtime-Version"},
	} {
		if v := strings.TrimSpace(resp.Header.Get(h.key)); v != "" {
			out = append(out, NucleiFingerprint{
				Tech: v, MatchedAt: url, Source: "http-header", Note: h.label,
			})
		}
	}
	if m := nucleiTitleRe.FindStringSubmatch(string(body)); len(m) > 1 {
		title := strings.TrimSpace(nucleiSpaceRe.ReplaceAllString(m[1], " "))
		if title != "" {
			out = append(out, NucleiFingerprint{
				Tech: title, MatchedAt: url, Source: "http-title", Note: "HTML <title>",
			})
		}
	}
	note := fmt.Sprintf("HTTP 粗判（来源：响应头/标题，状态码 %d）", resp.StatusCode)
	if len(out) == 0 {
		note = fmt.Sprintf("HTTP 粗判也没有取到 Server / X-Powered-By / <title>（状态码 %d）", resp.StatusCode)
	}
	return out, note
}

// nucleiFingerprintProbe 探测目标指纹：先跑 tech 模板，没命中再回退 HTTP 粗判。
func nucleiFingerprintProbe(ctx context.Context, target string, rate, timeout int) (
	fps []NucleiFingerprint, requests int, source string, note string, err error) {
	if _, statErr := os.Stat(nucleiBinPath); statErr != nil {
		return nil, 0, "none", "nuclei 未安装: " + nucleiBinPath, fmt.Errorf("nuclei 未安装: %s", nucleiBinPath)
	}
	args := []string{
		"-u", target, "-tags", "tech", "-jsonl", "-silent", "-disable-update-check", "-nc",
		"-rl", strconv.Itoa(rate), "-t", nucleiTplRoot,
		"-stats", "-stats-interval", "1", "-stats-json",
	}
	hits, reqs, timedOut, runErr := nucleiRunExec(ctx, args, nil)
	if runErr != nil {
		return nil, reqs, "none", "tech 模板扫描失败: " + runErr.Error(), runErr
	}
	fps = nucleiFingerprintsFromHits(hits)
	source = "nuclei-tech"
	note = fmt.Sprintf("nuclei tech 模板命中 %d 条", len(hits))
	if timedOut {
		note += "（探测超时被中断，结果可能不完整）"
	}
	if len(fps) == 0 {
		// tech 没命中 → 回退到 HTTP 头/标题粗判，并明确标注来源
		fallback, fbNote := nucleiHTTPFingerprint(target, 8*time.Second)
		fps = fallback
		source = "http-header"
		if len(fallback) == 0 {
			source = "none"
		}
		note = "nuclei tech 模板未命中；" + fbNote
	}
	return fps, reqs, source, note, nil
}

// ---------------------------------------------------------------------------
// POST /api/nuclei/fingerprint
// ---------------------------------------------------------------------------

type nucleiFingerprintRequest struct {
	Target    string `json:"target"`
	Timeout   int    `json:"timeout"`
	RateLimit int    `json:"rate_limit"`
}

func (s *Server) nucleiFingerprint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, nucleiMaxBody)
	var req nucleiFingerprintRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	target, err := nucleiValidateTarget(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rate := req.RateLimit
	if rate <= 0 {
		rate = nucleiMatchDefRate
	}
	if rate > nucleiMatchMaxRate {
		rate = nucleiMatchMaxRate
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = nucleiProbeDefTimeout
	}
	if timeout < 10 {
		timeout = 10
	}
	if timeout > nucleiProbeMaxTimeout {
		timeout = nucleiProbeMaxTimeout
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()

	started := time.Now()
	fps, requests, source, note, probeErr := nucleiFingerprintProbe(ctx, target, rate, timeout)
	elapsed := time.Since(started).Milliseconds()
	if probeErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"target":       target,
			"fingerprints": []NucleiFingerprint{},
			"source":       source,
			"requests":     requests,
			"elapsed_ms":   elapsed,
			"note":         note,
			"error":        probeErr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":       target,
		"fingerprints": fps,
		"source":       source,
		"requests":     requests,
		"elapsed_ms":   elapsed,
		"note":         note,
	})
}

// ---------------------------------------------------------------------------
// POST /api/nuclei/match
// ---------------------------------------------------------------------------

type nucleiMatchRequest struct {
	Fingerprints []string `json:"fingerprints"`
	Limit        int      `json:"limit"`
}

func (s *Server) nucleiMatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, nucleiMaxBody)
	var req nucleiMatchRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	fps := make([]string, 0, len(req.Fingerprints))
	for _, f := range req.Fingerprints {
		if f = strings.TrimSpace(f); f != "" {
			fps = append(fps, f)
		}
	}
	if len(fps) == 0 {
		writeErr(w, http.StatusBadRequest, "缺少必填参数 fingerprints（先用 /api/nuclei/fingerprint 探测）")
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = nucleiMatchDefLimit
	}
	if limit > nucleiMatchMaxLimit {
		limit = nucleiMatchMaxLimit
	}
	total, items, err := nucleiMatchCandidates(fps, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fingerprints": fps,
		"total":        total,
		"items":        items,
		"limit":        limit,
		"message":      nucleiMatchMessage(total),
	})
}

// nucleiMatchMessage 结果为空时给出明确提示，避免前端白屏。
func nucleiMatchMessage(total int) string {
	if total > 0 {
		return ""
	}
	return "未匹配到与该指纹相关的 POC：模板库里没有同时满足 severity ∈ {critical, high, medium} " +
		"且带 rce / file-upload / deserialization / command-injection / sqli / misconfig 标签或 CVE 号的模板。"
}

// ---------------------------------------------------------------------------
// POST /api/nuclei/autorun
// ---------------------------------------------------------------------------

type nucleiAutorunRequest struct {
	Target       string   `json:"target"`
	Fingerprints []string `json:"fingerprints"`
	Templates    []string `json:"templates"`
	// AssetIDs 是资产页带过来的资产 id（只是上下文，后端不据此发请求）。
	AssetIDs  []string `json:"asset_ids"`
	Limit     int      `json:"limit"`
	RateLimit int      `json:"rate_limit"`
	Timeout   int      `json:"timeout"`
	Stream    bool     `json:"stream"`
}

// nucleiAutorunPlan 是「匹配 + 实弹」跑之前的准备结果。
type nucleiAutorunPlan struct {
	Fingerprints []NucleiFingerprint
	Candidates   []NucleiMatchCandidate
	TemplateIDs  []string
	Paths        []string
	Total        int
	Source       string
	Note         string
}

// nucleiAutorunPrepare 解析请求，必要时探测指纹 + 匹配候选 POC。
func nucleiAutorunPrepare(ctx context.Context, req nucleiAutorunRequest, target string, limit, rate, timeout int) (nucleiAutorunPlan, error) {
	plan := nucleiAutorunPlan{Source: "none"}
	for _, f := range req.Fingerprints {
		if f = strings.TrimSpace(f); f != "" {
			plan.Fingerprints = append(plan.Fingerprints, NucleiFingerprint{Tech: f, Source: "manual"})
		}
	}
	explicit := make([]string, 0, len(req.Templates))
	for _, t := range req.Templates {
		if t = strings.TrimSpace(t); t != "" {
			explicit = append(explicit, t)
		}
	}
	if len(explicit) > 0 {
		if len(explicit) > limit {
			explicit = explicit[:limit]
		}
		for _, ref := range explicit {
			abs, err := resolveNucleiTemplate(ref)
			if err != nil {
				return plan, err
			}
			plan.TemplateIDs = append(plan.TemplateIDs, ref)
			plan.Paths = append(plan.Paths, abs)
		}
		plan.Total = len(plan.TemplateIDs)
		plan.Source = "explicit"
		plan.Note = "按指定的模板列表验证"
		return plan, nil
	}

	// 没给指纹就先探测
	if len(plan.Fingerprints) == 0 {
		fps, requests, source, note, err := nucleiFingerprintProbe(ctx, target, rate, timeout)
		if err != nil {
			plan.Note = "指纹探测失败: " + err.Error()
		}
		plan.Fingerprints = fps
		plan.Source = source
		plan.Note = note
		_ = requests
	}
	names := make([]string, 0, len(plan.Fingerprints))
	for _, f := range plan.Fingerprints {
		names = append(names, f.Tech)
	}
	if len(names) == 0 {
		return plan, nil // 无指纹 → 无候选，交给上层明确提示
	}
	total, items, err := nucleiMatchCandidates(names, limit)
	if err != nil {
		return plan, err
	}
	plan.Candidates = items
	plan.Total = total
	for _, c := range items {
		abs := filepath.Join(nucleiTplRoot, filepath.FromSlash(c.Path))
		if st, statErr := os.Stat(abs); statErr == nil && !st.IsDir() {
			plan.TemplateIDs = append(plan.TemplateIDs, c.ID)
			plan.Paths = append(plan.Paths, abs)
		}
	}
	return plan, nil
}

func (s *Server) nucleiAutorun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, nucleiMaxBody)
	var req nucleiAutorunRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	target, err := nucleiValidateTarget(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = nucleiMatchDefLimit
	}
	if limit > nucleiMatchMaxLimit {
		limit = nucleiMatchMaxLimit
	}
	rate := req.RateLimit
	if rate <= 0 {
		rate = nucleiMatchDefRate
	}
	if rate > nucleiMatchMaxRate {
		rate = nucleiMatchMaxRate
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 180
	}
	if timeout < 5 {
		timeout = 5
	}
	if timeout > 600 {
		timeout = 600
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()

	started := time.Now()
	plan, err := nucleiAutorunPrepare(ctx, req, target, limit, rate, timeout)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// 匹配不到候选：明确说明并停止，绝不盲扫全库
	if len(plan.Paths) == 0 {
		msg := nucleiMatchMessage(plan.Total)
		if msg == "" {
			msg = "没有可用的候选模板"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"target":       target,
			"fingerprints": plan.Fingerprints,
			"candidates":   plan.Candidates,
			"hits":         []NucleiHit{},
			"summary": map[string]any{
				"candidates": plan.Total,
				"ran":        0,
				"requests":   0,
				"matched":    0,
				"elapsed_ms": time.Since(started).Milliseconds(),
				"timed_out":  false,
				"strategy":   "未匹配到候选 POC，未对目标发起任何 POC 请求",
				"target":     target,
			},
			"message": msg,
		})
		return
	}

	args := []string{
		"-u", target, "-jsonl", "-silent", "-disable-update-check", "-nc",
		"-rl", strconv.Itoa(rate), "-stats", "-stats-interval", "1", "-stats-json",
	}
	for _, p := range plan.Paths {
		args = append(args, "-t", p)
	}
	strategy := fmt.Sprintf("限速 %d req/s，候选模板 %d 个", rate, len(plan.Paths))

	if req.Stream {
		s.nucleiAutorunStream(w, r, ctx, args, strategy, target, plan, started)
		return
	}

	hits, requests, timedOut, runErr := nucleiRunExec(ctx, args, nil)
	if runErr != nil {
		writeErr(w, http.StatusInternalServerError, runErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":       target,
		"fingerprints": plan.Fingerprints,
		"candidates":   plan.Candidates,
		"hits":         hits,
		"summary": map[string]any{
			"candidates": plan.Total,
			"ran":        len(plan.Paths),
			"requests":   requests,
			"matched":    len(hits),
			"elapsed_ms": time.Since(started).Milliseconds(),
			"timed_out":  timedOut,
			"strategy":   strategy,
			"target":     target,
		},
	})
}

// nucleiAutorunStream 用 SSE 把三段结果依次推给页面：指纹 → 候选 → 命中 → 汇总。
func (s *Server) nucleiAutorunStream(w http.ResponseWriter, r *http.Request, ctx context.Context,
	args []string, strategy, target string, plan nucleiAutorunPlan, started time.Time) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	var mu sync.Mutex
	send := func(event string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		flusher.Flush()
	}

	send("fingerprint", map[string]any{
		"target":       target,
		"fingerprints": plan.Fingerprints,
		"source":       plan.Source,
		"note":         plan.Note,
	})
	send("candidates", map[string]any{
		"total":   plan.Total,
		"items":   plan.Candidates,
		"ran":     len(plan.Paths),
		"message": nucleiMatchMessage(plan.Total),
	})

	// 心跳：模板多的时候可能几十秒没命中，避免中间层断连
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				mu.Lock()
				fmt.Fprint(w, ": ping\n\n")
				flusher.Flush()
				mu.Unlock()
			}
		}
	}()

	hits, requests, timedOut, runErr := nucleiRunExec(ctx, args, func(h NucleiHit) {
		send("hit", h)
	})
	close(done)

	if runErr != nil {
		send("error", map[string]any{"error": runErr.Error()})
		return
	}
	send("summary", map[string]any{
		"candidates": plan.Total,
		"ran":        len(plan.Paths),
		"requests":   requests,
		"matched":    len(hits),
		"elapsed_ms": time.Since(started).Milliseconds(),
		"timed_out":  timedOut,
		"strategy":   strategy,
		"target":     target,
	})
}
