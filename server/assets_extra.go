package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// =====================================================================
// 资产中枢的三个新接口：血缘 / 覆盖度 / POC 联动
//
// 本文件只放「资产模块自己的新能力」，路由注册在 server.go（由维护者统一合并）。
//
// 1) GET  /api/assets/lineage   —— 资产血缘：谁发现的、什么时候发现的、归属谁
// 2) GET  /api/assets/coverage  —— 覆盖度可视化（复用既有覆盖度口径）
// 3) POST /api/assets/poc-match —— 指纹 → POC 候选（只放行能落地的模板）
//
// 说明：POC 候选走 Go 侧标签匹配（与 Nuclei MCP 的 poc_dangerous 同口径：
// 同一套危险 tag / 描述词 / 分档），不 fork Python 子进程——页面点一下就要有
// 响应，子进程方式太慢也太脆。模板索引自己扫 /opt/artex/nuclei-templates，
// 与 server/nuclei.go 的索引互不依赖（那边正在被并行改动，这里保持自洽）。
// =====================================================================

// ---------------------------------------------------------------------------
// GET /api/assets/lineage
// ---------------------------------------------------------------------------

// assetLineage 返回资产的发现血缘。
//
// 参数：
//   - ids=1,2,3     指定资产（表格当前页常用）
//   - id=123        单个资产
//   - dsl=...       DSL 查询（与全局资产搜索同一套语法）
//   - type=...      DSL 模式下的类型过滤
//   - task_id=...   指定「当前任务」，用于标记资产是否在任务范围内
//   - limit/offset  分页（默认 50 / 0）
func (s *Server) assetLineage(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query()
	ids, err := parseAssetIDList(q.Get("ids"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if raw := strings.TrimSpace(q.Get("id")); raw != "" {
		id, convErr := strconv.ParseInt(raw, 10, 64)
		if convErr != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		ids = append(ids, id)
	}
	dsl := strings.TrimSpace(q.Get("dsl"))
	if len(ids) == 0 && dsl == "" {
		writeErr(w, http.StatusBadRequest, "需要 ids / id / dsl 之一")
		return
	}
	if dsl != "" {
		if err := db.ValidateDSL(dsl); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	items, total, err := as.QueryAssetLineage(db.AssetLineageQuery{
		IDs:    ids,
		DSL:    dsl,
		Type:   strings.TrimSpace(q.Get("type")),
		TaskID: taskID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"assets": items,
		"total":  total,
	})
}

// parseAssetIDList 解析 "1,2,3" 形式的资产 id 列表。
func parseAssetIDList(raw string) ([]int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := make([]int64, 0, 8)
	seen := map[int64]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("invalid asset id: %s", part)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) > 500 {
		return nil, fmt.Errorf("一次最多查询 %d 个资产", 500)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// GET /api/assets/coverage
// ---------------------------------------------------------------------------

// assetCoverage 返回资产覆盖度。
//
// 参数：
//   - task_id=...  指定任务 → 走任务口径（范围 = 任务 scope ∪ 事实锚点）
//   - dsl=...      指定 DSL → 走全局口径（范围 = 命中 DSL 的资产）
//   - type=...     全局口径下的类型过滤
//
// 两种口径的「已测」定义一致：被事实锚点（exploration_nodes.kind='fact'）覆盖。
func (s *Server) assetCoverage(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
	dsl := strings.TrimSpace(q.Get("dsl"))
	typ := strings.TrimSpace(q.Get("type"))

	var (
		cov   *db.Coverage
		scope string
		err   error
	)
	if taskID > 0 {
		scope = "task"
		// 覆盖度功能关闭 → 与 /api/tasks/{id}/coverage 一样短路。
		if !as.CoverageEnabled(taskID) {
			writeJSON(w, http.StatusOK, map[string]any{
				"enabled":     false,
				"scope":       scope,
				"denominator": 0,
				"tested":      0,
				"untested":    0,
				"pct":         nil,
				"by_type":     []db.CoverageByType{},
			})
			return
		}
		cov, err = as.TaskCoverageWithSources(taskID)
	} else {
		scope = "global"
		if dsl != "" {
			if err := db.ValidateDSL(dsl); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		cov, err = as.AssetCoverage(dsl, typ)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cov.Enabled = true
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     cov.Enabled,
		"scope":       scope,
		"scope_rows":  cov.ScopeRows,
		"denominator": cov.Denominator,
		"tested":      cov.Tested,
		"untested":    cov.Denominator - cov.Tested,
		"pct":         cov.Pct,
		"by_type":     cov.ByType,
	})
}

// ---------------------------------------------------------------------------
// POST /api/assets/attribute
// ---------------------------------------------------------------------------

// assetAttribute 批量改资产的企业归属。company_id=0 表示取消归属。
func (s *Server) assetAttribute(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAssetPocBodyBytes)
	var req struct {
		IDs       []int64 `json:"ids"`
		CompanyID int64   `json:"company_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "ids required")
		return
	}
	if len(req.IDs) > 500 {
		writeErr(w, http.StatusBadRequest, "一次最多改 500 条资产")
		return
	}
	var companyID *int64
	if req.CompanyID > 0 {
		cs := s.companyStore()
		if cs == nil {
			writeErr(w, 503, "database unavailable")
			return
		}
		company, err := cs.GetCompany(req.CompanyID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if company == nil {
			writeErr(w, http.StatusNotFound, "company not found")
			return
		}
		id := req.CompanyID
		companyID = &id
	}
	updated, err := as.SetAssetsCompany(req.IDs, companyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated})
}

// ---------------------------------------------------------------------------
// POST /api/assets/poc-match
// ---------------------------------------------------------------------------

// maxAssetPocBodyBytes 是资产模块写接口请求体的上限（1MB）。
const maxAssetPocBodyBytes = 1 << 20

// assetPocMatchRequest 是 POC 联动的入参。
type assetPocMatchRequest struct {
	AssetIDs []int64 `json:"asset_ids"`
	DSL      string  `json:"dsl"`
	Type     string  `json:"type"`
	Limit    int     `json:"limit"`
}

// assetPocMatchResponse 是 POC 联动的返回。
type assetPocMatchResponse struct {
	Assets     []pocMatchAsset `json:"assets"`
	Candidates []pocCandidate  `json:"candidates"`
	Total      int             `json:"total"`
	Limit      int             `json:"limit"`
	Scanned    int             `json:"templates_scanned"`
	Eligible   int             `json:"templates_eligible"`
	Warning    string          `json:"warning,omitempty"`
}

// pocMatchAsset 是参与匹配的一条资产（只回显必要信息）。
type pocMatchAsset struct {
	AssetID      int64    `json:"asset_id"`
	Label        string   `json:"label"`
	Target       string   `json:"target"`
	Type         string   `json:"type"`
	Fingerprints []string `json:"fingerprints"`
}

// pocCandidate 是一个候选模板（资产 × 模板）。
type pocCandidate struct {
	AssetID    int64    `json:"asset_id"`
	AssetLabel string   `json:"asset_label"`
	Target     string   `json:"target"`
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Tags       string   `json:"tags"`
	Path       string   `json:"path"`
	Matched    []string `json:"matched"`
	Tier       string   `json:"tier"`
	TierLabel  string   `json:"tier_label"`
	Score      int      `json:"score"`
	Advice     string   `json:"advice"`
}

// assetPocMatch 用资产指纹反查 Nuclei 模板候选。
//
// 只放行「能落地」的模板：severity ∈ {critical, high, medium} 且命中
// rce / file-upload / deserialization / command-injection / sqli 类别
// （口径与 Nuclei MCP 的 poc_dangerous 一致，见 pocDangerTags）。
func (s *Server) assetPocMatch(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAssetPocBodyBytes)
	var req assetPocMatchRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.AssetIDs) == 0 && strings.TrimSpace(req.DSL) == "" {
		writeErr(w, http.StatusBadRequest, "需要 asset_ids 或 dsl 之一")
		return
	}
	if req.DSL != "" {
		if err := db.ValidateDSL(req.DSL); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	limit := req.Limit
	if limit <= 0 {
		limit = pocDefaultLimit
	}
	if limit > pocMaxLimit {
		limit = pocMaxLimit
	}

	fingerprints, err := as.AssetFingerprints(req.AssetIDs, req.DSL, req.Type, pocMaxAssets)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	templates, err := pocTemplateIndex()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	assets := make([]pocMatchAsset, 0, len(fingerprints))
	candidates := make([]pocCandidate, 0, 64)
	eligible := 0

	// 先把资产指纹抽成关键词表（全局去重），再对每个模板算一次命中：
	// 模板库上万条、资产几十条时，逐对重算关键词会慢一个数量级。
	assetTokens := make([][]string, len(fingerprints))
	globalIndex := map[string]int{}
	globalTokens := make([]string, 0, 64)
	for i, fp := range fingerprints {
		tokens := pocFingerprintTokens(fp)
		assetTokens[i] = tokens
		for _, token := range tokens {
			if _, ok := globalIndex[token]; ok {
				continue
			}
			globalIndex[token] = len(globalTokens)
			globalTokens = append(globalTokens, token)
		}
	}

	// 合格模板（严重度 + 类别过滤后）先算好命中了哪些关键词。
	type templateHit struct {
		template pocTemplate
		tokens   []int // globalTokens 的下标
	}
	hits := make([]templateHit, 0, 256)
	for _, tpl := range templates {
		if !pocSeverityAllowed(tpl.Severity) {
			continue
		}
		if !pocDangerousCategory(tpl) {
			continue
		}
		eligible++
		matched := make([]int, 0, 3)
		for idx, token := range globalTokens {
			if pocWordHit(tpl.words, token) {
				matched = append(matched, idx)
			}
		}
		if len(matched) == 0 {
			continue
		}
		hits = append(hits, templateHit{template: tpl, tokens: matched})
	}

	// 关键词 → 命中它的模板（倒排），再按资产取候选。
	byToken := make(map[int][]int, len(globalTokens))
	for i, hit := range hits {
		for _, idx := range hit.tokens {
			byToken[idx] = append(byToken[idx], i)
		}
	}
	scoreCache := make([]pocDangerMeta, len(hits))
	for i, hit := range hits {
		score, tier, tierLabel, advice := pocClassifyDanger(hit.template)
		scoreCache[i] = pocDangerMeta{Score: score, Tier: tier, TierLabel: tierLabel, Advice: advice}
	}

	for assetIdx, fp := range fingerprints {
		tokens := assetTokens[assetIdx]
		if len(tokens) == 0 {
			continue
		}
		seenTemplates := map[int]bool{}
		for _, token := range tokens {
			idx, ok := globalIndex[token]
			if !ok {
				continue
			}
			for _, hitIdx := range byToken[idx] {
				if seenTemplates[hitIdx] {
					continue
				}
				seenTemplates[hitIdx] = true
				hit := hits[hitIdx]
				meta := scoreCache[hitIdx]
				candidates = append(candidates, pocCandidate{
					AssetID:    fp.ID,
					AssetLabel: fp.Label,
					Target:     fp.Target,
					TemplateID: hit.template.ID,
					Name:       hit.template.Name,
					Severity:   hit.template.Severity,
					Tags:       hit.template.Tags,
					Path:       hit.template.Path,
					Matched:    matchedTokens(hit.tokens, globalTokens, tokens),
					Tier:       meta.Tier,
					TierLabel:  meta.TierLabel,
					Score:      meta.Score,
					Advice:     meta.Advice,
				})
			}
		}
	}

	// 排序：严重度 → 危险分 → 命中指纹数 → 资产 id
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if ra, rb := pocSeverityRank(a.Severity), pocSeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if len(a.Matched) != len(b.Matched) {
			return len(a.Matched) > len(b.Matched)
		}
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		return a.TemplateID < b.TemplateID
	})
	total := len(candidates)
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}

	used := map[int64]bool{}
	for _, c := range candidates {
		used[c.AssetID] = true
	}
	for _, fp := range fingerprints {
		if !used[fp.ID] {
			continue
		}
		assets = append(assets, pocMatchAsset{
			AssetID:      fp.ID,
			Label:        fp.Label,
			Target:       fp.Target,
			Type:         fp.Type,
			Fingerprints: pocFingerprintTokens(fp),
		})
	}

	writeJSON(w, http.StatusOK, assetPocMatchResponse{
		Assets:     assets,
		Candidates: candidates,
		Total:      total,
		Limit:      limit,
		Scanned:    len(templates),
		Eligible:   eligible,
	})
}

// ---------------------------------------------------------------------------
// POC 模板索引（自建，不依赖 server/nuclei.go）
// ---------------------------------------------------------------------------

const (
	// pocTemplateRoot 是 Nuclei 模板库目录（与 /opt/artex/bin/nuclei 共用）。
	pocTemplateRoot = "/opt/artex/nuclei-templates"
	// pocIndexTTL 是模板索引的内存缓存时长。
	pocIndexTTL = 10 * time.Minute
	// pocDefaultLimit / pocMaxLimit 是候选模板条数的默认与上限。
	pocDefaultLimit = 50
	pocMaxLimit     = 200
	// pocMaxAssets 是单次参与匹配的资产上限。
	pocMaxAssets = 200
	// pocHeadBytes 只读模板头部：info 块基本都在前 8K。
	pocHeadBytes = 8192
)

// pocTemplate 是模板索引里的一行。
type pocTemplate struct {
	ID          string
	Name        string
	Severity    string
	Tags        string
	Path        string
	Description string
	// words 是 id/name/tags/path 拆出的词，用于指纹匹配。
	words []string
}

var (
	pocIdxMu   sync.Mutex
	pocIdxAt   time.Time
	pocIdxList []pocTemplate
)

// pocTemplateIndex 取模板索引（内存缓存 10 分钟）。
func pocTemplateIndex() ([]pocTemplate, error) {
	pocIdxMu.Lock()
	defer pocIdxMu.Unlock()
	if len(pocIdxList) > 0 && time.Since(pocIdxAt) < pocIndexTTL {
		return pocIdxList, nil
	}
	if _, err := os.Stat(pocTemplateRoot); err != nil {
		return nil, fmt.Errorf("模板目录不可用: %s", pocTemplateRoot)
	}
	list, err := buildPocTemplateIndex()
	if err != nil {
		return nil, err
	}
	pocIdxList, pocIdxAt = list, time.Now()
	return list, nil
}

// buildPocTemplateIndex 扫模板目录建索引。
func buildPocTemplateIndex() ([]pocTemplate, error) {
	out := make([]pocTemplate, 0, 8192)
	skip := map[string]bool{".git": true, ".github": true, "helpers": true, "profiles": true}
	err := filepath.WalkDir(pocTemplateRoot, func(p string, d os.DirEntry, walkErr error) error {
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
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if len(raw) > pocHeadBytes {
			raw = raw[:pocHeadBytes]
		}
		id, info := pocParseTemplateHead(string(raw))
		if id == "" || len(info) == 0 {
			return nil // payload / workflow / 配置，不是模板
		}
		rel, err := filepath.Rel(pocTemplateRoot, p)
		if err != nil {
			return nil
		}
		tpl := pocTemplate{
			ID:          id,
			Name:        info["name"],
			Severity:    strings.ToLower(strings.TrimSpace(info["severity"])),
			Tags:        pocNormalizeTags(info["tags"]),
			Path:        filepath.ToSlash(rel),
			Description: strings.TrimSpace(info["description"]),
		}
		if tpl.Severity == "" {
			tpl.Severity = "unknown"
		}
		tpl.words = pocTemplateWords(tpl)
		out = append(out, tpl)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := pocSeverityRank(out[i].Severity), pocSeverityRank(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// pocParseTemplateHead 解析模板头部的 id 与 info 块（不引入 YAML 依赖）。
func pocParseTemplateHead(raw string) (string, map[string]string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) > 300 {
		lines = lines[:300]
	}
	info := map[string]string{}
	id := ""
	inInfo := false
	curKey := ""
	curIndent := 0
	blockIndent := -1
	var block []string

	flushBlock := func() {
		if curKey != "" && blockIndent >= 0 {
			info[curKey] = strings.TrimSpace(strings.Join(block, " "))
		}
		block = nil
		blockIndent = -1
	}

	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		if !inInfo {
			if trimmed == "" {
				continue
			}
			if indent == 0 && strings.HasPrefix(trimmed, "id:") {
				id = pocUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "id:")))
			}
			if indent == 0 && trimmed == "info:" {
				inInfo = true
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		if indent == 0 {
			break // info 块结束
		}
		// 块标量（| / >）的续行
		if blockIndent >= 0 {
			if indent > curIndent {
				block = append(block, trimmed)
				continue
			}
			flushBlock()
		}
		if strings.HasPrefix(trimmed, "- ") && curKey != "" {
			item := pocUnquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			if item == "" {
				continue
			}
			if info[curKey] == "" {
				info[curKey] = item
			} else {
				info[curKey] += ", " + item
			}
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		curKey = strings.ToLower(strings.TrimSpace(key))
		curIndent = indent
		val = strings.TrimSpace(val)
		if val == "|" || val == ">" || strings.HasPrefix(val, "|") || strings.HasPrefix(val, ">") {
			blockIndent = indent
			block = nil
			info[curKey] = ""
			continue
		}
		info[curKey] = pocUnquote(val)
	}
	flushBlock()
	return id, info
}

func pocUnquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	if len(v) >= 1 && (v[0] == '\'' || v[0] == '"') {
		return v[1:]
	}
	return v
}

// pocNormalizeTags 把 tags 规范成小写逗号串。
func pocNormalizeTags(v string) string {
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';' || r == ' '
	})
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

// pocTemplateWords 把模板的可匹配文本拆成词。
func pocTemplateWords(tpl pocTemplate) []string {
	blob := strings.ToLower(tpl.ID + " " + tpl.Name + " " + tpl.Tags + " " + tpl.Path)
	fields := strings.FieldsFunc(blob, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// 指纹 → 模板匹配
// ---------------------------------------------------------------------------

// pocFingerprintTokens 提取一条资产的指纹关键词。
func pocFingerprintTokens(fp db.AssetFingerprint) []string {
	raw := make([]string, 0, 8)
	raw = append(raw, fp.Technologies...)
	raw = append(raw, fp.PageTitle, fp.ServiceName, fp.AppName, fp.Category, fp.BundleID)
	seen := map[string]bool{}
	out := make([]string, 0, 12)
	for _, item := range raw {
		for _, token := range pocTokenize(item) {
			if seen[token] {
				continue
			}
			seen[token] = true
			out = append(out, token)
		}
	}
	return out
}

// pocTokenize 把一段文本拆成候选关键词：保留字母数字组合，丢掉过短/泛用词。
func pocTokenize(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.ToLower(f)
		if len(f) < 3 {
			continue
		}
		if pocStopWords[f] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// pocStopWords 是没有区分度的通用词（匹配它们只会刷出无关模板）。
// 注意：php 不在表里——它是最常见的指纹，必须参与匹配。
var pocStopWords = map[string]bool{
	"http": true, "https": true, "www": true, "com": true, "net": true, "org": true,
	"gov": true, "edu": true, "cn": true, "html": true,
	"linux": true, "windows": true, "macos": true, "server": true, "web": true,
	"api": true, "app": true, "apps": true, "example": true, "test": true,
	"demo": true, "admin": true, "system": true, "other": true, "unknown": true,
	"none": true, "default": true, "software": true, "application": true,
	"program": true, "service": true, "site": true, "portal": true, "index": true,
	"home": true, "login": true, "main": true, "www1": true, "cdn": true,
}

// pocMatchTokens 返回命中的指纹关键词。
func pocMatchTokens(tpl pocTemplate, tokens []string) []string {
	matched := make([]string, 0, 3)
	for _, token := range tokens {
		if pocWordHit(tpl.words, token) {
			matched = append(matched, token)
		}
	}
	return matched
}

// pocDangerMeta 是模板的「拿 shell 概率」分档结果。
type pocDangerMeta struct {
	Score     int
	Tier      string
	TierLabel string
	Advice    string
}

// matchedTokens 从模板命中的关键词集合里，挑出这条资产自己拥有的那些
// （模板命中的是全局关键词表，资产只认自己的指纹）。
func matchedTokens(hitIdx []int, globalTokens []string, assetTokens []string) []string {
	if len(hitIdx) == 0 || len(assetTokens) == 0 {
		return nil
	}
	hitSet := make(map[string]bool, len(hitIdx))
	for _, idx := range hitIdx {
		if idx >= 0 && idx < len(globalTokens) {
			hitSet[globalTokens[idx]] = true
		}
	}
	out := make([]string, 0, len(hitIdx))
	for _, token := range assetTokens {
		if hitSet[token] {
			out = append(out, token)
		}
	}
	return out
}

// pocWordHit 判断关键词是否命中模板的词表：完全相等，或模板词以关键词开头
// （thinkphp → thinkphp、springboot → spring、log4j → log4j-core）。
func pocWordHit(words []string, token string) bool {
	for _, w := range words {
		if w == token {
			return true
		}
		if len(w) > len(token) && strings.HasPrefix(w, token) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 危险度分级（与 Nuclei MCP 的 poc_dangerous 同口径）
// ---------------------------------------------------------------------------

// pocDangerTags：tag → 拿 shell 危险度分值（与 nuclei_mcp.py DANGER_TAGS 一致）。
var pocDangerTags = map[string]int{
	"rce": 100, "remote-code-execution": 100, "command-injection": 96, "os-command-injection": 96,
	"code-injection": 92, "file-upload": 88, "arbitrary-file-upload": 88, "unrestricted-file-upload": 88,
	"file-write": 84, "arbitrary-file-write": 84, "deserialization": 72, "deserialize": 72,
	"insecure-deserialization": 72, "rfi": 62, "ssti": 60, "sqli": 48, "sql-injection": 48, "lfi": 42,
}

// pocDangerDescWords：描述关键词兜底（与 nuclei_mcp.py DANGER_DESC_WORDS 一致）。
var pocDangerDescWords = []struct {
	word  string
	score int
}{
	{"remote code execution", 100},
	{"arbitrary command execution", 96},
	{"command injection", 96},
	{"os command", 94},
	{"code execution", 90},
	{"file upload", 86},
	{"arbitrary file write", 84},
	{"write file", 80},
	{"deserialization", 72},
	{"outfile", 55},
	{"sql injection", 46},
}

// pocAllowedTags 是允许进入候选的类别：rce / 上传 / 反序列化 / 命令注入 / SQL 注入。
var pocAllowedTags = map[string]bool{
	"rce": true, "remote-code-execution": true, "command-injection": true,
	"os-command-injection": true, "code-injection": true, "file-upload": true,
	"arbitrary-file-upload": true, "unrestricted-file-upload": true, "file-write": true,
	"arbitrary-file-write": true, "deserialization": true, "deserialize": true,
	"insecure-deserialization": true, "sqli": true, "sql-injection": true,
}

// pocAllowedDescWords 是描述里允许的关键词（与 pocAllowedTags 同义）。
var pocAllowedDescWords = []string{
	"remote code execution", "arbitrary command execution", "command injection",
	"code execution", "file upload", "arbitrary file write", "write file",
	"deserialization", "sql injection", "outfile",
}

// pocTiers 是「拿 shell 概率」分档（与 nuclei_mcp.py DANGER_TIERS 一致）。
var pocTiers = []struct {
	min    int
	tier   string
	label  string
	advice string
}{
	{90, "A", "直接命令执行/代码执行 —— 命中即等于拿到了命令通道",
		"用「验证」按钮跑一次确认命中；命中后可直接改命令参数复现，再配合 Webshell MCP 落马"},
	{80, "B", "文件上传/任意文件写 —— 命中即等于能落地文件",
		"先确认上传目录能否解析脚本、有没有重命名/白名单；能解析就落地马子并登记"},
	{60, "C", "反序列化 / SSTI / RFI —— 可执行代码但需要构造 payload",
		"先用模板自带 payload 确认可利用，再按目标中间件版本换 gadget 链"},
	{45, "D", "SQL 注入 —— 只有满足条件才能转成文件写入",
		"重点看能否写文件：需要 FILE 权限 / secure_file_priv 可写 / 堆叠查询"},
}

// pocSeverityAllowed 只放行 high / critical / medium。
func pocSeverityAllowed(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium":
		return true
	default:
		return false
	}
}

// pocSeverityRank 给严重度排序（小的在前）。
func pocSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

// pocDangerousCategory 判断模板是否属于允许进入候选的类别。
func pocDangerousCategory(tpl pocTemplate) bool {
	for _, tag := range strings.Split(tpl.Tags, ",") {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if pocAllowedTags[tag] {
			return true
		}
	}
	blob := strings.ToLower(tpl.Name + " " + tpl.Description)
	for _, word := range pocAllowedDescWords {
		if strings.Contains(blob, word) {
			return true
		}
	}
	return false
}

// pocClassifyDanger 给模板打「拿 shell 概率」分档。
func pocClassifyDanger(tpl pocTemplate) (int, string, string, string) {
	score := 0
	for _, tag := range strings.Split(tpl.Tags, ",") {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if s, ok := pocDangerTags[tag]; ok && s > score {
			score = s
		}
	}
	blob := strings.ToLower(tpl.Name + " " + tpl.Description)
	for _, entry := range pocDangerDescWords {
		if strings.Contains(blob, entry.word) && entry.score > score {
			score = entry.score
		}
	}
	for _, tier := range pocTiers {
		if score >= tier.min {
			return score, tier.tier, tier.label, tier.advice
		}
	}
	return score, "E", "文件读取 / 其他 —— 一般拿不到 shell", "当辅助信息用，别指望直接拿 shell"
}
