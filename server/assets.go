package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// companyScopeInputs accepts both the new [{kind,value}] contract and the
// historical ["example.com","203.0.113.10"] contract.
type companyScopeInputs []db.ScopeInput

const maxCompanyMutationBodyBytes = 2 << 20

func decodeCompanyMutationRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxCompanyMutationBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		}
		return false
	}
	return true
}

func (items *companyScopeInputs) UnmarshalJSON(data []byte) error {
	var rawItems []json.RawMessage
	if err := json.Unmarshal(data, &rawItems); err != nil {
		return err
	}
	out := make([]db.ScopeInput, 0, len(rawItems))
	for i, raw := range rawItems {
		var legacy string
		if err := json.Unmarshal(raw, &legacy); err == nil {
			out = append(out, db.ScopeInput{Value: legacy})
			continue
		}
		var structured db.ScopeInput
		if err := json.Unmarshal(raw, &structured); err != nil {
			return fmt.Errorf("scope[%d] must be a string or {kind,value}", i)
		}
		out = append(out, structured)
	}
	*items = out
	return nil
}

// assetStore returns the asset store.
func (s *Server) assetStore() *db.AssetStore {
	if s.m.pg == nil {
		return nil
	}
	return s.m.pg.Assets()
}

// companyStore returns the company store.
func (s *Server) companyStore() *db.CompanyStore {
	if s.m.pg == nil {
		return nil
	}
	return s.m.pg.Companies()
}

// =====================================================================
// GET /api/companies
// =====================================================================

func (s *Server) listCompanies(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	companies, err := cs.ListCompanies()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, companies)
}

// =====================================================================
// POST /api/companies
// =====================================================================

func (s *Server) createCompany(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		Name  string             `json:"name"`
		Logo  string             `json:"logo"`
		Scope companyScopeInputs `json:"scope"`
	}
	if !decodeCompanyMutationRequest(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, 400, "name required")
		return
	}
	if err := db.ValidateCompanyScopeInputBounds(req.Scope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, added, skipped, invalid, scopeErrs, err := cs.CreateCompanyWithScope(req.Name, req.Logo, req.Scope, "api")
	if err != nil {
		if errors.Is(err, db.ErrCompanyNameConflict) {
			writeErr(w, http.StatusConflict, "企业名称已存在")
			return
		}
		var validationErr *db.CompanyScopeValidationError
		if errors.As(err, &validationErr) {
			writeErr(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{
		"id":            id,
		"created":       true,
		"scope_added":   added,
		"scope_skipped": skipped,
		"scope_invalid": invalid,
	}
	if len(scopeErrs) > 0 {
		out["scope_errors"] = scopeErrs
	}
	// Scope rules only claim assets that ALREADY exist — they never harvest — so 0
	// is a normal answer for a freshly created company. The operator still has to
	// see it, otherwise a company with 9 rules and no assets looks like it worked.
	// A failure to compute the count must not fail the write that already committed.
	if count, countErr := cs.AssetCount(id); countErr == nil {
		out["asset_count"] = count
	}
	writeJSON(w, 201, out)
}

// =====================================================================
// GET /api/companies/{id}
// =====================================================================

func (s *Server) getCompany(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := cs.GetCompany(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if c == nil {
		writeErr(w, 404, "company not found")
		return
	}
	scope, err := cs.GetScope(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"company": c, "scope": scope})
}

// =====================================================================
// POST /api/companies/{id}/scope
// =====================================================================

func (s *Server) addCompanyScope(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid company id")
		return
	}
	var req struct {
		Scope  companyScopeInputs `json:"scope"`
		Reason string             `json:"reason"`
		Reset  bool               `json:"reset"` // if true, replace existing scope
	}
	if !decodeCompanyMutationRequest(w, r, &req) {
		return
	}
	if err := db.ValidateCompanyScopeInputBounds(req.Scope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var added, skipped, invalid int
	var errs []string
	var mutationErr error
	if req.Reset {
		added, invalid, errs, mutationErr = cs.UpdateScopeInputsChecked(id, req.Scope, req.Reason)
	} else {
		added, skipped, invalid, errs, mutationErr = cs.AddScopeInputsChecked(id, req.Scope, req.Reason)
	}
	if mutationErr != nil {
		if errors.Is(mutationErr, db.ErrCompanyNotFound) {
			writeErr(w, http.StatusNotFound, "company not found")
			return
		}
		var validationErr *db.CompanyScopeValidationError
		if errors.As(mutationErr, &validationErr) {
			writeErr(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, mutationErr.Error())
		return
	}
	out := map[string]any{
		"added":   added,
		"skipped": skipped,
		"invalid": invalid,
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	// Reported separately from errors: this is pre-existing bad data, not a fault
	// in the submitted rules, but the operator still has to see it or those assets
	// look like the IP/CIDR rules simply never match. A failure to build the
	// warning must not fail the scope write that already committed.
	if warning, err := cs.MalformedIPAssetWarning(); err == nil && warning != "" {
		out["warnings"] = []string{warning}
	}
	// Same reasoning as createCompany: 范围规则只认领已存在的资产，0 命中是正常结果，
	// 但操作员必须看见。统计失败不得挡掉已经提交的范围写操作。
	if count, countErr := cs.AssetCount(id); countErr == nil {
		out["asset_count"] = count
	}
	writeJSON(w, 200, out)
}

// =====================================================================
// DELETE /api/companies/{id}
// =====================================================================

func (s *Server) deleteCompany(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	var req struct {
		DeleteAssets bool `json:"delete_assets"`
	}
	// The body is optional. Only an actual empty body is ignored; malformed or
	// trailing JSON is a client error.
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	} else {
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				writeErr(w, http.StatusBadRequest, "invalid JSON: multiple values")
			} else {
				writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			}
			return
		}
	}

	assetsDeleted, err := s.m.DeleteCompanyWithAssets(id, req.DeleteAssets)
	if err != nil {
		if errors.Is(err, db.ErrCompanyNotFound) {
			writeErr(w, http.StatusNotFound, "company not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": 1, "assets_deleted": assetsDeleted})
}

// =====================================================================
// POST /api/companies/reattribute
// =====================================================================

func (s *Server) reattribute(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	// 不只是重算归属：企业范围里声明的域名/IP 会先补落成资产行，再按范围重算。
	// 这样"先配范围、后补这条按钮"也能把资产数补齐。
	materialized, err := cs.MaterializeScopeAssets()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "assets_materialized": materialized})
}

// =====================================================================
// GET /api/assets
// =====================================================================

const (
	defaultAssetPageSize = 50
	maxAssetPageSize     = 200
)

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query()
	typ := q.Get("type")
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = defaultAssetPageSize
	} else if limit > maxAssetPageSize {
		limit = maxAssetPageSize
	}
	if offset < 0 {
		offset = 0
	}

	assets := []*db.Asset{}
	var err error
	// total is the full match count ignoring limit/offset. Count first so an offset
	// beyond the last row can return an empty page without an expensive scan.
	total := 0

	if dsl := q.Get("dsl"); dsl != "" {
		if err := db.ValidateDSL(dsl); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// task_id scopes the DSL search to a task's assets (the task detail
		// "测试资产" search); 0 means the global asset view.
		taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
		total, err = as.CountDSL(dsl, typ, taskID)
		if err == nil && offset < total {
			assets, err = as.QueryDSL(dsl, typ, taskID, limit, offset)
		}
	} else {
		companyID, _ := strconv.ParseInt(q.Get("company_id"), 10, 64)
		taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
		switch {
		case companyID > 0:
			total, err = as.CountByCompany(companyID, typ)
			if err == nil && offset < total {
				assets, err = as.QueryByCompany(companyID, typ, limit, offset)
			}
		case taskID > 0:
			total, err = as.CountByTask(taskID, typ)
			if err == nil && offset < total {
				assets, err = as.QueryByTask(taskID, typ, limit, offset)
			}
		default:
			if typ == "" {
				typ = "root_domain"
			}
			total, err = as.CountByType(typ)
			if err == nil && offset < total {
				assets, err = as.QueryByType(typ, limit, offset)
			}
		}
	}

	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"count":  len(assets),
		"total":  total,
		"assets": assets,
	})
}

// =====================================================================
// GET /api/assets/counts
// =====================================================================

func (s *Server) assetCounts(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var counts map[string]int
	var err error
	if taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64); taskID > 0 {
		counts, err = as.CountsByTypeForTask(taskID)
	} else {
		counts, err = as.CountsByType()
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, counts)
}

// =====================================================================
// DELETE /api/assets
// =====================================================================

func (s *Server) deleteAssets(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "ids required")
		return
	}
	deleted, err := as.DeleteByIDs(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted})
}

// =====================================================================
// POST /api/assets
// =====================================================================

func (s *Server) insertAssets(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		TaskID int64 `json:"task_id"`
		Assets []struct {
			Type string `json:"type"`
			// root_domain / subdomain
			Domain      string   `json:"domain"`
			ICP         string   `json:"icp"`
			RecordType  string   `json:"record_type"`
			RecordValue []string `json:"record_value"`
			// ip
			IP           string           `json:"ip"`
			BoundDomains []string         `json:"bound_domains"`
			OpenPorts    []db.PortService `json:"open_ports"`
			// app
			AppName     string `json:"app_name"`
			BundleID    string `json:"bundle_id"`
			Category    string `json:"category"`
			Description string `json:"description"`
			AppICP      string `json:"app_icp"`
			// service http
			URL           string           `json:"url"`
			Technologies  []string         `json:"technologies"`
			StatusCode    *int             `json:"status_code"`
			ContentLength *int64           `json:"content_length"`
			PageTitle     string           `json:"page_title"`
			FaviconMMH3   string           `json:"favicon_mmh3"`
			Auth          []map[string]any `json:"auth"`
			ServiceIP     string           `json:"service_ip"`
			// service other
			Port        int    `json:"port"`
			ServiceName string `json:"service_name"`
			// endpoint
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}

	type result struct {
		Index int    `json:"index"`
		ID    int64  `json:"id"`
		Type  string `json:"type"`
	}
	type errEntry struct {
		Index int    `json:"index"`
		Error string `json:"error"`
	}
	var results []result
	var errs []errEntry

	for i, a := range req.Assets {
		var id int64
		var err error
		switch a.Type {
		case "root_domain":
			id, err = as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: a.Domain, ICP: a.ICP, TaskID: req.TaskID})
		case "ip":
			id, err = as.UpsertIP(db.UpsertIPReq{IP: a.IP, BoundDomains: a.BoundDomains, OpenPorts: a.OpenPorts, TaskID: req.TaskID})
		case "subdomain":
			id, err = as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: a.Domain, RecordType: a.RecordType, RecordValue: a.RecordValue, ICP: a.ICP, TaskID: req.TaskID})
		case "app":
			id, err = as.UpsertApp(db.UpsertAppReq{Name: a.AppName, BundleID: a.BundleID, Category: a.Category, Description: a.Description, ICP: a.AppICP, TaskID: req.TaskID})
		case "service":
			if a.URL != "" {
				svcIP := a.ServiceIP
				if svcIP == "" {
					svcIP = a.IP
				}
				id, err = as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: a.URL, Technologies: a.Technologies, StatusCode: a.StatusCode, ContentLength: a.ContentLength, PageTitle: a.PageTitle, FaviconMMH3: a.FaviconMMH3, Auth: a.Auth, IP: svcIP, TaskID: req.TaskID})
			} else {
				id, err = as.UpsertOtherService(db.UpsertOtherServiceReq{Domain: a.Domain, IP: a.IP, Port: a.Port, ServiceName: a.ServiceName, Auth: a.Auth, TaskID: req.TaskID})
			}
		case "endpoint":
			svcIP := a.ServiceIP
			if svcIP == "" {
				svcIP = a.IP
			}
			id, err = as.UpsertEndpoint(db.UpsertEndpointReq{URL: a.URL, Method: a.Method, Params: a.Params, IP: svcIP, TaskID: req.TaskID})
		default:
			errs = append(errs, errEntry{Index: i, Error: "unknown type: " + a.Type})
			continue
		}
		if err != nil {
			errs = append(errs, errEntry{Index: i, Error: err.Error()})
			continue
		}
		if req.TaskID > 0 {
			_ = as.SetTaskAssetSource(req.TaskID, id, "api", "通过资产 API 登记", nil)
		}
		results = append(results, result{Index: i, ID: id, Type: a.Type})
	}
	writeJSON(w, 200, map[string]any{"results": results, "errors": errs})
}

// =====================================================================
// POST /api/assets/register
// =====================================================================

// registerAssetEntry is one asset this request actually wrote, reported with the
// ownership columns read back from the database after attribution.
type registerAssetEntry struct {
	ID            int64  `json:"id"`
	Type          string `json:"type"`
	Value         string `json:"value"`
	CompanyID     int64  `json:"company_id"`
	CompanySource string `json:"company_source"`
}

// registerAssets 是资产页的「新增资产」入口：人给什么就记什么。
//
// 设计理由：资产页录入的是操作员手上的已知资产，不是一次采集任务。所以这里只做
// 「原样登记」——域名建成 root_domain、IP 建成 ip，绝不因为拿到了一个域名就去做
// DNS 解析 / HTTP 探测之类的自动延伸（那属于侦察任务，会悄悄扩大资产库）。
//
// 另一条边界：CIDR / ICP / 关键词本身不是资产，而是「企业范围规则」，只有挂到某个
// 企业上才有意义（它们的用途是圈定哪些资产算这个企业的）。因此没选企业时它们不会
// 被悄悄丢掉，也不会被硬塞进资产库，而是作为 skipped 明确回报「需要先选择企业」。
//
// 选了企业时，域名/IP 走 explicit 归属（company_source='explicit'）：操作员显式
// 指定优先，后续按范围重算归属不会把它改回去，即使它不匹配该企业已有的任何规则。
func (s *Server) registerAssets(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	cs := s.companyStore()
	if as == nil || cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		CompanyID int64              `json:"company_id"`
		Scope     companyScopeInputs `json:"scope"`
	}
	if !decodeCompanyMutationRequest(w, r, &req) {
		return
	}
	// 请求级上限先校验：它能直接指出是第几条超长，比逐条解析时报错更有用。
	if err := db.ValidateCompanyScopeInputBounds(req.Scope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	companyID := req.CompanyID
	if companyID > 0 {
		// 范围类规则需要一个落点。企业不存在时必须整体拒绝，否则会写进一批
		// 谁也认领不了的资产/规则，看起来像成功了。
		company, err := cs.GetCompany(companyID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if company == nil {
			writeErr(w, http.StatusNotFound, "企业不存在")
			return
		}
	}

	type createdAsset struct {
		id    int64
		typ   string
		value string
	}
	type invalidEntry struct {
		Index int    `json:"index"`
		Kind  string `json:"kind"`
		Value string `json:"value"`
		Error string `json:"error"`
	}
	type skippedEntry struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Reason string `json:"reason"`
	}

	created := make([]createdAsset, 0, len(req.Scope))
	invalid := make([]invalidEntry, 0)
	skipped := make([]skippedEntry, 0)
	companyScopeAdded := 0
	companyScopeSkipped := 0

	for i, input := range req.Scope {
		// index 从 1 开始，直接对应操作员看到的那一行。
		rule, err := db.ParseScopeInput(db.ScopeInput{Kind: input.Kind, Value: input.Value})
		if err != nil {
			// 单条解析失败只影响它自己：其余条目照常入库，逐条回报原因。
			invalid = append(invalid, invalidEntry{
				Index: i + 1,
				Kind:  strings.TrimSpace(input.Kind),
				Value: input.Value,
				Error: err.Error(),
			})
			continue
		}
		switch rule.Kind {
		case "domain":
			id, err := as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: rule.Domain})
			if err != nil {
				// 存储失败不是本次输入的问题，不伪装成 invalid：此时前面的资产
				// 可能已经落库，必须让调用方知道请求整体失败了。
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			created = append(created, createdAsset{id: id, typ: "root_domain", value: rule.Domain})
		case "ip":
			// ParseScopeInput 把裸 IP 归一成 /32 或 /128 的 CIDR；资产列里存的是
			// 地址本身，不带掩码。
			ip, _, cidrErr := net.ParseCIDR(rule.Net)
			if cidrErr != nil {
				invalid = append(invalid, invalidEntry{
					Index: i + 1,
					Kind:  rule.Kind,
					Value: rule.Raw,
					Error: "无效 IP: " + cidrErr.Error(),
				})
				continue
			}
			id, err := as.UpsertIP(db.UpsertIPReq{IP: ip.String()})
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			created = append(created, createdAsset{id: id, typ: "ip", value: ip.String()})
		case "cidr", "icp", "keyword":
			value := registerScopeRuleValue(rule)
			if companyID <= 0 {
				skipped = append(skipped, skippedEntry{Kind: rule.Kind, Value: value, Reason: scopeRuleNeedsCompany})
				continue
			}
			// 一条一次调用，这样「被跳过（重复）」能逐条对应回原始规则。
			added, skip, bad, errs, err := cs.AddScopeInputsChecked(
				companyID, []db.ScopeInput{{Kind: rule.Kind, Value: value}}, "资产页手工添加",
			)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			companyScopeAdded += added
			companyScopeSkipped += skip
			if bad > 0 {
				message := strings.Join(errs, "；")
				if message == "" {
					message = "该规则未被企业范围接受"
				}
				invalid = append(invalid, invalidEntry{Index: i + 1, Kind: rule.Kind, Value: value, Error: message})
			}
		}
	}

	// 同一个域名/IP 粘两次会 upsert 成同一条资产，只回报一次，让「已添加 N 个
	// 资产」和资产库里真正多了几行对得上。
	unique := make([]createdAsset, 0, len(created))
	seen := make(map[int64]bool, len(created))
	for _, a := range created {
		if seen[a.id] {
			continue
		}
		seen[a.id] = true
		unique = append(unique, a)
	}
	ids := make([]int64, 0, len(unique))
	for _, a := range unique {
		ids = append(ids, a.id)
	}

	if companyID > 0 && len(ids) > 0 {
		// 显式归属：企业是操作员选的，所以即使这条资产不匹配企业已有的范围规则，
		// 也要落到该企业，并且后续范围重算不许把它改回去。
		if _, err := as.SetAssetsCompany(ids, &companyID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// 归属写完回读真实值：Upsert 内部会按范围顺手认领（company_source='scope'），
	// 响应里不能拿内存里的期望值冒充落库结果。
	attribution, err := as.CompanyAttributionByIDs(ids)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	assetsOut := make([]registerAssetEntry, 0, len(unique))
	for _, a := range unique {
		entry := registerAssetEntry{ID: a.id, Type: a.typ, Value: a.value}
		if att, ok := attribution[a.id]; ok && att.CompanyID != nil {
			entry.CompanyID = *att.CompanyID
			entry.CompanySource = att.CompanySource
		}
		// 未归属时故意不回填 company_source：插入时内部总会写一个派生来源
		// （scope），把它回给调用方会让页面把「无主资产」显示成「范围命中」。
		assetsOut = append(assetsOut, entry)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"assets":                assetsOut,
		"company_scope_added":   companyScopeAdded,
		"company_scope_skipped": companyScopeSkipped,
		"invalid":               invalid,
		"skipped":               skipped,
	})
}

// scopeRuleNeedsCompany 是未选企业时的跳过原因。范围类规则没有「全局」语义，
// 必须说清楚下一步，否则操作员只会以为系统把 CIDR 弄丢了。
const scopeRuleNeedsCompany = "CIDR/ICP/关键词是企业范围规则，需要先选择企业"

// registerScopeRuleValue 返回要交给企业范围存储的归一化文本：cidr 用归一化网段，
// icp/keyword 用归一化文本（存储层会再解析一次，传归一化值才不会二次变动）。
func registerScopeRuleValue(rule db.ParsedScope) string {
	if rule.Kind == "cidr" {
		return rule.Net
	}
	return rule.Value
}
