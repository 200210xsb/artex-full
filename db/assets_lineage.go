package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// =====================================================================
// 资产血缘（发现来源可追溯）
//
// 血缘回答一个问题：这条资产「是谁发现的、什么时候发现的、归属谁」。
// 数据来源：
//   - assets.task_ids          → 关联到哪些任务
//   - task_asset_links         → 每个任务的发现方式（source / source_summary / 节点）
//   - assets.company_id/source → 企业归属与归属方式
//   - assets.created_at        → 首次入库时间（发现时间）
// =====================================================================

// AssetLineageSource 是一条「发现来源」：哪个任务、用什么方式关联的。
type AssetLineageSource struct {
	TaskID        int64  `json:"task_id"`
	TaskName      string `json:"task_name"`
	TaskStatus    string `json:"task_status,omitempty"`
	Source        string `json:"source"`
	SourceSummary string `json:"source_summary,omitempty"`
	SourceNodeID  *int64 `json:"source_node_id,omitempty"`
	LinkedAt      string `json:"linked_at,omitempty"`
}

// AssetLineage 是一条资产的完整血缘。
type AssetLineage struct {
	ID            int64    `json:"id"`
	Type          string   `json:"type"`
	Label         string   `json:"label"`
	Domain        string   `json:"domain,omitempty"`
	RootDomain    string   `json:"root_domain,omitempty"`
	IP            string   `json:"ip,omitempty"`
	Port          *int     `json:"port,omitempty"`
	URL           string   `json:"url,omitempty"`
	BundleID      string   `json:"bundle_id,omitempty"`
	Technologies  []string `json:"technologies"`
	TaskIDs       []int64  `json:"task_ids"`
	CompanyID     *int64   `json:"company_id,omitempty"`
	CompanyName   string   `json:"company_name,omitempty"`
	CompanySource string   `json:"company_source,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
	LastSeen      string   `json:"last_seen,omitempty"`
	// InScope 表示该资产是否落在查询指定的任务范围内（未指定任务时恒为 false）。
	InScope bool `json:"in_scope"`
	// SiblingCount 是同根域名（同企业时同企业）下的兄弟资产数量。
	SiblingCount int                  `json:"sibling_count"`
	Sources      []AssetLineageSource `json:"sources"`
}

// AssetLineageQuery 是一次血缘查询的过滤条件。
// 三种定位方式互斥，优先级：IDs > DSL。
type AssetLineageQuery struct {
	IDs    []int64
	DSL    string
	Type   string
	TaskID int64
	Limit  int
	Offset int
}

// QueryAssetLineage 返回匹配资产的发现血缘。IDs 为空且 DSL 为空时返回空列表
// （调用方应先校验参数，避免无条件全表扫描）。
func (s *AssetStore) QueryAssetLineage(q AssetLineageQuery) ([]AssetLineage, int, error) {
	if len(q.IDs) == 0 && strings.TrimSpace(q.DSL) == "" {
		return []AssetLineage{}, 0, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if q.Offset < 0 {
		q.Offset = 0
	}

	// 1) 先按过滤条件取出资产 id 集合。
	var ids []int64
	total := 0
	if len(q.IDs) > 0 {
		placeholders := make([]string, len(q.IDs))
		args := make([]any, len(q.IDs))
		for i, id := range q.IDs {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = id
		}
		sql := "SELECT id FROM assets WHERE id IN (" + strings.Join(placeholders, ",") + ")"
		if err := s.db.QueryRow("SELECT count(*) FROM ("+sql+") t", args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, limit, q.Offset)
		sql += fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
		rows, err := s.db.Query(sql, args...)
		if err != nil {
			return nil, 0, err
		}
		ids, err = scanInt64s(rows)
		if err != nil {
			return nil, 0, err
		}
	} else {
		node, err := ParseDSL(q.DSL)
		if err != nil {
			return nil, 0, err
		}
		where, args, err := buildDSLWhere(node)
		if err != nil {
			return nil, 0, err
		}
		if q.Type != "" {
			args = append(args, q.Type)
			where += fmt.Sprintf(" AND type = $%d", len(args))
		}
		if err := s.db.QueryRow("SELECT count(*) FROM assets WHERE "+where, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, limit, q.Offset)
		rows, err := s.db.Query("SELECT id FROM assets WHERE "+where+
			fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		ids, err = scanInt64s(rows)
		if err != nil {
			return nil, 0, err
		}
	}

	if len(ids) == 0 {
		return []AssetLineage{}, total, nil
	}

	// 2) 资产主体信息。
	rows, err := s.db.Query(`
SELECT a.id, a.type,
       COALESCE(NULLIF(a.url,''), NULLIF(a.domain,''), NULLIF(a.ip,''), NULLIF(a.app_name,''), NULLIF(a.root_domain,''), '#' || a.id::text),
       COALESCE(a.domain,''), COALESCE(a.root_domain,''), COALESCE(a.ip,''), a.port,
       COALESCE(a.url,''), COALESCE(a.bundle_id,''),
       array_to_json(a.technologies)::text, array_to_json(a.task_ids)::text,
       a.company_id, COALESCE(c.name,''), COALESCE(a.company_source,''),
       a.created_at::text, a.updated_at::text, a.last_seen::text
FROM assets a
LEFT JOIN companies c ON c.id = a.company_id
WHERE a.id = ANY($1::bigint[])
ORDER BY a.last_seen DESC, a.id DESC`, ids)
	if err != nil {
		return nil, 0, err
	}
	out := []AssetLineage{}
	byID := map[int64]*AssetLineage{}
	for rows.Next() {
		var item AssetLineage
		var port sql.NullInt64
		var companyID sql.NullInt64
		var techsRaw, taskIDsRaw []byte
		if err := rows.Scan(&item.ID, &item.Type, &item.Label,
			&item.Domain, &item.RootDomain, &item.IP, &port,
			&item.URL, &item.BundleID, &techsRaw, &taskIDsRaw,
			&companyID, &item.CompanyName, &item.CompanySource,
			&item.CreatedAt, &item.UpdatedAt, &item.LastSeen); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if port.Valid {
			p := int(port.Int64)
			item.Port = &p
		}
		if companyID.Valid {
			cid := companyID.Int64
			item.CompanyID = &cid
		}
		if len(techsRaw) > 0 {
			_ = json.Unmarshal(techsRaw, &item.Technologies)
		}
		if len(taskIDsRaw) > 0 {
			_ = json.Unmarshal(taskIDsRaw, &item.TaskIDs)
		}
		item.Technologies = dedupeStrings(item.Technologies)
		item.Sources = []AssetLineageSource{}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	for i := range out {
		byID[out[i].ID] = &out[i]
	}

	// 3) 发现来源：task_asset_links JOIN tasks。
	linkRows, err := s.db.Query(`
SELECT link.asset_id, link.task_id,
       COALESCE(NULLIF(t.name,''), NULLIF(t.description,''), '#' || t.id::text),
       COALESCE(t.status,''),
       COALESCE(link.source,''), COALESCE(link.source_summary,''), link.source_node_id,
       link.created_at::text
FROM task_asset_links link
JOIN tasks t ON t.id = link.task_id
WHERE link.asset_id = ANY($1::bigint[])
ORDER BY link.asset_id, link.created_at, link.task_id`, ids)
	if err != nil {
		return nil, 0, err
	}
	for linkRows.Next() {
		var assetID int64
		var src AssetLineageSource
		var nodeID sql.NullInt64
		if err := linkRows.Scan(&assetID, &src.TaskID, &src.TaskName, &src.TaskStatus,
			&src.Source, &src.SourceSummary, &nodeID, &src.LinkedAt); err != nil {
			linkRows.Close()
			return nil, 0, err
		}
		if nodeID.Valid {
			id := nodeID.Int64
			src.SourceNodeID = &id
		}
		if item := byID[assetID]; item != nil {
			item.Sources = append(item.Sources, src)
		}
	}
	if err := linkRows.Err(); err != nil {
		linkRows.Close()
		return nil, 0, err
	}
	linkRows.Close()

	// 4) 兄弟资产数量（同根域名；无根域名时按同企业）。
	siblingRows, err := s.db.Query(`
SELECT sel.id, (
  SELECT count(*) FROM assets a
  WHERE a.id <> sel.id
    AND (
      (COALESCE(sel.root_domain,'') <> '' AND a.root_domain = sel.root_domain)
      OR (COALESCE(sel.root_domain,'') = '' AND sel.company_id IS NOT NULL AND a.company_id = sel.company_id)
    )
)
FROM (SELECT id, root_domain, company_id FROM assets WHERE id = ANY($1::bigint[])) sel`, ids)
	if err != nil {
		return nil, 0, err
	}
	for siblingRows.Next() {
		var assetID int64
		var count int
		if err := siblingRows.Scan(&assetID, &count); err != nil {
			siblingRows.Close()
			return nil, 0, err
		}
		if item := byID[assetID]; item != nil {
			item.SiblingCount = count
		}
	}
	if err := siblingRows.Err(); err != nil {
		siblingRows.Close()
		return nil, 0, err
	}
	siblingRows.Close()

	// 5) 是否在指定任务范围内。
	if q.TaskID > 0 {
		inScope, err := s.AssetIDsInTaskScope(q.TaskID, ids)
		if err != nil {
			return nil, 0, err
		}
		for i := range out {
			out[i].InScope = inScope[out[i].ID]
		}
	}
	return out, total, nil
}

// AssetIDsInTaskScope 返回给定资产中落在任务范围内的子集。
// 复用 list_assets 的范围口径（scopeTargetCTE）：按归属判定「在不在范围内」，
// 而不是按字面量相等。
func (s *AssetStore) AssetIDsInTaskScope(taskID int64, ids []int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	if taskID <= 0 || len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`WITH `+scopeTargetCTE+`
SELECT id FROM target WHERE id = ANY($2::bigint[])`, taskID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// =====================================================================
// 资产覆盖度（全局视图）
//
// 口径与任务覆盖度完全一致：分母 = 范围内的资产数，分子 = 被事实锚点覆盖
// （exploration_nodes.kind='fact' 锚定过）的资产数。任务内直接复用
// TaskCoverageWithSources；这里只补一个「按 DSL/类型过滤的全局视图」。
// =====================================================================

// AssetCoverage computes the global coverage view over the assets matching a
// DSL expression and/or type. The tested/not-tested definition is the same as
// the per-task coverage: an asset counts as tested once a fact node anchors it.
func (s *AssetStore) AssetCoverage(dsl, typ string) (*Coverage, error) {
	cov := &Coverage{Enabled: true, ByType: []CoverageByType{}}
	node, err := ParseDSL(dsl)
	if err != nil {
		return nil, err
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		return nil, err
	}
	if typ != "" {
		args = append(args, typ)
		where += fmt.Sprintf(" AND type = $%d", len(args))
	}
	rows, err := s.db.Query(`
WITH target AS (
  SELECT a.id, a.type FROM assets a WHERE `+where+`
),
tested AS (
  SELECT DISTINCT ea.asset_id
  FROM exploration_anchors ea
  JOIN exploration_nodes en ON en.id = ea.node_id AND en.kind = 'fact'
)
SELECT target.type, count(*) AS total,
       count(*) FILTER (WHERE target.id IN (SELECT asset_id FROM tested)) AS tested
FROM target GROUP BY target.type ORDER BY target.type`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var byType CoverageByType
		if err := rows.Scan(&byType.Type, &byType.Total, &byType.Tested); err != nil {
			return nil, err
		}
		cov.ByType = append(cov.ByType, byType)
		cov.Denominator += byType.Total
		cov.Tested += byType.Tested
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if cov.Denominator > 0 {
		pct := float64(cov.Tested) / float64(cov.Denominator)
		cov.Pct = &pct
	}
	return cov, nil
}

// =====================================================================
// POC 匹配用的资产指纹
// =====================================================================

// AssetFingerprint 是用于匹配 Nuclei 模板的资产指纹摘要。
type AssetFingerprint struct {
	ID           int64    `json:"id"`
	Type         string   `json:"type"`
	Label        string   `json:"label"`
	Target       string   `json:"target"`
	Domain       string   `json:"domain,omitempty"`
	RootDomain   string   `json:"root_domain,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Port         *int     `json:"port,omitempty"`
	URL          string   `json:"url,omitempty"`
	ServiceName  string   `json:"service_name,omitempty"`
	AppName      string   `json:"app_name,omitempty"`
	PageTitle    string   `json:"page_title,omitempty"`
	Category     string   `json:"category,omitempty"`
	BundleID     string   `json:"bundle_id,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// AssetFingerprints returns the fingerprint summary of the given assets.
// When ids is empty the assets are selected by DSL (plus an optional type
// filter) instead. The result is capped at maxRows so a broad DSL query
// cannot flood the matcher.
func (s *AssetStore) AssetFingerprints(ids []int64, dsl, typ string, maxRows int) ([]AssetFingerprint, error) {
	if maxRows <= 0 {
		maxRows = 200
	}
	if maxRows > 1000 {
		maxRows = 1000
	}
	query := `
SELECT id, type,
       COALESCE(NULLIF(url,''), NULLIF(domain,''), NULLIF(ip,''), NULLIF(app_name,''), NULLIF(root_domain,''), '#' || id::text),
       COALESCE(NULLIF(url,''), NULLIF(domain,''), NULLIF(ip,''), ''),
       COALESCE(domain,''), COALESCE(root_domain,''), COALESCE(ip,''), port,
       COALESCE(url,''), COALESCE(service_name,''), COALESCE(app_name,''),
       COALESCE(page_title,''), COALESCE(category,''), COALESCE(bundle_id,''),
       array_to_json(technologies)::text
FROM assets`
	var args []any
	if len(ids) > 0 {
		args = append(args, ids)
		query += " WHERE id = ANY($1::bigint[])"
	} else {
		node, err := ParseDSL(dsl)
		if err != nil {
			return nil, err
		}
		where, dslArgs, err := buildDSLWhere(node)
		if err != nil {
			return nil, err
		}
		args = append(args, dslArgs...)
		if typ != "" {
			args = append(args, typ)
			where += fmt.Sprintf(" AND type = $%d", len(args))
		}
		query += " WHERE " + where
	}
	args = append(args, maxRows)
	query += fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetFingerprint{}
	for rows.Next() {
		var f AssetFingerprint
		var port sql.NullInt64
		var techsRaw []byte
		if err := rows.Scan(&f.ID, &f.Type, &f.Label, &f.Target,
			&f.Domain, &f.RootDomain, &f.IP, &port,
			&f.URL, &f.ServiceName, &f.AppName,
			&f.PageTitle, &f.Category, &f.BundleID, &techsRaw); err != nil {
			return nil, err
		}
		if port.Valid {
			p := int(port.Int64)
			f.Port = &p
		}
		if len(techsRaw) > 0 {
			_ = json.Unmarshal(techsRaw, &f.Technologies)
		}
		f.Technologies = dedupeStrings(f.Technologies)
		f.Target = fingerprintTarget(f)
		out = append(out, f)
	}
	return out, rows.Err()
}

// fingerprintTarget 计算 POC 验证的目标：HTTP 服务/接口用完整 URL，
// 其余用 host[:port]。
func fingerprintTarget(f AssetFingerprint) string {
	if f.URL != "" {
		return f.URL
	}
	host := f.Domain
	if host == "" {
		host = f.IP
	}
	if host == "" {
		return ""
	}
	if f.Port != nil && *f.Port > 0 && !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, *f.Port)
	}
	return host
}

// =====================================================================
// 批量改企业归属
// =====================================================================

// SetAssetsCompany 批量改资产的企业归属。companyID 为 nil 时取消归属。
// 归属方式写成 explicit（人工指定），这样后续的范围重算不会把它改回去。
// 返回实际更新的行数。
func (s *AssetStore) SetAssetsCompany(ids []int64, companyID *int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var arg any
	if companyID != nil {
		arg = *companyID
	}
	res, err := s.db.Exec(`
UPDATE assets
SET company_id = $2, company_source = 'explicit'
WHERE id = ANY($1::bigint[])`, ids, arg)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// AssetCompanyAttribution is the persisted ownership of one asset: the two
// columns the asset page renders (company_id, company_source).
type AssetCompanyAttribution struct {
	ID            int64
	CompanyID     *int64
	CompanySource string
}

// CompanyAttributionByIDs reads back the committed company_id / company_source
// of the given assets. Callers that write ownership (SetAssetsCompany, the
// upserts' scope/task resolution in resolveCompanyForTask) must re-read instead of
// echoing the value they intended: another path may have claimed or cleared the row.
func (s *AssetStore) CompanyAttributionByIDs(ids []int64) (map[int64]AssetCompanyAttribution, error) {
	out := make(map[int64]AssetCompanyAttribution, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`
SELECT id, company_id, COALESCE(company_source, '')
FROM assets
WHERE id = ANY($1::bigint[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item AssetCompanyAttribution
		if err := rows.Scan(&item.ID, &item.CompanyID, &item.CompanySource); err != nil {
			return nil, err
		}
		out[item.ID] = item
	}
	return out, rows.Err()
}

// =====================================================================
// 小工具
// =====================================================================

func scanInt64s(rows *sql.Rows) ([]int64, error) {
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func dedupeStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
