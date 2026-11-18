package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

// LLM 测绘：发现暴露的大模型服务、登记未授权能力与泄露的密钥。
//
// 为什么单独建表而不是塞进 assets：assets 是"客户授权资产"的图谱，而这里的对象
// 可能是公网上任何一个暴露实例（测绘阶段未必在授权清单里）。混在一起会把未授权
// 目标混进客户资产统计，报告和覆盖度都会算错。

// LLMAsset 是一个可访问的大模型服务实例。
type LLMAsset struct {
	ID        int64     `json:"id"`
	URL       string    `json:"url"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Vendor    string    `json:"vendor"`
	Version   string    `json:"version"`
	Unauth    bool      `json:"unauth"` // 无需凭据即可列模型/推理
	Models    []string  `json:"models"`
	Evidence  string    `json:"evidence"` // 判据：命中的路径 + 状态码
	Source    string    `json:"source"`   // seed / assets
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// LLMKey 是一条泄露的密钥记录。Raw 只落库、默认不外传，接口只回 Masked。
type LLMKey struct {
	ID      int64  `json:"id"`
	AssetID int64  `json:"asset_id,omitempty"`
	URL     string `json:"url"`
	KeyType string `json:"key_type"`
	// Raw 是密钥原文：只落库、永不外传（json:"-"），接口一律只回 Masked。
	Raw         string    `json:"-"`
	Masked      string    `json:"masked"`
	Fingerprint string    `json:"fingerprint"`
	Context     string    `json:"context"`
	FoundAt     time.Time `json:"found_at"`
}

// EnsureLLMHuntTables 建表（幂等）。
func (d *DB) EnsureLLMHuntTables() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS llm_assets (
			id         bigserial PRIMARY KEY,
			url        text NOT NULL UNIQUE,
			host       text NOT NULL,
			port       integer NOT NULL,
			vendor     text NOT NULL DEFAULT '',
			version    text NOT NULL DEFAULT '',
			unauth     boolean NOT NULL DEFAULT false,
			models     jsonb NOT NULL DEFAULT '[]',
			evidence   text NOT NULL DEFAULT '',
			source     text NOT NULL DEFAULT '',
			first_seen timestamptz NOT NULL DEFAULT now(),
			last_seen  timestamptz NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_assets_vendor ON llm_assets(vendor)`,
		`CREATE TABLE IF NOT EXISTS llm_keys (
			id          bigserial PRIMARY KEY,
			asset_id    bigint,
			url         text NOT NULL,
			key_type    text NOT NULL,
			raw         text NOT NULL,
			masked      text NOT NULL,
			fingerprint text NOT NULL,
			context     text NOT NULL DEFAULT '',
			found_at    timestamptz NOT NULL DEFAULT now(),
			UNIQUE (fingerprint, url)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_llm_keys_type ON llm_keys(key_type)`,
		`CREATE TABLE IF NOT EXISTS llm_scans (
			id         bigserial PRIMARY KEY,
			status     text NOT NULL DEFAULT 'running',
			total      integer NOT NULL DEFAULT 0,
			done       integer NOT NULL DEFAULT 0,
			assets     integer NOT NULL DEFAULT 0,
			keys       integer NOT NULL DEFAULT 0,
			note       text NOT NULL DEFAULT '',
			started_at timestamptz NOT NULL DEFAULT now(),
			finished_at timestamptz
		)`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpsertLLMAsset 写入或刷新一个实例，返回 id。
func (d *DB) UpsertLLMAsset(a *LLMAsset) (int64, error) {
	models := encodeJSONOr(a.Models, "[]")
	var id int64
	err := d.QueryRow(`
INSERT INTO llm_assets(url,host,port,vendor,version,unauth,models,evidence,source,last_seen)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
ON CONFLICT (url) DO UPDATE SET
  vendor=EXCLUDED.vendor, version=EXCLUDED.version, unauth=EXCLUDED.unauth,
  models=EXCLUDED.models, evidence=EXCLUDED.evidence, last_seen=now()
RETURNING id`,
		a.URL, a.Host, a.Port, a.Vendor, a.Version, a.Unauth, models, a.Evidence, a.Source).Scan(&id)
	return id, err
}

// InsertLLMKey 落一条密钥；重复（同指纹同来源）忽略。
func (d *DB) InsertLLMKey(k *LLMKey) (bool, error) {
	res, err := d.Exec(`
INSERT INTO llm_keys(asset_id,url,key_type,raw,masked,fingerprint,context)
VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (fingerprint,url) DO NOTHING`,
		nullIfZero(k.AssetID), k.URL, k.KeyType, k.Raw, k.Masked, k.Fingerprint, k.Context)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListLLMAssets 返回最近的实例（限 500）。
func (d *DB) ListLLMAssets(limit int) ([]LLMAsset, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`SELECT id,url,host,port,vendor,version,unauth,models::text,evidence,source,first_seen,last_seen
FROM llm_assets ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMAsset
	for rows.Next() {
		var a LLMAsset
		var models string
		if err := rows.Scan(&a.ID, &a.URL, &a.Host, &a.Port, &a.Vendor, &a.Version,
			&a.Unauth, &models, &a.Evidence, &a.Source, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		a.Models = decodeStringSlice(models)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListLLMKeys 返回密钥记录；不返回 raw。
func (d *DB) ListLLMKeys(limit int) ([]LLMKey, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`SELECT id,coalesce(asset_id,0),url,key_type,masked,fingerprint,context,found_at
FROM llm_keys ORDER BY found_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMKey
	for rows.Next() {
		var k LLMKey
		if err := rows.Scan(&k.ID, &k.AssetID, &k.URL, &k.KeyType, &k.Masked, &k.Fingerprint, &k.Context, &k.FoundAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// LLMKeyRaw 取出原文（只在用户显式点开某一条时调用，调用方负责用后即弃）。
func (d *DB) LLMKeyRaw(id int64) (string, error) {
	var raw string
	err := d.QueryRow(`SELECT raw FROM llm_keys WHERE id=$1`, id).Scan(&raw)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return raw, err
}

// DeleteLLMKey 删除一条记录。
func (d *DB) DeleteLLMKey(id int64) error {
	_, err := d.Exec(`DELETE FROM llm_keys WHERE id=$1`, id)
	return err
}

// DeleteLLMAsset 删除一个实例（连带它的密钥记录）。
func (d *DB) DeleteLLMAsset(id int64) error {
	if _, err := d.Exec(`DELETE FROM llm_keys WHERE asset_id=$1`, id); err != nil {
		return err
	}
	_, err := d.Exec(`DELETE FROM llm_assets WHERE id=$1`, id)
	return err
}

// StartLLMScan 记录一次扫描。
func (d *DB) StartLLMScan(total int) (int64, error) {
	var id int64
	err := d.QueryRow(`INSERT INTO llm_scans(total) VALUES($1) RETURNING id`, total).Scan(&id)
	return id, err
}

// UpdateLLMScan 更新进度。
func (d *DB) UpdateLLMScan(id int64, done, assets, keys int, status, note string) error {
	_, err := d.Exec(`UPDATE llm_scans SET done=$2, assets=$3, keys=$4, status=COALESCE(NULLIF($5,''),status), note=$6,
finished_at=CASE WHEN $5 IN ('done','failed','stopped') THEN now() ELSE finished_at END WHERE id=$1`,
		id, done, assets, keys, status, note)
	return err
}

// LastLLMScan 取最近一次扫描状态。
func (d *DB) LastLLMScan() (map[string]any, error) {
	row := d.QueryRow(`SELECT id,status,total,done,assets,keys,note,started_at,finished_at
FROM llm_scans ORDER BY id DESC LIMIT 1`)
	var (
		id                int64
		status, note      string
		total, done, a, k int
		started           time.Time
		finished          sql.NullTime
	)
	if err := row.Scan(&id, &status, &total, &done, &a, &k, &note, &started, &finished); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]any{
		"id": id, "status": status, "total": total, "done": done,
		"assets": a, "keys": k, "note": note, "started_at": started,
	}
	if finished.Valid {
		out["finished_at"] = finished.Time
	}
	return out, nil
}

// encodeJSONOr marshals v, falling back to def when v is nil or cannot encode.
func encodeJSONOr(v any, def string) string {
	if v == nil {
		return def
	}
	b, err := json.Marshal(v)
	if err != nil {
		return def
	}
	return string(b)
}

// decodeStringSlice parses a JSON array of strings, tolerating NULL/garbage.
func decodeStringSlice(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// SetLLMScanTotal 在搜索发现完成后回填目标总数。
func (d *DB) SetLLMScanTotal(id int64, total int) error {
	_, err := d.Exec(`UPDATE llm_scans SET total=$2 WHERE id=$1`, id, total)
	return err
}
