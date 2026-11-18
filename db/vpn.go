package db

import (
	"database/sql"
	"time"
)

// VPNProfile 是一条 OpenVPN 出口配置：平台给的 .ovpn 原文加上该项目的账号。
//
// 配置原样保存（不做归一化），因为归一化规则会随 openvpn 版本演进，
// 保留原文才能在规则改进后重新生成，而不是被早期版本改写过的产物锁死。
type VPNProfile struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	OVPN         string    `json:"ovpn,omitempty"`
	Username     string    `json:"username"`
	Password     string    `json:"password,omitempty"`
	ExpectEgress string    `json:"expect_egress"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

const vpnProfileCols = `id, name, ovpn, username, password, expect_egress, enabled, created_at, updated_at`

func scanVPNProfile(sc interface{ Scan(...any) error }) (*VPNProfile, error) {
	var p VPNProfile
	if err := sc.Scan(&p.ID, &p.Name, &p.OVPN, &p.Username, &p.Password,
		&p.ExpectEgress, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// EnsureVPNTable creates the VPN profile table and the task egress column.
// Idempotent, like the other Ensure* helpers.
func (d *DB) EnsureVPNTable() error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS vpn_profiles (
			id            bigserial PRIMARY KEY,
			name          text NOT NULL UNIQUE,
			ovpn          text NOT NULL DEFAULT '',
			username      text NOT NULL DEFAULT '',
			password      text NOT NULL DEFAULT '',
			expect_egress text NOT NULL DEFAULT '',
			enabled       boolean NOT NULL DEFAULT true,
			created_at    timestamptz NOT NULL DEFAULT now(),
			updated_at    timestamptz NOT NULL DEFAULT now()
		)`,
		// 任务出口：'' 或 'global' = 平台全局代理；'vpn:<id>' = 该 VPN 隧道。
		// 用文本而不是外键，是为了在 VPN 配置被删掉后，历史任务仍能保留当时的
		// 出口记录（审计要能回答"这次测试从哪出去的"）。
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS egress text NOT NULL DEFAULT ''`,
		// 账号密码按任务保存：平台是每个项目（每期）发一套凭据，同一个 .ovpn
		// 会被不同项目复用，把账号挂在配置上就必然串号。
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS vpn_username text NOT NULL DEFAULT ''`,
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS vpn_password text NOT NULL DEFAULT ''`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListVPNProfiles returns every profile, newest last.
func (d *DB) ListVPNProfiles() ([]VPNProfile, error) {
	rows, err := d.Query(`SELECT ` + vpnProfileCols + ` FROM vpn_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VPNProfile
	for rows.Next() {
		p, err := scanVPNProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// VPNProfileByID returns one profile, or nil when absent.
func (d *DB) VPNProfileByID(id int64) (*VPNProfile, error) {
	p, err := scanVPNProfile(d.QueryRow(`SELECT `+vpnProfileCols+` FROM vpn_profiles WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// SaveVPNProfile inserts or updates a profile. An empty Password on update keeps
// the stored one: the UI never echoes the secret back, so a blank field means
// "unchanged" rather than "clear it".
func (d *DB) SaveVPNProfile(p *VPNProfile) error {
	if p.ID == 0 {
		return d.QueryRow(`
INSERT INTO vpn_profiles(name, ovpn, username, password, expect_egress, enabled)
VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
			p.Name, p.OVPN, p.Username, p.Password, p.ExpectEgress, p.Enabled).Scan(&p.ID)
	}
	if p.Password == "" {
		_, err := d.Exec(`
UPDATE vpn_profiles SET name=$2, ovpn=$3, username=$4, expect_egress=$5, enabled=$6, updated_at=now()
WHERE id=$1`, p.ID, p.Name, p.OVPN, p.Username, p.ExpectEgress, p.Enabled)
		return err
	}
	_, err := d.Exec(`
UPDATE vpn_profiles SET name=$2, ovpn=$3, username=$4, password=$5, expect_egress=$6, enabled=$7, updated_at=now()
WHERE id=$1`, p.ID, p.Name, p.OVPN, p.Username, p.Password, p.ExpectEgress, p.Enabled)
	return err
}

// DeleteVPNProfile removes a profile.
func (d *DB) DeleteVPNProfile(id int64) error {
	_, err := d.Exec(`DELETE FROM vpn_profiles WHERE id=$1`, id)
	return err
}

// TaskEgress 是一任务绑定的出口及其凭据。Password 只在写入时使用，
// 读出来给界面看的时候一律置空（与其他密钥字段一致）。
type TaskEgress struct {
	Egress   string `json:"egress"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

// SetTaskEgress stores a task's egress binding and its per-project credentials.
// An empty Password keeps the stored one, so saving the form without retyping the
// secret does not wipe it.
func (d *DB) SetTaskEgress(taskID int64, e TaskEgress) error {
	var err error
	if e.Password == "" {
		_, err = d.Exec(`UPDATE tasks SET egress=$2, vpn_username=$3, updated_at=now() WHERE id=$1`,
			taskID, e.Egress, e.Username)
	} else {
		_, err = d.Exec(`UPDATE tasks SET egress=$2, vpn_username=$3, vpn_password=$4, updated_at=now() WHERE id=$1`,
			taskID, e.Egress, e.Username, e.Password)
	}
	if err != nil {
		return err
	}
	return nil
}

// TaskEgressOf returns the egress binding and its credentials for a task.
func (d *DB) TaskEgressOf(taskID int64) (TaskEgress, error) {
	var e TaskEgress
	err := d.QueryRow(`SELECT coalesce(egress,''), coalesce(vpn_username,''), coalesce(vpn_password,'')
FROM tasks WHERE id=$1`, taskID).Scan(&e.Egress, &e.Username, &e.Password)
	if err == sql.ErrNoRows {
		return TaskEgress{}, nil
	}
	return e, err
}

// TaskEgress returns only the binding (kept for callers that do not need credentials).
func (d *DB) TaskEgress(taskID int64) (string, error) {
	e, err := d.TaskEgressOf(taskID)
	return e.Egress, err
}
