package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Autumn-27/artex/device"
)

// 移动端设备登记表。
//
// 设备不是探索图里的资产节点，而是「被测环境的外部实体」：它有自己的生命周期
// （接入/离线/被移除），但要被 agent 工具、REST 接口、前端页面共用同一份状态，
// 所以落在 devices 表，由 device.Hub 负责合并实时枚举（ADB/iOS/接入代理）与登记行。

var (
	// ErrDeviceInvalid 表示设备记录不合法。
	ErrDeviceInvalid = errors.New("invalid device")
	// ErrDeviceNotFound 表示设备不存在。
	ErrDeviceNotFound = errors.New("device not found")
)

// DeviceStore 是设备登记表访问器。
type DeviceStore struct{ db *DB }

// Devices 返回设备登记表访问器。
func (d *DB) Devices() *DeviceStore { return &DeviceStore{db: d} }

const deviceCols = `id, platform, state, transport, serial, udid, name, model, product, codename,
	os_version, address, product_id, transport_id, note, tags, extra, last_seen, created_at`

func scanDevice(row interface{ Scan(...any) error }) (device.Device, error) {
	var dv device.Device
	var tags []string
	var extra []byte
	var lastSeen, createdAt time.Time
	if err := row.Scan(&dv.ID, &dv.Platform, &dv.State, &dv.Transport, &dv.Serial, &dv.UDID,
		&dv.Name, &dv.Model, &dv.Product, &dv.Codename, &dv.OSVersion, &dv.Address,
		&dv.ProductID, &dv.TransportID, &dv.Note, &tags, &extra, &lastSeen, &createdAt); err != nil {
		return dv, err
	}
	dv.Tags = tags
	dv.Extra = map[string]any{}
	if len(extra) > 0 {
		_ = json.Unmarshal(extra, &dv.Extra)
	}
	dv.LastSeen = lastSeen
	dv.CreatedAt = createdAt
	return dv, nil
}

// UpsertDevice 登记或更新一台设备（按 id 覆盖登记信息）。
func (s *DeviceStore) UpsertDevice(dv device.Device) error {
	if strings.TrimSpace(dv.ID) == "" {
		return ErrDeviceInvalid
	}
	if dv.Platform != device.PlatformAndroid && dv.Platform != device.PlatformIOS {
		return ErrDeviceInvalid
	}
	if dv.State == "" {
		dv.State = "offline"
	}
	tags := dv.Tags
	if tags == nil {
		tags = []string{}
	}
	extra := dv.Extra
	if extra == nil {
		extra = map[string]any{}
	}
	raw, err := json.Marshal(extra)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO devices (`+deviceCols+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now(),now())
ON CONFLICT (id) DO UPDATE SET
  platform=$2, state=$3, transport=$4, serial=$5, udid=$6, name=$7, model=$8, product=$9,
  codename=$10, os_version=$11, address=$12, product_id=$13, transport_id=$14,
  note=CASE WHEN EXCLUDED.note <> '' THEN EXCLUDED.note ELSE devices.note END,
  tags=$16, extra=$17, last_seen=now(), updated_at=now()`,
		dv.ID, string(dv.Platform), dv.State, dv.Transport, dv.Serial, dv.UDID, dv.Name, dv.Model,
		dv.Product, dv.Codename, dv.OSVersion, dv.Address, dv.ProductID, dv.TransportID,
		dv.Note, tags, raw)
	return err
}

// DeleteDevice 从登记表移除一台设备。
func (s *DeviceStore) DeleteDevice(id string) error {
	_, err := s.db.Exec(`DELETE FROM devices WHERE id=$1`, id)
	return err
}

// ListStoredDevices 返回登记表中全部设备。
func (s *DeviceStore) ListStoredDevices() ([]device.Device, error) {
	rows, err := s.db.Query(`SELECT ` + deviceCols + ` FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []device.Device{}
	for rows.Next() {
		dv, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dv)
	}
	return out, rows.Err()
}

// GetDevice 按 id 取一台登记设备；不存在返回 nil。
func (s *DeviceStore) GetDevice(id string) (*device.Device, error) {
	dv, err := scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &dv, nil
}

// ListDevices 按平台过滤登记设备。
func (s *DeviceStore) ListDevices(platform string) ([]device.Device, error) {
	if strings.TrimSpace(platform) == "" {
		return s.ListStoredDevices()
	}
	rows, err := s.db.Query(`SELECT `+deviceCols+` FROM devices WHERE platform=$1 ORDER BY last_seen DESC`, platform)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []device.Device{}
	for rows.Next() {
		dv, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dv)
	}
	return out, rows.Err()
}

// UpdateDeviceNote 更新设备备注与标签（前端页面用）。
func (s *DeviceStore) UpdateDeviceNote(id, note string, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	res, err := s.db.Exec(`UPDATE devices SET note=$2, tags=$3, updated_at=now() WHERE id=$1`, id, note, tags)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDeviceNotFound
	}
	return nil
}
