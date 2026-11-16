package db

import "time"

const (
	SettingOpsecEnabled     = "opsec_enabled"
	SettingOpsecTorHost     = "opsec_tor_host"
	SettingOpsecTorPort     = "opsec_tor_port"
	SettingOpsecControlPort = "opsec_tor_control_port"
	SettingOpsecControlPass = "opsec_tor_control_password"
	SettingOpsecBypassList  = "opsec_bypass_list"
)

type OpsecLeak struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Worker string    `json:"worker"`
	Tool   string    `json:"tool"`
	Target string    `json:"target"`
	Reason string    `json:"reason"`
}

const opsecLeakKeep = 5000

func (d *DB) InsertOpsecLeak(l OpsecLeak) error {
	if d == nil {
		return nil
	}
	ts := l.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	if _, err := d.Exec(
		`INSERT INTO opsec_leak_log(ts, worker, tool, target, reason) VALUES ($1,$2,$3,$4,$5)`,
		ts, l.Worker, l.Tool, l.Target, l.Reason); err != nil {
		return err
	}
	_, _ = d.Exec(`DELETE FROM opsec_leak_log WHERE id NOT IN (
		SELECT id FROM opsec_leak_log ORDER BY id DESC LIMIT $1)`, opsecLeakKeep)
	return nil
}

func (d *DB) ListOpsecLeaks(limit int) ([]OpsecLeak, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := d.Query(
		`SELECT id, ts, worker, tool, target, reason FROM opsec_leak_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OpsecLeak{}
	for rows.Next() {
		var l OpsecLeak
		if err := rows.Scan(&l.ID, &l.TS, &l.Worker, &l.Tool, &l.Target, &l.Reason); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
