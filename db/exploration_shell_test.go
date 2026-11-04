package db

import "testing"

// 会话库里登记的 WebShell 落在本任务资产上，就算「拿到了」——即便活动记录里没有
// shell_add 调用（页面上手工登记、别的进程调 MCP，都不会写 activity）。
func TestHasLandedShellSession(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("shell-landed", "验证会话归属判定")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)

	var taskID int64
	if err := d.QueryRow(`
INSERT INTO tasks(name, description, goal, exploration_id, status)
VALUES ('t', 'd', 'g', $1, 'created') RETURNING id`, expID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)

	if _, err := d.Exec(`
INSERT INTO assets(type, ip, domain, task_ids) VALUES ('service', '203.0.113.77', 'shell.example.test', ARRAY[$1]::bigint[])`,
		taskID); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE $1 = ANY(task_ids)`, taskID)

	es := d.Exploration(expID)

	ok, err := es.HasLandedShellSession([]string{"203.0.113.77"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("按 IP 命中应判 true")
	}

	ok, err = es.HasLandedShellSession([]string{"shell.example.test"})
	if err != nil || !ok {
		t.Fatalf("按域名命中应判 true: ok=%v err=%v", ok, err)
	}

	ok, err = es.HasLandedShellSession([]string{"198.51.100.9", "not-this-task.example"})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("无关主机不该命中")
	}

	ok, err = es.HasLandedShellSession(nil)
	if err != nil || ok {
		t.Fatalf("空主机列表应判 false: ok=%v err=%v", ok, err)
	}
}
