package db

import (
	"fmt"
	"testing"
	"time"
)

// TestTaskCompanyFallbackAttribution 覆盖「任务关联了企业时，任务期间探测出的新资产
// 也要归属到该企业」的兜底规则（company_source='task'）：
//
//	a) 企业范围只有不相关域名 + 任务关联该企业 → 探到的 IP 记为 task；
//	b) 企业范围补上该 IP 所在 CIDR 后 → 记为 scope（范围优先于任务兜底）；
//	c) 任务没关联企业 → 不归属；
//	d) 任务关联两个企业 → 无法判定归属，不猜，保持未归属；
//	e) 人工指定成 explicit 之后再 Upsert 同一个 IP → 仍是 explicit；
//	f) RecomputeAttribution 只重建 scope 行，task 归属不会被清掉。
//
// 用 203.0.113.0/24 这个文档保留网段，避免和库里真实资产撞车。
func TestTaskCompanyFallbackAttribution(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	as := d.Assets()
	cs := d.Companies()
	stamp := time.Now().UnixNano()

	// 上一轮失败的测试可能留下同名企业和同网段范围规则。两个企业都声明
	// 203.0.113.0/24 时归属会变得不确定，所以先按名字前缀清掉残留。
	if _, err := d.Exec(`DELETE FROM companies WHERE nkey LIKE 'task-company-fallback-%'`); err != nil {
		t.Fatalf("reset stale companies: %v", err)
	}

	newCompany := func(t *testing.T, label string) int64 {
		t.Helper()
		id, _, err := cs.UpsertCompany(fmt.Sprintf("task-company-fallback-%s-%d", label, stamp), "")
		if err != nil {
			t.Fatalf("create company %s: %v", label, err)
		}
		t.Cleanup(func() { cleanupCompany(d, id) })
		return id
	}
	newTask := func(t *testing.T, label string, companyIDs []int64) *Task {
		t.Helper()
		task, err := d.CreateTaskWithOptions(label,
			"task company fallback attribution", TaskCreateOptions{CompanyIDs: companyIDs})
		if err != nil {
			t.Fatalf("create task %s: %v", label, err)
		}
		t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
		return task
	}
	addScope := func(t *testing.T, companyID int64, raw string) {
		t.Helper()
		added, skipped, invalid, errs := cs.AddScope(companyID, []string{raw}, "test")
		if added != 1 || skipped != 0 || invalid != 0 || len(errs) != 0 {
			t.Fatalf("AddScope(%q): added=%d skipped=%d invalid=%d errs=%v",
				raw, added, skipped, invalid, errs)
		}
	}
	// IP 上有唯一索引，Upsert 会更新残留行；统一先清掉，保证断言的是本次插入。
	resetIP := func(t *testing.T, ip string) {
		t.Helper()
		if _, err := d.Exec(`DELETE FROM assets WHERE type = 'ip' AND ip = $1`, ip); err != nil {
			t.Fatalf("reset ip %s: %v", ip, err)
		}
	}
	insertIP := func(t *testing.T, ip string, taskID int64) int64 {
		t.Helper()
		resetIP(t, ip)
		id, err := as.UpsertIP(UpsertIPReq{IP: ip, TaskID: taskID})
		if err != nil {
			t.Fatalf("UpsertIP(%s): %v", ip, err)
		}
		t.Cleanup(func() { deleteAsset(d, id) })
		return id
	}
	assertAttribution := func(t *testing.T, assetID int64, wantCompany *int64, wantSource string) {
		t.Helper()
		var companyID *int64
		var source string
		if err := d.QueryRow(`SELECT company_id, company_source FROM assets WHERE id = $1`,
			assetID).Scan(&companyID, &source); err != nil {
			t.Fatalf("read attribution of asset %d: %v", assetID, err)
		}
		if wantCompany == nil {
			if companyID != nil {
				t.Fatalf("asset %d company_id = %d, want NULL", assetID, *companyID)
			}
			return
		}
		if companyID == nil || *companyID != *wantCompany || source != wantSource {
			got := "NULL"
			if companyID != nil {
				got = fmt.Sprintf("%d", *companyID)
			}
			t.Fatalf("asset %d company=%s source=%q, want %d/%q",
				assetID, got, source, *wantCompany, wantSource)
		}
	}

	t.Run("scope_miss_falls_back_to_the_single_task_company", func(t *testing.T) {
		companyID := newCompany(t, "a")
		// 企业范围里只有一个和该 IP 无关的域名规则。
		addScope(t, companyID, fmt.Sprintf("unrelated-%d.example.test", stamp))
		task := newTask(t, "task-company-fallback-a", []int64{companyID})

		assetID := insertIP(t, "203.0.113.201", task.ID)
		assertAttribution(t, assetID, &companyID, companySourceTask)
	})

	t.Run("scope_hit_wins_over_task_fallback", func(t *testing.T) {
		companyID := newCompany(t, "b")
		addScope(t, companyID, "203.0.113.0/24")
		task := newTask(t, "task-company-fallback-b", []int64{companyID})

		// 该 IP 落在企业范围 CIDR 内：范围命中优先，不写 task。
		assetID := insertIP(t, "203.0.113.10", task.ID)
		assertAttribution(t, assetID, &companyID, companySourceScope)
	})

	t.Run("task_without_company_leaves_the_asset_unowned", func(t *testing.T) {
		task := newTask(t, "task-company-fallback-c", nil)

		assetID := insertIP(t, "203.0.113.202", task.ID)
		assertAttribution(t, assetID, nil, "")
	})

	t.Run("two_companies_are_not_guessed", func(t *testing.T) {
		first := newCompany(t, "d1")
		second := newCompany(t, "d2")
		task := newTask(t, "task-company-fallback-d", []int64{first, second})

		assetID := insertIP(t, "203.0.113.203", task.ID)
		assertAttribution(t, assetID, nil, "")
	})

	t.Run("explicit_is_never_downgraded", func(t *testing.T) {
		companyID := newCompany(t, "e")
		task := newTask(t, "task-company-fallback-e", []int64{companyID})

		// 先按任务兜底归属，再人工改成 explicit，然后用同一个 IP 再 Upsert 一次。
		assetID := insertIP(t, "203.0.113.204", task.ID)
		assertAttribution(t, assetID, &companyID, companySourceTask)
		if _, err := as.SetAssetsCompany([]int64{assetID}, &companyID); err != nil {
			t.Fatalf("SetAssetsCompany: %v", err)
		}
		assertAttribution(t, assetID, &companyID, companySourceExplicit)

		if _, err := as.UpsertIP(UpsertIPReq{IP: "203.0.113.204", TaskID: task.ID}); err != nil {
			t.Fatalf("re-UpsertIP after explicit: %v", err)
		}
		assertAttribution(t, assetID, &companyID, companySourceExplicit)
	})

	t.Run("recompute_attribution_keeps_task_owned_rows", func(t *testing.T) {
		companyID := newCompany(t, "f")
		addScope(t, companyID, fmt.Sprintf("unrelated-%d.example.test", stamp))
		task := newTask(t, "task-company-fallback-f", []int64{companyID})

		assetID := insertIP(t, "203.0.113.205", task.ID)
		assertAttribution(t, assetID, &companyID, companySourceTask)

		// RecomputeAttribution 只清 scope 行并重建范围归属；task 不是范围推导的，
		// 必须保持原样，否则范围重算一跑就丢了任务期间的归属。
		if err := cs.RecomputeAttribution(); err != nil {
			t.Fatalf("RecomputeAttribution: %v", err)
		}
		assertAttribution(t, assetID, &companyID, companySourceTask)
	})
}
