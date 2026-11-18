package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestGraphOverviewExposesAssociatedCompanies pins the situational snapshot the
// planner wakes up with: the companies a human attached to the task must be
// visible there (name, asset_count, scope rules), even when they own no assets
// yet. Without it the planner only saw "范围未锚定" and went hunting for a
// company that does have assets — adopting an unrelated company into the task.
func TestGraphOverviewExposesAssociatedCompanies(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	companies := d.Companies()
	stamp := time.Now().UnixNano()
	name := fmt.Sprintf("overview-company-%d", stamp)
	companyID, _, err := companies.UpsertCompany(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = companies.DeleteCompany(companyID) })

	domain := fmt.Sprintf("overview-%d.example", stamp)
	// IP 资产在全库唯一（uq_av2_ip），写死一个地址会让第二次跑撞上上一轮留下的行，
	// asset_count 就只剩 1。用 TEST-NET-3 里按时间戳取的地址，每次都是新的。
	ip := fmt.Sprintf("203.0.113.%d", stamp%254+1)
	if added, skipped, invalid, errs := companies.AddScopeInputs(companyID, []db.ScopeInput{
		{Kind: "domain", Value: domain},
		{Kind: "ip", Value: ip},
	}, "overview test"); added != 2 || skipped != 0 || invalid != 0 || len(errs) != 0 {
		t.Fatalf("seed company scope: added=%d skipped=%d invalid=%d errors=%v", added, skipped, invalid, errs)
	}

	task, err := d.CreateTaskWithOptions("overview task", "no assets yet", db.TaskCreateOptions{
		CompanyIDs: []int64{companyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	// 资产是全局的，公司删掉后行还在；不显式清掉就会污染后面几轮的统计。
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM assets WHERE company_id = $1 OR domain = $2 OR ip = $3`, companyID, domain, ip); err != nil {
			t.Logf("cleanup assets: %v", err)
		}
	})

	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(d.Assets(), companies)

	overview := tools.graphOverviewData()
	if overview["task_companies_note"] == nil || !strings.Contains(fmt.Sprint(overview["task_companies_note"]), "不得") {
		t.Fatalf("boundary note missing from overview: %#v", overview["task_companies_note"])
	}
	raw, err := json.Marshal(overview["task_companies"])
	if err != nil {
		t.Fatal(err)
	}
	var listed []map[string]any
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("task_companies=%s, want exactly the one associated company", raw)
	}
	entry := listed[0]
	if fmt.Sprint(entry["name"]) != name {
		t.Errorf("company name = %v, want %q", entry["name"], name)
	}
	// 声明的域名/IP 规则在保存时就会落成资产，所以这里的 asset_count 是 2（一条
	// domain + 一条 ip），不再是"规则存在但零资产"。规划者拿到的数字因此可信。
	if got := fmt.Sprint(entry["asset_count"]); got != "2" {
		t.Errorf("asset_count = %v, want 2 (declared domain + ip materialized as assets)", got)
	}
	scope := fmt.Sprint(entry["scope"])
	for _, want := range []string{"domain:" + domain, "ip:" + ip + "/32"} {
		if !strings.Contains(scope, want) {
			t.Errorf("scope %q missing %q", scope, want)
		}
	}
}
