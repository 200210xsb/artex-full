package db

import (
	"fmt"
	"testing"
	"time"
)

// TestCreateTaskExpandsCompanyScopeRules pins change A: associating a company
// with a task copies the company's scope RULES onto task_scope. A company's
// kind='company' row only covers assets already attributed to it, and scope rules
// never harvest — so without this expansion a company with rules but 0 assets
// yields a task with no target at all (the production incident).
func TestCreateTaskExpandsCompanyScopeRules(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	stamp := time.Now().UnixNano()
	// One domain is deliberately declared by BOTH companies: the expansion must
	// hit uq_task_scope_v2 and rely on ON CONFLICT DO NOTHING instead of failing.
	sharedDomain := fmt.Sprintf("expand-shared-%d.example.test", stamp)
	soloDomain := fmt.Sprintf("expand-solo-%d.example.test", stamp)

	companyA, _, err := d.Companies().UpsertCompany(fmt.Sprintf("Expand Scope A %d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	companyB, _, err := d.Companies().UpsertCompany(fmt.Sprintf("Expand Scope B %d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM companies WHERE id IN ($1,$2)`, companyA, companyB) })

	addRules := func(companyID int64, inputs []ScopeInput) {
		t.Helper()
		added, _, invalid, errs, err := d.Companies().AddScopeInputsChecked(companyID, inputs, "test")
		if err != nil {
			t.Fatalf("add scope: %v (%v)", err, errs)
		}
		if invalid != 0 || added != len(inputs) {
			t.Fatalf("add scope added=%d invalid=%d errs=%v want added=%d", added, invalid, errs, len(inputs))
		}
	}
	addRules(companyA, []ScopeInput{
		{Kind: "domain", Value: sharedDomain},
		{Kind: "domain", Value: soloDomain},
	})
	addRules(companyB, []ScopeInput{
		{Kind: "domain", Value: sharedDomain},
		{Kind: "ip", Value: "10.20.30.40"},
		{Kind: "cidr", Value: "10.9.0.0/16"},
		{Kind: "icp", Value: "京ICP备12345678号"},
		{Kind: "keyword", Value: "Expand Keyword"},
	})

	task, err := d.CreateTaskWithOptions("expand company scope", "use company rules", TaskCreateOptions{
		CompanyIDs: []int64{companyA, companyB},
	})
	if err != nil {
		t.Fatalf("create task with duplicated scope rules must not fail: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	// Domain rules become root_domain rows, shared one only once (ON CONFLICT).
	type scopeRow struct {
		Kind   string
		Domain string
		Net    string
		Value  string
		Source string
		Reason string
	}
	rows, err := d.Query(`
SELECT kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(value,''), source, COALESCE(reason,'')
FROM task_scope
WHERE task_id=$1 AND kind <> 'company'
ORDER BY kind, domain, net::text`, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []scopeRow
	for rows.Next() {
		var row scopeRow
		if err := rows.Scan(&row.Kind, &row.Domain, &row.Net, &row.Value, &row.Source, &row.Reason); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got = append(got, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Expected expansion: 2 domains (shared deduplicated), 1 ip, 1 cidr, 1 icp.
	// keyword is intentionally NOT expanded (it is attribution context, not a target).
	if len(got) != 5 {
		t.Fatalf("expanded task_scope rows=%d want 5: %+v", len(got), got)
	}
	domains := map[string]int{}
	kinds := map[string]int{}
	for _, row := range got {
		kinds[row.Kind]++
		if row.Source != "manual" {
			t.Errorf("expanded row kind=%s source=%q want manual", row.Kind, row.Source)
		}
		switch row.Kind {
		case "root_domain", "subdomain":
			domains[row.Domain]++
			if row.Net != "" || row.Value != "" {
				t.Errorf("domain row carries net/value: %+v", row)
			}
		case "ip":
			if row.Net != "10.20.30.40/32" {
				t.Errorf("ip row net=%q want 10.20.30.40/32", row.Net)
			}
		case "cidr":
			if row.Net != "10.9.0.0/16" {
				t.Errorf("cidr row net=%q want 10.9.0.0/16", row.Net)
			}
		case "icp":
			if row.Value == "" {
				t.Errorf("icp row has empty value: %+v", row)
			}
		default:
			t.Errorf("unexpected expanded kind %q: %+v", row.Kind, row)
		}
	}
	if domains[sharedDomain] != 1 {
		t.Errorf("shared domain rows=%d want 1 (ON CONFLICT dedupe): %+v", domains[sharedDomain], got)
	}
	if domains[soloDomain] != 1 {
		t.Errorf("solo domain rows=%d want 1: %+v", domains[soloDomain], got)
	}
	if kinds["keyword"] != 0 {
		t.Errorf("keyword rules must not become task targets, got %d rows", kinds["keyword"])
	}
	var keywordRows int
	if err := d.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND kind='keyword'`, task.ID).Scan(&keywordRows); err != nil {
		t.Fatal(err)
	}
	if keywordRows != 0 {
		t.Fatalf("keyword task_scope rows=%d want 0", keywordRows)
	}

	// Every non-keyword company rule has a matching task row. Attribution is not
	// part of the check: two companies declaring the same target collapse into one
	// row (kept under the first company), so matching on company_id would report
	// the second company's rule as missing.
	var missing int
	if err := d.QueryRow(`
SELECT count(*)
FROM company_scope scope
WHERE scope.company_id IN ($1,$2) AND scope.kind IN ('domain','ip','cidr','icp')
  AND NOT EXISTS (
    SELECT 1 FROM task_scope ts
    WHERE ts.task_id=$3 AND ts.source='manual'
      AND ((scope.kind='domain' AND ts.kind='root_domain' AND ts.domain=scope.domain)
        OR (scope.kind='ip' AND ts.kind='ip' AND ts.net=scope.net)
        OR (scope.kind='cidr' AND ts.kind='cidr' AND ts.net=scope.net)
        OR (scope.kind='icp' AND ts.kind='icp' AND ts.value=scope.value))
  )`, companyA, companyB, task.ID).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing != 0 {
		t.Fatalf("%d company scope rules were not expanded onto the task", missing)
	}

	// A second task over the same companies is idempotent (no unique violation)
	// and expands to the same set of rows.
	second, err := d.CreateTaskWithOptions("expand company scope again", "same rules", TaskCreateOptions{
		CompanyIDs: []int64{companyA, companyB},
	})
	if err != nil {
		t.Fatalf("second task with same company rules must not fail: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(second.ID) })
	var secondRows int
	if err := d.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND kind <> 'company'`, second.ID).Scan(&secondRows); err != nil {
		t.Fatal(err)
	}
	if secondRows != len(got) {
		t.Fatalf("second task expanded rows=%d want %d", secondRows, len(got))
	}
}
