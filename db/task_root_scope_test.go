package db

import (
	"fmt"
	"testing"
	"time"
)

// TestTaskRootDomainAllowedKeepsScopeReadOnly pins the authorization rule that
// asset collection must not widen: once a task declares a scope (its own root
// domains or a human-attached company's domain rules), a newly discovered root
// domain is not allowed, while a subdomain of a declared root is.
func TestTaskRootDomainAllowedKeepsScopeReadOnly(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	cs := d.Companies()
	assets := d.Assets()
	stamp := time.Now().UnixNano()
	inScope := fmt.Sprintf("guard-in-%d.invalid", stamp)
	outScope := fmt.Sprintf("guard-out-%d.invalid", stamp)
	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("guard-%d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = cs.DeleteCompanyWithAssets(companyID, true) })
	if _, _, _, _, err := cs.AddScopeInputsChecked(companyID, []ScopeInput{
		{Kind: "domain", Value: inScope},
	}, "test"); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTaskWithOptions("scope guard", "only the declared domain", TaskCreateOptions{
		CompanyIDs: []int64{companyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	allowed, err := assets.TaskRootDomainAllowed(task.ID, inScope)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatalf("declared root %q must be allowed", inScope)
	}
	subAllowed, err := assets.TaskRootDomainAllowed(task.ID, "sub."+inScope)
	if err != nil {
		t.Fatal(err)
	}
	if !subAllowed {
		t.Fatalf("subdomain of a declared root must be allowed")
	}
	outAllowed, err := assets.TaskRootDomainAllowed(task.ID, outScope)
	if err != nil {
		t.Fatal(err)
	}
	if outAllowed {
		t.Fatalf("new root %q must NOT be allowed: the declared scope is read-only", outScope)
	}

	// A task with no declared scope keeps the legacy target-driven behavior.
	open, err := d.CreateTaskWithOptions("no scope", "target from the description", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(open.ID) })
	openAllowed, err := assets.TaskRootDomainAllowed(open.ID, outScope)
	if err != nil {
		t.Fatal(err)
	}
	if !openAllowed {
		t.Fatalf("a task without a declared scope must stay permissive")
	}
}
