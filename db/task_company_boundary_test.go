package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAgentCannotWidenTaskCompanyBoundary guards the authorization edge that was
// blown open in production: a task associated with company A let the planning
// agent register company B (the only company with assets) into the task's scope,
// so the task silently started testing somebody else's assets.
func TestAgentCannotWidenTaskCompanyBoundary(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	companies := d.Companies()
	stamp := time.Now().UnixNano()
	boundID, _, err := companies.UpsertCompany(fmt.Sprintf("boundary-bound-%d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupCompany(d, boundID) })
	otherID, _, err := companies.UpsertCompany(fmt.Sprintf("boundary-other-%d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupCompany(d, otherID) })

	task, err := d.CreateTaskWithOptions("boundary task", "only the bound company", TaskCreateOptions{
		CompanyIDs: []int64{boundID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	assets := d.Assets()

	// The agent must not pull an unrelated company into the task's scope.
	if _, err := assets.AddAgentScope(task.ID, "company", fmt.Sprintf("%d", otherID), "agent guesses", "agent"); err == nil {
		t.Fatal("agent widening the task to an unrelated company must be rejected")
	} else if !strings.Contains(err.Error(), "授权企业范围已由人限定") {
		t.Fatalf("rejection should name the boundary, got: %v", err)
	}
	// The declared company stays available to the agent.
	if _, err := assets.AddAgentScope(task.ID, "company", fmt.Sprintf("%d", boundID), "same company", "agent"); err != nil {
		t.Fatalf("agent re-registering the declared company: %v", err)
	}
	// The operator may still widen the boundary by hand.
	if _, err := assets.AddAgentScope(task.ID, "company", fmt.Sprintf("%d", otherID), "operator chose it", "manual"); err != nil {
		t.Fatalf("manual widening must stay allowed: %v", err)
	}

	// A task that declares no company (target-driven) keeps the old behavior.
	open, err := d.CreateTaskWithOptions("no company task", "target driven", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(open.ID) })
	if _, err := assets.AddAgentScope(open.ID, "company", fmt.Sprintf("%d", otherID), "target driven", "agent"); err != nil {
		t.Fatalf("task without a company boundary may still bind one: %v", err)
	}
}
