package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestInsertAssetsRejectsOutOfScopeRootDomain guards the boundary from the tool
// side: an agent that finds a new root domain (CDN, redirect target, neighbouring
// site) must not be able to write it into the asset library, because that insert
// creates a root_domain asset AND an auto scope row — i.e. the agent would widen
// the authorization range the operator declared.
func TestInsertAssetsRejectsOutOfScopeRootDomain(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	stamp := time.Now().UnixNano()
	inScope := fmt.Sprintf("guard-in-%d.invalid", stamp)
	outScope := fmt.Sprintf("guard-out-%d.invalid", stamp)
	cs := d.Companies()
	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("insert-guard-%d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = cs.DeleteCompanyWithAssets(companyID, true) })
	if _, _, _, _, err := cs.AddScopeInputsChecked(companyID, []db.ScopeInput{
		{Kind: "domain", Value: inScope},
	}, "test"); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTaskWithOptions("insert guard", "scope is read-only", db.TaskCreateOptions{
		CompanyIDs: []int64{companyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	ts.SetTaskID(task.ID)
	ts.SetAssetStore(d.Assets(), cs)

	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{"type": "root_domain", "domain": inScope},
			map[string]any{"type": "root_domain", "domain": outScope},
			// A subdomain of an out-of-scope root must be rejected too: its insert
			// also creates the out-of-scope root asset and an auto scope row.
			map[string]any{"type": "subdomain", "domain": "api." + outScope, "record_type": "A"},
		},
	})

	errs, _ := out["errors"].([]any)
	if len(errs) < 2 {
		t.Fatalf("out-of-scope root and its subdomain must both be reported: %v", out)
	}
	var outSubRows int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE domain=$1`, "api."+outScope).Scan(&outSubRows); err != nil {
		t.Fatal(err)
	}
	if outSubRows != 0 {
		t.Fatalf("subdomain of an out-of-scope root was written into the asset library")
	}
	var outRows int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='root_domain' AND domain=$1`, outScope).Scan(&outRows); err != nil {
		t.Fatal(err)
	}
	if outRows != 0 {
		t.Fatalf("out-of-scope root %q was written into the asset library", outScope)
	}
	var inRows int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='root_domain' AND domain=$1`, inScope).Scan(&inRows); err != nil {
		t.Fatal(err)
	}
	if inRows != 1 {
		t.Fatalf("declared root %q should have been inserted, rows=%d", inScope, inRows)
	}
}
