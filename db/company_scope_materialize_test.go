package db

import (
	"fmt"
	"testing"
	"time"
)

// TestCompanyScopeMaterializesDeclaredAssets pins the fix for the "9 rules, 0
// assets" confusion: a domain/IP rule a human declares IS a target they declared,
// so saving it must put a real asset row in the library (and attribute it), not
// just leave a claim condition waiting for somebody else to collect it.
func TestCompanyScopeMaterializesDeclaredAssets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	cs := d.Companies()
	stamp := time.Now().UnixNano()
	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("materialize-%d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = cs.DeleteCompanyWithAssets(companyID, true) })

	domain := fmt.Sprintf("materialize-%d.invalid", stamp)
	if _, _, _, err := cs.UpdateScopeInputsChecked(companyID, []ScopeInput{
		{Kind: "domain", Value: domain},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	assertOwnedRootDomain := func(wantSource string) {
		t.Helper()
		var id, company int64
		var source string
		if err := d.QueryRow(`
SELECT id, COALESCE(company_id,0), company_source FROM assets
WHERE type='root_domain' AND domain=$1`, domain).Scan(&id, &company, &source); err != nil {
			t.Fatalf("declared domain asset missing: %v", err)
		}
		if company != companyID || source != wantSource {
			t.Fatalf("declared domain asset company=%d source=%q, want %d/%q", company, source, companyID, wantSource)
		}
	}
	assertOwnedRootDomain("scope")
	if count, err := cs.AssetCount(companyID); err != nil || count != 1 {
		t.Fatalf("company asset count=%d err=%v, want 1", count, err)
	}

	// A CIDR rule is a matching condition, not an enumerable target: it must NOT
	// invent an asset row (that would mean fabricating hosts inside the range).
	cidr := "203.0.113.128/28"
	if _, _, _, _, err := cs.AddScopeInputsChecked(companyID, []ScopeInput{
		{Kind: "cidr", Value: cidr},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	var assetRows int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='root_domain' AND domain=$1`, cidr).Scan(&assetRows); err != nil {
		t.Fatal(err)
	}
	if assetRows != 0 {
		t.Fatalf("CIDR rule created %d asset rows; it must stay a matching rule", assetRows)
	}

	// An explicit single IP rule is a concrete target and materializes as an ip asset.
	ip := fmt.Sprintf("203.0.113.%d", (stamp%50)+1)
	if _, _, _, _, err := cs.AddScopeInputsChecked(companyID, []ScopeInput{
		{Kind: "ip", Value: ip},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	var ipCompany int64
	var ipSource string
	if err := d.QueryRow(`
SELECT COALESCE(company_id,0), company_source FROM assets WHERE type='ip' AND ip=$1`, ip).
		Scan(&ipCompany, &ipSource); err != nil {
		t.Fatalf("declared single-IP asset missing: %v", err)
	}
	if ipCompany != companyID || ipSource != "scope" {
		t.Fatalf("declared IP asset company=%d source=%q, want %d/scope", ipCompany, ipSource, companyID)
	}

	// "重新认领" must also backfill rules that existed before materialization was
	// introduced: drop the asset rows, run MaterializeScopeAssets, expect them back.
	if _, err := d.Exec(`DELETE FROM assets WHERE (type='root_domain' AND domain=$1) OR (type='ip' AND ip=$2)`,
		domain, ip); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.MaterializeScopeAssets(); err != nil {
		t.Fatal(err)
	}
	assertOwnedRootDomain("scope")
	var backfilledIP int64
	if err := d.QueryRow(`SELECT COALESCE(company_id,0) FROM assets WHERE type='ip' AND ip=$1`, ip).Scan(&backfilledIP); err != nil {
		t.Fatalf("backfilled IP asset missing: %v", err)
	}
	if backfilledIP != companyID {
		t.Fatalf("backfilled IP asset company=%d, want %d", backfilledIP, companyID)
	}
}
