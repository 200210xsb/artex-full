package db

import (
	"fmt"
	"testing"
	"time"
)

// TestScopeNormalizationSubdomainNotRejected pins the fix for the production
// incident: an operator pasted 513 URLs into the company scope editor, the
// platform stored each raw host under kind='root_domain', and every asset the
// agent reported under the registrable root was rejected as out of scope.
//
// The fix keeps the granularity the operator declared (kind='subdomain') and
// widens both sides to the same eTLD+1 only where they are compared. The scope
// itself stays READ-ONLY: a root that was never declared is still rejected.
func TestScopeNormalizationSubdomainNotRejected(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	cs := d.Companies()
	assets := d.Assets()
	stamp := time.Now().UnixNano()
	// ".invalid" is a reserved TLD, so the registrable root of
	// "www.guard-<stamp>.invalid" is "guard-<stamp>.invalid".
	subdomain := fmt.Sprintf("www.guard-%d.invalid", stamp)
	root := fmt.Sprintf("guard-%d.invalid", stamp)
	outOfScope := fmt.Sprintf("other-%d.invalid", stamp)

	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("norm-%d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = cs.DeleteCompanyWithAssets(companyID, true) })

	// The operator pasted the SUBDOMAIN — exactly what happens when a URL list
	// is fed into the scope editor.
	if _, _, _, _, err := cs.AddScopeInputsChecked(companyID, []ScopeInput{
		{Kind: "domain", Value: "https://" + subdomain + "/path"},
	}, "test"); err != nil {
		t.Fatal(err)
	}

	// The company rule keeps the exact host: a subdomain must not be promoted to
	// its parent root, which would authorize every sibling host silently.
	var companyKind, companyDomain string
	if err := d.QueryRow(`
SELECT kind, COALESCE(domain,'') FROM company_scope
WHERE company_id=$1 AND kind IN ('domain','subdomain') LIMIT 1`, companyID).Scan(&companyKind, &companyDomain); err != nil {
		t.Fatalf("company scope row missing: %v", err)
	}
	if companyKind != "subdomain" || companyDomain != subdomain {
		t.Fatalf("company scope = (%q,%q), want (subdomain,%q)", companyKind, companyDomain, subdomain)
	}

	task, err := d.CreateTaskWithOptions("scope normalization", "declared via subdomain", TaskCreateOptions{
		CompanyIDs: []int64{companyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	// The task scope copies the rule at the same granularity.
	var scopeKind, scopeDomain string
	if err := d.QueryRow(`
SELECT kind, COALESCE(domain,'') FROM task_scope
WHERE task_id=$1 AND kind IN ('root_domain','subdomain') LIMIT 1`, task.ID).Scan(&scopeKind, &scopeDomain); err != nil {
		t.Fatalf("task scope row missing: %v", err)
	}
	if scopeKind != "subdomain" {
		t.Fatalf("task scope kind = %q, want subdomain", scopeKind)
	}
	if scopeDomain != subdomain {
		t.Fatalf("task scope domain = %q, want the declared host %q", scopeDomain, subdomain)
	}

	// The agent reports the bare root: must be allowed now.
	allowed, err := assets.TaskRootDomainAllowed(task.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatalf("root %q must be allowed: the scope was declared via its subdomain %q", root, subdomain)
	}

	// A subdomain of that root is still allowed.
	subAllowed, err := assets.TaskRootDomainAllowed(task.ID, "deep."+root)
	if err != nil {
		t.Fatal(err)
	}
	if !subAllowed {
		t.Fatalf("subdomain of a declared root must be allowed")
	}

	// A root that was never declared stays rejected — normalization must not
	// widen the authorization boundary.
	outAllowed, err := assets.TaskRootDomainAllowed(task.ID, outOfScope)
	if err != nil {
		t.Fatal(err)
	}
	if outAllowed {
		t.Fatalf("undeclared root %q must NOT be allowed: the declared scope is read-only", outOfScope)
	}
}

// TestParseScopeLineKeepsDeclaredGranularity pins the write-side contract: a
// pasted subdomain stays kind=subdomain with its exact host, a bare root stays
// kind=domain, and Raw keeps the operator's original input for audit.
func TestParseScopeLineKeepsDeclaredGranularity(t *testing.T) {
	cases := []struct {
		in       string
		wantKind string
		wantHost string
		wantRoot string
	}{
		{"www.example.com", "subdomain", "www.example.com", "example.com"},
		{"https://www.example.com/path", "subdomain", "www.example.com", "example.com"},
		{"example.com", "domain", "example.com", "example.com"},
		{"a.b.c.example.co.uk", "subdomain", "a.b.c.example.co.uk", "example.co.uk"},
		{"https://example.co.uk/x", "domain", "example.co.uk", "example.co.uk"},
		// 带端口的取主机地址，端口不进范围。
		{"http://203.0.113.10:8080/x", "ip", "", ""},
		{"203.0.113.10:8080", "ip", "", ""},
	}
	for _, tc := range cases {
		rule, err := ParseScopeLine(tc.in)
		if err != nil {
			t.Fatalf("ParseScopeLine(%q): %v", tc.in, err)
		}
		if rule.Kind != tc.wantKind {
			t.Fatalf("ParseScopeLine(%q).Kind = %q, want %q", tc.in, rule.Kind, tc.wantKind)
		}
		if rule.Raw != tc.in {
			t.Errorf("ParseScopeLine(%q).Raw = %q, want the original input", tc.in, rule.Raw)
		}
		if tc.wantKind == "ip" {
			if rule.Net != "203.0.113.10/32" {
				t.Errorf("ParseScopeLine(%q).Net = %q, want 203.0.113.10/32", tc.in, rule.Net)
			}
			continue
		}
		if rule.Domain != tc.wantHost {
			t.Errorf("ParseScopeLine(%q).Domain = %q, want %q", tc.in, rule.Domain, tc.wantHost)
		}
		if root, _ := RootDomain(rule.Domain); root != tc.wantRoot {
			t.Errorf("RootDomain(ParseScopeLine(%q).Domain) = %q, want %q", tc.in, root, tc.wantRoot)
		}
	}
}
