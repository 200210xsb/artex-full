package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// registerAssetsResponse mirrors the POST /api/assets/register payload.
type registerAssetsResponse struct {
	Assets []struct {
		ID            int64  `json:"id"`
		Type          string `json:"type"`
		Value         string `json:"value"`
		CompanyID     int64  `json:"company_id"`
		CompanySource string `json:"company_source"`
	} `json:"assets"`
	CompanyScopeAdded   int `json:"company_scope_added"`
	CompanyScopeSkipped int `json:"company_scope_skipped"`
	Invalid             []struct {
		Index int    `json:"index"`
		Kind  string `json:"kind"`
		Value string `json:"value"`
		Error string `json:"error"`
	} `json:"invalid"`
	Skipped []struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Reason string `json:"reason"`
	} `json:"skipped"`
}

func postRegisterAssets(t *testing.T, s *Server, body any) (*httptest.ResponseRecorder, registerAssetsResponse) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/assets/register", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	s.registerAssets(rec, req)
	var out registerAssetsResponse
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
		}
	}
	return rec, out
}

// 不选企业：域名/IP 入资产库，CIDR/ICP/关键词作为企业范围规则被跳过并说明原因。
func TestRegisterAssetsWithoutCompanySkipsScopeRules(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	as := m.pg.Assets()

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("register-%d.invalid", stamp)
	// 用 net.ParseIP 归一化后再比较/清理：IPv6 的文本形式（零压缩）由标准库决定，
	// 手写的期望值可能是等价但不同的写法。
	ip := net.ParseIP(fmt.Sprintf("2001:db8:%x::20", uint64(stamp)&0xffff)).String()
	network := ip + "/128"
	// 自己建的行自己清理，测试库是共用的。
	defer func() {
		_, _ = as.DeleteByHost(domain)
		_, _ = as.DeleteByHost(ip)
	}()

	rec, res := postRegisterAssets(t, s, map[string]any{
		"scope": []map[string]string{
			{"kind": "domain", "value": domain},
			{"kind": "ip", "value": ip},
			{"kind": "cidr", "value": network},
			{"kind": "icp", "value": fmt.Sprintf("京ICP备%d号-1", stamp)},
			{"kind": "keyword", "value": "register keyword"},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(res.Assets) != 2 {
		t.Fatalf("assets=%d want 2: %+v", len(res.Assets), res.Assets)
	}
	if res.Assets[0].Type != "root_domain" || res.Assets[0].Value != domain {
		t.Fatalf("first asset=%+v want root_domain/%s", res.Assets[0], domain)
	}
	if res.Assets[1].Type != "ip" || res.Assets[1].Value != ip {
		t.Fatalf("second asset=%+v want ip/%s", res.Assets[1], ip)
	}
	for _, asset := range res.Assets {
		if asset.CompanyID != 0 || asset.CompanySource != "" {
			t.Fatalf("asset %d should be unowned, got company=%d source=%q", asset.ID, asset.CompanyID, asset.CompanySource)
		}
	}
	if len(res.Skipped) != 3 {
		t.Fatalf("skipped=%d want 3 (cidr/icp/keyword): %+v", len(res.Skipped), res.Skipped)
	}
	for _, item := range res.Skipped {
		if !strings.Contains(item.Reason, "需要先选择企业") {
			t.Fatalf("skipped reason must tell the operator to pick a company: %+v", item)
		}
	}
	if len(res.Invalid) != 0 {
		t.Fatalf("invalid=%+v want none", res.Invalid)
	}
	if res.CompanyScopeAdded != 0 || res.CompanyScopeSkipped != 0 {
		t.Fatalf("no company: scope_added=%d scope_skipped=%d want 0/0", res.CompanyScopeAdded, res.CompanyScopeSkipped)
	}
}

// 选了企业：域名/IP 显式归属（company_source='explicit'），CIDR/ICP 写进企业范围。
func TestRegisterAssetsWithCompanyAttributesExplicitlyAndAddsScope(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	cs := m.pg.Companies()
	as := m.pg.Assets()

	stamp := time.Now().UnixNano()
	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("Register Assets Company %d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.DeleteCompany(companyID) }()

	domain := fmt.Sprintf("register-owned-%d.invalid", stamp)
	ip := net.ParseIP(fmt.Sprintf("2001:db8:%x::30", uint64(stamp)&0xffff)).String()
	// /128 只覆盖这一条地址，避免这条范围规则在共用测试库里顺手认领别的行。
	network := ip + "/128"
	defer func() {
		_, _ = as.DeleteByHost(domain)
		_, _ = as.DeleteByHost(ip)
	}()

	rec, res := postRegisterAssets(t, s, map[string]any{
		"company_id": companyID,
		"scope": []map[string]string{
			{"kind": "domain", "value": domain},
			{"kind": "ip", "value": ip},
			{"kind": "cidr", "value": network},
			{"kind": "icp", "value": fmt.Sprintf("沪ICP备%d号-1", stamp)},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(res.Assets) != 2 {
		t.Fatalf("assets=%d want 2: %+v", len(res.Assets), res.Assets)
	}
	if res.CompanyScopeAdded != 2 || res.CompanyScopeSkipped != 0 {
		t.Fatalf("scope_added=%d scope_skipped=%d want 2/0", res.CompanyScopeAdded, res.CompanyScopeSkipped)
	}
	if len(res.Skipped) != 0 || len(res.Invalid) != 0 {
		t.Fatalf("skipped=%+v invalid=%+v want none", res.Skipped, res.Invalid)
	}

	// 归属是显式的：口径不靠企业已有的范围规则命中。
	for _, asset := range res.Assets {
		if asset.CompanyID != companyID || asset.CompanySource != "explicit" {
			t.Fatalf("asset %d response company=%d source=%q want %d/explicit",
				asset.ID, asset.CompanyID, asset.CompanySource, companyID)
		}
		var gotCompany *int64
		var gotSource string
		if err := m.pg.QueryRow(`SELECT company_id, company_source FROM assets WHERE id=$1`, asset.ID).
			Scan(&gotCompany, &gotSource); err != nil {
			t.Fatal(err)
		}
		if gotCompany == nil || *gotCompany != companyID || gotSource != "explicit" {
			t.Fatalf("asset %d stored company=%v source=%q want %d/explicit", asset.ID, gotCompany, gotSource, companyID)
		}
	}

	scope, err := cs.GetScope(companyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(scope) != 2 {
		t.Fatalf("company scope=%d want 2: %+v", len(scope), scope)
	}
	kinds := map[string]bool{}
	for _, rule := range scope {
		kinds[rule.Kind] = true
	}
	if !kinds["cidr"] || !kinds["icp"] {
		t.Fatalf("company scope kinds=%v want cidr+icp", kinds)
	}
}

// 企业不存在：整体 4xx 拒绝，资产和企业范围都不能留下半成品。
func TestRegisterAssetsRejectsMissingCompanyWithoutWriting(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("register-orphan-%d.invalid", stamp)
	network := net.ParseIP(fmt.Sprintf("2001:db8:%x::40", uint64(stamp)&0xffff)).String() + "/128"

	rec, _ := postRegisterAssets(t, s, map[string]any{
		"company_id": 999999999,
		"scope": []map[string]string{
			{"kind": "domain", "value": domain},
			{"kind": "cidr", "value": network},
		},
	})
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("missing company status=%d body=%s want 4xx", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing company status=%d body=%s want 404", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "企业不存在") {
		t.Fatalf("missing company body=%s want 企业不存在", rec.Body.String())
	}

	var assetCount int
	if err := m.pg.QueryRow(`SELECT count(*) FROM assets WHERE type='root_domain' AND domain=$1`, domain).
		Scan(&assetCount); err != nil {
		t.Fatal(err)
	}
	if assetCount != 0 {
		t.Fatalf("rejected request still wrote %d asset(s) for %s", assetCount, domain)
	}
	var scopeCount int
	if err := m.pg.QueryRow(`SELECT count(*) FROM company_scope WHERE kind='domain' AND domain=$1`, domain).
		Scan(&scopeCount); err != nil {
		t.Fatal(err)
	}
	if scopeCount != 0 {
		t.Fatalf("rejected request still wrote %d company scope rule(s) for %s", scopeCount, domain)
	}
}
