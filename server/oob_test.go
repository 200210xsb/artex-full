package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 直接打 handler，不起完整服务、不碰生产端口。
// 这些 handler 不依赖 Server 的字段，所以空结构体就够。
func TestOOBHandlers(t *testing.T) {
	s := &Server{}

	do := func(name string, fn func(http.ResponseWriter, *http.Request), req *http.Request) (int, map[string]any) {
		rec := httptest.NewRecorder()
		fn(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: body is not JSON: %v (%s)", name, err, rec.Body.String())
		}
		return rec.Code, out
	}
	get := func(p string) *http.Request { return httptest.NewRequest("GET", p, nil) }

	// 1) overview
	code, ov := do("overview", s.oobOverview, get("/api/oob/overview"))
	if code != 200 {
		t.Fatalf("overview status = %d", code)
	}
	t.Logf("overview: available=%v host=%v ports=%v sessions=%v hits=%v",
		ov["available"], ov["public_host"], ov["ports"], ov["sessions"], ov["hits"])
	if ov["available"] != true {
		t.Fatalf("OOB db should be readable here: %v", ov["error"])
	}
	if ov["public_host"] == nil || ov["public_host"] == "" {
		t.Errorf("OOB_PUBLIC_HOST not configured -> generated payloads would be unreachable")
	}

	// 2) sessions
	code, sl := do("sessions", s.oobSessions, get("/api/oob/sessions"))
	if code != 200 {
		t.Fatalf("sessions status = %d", code)
	}
	list, _ := sl["sessions"].([]any)
	t.Logf("sessions: %d", len(list))
	if len(list) == 0 {
		t.Skip("no sessions in db; downstream checks need at least one")
	}
	first, _ := list[0].(map[string]any)
	sid, _ := first["id"].(string)
	lvl, _ := first["level"].(float64)
	hc, _ := first["hit_count"].(float64)
	t.Logf("session %s: level=%.0f (%v) hits=%.0f verdict=%v",
		sid, lvl, first["level_name"], hc, first["verdict"])
	if _, ok := first["verdict"].(string); !ok {
		t.Errorf("session missing verdict")
	}
	for _, k := range []string{"variants", "remote_ips", "uas", "hosts"} {
		if _, ok := first[k].([]any); !ok {
			t.Errorf("session field %s should be an array (got %T)", k, first[k])
		}
	}

	// 3) hits
	code, hl := do("hits", s.oobHits, get("/api/oob/hits?session_id="+sid+"&limit=10"))
	if code != 200 {
		t.Fatalf("hits status = %d", code)
	}
	hits, _ := hl["hits"].([]any)
	t.Logf("hits: %d", len(hits))
	if hc > 0 && len(hits) == 0 {
		t.Errorf("session claims %.0f hits but list is empty", hc)
	}

	// 4) hit detail
	if len(hits) > 0 {
		h0, _ := hits[0].(map[string]any)
		id := fmt.Sprintf("%.0f", h0["id"].(float64))
		req := get("/api/oob/hits/" + id)
		req.SetPathValue("id", id)
		code, det := do("hit detail", s.oobHitDetail, req)
		if code != 200 {
			t.Fatalf("hit detail status = %d", code)
		}
		hv, _ := det["hit"].(map[string]any)
		if hv == nil {
			t.Fatalf("hit detail missing hit object")
		}
		if _, ok := det["headers"].(map[string]any); !ok {
			t.Errorf("hit detail headers should decode to an object")
		}
		if _, ok := det["body"].(string); !ok {
			t.Errorf("hit detail missing body string")
		}
		t.Logf("detail #%s: %v %v remote=%v ua=%v",
			id, hv["method"], hv["path"], hv["remote_ip"], hv["ua"])
	}

	// 5) capability
	code, capm := do("capability", s.oobCapability, get("/api/oob/capability?session_id="+sid))
	if code != 200 {
		t.Fatalf("capability status = %d", code)
	}
	if capm["level"] == nil {
		t.Errorf("capability missing level")
	}
	ev, ok := capm["evidence"].(map[string]any)
	if !ok || len(ev) == 0 {
		t.Errorf("capability missing evidence map")
	}
	limits, _ := capm["limits"].([]any)
	if len(limits) == 0 {
		t.Errorf("capability should state its own limits")
	}
	t.Logf("capability: level=%v name=%v evidence=%d limits=%d",
		capm["level"], capm["level_name"], len(ev), len(limits))

	// 6) payloads
	code, pl := do("payloads", s.oobPayloads, get("/api/oob/payloads?session_id="+sid))
	if code != 200 {
		t.Fatalf("payloads status = %d", code)
	}
	ps, _ := pl["payloads"].([]any)
	t.Logf("payloads: %d", len(ps))
	if len(ps) == 0 {
		t.Logf("payloads warning: %v", pl["warning"])
	}
	for _, p := range ps {
		pm, _ := p.(map[string]any)
		if u, _ := pm["url"].(string); u == "" {
			t.Errorf("payload %v has empty url", pm["name"])
		}
	}

	// 6.1) 每个监听端口都要有 baseline/cap —— 只给第一个端口等于把其余端口白开。
	if want, ok := pl["ports"].([]any); ok && len(want) > 0 {
		seen := map[string]bool{}
		for _, p := range ps {
			pm, _ := p.(map[string]any)
			kind, _ := pm["kind"].(string)
			u, _ := pm["url"].(string)
			for _, w := range want {
				port := fmt.Sprintf(":%v/", w)
				if (kind == "baseline" || kind == "cap") && strings.Contains(u, port) {
					seen[fmt.Sprintf("%s%v", kind, w)] = true
				}
			}
		}
		for _, w := range want {
			for _, kind := range []string{"baseline", "cap"} {
				if !seen[kind+fmt.Sprint(w)] {
					t.Errorf("端口 %v 没有 %s 载荷（多端口监听形同虚设）", w, kind)
				}
			}
		}
		t.Logf("端口覆盖: %d 个端口 × baseline/cap 全部有载荷", len(want))
	} else {
		t.Errorf("payloads 响应缺少 ports 字段")
	}

	// 7) 异常输入
	code, _ = do("capability-no-sid", s.oobCapability, get("/api/oob/capability"))
	if code != 400 {
		t.Errorf("capability without session_id should be 400, got %d", code)
	}

	req := get("/api/oob/hits/abc")
	req.SetPathValue("id", "abc")
	rec := httptest.NewRecorder()
	s.oobHitDetail(rec, req)
	if rec.Code != 400 {
		t.Errorf("non-numeric hit id should be 400, got %d", rec.Code)
	}

	// 8) 不存在的会话：命中/能力接口应给空结果而不是 500
	code, hl = do("hits-unknown", s.oobHits, get("/api/oob/hits?session_id=__nope__"))
	if code != 200 || len(hl["hits"].([]any)) != 0 {
		t.Errorf("unknown session hits should be empty 200, got %d", code)
	}
	code, _ = do("capability-unknown", s.oobCapability, get("/api/oob/capability?session_id=__nope__"))
	if code != 200 {
		t.Errorf("unknown session capability should be 200 with L0, got %d", code)
	}
}
