package server

import "testing"

// TestAutoVerifyNeedsExplicitConfirm 锁住自动验证的确认门：自动验证会用别人泄漏的
// 凭据向厂商发只读请求，所以必须显式 confirm=true —— 与 /api/llmhunt/keys/verify
// 是同一道门。之前只有手动验证接口有这道门，扫描接口能绕过去。
func TestAutoVerifyNeedsExplicitConfirm(t *testing.T) {
	if err := checkAutoVerifyConfirm(true, false); err == nil {
		t.Fatal("auto_verify without confirm must be rejected")
	}
	if err := checkAutoVerifyConfirm(true, true); err != nil {
		t.Fatalf("auto_verify with confirm must be allowed: %v", err)
	}
	// 不开自动验证时不需要确认（普通扫描不该被这道门拦住）。
	if err := checkAutoVerifyConfirm(false, false); err != nil {
		t.Fatalf("plain scan must not need confirm: %v", err)
	}
}
