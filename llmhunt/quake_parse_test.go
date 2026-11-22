package llmhunt

import (
	"encoding/json"
	"testing"
)

// TestParseQuakeHostsToleratesErrorShape 锁住 Quake 响应的两种形态。
//
// 失败时 Quake 返回 {"code":"q2001","message":"…","data":{}} —— data 是**空对象**
// 而不是数组。旧代码把 data 声明成数组，整个响应解析失败，错误又被吞成
// "没有结果"：持续狩猎因此空转了几百轮，却没人发现测绘账户的配额早就用完了。
func TestParseQuakeHostsToleratesErrorShape(t *testing.T) {
	// 成功形态：数组
	ok, err := parseQuakeHosts(json.RawMessage(`[{"ip":"1.2.3.4","port":80},{"ip":"5.6.7.8","port":"8080"}]`))
	if err != nil {
		t.Fatalf("array shape must parse: %v", err)
	}
	if len(ok) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(ok))
	}
	if ok[0].host != "1.2.3.4" || ok[0].port != 80 {
		t.Fatalf("unexpected host: %+v", ok[0])
	}
	// 端口写成字符串也要认（Quake 两种都出现过）。
	if ok[1].port != 8080 {
		t.Fatalf("string port not parsed: %+v", ok[1])
	}

	// 失败形态：空对象 —— 视为没有结果，而不是解析错误
	none, err := parseQuakeHosts(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("object shape must not error: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 hosts, got %d", len(none))
	}
}
