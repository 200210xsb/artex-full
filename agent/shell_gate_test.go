package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 目标要求 shell 时，证据里必须能看出「已登记」或「如实写明没拿到」；
// 只写「命令回显成功」不算达成。这里只测纯文本判定部分（不碰 DB）。
func TestShellGoalClassification(t *testing.T) {
	shellGoals := []string{
		`{"text":"shell"}`,
		`{"text":"拿权限"}`,
		`{"text":"在目标上获取可用的短期临时Shell（… id/whoami 回显验证 …）"}`,
		`{"text":"getshell 后落马登记"}`,
	}
	for _, g := range shellGoals {
		if !shellGoalRE.MatchString(nodeText(&db.Node{Payload: []byte(g)})) {
			t.Fatalf("goal 应被识别为 shell 目标: %s", g)
		}
	}
	otherGoals := []string{
		`{"text":"对目标站点完成 SQL 注入验证"}`,
		`{"text":"资产覆盖度达到 80%"}`,
	}
	for _, g := range otherGoals {
		if shellGoalRE.MatchString(nodeText(&db.Node{Payload: []byte(g)})) {
			t.Fatalf("goal 不该被识别为 shell 目标: %s", g)
		}
	}

	// 证据：如实写了卡点的，属于合法收口，不拦。
	absence := []string{
		`{"detail":"三条路都不通，未取得 shell：上传点无、FILE 权限无、日志不可写"}`,
		`{"detail":"web 目录不可写，落地失败"}`,
	}
	for _, e := range absence {
		if !shellAbsenceRE.MatchString(nodeText(&db.Node{Payload: []byte(e)})) {
			t.Fatalf("应识别为「未取得 shell」的如实记录: %s", e)
		}
	}
	// 证据：只证明能执行命令的，不算收口。
	fake := `{"detail":"DBGp eval shell_exec(\"id\") 回显 uid=997 gid=997，Shell 已验 id/whoami"}`
	if shellAbsenceRE.MatchString(nodeText(&db.Node{Payload: []byte(fake)})) {
		t.Fatalf("「命令回显」不该被当成「未取得 shell」的收口: %s", fake)
	}

	// 没有 store 时不能 panic，也不能误拦（查不动就不拦）。
	if msg := guardShellGoal(nil, &db.Node{Payload: []byte(`{"text":"shell"}`)}, nil); msg != "" {
		t.Fatalf("无 store 时不应拦截，got %q", msg)
	}
	if msg := guardShellGoal(nil, &db.Node{Payload: []byte(`{"text":"sql"}`)}, nil); msg != "" {
		t.Fatalf("非 shell 目标不应拦截，got %q", msg)
	}

	// 拦截理由必须给出可执行动作，否则模型只会换个说法继续糊。
	for _, want := range []string{"shell_add", "未取得 shell"} {
		if !strings.Contains(shellGateRejectMsg, want) {
			t.Fatalf("拦截理由缺少关键指引 %q: %s", want, shellGateRejectMsg)
		}
	}
}
