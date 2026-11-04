package agent

// shell_gate.go —— prove_goal 的 shell 目标校验。
//
// 攻防类任务的目标文本往往直接写「拿到 shell / 拿权限」。这类目标最容易被
// 「命令能跑」冒充：DBGp eval、模板注入、反序列化只要回一行 uid=… ，模型就
// 倾向于写「Shell 已获取」，但服务器上没有任何可复用的马，WebShell 页面上
// 也没有会话。区别是可查的：真的落马并登记过，活动记录里必然有 shell_add /
// shell_exec 的调用；只验证了能执行，则一条都没有。
//
// 所以这里不是拦「没拿到」，而是拦「没说清」：要么有登记，要么在证据里如实
// 写明未取得 shell 及卡点，二者都不满足就拒绝标记 met。

import (
	"encoding/json"
	"regexp"

	"github.com/Autumn-27/artex/db"
)

var (
	// 目标文本命中这些词，说明这条目标要的是 shell / 权限本身。
	shellGoalRE = regexp.MustCompile(`(?i)shell|webshell|getshell|拿权限|落马|马子`)
	// 证据文本命中这些词，说明已经如实记录了「没拿到」，属于合法收口。
	shellAbsenceRE = regexp.MustCompile(`(?i)未取得\s*shell|未拿到\s*shell|未获得\s*shell|未落地|无法落地|落地失败|写不进去|不具备落地条件|无落地条件|未注册`)
)

// shellGateRejectMsg 是拒绝 prove_goal 的理由。文案本身就是给模型的行动指令，
// 所以单独提出来：测试盯住它别退化成一句没有可执行步骤的「证据不足」。
const shellGateRejectMsg = "目标要求 shell/权限，但本任务的活动记录里没有任何 shell_add / shell_exec 调用——" +
	"命令回显只证明「能执行」，不证明「已落地并登记」。请二选一后再 prove_goal：" +
	"①派意图真正落地马（记录绝对路径）并用 mcp__Webshell__shell_add 登记、shell_exec 复核 id/whoami；" +
	"②在证据里如实写明「未取得 shell」以及三条取 shell 路径各自的卡点。"

// nodeText 把节点 payload 压成一段可匹配的文本（payload 通常是 {"text":…}/{"detail":…}）。
func nodeText(n *db.Node) string {
	if n == nil || len(n.Payload) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(n.Payload, &m); err == nil {
		var b []byte
		for _, k := range []string{"text", "detail", "summary", "title", "name"} {
			if v, ok := m[k].(string); ok && v != "" {
				b = append(b, v...)
				b = append(b, '\n')
			}
		}
		if len(b) > 0 {
			return string(b)
		}
	}
	return string(n.Payload)
}

// guardShellGoal 返回非空字符串表示拒绝本次 prove_goal，字符串就是给模型的理由。
func guardShellGoal(ts *db.ExplorationStore, goal, evidence *db.Node) string {
	if ts == nil || goal == nil {
		return ""
	}
	if !shellGoalRE.MatchString(nodeText(goal)) {
		return ""
	}
	if shellAbsenceRE.MatchString(nodeText(evidence)) {
		return ""
	}
	n, err := ts.WebshellToolUsage()
	if err != nil {
		// 查不动就不拦（宁可放过，不要让一次 DB 抖动把目标判定卡死）。
		return ""
	}
	if n > 0 {
		return ""
	}
	return shellGateRejectMsg
}
