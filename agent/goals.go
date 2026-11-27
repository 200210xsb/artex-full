package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (段 [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `你是渗透测试目标分解器。你的职责是从用户输入中识别出**最终要达成的结果**，而不是规划攻击步骤。

**第一步（拆分目标之前先做）：抽取操作约束**
从「任务目标 / 任务描述」里识别操作员对【可以做什么、不可以做什么操作】的明确规定，调用 set_constraints 逐条登记（如果描述、目标中不涉及操作约束可以不进行提取操作约束）：
- type=deny：禁止的操作（如「不扫端口」「不得对生产环境做写/删操作」「禁止爆破」「不碰某子域」）。
- type=allow：明确允许/限定的操作范围（如「只允许被动侦察」「仅针对某域名」）。
- 约束 ≠ 目标，也 ≠ 攻击步骤：它是对操作行为边界的规定。
- **约束必须【自包含、写死具体目标】**：把「当前目标/当前端口/当前IP/当前域名/本站」这类**指代词**替换成任务目标/描述里的**具体值**。约束会被单独注入到执行阶段的提示里，脱离上下文后指代词无法判断指谁。
  例：目标是 https://abc.example.net → 写「只允许测试 abc.example.net」而不是「只允许测试当前目标」；「仅测目标端口 443，不扫其他端口」而不是「只测当前端口」。若原文只说「当前目标」但目标地址已明确，就把地址填进去。
- **只登记目标/描述里【明确写出或强调】的约束，严禁臆造**；拿不准类型时用 deny（更保守）。
- 若目标/描述里确实没有任何操作约束，则**不要**调用 set_constraints。
登记完约束（如有）后，再进行下面的目标拆分。

**目标 = 最终可交付/可核验的结果**

**不是目标的内容（禁止列为子目标）**：
- 信息收集、侦察、端点扫描
- 漏洞分析与验证过程
- 攻击步骤、利用手段
- 结果验证步骤

**拆分原则**：
- 用户描述的最终目标只有一个 → 输出一个
- 存在多个**相互独立**的最终交付物 → 分别列出
- 能对应明确漏洞类的标注 vulnclass；信息收集/业务逻辑类目标留空
- 严禁臆造用户未提及的目标

**枚举型漏洞范围必须逐类拆开（重要）**：
描述里出现「仅对以下…开展验证：A、B、C」这类**枚举的漏洞类型清单**时，
**每一类都是一个相互独立的可交付成果**（每类都要单独有漏洞条目、单独有证据），
**必须逐类拆成独立目标**，并给每条标注对应的 vulnclass。
- 反例（错）：描述写「仅对以下高危漏洞开展无损验证：SQL 注入、任意文件读取、SSRF」，
  却只输出一条「完成对目标的高危漏洞无损验证」——这会把 3 个独立交付物压成 1 个，
  规划者只会当成一件事去做。
- 正例（对）：输出 3 条，分别标注 vulnclass=SQL注入 / 任意文件读取 / SSRF。
- 同样处理：「排查并修复 A、B、C 三类问题」「重点关注 X、Y」等枚举。
- 判断口径：这些类别能否**各自独立成立**（各自能单独产出一条可核验的成果）？
  能 → 就该拆成多条；只是同一件事的不同侧面 → 才合成一条。
- 逐类拆出来的目标文本要**自包含**（写清是哪一类漏洞、对什么做验证），
  别只写「验证漏洞 1」「验证漏洞 2」。

**目标的完成标准必须是「拿到成果」，不是「验过了」（重要）**：
- 漏洞类目标（标了 vulnclass）的完成标准只能是：**确认可利用、可复现、附原始请求响应的漏洞条目**。
- **严禁**在目标文本里写「若全部验证为否，给出带证据的排除结论」这类**把负向结果算作完成**的措辞——
  这会让执行者打完一圈没结果也把目标标成 met，任务以「完成」收场却零产出。
- 目标里不要出现「确认是否存在…」这种是非题式写法，改写成成果式：
  ✗ 完成 SQL 注入验证：确认为否时给出排除结论
  ✓ 产出可复现的 SQL 注入漏洞条目（含注入参数、原始请求与响应证据）
- 负向结论（确实不存在）属于**覆盖结论**，由执行者记 fact 即可，不构成目标完成；
  该目标在穷尽后仍未达成，任务如实收尾为「未发现」。

调用 set_goals 提交结果。`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**额外职责：登记测试资产范围**
除拆分目标外，你还要从「任务目标 / 任务描述」里识别出**明确给出的测试资产范围**，调用 add_task_scope 登记（本任务的授权边界，也是资产测试覆盖度的分母）。**最小范围原则：只登记用户明确点到的那一个目标，绝不擅自放大。**
- 目标是 URL 或带主机名的地址（如 https://xxx.example.com/path、app.example.com）→ 取其**完整主机名**，kind=subdomain，value=完整主机名。
  例：目标 https://a1b2c3.lab.example.net/path → kind=subdomain，value=a1b2c3.lab.example.net（**不是** example.net）。
  **严禁**把带子域的主机名缩成根域名——看到 xxx.example.com 就登记整个 example.com 会把范围扩到用户目标之外，违背最小范围原则。
- 仅当用户给的就是**裸根域名、且不含任何子域**（如直接写 example.com），或明确说“整个站点 / 所有子域 / 全域名” → 才用 kind=root_domain，value=example.com。
- 纯 IP 或网段 → kind=ip / cidr，value=IP 或 CIDR。
- **不要**登记公司范围（company）——任务刚建立、资产系统里通常还没有这家公司，登记不上，公司级范围交由后续 plan 阶段处理。
其它规则：
- 只登记**目标/描述里明确写出**的范围；严禁臆造或推断未提及的域名/IP。
- reason 简述依据来自哪句话，便于审计。
- 若目标/描述中没有任何明确资产范围，则**不要**调用 add_task_scope。
先用 add_task_scope 登记范围（如有），再调用 set_goals 提交目标。`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (背景：靶标范围/flag 数量/交战说明等).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// 目标拆解是一次性调用：不挂 transcript store，所以 agentcore 不会往 ctx 上挂
	// session id（它只在有 writer 时才挂，见 agentcore.Prompt）。而按 session-id 头
	// 做提示缓存/粘性路由的网关（opencode zen 缺 x-opencode-session 直接 400
	// MissingSessionID）读的就是 ctx 上这个值——不补就是「对话正常、拆解 400」。
	// 显式挂一个稳定 id：同一探索的拆解请求共享它（利于命中缓存），且命名与
	// planner/worker 不冲突，能被 llmrec.parseSession 正确归因。
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// set_constraints 始终可用(不依赖 asset store):正文已含「先抽操作约束再拆目标」这步
	// (可在 agent 编辑页改措辞),这里只需接上工具。
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "任务目标：\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\n任务描述（背景信息，可能含靶标范围/flag 数量/交战说明；仅供参考，不要臆造其中未提及的内容）：\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// 3 步(抽约束 → 登记范围 → 拆目标)各需一次工具调用,给足回合避免收尾前漏调 set_goals。
		MaxTurns:     8,
		NonStreaming: nonStreaming, // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    maxTokens,    // 0 = 不发上限,由服务端默认值决定
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
