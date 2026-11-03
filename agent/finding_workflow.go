package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**漏洞编号约定**：finding_id 是独立漏洞记录 ID；finding_node_id 是探索节点 ID。list_findings / list_task_findings / node_detail / get_task_node_detail 的 id 保留为探索节点 ID，应从同一返回的 finding_id 读取独立编号。get_finding_traffic / bind_finding_traffic 用独立 finding_id。旧 update_finding_report 的 finding_id 参数仍传 finding_node_id。不要把 report_finding 第一行的数字用于证据工具，也不要遇到编号错误后猜测其他数字。"

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// findingQualityGuidance keeps low-value noise out of the findings list. Task goal
// templates already trim it, but an agent can drift from prose it was given once;
// putting the rule in the shared finding-workflow guidance surfaces it to every
// reporter (worker / planner / pentest / auto / mainagent) on every run.
const findingQualityGuidance = "\n\n**漏洞上报门槛（别刷垃圾，也别漏真洞）**\n\n该报的（有证据就报，别因为没直接拿到权限就丢掉）：\n- XSS：反射型 / 存储型 / DOM 都算。只要能给出真实渲染并执行的证据（浏览器截图、控制台输出、DOM 变化）就报，payload 自包含也报；写清触发路径与前提（是否需要交互、有无 HttpOnly / CSP）。\n- 盲 SSRF：有带外回连证据（DNS/HTTP 打到自建监听或 Collaborator 之类），或能证明可达内网 / 云元数据 / 非预期主机，就算没有回显也报；写清带出通道与可继续利用的方向。\n- 无回显盲注：只要有可复现的时间 / 布尔 / 带外侧信道证据就报，不要求看到数据。\n- 组合拳：单看很轻、但确实是链条一环的可以报，必须在 summary/evidence 写清 A 的产出如何让 B 成立、每一步的真实证据、最终影响与定级依据；链条没有真正跑通就不能当组合拳上报。\n\n不报的（一律不写，也不要当「待确认漏洞」堆着）：\n- 版本号 / 指纹泄露、缺失安全响应头、目录列表或 robots.txt 等静态泄露、纯信息提示类。\n- **没有实质影响的未授权访问**：匿名能打开但只返回公开信息、健康检查、空列表、字典/枚举清单，或只泄露你自己的测试数据；既读不到敏感数据，也没有业务写操作或越权效果。\n- **未授权的低价值信息泄露**：内部字段名/表名、组件版本、报错堆栈、公开配置——拿不到凭据/密钥，也拿不到用户或业务数据，且无法作为后续利用的前置。\n- 只能自己把 payload 粘给自己、没有任何用户交互路径的自测 XSS。\n- 参数看着像 URL 但毫无回连或侧信道证据的「疑似 SSRF」；既无回显也无任何侧信道的盲注猜测。\n- 仅凭 CVE / 补丁对比推断的问题；以及只有先拿到同权限凭据才有意义的「问题」。\n\n未授权类怎么判：拿到敏感数据（用户 / 业务 / 凭据密钥），或能产生写操作 / 越权操作 → 该报；只是能打开、内容没有价值 → 不报；能当链条前置（泄露内部路径、内部服务地址、可用凭据 → 后续利用）→ 按组合拳报，并在 evidence 里把链条写全。\n拿不准的写进 TodoWrite 标存疑，不发 finding；定级只保留高危 / 严重，组合拳按最终影响定级。"

// redteamQualityGuidance replaces the general bar for the 攻防 (red-team chain)
// agent: that role is scored on exactly two outcomes, so letting it report XSS /
// SSRF / low-value disclosure would contradict its own prompt.
const redteamQualityGuidance = "\n\n**上报门槛（攻防 agent 严格版：只报 RCE 与三要素泄露）**\n- 只报两类：① RCE（命令/代码执行、反序列化、上传 getshell、模板注入执行，须附真实命令输出或回连证明）；② 泄露【三要素】的信息泄露（身份证号 / 手机号 / 银行卡号，含姓名、住址、账号口令等可直接冒用或登录的组合；必须实际取到数据并给脱敏样本）。\n- 其它漏洞（XSS / SSRF / 无数据的注入 / 未授权的空数据 / 低价值信息泄露…）只作为链路中间步骤记录在 fact 与总结里，**不调用 report_finding**；只有当它们最终导出 RCE 或三要素泄露时，才按最终成果 + 链路一起上报。\n- 拿不准的记 TodoWrite 标存疑，不发 finding；定级：RCE 与三要素泄露按高危/严重报，链路按最终影响定级。"

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	// The quality bar only makes sense for a role that can actually report.
	quality := ""
	for _, tool := range tools {
		if tool.Name() == "report_finding" {
			quality = findingQualityGuidance
			if agentKey == "redteam" {
				quality = redteamQualityGuidance
			}
			break
		}
	}
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, quality
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\n默认由报告 Agent 在编写报告前核对并绑定流量。上报者在 evidence 中保留验证命令、关键输出、已有的真实流量 ID 及其用途，供报告 Agent 对照执行记录核实；无需为绑定额外查包。兼容显式即时绑定：traffic_refs 或 evidence_hint_id 可提交已核实的引用，后者读取本任务指定 hint 的结构化引用；任一无效则本次上报全部失败。TCP/无包不需要这些可选参数。返回 finding_id 与 finding_node_id 分别表示独立记录和探索节点。"
		case "add_hint", "add_task_hint":
			note = "\n交接已确认漏洞时，在对应提示的 traffic_refs 中保留已核实流量的 ID、用途、说明和顺序（单条放顶层，批量放对应 hints 元素），并在 text 中说明它证明的具体漏洞。调用方不能只交接文字而丢弃已有流量引用。未核实的候选不能作为证据传递。"
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**流量证据交接（可选）**：自动绑定默认由报告 Agent 在漏洞入库后、编写报告前完成。上报者应在 evidence 保留验证命令、关键输出、已有真实流量 ID 及其用途，任务中带 intent_id，便于报告 Agent 追溯；不必为了绑定额外查包。Auto / Planner 代为上报时不要丢弃执行者已有的引用。add_hint / add_task_hint 可用 traffic_refs 交接；显式即时绑定仍兼容 report_finding 的 traffic_refs / evidence_hint_id。TCP 或无包时正常登记，不能猜测 ID，也不能仅为补包重复探测。"
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\n平台对话没有任务上下文时，不直接调用 report_finding；通过 add_task_hint 向已有对应任务交接，由任务 Agent 登记，并用 list_task_findings 核对结果。"
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\n判定目标完成前，先完成本次已有证据的上报/交接。不要在证据交接尚未完成时仅因文字漏洞已登记就结束任务、取消 Worker；无包不要求等待或强行抓包。"
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**报告前自动关联流量（已开启）**：你负责为本次触发的漏洞核对并绑定流量，再撰写报告。先从 report_finding 返回 JSON 或 get_task_node_detail / list_task_findings 取得明确的 finding_id 与 finding_node_id。读取漏洞详情、对应意图的执行记录及已有证据清单，优先使用上报者交接的真实 ID。若本次验证为 HTTP 且流量工具可用，用 traffic_search 筛选候选，再用 traffic_get 逐条核实请求/响应确实支持该漏洞；域名和时间只用于筛选，不证明归属。将确认的证据按复现顺序用 bind_finding_traffic(finding_id, traffic_refs) 关联，选择 baseline / proof / verification / supporting 并说明用途。只能操作本次漏洞，不重复创建漏洞或重新探测目标。绑定成功后重新调用 get_finding_traffic 获取最新 version，读取所需正文，再将实际读取的 version 作为 evidence_version 传给 update_finding_report（其 finding_id 参数仍用 finding_node_id）。已有绑定不必重复追加。TCP、未采集、工具不可用或没有确切匹配时，跳过自动绑定，依据文字/命令证据正常写报告并说明原因，不得为凑齐流量而猜测。绑定失败不宣称成功；保留已有证据并在报告说明未绑定原因。"
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, quality + guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "可选：已核实且对应本提示中具体漏洞的流量引用，保留顺序；交接后 report_finding 可传 evidence_hint_id 携带这些引用。", "items": obj(map[string]any{"traffic_id": str("真实流量 ID"), "role": str("baseline / proof / verification / supporting"), "note": str("该流量支持什么结论")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d 必须是本任务的提示节点（继承提示不可直接用于绑定）", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
