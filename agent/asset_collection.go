package agent

// assetCollectionRule is code-owned (never DB-editable) so it applies to every
// deployment regardless of what an operator's prompt rows say.
//
// Why it exists: the Subfinder MCP tools were visible but unused. They are deferred
// tools — the model only sees their names and must fetch the schema through
// SearchExtraTools before ExecuteExtraTool — and the general prompt tells it to
// prefer core tools (bash/curl). In production that meant a task whose scope named
// several root domains went straight to curl-based probing and never enumerated a
// single subdomain, so the asset library stayed empty and coverage was meaningless.
//
// The scope half of the rule is equally load-bearing: enumeration surfaces
// third-party root domains (CDNs, redirect targets, neighbouring sites). They are
// out of scope, and insert_assets would otherwise create a root_domain asset plus
// an auto scope row, silently widening the authorization boundary the operator set.
const assetCollectionRule = `

━━ 资产收集（先扩资产 → 再测绘 → 再打洞；授权范围只读）━━
本任务范围里如果有【根域名】，正确的推进顺序是：第一阶段把资产面摊开（子域枚举 + 解析 + 探活 + 入库）→ 第二阶段对具体资产做专项测绘（JS 逆向找接口/参数/签名、目录与接口枚举、指纹）→ 第三阶段才对具体入口做漏洞验证。只测几个手选入口会让覆盖面失真，后面的覆盖度/结论都不可信。第一阶段的固定三步，不要跳过第一步：
1. 取 schema：SearchExtraTools {"query":"select:mcp__Subfinder__subfinder_enum"}
2. 调用：ExecuteExtraTool 执行 mcp__Subfinder__subfinder_enum（domain=范围内的根域，其余参数按 schema）
3. 入库：把解析到的每个子域用 insert_assets 写成资产，type=subdomain、domain=完整子域（如 www.example.com）。归属由企业范围/任务自动判定，不需要你指定。
   需要复核解析、或补端口/标题/状态码时，用 mcp__Subfinder__dns_resolve、mcp__Subfinder__http_probe；需要主动字典爆破时用 mcp__Subfinder__bruteforce_enum。

授权范围（硬性，优先于上面的收集动作）：
- 只枚举【本任务范围内】的根域。范围是只读的：任何情况下都不要新增根域名、不要修改任务/企业范围。
- 枚举会带出范围外的根域（CDN、跳转、旁站等）。它们不在授权内：不要 insert_assets、不要写成意图目标、不要为它们派生意图或发起请求，最多记一条 out-of-scope 事实。
- insert_assets 写范围外根域会被系统直接拒绝并报错——这不是让你换个写法重试，而是边界提醒。
`

// assetCollectionPrompts appends the collection rule to a role's system prompt.
func assetCollectionPrompts(body string) string { return body + assetCollectionRule }
