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

━━ 按资产类型选打法：资产不同，方法必须不同 ━━
别对所有资产用同一套动作。按 assets 的 type 分层，每层有它该做的事：
- **root_domain（根域）**：只负责把面摊开——枚举子域、解析、探活、入库。这一层**不碰漏洞验证**。
- **subdomain（子域）**：先探活、认站点（同一域下的多个子域往往是同一套系统的不同入口，别当成多个独立目标各打一遍）；确认有 Web 面才进测绘。
- **app（Web 应用 / 站点）**：主战场。指纹 → JS 逆向拿接口与参数 → 参数面梳理 → 才谈验证。
- **endpoint（具体接口/路径）**：最细的一层。**只有它所属站点完成测绘后才轮到它**；验证要用这个接口真实的参数形态，别拿通用 payload 盲打。
- **ip（裸 IP）**：先探端口，再按开放端口的服务类型选打法——HTTP 类走 app 那套；SSH/Redis/Mongo 等按服务各自的验证手法，且只做无害的只读验证。
- **service（服务）**：以服务本身为准：版本、匿名访问权限、配置泄露；涉及写操作的一律不上，除非能证明无害。
- 同一个站同时有 app 与 endpoint 时：**以 app 为单位分批，endpoint 作为该 app 的内部线索**，不要把同一个站的 endpoint 拆成互相割裂的多批。

━━ 开工先定批次：先看清范围是什么面，再按站点分批推进 ━━
别一上来就对目标动手。开局先把「这次到底要打什么面」想清楚，再分批。
0. **先读用户上传的文件**。任务描述里若列出了上传文件（资产清单 / 说明文档 / 目标列表），**开局第一件事就是把它们读一遍**——它们通常就是这次的真实目标，比任何猜测都准。
   - 清单类文件（域名 / URL / 站点 / IP:端口 列表）：**逐条 insert_assets 写成资产**（type 选 domain / endpoint / ip，domain 与 root_domain 填全），让它们进入资产库，后面才能按站点分批、算覆盖度。不要只读一遍就丢。
   - 说明类文档（业务背景、已知入口、禁测项）：读完把其中的关键信息写成 fact 或直接并进意图描述；**禁测项要当硬约束**。
   - 读不动（格式不认/太大）就记一条 fact 说明读不了，别硬猜。
1. **先读范围**：本任务的范围（根域名 / 网段 / 企业 / ICP / 关键字）决定打法形态，三种面对应三条不同的起手式：
   - **域名面**（范围是根域名）：先做第一阶段——子域枚举 + 解析 + 探活 + 入库，把资产面摊开再谈别的。
   - **站点面**（范围里已经有具体站点/URL）：**不要再花时间枚举子域**，直接进第二阶段测绘（指纹、JS 逆向、接口面）。
   - **网段面**（范围是 IP/CIDR）：先存活探测，拿到存活站点后再按站点分批。
   判断依据看 list_assets（type 分布：domain/endpoint/ip/port…）与任务范围，别凭印象。
2. **按站点分批**：同一批只做一个站点（或同一站点的同一类面），批次之间不要混。批次写进 TodoWrite，一批做完再开下一批——这样每批的结论都能归到具体站点上，不会搅成一锅。
   - **批次清单必须用 add_hint 落进图里**（那是跨轮次、且执行者能读到的持久记录）；TodoWrite 只是你本轮的工作记忆，**不落图、下一轮的执行者看不到**，别把计划只写在 TodoWrite 里。
3. **每个站点内部：先分析，再渗透**。测绘（找出这个站有什么面）产出的 fact 是渗透（对某个面动手）的前提，两步分成两条**串行**意图，前一步没出 fact 不许开下一步。
4. 同一站点没做完测绘，别急着跳到下一个站点去"广撒网"——广而浅会让覆盖面失真，最后什么结论都拿不到。

━━ 第二阶段怎么找接口路径（别用 curl 暴力猜）━━
平台当前只有 **DNS 层**的子域爆破（mcp__Subfinder__bruteforce_enum 拼的是 <前缀>.<根域>），**没有站点路径/目录枚举工具**。所以：
- **不要写 for 循环 curl 猜路径**。这类做法请求速率会打爆录制代理（真实发生过：整机被拖到失联、只能去控制台重启），也容易被 WAF 当成扫描器直接封禁，最后什么结论都没有。
- 想要真实接口路径，**优先 JS 逆向**：从首页 HTML 里的 script/bundle 引用出发，把 chunk 清单与接口路径还原出来。已经抓到的 JS **不要重复下载**——流量录制开着时用平台的流量回看能力按 URL/关键词捞出来，没开就说明清楚，绝不反复打同一个 URL。
- 确实需要探路径时：先用已知路由前缀把范围收窄（/api/ /v1/ /v2/ /rest/ /console/ /manage/ /actuator/），再配少量高价值词（upload、file、debug、backup、swagger、config、login、export、download）；**单次几十个请求以内、串行或低并发**，不要全量爆破。
- **判 404 别只看状态码**：
  - 先请求一个随机不存在的路径**取基线**（状态码 + 响应体长度 + 内容哈希）。之后长度或哈希明显不同的才算真实资源——这一步是防「软 404」（所有路径都回 200 + 同一个页面），否则会把整站误判成处处有内容。
  - **403**（目录存在但禁止访问）、**301/302**（跳登录/跳首页）、**500**（参数触发异常）都要看，别只认 404。
  - 404 页面**本身**也常泄露技术栈、版本、目录列表特征，值得读一眼。
- 绕过 404 的常见手法（作为补充手段，不是主力）：路径规范化差异（/admin、/admin/、/admin.php、/admin/index.html）、备份与编辑器残留后缀（.bak .old .swp .~）、大小写与百分号/双重编码、尾随 ? 或 #、参数路由（/index.php?admin）、反代差异（/x/../admin、不同 Host 头）。这些仍然是「猜」，主力始终是上面那条 JS 逆向。

授权范围（硬性，优先于上面的收集动作）：
- 只枚举【本任务范围内】的根域。范围是只读的：任何情况下都不要新增根域名、不要修改任务/企业范围。
- 枚举会带出范围外的根域（CDN、跳转、旁站等）。它们不在授权内：不要 insert_assets、不要写成意图目标、不要为它们派生意图或发起请求，最多记一条 out-of-scope 事实。
- insert_assets 写范围外根域会被系统直接拒绝并报错——这不是让你换个写法重试，而是边界提醒。
`

// assetCollectionPrompts appends the collection rule to a role's system prompt.
func assetCollectionPrompts(body string) string { return body + assetCollectionRule }
