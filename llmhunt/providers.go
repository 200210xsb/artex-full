package llmhunt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 复用 Subfinder 的 provider 配置：FOFA / Quake / Shodan 这类空间测绘引擎才是
// "找暴露实例"的正路（Bing 只能捞到教程页）。配置文件里填了 key 就自动启用，
// 没填就跳过，不报错。
//
// 配置位置与 Subfinder 一致：ARTEX_SUBFINDER_PC 指定的路径，否则 ~/.config/subfinder/provider-config.yaml。
// 支持的写法（Subfinder 原生格式）：
//   fofa: [email:key]
//   quake: [key]
//   shodan: [key]

// providerKeys 是解析出来的可用 key。
type providerKeys struct {
	FOFAEmail string
	FOFAKey   string
	Quake     string
	Shodan    string
	Hunter    string
}

func providerConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_SUBFINDER_PC")); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	return home + "/.config/subfinder/provider-config.yaml"
}

var yamlListLine = regexp.MustCompile(`^-\s*(.+)$`)

// loadProviderKeys 读取 Subfinder 的 provider-config.yaml（只认三行）。
func loadProviderKeys() providerKeys {
	var k providerKeys
	b, err := os.ReadFile(providerConfigPath())
	if err != nil {
		return k
	}
	var cur string
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !strings.HasPrefix(t, "-") && strings.HasSuffix(t, ":") {
			cur = strings.TrimSuffix(t, ":")
			continue
		}
		// 也支持 fofa: [email:key] 的单行写法
		if i := strings.Index(t, ":"); i > 0 && !strings.HasPrefix(t, "-") {
			head := strings.TrimSpace(t[:i])
			if head == "fofa" || head == "quake" || head == "shodan" || head == "hunter" {
				rest := strings.TrimSpace(t[i+1:])
				if v, ok := firstListValue(rest); ok {
					assign(&k, head, v)
				}
				cur = ""
				continue
			}
		}
		if m := yamlListLine.FindStringSubmatch(t); m != nil && cur != "" {
			v := strings.Trim(strings.TrimSpace(m[1]), `"'`)
			if v != "" && v != "[]" {
				assign(&k, cur, v)
			}
		}
	}
	return k
}

func firstListValue(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}
	v := strings.Trim(strings.TrimSpace(strings.Split(s, ",")[0]), `"'`)
	if v == "" || v == "[]" {
		return "", false
	}
	return v, true
}

func assign(k *providerKeys, provider, v string) {
	switch provider {
	case "fofa":
		if strings.Contains(v, ":") {
			parts := strings.SplitN(v, ":", 2)
			k.FOFAEmail, k.FOFAKey = parts[0], parts[1]
		} else {
			k.FOFAKey = v
		}
	case "quake":
		k.Quake = v
	case "shodan":
		k.Shodan = v
	case "hunter":
		k.Hunter = v
	}
}

// HasSpatialProvider 报告是否配置了任一空间测绘 key。
func (k providerKeys) HasSpatialProvider() bool {
	return k.FOFAKey != "" || k.Quake != "" || k.Shodan != "" || k.Hunter != ""
}

// vendorQueries 是"组件 → 各引擎的查询语句"。
type vendorQuery struct {
	vendor string
	fofa   string
	quake  string
	shodan string
	hunter string
}

var spatialQueries = []vendorQuery{
	{vendor: "ollama", fofa: `app="Ollama"`, quake: `app:"Ollama"`, shodan: `product:Ollama`, hunter: `web.body="Ollama is running"`},
	{vendor: "open-webui", fofa: `app="Open WebUI"`, quake: `app:"Open WebUI"`, shodan: `http.title:"Open WebUI"`, hunter: `web.title="Open WebUI"`},
	{vendor: "comfyui", fofa: `app="ComfyUI"`, quake: `app:"ComfyUI"`, shodan: `http.title:"ComfyUI"`, hunter: `web.title="ComfyUI"`},
	{vendor: "dify", fofa: `app="Dify"`, quake: `app:"Dify"`, shodan: `http.title:"Dify"`, hunter: `web.title="Dify"`},
	{vendor: "langflow", fofa: `app="Langflow"`, quake: `app:"Langflow"`, shodan: `http.title:"Langflow"`, hunter: `web.title="Langflow"`},
	{vendor: "flowise", fofa: `app="Flowise"`, quake: `app:"Flowise"`, shodan: `http.title:"Flowise"`, hunter: `web.title="Flowise"`},
	// 模型服务/网关：真正跑 DeepSeek / GLM / Qwen 的地方。
	{vendor: "openai-compatible", fofa: `body="/v1/models"`, quake: `app:"vLLM"`, shodan: `product:vLLM`, hunter: `web.body="vLLM"`},
	{vendor: "openai-compatible", fofa: `app="SGLang"`, quake: `app:"SGLang"`, shodan: `product:SGLang`, hunter: `web.body="SGLang"`},
	{vendor: "openai-compatible", fofa: `app="LMDeploy"`, quake: `app:"LMDeploy"`, shodan: `product:LMDeploy`, hunter: `web.body="LMDeploy"`},
	{vendor: "openai-compatible", fofa: `app="Xinference"`, quake: `app:"Xinference"`, shodan: `http.title:"Xinference"`, hunter: `web.title="Xinference"`},
	{vendor: "librechat", fofa: `app="LibreChat"`, quake: `app:"LibreChat"`, shodan: `http.title:"LibreChat"`, hunter: `web.title="LibreChat"`},
	{vendor: "lobechat", fofa: `app="LobeChat"`, quake: `app:"LobeChat"`, shodan: `http.title:"LobeChat"`, hunter: `web.title="LobeChat"`},
	{vendor: "fastgpt", fofa: `app="FastGPT"`, quake: `app:"FastGPT"`, shodan: `http.title:"FastGPT"`, hunter: `web.title="FastGPT"`},
	{vendor: "ragflow", fofa: `app="RAGFlow"`, quake: `app:"RAGFlow"`, shodan: `http.title:"RAGFlow"`, hunter: `web.title="RAGFlow"`},
}

// SpatialTargets 用空间测绘引擎找候选（每个组件一条查询，限量）。
func SpatialTargets(ctx context.Context, perVendor int) ([]Target, error) {
	k := loadProviderKeys()
	if !k.HasSpatialProvider() {
		return nil, nil
	}
	if perVendor <= 0 || perVendor > 50 {
		perVendor = 10
	}
	var out []Target
	var lastErr error
	seen := map[string]bool{}
	for _, q := range spatialQueries {
		var hosts []hostPort
		if k.FOFAKey != "" && q.fofa != "" {
			got, ferr := fofaSearch(ctx, k, q.fofa, perVendor)
			if ferr != nil {
				lastErr = ferr
			}
			hosts = append(hosts, got...)
		}
		if k.Quake != "" && q.quake != "" && len(hosts) < perVendor {
			got, qerr := quakeSearch(ctx, k.Quake, q.quake, perVendor)
			if qerr != nil {
				lastErr = qerr
			}
			hosts = append(hosts, got...)
		}
		if k.Shodan != "" && q.shodan != "" && len(hosts) < perVendor {
			hosts = append(hosts, shodanSearch(ctx, k.Shodan, q.shodan, perVendor)...)
		}
		if k.Hunter != "" && q.hunter != "" && len(hosts) < perVendor {
			got, herr := hunterSearch(ctx, k.Hunter, q.hunter, perVendor)
			if herr != nil {
				lastErr = herr
			}
			hosts = append(hosts, got...)
		}
		for _, h := range hosts {
			key := fmt.Sprintf("%s:%d", h.host, h.port)
			if h.host == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Target{Host: h.host, Port: h.port, Source: "spatial", Vendor: q.vendor})
			if len(hosts) >= perVendor {
				break
			}
		}
	}
	return out, lastErr
}

type hostPort struct {
	host string
	port int
}

// fofaSearch 调 FOFA 的 search/all。错误要报出来：FOFA 需要 email+key 成对，
// 只配了 key 时每个查询都会失败——静默吞掉的话，界面看起来就是"没找到"。
func fofaSearch(ctx context.Context, k providerKeys, query string, size int) ([]hostPort, error) {
	q := base64.StdEncoding.EncodeToString([]byte(query))
	u := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=host,ip,port",
		url.QueryEscape(k.FOFAEmail), url.QueryEscape(k.FOFAKey), url.QueryEscape(q), size)
	body, err := httpGetJSON(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Results [][]any `json:"results"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil, fmt.Errorf("FOFA 响应解析失败：%.120s", string(body))
	}
	var out []hostPort
	for _, row := range v.Results {
		host, port := "", 0
		if len(row) >= 1 {
			host = fmt.Sprint(row[0])
		}
		if len(row) >= 3 {
			if p, err := strconv.Atoi(fmt.Sprint(row[2])); err == nil {
				port = p
			}
		}
		if h, p, ok := splitHostPortLoose(host); ok {
			out = append(out, hostPort{h, p})
		} else if host != "" && port > 0 {
			out = append(out, hostPort{host, port})
		}
	}
	return out, nil
}

// quakeSearch 调 Quake 的 search/quake_service。
// 返回错误（限流/鉴权失败/网络）而不是静默吞掉——调用方要能区分"没找到"和
// "这次没查成"，否则一轮空转看起来像"测绘没结果"。
func quakeSearch(ctx context.Context, token, query string, size int) ([]hostPort, error) {
	payload, _ := json.Marshal(map[string]any{"query": query, "start": 0, "size": size, "include": []string{"ip", "port"}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://quake.360.net/api/v3/search/quake_service", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("X-QuakeToken", token)
	body, err := doJSON(req)
	if err != nil {
		return nil, err
	}
	// Quake 的响应形态有两套：
	//   成功：{"code":0,"data":[{"ip":"1.2.3.4","port":80}, …]}
	//   失败：{"code":"q2001","message":"用户当前积分不足…","data":{},"meta":{}}
	// 失败时 data 是**空对象**而不是数组。旧代码把 data 直接声明成数组，
	// 于是整个响应解析失败 → 错误被吞成"没有结果"。这正是持续狩猎空转几百轮
	// 却没人发现配额早就用完的原因：code 可能是数字也可能是字符串，所以
	// 一律用 RawMessage 收，再自己判别 data 的形态。
	var v struct {
		Code    json.RawMessage `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil, fmt.Errorf("Quake 响应解析失败：%.120s", string(body))
	}
	// Quake 用 code 表达业务错误：0=成功，其余（积分不足/配额用完/限流/鉴权）都要报出来。
	code := strings.Trim(strings.TrimSpace(string(v.Code)), `"`)
	if code != "" && code != "0" {
		msg := v.Message
		if msg == "" {
			msg = "code " + code
		}
		return nil, fmt.Errorf("Quake 返回 %s：%s", code, msg)
	}
	return parseQuakeHosts(v.Data)
}

// parseQuakeHosts 从 Quake 的 data 字段取出主机列表。
// data 可能是数组（成功）或空对象（失败时的形态）——后者直接当作没有结果。
func parseQuakeHosts(raw json.RawMessage) ([]hostPort, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if !strings.HasPrefix(trimmed, "[") {
		return nil, nil // 对象形态：错误响应里的空 data
	}
	var items []struct {
		IP   string   `json:"ip"`
		Port quakeInt `json:"port"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return nil, fmt.Errorf("Quake 结果解析失败：%.120s", trimmed)
	}
	var out []hostPort
	for _, d := range items {
		if d.IP != "" && d.Port.n > 0 {
			out = append(out, hostPort{d.IP, d.Port.n})
		}
	}
	return out, nil
}

// quakeInt 兼容 Quake 把端口写成数字（80）或字符串（"80"）两种情况。
type quakeInt struct{ n int }

func (p *quakeInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	n, err := strconv.Atoi(s)
	if err == nil {
		p.n = n
	}
	return nil // 解析不了就当 0，不让整条响应挂掉
}

// shodanSearch 调 Shodan host/search。
func shodanSearch(ctx context.Context, key, query string, size int) []hostPort {
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&minify=true",
		url.QueryEscape(key), url.QueryEscape(query))
	body, err := httpGetJSON(ctx, u, nil)
	if err != nil {
		return nil
	}
	var v struct {
		Matches []struct {
			IP        string `json:"ip_str"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
		} `json:"matches"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var out []hostPort
	for _, m := range v.Matches {
		if m.IP != "" && m.Port > 0 {
			out = append(out, hostPort{m.IP, m.Port})
			if len(out) >= size {
				break
			}
		}
	}
	return out
}

func httpGetJSON(ctx context.Context, u string, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return doJSON(req)
}

func doJSON(req *http.Request) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// splitHostPortLoose 解析 "http://1.2.3.4:11434" / "1.2.3.4:11434"。
func splitHostPortLoose(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		port := 0
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		if port == 0 {
			if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		return u.Hostname(), port, true
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 {
		if p, err := strconv.Atoi(s[i+1:]); err == nil && p > 0 && p <= 65535 {
			return s[:i], p, true
		}
	}
	return "", 0, false
}

// hunterSearch 调奇安信 Hunter 的 openApi/search。
// Hunter 的 page_size 只接受 10/20/50/100，其它值直接报"页大小不合法"。
func hunterSearch(ctx context.Context, key, query string, size int) ([]hostPort, error) {
	pageSize := 10
	if size > 10 {
		pageSize = 20
	}
	if size > 20 {
		pageSize = 50
	}
	search := base64.StdEncoding.EncodeToString([]byte(query))
	u := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=%d&is_web=3",
		url.QueryEscape(key), url.QueryEscape(search), pageSize)
	body, err := httpGetJSON(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Arr []struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			} `json:"arr"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &v) != nil {
		return nil, fmt.Errorf("Hunter 响应解析失败：%.120s", string(body))
	}
	// code=429 是限流、400 是查询语法问题——都要报出来，别当成"没找到"。
	if v.Code != 200 {
		msg := v.Message
		if msg == "" {
			msg = fmt.Sprintf("code %d", v.Code)
		}
		return nil, fmt.Errorf("Hunter 返回 %d：%s", v.Code, msg)
	}
	var out []hostPort
	for _, a := range v.Data.Arr {
		if a.IP != "" && a.Port > 0 {
			out = append(out, hostPort{a.IP, a.Port})
			if len(out) >= size {
				break
			}
		}
	}
	return out, nil
}
