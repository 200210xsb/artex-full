package server

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/llmhunt"
	actool "github.com/Autumn-27/norma/tool"
)

// 大模型资产测绘：扫描器按 Server 单例持有（同一时刻只允许一次扫描）。
var llmHuntOnce sync.Once

var verifierOnce sync.Once

// llmVerifier 返回密钥验证器（进程内单例）。
func (s *Server) llmVerifier() *llmhunt.Verifier {
	verifierOnce.Do(func() { s.llmVerify = llmhunt.NewVerifier(s.m.pg) })
	return s.llmVerify
}

// llmVerifyKeys 验证尚未验证的密钥可用性。
//
// 必须显式带 confirm=true：这一步会**用别人的凭据**向厂商发一次只读请求，
// 只在你有权验证的 key 上使用。
func (s *Server) llmVerifyKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
		Limit   int  `json:"limit"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !req.Confirm {
		writeErr(w, 400, "需要显式确认（confirm=true）：验证会用该密钥向厂商发起一次只读请求")
		return
	}
	tried, valid, err := s.llmVerifier().VerifyPending(r.Context(), req.Limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tried": tried, "valid": valid})
}

var ghHunterOnce sync.Once

// llmKeyHunter 返回 GitHub 密钥狩猎器（进程内单例）。
func (s *Server) llmKeyHunter() *llmhunt.GitHubKeyHunter {
	ghHunterOnce.Do(func() {
		s.llmGH = llmhunt.NewGitHubKeyHunter(s.m.pg, "")
	})
	return s.llmGH
}

// llmKeyHuntStart 启动一轮 GitHub 公开仓库密钥狩猎。
func (s *Server) llmKeyHuntStart(w http.ResponseWriter, r *http.Request) {
	h := s.llmKeyHunter()
	if !h.Ready() {
		writeErr(w, 400, "未配置 GitHub token：把 PAT 写到 /root/.artex-gh-token 或设置 ARTEX_GH_TOKEN")
		return
	}
	if err := h.Start(r.Context()); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// llmKeyHuntStatus 查询密钥狩猎状态。
func (s *Server) llmKeyHuntStatus(w http.ResponseWriter, r *http.Request) {
	h := s.llmKeyHunter()
	dorks, files, found, lastErr := h.Progress()
	writeJSON(w, 200, map[string]any{
		"ready": h.Ready(), "running": h.Running(), "found": found,
		"dorks_done": dorks, "files_fetched": files, "last_error": lastErr,
	})
}

// llmKeyStats 按厂商/来源统计密钥。
func (s *Server) llmKeyStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.m.pg.LLMKeyStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) llmScanner() *llmhunt.Scanner {
	llmHuntOnce.Do(func() {
		s.llmHunt = llmhunt.New(s.m.pg)
		s.llmHunt.SetDiscoverer(s.llmSearchDiscoverer())
	})
	return s.llmHunt
}

// llmSearchDiscoverer 把 ARTEX 已配置的 web_search 后端借给测绘用（不花模型额度，
// 只有 deepseek 后端例外）。返回 nil 表示当前配置不可用，调用方会退化为"只扫给定目标"。
func (s *Server) llmSearchDiscoverer() llmhunt.Discoverer {
	opts := s.m.WebSearchOpts()
	if !opts.Enabled {
		return nil
	}
	cfg := actool.WebSearchConfig{
		Backend:      opts.Backend,
		BraveAPIKey:  opts.BraveKey,
		TavilyAPIKey: opts.TavilyKey,
		Proxy:        opts.Proxy,
	}
	if opts.DeepSeekBaseURL != "" {
		cfg.DeepSeekBaseURL = opts.DeepSeekBaseURL
		cfg.DeepSeekAPIKey = opts.DeepSeekAPIKey
		cfg.DeepSeekModel = opts.DeepSeekModel
	}
	return func(ctx context.Context, query string, limit int) ([]string, error) {
		res, err := actool.WebSearchProbe(ctx, cfg, query, limit)
		if err == nil && len(res) > 0 {
			out := make([]string, 0, len(res))
			for _, r := range res {
				if r.URL != "" {
					out = append(out, r.URL)
				}
			}
			if len(out) > 0 {
				return out, nil
			}
		}
		// 配置的后端不可用（国内网络里 ddgs 基本不可达）时回落到 Bing。
		log.Printf("[llmhunt] web_search 后端不可用(%v)，改用 Bing", err)
		return llmhunt.BingSearch(ctx, query, limit)
	}
}

// llmHuntScan 启动一次测绘。
//
// 目标来源三选一：粘贴清单（seeds）、资产库（assets）、或两者都给。
// 刻意**不做**网段/端口段扫描：那既吵又容易越界，目标必须由操作者给出。
func (s *Server) llmHuntScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Seeds         string `json:"seeds"`       // 每行 host / host:port / URL
		FromAssets    bool   `json:"from_assets"` // 从资产库取（授权资产）
		UseSearch     bool   `json:"use_search"`  // 用搜索引擎发现候选
		Dorks         string `json:"dorks"`       // 自定义搜索词（每行一个；空=内置）
		MaxFromSearch int    `json:"max_from_search"`
		AllowAuth     bool   `json:"allow_auth"` // 默认口令探测（POST，仅授权目标）
		HuntLeaks     bool   `json:"hunt_leaks"` // 先找"响应里已含 key"的 URL（Hunter/Quake）
		MaxTargets    int    `json:"max_targets"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	max := req.MaxTargets
	if max <= 0 || max > 2000 {
		max = 200
	}

	var targets []llmhunt.Target
	if strings.TrimSpace(req.Seeds) != "" {
		t, err := llmhunt.ParseSeeds(req.Seeds, max)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		targets = append(targets, t...)
	}
	if req.FromAssets {
		fromAssets, err := s.m.llmHuntAssets(max)
		if err != nil {
			writeErr(w, 500, "读取资产库失败: "+err.Error())
			return
		}
		targets = append(targets, fromAssets...)
	}
	var dorks []string
	if req.UseSearch {
		if strings.TrimSpace(req.Dorks) != "" {
			for _, line := range strings.Split(req.Dorks, "\n") {
				if v := strings.TrimSpace(line); v != "" {
					dorks = append(dorks, v)
				}
			}
		} else {
			dorks = llmhunt.DefaultDorks
		}
		if s.llmSearchDiscoverer() == nil {
			writeErr(w, 400, "搜索引擎未启用：请先在「设置 → 联网搜索」里配置并启用")
			return
		}
	}
	if len(targets) == 0 && len(dorks) == 0 && !req.HuntLeaks {
		writeErr(w, 400, "请粘贴目标清单、勾选「从资产库扫描」「用搜索引擎发现」，或勾选「先找泄漏的密钥文件」")
		return
	}

	id, err := s.llmScanner().Start(llmhunt.Options{
		Targets:         targets,
		Dorks:           dorks,
		MaxFromSearch:   req.MaxFromSearch,
		AllowAuthChecks: req.AllowAuth,
		HuntLeaks:       req.HuntLeaks,
		// 探测目标走全局代理出口（不暴露 VPS 自己的 IP）。
		Proxy: s.m.GlobalProxy(),
	})
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"scan_id": id, "targets": len(targets)})
}

// llmHuntStop 停止当前扫描。
func (s *Server) llmHuntStop(w http.ResponseWriter, r *http.Request) {
	s.llmScanner().Stop()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// llmHuntStatus 返回最近一次扫描状态 + 是否有扫描在跑。
func (s *Server) llmHuntStatus(w http.ResponseWriter, r *http.Request) {
	last, _ := s.m.pg.LastLLMScan()
	writeJSON(w, 200, map[string]any{
		"running": s.llmScanner().Running(),
		"last":    last,
	})
}

// llmHuntAssets 列出发现的大模型实例。
func (s *Server) llmHuntAssets(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.ListLLMAssets(300)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"assets": rows})
}

// llmHuntKeys 列出泄露的密钥（只回掩码，原文要单独取）。
func (s *Server) llmHuntKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.ListLLMKeys(300)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"keys": rows})
}

// llmHuntReveal 取出某条密钥的原文。
//
// 这是一次显式动作：界面上默认只显示掩码，用户点"查看原文"才会走到这里。
// 原文不写日志、不缓存、不回显到 URL 上。
func (s *Server) llmHuntReveal(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	raw, err := s.m.pg.LLMKeyRaw(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if raw == "" {
		writeErr(w, 404, "记录不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"raw": raw})
}

// llmHuntDeleteKey 删除一条密钥记录。
func (s *Server) llmHuntDeleteKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	if err := s.m.pg.DeleteLLMKey(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// llmHuntDeleteAsset 删除一个实例（连带它的密钥记录）。
func (s *Server) llmHuntDeleteAsset(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id 非法")
		return
	}
	if err := s.m.pg.DeleteLLMAsset(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}
