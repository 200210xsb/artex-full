package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// llmProfileProbe 对单个 LLM profile 发一次最小推理请求，验证"推理后端"是否活着。
//
// 为什么要它：熔断器只对"快速失败"（401/429/5xx）有效；挂起型故障（HTTP 200 但
// 推理后端永远不回，实测 ai.nccsec.cn 那样）不会触发 Trip——任务就表现为
// "规划中…"永久卡死，没人知道是 LLM 死了。这个探测 15 秒判死，UI 一个按钮可见。
func (s *Server) llmProfileProbe(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	prov, _, ok := s.providerForProfile(id)
	if !ok {
		writeErr(w, 404, "profile 不存在或未配置")
		return
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 最小推理请求：非流式 + max_tokens=5。供应商连一个 token 都吐不出来
	// 就是后端挂了；能吐出来说明推理链路活着。
	req := llm.CompletionRequest{
		Messages:  []llm.Message{llm.UserText("回复 ok")},
		MaxTokens: 5,
	}
	_, _, _, err = prov.Complete(ctx, req)
	elapsed := time.Since(start).Round(100 * time.Millisecond).String()

	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "context deadline exceeded") || ctx.Err() != nil {
			msg = "15 秒无响应（推理后端挂起）"
		}
		if len(msg) > 160 {
			msg = msg[:160]
		}
		writeJSON(w, 200, map[string]any{"ok": false, "status": msg, "elapsed": elapsed})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": "推理正常", "elapsed": elapsed})
}
