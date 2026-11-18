package llmhunt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 密钥可用性验证。
//
// 这一动作的性质要说清楚：验证 = 拿别人的凭据向厂商发一次请求。所以：
//   - 只用厂商的"免费只读"接口（列模型），绝不发推理请求 —— 推理会花对方的钱；
//   - 每条 key 只验证一次，不重试；
//   - 结果只记"有效/无效"，不落任何响应内容；
//   - 默认关闭，必须显式开启；只应在你有权验证的 key 上使用。
// 这是 TruffleHog --only-verified 那套做法：一次最小请求，证明它活着。

const verifyGap = 1500 * time.Millisecond

// verifyTarget 描述某个厂商的验证方式。
type verifyTarget struct {
	url     string
	headers func(key string) map[string]string
}

var verifyTargets = map[string]verifyTarget{
	"OpenAI": {
		url: "https://api.openai.com/v1/models",
		headers: func(k string) map[string]string {
			return map[string]string{"Authorization": "Bearer " + k}
		},
	},
	"Anthropic": {
		url: "https://api.anthropic.com/v1/models",
		headers: func(k string) map[string]string {
			return map[string]string{"x-api-key": k, "anthropic-version": "2023-06-01"}
		},
	},
}

// Verifier 负责批量验证。
type Verifier struct {
	pg     *db.DB
	client *http.Client
}

// SetProxy 让验证请求走指定出口（http/socks5）。
//
// 必须走代理：api.openai.com / api.anthropic.com 从国内直连不通，之前所有验证都
// 被记成"请求失败（网络/超时）"，看起来像密钥无效，其实是我们没出去。
func (v *Verifier) SetProxy(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	v.client = &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
}

// NewVerifier 构造验证器。
func NewVerifier(pg *db.DB) *Verifier {
	return &Verifier{pg: pg, client: &http.Client{Timeout: 20 * time.Second}}
}

// VerifyPending 验证最多 limit 条尚未验证的 key，返回 (尝试数, 有效数)。
func (v *Verifier) VerifyPending(ctx context.Context, limit int) (tried, valid int, err error) {
	rows, err := v.pg.UnverifiedKeys(limit)
	if err != nil {
		return 0, 0, err
	}
	for _, k := range rows {
		if ctx.Err() != nil {
			break
		}
		vt, ok := verifyTargets[k.Type]
		if !ok {
			// AWS/阿里云/GitHub 这类不做网络验证：API 形态差异大、误判成本高。
			_ = v.pg.SetLLMKeyVerify(k.ID, "unsupported", "该类密钥不支持自动验证")
			continue
		}
		tried++
		state, note := v.verifyOne(ctx, vt, k.Raw)
		_ = v.pg.SetLLMKeyVerify(k.ID, state, note)
		if state == "valid" {
			valid++
		}
		time.Sleep(verifyGap)
	}
	return tried, valid, nil
}

// verifyOne 发一次最小请求判断可用性。
func (v *Verifier) verifyOne(ctx context.Context, vt verifyTarget, key string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vt.url, nil)
	if err != nil {
		return "error", "请求构造失败"
	}
	for k, val := range vt.headers(key) {
		req.Header.Set(k, val)
	}
	req.Header.Set("User-Agent", "ARTEX-KeyVerify/1.0")
	resp, err := v.client.Do(req)
	if err != nil {
		return "error", "请求失败（网络/超时）"
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 4096)) // 只读状态码，不留内容
	switch {
	case resp.StatusCode == 200:
		return "valid", "厂商只读接口返回 200（仅列模型，未发起推理）"
	case resp.StatusCode == 401, resp.StatusCode == 403:
		return "invalid", fmt.Sprintf("厂商返回 %d（密钥无效或已禁用）", resp.StatusCode)
	case resp.StatusCode == 429:
		return "error", "厂商限流（429），结果不确定"
	default:
		return "error", fmt.Sprintf("厂商返回 %d", resp.StatusCode)
	}
}

// VerifyNewKeys 验证"本轮新发现"的 key（每条一次、上限 limit）。
//
// 只用于 OpenAI / Anthropic 这类有免费只读接口（列模型）的厂商；不发推理请求。
func (s *Scanner) VerifyNewKeys(ctx context.Context, limit int) (tried, valid int) {
	v := NewVerifier(s.pg)
	t, ok, err := v.VerifyPending(ctx, limit)
	if err != nil {
		s.logf("自动验证失败: %v", err)
		return 0, 0
	}
	return t, ok
}
