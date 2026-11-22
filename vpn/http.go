package vpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// httpClient performs a single tiny GET through a SOCKS dialer. It exists so the
// exit check shares the exact path a task's traffic takes.
type httpClient struct {
	dial func(network, addr string) (net.Conn, error)
}

// getRaw 取一次响应，**不跟随重定向**。
//
// 为什么要禁掉重定向：出口探测的 IP 型端点（1.1.1.1）在 http 下会 301 跳到
// https://1.1.1.1/，跟过去就是对 1.1.1.1 做一次没有 SNI 的 TLS 握手，Cloudflare
// 直接回 internal error 告警 → 探测必然失败 → 好好的隧道被误判成断链拆掉。
//
// err 只在**传输层**失败（DNS 解析不了 / 连不上 / 超时）时非空；任何 HTTP 状态码
// 都说明「隧道在通」——响应本身就是证据，301/404 也算。
func (c *httpClient) getRaw(url string) (string, int, error) {
	tr := &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return c.dial(network, addr)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return strings.TrimSpace(string(body)), resp.StatusCode, nil
}

// get 取一次 200 响应，body 即出口地址（用于核对「出口 IP 是否符合预期」）。
func (c *httpClient) get(url string) (string, error) {
	body, code, err := c.getRaw(url)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("探测端点返回 %d", code)
	}
	return strings.TrimSpace(body), nil
}
