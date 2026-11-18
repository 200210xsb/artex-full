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

func (c *httpClient) get(url string) (string, error) {
	tr := &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return c.dial(network, addr)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("探测端点返回 %d", resp.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}
