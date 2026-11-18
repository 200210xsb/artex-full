package agent

import (
	"context"
	"testing"
)

func TestEgressProxyRoundTrip(t *testing.T) {
	const want = "socks5://10.201.1.2:1080"
	ctx := WithEgressProxy(context.Background(), want)
	if got := EgressProxyFrom(ctx); got != want {
		t.Errorf("EgressProxyFrom() = %q, want %q", got, want)
	}
}

func TestEgressProxyEmptyIsNoop(t *testing.T) {
	// 空串不写入 ctx：调用方不必判断"有没有出口"，直接一直挂即可。
	ctx := WithEgressProxy(context.Background(), "  ")
	if got := EgressProxyFrom(ctx); got != "" {
		t.Errorf("空出口不应写入 ctx，得到 %q", got)
	}
	if got := EgressProxyFrom(nil); got != "" {
		t.Errorf("nil ctx 应返回空，得到 %q", got)
	}
}
