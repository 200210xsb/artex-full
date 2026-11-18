package server

import (
	"net"
	"testing"
)

// 规范类模板里会拿云元数据地址举例，种子解析曾把示例当成真目标建成资产。
func TestIsNeverTargetIP(t *testing.T) {
	never := []string{
		"169.254.169.254", // 云元数据（链路本地）
		"127.0.0.1",       // 回环
		"::1",
		"0.0.0.0",
		"224.0.0.1", // 组播
	}
	for _, s := range never {
		if ip := net.ParseIP(s); ip == nil || !isNeverTargetIP(ip) {
			t.Errorf("%s 应被判为非目标地址", s)
		}
	}
	// 私有网段是合法的内网测试目标，不能被误杀。
	for _, s := range []string{"10.0.0.5", "192.168.1.10", "172.16.0.1", "8.8.8.8"} {
		if ip := net.ParseIP(s); ip != nil && isNeverTargetIP(ip) {
			t.Errorf("%s 不应被判为非目标地址", s)
		}
	}
}
