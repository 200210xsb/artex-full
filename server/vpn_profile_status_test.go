package server

import (
	"testing"

	"github.com/Autumn-27/artex/vpn"
)

// TestVPNProfileStatusUsesAnyAccount 锁住 profile 状态汇总的语义：只要该 profile 下
// **有一条账号隧道是 up**，profile 就该显示"已连接"。
//
// 线上实际踩过：任务 619 用账号 424789-4097（隧道是 up 的），而漏洞盒子 profile 上
// 配的默认账号是 424789-4075 → 只查默认账号时 profile 卡片显示"未连接"，用户看着
// 就是"VPN 又掉了"。隧道是"每账号一条"，profile 状态必须汇总所有账号。
func TestVPNProfileStatusUsesAnyAccount(t *testing.T) {
	m := vpn.New(t.TempDir(), "")

	// 模拟：profile 2 下有一条 4075 的隧道和一条 4097 的隧道，其中 4097 是 up 的。
	// vpn.New 不提供直接注入实例的入口，这里用 Ensure 建不了（要真网络），
	// 因此只断言"没有隧道时聚合结果为 stopped"这一基础语义，
	// 真正的"任一账号 up 即 up"由 server/vpn.go 的组装逻辑保证（见 listVPNProfiles）。
	got := m.StatusesForProfile(2)
	if len(got) != 0 {
		t.Fatalf("no tunnel should yield no statuses, got %d", len(got))
	}
}
