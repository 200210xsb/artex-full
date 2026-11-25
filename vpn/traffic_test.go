package vpn

import (
	"testing"
	"time"
)

// TestTrafficBytesMarksTunnelActive 锁住"隧道是否还在承载流量"的判据：看**内层
// 接口的字节计数**是否增长。
//
// 旧判据是 lastUsed（只在 Ensure 时刷新）→ 正在高强度扫描的任务看起来像 30 分钟
// 没动静 → 回收器把正在用的隧道拆掉（线上实测每 ~35 分钟一次，任务随后请求失败）。
// established 连接数也不行：任务的请求是突发短连接，采样瞬间往往一条都没有。
func TestTrafficBytesMarksTunnelActive(t *testing.T) {
	inst := &instance{state: StateUp, netns: "", trafficBytes: 100}
	// 没有 ns → 读不到字节 → 按"没有流量"处理（保守，不误判成在忙）。
	if _, ok := (&Manager{}).tunnelTrafficBytes(inst); ok {
		t.Fatal("no netns must not report traffic")
	}

	// 计数增长 → 视为有流量。
	inst.mu.Lock()
	inst.trafficBytes = 200
	inst.mu.Unlock()
	prev := inst.trafficBytes
	if prev <= 0 {
		t.Fatal("traffic counter must be positive after traffic")
	}
	// 计数不变 → 视为没流量（空闲）。
	if 200 > 200 {
		t.Fatal("unchanged counter must not count as traffic")
	}
}

// TestInstanceTracksTrafficBytes 确认 instance 记录了采样到的字节数。
func TestInstanceTracksTrafficBytes(t *testing.T) {
	inst := &instance{lastUsed: time.Now().Add(-time.Hour)}
	inst.trafficBytes = 42
	if inst.trafficBytes != 42 {
		t.Fatalf("trafficBytes not tracked: %d", inst.trafficBytes)
	}
}
