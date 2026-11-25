// Package vpn runs OpenVPN profiles as isolated egress paths for tasks.
//
// Bounty platforms hand out an .ovpn plus one account, and expect all traffic for
// their project to leave through that tunnel. ARTEX used to have exactly one
// global egress, so two projects running side by side would share an exit — which
// is both wrong for the engagement and impossible to audit afterwards.
//
// Each profile therefore gets its own network namespace: openvpn owns the default
// route *inside* that namespace, and a sing-box instance next to it exposes a
// SOCKS endpoint the task's tools can use. Nothing touches the host routing table,
// so several tunnels can be up at once.
//
// Two properties matter more than throughput:
//
//   - fail closed. Once the tunnel is up the bootstrap route is removed, so if
//     openvpn dies the namespace has no way out at all. A task never silently
//     falls back to the host's direct connection.
//   - no leftovers. Tunnels are torn down on shutdown, and teardown enumerates the
//     namespace's processes rather than trusting a PID file: openvpn daemonizes,
//     and a stale PID would leave the process holding the namespace forever.
package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrUnsupported is returned on platforms without network namespaces.
var ErrUnsupported = errors.New("当前平台不支持 VPN 出口（需要 Linux 网络命名空间）")

// errStopRebuild 表示看门狗不该重建这条隧道（已停用/已回收）。
var errStopRebuild = errors.New("停止重建")

// Profile is one OpenVPN configuration plus the account in use.
//
// Key identifies a tunnel: the same .ovpn with a different account is a different
// tunnel, because the platform routes each project's traffic by account. Tasks of
// the same project share one tunnel; a different project gets its own.
type Profile struct {
	Key          string // tunnel identity, e.g. "3|424789-4069"
	ID           int64  // the stored profile row, for logging/display
	Name         string
	Raw          string // the .ovpn exactly as the operator uploaded it
	Username     string
	Password     string
	ExpectEgress string // optional expected exit IP; empty = do not check
}

// State values reported to the UI.
const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateUp       = "up"
	StateError    = "error"
)

// idleTTL 是一条隧道"没人用"多久后回收。任务跑完不会显式通知隧道，靠这个兜底：
// 不回收的话，每条隧道会一直占着命名空间、两个进程和约 45MB 内存。
const idleTTL = 30 * time.Minute

// Status is a snapshot of one profile's tunnel.
type Status struct {
	Key       string    `json:"key"`
	ID        int64     `json:"id"`
	Username  string    `json:"username,omitempty"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	SOCKSAddr string    `json:"socks_addr,omitempty"`
	EgressIP  string    `json:"egress_ip,omitempty"`
	Expect    string    `json:"expect_egress,omitempty"`
	Notes     []string  `json:"notes,omitempty"` // config rewrites applied on start
	LastErr   string    `json:"last_error,omitempty"`
	Since     time.Time `json:"since,omitempty"`
}

// Up reports whether the tunnel currently carries traffic.
func (s Status) Up() bool { return s.State == StateUp }

// Manager owns the tunnels. One per process.
type Manager struct {
	// activeBinding 由 server 注入：某 profile 是否还有任务绑定且在跑。
	// 为 nil 时退化为纯空闲判定（旧行为）。
	activeBinding ActiveBinding
	dir           string // where generated configs and credential files live
	singbox       string // sing-box binary used as the in-namespace SOCKS server
	// liveURLs 是「隧道是否还通」的探测端点：必须是 **IP 字面量**（不依赖 DNS），
	// 且任何 HTTP 状态码都算通——响应本身就是隧道在承载流量的证据。
	// 隧道 push 的内网 DNS 会间歇性不可达（实测漏洞盒子），拿域名型端点判断连通性
	// 会把「只有 DNS 坏了」误判成「隧道断了」，进而拆掉一条好隧道。
	liveURLs []string
	// egressURLs 是「出口 IP 是多少」的回显端点：域名型，200 响应体即出口地址。
	// 只在需要核对出口时用（建链时、或用户手动刷新），不参与连通性判定。
	egressURLs []string

	mu     sync.Mutex
	items  map[string]*instance
	slots  map[int]bool // veth slot allocation, so subnets never collide
	logf   func(string, ...any)
	closed bool

	janitorOnce sync.Once
}

// New returns a manager that keeps its generated files under dir. singbox may be
// empty, in which case the tunnel comes up without a SOCKS endpoint and Ensure
// fails with a clear error.
func New(dir, singbox string) *Manager {
	return &Manager{
		dir:     dir,
		singbox: singbox,
		// 连通性用 IP 字面量端点：不依赖 DNS，且 http://1.1.1.1 会 301 跳到 https，
		// 这里只取「有没有响应」，跳转与否无所谓（vpn/http.go 里已禁掉跟随重定向）。
		liveURLs: []string{"http://1.1.1.1/", "http://1.0.0.1/"},
		// 出口地址用域名型端点：响应体就是出口 IP（ip.3322.net 专门做这个）。
		egressURLs: []string{"http://ip.3322.net"},
		items:      map[string]*instance{},
		slots:      map[int]bool{},
		logf:       log.Printf,
	}
}

// SetLogger overrides the logger (used by tests).
func (m *Manager) SetLogger(f func(string, ...any)) { m.logf = f }

// Ensure brings the profile's tunnel up (idempotent) and returns the SOCKS URL a
// task should use. It blocks until the exit path is verified or ctx expires.
func (m *Manager) Ensure(ctx context.Context, p Profile) (string, error) {
	if p.ID == 0 && p.Key == "" {
		return "", errors.New("VPN 出口缺少标识")
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return "", errors.New("VPN 管理器已关闭")
	}
	key := p.Key
	if key == "" {
		key = fmt.Sprintf("profile:%d", p.ID)
	}
	inst := m.items[key]
	if inst == nil {
		inst = &instance{profile: p, state: StateStopped}
		m.items[key] = inst
	}
	inst.profile = p // credentials/config may have been edited
	m.mu.Unlock()

	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.state == StateUp && inst.socksAddr != "" {
		inst.lastUsed = time.Now()
		return "socks5://" + inst.socksAddr, nil
	}
	// bringUp 用**独立的后台 ctx**，不继承调用方的 ctx：
	// UI 手动连接传的是 HTTP 请求 ctx——浏览器超时/关页就会 cancel，把建到一半的
	// 隧道打死（实测报 context canceled，UI 显示"异常"）。任务侧 ProxyAddrFor
	// 传的是 2 分钟超时 ctx，同样会在慢建链时误杀。隧道一旦开始建立就应该
	// 跑完（monitor 会做后续健康检查），调用方提前断开不应影响它。
	// 调用方如果不想等，可以自行断开请求——隧道继续在后台建，下次 Ensure 命中
	// StateUp 直接返回。
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer buildCancel()
	_ = ctx // 调用方提前放弃等待不影响建链：buildCtx 独立于调用方
	if err := m.bringUp(buildCtx, inst); err != nil {
		inst.state = StateError
		inst.lastErr = err.Error()
		return "", err
	}
	inst.state = StateUp
	inst.since = time.Now()
	inst.lastUsed = time.Now()
	inst.lastErr = ""
	go m.monitor(inst)
	m.startJanitor()
	return "socks5://" + inst.socksAddr, nil
}

// Stop tears one tunnel down.
func (m *Manager) Stop(key string) {
	m.mu.Lock()
	inst := m.items[key]
	m.mu.Unlock()
	if inst == nil {
		return
	}
	inst.mu.Lock()
	m.teardown(inst)
	inst.state = StateStopped
	inst.mu.Unlock()
}

// Forget stops a tunnel and drops it from the manager (profile deleted).
func (m *Manager) ForgetPrefix(prefix string) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		if k == prefix || strings.HasPrefix(k, prefix+"|") {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()
	for _, k := range keys {
		m.Stop(k)
		m.mu.Lock()
		delete(m.items, k)
		m.mu.Unlock()
	}
}

// Forget drops one tunnel.
func (m *Manager) Forget(key string) {
	m.Stop(key)
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
}

// Status returns one profile's snapshot.
func (m *Manager) Status(key string) Status {
	m.mu.Lock()
	inst := m.items[key]
	m.mu.Unlock()
	if inst == nil {
		return Status{State: StateStopped}
	}
	return inst.snapshot()
}

// Statuses returns every known profile, sorted by id.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	sort.Strings(keys)
	out := make([]Status, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.Status(k))
	}
	return out
}

// Close stops every tunnel. Call on shutdown so no namespace survives the process.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	for _, k := range keys {
		m.Stop(k)
	}
}

// instance is one profile's live tunnel state.
type instance struct {
	profile Profile

	mu        sync.Mutex
	state     string
	socksAddr string
	egressIP  string
	notes     []string
	lastErr   string
	since     time.Time
	lastUsed  time.Time // 最近一次有流量（或被任务取用）；空闲回收据此判断
	// trafficBytes 是上次采样到的隧道内层字节数（rx+tx）。下一次采样比它大
	// 就说明这期间真的有流量流过隧道。
	trafficBytes uint64
	slot         int
	closed       bool

	// 平台相关字段（linux 实现在 linux.go 里使用）
	socksCmd *exec.Cmd
	netns    string
	veth     string
	nsIP     string
	hostIP   string
	extIface string
}

func (i *instance) snapshot() Status {
	i.mu.Lock()
	defer i.mu.Unlock()
	return Status{
		Key:       i.profile.Key,
		ID:        i.profile.ID,
		Username:  i.profile.Username,
		Name:      i.profile.Name,
		State:     i.state,
		SOCKSAddr: i.socksAddr,
		EgressIP:  i.egressIP,
		Expect:    i.profile.ExpectEgress,
		Notes:     append([]string(nil), i.notes...),
		LastErr:   i.lastErr,
		Since:     i.since,
	}
}

// monitor probes the tunnel and re-establishes it when it stops carrying traffic.
func (m *Manager) monitor(inst *instance) {
	const (
		interval   = 20 * time.Second
		maxFails   = 2
		minBackoff = 3 * time.Second
	)
	fails := 0
	backoff := minBackoff
	for {
		time.Sleep(interval)
		inst.mu.Lock()
		if inst.state != StateUp || inst.closed {
			inst.mu.Unlock()
			return
		}
		addr := inst.socksAddr
		inst.mu.Unlock()

		if err := m.probe(addr); err == nil {
			fails = 0
			backoff = minBackoff
			continue
		} else {
			fails++
			m.logf("[vpn] %s 探测失败（%d/%d）: %v", inst.profile.Name, fails, maxFails, err)
		}
		if fails < maxFails {
			continue
		}

		inst.mu.Lock()
		if inst.closed {
			inst.mu.Unlock()
			return
		}
		inst.state = StateError
		m.teardown(inst)
		inst.mu.Unlock()

		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		err := func() error {
			inst.mu.Lock()
			defer inst.mu.Unlock()
			// 期间可能被空闲回收（状态变 Stopped）或被显式停掉：都不该再拉起。
			if inst.closed || inst.state != StateError {
				return errStopRebuild
			}
			return m.bringUp(ctx, inst)
		}()
		cancel()
		inst.mu.Lock()
		if errors.Is(err, errStopRebuild) {
			inst.mu.Unlock()
			return
		}
		if err != nil {
			inst.state = StateError
			inst.lastErr = err.Error()
			inst.mu.Unlock()
			fails = maxFails // keep retrying
			continue
		}
		inst.state = StateUp
		inst.since = time.Now()
		inst.lastErr = ""
		inst.mu.Unlock()
		fails = 0
	}
}

// startJanitor 启动空闲回收循环（只启动一次）。
func (m *Manager) startJanitor() {
	m.janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				m.mu.Lock()
				closed := m.closed
				m.mu.Unlock()
				if closed {
					return
				}
				m.reapIdle()
			}
		}()
	})
}

// ActiveBinding 由 server 层注入：报告某 profile（**且某个账号**）是否还有任务
// 绑定且在跑。
//
// 为什么要带账号：隧道是"每个账号一条"（同一份 .ovpn 会被不同项目复用，账号不同
// 出口就不同）。只按 profile 判断会把"这个 profile 下别的账号的任务"也算成占用，
// 于是某条早已没有任务用的隧道（比如任务被删了）永远算"有占用"，回收不掉。
type ActiveBinding func(profileID int64, username string) bool

// SetActiveBindingCheck 注入占用检查（server 启动时调用一次）。
func (m *Manager) SetActiveBindingCheck(fn ActiveBinding) {
	m.activeBinding = fn
}

// reapIdle 停掉长时间没人用、且没有任务绑定的隧道。
func (m *Manager) reapIdle() {
	m.mu.Lock()
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	for _, k := range keys {
		m.mu.Lock()
		inst := m.items[k]
		if inst == nil {
			// 已被 Forget 掉，连带把条目删掉。
			delete(m.items, k)
			m.mu.Unlock()
			continue
		}
		m.mu.Unlock()

		inst.mu.Lock()
		name := inst.profile.Name
		profID := inst.profile.ID
		lastUsed := inst.lastUsed
		up := inst.state == StateUp
		inst.mu.Unlock()

		// 判定顺序很重要：先看占用，再看空闲。
		// 有任务绑定（running/created）→ 永不回收，哪怕 30 分钟没流量（任务可能
		// 在等远端响应、在慢慢跑长命令）。占用检查失败（DB 不可用）保守视为有占用。
		occupied := true
		if m.activeBinding != nil {
			occupied = m.activeBinding(profID, inst.profile.Username)
		}
		idle := false
		reason := ""
		if !occupied {
			// 无占用：宽限期（idleTTL/2 = 15 分钟）一到就回收。
			if !lastUsed.IsZero() && time.Since(lastUsed) > idleTTL/2 {
				idle = true
				reason = "无任务占用且空闲超过 15 分钟"
			}
		} else if up && !lastUsed.IsZero() && time.Since(lastUsed) > idleTTL {
			// 有占用但 30 分钟没有流量：**先看隧道是不是其实还在跑流量**。
			//
			// lastUsed 过去只在 Ensure()（任务来取这条隧道）时刷新，而任务的实际
			// 流量是 worker 的子进程直连 socks 走的，进程内看不到——于是"正在高强度
			// 扫描"的任务，lastUsed 一直停在启动那一刻，30 分钟后被当成卡死回收，
			// 正在跑的隧道被拆掉，任务下一次请求直接失败（用户看到的"VPN 又掉了"，
			// 实测线上每 ~35 分钟被拆一次）。
			//
			// 现在改用**隧道内层接口的字节计数**判断：两次采样之间计数增长 = 流量
			// 确实在跑 → 刷新 lastUsed 并保留隧道。
			if bytes, ok := m.tunnelTrafficBytes(inst); ok {
				inst.mu.Lock()
				grew := bytes > inst.trafficBytes
				if grew {
					inst.trafficBytes = bytes
					inst.lastUsed = time.Now()
				}
				inst.mu.Unlock()
				if grew {
					m.logf("[vpn] %s 仍有流量通过，保留隧道（不按空闲回收）", name)
					continue
				}
			}
			idle = true
			reason = "有占用但空闲超过 30 分钟"
		}
		_ = up

		if idle {
			// Stop 会把状态置为 Stopped；monitor 重连前会重新检查状态，因此不会把
			// 刚回收的隧道又拉起来。下次任务取用时 Ensure 会重建。
			m.logf("[vpn] %s 回收隧道：%s（任务再跑时自动重连）", name, reason)
			m.Stop(k)
		}
	}
}

// probe 判断隧道是否还在承载流量。
//
// 判据是「有没有拿到 HTTP 响应」，不是「有没有拿到出口 IP」：出口 IP 要靠域名型
// 回显端点，而隧道 push 的内网 DNS 会间歇性不可达（实测漏洞盒子，窗口 10~20 秒），
// 那段时间里拿不到 IP 但隧道其实好好的。旧判据会把这种假失败当成断链，monitor
// 连续两次就拆链，于是好隧道被反复重建（用户看到的「VPN 又没了」）。
//
// 端点用 IP 字面量，不依赖 DNS；且不跟随重定向（http://1.1.1.1 会跳 https，
// 跟过去会撞上无 SNI 的 TLS 握手失败）。
func (m *Manager) probe(socksAddr string) error {
	if socksAddr == "" {
		return errors.New("隧道未就绪")
	}
	var lastErr error
	backoffs := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(backoffs[i-1])
		}
		for _, u := range m.liveURLs {
			_, _, err := probeRawVia(socksAddr, u)
			if err == nil {
				return nil // 任何响应都算隧道在通
			}
			lastErr = err
		}
	}
	return lastErr
}

// probeEgress 取当前出口地址（域名型回显端点，响应体即出口 IP）。
// 隧道内 DNS 不可用时返回错误——这不代表隧道断了，只代表此刻拿不到出口地址。
func (m *Manager) probeEgress(socksAddr string) (string, error) {
	if socksAddr == "" {
		return "", errors.New("隧道未就绪")
	}
	var lastErr error
	for _, u := range m.egressURLs {
		ip, err := probeVia(socksAddr, u)
		if err == nil && ip != "" {
			return ip, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("出口未返回地址")
		}
	}
	return "", lastErr
}

// normalizeShort renders config notes for logs.
func normalizeShort(notes []string) string {
	if len(notes) == 0 {
		return "无"
	}
	return strings.Join(notes, "；")
}
