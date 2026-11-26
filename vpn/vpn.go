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

// occupiedIdleTTL 是"有任务绑定"的隧道多久没流量才回收。给得比 idleTTL 宽得
// 多：planner 一轮规划就要 5~17 分钟，长命令/等远端响应期间本来就没有新流量。
// 30 分钟会把正在跑的任务的出口拆掉（任务下一次请求直接失败），2 小时足够
// 分辨"任务卡死"和"任务在正常长跑"。
const occupiedIdleTTL = 2 * time.Hour

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
		//
		// 端点要选**国内出口真能通的**：这些隧道（漏洞盒子/360 众测）的出口是
		// 国内运营商网络，Cloudflare 的 1.1.1.1 和 1.0.0.1 在那边经常被过滤
		// （实测 socks 报 "general SOCKS server failure"），拿它们探测会导致
		// 好隧道被判死、反复重建。所以首选几家国内 DNS 的 IP：它们只要求"有
		// 响应"（404/403 就算），不要求 200。
		liveURLs: []string{
			"http://223.5.5.5/",    // AliDNS
			"http://119.29.29.29/", // DNSPod
			"http://180.76.76.76/", // 百度 DNS
			"http://1.1.1.1/",      // Cloudflare：国内部分出口不通，放最后兜底
		},
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
	// 先采一个字节计数基线：否则第一次回收检查时，计数必然"比 0 大"，会被当成
	// 有流量而白留一条空闲隧道 30 分钟。
	//
	// 注意：这里**不能**用 m.tunnelTrafficBytes(inst)——本函数已持有 inst.mu
	// （defer 解锁），而那个方法内部还会再拿一次锁：Go 的 mutex 不可重入 →
	// 自死锁，整个实例的锁被永久持有，/api/vpn、/api/tasks 等碰 VPN 管理器的
	// 接口会全部挂住（实测踩过）。此处已持锁，直接调用不拿锁的 tunnelBytes。
	if bytes, ok := tunnelBytes(inst.netns); ok {
		inst.trafficBytes = bytes
	}
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

// StatusesForProfile 返回某个 profile 下**所有账号**的隧道状态。
//
// 为什么需要它：隧道是"每账号一条"（同一份 .ovpn 被不同项目复用，账号不同出口
// 就不同），而任务用的账号常常和 profile 上配的默认账号不同。若只按默认账号查
// 状态，实际正在跑的隧道会被显示成"未连接"——用户看着就是"VPN 又掉了"。
func (m *Manager) StatusesForProfile(profileID int64) []Status {
	m.mu.Lock()
	keys := make([]string, 0, len(m.items))
	for k, inst := range m.items {
		if inst != nil && inst.profile.ID == profileID {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()
	sort.Strings(keys)
	out := make([]Status, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.Status(k))
	}
	return out
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
	// building 表示"正在后台建链"，防止 reapIdle 的自动重建并发起多条。
	building bool

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

// noteTraffic 采样一次隧道内层字节计数，作为下次的比较基线。
func (m *Manager) noteTraffic(inst *instance) {
	bytes, ok := m.tunnelTrafficBytes(inst)
	if !ok {
		return
	}
	inst.mu.Lock()
	inst.trafficBytes = bytes
	inst.mu.Unlock()
}

// tunnelCarryingTraffic 报告自上次采样以来隧道里是否有字节流动。
// 有 = 隧道确实在承载流量（哪怕探测端点不可达），此时不该拆它。
func (m *Manager) tunnelCarryingTraffic(inst *instance) bool {
	bytes, ok := m.tunnelTrafficBytes(inst)
	if !ok {
		return false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if bytes > inst.trafficBytes {
		inst.trafficBytes = bytes
		return true
	}
	return false
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
			m.noteTraffic(inst)
			continue
		} else {
			// 探测失败**不等于**隧道死了：出口网络可能屏蔽了探测端点（实测国内
			// 出口连 1.1.1.1 都失败）。隧道里还有字节在流动 = 隧道确实在干活，
			// 这时候拆链只会打断正在跑的任务（用户看到的就是"VPN 又掉了"，
			// 任务下一次请求直接失败）。
			if m.tunnelCarryingTraffic(inst) {
				fails = 0
				backoff = minBackoff
				m.logf("[vpn] %s 探测失败但隧道仍有流量通过，保留隧道: %v", inst.profile.Name, err)
				continue
			}
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
		} else if occupied && !up {
			// 有任务绑定但隧道是停的（被 idle 回收过、或建链失败）：**自动重建**。
			// 之前只在任务来取 ProxyAddrFor 时才重建，而任务运行期间不会再取一次，
			// 于是隧道一旦被回收，任务就顶着"出口 —"跑（fail-closed，所有请求被
			// 阻断），用户看到的就是"任务在跑但 VPN 掉了"。
			inst.mu.Lock()
			needBringUp := !inst.closed && !inst.building
			if needBringUp {
				inst.building = true
			}
			inst.mu.Unlock()
			if needBringUp {
				// 重建放在后台，别把 reapIdle 卡在 20~60 秒的拨号上。
				go func(it *instance) {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
					defer cancel()
					defer func() {
						it.mu.Lock()
						it.building = false
						it.mu.Unlock()
					}()
					it.mu.Lock()
					err := m.bringUp(ctx, it)
					if err != nil {
						it.state = StateError
						it.lastErr = err.Error()
						it.building = false
						it.mu.Unlock()
						m.logf("[vpn] %s 有任务绑定但隧道未就绪，自动重建失败: %v", name, err)
						return
					}
					it.state = StateUp
					it.since = time.Now()
					it.lastUsed = time.Now()
					it.lastErr = ""
					it.building = false
					it.mu.Unlock()
					m.logf("[vpn] %s 有任务绑定但隧道未就绪，已自动重建：%s", name, it.socksAddr)
				}(inst)
				continue
			}
		}
		// 有任务绑定且隧道在跑：**永不按空闲回收**。
		//
		// 之前的"30 分钟/2 小时无流量就回收"是错的：任务的实际流量是 worker 子进程
		// 直连 socks 走的，进程内只能看到隧道内层字节计数，而 planner 一轮规划就要
		// 5~17 分钟、长命令/等远端响应本来就没有新字节；一旦被回收，隧道实例连同
		// 槽位被释放，worker 里烤死的 socks 地址就指向一条不存在的隧道——任务顶着
		// "出口 —"继续跑，所有请求 fail-closed（用户看到"任务在跑但 VPN 掉了"）。
		//
		// 资源代价是每条绑定任务占一个命名空间，这是可以接受的：任务结束/暂停后
		// 占用判定变成 false，下一个回收周期（15 分钟宽限）就会释放。
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
