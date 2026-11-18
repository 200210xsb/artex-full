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
	dir      string // where generated configs and credential files live
	singbox  string // sing-box binary used as the in-namespace SOCKS server
	probeURL string // plain-HTTP endpoint that echoes the caller's IP

	mu     sync.Mutex
	items  map[string]*instance
	slots  map[int]bool // veth slot allocation, so subnets never collide
	logf   func(string, ...any)
	closed bool
}

// New returns a manager that keeps its generated files under dir. singbox may be
// empty, in which case the tunnel comes up without a SOCKS endpoint and Ensure
// fails with a clear error.
func New(dir, singbox string) *Manager {
	return &Manager{
		dir:      dir,
		singbox:  singbox,
		probeURL: "http://ip.3322.net",
		items:    map[string]*instance{},
		slots:    map[int]bool{},
		logf:     log.Printf,
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
		return "socks5://" + inst.socksAddr, nil
	}
	if err := m.bringUp(ctx, inst); err != nil {
		inst.state = StateError
		inst.lastErr = err.Error()
		return "", err
	}
	inst.state = StateUp
	inst.since = time.Now()
	inst.lastErr = ""
	go m.monitor(inst)
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
	slot      int
	closed    bool

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
			if inst.closed {
				return errors.New("closed")
			}
			return m.bringUp(ctx, inst)
		}()
		cancel()
		inst.mu.Lock()
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

// probe reports whether the tunnel currently carries traffic, and that the exit
// address is the one the profile promised.
func (m *Manager) probe(socksAddr string) error {
	if socksAddr == "" {
		return errors.New("隧道未就绪")
	}
	ip, err := probeVia(socksAddr, m.probeURL)
	if err != nil {
		return err
	}
	if ip == "" {
		return errors.New("出口未返回地址")
	}
	return nil
}

// normalizeShort renders config notes for logs.
func normalizeShort(notes []string) string {
	if len(notes) == 0 {
		return "无"
	}
	return strings.Join(notes, "；")
}
