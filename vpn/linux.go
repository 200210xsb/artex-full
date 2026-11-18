//go:build linux

package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	netnsPrefix = "artexvpn"
	vethPrefix  = "aveth"
	socksPort   = 1080
	// tunnelWait 是等 openvpn 建链的上限。UDP 建链通常 5 秒内完成，TCP 稍慢；
	// 超过这个时间还连不上，多半是网络或账号问题，早点报错比一直挂着好。
	tunnelWait = 75 * time.Second
	// maxSlots 决定同时能起多少条隧道（每条一个 /24）。
	maxSlots = 200
)

// Supported reports whether this platform can host VPN tunnels.
func Supported() bool { return true }

// CleanupStale removes namespaces, veth pairs and NAT rules left behind by a
// previous process. Called once at startup: an unclean exit would otherwise leave
// occupied subnet slots and dangling routes that no code path owns any more.
func (m *Manager) CleanupStale() {
	out, err := exec.Command("ip", "netns", "list").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.HasPrefix(fields[0], netnsPrefix) {
				continue
			}
			if pids, perr := exec.Command("ip", "netns", "pids", fields[0]).Output(); perr == nil {
				for _, f := range strings.Fields(string(pids)) {
					if pid, e := strconv.Atoi(f); e == nil && pid > 0 {
						_ = syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			}
			_ = exec.Command("ip", "netns", "del", fields[0]).Run()
			m.logf("[vpn] 清理上次遗留的命名空间 %s", fields[0])
		}
	}
	links, err := exec.Command("ip", "-brief", "link", "show").Output()
	if err == nil {
		for _, line := range strings.Split(string(links), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			name := strings.SplitN(fields[0], "@", 2)[0]
			if strings.HasPrefix(name, vethPrefix) {
				_ = exec.Command("ip", "link", "del", name).Run()
			}
		}
	}
	// NAT/FORWARD 规则按子网逐条加，这里按前缀整体清。
	for _, table := range []string{"nat", "filter"} {
		args := []string{"-t", table, "-S"}
		if table == "filter" {
			args = []string{"-S", "FORWARD"}
		}
		if rules, rerr := exec.Command("iptables", args...).Output(); rerr == nil {
			for _, rule := range strings.Split(string(rules), "\n") {
				if !strings.Contains(rule, "10.201.") {
					continue
				}
				del := strings.Replace(rule, "-A ", "-D ", 1)
				_ = exec.Command("iptables", append(append([]string{"-t", table}, strings.Fields(del)...))...).Run()
			}
		}
	}
}

// bringUp 建命名空间、拉 openvpn、钉路由、起隧道内 socks，并校验真实出口。
// 调用方持有 inst.mu。
func (m *Manager) bringUp(ctx context.Context, inst *instance) error {
	p := inst.profile
	if m.singbox == "" {
		return errors.New("未找到 sing-box，无法在隧道内提供 SOCKS 出口")
	}

	dir := filepath.Join(m.dir, fmt.Sprint(p.ID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	authPath := filepath.Join(dir, "auth.txt")
	if err := os.WriteFile(authPath, []byte(p.Username+"\n"+p.Password+"\n"), 0o600); err != nil {
		return fmt.Errorf("写入账号文件失败: %w", err)
	}
	cfg, notes := Normalize(p.Raw, authPath)
	inst.notes = notes
	cfgPath := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}
	serverHost, hasRemote := RemoteAddr(p.Raw)
	if !hasRemote {
		return errors.New("配置里没有 remote 行，无法建立隧道")
	}

	slot, hostIP, nsIP, err := m.allocSlot()
	if err != nil {
		return err
	}
	inst.slot, inst.hostIP, inst.nsIP = slot, hostIP, nsIP
	ns := fmt.Sprintf("%s%d", netnsPrefix, p.ID)
	veth := fmt.Sprintf("%s%d", vethPrefix, p.ID)

	ext, err := defaultIface()
	if err != nil {
		m.freeSlot(slot)
		return err
	}
	// 上一次异常退出可能留下同名命名空间/规则：用临时句柄清掉，不能拿 inst 去清，
	// 那会把刚算好的名字一起抹掉。
	m.destroyNS(&instance{netns: ns, veth: veth, hostIP: hostIP, extIface: ext})

	inst.netns, inst.veth, inst.extIface = ns, veth, ext

	m.logf("[vpn] %s 建隧道：ns=%s veth=%s %s/24 出网=%s（%s）", p.Name, inst.netns, inst.veth, hostIP, ext, normalizeShort(notes))
	if err := setupNetns(inst, ext); err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return err
	}

	// 引导路由：openvpn 必须先够到 VPN 服务器。
	if err := runIP(inst.netns, "route", "add", "default", "via", hostIP); err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return fmt.Errorf("加引导路由失败: %w", err)
	}

	logPath := filepath.Join(dir, "openvpn.log")
	pidPath := filepath.Join(dir, "openvpn.pid")
	_ = os.Remove(pidPath)
	if err := startOpenVPN(ctx, inst, cfgPath, logPath, pidPath); err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return err
	}

	if err := waitTunnel(ctx, inst, logPath); err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return err
	}

	// 无论服务端有没有推 redirect-gateway，出口必须覆盖全部流量：补齐两条
	// 半区路由，再删掉引导默认路由（这一步同时是 fail-closed 的关键）。
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if !routeExists(inst.netns, half) {
			if err := runIP(inst.netns, "route", "add", half, "dev", "tun0"); err != nil {
				m.logf("[vpn] %s 补路由 %s 失败: %v", p.Name, half, err)
			}
		}
	}
	// openvpn 退出时会把它自己加的服务器 host 路由一起撤掉；显式钉一条，
	// 掉线后才能自愈重连。
	_ = runIP(inst.netns, "route", "replace", serverHost, "via", hostIP)
	_ = runIP(inst.netns, "route", "del", "default", "via", hostIP)

	if err := m.startSocks(inst, dir); err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return err
	}

	addr := net.JoinHostPort(nsIP, fmt.Sprint(socksPort))
	if err := waitPort(addr, 15*time.Second); err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return fmt.Errorf("隧道内 SOCKS 未就绪: %w", err)
	}

	ip, err := probeVia(addr, m.probeURL)
	if err != nil {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return fmt.Errorf("出口探测失败: %w", err)
	}
	if want := strings.TrimSpace(p.ExpectEgress); want != "" && ip != want {
		m.destroyNS(inst)
		m.freeSlot(slot)
		return fmt.Errorf("出口 IP 不符：实际 %s，预期 %s", ip, want)
	}

	inst.socksAddr = addr
	inst.egressIP = ip
	m.logf("[vpn] %s 就绪：socks5://%s 出口 %s", p.Name, addr, ip)
	return nil
}

// teardown 收掉一条隧道的一切痕迹。调用方持有 inst.mu。
func (m *Manager) teardown(inst *instance) {
	m.destroyNS(inst)
	if inst.slot > 0 {
		m.freeSlot(inst.slot)
		inst.slot = 0
	}
	inst.socksAddr = ""
	inst.egressIP = ""
}

// destroyNS 杀掉命名空间里的进程、删除命名空间/veth 和 NAT 规则。
func (m *Manager) destroyNS(inst *instance) {
	if inst.socksCmd != nil && inst.socksCmd.Process != nil {
		_ = inst.socksCmd.Process.Kill()
		_, _ = inst.socksCmd.Process.Wait()
		inst.socksCmd = nil
	}
	if inst.netns != "" {
		// openvpn 自己 daemonize 了，PID 文件不可靠；直接枚举命名空间里的进程。
		if out, err := exec.Command("ip", "netns", "pids", inst.netns).Output(); err == nil {
			for _, f := range strings.Fields(string(out)) {
				if pid, err := strconv.Atoi(f); err == nil && pid > 0 {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
		_ = exec.Command("ip", "netns", "del", inst.netns).Run()
		inst.netns = ""
	}
	if inst.veth != "" {
		_ = exec.Command("ip", "link", "del", inst.veth).Run()
		inst.veth = ""
	}
	if inst.hostIP != "" && inst.extIface != "" {
		netw := subnetOf(inst.hostIP)
		_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", netw, "-o", inst.extIface, "-j", "MASQUERADE").Run()
		_ = exec.Command("iptables", "-D", "FORWARD", "-s", netw, "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-D", "FORWARD", "-d", netw, "-j", "ACCEPT").Run()
	}
}

// allocSlot 分配一个 veth 子网槽位。
func (m *Manager) allocSlot() (slot int, hostIP, nsIP string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for s := 1; s <= maxSlots; s++ {
		if m.slots[s] {
			continue
		}
		m.slots[s] = true
		return s, fmt.Sprintf("10.201.%d.1", s), fmt.Sprintf("10.201.%d.2", s), nil
	}
	return 0, "", "", errors.New("同时在线的 VPN 隧道已达上限")
}

func (m *Manager) freeSlot(slot int) {
	m.mu.Lock()
	delete(m.slots, slot)
	m.mu.Unlock()
}

// setupNetns 建命名空间、veth 对和 NAT（让 openvpn 能先够到服务器）。
func setupNetns(inst *instance, ext string) error {
	if err := exec.Command("ip", "netns", "add", inst.netns).Run(); err != nil {
		return fmt.Errorf("创建 netns 失败: %w", err)
	}
	peer := inst.veth + "-ns"
	if err := exec.Command("ip", "link", "add", inst.veth, "type", "veth", "peer", "name", peer).Run(); err != nil {
		return fmt.Errorf("创建 veth 失败: %w", err)
	}
	if err := exec.Command("ip", "link", "set", peer, "netns", inst.netns).Run(); err != nil {
		return fmt.Errorf("veth 移入 netns 失败: %w", err)
	}
	addrs := [][]string{
		{"ip", "addr", "add", inst.hostIP + "/24", "dev", inst.veth},
		{"ip", "link", "set", inst.veth, "up"},
	}
	for _, a := range addrs {
		if out, err := exec.Command(a[0], a[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("配置 veth 失败: %v %s", err, strings.TrimSpace(string(out)))
		}
	}
	for _, a := range [][]string{
		{"ip", "netns", "exec", inst.netns, "ip", "addr", "add", inst.nsIP + "/24", "dev", peer},
		{"ip", "netns", "exec", inst.netns, "ip", "link", "set", peer, "up"},
		{"ip", "netns", "exec", inst.netns, "ip", "link", "set", "lo", "up"},
	} {
		if out, err := exec.Command(a[0], a[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("配置 netns 网卡失败: %v %s", err, strings.TrimSpace(string(out)))
		}
	}
	netw := subnetOf(inst.hostIP)
	for _, a := range [][]string{
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", netw, "-o", ext, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-s", netw, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-d", netw, "-j", "ACCEPT"},
	} {
		if out, err := exec.Command(a[0], a[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("配置 NAT 失败: %v %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func startOpenVPN(ctx context.Context, inst *instance, cfgPath, logPath, pidPath string) error {
	args := []string{"netns", "exec", inst.netns, "openvpn",
		"--config", cfgPath,
		"--log", logPath,
		"--writepid", pidPath,
		"--daemon",
	}
	cmd := exec.CommandContext(ctx, "ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("启动 openvpn 失败: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitTunnel 等 tun0 拿到地址、且出口路由就绪。
func waitTunnel(ctx context.Context, inst *instance, logPath string) error {
	deadline := time.Now().Add(tunnelWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		if tunReady(inst.netns) {
			return nil
		}
	}
	tail := ""
	if b, err := os.ReadFile(logPath); err == nil {
		tail = lastLines(string(b), 6)
	}
	return fmt.Errorf("隧道 %s 内未建立（日志尾部：%s）", tunnelWait, tail)
}

// startSocks 在命名空间内起 sing-box，只做一件事：把 SOCKS 请求直接发出去
// （命名空间里的默认路由已经是隧道）。
func (m *Manager) startSocks(inst *instance, dir string) error {
	cfg := fmt.Sprintf(`{"log":{"level":"warn"},
 "inbounds":[{"type":"mixed","listen":%q,"listen_port":%d}],
 "outbounds":[{"type":"direct","tag":"direct"}]}`, inst.nsIP, socksPort)
	cfgPath := filepath.Join(dir, "socks.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("写入 SOCKS 配置失败: %w", err)
	}
	bin := m.singbox
	if bin == "" {
		return errors.New("未找到 sing-box")
	}
	cmd := exec.Command("ip", "netns", "exec", inst.netns, bin, "run", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动隧道内 SOCKS 失败: %w", err)
	}
	inst.socksCmd = cmd
	return nil
}

func tunReady(ns string) bool {
	// 必须用 -o（每条一行、带 "inet " 前缀）：-brief 的输出里没有 inet 字样，
	// 用它做过就绪判断会永远为假，隧道明明起来了也报超时。
	out, err := exec.Command("ip", "netns", "exec", ns, "ip", "-o", "-4", "addr", "show", "dev", "tun0").Output()
	if err != nil || !strings.Contains(string(out), "inet ") {
		return false
	}
	return routeExists(ns, "0.0.0.0/1") || routeExists(ns, "default")
}

func routeExists(ns, dst string) bool {
	out, err := exec.Command("ip", "netns", "exec", ns, "ip", "route", "show", dst).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

func runIP(ns string, args ...string) error {
	all := append([]string{"netns", "exec", ns, "ip"}, args...)
	out, err := exec.Command("ip", all...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitPort(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("端口 %s 在 %s 内未监听", addr, d)
}

// probeVia 经 SOCKS 取一次出口地址。返回的就是对端看到的来源 IP。
func probeVia(socksAddr, url string) (string, error) {
	dialer, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	if err != nil {
		return "", err
	}
	client := &httpClient{dial: dialer.Dial}
	return client.get(url)
}

func defaultIface() (string, error) {
	out, err := exec.Command("ip", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return "", fmt.Errorf("识别出网网卡失败: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", errors.New("识别出网网卡失败")
}

func subnetOf(hostIP string) string {
	if i := strings.LastIndexByte(hostIP, '.'); i > 0 {
		return hostIP[:i] + ".0/24"
	}
	return hostIP
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
