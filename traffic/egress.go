package traffic

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 出口分流：为什么录制代理不能把每个请求都塞给全局出口代理
//
// 原来的行为是「配了全局出口代理 → 全部请求都从它出去」。全局出口通常是海外
// 节点，于是连纯国内的渗透目标也要绕一圈：实测同一个 POST，走代理 7.62s，
// 直连 0.078s，差 100 倍。
//
// 执行 Agent 的应对是绕开代理——命令里加 `curl --noproxy '*'`。而录制只在请求
// 经过 8788 时发生：一旦绕开，请求既不落库也无法绑定，漏洞就只能显示「流量
// 证据 0 条」。这不是 Agent 乱来，是「要速度」和「要证据」被做成了互斥选项。
//
// 解法是把分流下沉到录制代理内部：目标直连得通就直连出网，照样过 MITM、照样
// 落库；只有直连不通（典型是墙外站点）才交给全局出口。速度和证据不再二选一，
// 绕过代理也就失去了动机。
//
// 判断顺序（命中即返回）：
//  1. 运营者显式规则 traffic.egress_proxy  → 走出口（最高优先级，能覆盖下面一切）
//  2. 运营者显式规则 traffic.egress_direct → 直连
//  3. 目标是私网/回环地址 → 直连（丢给海外代理只会打不通，还会把内网地址交给对方）
//  4. 直连探测（带缓存）→ 通就直连，不通才走出口

const (
	// egressProbeTimeout 是一次直连可达性探测的上限。宁可把偶尔能直连的海外
	// 站点判成「需走出口」，也不让首个请求多等一秒以上——慢正是当初绕过代理
	// 的动机，分流自己不能变成新的慢点。
	egressProbeTimeout = 900 * time.Millisecond
	// egressOKTTL 缓存「直连可行」。这是一条相对稳定的事实，缓存久些省开销。
	egressOKTTL = 10 * time.Minute
	// egressFailTTL 缓存「直连不可行」。可能只是瞬时抖动（线路切换、临时丢包），
	// 所以比成功短，网络恢复后能自动回到直连而不必重启。
	egressFailTTL = 3 * time.Minute
	// egressProbeConcurrency 限同一时刻在飞探测数的上限。
	//
	// 这一条是拿事故换来的：录制代理的 upstream 回调在**每个连接**上同步跑，
	// 爬虫类流量（枚举 chunk 文件名那种）会在几秒内造出成百上千个新地址，每个
	// 都发起一次 TCP 探测。没有上限时探测扇出比排空快得多，连接与 goroutine
	// 在机器上堆积，RAM 3.6G / 2 核的小机器直接被拖死到 ssh 都进不去。
	egressProbeConcurrency = 8
	// egressProbeQueueWait 是排队等探测槽位的上限。等不到就按直连放行——此时
	// 宁可赌一把直连（国内目标九成能通），也不能让请求卡在这里把队列越堆越长。
	egressProbeQueueWait = 2 * time.Second
)

// egressRules 是运营者显式指定的分流后缀（小写、无前导点，如 "ys7.com"）。
type egressRules struct {
	direct []string
	proxy  []string
}

// dialProbe 是某个地址的直连可达性缓存。
//
// 用「一个 entry 一把锁」而不是给整张表上锁：探测要占住几百毫秒，全局锁会把
// 不相干的目标也堵在门上。同一地址的并发请求则会正确地排队等第一次探测结果，
// 避免同时打出一串 SYN。
type dialProbe struct {
	mu  sync.Mutex
	ok  bool
	exp time.Time
}

// SetEgressRules 设置显式分流名单，逗号/空白/换行分隔的 host 后缀，如
// "ys7.com, lenovo.com.cn"。空字符串表示不设该方向。改动立即生效（下一个
// 建连即按新规则走，不必重启也不用重建代理）。
//
// 两项都留空时完全依赖自动判断（私网直连 + 直连探测），这也是默认推荐的用法：
// 只有自动判断不合意时才需要手工干预。
func (t *Traffic) SetEgressRules(direct, proxy string) {
	t.egress.Store(&egressRules{
		direct: splitEgressList(direct),
		proxy:  splitEgressList(proxy),
	})
}

// EgressRules 返回当前生效的显式名单，供状态接口回显。
func (t *Traffic) EgressRules() (direct, proxy []string) {
	r := t.egress.Load()
	if r == nil {
		return nil, nil
	}
	return append([]string(nil), r.direct...), append([]string(nil), r.proxy...)
}

func splitEgressList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.ToLower(strings.Trim(strings.TrimSpace(f), "."))
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// preferDirect 判断这一次请求是否应该直连出网（true = 直连，false = 交给 upstream）。
//
// 仅在配置了全局出口代理时才会被问到；没有出口时上游本来就是 nil，直接拨号。
func (t *Traffic) preferDirect(req *http.Request) bool {
	addr := egressAddr(req)
	if addr == "" {
		return false
	}
	host := hostOnly(addr)

	if r := t.egress.Load(); r != nil {
		// 显式「走出口」优先：「这个目标必须从出口出去」通常意味着安全或合规
		// 要求（隐藏源 IP、固定出口地域），不能因为探测通了就改直连。
		if matchHostSuffix(host, r.proxy) {
			return false
		}
		if matchHostSuffix(host, r.direct) {
			return true
		}
	}

	// 私网 / 回环 / 链路本地：海外出口根本到不了，只能直连。
	if ip := net.ParseIP(host); ip != nil && nonPublicIP(ip) {
		return true
	}
	return t.probeDirect(addr)
}

// egressAddr 从请求里取出 "host:port"。CONNECT 请求的 URL 是 "example.com:443"
// 这种只有 Host 的形态，普通请求才带 Scheme，所以端口按 Scheme 缺省补。
func egressAddr(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	host := req.URL.Hostname()
	if host == "" {
		host = hostOnly(req.Host)
	}
	if host == "" {
		return ""
	}
	port := req.URL.Port()
	if port == "" {
		switch strings.ToLower(req.URL.Scheme) {
		case "http", "ws":
			port = "80"
		default:
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

// matchHostSuffix 按域名后缀匹配（"ys7.com" 命中 "open.ys7.com"，不命中
// "notys7.com"）。IP 目标要求完全相等。
func matchHostSuffix(host string, suffixes []string) bool {
	if len(suffixes) == 0 {
		return false
	}
	h := strings.ToLower(strings.Trim(host, "."))
	for _, s := range suffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// nonPublicIP 判断是否属于不该送去外部代理的地址段。
func nonPublicIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

// probeDirect 对地址做一次 TCP 握手，判断能否自己出网；结果按 TTL 缓存。
//
// 探测本身是「多打一个 SYN」，对目标无副作用；但对同一个地址只会发生一次
// （之后命中缓存），不会给目标造成额外压力。
func (t *Traffic) probeDirect(addr string) bool {
	entry, _ := t.probes.LoadOrStore(addr, &dialProbe{})
	p := entry.(*dialProbe)

	// 探测是唯一会对目标多打一个 SYN 的动作，也是唯一会占住调用方 goroutine
	// 的动作（upstream 回调是同步的）。用信号量把扇出按住：队列排不上就放行直连，
	// 不让请求陪着一起等。信号量要在地址锁之前拿——否则同地址的请求会攥着锁
	// 排队等一个根本轮不到自己的槽位，把这条地址彻底堵死。
	if t.probeSem != nil {
		select {
		case t.probeSem <- struct{}{}:
			defer func() { <-t.probeSem }()
		case <-time.After(egressProbeQueueWait):
			return true
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.exp.IsZero() && time.Now().Before(p.exp) {
		return p.ok
	}

	// 拨号带硬超时。ctx 只能打断「已经排上号的连接」，拦不住域名解析本身——
	// cgo resolver 的 DNS 查询不受 ctx 控制，所以这里额外用 goroutine 包一层，
	// 保证解析卡在哪，调用方都能在超时后走人，不至于把请求线程一起拖住。
	ctx, cancel := context.WithTimeout(context.Background(), egressProbeTimeout)
	defer cancel()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		ch <- dialResult{c, err}
	}()
	var res dialResult
	select {
	case res = <-ch:
	case <-ctx.Done():
		res = dialResult{err: ctx.Err()}
	}
	ok := res.err == nil
	if ok && res.conn != nil {
		res.conn.Close()
	}
	p.ok = ok
	if ok {
		p.exp = time.Now().Add(egressOKTTL)
	} else {
		p.exp = time.Now().Add(egressFailTTL)
	}
	return ok
}
