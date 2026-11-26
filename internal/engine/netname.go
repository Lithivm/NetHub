package engine

import (
	"fmt"
	"net"
	"nethub/internal/dnsmap"
	"sort"
	"strings"
	"time"

	"nethub/internal/config"
	"nethub/internal/proc"
	"nethub/internal/rules"
	"nethub/internal/upstream"
)

// ───────── 本机网络变化（A16：带 LocalNets 条件的规则靠它生效/失效）─────────

// localNetLoop 定期把本机地址告诉规则层。
// 为什么需要循环而不是只做一次：笔记本会在“公司网/家里/热点”之间切换，
// 插拔网线或用 WLAN 都会变地址；规则要跟着变（否则该走隧道的流量会直连）。
func (e *Engine) localNetLoop() {
	defer e.wg.Done()
	last := ""
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		ips := localIPv4s()
		sig := ipsKey(ips)
		if sig != last {
			e.ruleSet().SetLocalIPs(ips)
			if last != "" {
				// 真的变了（唤醒/插拔网线/换 Wi-Fi）→ 记下时刻，DNS 自检据此让一步。
				// 首次采样**不算**变化：那是“我们刚开始看”，而启动那一下正是最该自检的时候
				// （那里另外留了 3 秒给本地 DNS 栈）。
				e.netChangedAt.Store(time.Now().UnixNano())
				// 只在真的变了的时候说一句，别刷日志
				e.bus.Info("本机网络变化：现在 %s（带本机网段条件的规则会据此生效/失效）", sig)
			}
			last = sig
		}
		select {
		case <-e.done:
			return
		case <-tick.C:
		}
	}
}

// localIPv4s 本机当前的非回环 IPv4（只取已启用且有地址的网卡）。
func localIPv4s() []net.IP {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := it.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					out = append(out, v4)
				}
			}
		}
	}
	return out
}

// ipsKey 给一组地址排个序拼成短字符串（用于“有没有变化”的比较与日志）。
func ipsKey(ips []net.IP) string {
	ss := make([]string, 0, len(ips))
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	sort.Strings(ss)
	return strings.Join(ss, ", ")
}

// procNewResolver 供测试直接造一个进程解析器（生产路径由 New 注入）。
func procNewResolver() *proc.Resolver { return proc.NewResolver() }

// ───────────────────────── 域名规则（名字↔IP）─────────────────────────

// resolveHostTargets 把规则里的域名解析成 IP，填进规则集（供匹配与过滤器用）。
//
// 解析不到的域名**不阻断启动**（DNS 一时不可用很常见）：那条规则暂时不匹配任何东西，
// 界面上能看到它没解析出来。warnChange 为真时（定期刷新）把"IP 变了"说出来，
// 因为过滤器在启动时就装配好了，新 IP 要重启服务才生效。
func (e *Engine) resolveHostTargets(warnChange bool) {
	e.seedFromHosts()
	hosts := e.ruleSet().HostTargets()
	if len(hosts) == 0 {
		// 没有具体域名要解析：但可能有通配规则，仍要把观察到的名字交下去
		e.applyHostIPs()
		return
	}
	var unresolved []string
	for _, h := range hosts {
		before := e.names.IPsFor(h)
		ips, err := e.names.Resolve(h, dnsmap.PrioRule)
		if err != nil || len(ips) == 0 {
			unresolved = append(unresolved, h)
			continue
		}
		if warnChange && len(before) > 0 && !sameStrSet(before, ips) {
			e.bus.Warn("域名 %s 的 IP 变了（%v → %v）—— 过滤器在启动时装配，重启服务后新 IP 才生效",
				h, before, ips)
		}
	}
	e.applyHostIPs()
	if len(unresolved) > 0 {
		// 解析不到的域名规则 = **一条也不拦**（不猜、也不退化成拦全部）。
		// 启动时也必须说一声，否则“规则配了、什么都没拦、日志也不说”就是静默失效。
		if warnChange {
			e.bus.Warn("这些域名规则暂时解析不到，暂时不匹配任何流量：%v", unresolved)
		} else {
			e.bus.Warn("域名规则解析不到，这条规则目前不匹配任何流量：%v（本机 DNS 或 hosts 里没有这些名字？）", unresolved)
		}
	}
}

// seedFromHosts 把 hosts 托管里的条目先灌进名字表。
//
// 为什么要这一步：hosts 里的名字**根本不会产生 DNS 报文**（系统直接查文件），
// 而我们学名字靠的是嗅探 DNS 应答 —— 不灌的话，“内网域名全靠 hosts 写死”
// 这种最典型的场景下，通配域名将什么都匹配不到。
// TTL 给长一点（每轮 nameLoop 都会重新灌一遍，过期清理不会误删）。
func (e *Engine) seedFromHosts() {
	if e.cfg == nil {
		return
	}
	hosts := e.cfg.HostsCopy()
	if !hosts.Manage {
		return
	}
	for _, line := range hosts.Entries {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if net.ParseIP(f[0]).To4() == nil {
			continue
		}
		for _, name := range f[1:] {
			if dnsmap.IsHostname(name) && !dnsmap.IsWildcard(name) {
				e.names.SetWithTTL(name, []string{f[0]}, dnsmap.PrioObserved, 12*time.Hour)
			}
		}
	}
}

// applyHostIPs 把“名字表里的全部名字（含观察到的）”交给**当前**规则集。
func (e *Engine) applyHostIPs() { e.applyHostIPsTo(e.ruleSet()) }

// applyHostIPsTo 把“名字表里的全部名字（含观察到的）”交给指定规则集。
//
// 通配域名（*.example.com）就是靠这一步才能命中：规则层从 map 里挑出后缀匹配的名字，
// 把它们当前解析到的 IP 填进 hostIPs —— 这决定了过滤器会不会拦住这些 IP。
//
// 热重载要用它把学到的名字**继承**给新规则集（否则通配规则会“忘掉”已观察到的名字）。
func (e *Engine) applyHostIPsTo(s *rules.Set) {
	byHost := map[string][]*net.IPNet{}
	for h, ips := range e.names.Snapshot() {
		var nets []*net.IPNet
		for _, str := range ips {
			if ip := net.ParseIP(str); ip != nil && ip.To4() != nil {
				nets = append(nets, &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)})
			}
		}
		if len(nets) > 0 {
			byHost[h] = nets
		}
	}
	s.SetHostIPs(byHost)
}

// nameLoop 定期刷新域名解析（内网 DNS 记录会变；不刷新就一直是启动那一份）。
func (e *Engine) nameLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(dnsmap.TTL)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			e.resolveHostTargets(true)
			e.pruneNames()
			e.sweepFakeIP()
		}
	}
}

// pruneNames 掉过期的**观察结果**（规则里写的域名由 resolveHostTargets 重新解析）。
//
// 为什么必须做：观察到的名字对应的 IP 会进动态过滤器，不摘掉的话
// 过滤器只会越滚越大、而且会把早就不用的域名的旧 IP 一直当成“要接管的目标”。
func (e *Engine) pruneNames() {
	exp := e.names.Expired()
	if len(exp) == 0 {
		return
	}
	for _, h := range exp {
		e.names.Remove(h)
	}
	e.bus.Debug("name.expire: count=%d names=%v", len(exp), exp)
	e.applyHostIPs()
	e.onWildcardsChanged()
}

// HostResolveView 域名解析状态（界面/诊断页看"这个域名现在指到哪"）。
type HostResolveView struct {
	Host    string   `json:"host"`
	IPs     []string `json:"ips"`
	Age     string   `json:"age"`
	Stale   bool     `json:"stale"`
	Failed  bool     `json:"failed"`
	LastErr string   `json:"lastErr"`
}

// HostResolves 列出所有域名规则的解析状态。
func (e *Engine) HostResolves() []HostResolveView {
	if e.names == nil {
		return nil
	}
	st := e.names.Status()
	out := make([]HostResolveView, 0, len(st))
	for _, s := range st {
		out = append(out, HostResolveView{
			Host: s.Host, IPs: s.IPs, Age: s.Age.Truncate(time.Second).String(),
			Stale: s.Stale, Failed: s.Failed, LastErr: s.LastErr,
		})
	}
	return out
}

// NameForIP 这个 IP 当前对应哪个域名（界面解释"这条连接为什么走了隧道"用）。
func (e *Engine) NameForIP(ip net.IP) string {
	if e.names == nil {
		return ""
	}
	n, _ := e.names.NameFor(ip)
	return n
}

// dialViaName 把**域名**交给上游解析并连接（而不是本机先解析成 IP）。
//
// 为什么单独一条路（不走预热池/竞速）：那两套是围绕"目标 IP"建的，
// 而这里的目标是名字 —— 混进去只会把两条路径都弄乱；域名规则的连接量本来也小。
func (e *Engine) dialViaName(ch config.Chain, host string, dport uint16) (net.Conn, error) {
	raws := e.cfg.UpstreamsResolved(ch)
	if len(raws) == 0 {
		return nil, fmt.Errorf("链 %s 没有配置上游", ch.Name)
	}
	per := e.cfg.DialTimeoutDur()
	var lastErr error
	for _, raw := range raws {
		u, err := upstream.Parse(raw)
		if err != nil {
			lastErr = err
			continue
		}
		conn, err := u.DialHost(host, dport, per)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用上游")
	}
	return nil, fmt.Errorf("把域名 %s 交给上游解析失败: %w", host, lastErr)
}
