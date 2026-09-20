// Package dnsmap 维护「域名 ↔ IP」的对应关系。
//
// 为什么需要它：我们在 **IP 包层**拦流量，包里没有域名。所以要在规则里写域名、
// 或者要把域名交给上游去解析（而不是本机先解析成 IP），都必须先能回答两个问题：
//
//	这个域名现在解析到哪些 IP？   → 用来把域名规则变成可匹配的 IP 集合
//	这个 IP 是哪個域名解析来的？ → 用来在连上游时把**域名**写进 SOCKS5/CONNECT
//
// 两个来源，优先级不同：
//
//	① 配置里写的域名规则（Priority 高）—— 规则说 main.his.com，那这个 IP 就叫这个名字
//	② 观察到的 DNS 响应（Priority 低）—— 将来支持通配域名时用（应用查过什么就知道什么）
package dnsmap

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// TTL 一个解析结果的保鲜期。内网域名一般变得不快，但改了 DNS 记录/换了机器要能跟上，
// 所以取一个折中：5 分钟。
const TTL = 5 * time.Minute

type entry struct {
	ips     []string // 该域名解析到的 IP（字符串形式，便于比较）
	at      time.Time
	prio    int
	failed  bool
	lastErr string
}

// Map 域名↔IP 映射表（并发安全）。
type Map struct {
	mu      sync.RWMutex
	byHost  map[string]*entry // 域名 → 解析结果
	byIP    map[string]string // IP → 域名（优先级高的胜出）
	prio    map[string]int    // IP → 当前记着的名字的优先级
	lookup  func(string) ([]string, error)
	nowFunc func() time.Time
}

// New 建一个映射表。lookup 为 nil 时用系统解析器（net.LookupHost）。
func New() *Map {
	return &Map{
		byHost:  map[string]*entry{},
		byIP:    map[string]string{},
		prio:    map[string]int{},
		lookup:  net.LookupHost,
		nowFunc: time.Now,
	}
}

// Priority：配置里的域名规则 > 观察到的 DNS。
const (
	PrioObserved = 10
	PrioRule     = 20
)

// Set 写入一个域名→IP 的解析结果（来自配置解析或观察到的 DNS）。
func (m *Map) Set(host string, ips []string, prio int) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	cp := make([]string, 0, len(ips))
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil {
			cp = append(cp, p.String())
		}
	}
	sort.Strings(cp)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.byHost[host] = &entry{ips: cp, at: m.nowFunc(), prio: prio}
	for _, ip := range cp {
		if cur, ok := m.prio[ip]; !ok || prio >= cur {
			m.byIP[ip] = host
			m.prio[ip] = prio
		}
	}
}

// MarkFailed 记一次解析失败（界面上要能说出"这个域名现在解析不到"）。
func (m *Map) MarkFailed(host, errText string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byHost[host] = &entry{at: m.nowFunc(), failed: true, lastErr: errText}
}

// Resolve 解析一个域名并写进表里（prio 决定它盖不盖得住别的来源）。
// 返回解析到的 IP（失败时返回 nil 与错误）。
func (m *Map) Resolve(host string, prio int) ([]string, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, nil
	}
	ips, err := m.lookup(host)
	if err != nil || len(ips) == 0 {
		msg := "解析不到"
		if err != nil {
			msg = err.Error()
		}
		m.MarkFailed(host, msg)
		return nil, err
	}
	m.Set(host, ips, prio)
	return ips, nil
}

// IPsFor 某域名当前解析到的 IP（不含过期判断：由调用方决定要不要刷新）。
func (m *Map) IPsFor(host string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e := m.byHost[normalizeHost(host)]
	if e == nil {
		return nil
	}
	return append([]string{}, e.ips...)
}

// NameFor 某个 IP 对应的域名（用来把域名交给上游）。
// 多个域名解析到同一个 IP 时，返回优先级最高的那个。
func (m *Map) NameFor(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.byIP[ip.String()]
	return h, ok
}

// HostStatus 一条域名的当前状态（界面/诊断用）。
type HostStatus struct {
	Host    string
	IPs     []string
	Age     time.Duration
	Stale   bool
	Failed  bool
	LastErr string
}

// Status 列出表里所有域名的状态（按域名排序，保证输出稳定）。
func (m *Map) Status() []HostStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]HostStatus, 0, len(m.byHost))
	now := m.nowFunc()
	for h, e := range m.byHost {
		out = append(out, HostStatus{
			Host: h, IPs: append([]string{}, e.ips...), Age: now.Sub(e.at),
			Stale: now.Sub(e.at) > TTL, Failed: e.failed, LastErr: e.lastErr,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Hosts 表里所有域名（引擎按它做定期刷新）。
func (m *Map) Hosts() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.byHost))
	for h := range m.byHost {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// IsHostname 一个目标写法是域名（而不是 IP/CIDR）。
//
// 认法：含字母、且不是 IP/CIDR。通配（`*.his.com`）也算域名 —— 它的匹配要靠
// 观察到的 DNS（见包注释），本包只负责"这个字符串该按名字处理"。
func IsHostname(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || net.ParseIP(s) != nil || strings.Contains(s, "/") {
		return false
	}
	return strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// IsWildcard 通配域名（*.x.com / main.*.com）。
func IsWildcard(s string) bool { return strings.Contains(s, "*") }

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// NewWithLookup 用自定义解析函数建表（测试用：不碰真实 DNS）。
func NewWithLookup(fn func(string) ([]string, error)) *Map {
	m := New()
	if fn != nil {
		m.lookup = fn
	}
	return m
}
