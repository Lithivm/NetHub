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
	"fmt"
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
	ttl     time.Duration // 0 = 用默认 TTL（观测到的 DNS 会带真实 TTL）
	failed  bool
	lastErr string
}

// Map 域名↔IP 映射表（并发安全）。
type Map struct {
	mu      sync.RWMutex
	byHost  map[string]*entry   // 域名 → 解析结果
	byIP    map[string][]string // IP → 所有映射到它的域名（一个 IP 常被多个名字共用）
	lookup  func(string) ([]string, error)
	nowFunc func() time.Time
}

// New 建一个映射表。lookup 为 nil 时用系统解析器（net.LookupHost）。
func New() *Map {
	return &Map{
		byHost:  map[string]*entry{},
		byIP:    map[string][]string{},
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
//
// 优先级只升不降：规则里写的域名（PrioRule）不会被随后观察到的 DNS 覆盖 ——
// 观察是一路持续写入的，不挡一下就会把规则解析结果冲成低优先级的。
func (m *Map) Set(host string, ips []string, prio int) {
	m.SetWithTTL(host, ips, prio, 0)
}

// SetWithTTL 同 Set，但带上这个结果的保鲜期（观测到的 DNS 会用应答里真实的 TTL）。
func (m *Map) SetWithTTL(host string, ips []string, prio int, ttl time.Duration) {
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
	if old := m.byHost[host]; old != nil && old.prio > prio {
		return // 低优先级来源不许覆盖高优先级
	}
	m.byHost[host] = &entry{ips: cp, at: m.nowFunc(), prio: prio, ttl: ttl}
	m.rebuildIndex()
}

// MarkFailed 记一次解析失败（界面上要能说出"这个域名现在解析不到"）。
func (m *Map) MarkFailed(host, errText string) {
	m.MarkFailedPrio(host, errText, PrioRule)
}

// MarkFailedPrio 同 MarkFailed，但可指定来源优先级（同样只升不降）。
func (m *Map) MarkFailedPrio(host, errText string, prio int) {
	host = normalizeHost(host)
	if host == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.byHost[host]; old != nil && old.prio > prio {
		return
	}
	m.byHost[host] = &entry{at: m.nowFunc(), prio: prio, failed: true, lastErr: errText}
	m.rebuildIndex()
}

// Remove 删掉一个域名（过期清理用）。
func (m *Map) Remove(host string) {
	host = normalizeHost(host)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byHost[host]; !ok {
		return
	}
	delete(m.byHost, host)
	m.rebuildIndex()
}

// Expired 列出**已经过期**的域名（只报观测来源的：规则里的域名由引擎定期重解析）。
//
// 为什么必须清理：观测到的名字对应的 IP 会被加进内核过滤器，
// 不摘掉的话过滤器只会越滚越大（客户机连跑几个月的场景）。
func (m *Map) Expired() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.nowFunc()
	var out []string
	for h, e := range m.byHost {
		if e.prio != PrioObserved || e.failed {
			continue
		}
		if now.Sub(e.at) > e.ttlOrDefault() {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// rebuildIndex 重建 IP → 域名 的反查索引（调用方必须已持锁）。
//
// 每次写入都整表重建：写入是 DNS 速率（几十次/秒量级），而这样能彻底避免
// “删条目时索引残留”这类难查的 bug。
func (m *Map) rebuildIndex() {
	byIP := make(map[string][]string, len(m.byIP))
	for h, e := range m.byHost {
		if e.failed || len(e.ips) == 0 {
			continue
		}
		for _, ip := range e.ips {
			byIP[ip] = append(byIP[ip], h)
		}
	}
	for ip := range byIP {
		sort.Strings(byIP[ip])
	}
	m.byIP = byIP
}

func (e *entry) ttlOrDefault() time.Duration {
	if e.ttl > 0 {
		return e.ttl
	}
	return TTL
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
// 多个域名解析到同一个 IP 时，返回优先级最高的那个（同级取名字序最小的，保证稳定）。
func (m *Map) NameFor(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := m.byIP[ip.String()]
	best, bestPrio := "", -1
	for _, h := range names {
		e := m.byHost[h]
		if e == nil {
			continue
		}
		if e.prio > bestPrio {
			best, bestPrio = h, e.prio
		}
	}
	return best, best != ""
}

// NamesFor 某个 IP 当前关联到的**所有**域名。
//
// 通配域名（*.his.com）匹配时必须看全部名字：一个 IP 常被多个名字共用，
// 只看优先级最高的那个会漏掉通配规则该命中的情况。
func (m *Map) NamesFor(ip net.IP) []string {
	if ip == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := m.byIP[ip.String()]
	if len(names) == 0 {
		return nil
	}
	return append([]string{}, names...)
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
			Stale: now.Sub(e.at) > e.ttlOrDefault(), Failed: e.failed, LastErr: e.lastErr,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Snapshot 当前所有“有解析结果”的域名 → IP（不含失败/过期的）。
//
// 给引擎用：它要把这些名字连同规则里的域名一起交给 rules.SetHostIPs，
// 通配域名（*.his.com）就是从这里挑出命中的那几个。
func (m *Map) Snapshot() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]string, len(m.byHost))
	for h, e := range m.byHost {
		if e.failed || len(e.ips) == 0 {
			continue
		}
		out[h] = append([]string{}, e.ips...)
	}
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

// WildcardSuffix 校验并归一化一个通配域名，返回可用来做后缀匹配的串。
//
//	*.his.com  →  ".his.com"
//
// **只接受 `*.域名` 这一种写法**：`his.*.com`、`*`、`*.` 这类拒绝并给出原因 ——
// 规则要能被人工一眼看懂，中间星号的语义（DNS 里星号只代表一个标签）跟直觉差太远。
func WildcardSuffix(s string) (string, error) {
	raw := s
	s = normalizeHost(s)
	if !strings.HasPrefix(s, "*.") {
		return "", fmt.Errorf("通配域名只支持 `*.域名` 这种写法（例如 *.his.com），"+
			"不支持写在中间或只有 * —— 收到的是 %q", strings.TrimSpace(raw))
	}
	suffix := s[1:] // 留着前导点：靠它保证 *.his.com 不匹配 his.com 本身
	rest := suffix[1:]
	if rest == "" {
		return "", fmt.Errorf("通配域名 %q 后面没有域名", strings.TrimSpace(raw))
	}
	for _, label := range strings.Split(rest, ".") {
		if label == "" {
			return "", fmt.Errorf("通配域名 %q 里有空的标签（连续的点或多写的点）", strings.TrimSpace(raw))
		}
		if strings.ContainsAny(label, "* /\\") {
			return "", fmt.Errorf("通配域名 %q 的标签 %q 里有非法字符", strings.TrimSpace(raw), label)
		}
	}
	return suffix, nil
}

// MatchWildcard 用 WildcardSuffix 得到的后缀去匹配一个域名。
//
//	MatchWildcard(".his.com", "a.his.com")     → true
//	MatchWildcard(".his.com", "a.b.his.com")   → true（多层也认，规则写法要符合直觉）
//	MatchWildcard(".his.com", "his.com")       → false（不含裸域名自身，与证书通配一致）
//	MatchWildcard(".his.com", "x.his.com.evil")→ false
func MatchWildcard(suffix, host string) bool {
	if suffix == "" {
		return false
	}
	h := normalizeHost(host)
	return len(h) > len(suffix) && strings.HasSuffix(h, suffix)
}

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
