// Package rules 负责"目标是哪条链"的判定。
//
// 判定维度：目标 IP / CIDR。这是刻意的设计决定——
// 内网域名通常已在系统 hosts 里被映射成内网 IP（app.your-domain.com → 10.0.0.10），
// 所以按 IP 段匹配就覆盖了全部已知目标，不需要解析 TLS SNI 或 DNS。
package rules

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Action 规则命中后的动作。
//
// 为什么用枚举而不是几个 bool：动作以后还会加（比如链内多发/负载均衡），
// 用两个 bool 很容易出现“又直连又阻断”这种没有意义的组合。
type Action int

const (
	ActionChain  Action = iota // 走链（隧道）
	ActionDirect               // 直连（原样放行）
	ActionBlock                // 阻断（丢弃 + 尽力回 RST）
)

// String 日志/界面用的人话。
func (a Action) String() string {
	switch a {
	case ActionDirect:
		return "直连"
	case ActionBlock:
		return "阻断"
	default:
		return "隧道"
	}
}

// Route 一条路由规则：命中 Targets（任一 IP 或 CIDR）+ Ports 的流量按 Action 处理。
// 形状与 config.Route 一致：一个动作挂一组目标（对齐 Proxifier 的规则）。
//
// Direct / Block 由调用方根据保留链名（config.DirectChain / config.BlockChain）映射过来
// —— 规则层不认识配置层的常量。
type Route struct {
	Name    string   `yaml:"name,omitempty" json:"name,omitempty"`
	Targets []string `yaml:"targets" json:"targets"`
	Ports   []string `yaml:"ports,omitempty" json:"ports,omitempty"`
	Chain   string   `yaml:"chain" json:"chain"`
	Action  Action   `yaml:"-" json:"-"`

	nets  []*net.IPNet // 解析缓存，与 Targets 一一对应
	ports []portRange  // 解析缓存，与 Ports 一一对应；留空 = 任意端口
}

// Label 日志/报错里的简短指代。
func (r Route) Label() string {
	ts := strings.Join(r.Targets, ", ")
	if len(r.Ports) > 0 {
		ts += "  端口 " + strings.Join(r.Ports, ",")
	}
	if n := strings.TrimSpace(r.Name); n != "" {
		return n + "：" + ts
	}
	return ts
}

// Matches 目标命中 **且** 端口命中即算该规则命中（Ports 留空 = 端口不参与判定）。
func (r Route) Matches(ip net.IP, port uint16) bool {
	if !r.matchesIP(ip) {
		return false
	}
	if len(r.ports) == 0 {
		return true
	}
	for _, pr := range r.ports {
		if port >= pr.first && port <= pr.last {
			return true
		}
	}
	return false
}

// MatchesTarget 只看目标（不管端口）—— 界面上“只填了 IP”的查询用。
func (r Route) MatchesTarget(ip net.IP) bool { return r.matchesIP(ip) }

// Prefix 该规则目标里最长的前缀长度（/32 → 32）。用来做“最具体优先”排序。
func (r Route) Prefix() int {
	best := 0
	for _, n := range r.nets {
		if ones, _ := n.Mask.Size(); ones > best {
			best = ones
		}
	}
	return best
}

// Explain 解释一个连接目标会命中谁：
//
//	matched  —— 生效的规则下标（-1 = 都不命中，按“不拦截”处理）
//	shadowed —— 也匹配、但排在后面永远轮不到的规则下标
//
// ignorePort 为真时只看目标（界面上没填端口的情况）。
func (s *Set) Explain(ip net.IP, port uint16, ignorePort bool) (matched int, shadowed []int, ok bool) {
	v4 := ip.To4()
	if v4 == nil {
		return -1, nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	matched = -1
	for i := range s.routes {
		hit := s.routes[i].Matches(v4, port)
		if ignorePort {
			hit = s.routes[i].MatchesTarget(v4)
		}
		if !hit {
			continue
		}
		if matched < 0 {
			matched = i
			continue
		}
		shadowed = append(shadowed, i)
	}
	return matched, shadowed, matched >= 0
}

// matchesIP 任一目标命中即算该目标的命中（端口不参与）。
func (r Route) matchesIP(ip net.IP) bool {
	for _, n := range r.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Set 是一组有序规则（先匹配先生效，和 Proxifier 语义一致）。
type Set struct {
	mu     sync.RWMutex
	routes []Route
}

func New() *Set { return &Set{} }

// Load 校验并载入规则。任一条非法就整体失败（避免半生效状态）。
func (s *Set) Load(routes []Route) error {
	out := make([]Route, 0, len(routes))
	for i, r := range routes {
		r.Name = strings.TrimSpace(r.Name)
		r.Chain = strings.TrimSpace(r.Chain)
		if len(r.Targets) == 0 {
			return fmt.Errorf("第 %d 条规则%s: 至少要有一个目标", i+1, r.Label())
		}
		if r.Chain == "" {
			return fmt.Errorf("第 %d 条规则%s: chain 为空", i+1, r.Label())
		}
		nets := make([]*net.IPNet, 0, len(r.Targets))
		for j, t := range r.Targets {
			t = strings.TrimSpace(t)
			if t == "" {
				return fmt.Errorf("第 %d 条规则%s: 第 %d 个目标为空", i+1, r.Label(), j+1)
			}
			ipnet, err := parseTarget(t)
			if err != nil {
				return fmt.Errorf("第 %d 条规则%s: 目标 %s: %w", i+1, r.Label(), t, err)
			}
			nets = append(nets, ipnet)
		}
		ports := make([]portRange, 0, len(r.Ports))
		for _, p := range r.Ports {
			pr, perr := parsePortRange(p)
			if perr != nil {
				return fmt.Errorf("第 %d 条规则%s: %v", i+1, r.Label(), perr)
			}
			ports = append(ports, pr)
		}
		r.ports, r.nets = ports, nets
		out = append(out, r)
	}
	s.mu.Lock()
	s.routes = out
	s.mu.Unlock()
	return nil
}

// Match 返回命中的链名与动作（ActionDirect / ActionBlock 时链名无意义）。
// 第三个返回值表示是否命中。
// 每收到一个包都要调一次，所以这里不复制 Route（只回传字符串/枚举 + 布尔）。
func (s *Set) Match(ip net.IP, port uint16) (chain string, act Action, ok bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", ActionChain, false // 目前只做 IPv4
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.routes {
		if s.routes[i].Matches(v4, port) {
			return s.routes[i].Chain, s.routes[i].Action, true
		}
	}
	return "", ActionChain, false
}

// List 返回当前规则的副本。
func (s *Set) List() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Route, len(s.routes))
	copy(out, s.routes)
	return out
}

// Range 一段地址区间（闭区间），由 CIDR 展开而来。
// Ports 为空 = 该区间上任意端口都命中；非空 = 只有这些端口才进过滤器。
type Range struct {
	First uint32
	Last  uint32
	Ports []PortRange
}

// PortRange 端口区间（闭区间）。
type PortRange struct {
	First uint16
	Last  uint16
}

// FilterRanges 返回**需要进内核过滤器**的地址区间（已合并重叠）。
//
// 进过滤器 = 这些包会被转到用户态由引擎决定命运：
//   - 走链的规则：要改写地址并转给 relay
//   - 阻断的规则：要丢掉（不接管就没法丢）
//
// 而**直连**规则的目标不进过滤器：那些包在驱动层就被放行了，一次用户态都不用来
// （只有和上面两类重叠的直连目标会落到引擎里再原样放回，见 engine.packetLoop）。
//
// CIDR 展成 {first,last} 整数区间后合并相邻/重叠的区间（仅端口条件一致时），
// 以缩短过滤器长度。
func (s *Set) FilterRanges() []Range {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rs []Range
	for _, r := range s.routes {
		if r.Action == ActionDirect {
			continue
		}
		var ports []PortRange
		for _, p := range r.ports {
			ports = append(ports, PortRange{p.first, p.last})
		}
		for _, n := range r.nets {
			first := IP2U(n.IP.To4())
			mask := IP2U(net.IP(n.Mask).To4())
			last := first | ^mask
			rs = append(rs, Range{first, last, ports})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].First < rs[j].First })

	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 && samePorts(out[n-1].Ports, r.Ports) && r.First <= out[n-1].Last+1 {
			if r.Last > out[n-1].Last {
				out[n-1].Last = r.Last
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// samePorts 两组端口集合是否完全一致（只有一致的两段才能合并区间）。
func samePorts(a, b []PortRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// portRange 端口区间（闭区间）。
type portRange struct{ first, last uint16 }

// parsePortRange 接受 "443" 或 "8000-9000"（也接受 8000~9000；写反了自动换）。
func parsePortRange(s string) (portRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return portRange{}, fmt.Errorf("端口为空")
	}
	lo, hi, hasSep := s, "", false
	if i := strings.IndexAny(s, "-~"); i >= 0 {
		lo, hi, hasSep = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
	}
	a, err := strconv.Atoi(lo)
	if err != nil || a < 1 || a > 65535 {
		return portRange{}, fmt.Errorf("端口 %q 不合法（要在 1-65535）", s)
	}
	b := a
	if hasSep {
		v, err := strconv.Atoi(hi)
		if err != nil || v < 1 || v > 65535 {
			return portRange{}, fmt.Errorf("端口 %q 不合法（要在 1-65535）", s)
		}
		b = v
	}
	if a > b {
		a, b = b, a
	}
	return portRange{uint16(a), uint16(b)}, nil
}

// parseTarget 接受 "10.0.1.0/24" 或裸 IP "10.0.1.10"。
func parseTarget(t string) (*net.IPNet, error) {
	if strings.Contains(t, "/") {
		_, n, err := net.ParseCIDR(t)
		if err != nil {
			return nil, fmt.Errorf("CIDR 非法: %w", err)
		}
		if n.IP.To4() == nil {
			return nil, fmt.Errorf("仅支持 IPv4")
		}
		return n, nil
	}
	ip := net.ParseIP(t)
	if ip == nil {
		return nil, fmt.Errorf("不是合法 IP 或 CIDR")
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("仅支持 IPv4")
	}
	return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
}

func IP2U(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

// IP2U / U2IP 在 IPv4 与 uint32 之间转换（过滤器表达式与测试用）。
func U2IP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
}
