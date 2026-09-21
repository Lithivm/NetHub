// Package rules 负责"目标是哪条链"的判定。
//
// 判定维度：目标 IP / CIDR。这是刻意的设计决定——
// 内网域名通常已在系统 hosts 里被映射成内网 IP（app.your-domain.com → 10.0.0.10），
// 所以按 IP 段匹配就覆盖了全部已知目标，不需要解析 TLS SNI 或 DNS。
package rules

import (
	"fmt"
	"net"
	"nethub/internal/dnsmap"
	"nethub/internal/netx"
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

	// LocalNets 仅当**本机**的某块网卡地址落在这些网段里时，这条规则才生效（A16）。
	// 空 = 总是生效（与以前一致）。
	// 用途：笔记本在公司（10.0.0.0/8）走隧道、回家（192.168.1.0/24）直连，
	// 不用手动改配置；也用于“只在客户内网环境下接管”这种安全阀。
	LocalNets []string `yaml:"local_nets,omitempty" json:"localNets,omitempty"`

	// Apps 进程条件（可选），写成进程名，支持 * 通配：chrome.exe / *.exe / *weixin*。
	// **与 Targets 是 AND 关系**：两样都填 → 两个都要命中；只填 Apps → 该进程的所有 TCP
	// 连接都算命中（此时过滤器要拦全部流量，见 FilterRanges）。
	//
	// 定位：只用来写“例外”（某程序必须走 / 绝不许走隧道），主用法仍是按目标。
	// 查不到进程时（受保护进程/系统服务/极短连接）**不命中** —— 即“不因为识别不出
	// 进程就改变流量走向”，宁可漏过也不误伤（fail-open）。
	Apps []string `yaml:"apps,omitempty" json:"apps,omitempty"`

	nets []*net.IPNet // 解析缓存，与 Targets 里的 IP/CIDR 一一对应
	// hosts 与 hostIPs：目标里的**域名**部分（原样保留）+ 它们当前解析到的 IP。
	// 为什么不把域名直接换成 IP 写进配置：IP 会变（多 A 记录/备用机房），
	// 写死很快就错。运行时由引擎解析后通过 SetHostIPs 填进来。
	hosts   []string
	hostIPs []*net.IPNet
	// wildcards 目标里的**通配域名**（*.his.com）。归一化后的后缀（如 .his.com）。
	//
	// 为什么不能归类进 hosts：通配域名**没法主动解析**（枚举不出来），只能等观
	// 察到应用的 DNS 应答（见 dnsmap 与 engine 的 dnsWatch）；匹配发生在“名字”层面，
	// 命中后的 IP 会由 SetHostIPs 填进 hostIPs（过滤器才能拦住它们）。
	wildcards []string
	ports     []portRange  // 解析缓存，与 Ports 一一对应；留空 = 任意端口
	local     []*net.IPNet // 解析缓存，与 LocalNets 一一对应
	apps      []string     // 解析缓存，与 Apps 一一对应（已去空白）
}

// HasApps 这条规则带进程条件。
func (r Route) HasApps() bool { return len(r.apps) > 0 }

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
	return r.MatchesProc(ip, port, "")
}

// MatchesProc 目标 + 端口 + 进程 三个维度一起判。
//
// 只填 Apps 的规则不看目标/端口 —— 该进程的所有连接都命中。
func (r Route) MatchesProc(ip net.IP, port uint16, procName string) bool {
	return r.MatchesName("", ip, port, procName)
}

// MatchesName 同 MatchesProc，额外给出这个目标 IP 当前关联到的**域名**（可为空）。
//
// 为什么要传名字：通配域名（*.his.com）在包里是看不见的，只能拿“这个 IP 是哪个
// 名字解析来的”去比 —— 名字由引擎从观察到的 DNS 里拿到（见 dnsmap）。
func (r Route) MatchesName(name string, ip net.IP, port uint16, procName string) bool {
	if len(r.apps) > 0 {
		if !matchAnyApp(r.apps, procName) {
			return false
		}
		if len(r.nets) == 0 && len(r.hosts) == 0 && len(r.wildcards) == 0 {
			return true // 只按进程：目标/端口不参与
		}
	}
	if !r.matchesIP(ip) && !r.matchesWildcard(name) {
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

// matchAnyApp 进程名是否命中 Apps 里任意一条（不区分大小写，支持 * 通配）。
func matchAnyApp(apps []string, procName string) bool {
	for _, a := range apps {
		if MatchAppName(a, procName) {
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
		if !s.active(s.routes[i]) {
			continue // 当前网络下不生效的规则不参与解释
		}
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
	for _, n := range r.hostIPs { // 域名目标当前解析到的 IP（含通配域名观察到的 IP）
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// matchesWildcard 名字是否命中本规则里的任一条通配域名。
func (r Route) matchesWildcard(name string) bool {
	if name == "" || len(r.wildcards) == 0 {
		return false
	}
	for _, w := range r.wildcards {
		if dnsmap.MatchWildcard(w, name) {
			return true
		}
	}
	return false
}

// WildcardTargets 本规则里的通配域名（归一化后的后缀）—— 引擎用它算动态过滤器。
func (r Route) WildcardTargets() []string { return append([]string{}, r.wildcards...) }

// HostTargets 这条规则里写的域名（原样，供引擎去解析与透传给上游）。
func (r Route) HostTargets() []string { return append([]string{}, r.hosts...) }

// SetHostIPs 把引擎解析出来的「域名 → IP」填进整组规则。
//
// 解析放到引擎而不是这里，是因为它要做 DNS I/O 且会定期刷新；
// 规则层只负责"拿到就用"，保持无副作用、可单测。
//
// 传进来的 byHost 除了规则里写的具体域名，还包括**观察到**的域名（通配域名靠它）。
// 通配规则会从这里挑出所有命中的名字，把它们当前解析到的 IP 填进 hostIPs ——
// 这一步决定了引擎会不会把这些 IP 装进内核过滤器。
func (s *Set) SetHostIPs(byHost map[string][]*net.IPNet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.routes {
		r := &s.routes[i]
		if len(r.hosts) == 0 && len(r.wildcards) == 0 {
			continue
		}
		var ips []*net.IPNet
		for _, h := range r.hosts {
			ips = append(ips, byHost[h]...)
		}
		for _, w := range r.wildcards {
			// 名字表里可能有几十上百个名字（都是观察来的），这里只跑一遍。
			for h, ns := range byHost {
				if dnsmap.MatchWildcard(w, h) {
					ips = append(ips, ns...)
				}
			}
		}
		r.hostIPs = ips
	}
}

// Set 是一组有序规则（先匹配先生效，和 Proxifier 语义一致）。
type Set struct {
	mu     sync.RWMutex
	routes []Route
	// needsProc 至少有一条规则带进程条件 —— 引擎据此决定要不要查 TCP 表。
	needsProc bool
	// hasWildcards 至少有一条通配域名规则 —— 引擎据此决定要不要查
	// “目标 IP 是哪个名字”的反查表（每包一次 map 查找，能省则省）。
	hasWildcards bool
	// localIPs 本机当前的非回环 IPv4（由引擎探测后写入）。
	// 规则带 LocalNets 时用它判断“现在这台机器是不是在公司网里”。
	localIPs []net.IP
}

// SetLocalIPs 更新本机地址（引擎在网络变化时调）。
func (s *Set) SetLocalIPs(ips []net.IP) {
	s.mu.Lock()
	s.localIPs = ips
	s.mu.Unlock()
}

// LocalIPs 当前已知的本机地址。
func (s *Set) LocalIPs() []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]net.IP(nil), s.localIPs...)
}

// active 这条规则在当前网络下是否生效（没有 LocalNets 就总是生效）。
func (s *Set) active(r Route) bool {
	if len(r.local) == 0 {
		return true
	}
	for _, ip := range s.localIPs {
		for _, n := range r.local {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func New() *Set { return &Set{} }

// Load 校验并载入规则。任一条非法就整体失败（避免半生效状态）。
func (s *Set) Load(routes []Route) error {
	out := make([]Route, 0, len(routes))
	for i, r := range routes {
		r.Name = strings.TrimSpace(r.Name)
		r.Chain = strings.TrimSpace(r.Chain)
		apps := make([]string, 0, len(r.Apps))
		for _, a := range r.Apps {
			if a = strings.TrimSpace(a); a != "" {
				apps = append(apps, a)
			}
		}
		if len(r.Targets) == 0 && len(apps) == 0 {
			return fmt.Errorf("第 %d 条规则%s: 至少要有一个目标（或一个进程条件）", i+1, r.Label())
		}
		if r.Chain == "" {
			return fmt.Errorf("第 %d 条规则%s: chain 为空", i+1, r.Label())
		}
		nets := make([]*net.IPNet, 0, len(r.Targets))
		hosts := make([]string, 0, len(r.Targets))
		wildcards := make([]string, 0, len(r.Targets))
		for j, t := range r.Targets {
			t = strings.TrimSpace(t)
			if t == "" {
				return fmt.Errorf("第 %d 条规则%s: 第 %d 个目标为空", i+1, r.Label(), j+1)
			}
			// 域名目标：不适求当下能解析（DNS 可能一时不可用），原样记下，
			// 由引擎解析成功后通过 SetHostIPs 填进来；解析不到顶多是这条不命中。
			if dnsmap.IsHostname(t) {
				if dnsmap.IsWildcard(t) {
					suffix, werr := dnsmap.WildcardSuffix(t)
					if werr != nil {
						return fmt.Errorf("第 %d 条规则%s: 目标 %v", i+1, r.Label(), werr)
					}
					wildcards = append(wildcards, suffix)
					continue
				}
				hosts = append(hosts, strings.ToLower(t))
				continue
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
		// A16：可选的“仅在某些本机网段下生效”
		local := make([]*net.IPNet, 0, len(r.LocalNets))
		for _, ln := range r.LocalNets {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			ipnet, err := parseTarget(ln)
			if err != nil {
				return fmt.Errorf("第 %d 条规则%s: 本机网段 %s: %w", i+1, r.Label(), ln, err)
			}
			local = append(local, ipnet)
		}
		r.ports, r.nets, r.local, r.apps, r.hosts = ports, nets, local, apps, hosts
		r.wildcards = wildcards
		out = append(out, r)
	}
	s.mu.Lock()
	s.routes = out
	s.needsProc = false
	s.hasWildcards = false
	for i := range out {
		if out[i].HasApps() {
			s.needsProc = true
		}
		if len(out[i].wildcards) > 0 {
			s.hasWildcards = true
		}
	}
	s.mu.Unlock()
	return nil
}

// Match 返回命中的链名与动作（不含进程维度；等价于“进程未知”）。
func (s *Set) Match(ip net.IP, port uint16) (chain string, act Action, ok bool) {
	return s.MatchProc(ip, port, "")
}

// MatchProc 同 Match，但带上"这条连接属于哪个进程"（空串 = 未知）。
//
// 返回命中的链名与动作（ActionDirect / ActionBlock 时链名无意义），第三个返回值表示是否命中。
// 每收到一个包都要调一次，所以这里不复制 Route（只回传字符串/枚举 + 布尔）。
func (s *Set) MatchProc(ip net.IP, port uint16, procName string) (chain string, act Action, ok bool) {
	return s.MatchName("", ip, port, procName)
}

// MatchName 同 MatchProc，额外给出目标 IP 当前关联到的域名（通配域名规则靠它命中）。
func (s *Set) MatchName(name string, ip net.IP, port uint16, procName string) (chain string, act Action, ok bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", ActionChain, false // 目前只做 IPv4
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.routes {
		// 带 LocalNets 的规则要"现在这台机器处于那个网络"才生效（A16）
		if !s.active(s.routes[i]) {
			continue
		}
		if s.routes[i].MatchesName(name, v4, port, procName) {
			return s.routes[i].Chain, s.routes[i].Action, true
		}
	}
	return "", ActionChain, false
}

// HasWildcards 当前规则里有没有通配域名。
// 没有的话引擎不做"IP → 名字"的反查（每包一次查找，不该白白付给所有人）。
func (s *Set) HasWildcards() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasWildcards
}

// WildcardMatch 名字是否被某条通配规则命中（不看 IP）—— DNS 接管用它决定要不要答假 IP。
//
// 为什么不复用 MatchName：那条路要 IP 与端口，而这里只有“应用要解析的名字”。
func (s *Set) WildcardMatch(name string) bool {
	if name == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.routes {
		r := &s.routes[i]
		if len(r.wildcards) == 0 || !s.active(*r) {
			continue
		}
		if r.matchesWildcard(name) {
			return true
		}
	}
	return false
}

// NeedsProc 当前规则里有没有人用进程条件。
//
// 没有的话引擎**一个进程都不查**（TCP 表枚举是毫秒级开销，不该白白付给所有人）。
func (s *Set) NeedsProc() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.needsProc
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
// FilterRanges 需要装进内核过滤器的网段。
//
// 只装“要走链”与“要阻断”的：直连的流量**不进过滤器**（零开销、一个包也不碰）。
// 例外：includeDirect=true 时也把直连网段装进去 —— 这时我们不修改它、只统计双向字节
// （界面上的「统计直连流量」开关，默认关）。
func (s *Set) FilterRanges(includeDirect bool) []Range {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rs []Range
	for _, r := range s.routes {
		if r.Action == ActionDirect && !includeDirect {
			continue
		}
		var ports []PortRange
		for _, p := range r.ports {
			ports = append(ports, PortRange{p.first, p.last})
		}
		// 只按进程的规则：**一个目标都没写** → 目标提前不可知，只能拦全部（用户显式这么写才发生）。
		// 代价：所有流量都要过一遍用户态（见 packetLoop 里“没命中任何规则→原样放回”）。
		// ⚠ 这里必须看"总目标数"而不是 nets：域名规则在解析出来之前 nets 也是空的，
		// 若把它也归到这一类，一条还没生效的域名规则会让**全部流量**过用户态（性能地雷）。
		// 通配域名同理：它命中哪里要等观察到 DNS 才知道，没观察到之前什么都不拦。
		if len(r.nets) == 0 && len(r.hosts) == 0 && len(r.wildcards) == 0 {
			rs = append(rs, Range{0, 0xFFFFFFFF, ports})
			continue
		}
		// 域名目标：拦它**当前解析到**的 IP（引擎定期刷新并重建过滤器）。
		// 解析不到 → 这条现在什么都不拦（不猜、也不全拦），日志里会说哪几个域名没解析出来。
		for _, n := range r.hostIPs {
			first := IP2U(n.IP.To4())
			mask := IP2U(net.IP(n.Mask).To4())
			last := first | ^mask
			rs = append(rs, Range{first, last, ports})
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

// WildcardRanges 只取「通配域名规则」当前覆盖到的区间 —— 引擎用它拼**动态过滤器**。
//
// 为什么要单独一只过滤器：通配域名（*.his.com）事先不知道会解析成哪些 IP，
// 那些 IP 不在启动时装配的静态过滤器里，包根本到不了我们手上。做法是只读
// 嗅探应用的 DNS 应答，把学到的 IP 装进第二只（可热替换的）句柄。
//
// 这里同样只管“会走链/阻断”的规则：直连规则的目标本来就不用拦（不拦就是直连）。
func (s *Set) WildcardRanges(includeDirect bool) []Range {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rs []Range
	for _, r := range s.routes {
		if len(r.wildcards) == 0 {
			continue
		}
		if r.Action == ActionDirect && !includeDirect {
			continue
		}
		// 带本机网段条件（A16）的规则当前不生效时，它的 IP 也不该进过滤器
		// —— 否则这些包会白白过一趟用户态，而且“没命中”时还会被当作直连统计。
		if !s.active(r) {
			continue
		}
		var ports []PortRange
		for _, p := range r.ports {
			ports = append(ports, PortRange{p.first, p.last})
		}
		for _, n := range r.hostIPs {
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

// MatchAppName 进程名是否命中一条进程条件（不区分大小写，支持 * 通配，带路径只比文件名）。
//
// 放在 rules 而不是 proc：匹配逻辑与操作系统无关，proc 只管“查出进程名”。
func MatchAppName(cond, name string) bool {
	cond = strings.ToLower(strings.TrimSpace(cond))
	name = strings.ToLower(strings.TrimSpace(name))
	if cond == "" || name == "" || name == "?" {
		return false
	}
	if i := strings.LastIndexAny(cond, `\/`); i >= 0 {
		cond = cond[i+1:]
	}
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return matchWild(cond, name)
}

// matchWild 支持 * 的简单通配（不引入正则：规则要能被人工一眼看懂）。
func matchWild(pat, s string) bool {
	if pat == "*" {
		return true
	}
	if !strings.Contains(pat, "*") {
		return pat == s
	}
	parts := strings.Split(pat, "*")
	if parts[0] != "" && !strings.HasPrefix(s, parts[0]) {
		return false
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(s, last) {
		return false
	}
	pos := len(parts[0])
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(s[pos:], parts[i])
		if idx < 0 {
			return false
		}
		pos += idx + len(parts[i])
	}
	return true
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
	// IP 通配（10.100.100.*）在这里也认 —— 配置层会归一化，但规则层不该依赖
	// “上游一定规整过”；手写/脚本组出来的规则同样能进来。
	if netx.IsWildcardIP(t) {
		c, err := netx.WildcardToCIDR(t)
		if err != nil {
			return nil, err
		}
		t = c
	}
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

// HostTargets 整组规则里出现的所有域名（引擎按它做解析与刷新）。
func (s *Set) HostTargets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for i := range s.routes {
		for _, h := range s.routes[i].hosts {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sort.Strings(out)
	return out
}
