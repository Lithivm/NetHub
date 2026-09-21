// Package fakeip 维护「域名 ↔ 假 IP」的双向映射。
//
// 干什么用：DNS 接管（详见 KB 决策/2026-09-21-DNS接管已验证可行.md）。
// 应用问 main.his.com 时我们答一个假 IP，之后看到连到那个假 IP 的连接，
// 就知道它要去哪个域名 —— 于是"名字"在**连接之前**就到手了，不需要
// "先接后判"那套猜（那条路已删，见 744f4e2）。
//
// 三条硬要求：
//
//  1. **稳定**：同一个名字在进程活着期间恒定给同一个假 IP。否则同一域名每次解析
//     都换 IP → 连接回到我们手上时对不上名字，统计与规则匹配全乱。
//  2. **可回收**：名字过了 TTL 就把假 IP 还回池子（客户机连跑几个月的场景）。
//  3. **不撞**：默认用 198.19.0.0/16。**不能用 198.18.0.0/16** —— 那是 Clash
//     fake-ip-range 的默认段（实测本机 Clash 就是它），撞上就互相打架。
//     配成这一段会被明确拒绝。
//
// 已知取舍：映射只活在内存里 —— 重启后同一个名字可能拿到另一个假 IP。
// 应用端缓存的是我们发的 TTL（默认很短），所以影响窗口很小；真遇到
// "连接到一个我们不认识的假 IP"时，引擎会明确说出来而不是猜。
package fakeip

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// DefaultRange 默认假 IP 段。
const DefaultRange = "198.19.0.0/16"

// clashRange Clash（mihomo）默认的 fake-ip 段：配到它会互相打架，直接拒绝。
const clashRange = "198.18.0.0/16"

// realRanges 真实网络里会出现的段 —— 假 IP 段绝不能落在这些里面
// （否则假 IP 一旦“真的存在”，我们会把本该直连的流量拐进隧道）。
var realRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
}

// entry 一个名字的占用记录。
type entry struct {
	name    string
	ip      uint32
	expires time.Time
}

// Pool 假 IP 池（并发安全）。
type Pool struct {
	mu     sync.RWMutex
	net    *net.IPNet
	first  uint32 // 可用区间的第一个地址（跳开网络地址）
	last   uint32 // 可用区间的最后一个地址（跳开广播地址）
	byName map[string]*entry
	byIP   map[uint32]*entry
	free   []uint32 // 归还回来的地址（优先复用，减少假 IP 漂移）
	next   uint32   // 顺序分配的游标
	nowFn  func() time.Time
}

// NewPool 用一段 CIDR 建池。空串 = DefaultRange。
func NewPool(cidr string) (*Pool, error) {
	if cidr == "" {
		cidr = DefaultRange
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("假 IP 段 %q 不是合法 CIDR: %w", cidr, err)
	}
	v4 := n.IP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("假 IP 段 %q 不是 IPv4（引擎只做 IPv4）", cidr)
	}
	ones, bits := n.Mask.Size()
	if bits != 32 || ones > 28 {
		return nil, fmt.Errorf("假 IP 段 %q 太小或不是 IPv4（最大 /28，建议 /16）", cidr)
	}
	// 撞上 Clash 的 fake-ip 段就直接拒绝：两个程序抢同一段假 IP 会互相误判。
	if _, cr, _ := net.ParseCIDR(clashRange); cr != nil && cr.Contains(v4) {
		return nil, fmt.Errorf("假 IP 段 %q 落在 %s 里 —— 那是 Clash/mihomo 的 fake-ip 默认段，"+
			"两个程序用同一段假 IP 会互相误判。换一段（默认 %s）", cidr, clashRange, DefaultRange)
	}
	// 落在真实网络段里也不行（客户内网就是 10/8、172.16/12、192.168/16）。
	if bad := realRangeHit(n); bad != "" {
		return nil, fmt.Errorf("假 IP 段 %q 落在真实网络段 %s 里 —— 假 IP 必须选不会出现在真实网络中的段"+
			"（默认 %s）", cidr, bad, DefaultRange)
	}

	first := binary.BigEndian.Uint32(v4.To4())
	mask := binary.BigEndian.Uint32(net.IP(n.Mask).To4())
	last := first | ^mask
	p := &Pool{
		net:    n,
		first:  first + 1, // 跳过网络地址
		last:   last - 1,  // 跳过广播地址
		byName: map[string]*entry{},
		byIP:   map[uint32]*entry{},
		next:   first + 1,
		nowFn:  time.Now,
	}
	if p.first > p.last {
		return nil, fmt.Errorf("假 IP 段 %q 没有可用地址", cidr)
	}
	return p, nil
}

// Range 池子覆盖的网段（装内核过滤器时要用）。
func (p *Pool) Range() *net.IPNet {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cp := *p.net
	return &cp
}

// Assign 给名字分配（或复用）一个假 IP，并把它续期到 now+ttl。
//
// 同一个名字重复调用返回同一个 IP（除非它已经过期被回收了）。
// 池子满了返回 nil（调用方应当**放行原查询**，而不是乱答一个）。
func (p *Pool) Assign(name string, ttl time.Duration) net.IP {
	if name == "" {
		return nil
	}
	now := p.nowFn()
	if ttl <= 0 {
		ttl = time.Minute
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if e := p.byName[name]; e != nil && now.Before(e.expires) {
		e.expires = now.Add(ttl)
		return u32IP(e.ip)
	}
	// 过期的旧占用先清掉（同一个名字换了新 IP 之前要腾位置）
	if old := p.byName[name]; old != nil {
		p.releaseLocked(old)
	}
	ip, ok := p.takeLocked()
	if !ok {
		return nil // 池子满了
	}
	e := &entry{name: name, ip: ip, expires: now.Add(ttl)}
	p.byName[name] = e
	p.byIP[ip] = e
	return u32IP(ip)
}

// NameFor 反查：这个假 IP 是哪个域名。
func (p *Pool) NameFor(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	u := binary.BigEndian.Uint32(v4)
	p.mu.RLock()
	defer p.mu.RUnlock()
	e := p.byIP[u]
	if e == nil || !p.nowFn().Before(e.expires) {
		return "", false
	}
	return e.name, true
}

// IPFor 正查：这个域名现在的假 IP。
func (p *Pool) IPFor(name string) (net.IP, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e := p.byName[name]
	if e == nil || !p.nowFn().Before(e.expires) {
		return nil, false
	}
	return u32IP(e.ip), true
}

// Sweep 回收所有过期名字，返回被回收的名字（调用方要据此清掉下游缓存）。
func (p *Pool) Sweep() []string {
	now := p.nowFn()
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for name, e := range p.byName {
		if now.Before(e.expires) {
			continue
		}
		out = append(out, name)
		p.releaseLocked(e)
	}
	sort.Strings(out)
	return out
}

// Stats 用量（诊断/界面用）。
func (p *Pool) Stats() (used, capacity int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.byName), int(p.last-p.first) + 1
}

// Names 当前占用的全部名字（排序，便于日志稳定）。
func (p *Pool) Names() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.byName))
	for n := range p.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// takeLocked 取一个空闲地址（调用方须持写锁）。
func (p *Pool) takeLocked() (uint32, bool) {
	if n := len(p.free); n > 0 {
		ip := p.free[n-1]
		p.free = p.free[:n-1]
		return ip, true
	}
	for i := uint32(0); i <= p.last-p.first; i++ {
		ip := p.first + ((p.next - p.first + i) % (p.last - p.first + 1))
		if _, used := p.byIP[ip]; !used {
			p.next = ip + 1
			if p.next > p.last {
				p.next = p.first
			}
			return ip, true
		}
	}
	return 0, false
}

func (p *Pool) releaseLocked(e *entry) {
	delete(p.byName, e.name)
	delete(p.byIP, e.ip)
	p.free = append(p.free, e.ip)
}

func u32IP(u uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, u)
	return b
}

// realRangeHit 这段假 IP 落进了哪个真实网络段（空 = 没落进）。
func realRangeHit(n *net.IPNet) string {
	for _, c := range realRanges {
		_, r, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if r.Contains(n.IP) || n.Contains(r.IP) {
			return c
		}
	}
	return ""
}
