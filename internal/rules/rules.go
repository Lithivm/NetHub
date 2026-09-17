// Package rules 负责"目标是哪条链"的判定。
//
// 判定维度：目标 IP / CIDR。这是刻意的设计决定——
// 业务系统 的内网域名（app.example.com 等）在系统 hosts 里已被映射成内网 IP，
// 所以按 IP 段匹配就覆盖了全部已知目标，不需要解析 TLS SNI 或 DNS。
package rules

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// Route 一条路由规则：命中 Target（IP 或 CIDR）的流量走 Chain。
type Route struct {
	Target string `yaml:"target" json:"target"`
	Chain  string `yaml:"chain" json:"chain"`

	ipnet *net.IPNet // 解析缓存
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
		r.Target = strings.TrimSpace(r.Target)
		r.Chain = strings.TrimSpace(r.Chain)
		if r.Target == "" {
			return fmt.Errorf("第 %d 条规则: target 为空", i+1)
		}
		if r.Chain == "" {
			return fmt.Errorf("第 %d 条规则(%s): chain 为空", i+1, r.Target)
		}
		ipnet, err := parseTarget(r.Target)
		if err != nil {
			return fmt.Errorf("第 %d 条规则(%s): %w", i+1, r.Target, err)
		}
		r.ipnet = ipnet
		out = append(out, r)
	}
	s.mu.Lock()
	s.routes = out
	s.mu.Unlock()
	return nil
}

// Match 返回命中的链名。第二个返回值表示是否命中。
func (s *Set) Match(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false // 目前只做 IPv4
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.routes {
		if r.ipnet.Contains(v4) {
			return r.Chain, true
		}
	}
	return "", false
}

// List 返回当前规则的副本。
func (s *Set) List() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Route, len(s.routes))
	copy(out, s.routes)
	return out
}

// Ranges 返回所有规则的地址区间（已合并重叠），供 WinDivert 过滤器使用。
type Range struct {
	First uint32
	Last  uint32
}

// Ranges 把 CIDR 展开成 {first,last} 整数区间，合并相邻/重叠的区间以减少过滤器长度。
func (s *Set) Ranges() []Range {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rs []Range
	for _, r := range s.routes {
		first := ip2u(r.ipnet.IP.To4())
		mask := ip2u(net.IP(r.ipnet.Mask).To4())
		last := first | ^mask
		rs = append(rs, Range{first, last})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].First < rs[j].First })

	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 && r.First <= out[n-1].Last+1 {
			if r.Last > out[n-1].Last {
				out[n-1].Last = r.Last
			}
			continue
		}
		out = append(out, r)
	}
	return out
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

func ip2u(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

// U2IP 反向转换（过滤器表达式与日志展示用）。
func U2IP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
}
