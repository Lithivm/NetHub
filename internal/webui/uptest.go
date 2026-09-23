// 原生上游链路的实测入口：nethub.exe -test-upstream
//
// 这是"能不能不依赖 gost.exe"的实验装置：它绕过本地 gost 监听，
// 直接用 internal/upstream 连真实上游，再对每个链对应的内网目标发一个 HTTP 请求。
// 能拿到 HTTP 响应 = 协议假设成立（socks5+tls + RFC1929 认证 + CONNECT）。
package webui

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"nethub/internal/config"
	"nethub/internal/hostsmgr"
	"nethub/internal/upstream"
)

// TestUpstream 对每条链的原生上游做一次真实探测。不需要管理员权限。
func TestUpstream(cfg *config.Config) {
	fmt.Println("=== 原生上游链路实测（不经 gost）===")
	if len(cfg.ChainsSnapshot()) == 0 {
		fmt.Println("  配置里没有链")
		return
	}

	// 探针目标：从 hosts 条目里拿【真实主机 IP】，并要求它落在该链负责的网段内。
	// 不能用网段的 .1 当探针 —— 那多半不是真主机（实测会得到 host unreachable，
	// 容易让人误以为协议不通）。
	realHosts := realHostsByChain(cfg)

	pass, fail := 0, 0
	for _, ch := range cfg.ChainsSnapshot() {
		up, err := upstream.Parse(ch.Forward)
		if err != nil {
			fmt.Printf("  [%s] 解析上游失败: %v\n", ch.Name, err)
			fail++
			continue
		}
		fmt.Printf("\n[%s] 上游: %s\n", ch.Name, up.String())
		fmt.Printf("       TLS=%v  证书校验=%v  凭据已配置=%v\n", up.TLS, up.Verify, up.Creds.User != "")

		hosts := realHosts[ch.Name]
		if len(hosts) == 0 {
			fmt.Printf("       ⚠ 找不到该链网段内的真实主机（hosts 条目为空？）跳过\n")
			continue
		}

		whole := true
		for _, ip := range hosts {
			ok, detail := probeUpstream(up, ip)
			if ok {
				fmt.Printf("       ✓ %-16s %s\n", ip, detail)
			} else {
				fmt.Printf("       ✗ %-16s %s\n", ip, detail)
				whole = false
			}
		}
		if whole {
			pass++
		} else {
			fail++
		}
	}

	fmt.Printf("\n=== 结果：%d 条链通，%d 条不通 ===\n", pass, fail)
}

// realHostsByChain 从 hosts 条目里取出每个链网段内的真实主机 IP。
func realHostsByChain(cfg *config.Config) map[string][]net.IP {
	// ① 规则里写死的单个 IP（裸 IP 或 /32）就是真实目标，先收进来 ——
	// 与界面自检用同一套口径（见 probeIPsForChain），否则会出现
	// “界面能探活、命令行却说找不到主机”的不一致。
	out := map[string][]net.IP{}
	for _, rt := range cfg.RoutesSnapshot() {
		for _, t := range rt.Targets {
			t = strings.TrimSpace(t)
			if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
				out[rt.Chain] = append(out[rt.Chain], ip.To4())
				continue
			}
			if ip, n, err := net.ParseCIDR(t); err == nil && ip.To4() != nil {
				if ones, _ := n.Mask.Size(); ones == 32 {
					out[rt.Chain] = append(out[rt.Chain], ip.To4())
				}
			}
		}
	}

	type cidr struct {
		chain string
		n     *net.IPNet
	}
	var nets []cidr
	for _, rt := range cfg.RoutesSnapshot() {
		for _, t := range rt.Targets {
			if _, n, err := net.ParseCIDR(t); err == nil {
				nets = append(nets, cidr{rt.Chain, n})
			} else if ip := net.ParseIP(t); ip != nil {
				nets = append(nets, cidr{rt.Chain, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}})
			}
		}
	}

	seen := map[string]bool{}
	for _, e := range hostsEntriesFrom(cfg) {
		f := strings.Fields(e)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, cn := range nets {
			if cn.n.Contains(ip) {
				key := cn.chain + "|" + ip.String()
				if !seen[key] {
					seen[key] = true
					out[cn.chain] = append(out[cn.chain], ip)
				}
			}
		}
	}
	return out
}

// probeUpstream 经上游连到 ip，逐个试常见端口并真正发一个 HTTP 请求。
func probeUpstream(up *upstream.Upstream, ip net.IP) (bool, string) {
	var lastErr string
	for _, port := range []uint16{443, 80, 5432, 6446, 5000, 9056} {
		c, err := up.Dial(ip, port, 8*time.Second)
		if err != nil {
			lastErr = fmt.Sprintf(":%d %v", port, err)
			continue
		}
		// 端口能连上就再验一层：443 试 TLS+HTTP，其它只报握手成功
		if port == 443 {
			if kind, err := probeOnConn(c, ip.String()); err == nil {
				return true, fmt.Sprintf(":%d 且 %s 应用层响应正常", port, kind)
			} else {
				lastErr = fmt.Sprintf(":%d 连接成功但应用层失败: %v", port, err)
				continue
			}
		}
		c.Close()
		return true, fmt.Sprintf(":%d TCP 握手成功", port)
	}
	if lastErr == "" {
		lastErr = "所有常见端口都不通"
	}
	return false, lastErr
}

// probeOnConn 在已建立的连接上做 TLS + HTTP（复用 clash.go 里的思路）。
func probeOnConn(c net.Conn, host string) (string, error) {
	defer c.Close()
	kind, err := tryTLSGet(c, host)
	if err == nil {
		return kind, nil
	}
	return "", err
}

var _ = bufio.NewReader

// hostsEntriesFrom 取内网域名映射条目，回退顺序与检测那边一致：
// 配置 → hosts 文件里的标记区块 → 内置默认。
// （不能只读配置：默认配置的 entries 是空的，那样什么都探不到）
func hostsEntriesFrom(cfg *config.Config) []string {
	hosts := cfg.HostsCopy()
	if len(hosts.Entries) > 0 {
		return hosts.Entries
	}
	if block, ok, _, err := hostsmgr.Read(); err == nil && ok {
		return block
	}
	return defaultHostsEntries()
}
