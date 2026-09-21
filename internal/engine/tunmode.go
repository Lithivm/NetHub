// 让路检测：本机是不是已经有别的程序在用 TUN 模式接管流量（比如 Clash/mihomo）。
//
// 为什么必须检测：TUN 模式与我们的透明接管是**互斥**的 —— Clash 的 tun 配置里写着
// `dns-hijack: any:53`、`auto-route: true`、`device: Mihomo`，一旦启用，全机流量与
// DNS 都被它抓走，我们可能连包都收不到。那时继续“假装在工作”是最坏的结果
// （用户看到的是“NetHub 开着一堆规则全不生效”），所以必须查出来并说清楚。
//
// 检测三件事：
//  1. 网卡列表里有没有 mihomo/clash/tun 这类虚拟网卡，且是启用状态；
//  2. Clash Verge 的配置里 enable_tun_mode / tun.enable 是不是 true；
//  3. 本机 DNS 是不是指向 127.0.0.1（那样查询走环回，WinDivert 抓不到）。
package engine

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
	"gopkg.in/yaml.v3"
)

// TunReport 让路检测的结果。Reasons 为空 = 没有发现 TUN 接管。
type TunReport struct {
	Reasons   []string // 人读的依据（每条一个事实）
	TunDevice string   // 命中的虚拟网卡名（空 = 没发现）
	ClashTun  bool     // Clash Verge 配置里 TUN 开着
	DNSLocal  bool     // 本机 DNS 指向 127.0.0.1
}

// Active 是否需要让路（有任意一条依据）。
func (r TunReport) Active() bool { return len(r.Reasons) > 0 }

// Summary 一句话概括（日志/界面用）。
func (r TunReport) Summary() string { return strings.Join(r.Reasons, "；") }

// tunDeviceHints 虚拟网卡名的识别关键词（全小写比较）。
var tunDeviceHints = []string{"mihomo", "clash", "utun", "singbox", "sing-box", "tun"}

// detectTun 做全套检测。任何一步失败都不算命中（宁可漏报，不要误报说“你开了 TUN”）。
func detectTun() TunReport {
	var r TunReport

	// ① 网卡
	if ifaces, err := net.Interfaces(); err == nil {
		for _, in := range ifaces {
			name := strings.ToLower(in.Name)
			for _, hint := range tunDeviceHints {
				if !strings.Contains(name, hint) {
					continue
				}
				if in.Flags&net.FlagUp == 0 {
					continue // 网卡存在但没启用：不算接管
				}
				r.TunDevice = in.Name
				r.Reasons = append(r.Reasons, fmt.Sprintf("发现启用的虚拟网卡 %q", in.Name))
				break
			}
		}
	}

	// ② Clash Verge 配置（两家都可能出现：verge.yaml 是自己的开关，clash-verge.yaml 是内核配置）
	if dir := clashVergeDir(); dir != "" {
		if v, ok := readYamlFlag(filepath.Join(dir, "verge.yaml"), "enable_tun_mode"); ok && v {
			r.ClashTun = true
		}
		if v, ok := readYamlTunEnable(filepath.Join(dir, "clash-verge.yaml")); ok && v {
			r.ClashTun = true
		}
		if r.ClashTun {
			r.Reasons = append(r.Reasons, "Clash Verge 配置里 TUN 模式为开启")
		}
	}

	// ③ 本机 DNS 指向 127.0.0.1
	if dnsLocalOnly() {
		r.DNSLocal = true
		r.Reasons = append(r.Reasons, "本机 DNS 指向 127.0.0.1（查询走环回，抓不到）")
	}

	return r
}

// clashVergeDir Clash Verge 的配置目录（不存在返回空）。
func clashVergeDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return ""
	}
	dir := filepath.Join(appData, "io.github.clash-verge-rev.clash-verge-rev")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return ""
	}
	return dir
}

// readYamlFlag 读顶层布尔字段（读不出来返回 false, false）。
func readYamlFlag(path, key string) (bool, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return false, false
	}
	v, ok := m[key].(bool)
	return v, ok
}

// readYamlTunEnable 读 tun.enable（clash-verge.yaml 里的内核配置）。
func readYamlTunEnable(path string) (bool, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	var m struct {
		Tun struct {
			Enable *bool `yaml:"enable"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal(data, &m); err != nil || m.Tun.Enable == nil {
		return false, false
	}
	return *m.Tun.Enable, true
}

// dnsLocalOnly 本机每块网卡的 DNS 是不是都指向环回（127.x）。
//
// 只有“全都是环回”才算 —— 混着真实 DNS 时不报（那种情况我们大多还看得见）。
func dnsLocalOnly() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	seen := 0
	for _, s := range subs {
		ik, err := registry.OpenKey(k, s, registry.READ)
		if err != nil {
			continue
		}
		raw, _, err := ik.GetStringValue("NameServer")
		if err != nil || strings.TrimSpace(raw) == "" {
			raw, _, err = ik.GetStringValue("DhcpNameServer")
		}
		ik.Close()
		if err != nil || strings.TrimSpace(raw) == "" {
			continue // 这块网卡没有 DNS 配置
		}
		seen++
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == ';'
		}) {
			ip := net.ParseIP(strings.TrimSpace(part))
			if ip == nil || ip.To4() == nil {
				continue
			}
			if !ip.IsLoopback() {
				return false // 有真实 DNS，说明不是“全指本机”
			}
		}
	}
	return seen > 0
}
