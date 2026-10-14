package engine

import "testing"

// 网卡名判据（2026-10-14 收紧）。
//
// 为什么值得钉：误判的代价不只是日志里吓一跳 —— 检测到 TUN 会让**我们主动让路**
// （DNS 接管不启动、域名类规则随之失效），用户看到的是“规则装好了但什么都不生效”。
// 以前用「名字里含 tun」做子串匹配，于是 Windows 自己的 Tunnel 适配器、各类 VPN
// 都会被算成“有 TUN 模式的代理在接管流量”。
func TestLooksLikeTunDevice(t *testing.T) {
	cases := []struct {
		name string
		want bool
		why  string
	}{
		// 真应该命中：Clash/mihomo/sing-box 那一类 TUN 栈
		{"Mihomo", true, "Clash Verge 默认 device 名"},
		{"mihomo", true, "同上（小写）"},
		{"Clash", true, "工具自己建的同名网卡"},
		{"wintun", true, "Wintun 驱动建的适配器"},
		{"WinTun Adapter", true, "同上（带空格）"},
		{"sing-box", true, "sing-box 的 TUN"},
		{"singbox0", true, "同上"},
		{"utun4", true, "类 unix 隧道名"},
		{"tun2socks", true, "tun2socks"},
		{"tun", true, "裸 tun"},
		{"tun0", true, "裸 tun + 序号"},
		{"TUN (NetHub)", true, "裸 tun 作为独立词"},

		// 不该命中：Windows 自带 / VPN / 普通网卡 —— 名字里带 tunnel 不等于 TUN 模式代理
		{"Tunnel adapter Teredo Tunneling Pseudo-Interface", false, "Windows 自带隧道适配器"},
		{"Tunnel adapter isatap.{1A2B3C4D}", false, "同上"},
		{"Ethernet", false, "普通网卡"},
		{"WLAN", false, "普通无线网卡"},
		{"TAP-Windows Adapter V9", false, "OpenVPN 的 TAP（不是 TUN 模式代理）"},
		{"vEthernet (Default Switch)", false, "Hyper-V 虚拟网卡"},
		{"Tunisia VPN", false, "名字里含 tun 但不是一个词"},
		{"", false, "空名字"},
	}
	for _, tc := range cases {
		if got := looksLikeTunDevice(tc.name); got != tc.want {
			t.Errorf("looksLikeTunDevice(%q) = %v，应为 %v（%s）", tc.name, got, tc.want, tc.why)
		}
	}
}
