package webui

import (
	"strings"
	"testing"

	"nethub/internal/config"
	"nethub/internal/rules"
)

// 「在浏览器地址栏输入地址」这个场景的模拟：
// 一条输入会展开成**多条连接**（http/https 两个端口 × 多个解析地址），每条独立判定。
func TestSimulateBrowserTargets(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	cfg.Hosts = config.HostsCfg{Manage: true, Entries: []string{
		"10.0.0.5 main.example.com",
		"10.0.0.6 main.example.com", // 同一域名两个地址：浏览器会同时试
	}}
	cfg.Routes = []config.Route{{Name: "内网业务", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"}}
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "内网业务", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"}}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs

	rowsFor := func(input string) []SimRow {
		t.Helper()
		v := b.SimulateTargets(input)
		var out []SimRow
		for _, r := range v.Rows {
			if r.Input == input {
				out = append(out, r)
			}
		}
		return out
	}

	// ① 带协议的 URL：端口由 scheme 决定，解析走 hosts 条目
	rows := rowsFor("http://main.example.com/some/path?q=1")
	if len(rows) != 2 {
		t.Fatalf("http URL 应展开成 2 条（两个 hosts 地址 × 80），实际 %d：%+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Port != 80 || r.Source != "hosts 条目" || !r.OK {
			t.Errorf("http URL 的端口/来源不对：%+v", r)
		}
		if !strings.Contains(r.Action, "proxy-a") || r.Chain != "proxy-a" {
			t.Errorf("应命中内网业务走 proxy-a：%+v", r)
		}
	}

	// ② 没写协议：80 和 443 都列（不猜浏览器先试哪个）
	rows = rowsFor("main.example.com")
	if len(rows) != 4 {
		t.Fatalf("裸域名应展开成 4 条（2 地址 × 2 端口），实际 %d：%+v", len(rows), rows)
	}
	ports := map[int]bool{}
	for _, r := range rows {
		ports[r.Port] = true
	}
	if !ports[80] || !ports[443] {
		t.Errorf("裸域名应同时给出 80 与 443：%v", ports)
	}

	// ③ URL 里直接写 IP + 显式端口
	rows = rowsFor("http://10.0.0.5:8080/x")
	if len(rows) != 1 || rows[0].Port != 8080 || rows[0].Host != "10.0.0.5" {
		t.Errorf("IP 形式的 URL 应保留显式端口：%+v", rows)
	}

	// ④ URL 里写 IP 不写端口 → 按 scheme 的默认端口（浏览器语义）
	rows = rowsFor("http://10.0.0.5/")
	if len(rows) != 1 || rows[0].Port != 80 {
		t.Errorf("URL 没写端口时应按 scheme 补 80：%+v", rows)
	}

	// ⑤ 全局假设要说清楚（QUIC 回落、不跟重定向）
	v := b.SimulateTargets("https://main.example.com/")
	hints := strings.Join(v.Hints, "\n")
	if !strings.Contains(hints, "重定向") {
		t.Errorf("Hints 应说明不跟重定向：%v", v.Hints)
	}
	if !strings.Contains(hints, "QUIC") {
		t.Errorf("出现 443 时应提示 QUIC 会被拦下并回落：%v", v.Hints)
	}

	// ⑥ 汇总按“输入项/连接条数”分别报，不能只报输入数
	if !strings.Contains(v.Summary, "共 1 项输入") || !strings.Contains(v.Summary, "2 条连接") {
		t.Errorf("汇总应区分输入项与连接条数：%q", v.Summary)
	}
}

// 内网域名在本机解析不到是**常态**（DNS 在隧道另一端）——
// 这时必须仍能回答“这条规则覆不覆盖它”，靠的是名字匹配。
func TestSimulateDomainNotResolvable(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	cfg.Routes = []config.Route{{Name: "影像", Targets: []string{"*.example.com"}, Chain: "proxy-a", Ports: []string{"443"}}}
	rs := rules.New()
	if err := rs.Load([]rules.Route{{Name: "影像", Targets: []string{"*.example.com"}, Chain: "proxy-a", Ports: []string{"443"}}}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs

	// .invalid 是 RFC 2606 的保留域名（子域一定解析不到），系统解析必然失败
	v := b.SimulateTargets("https://no-such-host.example.com/")
	if len(v.Rows) != 1 {
		t.Fatalf("应给出 1 条连接，实际 %+v", v.Rows)
	}
	r := v.Rows[0]
	if !strings.HasPrefix(r.Source, "仅域名") {
		t.Errorf("解析不到时应说明只按名字判：%+v", r)
	}
	if r.Host != "no-such-host.example.com" || r.Port != 443 {
		t.Errorf("目标应保留域名与端口：%+v", r)
	}
	if !strings.Contains(r.Action, "proxy-a") || r.Rule != "影像" {
		t.Errorf("应靠名字命中通配规则：%+v", r)
	}
	if hints := strings.Join(v.Hints, "\n"); !strings.Contains(hints, "上游解析") {
		t.Errorf("Hints 应说明真实地址由上游解析：%v", v.Hints)
	}
}

// IP 区间与 IP 通配：规则保存时会被展开成 CIDR，模拟必须走**同一套归一化** ——
// 否则“规则里能写、模拟说无法识别”就自相矛盾了。
func TestSimulateIPRangeAndWildcard(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	cfg.Routes = []config.Route{
		{Name: "影像段", Targets: []string{"10.1.1.0/24"}, Chain: "proxy-a"},
		{Name: "弃用段", Targets: []string{"198.51.100.0/24"}, Chain: config.BlockChain},
	}
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "影像段", Targets: []string{"10.1.1.0/24"}, Chain: "proxy-a"},
		{Name: "弃用段", Targets: []string{"198.51.100.0/24"}, Chain: config.BlockChain, Action: rules.ActionBlock},
	}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs

	// ① 对齐的区间展开成一个 /24
	v := b.SimulateTargets("10.1.1.0-10.1.1.255")
	if len(v.Rows) != 1 {
		t.Fatalf("对齐区间应展开成 1 个网段，实际 %+v", v.Rows)
	}
	if r := v.Rows[0]; r.Host != "10.1.1.0/24" || !strings.Contains(r.Action, "proxy-a") {
		t.Errorf("区间应折成 10.1.1.0/24 并命中影像段：%+v", r)
	}

	// ② 非对齐的区间 → 多个网段，各自一行、各自判定
	v2 := b.SimulateTargets("10.1.1.1-10.1.1.3")
	if len(v2.Rows) < 2 {
		t.Fatalf("非对齐区间应展开成多个网段，实际 %+v", v2.Rows)
	}
	for _, r := range v2.Rows {
		if r.OK && !strings.Contains(r.Host, "/") {
			t.Errorf("每行的目标应是展开后的网段：%+v", r)
		}
		if !strings.Contains(r.Note, "区间展开") {
			t.Errorf("多网段要说清这是第几段：%+v", r)
		}
	}

	// ③ IP 通配（Proxifier 写法）= 一整段
	v3 := b.SimulateTargets("198.51.100.*")
	if len(v3.Rows) != 1 || v3.Rows[0].Host != "198.51.100.0/24" {
		t.Fatalf("IP 通配应折成 198.51.100.0/24：%+v", v3.Rows)
	}
	if !strings.Contains(v3.Rows[0].Action, "阻断") {
		t.Errorf("应命中弃用段（阻断）：%+v", v3.Rows[0])
	}

	// ④ 通配带端口
	v4 := b.SimulateTargets("198.51.100.*:443")
	if len(v4.Rows) != 1 || v4.Rows[0].Port != 443 {
		t.Errorf("通配带端口应保留端口：%+v", v4.Rows)
	}

	// ⑤ 写坏的区间：报错要指明是哪一侧（用配置层同一套文案，别自己编）
	v5 := b.SimulateTargets("10.1.1.0-10.1.1.300")
	if len(v5.Rows) != 1 || v5.Rows[0].OK || !strings.Contains(v5.Rows[0].Err, "10.1.1.300") {
		t.Errorf("写坏的区间应报错并指出坏的那一侧：%+v", v5.Rows)
	}
}
