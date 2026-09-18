package config

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"testing"
)

// NormalizeTargets 是"一条规则填多个目标"的入口：拆分 + 归一化 + 组内去重。
// 向量覆盖真实会粘进来的写法（工单一列、表格一行、带空行的多行）。
func TestNormalizeTargets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  []string
		dup  []string
		err  string // 期望的错误里要出现这个子串（"" = 不该报错）
	}{
		{name: "空串", in: ""},
		{name: "只有空白和分隔符", in: "  \n\t , ，、;\n"},
		{name: "单个目标自动补 /32", in: "10.1.1.1", out: []string{"10.1.1.1/32"}},
		{name: "空格分隔", in: "10.1.1.1 10.1.1.2",
			out: []string{"10.1.1.1/32", "10.1.1.2/32"}},
		{name: "换行分隔（带空行和缩进）", in: "\r\n  10.1.1.1 \r\n\r\n10.1.1.2\n",
			out: []string{"10.1.1.1/32", "10.1.1.2/32"}},
		{name: "中英文标点混用", in: "10.1.1.1,10.1.1.2；10.1.1.3、10.1.1.4;10.1.1.5，10.1.1.6",
			out: []string{"10.1.1.1/32", "10.1.1.2/32", "10.1.1.3/32", "10.1.1.4/32", "10.1.1.5/32", "10.1.1.6/32"}},
		{name: "网段保留掩码", in: "10.0.1.0/24 10.0.0.0/24",
			out: []string{"10.0.1.0/24", "10.0.0.0/24"}},
		{name: "顺序即输入顺序", in: "10.1.1.3 10.1.1.1 10.1.1.2",
			out: []string{"10.1.1.3/32", "10.1.1.1/32", "10.1.1.2/32"}},
		// 判重按归一化结果：单 IP 与它的 /32、等价网段都算同一个目标
		{name: "单 IP 与 /32 重复", in: "10.1.1.1, 10.1.1.1/32",
			out: []string{"10.1.1.1/32"}, dup: []string{"10.1.1.1/32"}},
		{name: "网段写法不同但等价", in: "10.1.1.5/24 10.1.1.0/24",
			out: []string{"10.1.1.0/24"}, dup: []string{"10.1.1.0/24"}},
		{name: "同一条出现三次", in: "10.1.1.1 10.1.1.1 10.1.1.1",
			out: []string{"10.1.1.1/32"}, dup: []string{"10.1.1.1/32", "10.1.1.1/32"}},
		// 坏输入不落地：整条规则失败，不留半生效状态
		{name: "非法目标", in: "10.1.1.1 abc", err: `"abc"`},
		{name: "IPv6 不支持", in: "::1", err: "只支持 IPv4"},
		{name: "乱写的网段", in: "10.1.1.0/33", err: `"10.1.1.0/33"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, dup, err := NormalizeTargets(c.in)
			if c.err == "" {
				if err != nil {
					t.Fatalf("不该报错，却得到: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("应该报错（含 %q），却成功了: out=%q", c.err, out)
				}
				if !strings.Contains(err.Error(), c.err) {
					t.Fatalf("错误 %q 里没有 %q", err, c.err)
				}
				if out != nil || dup != nil {
					t.Fatalf("报错时不该返回半截结果: out=%q dup=%q", out, dup)
				}
				return
			}
			if strings.Join(out, ",") != strings.Join(c.out, ",") {
				t.Errorf("out = %q，期望 %q", out, c.out)
			}
			if strings.Join(dup, ",") != strings.Join(c.dup, ",") {
				t.Errorf("dup = %q，期望 %q", dup, c.dup)
			}
		})
	}
}

// 旧格式兼容：v1 的 `target:`（一条规则一个目标）要能读进来，并变成 targets 列表。
func TestLoadLegacySingleTarget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"routes:\n  - target: 10.0.1.5/24\n    chain: proxy-a\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(p)
	if err != nil {
		t.Fatalf("旧格式应该能读: %v", err)
	}
	if len(c.Routes) != 1 {
		t.Fatalf("规则数 = %d，期望 1", len(c.Routes))
	}
	r := c.Routes[0]
	if r.Target != "" {
		t.Errorf("旧字段应该被清掉，实际 = %q", r.Target)
	}
	if strings.Join(r.Targets, ",") != "10.0.1.0/24" {
		t.Errorf("旧目标应并进 targets 并归一化，实际 = %q", r.Targets)
	}

	// 保存后应该是新形状（写 targets，不再写 target）
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "- target:") {
		t.Errorf("保存后不该再写旧字段:\n%s", b)
	}
	if !strings.Contains(string(b), "targets:") {
		t.Errorf("保存后应写 targets:\n%s", b)
	}
}

// Normalize 要能认出"改动过"（旧字段、未归一化的目标、组内重复）。
func TestNormalizeReportsChange(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "proxy-a", Forward: "socks5://127.0.0.1:1080"}},
		Routes: []Route{{Target: "10.1.1.1", Chain: "proxy-a"}},
	}
	changed, err := c.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("旧字段 target 应被算作改动过")
	}
	if strings.Join(c.Routes[0].Targets, ",") != "10.1.1.1/32" {
		t.Errorf("归一化结果 = %q", c.Routes[0].Targets)
	}
	// 再来一次应该是"没改动"
	changed, err = c.Normalize()
	if err != nil || changed {
		t.Errorf("第二次不该有改动: changed=%v err=%v", changed, err)
	}
}

// 多目标规则的增改：组内去重、跨规则重复要拦、网段包含关系不拦。
func TestAddRouteMultiTarget(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "proxy-a", Forward: "socks5://127.0.0.1:1080"}},
	}
	if err := c.AddRoute(Route{
		Name:    "内网主体链路",
		Targets: []string{"10.1.1.1", "10.1.1.1/32", " 10.2.0.0/24 "},
		Chain:   "proxy-a",
	}); err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 1 {
		t.Fatalf("多条目标应该落在**一条**规则里，实际 %d 条", len(c.Routes))
	}
	if got := strings.Join(c.Routes[0].Targets, ","); got != "10.1.1.1/32,10.2.0.0/24" {
		t.Errorf("组内重复/空白没处理干净: %q", got)
	}

	// 跨规则同名目标要拒绝，且报错要点出是哪条规则
	err := c.AddRoute(Route{Targets: []string{"10.1.1.1"}, Chain: "proxy-a"})
	if err == nil {
		t.Fatal("跨规则重复目标应该被拒绝")
	}
	if !strings.Contains(err.Error(), "「内网主体链路」") {
		t.Errorf("报错要指出是哪条规则: %v", err)
	}

	// 网段包含（宽里有窄）是 Proxifier 的正常用法，不拦
	if err := c.AddRoute(Route{Name: "特殊段的特殊处理", Targets: []string{"10.1.1.0/24"}, Chain: "proxy-a"}); err != nil {
		t.Errorf("网段包含关系不该被拦: %v", err)
	}

	// 编辑时要把自己原有的目标排除在重复检查外
	if err := c.UpdateRoute(0, Route{Name: "内网主体链路", Targets: []string{"10.1.1.1", "10.3.0.0/24"}, Chain: "proxy-a"}); err != nil {
		t.Errorf("编辑自己的目标不该报重复: %v", err)
	}
	if got := strings.Join(c.Routes[0].Targets, ","); got != "10.1.1.1/32,10.3.0.0/24" {
		t.Errorf("更新后 = %q", got)
	}

	// 没有目标 / 非法目标都要拒绝
	if err := c.AddRoute(Route{Targets: nil, Chain: "proxy-a"}); err == nil {
		t.Error("空目标应该被拒绝")
	}
	if err := c.AddRoute(Route{Targets: []string{"abc"}, Chain: "proxy-a"}); err == nil {
		t.Error("非法目标应该被拒绝")
	}
}

// 报错/日志里的指代：有名字用名字，没名字用目标。
func TestRouteDescribe(t *testing.T) {
	cases := []struct {
		r    Route
		want string
	}{
		{Route{Name: "业务系统", Targets: []string{"10.1.1.1/32"}}, "「业务系统」"},
		{Route{Targets: []string{"10.1.1.1/32"}}, "（10.1.1.1/32）"},
		{Route{Targets: []string{"10.1.1.1/32", "10.1.1.2/32"}}, "（10.1.1.1/32 10.1.1.2/32）"},
		{Route{Targets: []string{"a", "b", "c"}}, "（a b …）"},
		{Route{}, "（无目标）"},
	}
	for _, c := range cases {
		if got := c.r.Describe(); got != c.want {
			t.Errorf("Describe() = %q，期望 %q", got, c.want)
		}
	}
	if got := (Route{Name: "业务系统", Targets: []string{"a", "b"}}).Label(); got != "业务系统：a, b" {
		t.Errorf("Label() = %q", got)
	}
}

// Default() 是"新装机器"的起点：不预设任何真实环境 ——
// 否则新机器一启动就会去接管别人的网段，而 forward 为空会直接校验失败，
// 逼用户先把 config.yaml 填好。
func TestDefaultIsBlankSlate(t *testing.T) {
	c := Default()
	if len(c.Routes) != 0 {
		t.Errorf("默认配置不该预置任何规则: %+v", c.Routes)
	}
	for i, ch := range c.Chains {
		if ch.Forward != "" {
			t.Errorf("第 %d 条链不该预置上游: %q", i+1, ch.Forward)
		}
	}
	if err := c.Validate(); err == nil {
		t.Error("默认配置（上游为空）应该校验失败，否则会带着无效配置启动")
	}
}

// 规则的动作除了“走某条链”还有“直连”：用保留链名 DirectChain（direct）。
// 直连不需要（也不允许）在 chains 里真的建一条链。
func TestDirectRoute(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "proxy-a", Forward: "socks5://127.0.0.1:1080"}},
	}
	if err := c.AddRoute(Route{Name: "本机网段直连", Targets: []string{"192.168.199.0/24"}, Chain: DirectChain}); err != nil {
		t.Fatalf("直连规则不该要求先建链: %v", err)
	}
	if !c.Routes[0].IsDirect() {
		t.Error("IsDirect 应为真")
	}
	// 和隧道规则共存，且隧道网段里的单个邻居也能直连（宽里有窄，不拦）
	if err := c.AddRoute(Route{Name: "HIS 主链路", Targets: []string{"10.10.10.0/24"}, Chain: "proxy-a"}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddRoute(Route{Name: "同事机器直连", Targets: []string{"10.10.10.102"}, Chain: DirectChain}); err != nil {
		t.Errorf("直连目标不该被当重复拦掉: %v", err)
	}

	// 真的建一条叫 direct 的链要拒绝：保留名，避免“到底走代理还是直连”含糊
	if err := c.AddChain(Chain{Name: DirectChain, Forward: "socks5://127.0.0.1:1080"}); err == nil {
		t.Error("链名 direct 是保留名，应该被拒绝")
	}

	// 手写配置写 chain: direct 也要能进来（并保住直连语义）
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\n" +
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n" +
		"routes:\n  - name: 本机网段直连\n    targets: [\"192.168.199.0/24\"]\n    chain: direct\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(p)
	if err != nil {
		t.Fatalf("手写直连规则应该能载入: %v", err)
	}
	if len(c2.Routes) != 1 || !c2.Routes[0].IsDirect() {
		t.Errorf("载入后丢了直连语义: %+v", c2.Routes)
	}
}

// 端口写法归一化：单端口 / 区间 / 波浪号 / 写反了自动换 / 边界。
func TestNormalizePort(t *testing.T) {
	cases := []struct{ in, want, err string }{
		{in: "443", want: "443"},
		{in: " 443 ", want: "443"},
		{in: "8000-9000", want: "8000-9000"},
		{in: "9000-8000", want: "8000-9000"},
		{in: "8000~9000", want: "8000-9000"},
		{in: "443-443", want: "443"},
		{in: "1", want: "1"},
		{in: "65535", want: "65535"},
		{in: "0", err: "1-65535"},
		{in: "65536", err: "1-65535"},
		{in: "abc", err: "不是数字"},
		{in: "443-", err: "不是数字"},
		{in: "", err: "不能为空"},
	}
	for _, tc := range cases {
		got, err := NormalizePort(tc.in)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("NormalizePort(%q) 的错误不对: %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("NormalizePort(%q) = %q, %v（期望 %q）", tc.in, got, err, tc.want)
		}
	}
}

// PortsCover：a 留空 = 任意端口覆盖一切；否则要逐段包含。
func TestPortsCover(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, []string{"443"}, true},  // 任意端口覆盖一切
		{[]string{"443"}, nil, false}, // 单个端口盖不住“任意”
		{[]string{"440-450"}, []string{"441", "449"}, true},
		{[]string{"443"}, []string{"440-450"}, false},
		{[]string{"443", "8000-9000"}, []string{"8000"}, true},
	}
	for _, tc := range cases {
		if got := PortsCover(tc.a, tc.b); got != tc.want {
			t.Errorf("PortsCover(%v, %v) = %v（期望 %v）", tc.a, tc.b, got, tc.want)
		}
	}
}

// 同一目标 + 不同端口是端口维度的正当用法，不能被“重复目标”拦掉；
// 但被上面那条**完全覆盖**的规则仍然要拦（它永远轮不到）。
func TestPortDupCheck(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "proxy-a", Forward: "socks5://127.0.0.1:1080"}},
	}
	if err := c.AddRoute(Route{Name: "只走 443", Targets: []string{"10.0.0.5"}, Ports: []string{"443"}, Chain: "proxy-a"}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddRoute(Route{Name: "只走 5432", Targets: []string{"10.0.0.5"}, Ports: []string{"5432"}, Chain: "proxy-a"}); err != nil {
		t.Errorf("同一目标不同端口应该允许: %v", err)
	}
	err := c.AddRoute(Route{Name: "重复 443", Targets: []string{"10.0.0.5"}, Ports: []string{"443"}, Chain: "proxy-a"})
	if err == nil {
		t.Fatal("端口被上面全覆盖的规则应该被拒")
	}
	if !strings.Contains(err.Error(), "443") {
		t.Errorf("报错要指明是哪个端口: %v", err)
	}
	// 上面那条留空（任意端口）时，下面再写具体端口就该被拦
	c2 := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "proxy-a", Forward: "socks5://127.0.0.1:1080"}},
	}
	if err := c2.AddRoute(Route{Targets: []string{"10.0.0.5"}, Chain: "proxy-a"}); err != nil {
		t.Fatal(err)
	}
	if err := c2.AddRoute(Route{Targets: []string{"10.0.0.5"}, Ports: []string{"443"}, Chain: "proxy-a"}); err == nil {
		t.Error("任意端口已覆盖全部端口，这条应该被拒")
	}
}

// 一条链多个上游：forward 与 forwards 归一、策略/探测间隔、YAML 写回形状。
func TestChainMultiUpstream(t *testing.T) {
	// 老写法 forward → 归一成 Upstreams()
	c := &Config{Relay: "127.0.0.1:0", Chains: []Chain{{Name: "a", Forward: "socks5://127.0.0.1:1080"}}}
	if _, err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ups := c.Chains[0].Upstreams(); len(ups) != 1 || ups[0] != "socks5://127.0.0.1:1080" {
		t.Errorf("forward 没并进 Upstreams: %v", ups)
	}

	// 多上游：去空白、去重、策略大小写归一
	c.Chains = []Chain{{Name: "a", Forwards: []string{" socks5://127.0.0.1:1080 ", "socks5://127.0.0.1:1080", "socks5://127.0.0.1:1081"}, Strategy: "ROUND"}}
	if _, err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ups := c.Chains[0].Upstreams(); len(ups) != 2 {
		t.Errorf("去重后应剩 2 条: %v", ups)
	}
	if c.Chains[0].StrategyName() != StrategyRound {
		t.Errorf("策略应归一成 round: %q", c.Chains[0].Strategy)
	}
	if d := c.Chains[0].ProbeInterval(); d != 30*time.Second {
		t.Errorf("默认探测间隔应为 30s: %v", d)
	}
	if d := (Chain{Probe: "off"}).ProbeInterval(); d != 0 {
		t.Errorf("off 应关闭探测: %v", d)
	}
	if d := (Chain{Probe: "90s"}).ProbeInterval(); d != 90*time.Second {
		t.Errorf("90s 应被解析: %v", d)
	}

	// 非法策略要报错
	c.Chains = []Chain{{Name: "a", Forward: "socks5://127.0.0.1:1", Strategy: "bogus"}}
	if _, err := c.Normalize(); err == nil {
		t.Error("非法策略应该报错")
	}

	// 一个上游都没有：校验失败
	c.Chains = []Chain{{Name: "a"}}
	if err := c.Validate(); err == nil {
		t.Error("没有上游应该校验失败")
	}
}

// 配置文件形状：单个上游写 forward:，多个写 forwards:（保持文件好读）。
func TestChainYAMLShape(t *testing.T) {
	one := &Config{Relay: "127.0.0.1:0", Chains: []Chain{{Name: "a", Forwards: []string{"socks5://127.0.0.1:1080"}}}}
	b, err := yaml.Marshal(one)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "forward: socks5://127.0.0.1:1080") || strings.Contains(string(b), "forwards:") {
		t.Errorf("单上游应写成 forward:\n%s", b)
	}

	two := &Config{Relay: "127.0.0.1:0", Chains: []Chain{{Name: "a",
		Forwards: []string{"socks5://127.0.0.1:1080", "socks5://127.0.0.1:1081"}, Strategy: "failover"}}}
	b, err = yaml.Marshal(two)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "forwards:") || strings.Contains(string(b), "forward: ") {
		t.Errorf("多上游应写成 forwards:\n%s", b)
	}
}
