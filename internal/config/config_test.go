package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"nethub/internal/secret"
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
	if err := c.AddRoute(Route{Name: "本机网段直连", Targets: []string{"192.168.1.0/24"}, Chain: DirectChain}); err != nil {
		t.Fatalf("直连规则不该要求先建链: %v", err)
	}
	if !c.Routes[0].IsDirect() {
		t.Error("IsDirect 应为真")
	}
	// 和隧道规则共存，且隧道网段里的单个邻居也能直连（宽里有窄，不拦）
	if err := c.AddRoute(Route{Name: "HIS 主链路", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a"}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddRoute(Route{Name: "同事机器直连", Targets: []string{"10.0.0.102"}, Chain: DirectChain}); err != nil {
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
		"routes:\n  - name: 本机网段直连\n    targets: [\"192.168.1.0/24\"]\n    chain: direct\n"
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

// 规则智能：影子目标（被前面的规则完全覆盖）、最具体优先排序、配置体检。
func TestShadowSortPrecheck(t *testing.T) {
	c := &Config{
		Relay: "127.0.0.1:0",
		Chains: []Chain{
			{Name: "a", Forward: "socks5://127.0.0.1:1080"},
			{Name: "b", Forwards: []string{"socks5://127.0.0.1:1081", "socks5://127.0.0.1:1082"}},
		},
		Routes: []Route{
			// 先宽
			{Name: "宽", Targets: []string{"10.0.0.0/24"}, Chain: "a"},
			// 再窄：这是正常用法，不该被当成影子
			{Name: "窄", Targets: []string{"10.0.0.5/32"}, Chain: "b"},
			// 这条完全被第一条覆盖（目标相同 + 端口没写 = 端口被覆盖）
			{Name: "没用", Targets: []string{"10.0.0.0/24"}, Chain: "b"},
			// 同目标但端口不同 —— 不算影子（端口维度上是两条不同的规则）
			{Name: "端口版", Targets: []string{"10.0.0.7/32"}, Ports: []string{"443"}, Chain: "b"},
			{Name: "端口版2", Targets: []string{"10.0.0.7/32"}, Ports: []string{"5432"}, Chain: "b"},
		},
	}
	if _, err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if got := c.ShadowedTargets(2); len(got) != 1 || got[0] != "10.0.0.0/24" {
		t.Errorf("第 3 条应被标成影子: %v", got)
	}
	// 窄规则排在宽规则后面 = 永远轮不到（旧测试以为没问题，其实是死的）
	if got := c.ShadowedTargets(1); len(got) != 1 {
		t.Errorf("窄规则排在宽规则后面应被标成影子: %v", got)
	}
	// 端口版2 虽然和端口版1 端口不同，但被最上面那条无边界的 /24 包住了 → 仍是死的
	if got := c.ShadowedTargets(4); len(got) != 1 {
		t.Errorf("被更宽的规则包住（不管端口）也是影子: %v", got)
	}

	// 体检报告要把影子与“单上游”都点出来
	rep := strings.Join(c.Precheck(), "\n")
	if !strings.Contains(rep, "永远不生效") {
		t.Errorf("体检要指出影子目标:\n%s", rep)
	}
	if !strings.Contains(rep, "只有一条上游") {
		t.Errorf("体检要提醒单上游风险:\n%s", rep)
	}

	// 最具体优先排序：/32 与带端口的排前面
	if !c.SortRoutesBySpecificity() {
		t.Fatal("乱序时应返回“有改动”")
	}
	order := []string{}
	for _, r := range c.Routes {
		order = append(order, r.Name)
	}
	// 期望：两个带端口的 /32 在最前，其次不带端口的 /32，然后是 /24，最后是被覆盖的那条
	if order[0] != "端口版" || order[1] != "端口版2" {
		t.Errorf("带端口的 /32 应排最前: %v", order)
	}
	if order[2] != "窄" {
		t.Errorf("不带端口的 /32 应排在带端口的后面: %v", order)
	}
	if order[3] != "宽" {
		t.Errorf("/24 应排在 /32 后面: %v", order)
	}
	if c.SortRoutesBySpecificity() {
		t.Error("已经有序时不该再返回有改动")
	}
}

// 配置备份：保存会自动备一份（最多留 20），能列出来也能回滚。
func TestConfigBackupRestore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	seed := "relay: 127.0.0.1:0\nchains:\n  - name: a\n    forward: socks5://127.0.0.1:1080\nroutes: []\n"
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	// 改点东西再存：应产生备份
	c.Routes = []Route{{Name: "新的", Targets: []string{"10.0.0.0/24"}, Chain: "a"}}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	list := c.Backups()
	if len(list) != 1 {
		t.Fatalf("保存应产生 1 份备份，实际 %d: %v", len(list), list)
	}
	// 回滚：配置应回到“没有规则”的状态，且当前配置被再备一份
	restored, err := c.RestoreBackup(list[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Routes) != 0 {
		t.Errorf("回滚后应没有规则: %+v", restored.Routes)
	}
	if got := restored.Backups(); len(got) < 2 {
		t.Errorf("回滚前应把当前配置也备一份: %v", got)
	}
}

// 影子目标要认“被前面的宽网段整个包住”这种情况（最常见的排序错误），
// 但同网段不同端口不算（端口维度上是两条不同的规则）。
func TestShadowedByWiderRule(t *testing.T) {
	c := &Config{Relay: "127.0.0.1:0", Chains: []Chain{{Name: "a", Forward: "socks5://127.0.0.1:1080"}}}
	// 先宽后窄：窄的永远轮不到
	c.Routes = []Route{
		{Name: "宽", Targets: []string{"10.0.0.0/24"}, Chain: "a"},
		{Name: "窄", Targets: []string{"10.0.0.5/32"}, Chain: "a"},
		{Name: "窄但不同端口", Targets: []string{"10.0.0.7/32"}, Ports: []string{"80"}, Chain: "a"},
	}
	if got := c.ShadowedTargets(1); len(got) != 1 || got[0] != "10.0.0.5/32" {
		t.Errorf("被宽规则包住的 /32 应被标成影子: %v", got)
	}
	if got := c.ShadowedTargets(2); len(got) != 1 {
		t.Errorf("窄但端口不同，也算被“目标上”包住（端口没被盖住，但目标命中即停）: %v", got)
	}
	// 反过来（窄在前）就不该被标
	c.Routes = []Route{
		{Name: "窄", Targets: []string{"10.0.0.5/32"}, Chain: "a"},
		{Name: "宽", Targets: []string{"10.0.0.0/24"}, Chain: "a"},
	}
	if got := c.ShadowedTargets(1); len(got) != 0 {
		t.Errorf("窄在前时宽的不算影子: %v", got)
	}
	// 带端口的宽规则 + 同端口窄规则 → 影子；端口不覆盖 → 不算
	c.Routes = []Route{
		{Name: "宽443", Targets: []string{"10.0.0.0/24"}, Ports: []string{"443"}, Chain: "a"},
		{Name: "窄443", Targets: []string{"10.0.0.5/32"}, Ports: []string{"443"}, Chain: "a"},
		{Name: "窄80", Targets: []string{"10.0.0.9/32"}, Ports: []string{"80"}, Chain: "a"},
	}
	if got := c.ShadowedTargets(1); len(got) != 1 {
		t.Errorf("同端口才被盖住: %v", got)
	}
	if got := c.ShadowedTargets(2); len(got) != 0 {
		t.Errorf("不同端口不该被标成影子: %v", got)
	}
}

// 拨号调优：默认 5s/10s，非法值回默认，极值夹住，总预算不小于单次超时。
func TestDialTuning(t *testing.T) {
	c := &Config{}
	if got := c.DialTimeoutDur(); got != 5*time.Second {
		t.Errorf("默认单次超时应为 5s，得到 %s", got)
	}
	if got := c.DialBudgetDur(); got != 10*time.Second {
		t.Errorf("默认总预算应为 10s，得到 %s", got)
	}

	c.Tuning = Tuning{DialTimeout: "3s", DialBudget: "20s"}
	if c.DialTimeoutDur() != 3*time.Second || c.DialBudgetDur() != 20*time.Second {
		t.Errorf("自定义值没生效: %s / %s", c.DialTimeoutDur(), c.DialBudgetDur())
	}

	// 总预算比单次还小 → 提到单次（否则第一条就被预算卡掉）
	c.Tuning = Tuning{DialTimeout: "5s", DialBudget: "2s"}
	if got := c.DialBudgetDur(); got != 5*time.Second {
		t.Errorf("总预算不该小于单次超时，得到 %s", got)
	}

	// 非法/越界
	c.Tuning = Tuning{DialTimeout: "很快", DialBudget: "-1s"}
	if c.DialTimeoutDur() != 5*time.Second || c.DialBudgetDur() != 10*time.Second {
		t.Errorf("非法值应回默认: %s / %s", c.DialTimeoutDur(), c.DialBudgetDur())
	}
	c.Tuning = Tuning{DialTimeout: "5m", DialBudget: "10m"}
	if c.DialTimeoutDur() != 30*time.Second || c.DialBudgetDur() != time.Minute {
		t.Errorf("极值应夹住: %s / %s", c.DialTimeoutDur(), c.DialBudgetDur())
	}
	c.Tuning = Tuning{DialTimeout: "100ms"}
	if c.DialTimeoutDur() != time.Second {
		t.Errorf("过小的单次超时应提到 1s，得到 %s", c.DialTimeoutDur())
	}

	// 体检要把“会让人等太久”的情况说出来
	c.Chains = []Chain{{Name: "a", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = []Route{{Name: "r", Targets: []string{"10.0.0.0/24"}, Chain: "a"}}
	c.Relay = "127.0.0.1:0"
	c.Tuning = Tuning{DialTimeout: "15s"}
	found := false
	for _, line := range c.Precheck() {
		if strings.Contains(line, "单次上游超时") {
			found = true
		}
	}
	if !found {
		t.Error("单次超时 15s 时体检应该提醒")
	}
}

// A20：进程条件必须能存下来、也能读回来。
// 这条测试存在的理由：normalize() 是按值改字段的，漏了一行就会“保存后条件消失”
// —— 和当初 chain.secret 被写掉是同一类 bug，靠人眼看代码看不出来。
func TestRouteAppsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = nil

	// ① 只按进程（无目标）
	if err := c.AddRoute(Route{Name: "客户端全走隧道", Chain: "tun", Apps: []string{"his.exe", " *Weixin* "}}); err != nil {
		t.Fatalf("添加只按进程的规则失败: %v", err)
	}
	// ② 目标 + 进程（AND）
	if err := c.AddRoute(Route{Name: "例外", Targets: []string{"10.0.0.0/8"}, Chain: DirectChain,
		Apps: []string{`C:\Tools\raw.exe`}}); err != nil {
		t.Fatalf("添加目标+进程规则失败: %v", err)
	}
	if err := c.SaveAs(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("重新载入失败: %v", err)
	}
	if len(got.Routes) != 2 {
		t.Fatalf("规则数 = %d，期望 2", len(got.Routes))
	}
	r0 := got.Routes[0]
	if len(r0.Targets) != 0 {
		t.Errorf("第 1 条不该有目标，得到 %v", r0.Targets)
	}
	if len(r0.Apps) != 2 || r0.Apps[0] != "his.exe" || r0.Apps[1] != "*Weixin*" {
		t.Errorf("第 1 条进程条件 = %v，期望 [his.exe *Weixin*]（去空白、保大小写）", r0.Apps)
	}
	r1 := got.Routes[1]
	if len(r1.Apps) != 1 || !strings.EqualFold(r1.Apps[0], `C:\Tools\raw.exe`) {
		t.Errorf("第 2 条进程条件应原样保存（匹配时自行取文件名），得到 %v", r1.Apps)
	}
	if len(r1.Targets) != 1 || r1.Targets[0] != "10.0.0.0/8" {
		t.Errorf("第 2 条目标 = %v", r1.Targets)
	}

	// ③ 没目标又没进程 → 必须拒绝（否则会存出一条什么都不匹配的规则）
	if err := c.AddRoute(Route{Name: "空规则", Chain: "tun"}); err == nil {
		t.Error("既没目标也没进程条件的规则应被拒绝")
	}
	// ④ 进程条件重复要去重（不区分大小写）
	c2 := Default()
	c2.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c2.Routes = nil
	if err := c2.AddRoute(Route{Name: "重复", Chain: "tun", Apps: []string{"a.exe", "A.EXE", "a.exe"}}); err != nil {
		t.Fatalf("添加失败: %v", err)
	}
	if len(c2.Routes[0].Apps) != 1 {
		t.Errorf("进程条件未去重: %v", c2.Routes[0].Apps)
	}
}

// A20：有“只按进程”的规则时，排序与重叠检查不能崩，也不能给它乱定优先级。
func TestAppsOnlyRuleNoPanic(t *testing.T) {
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = nil
	if err := c.AddRoute(Route{Name: "例外", Chain: "tun", Apps: []string{"x.exe"}}); err != nil {
		t.Fatalf("添加失败: %v", err)
	}
	if err := c.AddRoute(Route{Name: "窄", Targets: []string{"10.0.0.5"}, Chain: "tun"}); err != nil {
		t.Fatalf("添加失败: %v", err)
	}
	c.SortRoutesBySpecificity() // 不得 panic
	ov := c.CheckOverlaps()     // 不得 panic
	t.Logf("排序后顺序: %v / 重叠结论 %d 条", []string{c.Routes[0].Name, c.Routes[1].Name}, len(ov))
	// 只按进程的规则目标为空 → 它不该被当成“覆盖别人”的那条
	for _, o := range ov {
		if o.Kind == "dead" && (o.EarlierName == "例外" || o.LaterName == "例外") {
			t.Errorf("只按进程的规则被误判为 dead: %+v", o)
		}
	}
}

// 规则开关：停用的规则不进匹配、不占目标、不参与排序与重叠判断。
func TestRouteEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = nil

	// 同一段内网地址，两条规则指向不同链（多环境现场就是这么用的）
	if err := c.AddRoute(Route{Name: "环境A", Targets: []string{"172.30.4.0/24"}, Chain: "tun"}); err != nil {
		t.Fatalf("加环境A失败: %v", err)
	}
	dup := Route{Name: "环境B", Targets: []string{"172.30.4.0/24"}, Chain: "tun"}
	dup.SetEnabled(false)
	if err := c.AddRoute(dup); err != nil {
		t.Fatalf("停用的重复规则应允许共存: %v", err)
	}
	// 两条都启用时 —— 必须报“目标已被占”
	if err := c.AddRoute(Route{Name: "环境C", Targets: []string{"172.30.4.0/24"}, Chain: "tun"}); err == nil {
		t.Error("两条都启用时，重复目标应被拒绝")
	}

	// 存盘 → 读回：开关要保留，缺省视为启用
	if err := c.SaveAs(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("载入失败: %v", err)
	}
	if !got.Routes[0].IsEnabled() {
		t.Error("第 1 条没写 enabled 应视为启用")
	}
	if got.Routes[1].IsEnabled() {
		t.Error("显式 false 的规则应视为停用")
	}
	// 停用的规则不参与匹配（引擎侧由 toRules 过滤，这里验 config 侧的判断）
	if names := got.EnabledRoutes(); len(names) != 1 || names[0].Name != "环境A" {
		t.Errorf("启用规则集 = %+v", names)
	}
	// 停用当前那条 → 第二条（停用的）不参与“被覆盖/冲突”结论
	if sh := got.ShadowedTargets(1); len(sh) != 0 {
		t.Errorf("停用的规则不该被判成被覆盖: %v", sh)
	}
	if ov := got.CheckOverlaps(); len(ov) != 0 {
		t.Errorf("停用的规则之间不该报重叠: %+v", ov)
	}
	// 排序：停用的原地不动
	got.SortRoutesBySpecificity()
	if got.Routes[1].Name != "环境B" {
		t.Errorf("停用的规则应保持原位，得到 %+v", []string{got.Routes[0].Name, got.Routes[1].Name})
	}
}

// 停用的规则引用不存在的链时允许载入（可以把某环境的规则整套停着放着），
// 但启用后存盘必须报错（这时候才需要补链）。
func TestDisabledRuleMissingChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = []Route{{Name: "别的环境", Targets: []string{"10.9.9.0/24"}, Chain: "不存在的链"}}
	if err := c.SaveAs(path); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("缺省启用时引用不存在的链，应该报错才对")
	}

	// 停用后 → 可以载入
	raw, _ := os.ReadFile(path)
	_ = os.WriteFile(path, []byte(strings.Replace(string(raw), "chain: 不存在的链",
		"chain: 不存在的链\n      enabled: false", 1)), 0o600)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("停用后引用不存在的链应允许: %v", err)
	}
	if got.Routes[0].IsEnabled() {
		t.Fatal("这条应该是停用的")
	}
	// 直接把它启用再校验 → 必须报错
	got.Routes[0].SetEnabled(true)
	if err := got.Validate(); err == nil {
		t.Error("启用后引用不存在的链，校验必须报错")
	}
}

// 自动排序：把“本机自身/环回”（127.0.0.0/8）排到最底下，其余按最具体优先。
func TestSortPutsLoopbackLast(t *testing.T) {
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = []Route{
		{Name: "Localhost", Targets: []string{"127.0.0.1/32"}, Chain: DirectChain},
		{Name: "大网段", Targets: []string{"10.0.0.0/8"}, Chain: "tun"},
		{Name: "窄段", Targets: []string{"10.1.2.0/24"}, Chain: "tun"},
		{Name: "环回段", Targets: []string{"127.0.0.0/8"}, Chain: DirectChain},
	}
	if !c.SortRoutesBySpecificity() {
		t.Fatal("应该需要重排")
	}
	got := []string{}
	for _, r := range c.Routes {
		got = append(got, r.Name)
	}
	want := []string{"窄段", "大网段", "Localhost", "环回段"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("排序结果 = %v，期望 %v", got, want)
		}
	}
	// 已经排好 → 再点一次不该有改动
	if c.SortRoutesBySpecificity() {
		t.Error("已经排好时不该报有改动（否则按钮每次都说“整理过了”）")
	}
}

// 自动排序：本机/兜底类（环回，以及"直连 + 全私网"）都排最后 —— 不再夹在业务网段中间。
func TestSortPutsLocalDirectLast(t *testing.T) {
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5://127.0.0.1:1080"}}
	c.Routes = []Route{
		{Name: "环回直连", Targets: []string{"127.0.0.1/32"}, Chain: DirectChain},
		{Name: "本地直连", Targets: []string{"172.22.224.0/20", "192.168.199.0/24"}, Chain: DirectChain},
		{Name: "bs 环境", Targets: []string{"10.24.67.0/24", "10.24.68.0/24"}, Chain: "tun"},
		{Name: "窄段业务", Targets: []string{"172.16.20.172/32"}, Chain: "tun"},
	}
	if !c.SortRoutesBySpecificity() {
		t.Fatal("应该需要重排")
	}
	var got []string
	for _, r := range c.Routes {
		got = append(got, r.Name)
	}
	want := []string{"窄段业务", "bs 环境", "环回直连", "本地直连"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("排序结果 = %v，期望 %v（兜底类都要在最后）", got, want)
		}
	}
	// 再点一次不该有改动
	if c.SortRoutesBySpecificity() {
		t.Error("已经排好时不该报有改动")
	}
	// 走链的私网规则不算兜底（bs 是链，排在直连类前面）
	if selfRule(Route{Targets: []string{"10.24.67.0/24"}, Chain: "tun"}) {
		t.Error("走链的私网规则不该被当成兜底类")
	}
	if !selfRule(Route{Targets: []string{"192.168.199.0/24"}, Chain: DirectChain}) {
		t.Error("直连的私网规则应算兜底类")
	}
	// 直连但目标是公网 → 不算兜底（那是“这些公网地址不走代理”的具体决定）
	if selfRule(Route{Targets: []string{"39.103.146.155/32"}, Chain: DirectChain}) {
		t.Error("直连的公网目标不该算兜底类")
	}
}

// 规则目标可以是域名（原样保留，不换成 IP），通配暂时明确拒绝。
func TestTargetAcceptsHostname(t *testing.T) {
	for in, want := range map[string]string{
		"main.his.com":    "main.his.com",
		"MAIN.HIS.COM":    "main.his.com",
		"opm.his.com.":    "opm.his.com.",
		"10.0.0.5":        "10.0.0.5/32",
		"10.0.0.0/24":     "10.0.0.0/24",
		"main-wbzxyy.cn":  "main-wbzxyy.cn",
		"a1.b2-c3.d4.com": "a1.b2-c3.d4.com",
		// 通配域名（靠观察到的 DNS 匹配）：归一化成 小写 + 单个前导 *
		"*.HIS.com":  "*.his.com",
		"*.his.com.": "*.his.com",
		"*.corp":     "*.corp",
	} {
		got, err := NormalizeTarget(in)
		if err != nil {
			t.Errorf("NormalizeTarget(%q) 报错: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeTarget(%q) = %q，期望 %q", in, got, want)
		}
	}
	// 通配域名里写错位置/写太宽：拒绝，报错要说清只支持 `*.域名`
	for _, bad := range []string{"main.*.com", "*his.com"} {
		_, err := NormalizeTarget(bad)
		if err == nil {
			t.Errorf("%q 应该被拒绝（只支持 *.域名）", bad)
			continue
		}
		if !strings.Contains(err.Error(), "*.域名") {
			t.Errorf("%q 的报错要说明支持的写法，得到 %v", bad, err)
		}
	}
	// 其他畸形写法：拒绝即可，但报错不能是空的也不能没有信息量
	for _, bad := range []string{"*", "*.", "*.a..com", "*.10.0.0.1"} {
		_, err := NormalizeTarget(bad)
		if err == nil {
			t.Errorf("%q 应该被拒绝", bad)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%q 的报错是空的", bad)
		}
	}
	// 明显不是域名也不是 IP 的写法仍要被挡
	for _, bad := range []string{"hello", "10.0.0.5/33", "a b.com"} {
		if _, err := NormalizeTarget(bad); err == nil {
			t.Errorf("%q 不是合法目标，应被拒绝", bad)
		}
	}
}

// IP 通配（Proxifier 写法）：10.100.100.* = 10.100.100.0/24。
func TestIPWildcard(t *testing.T) {
	for in, want := range map[string]string{
		"10.100.100.*": "10.100.100.0/24",
		"172.30.4.*":   "172.30.4.0/24",
		"192.168.1.*":  "192.168.1.0/24",
	} {
		got, err := NormalizeTarget(in)
		if err != nil {
			t.Errorf("NormalizeTarget(%q) 报错: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeTarget(%q) = %q，期望 %q", in, got, want)
		}
	}
	// 猜不出范围的写法要拒绝，并且说清怎么写（单独一个 * 走的是通配域名那条路，在上一组用例里）
	for _, bad := range []string{"10.*.100.5", "10.100.*.5"} {
		_, err := NormalizeTarget(bad)
		if err == nil {
			t.Errorf("%q 应该被拒绝", bad)
			continue
		}
		if !strings.Contains(err.Error(), "CIDR") {
			t.Errorf("%q 的报错要告诉用户改用 CIDR，得到 %v", bad, err)
		}
	}
}

// 不再加密：保存后配置里就是明文口令（和 gost 脚本一样），并且老配置的
// `secret:` 引用会被摊平成明文（下次保存自动迁移，不需要手工处理）。
func TestSaveWritesPlaintextCreds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	c := Default()
	c.Chains = []Chain{{Name: "tun", Forward: "socks5+tls://u:p@1.2.3.4:10080"}}
	c.Routes = nil
	if err := c.SaveAs(path); err != nil { // SaveAs 也走同一条落盘路径
		t.Fatalf("保存失败: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "u:p@1.2.3.4:10080") {
		t.Errorf("配置里应该是明文口令（不再加密），实际内容：\n%s", raw)
	}
	if strings.Contains(string(raw), "secret:") {
		t.Errorf("新版不该再写 secret: 引用：\n%s", raw)
	}
}

// 老配置（带 secret: 引用 + 保险箱里有口令）保存后要变成明文，引用被清掉。
func TestFlattenLegacySecrets(t *testing.T) {
	dir := t.TempDir()
	store, err := secret.Load(dir)
	if err != nil {
		t.Fatalf("打开假保险箱失败: %v", err)
	}
	if err := store.Put("chain-a", "userA:passA"); err != nil {
		t.Fatalf("写入假保险箱失败: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("保存假保险箱失败: %v", err)
	}
	path := filepath.Join(dir, "config.yaml")
	seed := "relay: 127.0.0.1:0\nchains:\n  - name: tun\n    forward: socks5+tls://1.2.3.4:10080\n    secret: chain-a\nroutes: []\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("载入失败: %v", err)
	}
	if got := c.UpstreamsResolved(c.Chains[0]); len(got) != 1 || !strings.Contains(got[0], "userA:passA") {
		t.Fatalf("引用的口令应该解得出来，得到 %v", got)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	raw, _ := os.ReadFile(path)
	s := string(raw)
	if !strings.Contains(s, "userA:passA") {
		t.Errorf("保存后应把口令摊平成明文，实际：\n%s", s)
	}
	if strings.Contains(s, "secret:") {
		t.Errorf("摊平后不该再有 secret: 引用：\n%s", s)
	}
}

// 手写进 config.yaml 的 IP 通配，也要能正常生效（不能只在界面保存那条路上才展开）。
func TestWildcardFromYAML(t *testing.T) {
	y := `version: 1
chains:
  - name: etyy
    forward: socks5://u:p@1.2.3.4:1080
routes:
  - targets: ["10.100.100.*"]
    chain: etyy
    enabled: true
`
	// 走真实的加载路径（写文件 → Load → Normalize → Rules）
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	// 配置层的契约：手写的通配在 Load 时就被展开成 CIDR（引擎/规则/过滤器只认 CIDR）。
	if len(c.Routes) != 1 {
		t.Fatalf("应有 1 条规则，实际 %d", len(c.Routes))
	}
	got := c.Routes[0].Targets
	if len(got) != 1 || got[0] != "10.100.100.0/24" {
		t.Fatalf("通配应被展开成 10.100.100.0/24，实际 %v", got)
	}
	// 落盘时也应该是展开后的写法（下次打开不再依赖展开逻辑）
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "10.100.100.0/24") || strings.Contains(string(b), "10.100.100.*") {
		t.Errorf("保存的配置里应该是 CIDR：\n%s", b)
	}
}
