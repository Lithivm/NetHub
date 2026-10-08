package engine

import (
	"net"
	"strings"
	"testing"
	"time"

	"nethub/internal/rules"
)

// statusWarnings 的判据表 —— **这张表就是“打开诊断页看到红色意味着什么”的口径**。
// 改这里的任何一行，都等于改了现场对“有事 / 没事”的理解，所以必须走测试。
func TestStatusWarnings(t *testing.T) {
	// 一个“哪都正常”的基线：跑够久了、内核句柄齐、名字表有东西、进程名查得到
	ok := func() (RuntimeStatus, ChainSummary) {
		st := RuntimeStatus{
			Running: true, Uptime: "6h12m", UptimeSec: 22320,
			Kernel: KernelFace{Main: true, Dyn: true, Inject: true, Socket: true, Reflect: true, Ranges: 12},
			Names:  NameFace{Count: 20, NewestSec: 3, Wildcards: true, Takeover: true, FakeUsed: 3, FakeCap: 65534},
			Conns:  ConnFace{Total: 700, Active: 2, ProcKnown: 10, ProcPorts: 104, ProcPIDs: 2},
			Rules:  RuleFace{Total: 7, Ranges: 12},
		}
		return st, ChainSummary{Total: 5}
	}

	if st, ch := ok(); len(statusWarnings(st, ch)) != 0 {
		t.Fatalf("基线状态不该有任何提示：%v", statusWarnings(st, ch))
	}

	cases := []struct {
		name   string
		mutate func(*RuntimeStatus, *ChainSummary)
		kind   string // 期望出现（或消失）的 kind
		absent bool
	}{
		{"引擎没在跑", func(st *RuntimeStatus, _ *ChainSummary) { st.Running = false }, "engine.stopped", false},
		{"过滤器一个区间都没有", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Kernel.Ranges = 0
			st.Rules.Total = 7
		}, "kernel.no-range", false},
		{"规则全删了就不报区间为 0", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Kernel.Ranges = 0
			st.Rules.Total = 0
		}, "kernel.no-range", true},
		{"主句柄不在", func(st *RuntimeStatus, _ *ChainSummary) { st.Kernel.Main = false }, "kernel.no-main", false},
		{"别人也在用 WinDivert", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Kernel.Peers = []string{"clash-verge.exe"}
		}, "kernel.peers", false},
		{"链不可用", func(_ *RuntimeStatus, ch *ChainSummary) { ch.Down = []string{"sjy"} }, "chain.down", false},
		// 刚启动那几十秒“还没探过”是正常态 —— 这条最容易变成误报
		{"刚启动时不报未探过", func(st *RuntimeStatus, ch *ChainSummary) {
			st.UptimeSec = 12
			ch.Untested = []string{"etyy"}
		}, "chain.untested", true},
		{"跑久了还没探过要报", func(_ *RuntimeStatus, ch *ChainSummary) {
			ch.Untested = []string{"etyy"}
		}, "chain.untested", false},
		{"有目标被前面的规则盖住", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Rules.Shadowed = []string{"第 2 条「排除更新端口」（1 个目标被覆盖）"}
		}, "rules.shadowed", false},
		{"有通配但没开 DNS 接管", func(st *RuntimeStatus, _ *ChainSummary) { st.Names.Takeover = false }, "names.no-takeover", false},
		{"有通配但名字表是空的", func(st *RuntimeStatus, _ *ChainSummary) { st.Names.Count = 0 }, "names.empty", false},
		{"刚启动时名字表空是正常的", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Names.Count = 0
			st.UptimeSec = 20
		}, "names.empty", true},
		{"没有通配规则就不提接管", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Names.Takeover = false
			st.Names.Wildcards = false
		}, "names.no-takeover", true},
		{"名字解析失败", func(st *RuntimeStatus, _ *ChainSummary) { st.Names.Failed = 2 }, "names.failed", false},
		{"名字表过期过半", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Names.Count, st.Names.Stale = 20, 12
		}, "names.stale", false},
		{"假 IP 池快满", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Names.FakeUsed, st.Names.FakeCap = 60000, 65534
		}, "names.pool-full", false},
		{"进程名查不出的偏多", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Conns.ProcKnown, st.Conns.ProcUnknow = 2, 8
		}, "proc.unknown", false},
		{"样本太小不判进程名", func(st *RuntimeStatus, _ *ChainSummary) {
			st.Conns.ProcKnown, st.Conns.ProcUnknow = 0, 3
		}, "proc.unknown", true},
	}
	for _, c := range cases {
		st, ch := ok()
		c.mutate(&st, &ch)
		got := statusWarnings(st, ch)
		found := false
		for _, w := range got {
			if w.Kind == c.kind {
				found = true
			}
		}
		if found == c.absent {
			t.Errorf("%s：kind=%s 出现=%v（想要出现=%v），实际=%v", c.name, c.kind, found, !c.absent, kinds(got))
		}
	}
}

// error 必须排在 warn 前面：卡上只显示前几条，最该修的要先被看到。
func TestStatusWarningsErrorsFirst(t *testing.T) {
	st := RuntimeStatus{
		Running: true, Uptime: "1h0m", UptimeSec: 3600,
		Kernel: KernelFace{Main: true, Ranges: 12},
		Names:  NameFace{Count: 20, Wildcards: true, Takeover: true, FakeCap: 100},
		Rules:  RuleFace{Total: 7, Shadowed: []string{"第 2 条「x」（1 个目标被覆盖）"}},
		Conns:  ConnFace{ProcKnown: 1, ProcUnknow: 9},
	}
	got := statusWarnings(st, ChainSummary{Total: 1, Down: []string{"sjy"}})
	if len(got) < 2 {
		t.Fatalf("这条状态应当至少两条提示：%v", kinds(got))
	}
	if got[0].Severity != "error" {
		t.Errorf("第一条应当是 error（最该修的排最前）：%v", kinds(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Severity == "warn" && got[i].Severity == "error" {
			t.Errorf("error 必须都在 warn 之前：%v", kinds(got))
		}
	}
}

func kinds(ws []StatusWarning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Severity+":"+w.Kind)
	}
	return out
}

func TestShortDur(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want string
	}{
		{45 * time.Second, "45s"},
		{3*time.Minute + 12*time.Second, "3m12s"},
		{time.Hour + 2*time.Minute, "1h2m"},
		{6*time.Hour + 12*time.Minute, "6h12m"},
	} {
		if got := shortDur(c.in); got != c.want {
			t.Errorf("shortDur(%s) = %q，想要 %q", c.in, got, c.want)
		}
	}
}

// rangeLabel：人读一行，含端口条件（诊断页折叠区里那份清单用它）。
func TestRangeLabel(t *testing.T) {
	rg := rules.Range{First: rules.IP2U(net.ParseIP("10.10.10.0")), Last: rules.IP2U(net.ParseIP("10.10.10.255"))}
	got := rangeLabel(rg)
	if !strings.Contains(got, "10.10.10.0") || !strings.Contains(got, "任意端口") {
		t.Errorf("rangeLabel = %q", got)
	}
	rg.Ports = []rules.PortRange{{First: 443, Last: 443}, {First: 8000, Last: 9000}}
	if got := rangeLabel(rg); !strings.Contains(got, "端口 443,8000-9000") {
		t.Errorf("端口区间没写对：%q", got)
	}
}
