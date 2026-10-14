package engine

import (
	"net"
	"strings"
	"testing"

	"nethub/internal/logbus"
)

// newLines 取环形缓冲里从 since 之后新写进来的行（logbus 没有“清空”，只能看下标）。
func newLines(b *logbus.Bus, since int) string {
	snap := b.Snapshot()
	if since > len(snap) {
		since = len(snap)
	}
	var sb strings.Builder
	for _, l := range snap[since:] {
		sb.WriteString(l.Text)
		sb.WriteString("\n")
	}
	return sb.String()
}

// 日志分档必须被钉住：normal 档一句都不许写，verbose 档才写。
//
// 为什么要专门一条测试：分档是**靠人自觉**的 —— 任何一个调用点都能顺手写成
// bus.Info 而在 code review 里看不出来。一旦破了，“简洁模式真的简洁”就要等
// 现场日志被刷爆才发现（而那时日志已经不好读了）。这条断言是它的守门人。
func TestRouteMatchOnlyInVerboseTier(t *testing.T) {
	e := newTestEngine()
	verdict := "命中第 3 条规则「HIS 主链路（etyy）」 → 走链 etyy"
	n := len(e.bus.Snapshot())

	e.routeMatchLog(51000, net.ParseIP("10.10.10.166"), 6446, "node.exe", 6702, verdict)
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("normal 档不该写 route.match：%q", got)
	}

	e.bus.SetLevel(logbus.LevelVerbose)
	e.routeMatchLog(51001, net.ParseIP("10.10.10.166"), 6446, "node.exe", 6702, verdict)
	got := newLines(e.bus, n)
	if !strings.Contains(got, "route.match: proc=node.exe pid=6702 target=10.10.10.166:6446") {
		t.Errorf("verbose 档要写出谁在连哪里：%q", got)
	}
	if !strings.Contains(got, "走链 etyy") {
		t.Errorf("verbose 档要写出为什么这么走（命中的规则与链）：%q", got)
	}

	// 同一条连接（同源端口）的重复判定在 1 分钟内塌成一行：SYN 重传不该刷屏
	n = len(e.bus.Snapshot())
	e.routeMatchLog(51001, net.ParseIP("10.10.10.166"), 6446, "node.exe", 6702, verdict)
	if got := newLines(e.bus, n); got != "" {
		t.Errorf("同一源端口 + 同一目标在窗口内只应写一行：%q", got)
	}
	// 另一条连接（新源端口）是另一行 —— Proxifier 也是每条连接一行
	n = len(e.bus.Snapshot())
	e.routeMatchLog(51002, net.ParseIP("10.10.10.166"), 6446, "node.exe", 6702, verdict)
	if got := newLines(e.bus, n); !strings.Contains(got, "route.match:") {
		t.Errorf("换一条连接就应当再有自己的一行：%q", got)
	}
}

// debug 档的状态转储（Engine.DumpState）：normal/verbose 一行都不写。
//
// 为什么要它：转储属于 debug 档的“内容”，若哪次重构把它改成 Info，
// 没启动引擎时也会每次切档刷一行；而这正是一开始那次“详细档看起来没用”的病因。
func TestDumpStateOnlyInDebugTier(t *testing.T) {
	e := newTestEngine() // 未启动：转储应当只写一行“引擎没在跑”，不炸
	n := len(e.bus.Snapshot())
	e.DumpState("测试")
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("normal 档不该转储：%q", got)
	}

	e.bus.SetLevel(logbus.LevelVerbose)
	n = len(e.bus.Snapshot())
	e.DumpState("测试")
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("verbose 档也不该转储：%q", got)
	}

	e.bus.SetLevel(logbus.LevelDebug)
	n = len(e.bus.Snapshot())
	e.DumpState("切到 debug 档")
	got := newLines(e.bus, n)
	if !strings.Contains(got, "dump.state") || !strings.Contains(got, "引擎没在跑") {
		t.Fatalf("debug 档应当说明“引擎没在跑”，得到：%q", got)
	}
}

// 每条链计数那行必须稳定排序：两次转储要能直接对比（map 遍历顺序是随机的）。
func TestChainCountsTextStable(t *testing.T) {
	in := map[string]uint64{"sjy": 2, "etyy": 724, "direct": 70}
	if got := chainCountsText(in); got != "direct:70,etyy:724,sjy:2" {
		t.Errorf("chainCountsText = %q", got)
	}
	if got := chainCountsText(nil); got != "无" {
		t.Errorf("空表应当是“无”，得到 %q", got)
	}
}

// 规则判定的那句话：有编号有名字才有用（现场要能对着规则列表核）。
func TestHitText(t *testing.T) {
	for _, c := range []struct {
		no   int
		name string
		want string
	}{
		{0, "", "没有规则命中"},
		{0, "不该被用到的名字", "没有规则命中"},
		{3, "", "命中第 3 条规则"},
		{3, "HIS 主链路（etyy）", "命中第 3 条规则「HIS 主链路（etyy）」"},
	} {
		if got := hitText(c.no, c.name); got != c.want {
			t.Errorf("hitText(%d, %q) = %q，想要 %q", c.no, c.name, got, c.want)
		}
	}
}

// 我们自己的探针（自检 / 共存检测走的 DialSelf 连接）在 normal 档**一行都不许写**：
// 它们是仪器不是应用流量 —— 与「不进连接列表、不计累计」同一条原则。
//
// 2026-10-14 用户报“一启动就打印了这么多日志”：开机那串 `proc=nethub.exe` 的
// intercept/relay.done 就是它们（界面一加载就做一次共存检测），
// 日志里看不出“这是我们自己发的”，看着像应用在连。
func TestSelfProbeConnLogOnlyInVerboseTier(t *testing.T) {
	e := newTestEngine()
	n := len(e.bus.Snapshot())

	e.connInfo(true, "intercept: chain=sjy target=10.100.100.99:443 action=relay")
	e.connInfo(true, "relay.done: chain=sjy target=10.100.100.99:443 up=0 B down=0 B")
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("normal 档不该写自己的探针连接：%q", got)
	}

	e.bus.SetLevel(logbus.LevelVerbose)
	e.connInfo(true, "intercept: chain=sjy target=10.100.100.99:443 action=relay")
	if got := newLines(e.bus, n); !strings.Contains(got, "intercept: chain=sjy target=10.100.100.99:443") {
		t.Errorf("verbose 档要能看到探针（否则自检排查没线索）：%q", got)
	}

	// 真实应用流量照旧：normal 档必须可见
	n = len(e.bus.Snapshot())
	e.connInfo(false, "relay.done: chain=etyy target=172.30.4.217:443 up=1 B down=2 B")
	if got := newLines(e.bus, n); !strings.Contains(got, "relay.done: chain=etyy") {
		t.Errorf("应用流量的连接必须在 normal 档可见：%q", got)
	}
}
