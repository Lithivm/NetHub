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
