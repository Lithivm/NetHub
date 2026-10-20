package engine

import (
	"net"
	"strings"
	"testing"

	"nethub/internal/dnsmap"
	"nethub/internal/fakeip"
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
// open/close 就是它们（界面一加载就做一次共存检测），
// 日志里看不出“这是我们自己发的”，看着像应用在连。
func TestSelfProbeConnLogOnlyInVerboseTier(t *testing.T) {
	e := newTestEngine()
	n := len(e.bus.Snapshot())

	e.connInfo(true, "open: nethub.exe (1) → 10.100.100.99:443 via sjy")
	e.connInfo(true, "close: nethub.exe (1) → 10.100.100.99:443 via sjy ↑0 B ↓0 B 1ms/2ms")
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("normal 档不该写自己的探针连接：%q", got)
	}

	e.bus.SetLevel(logbus.LevelVerbose)
	e.connInfo(true, "open: nethub.exe (1) → 10.100.100.99:443 via sjy")
	if got := newLines(e.bus, n); !strings.Contains(got, "open: nethub.exe (1) → 10.100.100.99:443") {
		t.Errorf("verbose 档要能看到探针（否则自检排查没线索）：%q", got)
	}

	// 真实应用流量照旧：normal 档必须可见
	n = len(e.bus.Snapshot())
	e.connInfo(false, "close: chrome.exe (999) → 172.30.4.217:443 via etyy ↑1 B ↓2 B 5ms/9ms")
	if got := newLines(e.bus, n); !strings.Contains(got, "close: chrome.exe (999) → 172.30.4.217:443 via etyy") {
		t.Errorf("应用流量的连接必须在 normal 档可见：%q", got)
	}
}

// 连接行对齐 Proxifier：`谁 (pid) → 目标 via 链`，名字已知时要写名字。
//
// 为什么：`172.30.4.217:80` 运维认不出是哪个业务，`main.his.com` 一眼就懂；
// 而 pid 0 是 Windows 的空闲进程（不可能拥有 TCP 连接），打出来只会骗人。
func TestConnLineFormat(t *testing.T) {
	if got := connWho("curl.exe", 12376); got != "curl.exe (12376)" {
		t.Errorf("connWho = %q", got)
	}
	if got := connWho("curl.exe", 0); got != "curl.exe" {
		t.Errorf("pid 0 不该写出来：%q", got)
	}
	if got := connWho("", 1234); got != "未知进程" {
		t.Errorf("进程查不到时要说不知道：%q", got)
	}

	e := newTestEngine()
	e.names = dnsmap.New()
	ip := net.ParseIP("172.30.4.217")
	if got := e.connTarget(ip, 80); got != "172.30.4.217:80" {
		t.Errorf("名字不知道时只写地址：%q", got)
	}
	e.names.Set("main.his.com", []string{ip.String()}, dnsmap.PrioObserved)
	if got := e.connTarget(ip, 80); got != "main.his.com(172.30.4.217):80" {
		t.Errorf("名字已知时带上名字：%q", got)
	}
	// 假 IP 只写名字（假 IP 是我们自己发的临时地址，写进日志只会让人去查一个不存在的地址）
	if pool, perr := fakeip.NewPool("198.19.0.0/16"); perr == nil {
		e.fake = pool
	}
	fake := net.ParseIP("198.19.0.1")
	e.names.Set("main.xamjyy.com", []string{fake.String()}, dnsmap.PrioObserved)
	if got := e.connTargetDial(fake, net.ParseIP("10.100.100.99"), 443); got != "main.xamjyy.com:443" {
		t.Errorf("假 IP 应当只写名字：%q", got)
	}
}

// normal 档只留 errors + 连接 open/close（Proxifier 的定义）；
// 判定面（stats / DNS 请求与应答 / ECH / 建隧道的方式）一律归 verbose。
//
// 这条用例是分档的守门人：加日志行时很容易顺手写成 bus.Info，
// 而“normal 又变吵了”要到现场才发现（那时日志已经没有可读性）。
func TestJudgementLinesStayOutOfNormal(t *testing.T) {
	e := newTestEngine()
	n := len(e.bus.Snapshot())

	// 每一行都写成“最容易被误写成 Info”的形态
	e.bus.Detail("stats: total=1 new=1 active=0 names=0 fake=0/65534 chain=") // 周期快照
	e.bus.Detail("dns.query: name=a.example type=A from=127.0.0.1:53")        // DNS 请求
	e.bus.Detail("upstream.pick: chain=etyy upstream=#1/1 socks5://x:10080 现拨 lat_ms=12")
	e.bus.Detail("conn.stage: a.exe (1) → x:80 via etyy resolve=1ms dial=2ms first_byte=3ms total=9ms")
	if got := newLines(e.bus, n); got != "" {
		t.Fatalf("normal 档不该写判定面：%q", got)
	}
	// verbose 档：这四类都要看得见
	e.bus.SetLevel(logbus.LevelVerbose)
	e.bus.Detail("stats: total=1 new=1 active=0 names=0 fake=0/65534 chain=")
	e.bus.Detail("dns.query: name=a.example type=A from=127.0.0.1:53")
	e.bus.Detail("upstream.pick: chain=etyy upstream=#1/1 socks5://x:10080 现拨 lat_ms=12")
	e.bus.Detail("conn.stage: a.exe (1) → x:80 via etyy resolve=1ms dial=2ms first_byte=3ms total=9ms")
	got := newLines(e.bus, n)
	for _, want := range []string{"stats:", "dns.query:", "upstream.pick:", "conn.stage:"} {
		if !strings.Contains(got, want) {
			t.Errorf("verbose 档应当看到 %s：%q", want, got)
		}
	}
}

// 我们自己的探针（自检 / 共存检测的 DialSelf 连接）不记进全局字节总数。
//
// 它们走的是同一条 relay，字节数会顺理成章地加进顶栏流量图里 —— 表现是
// "没人用的时候图上有几 KB 的流量"，而且会周期性出现（共存检测每次开界面都做）。
// 与"探针不进连接列表、不计速率"同一条原则（见 selfconn.go）。
func TestTunTotalSkipsSelfProbes(t *testing.T) {
	e := newTestEngine()
	if got := e.tunTotal(&connState{}, true); got != &e.tunUp {
		t.Errorf("普通连接应当记进全局上行总数")
	}
	if got := e.tunTotal(&connState{}, false); got != &e.tunDown {
		t.Errorf("普通连接应当记进全局下行总数")
	}
	if got := e.tunTotal(&connState{self: true}, true); got != nil {
		t.Errorf("自己的探针不该记进全局总数（上行）")
	}
	if got := e.tunTotal(&connState{self: true}, false); got != nil {
		t.Errorf("自己的探针不该记进全局总数（下行）")
	}
	if got := e.tunTotal(nil, true); got != nil {
		t.Errorf("nil 连接不该崩")
	}
}
