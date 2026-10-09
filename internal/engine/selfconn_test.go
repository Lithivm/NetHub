package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/config"
	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// 自己发起的探针连接（见 selfconn.go）绝不能冒充应用流量：
// ① 不进连接列表；② 不计入累计/各链累计；③ 不进进程名解析率。
//
// 这条的现场症状是用户报的「每次刚启动就冒出几个 nethub 连接，纯误导」。
func TestSelfConnHiddenFromList(t *testing.T) {
	e := New(logbus.New(50), rules.New(), config.Default())

	mk := func(sport uint16, self bool) *connState {
		st := &connState{
			dst: net.ParseIP("10.0.0.5"), dport: 443,
			app: net.ParseIP("192.168.1.9"), appPort: sport,
			chain: "proxy-a", action: rules.ActionChain, start: time.Now(),
			procName: "nethub.exe", self: self, counted: !self,
		}
		st.touch()
		e.conns[sport] = st
		return st
	}
	mk(50001, true)  // 我们自己发起的探针
	mk(50002, false) // 应用真的连接

	got := e.Conns(0, false)
	if len(got) != 1 {
		t.Fatalf("列表里应当只剩应用那条，得到 %d 条：%v", len(got), got)
	}
	if got[0].Sport != 50002 {
		t.Errorf("剩下那条应当是应用的（sport=50002），得到 %d", got[0].Sport)
	}

	// 进程名解析率也不该把我们自己算进去（恒为 nethub.exe，会把比例抬上去）
	rt := e.RuntimeStatus()
	if rt.Conns.ProcKnown != 1 || rt.Conns.ProcUnknow != 0 {
		t.Errorf("进程名解析率不该含自己的探针：known=%d unknown=%d",
			rt.Conns.ProcKnown, rt.Conns.ProcUnknow)
	}
}

// DialSelf 必须在 **connect 之前** 就登记本地端口。
//
// 为什么强调“之前”：启动时那批探测大多连不上（端口猜错），连不上就拿不到 net.Conn，
// 也就无从登记 —— 等 dial 返回再标是来不及的，那些失败探测照样会出现在列表里。
func TestDialSelfRegistersPort(t *testing.T) {
	e := New(logbus.New(50), rules.New(), config.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	conn, err := e.DialSelf("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("DialSelf 失败: %v", err)
	}
	port := uint16(conn.LocalAddr().(*net.TCPAddr).Port)
	conn.Close()

	e.mu.RLock()
	_, ok := e.selfPorts[port]
	e.mu.RUnlock()
	if !ok {
		t.Fatalf("本地端口 %d 没登记成“自己人” —— 这条连接会在列表里冒充应用流量", port)
	}

	// 登记过久的端口要被清掉（端口会被系统复用，留着会误判应用连接）
	e.mu.Lock()
	e.selfPorts[port] = time.Now().Add(-3 * time.Minute)
	e.mu.Unlock()
	e.pruneSelfPorts()
	e.mu.RLock()
	_, still := e.selfPorts[port]
	e.mu.RUnlock()
	if still {
		t.Error("超过 2 分钟的登记应当被 pruneSelfPorts 清掉")
	}
}

// 界面上的“活跃”必须含直连：打开“直连流量统计”后直连的行也在列表里，
// 就不能再用只统计隧道的 statActive（否则显示成“列了 N 条、活跃 0”）。
// （注意列表行数不等于活跃：刚结束的还会留 15 秒。）
func TestConnsActiveMatchesList(t *testing.T) {
	e := New(logbus.New(50), rules.New(), config.Default())
	mk := func(sport uint16, act rules.Action, ended, self bool) {
		st := &connState{
			dst: net.ParseIP("10.0.0.5"), dport: 443, app: net.ParseIP("192.168.1.9"),
			appPort: sport, action: act, start: time.Now(), self: self,
		}
		if ended {
			st.ended.Store(true)
		}
		st.touch()
		e.conns[sport] = st
	}
	mk(60001, rules.ActionChain, false, false)  // 走隧道、进行中
	mk(60002, rules.ActionDirect, false, false) // 直连、进行中（开了直连统计才会出现）
	mk(60003, rules.ActionChain, true, false)   // 已结束
	mk(60004, rules.ActionChain, false, true)   // 我们自己的探针、进行中

	if got, want := e.ConnsActive(), 2; got != want {
		t.Errorf("活跃（界面口径）= %d，想要 %d（含直连、不含已结束与自己的探针）", got, want)
	}
	// 列表行数会比“活跃”多：刚结束的还会在列表里留 15 秒（那是给人看“刚刚发生了什么”的）
	if got, want := len(e.Conns(0, false)), 3; got != want {
		t.Errorf("列表应当有 %d 条（2 条进行中 + 1 条刚结束；自己的探针不算），得到 %d", want, got)
	}
}

// “直连流量统计”开关与列表必须同步：关掉之后，那些靠它才可见的直连条目
// 要立刻从列表（和“活跃”）里消失 —— 否则界面会挂着一批不再被观察、字节数停住的连接。
func TestDirectStatsRowsFollowToggle(t *testing.T) {
	e := New(logbus.New(50), rules.New(), config.Default())

	mk := func(sport uint16, act rules.Action, statsOnly bool) {
		st := &connState{
			dst: net.ParseIP("192.168.199.1"), dport: 445, app: net.ParseIP("192.168.199.9"),
			appPort: sport, action: act, start: time.Now(), statsOnly: statsOnly,
		}
		st.touch()
		e.conns[sport] = st
	}
	mk(5001, rules.ActionChain, false)  // 走隧道：与开关无关，一直在列表里
	mk(5002, rules.ActionDirect, true)  // 直连规则命中（靠“直连统计”才可见）
	mk(5003, rules.ActionDirect, false) // 内置直连 7680：一直在（不受开关影响）
	mk(5004, rules.ActionBlock, false)  // 阻断：一直在

	e.cfg.SetCountDirect(false)
	if got, want := len(e.Conns(0, false)), 3; got != want {
		t.Errorf("关着直连统计时列表应当 %d 条（不含那条直连），得到 %d", want, got)
	}
	if got, want := e.ConnsActive(), 3; got != want {
		t.Errorf("活跃同上，应当 %d，得到 %d", want, got)
	}

	e.cfg.SetCountDirect(true)
	if got, want := len(e.Conns(0, false)), 4; got != want {
		t.Errorf("打开直连统计后列表应当 %d 条，得到 %d", want, got)
	}
	if got, want := e.ConnsActive(), 4; got != want {
		t.Errorf("活跃同上，应当 %d，得到 %d", want, got)
	}
}
