package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/rules"
)

// B1：手动结束一条连接（Proxifier 的 close a connection）。
//
// 语义要钉住的是三件事：
//  1. 关掉两端（应用侧与上游侧都断）—— 只断一边，relay 的另一条拷贝协程会挂在那儿；
//  2. 只生效一次（列表里连点两下不能让第一次的“已结束”变成第二次的误报成功）；
//  3. 不走中转的连接要拒绝（直连/阻断本来就不经过我们，说“结束”是在骗人）。
func TestKillConnClosesBothEndsOnce(t *testing.T) {
	e := newTestEngine()
	e.conns = map[uint16]*connState{}

	appSide, appPeer := net.Pipe() // “应用侧”：我们持有 appSide，对端 appPeer 当作应用
	upSide, upPeer := net.Pipe()   // “上游侧”
	st := &connState{
		dst: net.ParseIP("10.0.0.1"), dport: 80, appPort: 51000,
		chain: "c", action: rules.ActionChain, start: time.Now(),
	}
	st.c, st.upConn = appSide, upSide
	e.conns[51000] = st

	if err := e.KillConn(51000); err != nil {
		t.Fatalf("第一次结束应当成功：%v", err)
	}
	// 两端都要真的断开（对端读到 EOF/错误，而不是继续挂着）
	appPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := appPeer.Read(make([]byte, 1)); err == nil {
		t.Error("应用侧应当已断开，但还能读")
	}
	upPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upPeer.Read(make([]byte, 1)); err == nil {
		t.Error("上游侧应当已断开，但还能读")
	}

	// 第二次：拒绝（已经结束过），不能让它重复关/重复记日志
	if err := e.KillConn(51000); err == nil {
		t.Error("第二次结束应当被拒绝")
	}
	// 不存在的端口：拒绝
	if err := e.KillConn(51001); err == nil {
		t.Error("不存在的端口应当被拒绝")
	}
}

// 直连/阻断的连接没有中转账路，结束它没有任何意义 —— 必须明说，不能假装成功。
func TestKillConnRejectsNonRelayed(t *testing.T) {
	e := newTestEngine()
	e.conns = map[uint16]*connState{}
	st := &connState{dst: net.ParseIP("192.168.1.5"), dport: 445, appPort: 52000,
		action: rules.ActionDirect, start: time.Now()}
	e.conns[52000] = st
	if err := e.KillConn(52000); err == nil {
		t.Error("直连连接不该被“结束”（后端应给出人话解释）")
	}
	if st.killed {
		t.Error("拒绝时不能留下 killed 标记（否则以后真能结束时也被挡住）")
	}
}
