package engine

import (
	"net"
	"testing"
	"time"

	"nethub/internal/rules"
)

// 连接历史存档：结束的连接要留得住、新的在前、条数有上界、状态与列表一个口径。
//
// 为什么要这份存档：`ConnView` 那份 15 秒就不显示了（janitor 2 分钟物理删），
// 而"刚才那批连到哪儿去了/为什么失败"常常是在一两分钟之后才来看的。
func TestConnsHistoryRecordsEnded(t *testing.T) {
	e := newTestEngine()

	// ① 正常结束的一条
	ok := &connState{dst: net.ParseIP("192.0.2.217"), dport: 443, chain: "etyy",
		action: rules.ActionChain, start: time.Now().Add(-5 * time.Second), procName: "Vendor.HIS.exe", pid: 88, appPort: 51001}
	ok.up.Store(1741)
	ok.down.Store(11264)
	ok.packets.Store(12)
	e.finish(ok)

	// ② 失败的一条（错误信息必须带进存档 —— 这正是诊断要看的东西）
	bad := &connState{dst: net.ParseIP("198.51.100.99"), dport: 443, chain: "sjy",
		action: rules.ActionChain, start: time.Now().Add(-2 * time.Second), procName: "chrome.exe", pid: 77, appPort: 51002}
	bad.fail("连代理失败: i/o timeout")
	e.finish(bad)

	// ③ 我们自己的探针：不进存档（与「当前连接」列表同口径）
	probe := &connState{dst: net.ParseIP("10.0.0.1"), dport: 80, chain: "etyy",
		action: rules.ActionChain, start: time.Now(), self: true, appPort: 51003}
	e.finish(probe)

	// ④ finish 幂等：重复调用不该记两条
	e.finish(ok)

	got := e.ConnsHistory(0)
	if len(got) != 2 {
		t.Fatalf("应只有 2 条（探针不进存档、finish 幂等），实际 %d 条: %+v", len(got), got)
	}
	// 新的在前
	if got[0].Target != "198.51.100.99:443" || got[0].State != "失败" {
		t.Errorf("最新的那条应排在最前且状态为失败: %+v", got[0])
	}
	if got[1].Target != "192.0.2.217:443" || got[1].State != "已结束" {
		t.Errorf("第二条应是先结束的隧道连接: %+v", got[1])
	}
	if got[0].Err == "" {
		t.Error("失败原因必须留在存档里（诊断要看的就是它）")
	}
	if got[1].Proc != "Vendor.HIS.exe" || got[1].PID != 88 || got[1].Sport != 51001 {
		t.Errorf("进程/端口要留着（对着 netstat 核对用）: %+v", got[1])
	}
	if got[1].Up != 1741 || got[1].Down != 11264 || got[1].Packets != 12 {
		t.Errorf("字节数/包数要留着: %+v", got[1])
	}
	if got[0].AgoSec < 0 || got[0].AgoSec > 5 {
		t.Errorf("距今秒数应是刚刚（%d 秒）", got[0].AgoSec)
	}

	// limit 生效
	if one := e.ConnsHistory(1); len(one) != 1 || one[0].Target != "198.51.100.99:443" {
		t.Errorf("limit 应只取最新的那条: %+v", one)
	}

	// 清空
	e.ClearConnsHistory()
	if left := e.ConnsHistory(0); len(left) != 0 {
		t.Errorf("清空后应为空，实际 %d 条", len(left))
	}
}

// 存档条数有上界：长跑不能无限涨（现场一开机就是几万条连接）。
func TestConnsHistoryBounded(t *testing.T) {
	e := newTestEngine()
	for i := 0; i < ConnHistKeep+50; i++ {
		st := &connState{dst: net.ParseIP("10.0.0.1"), dport: uint16(1000 + i%1000),
			chain: "etyy", action: rules.ActionChain, start: time.Now(), appPort: uint16(i)}
		e.finish(st)
	}
	got := e.ConnsHistory(0)
	if len(got) != ConnHistKeep {
		t.Fatalf("存档应有上界 %d，实际 %d", ConnHistKeep, len(got))
	}
	// 最后结束的那条必须在（即"裁掉的是最老的"）
	last := &connState{dst: net.ParseIP("192.168.1.1"), dport: 445, chain: "direct",
		action: rules.ActionDirect, start: time.Now(), appPort: 65535}
	e.finish(last)
	got = e.ConnsHistory(0)
	if got[0].Target != "192.168.1.1:445" {
		t.Errorf("最新一条应在最前: %+v", got[0])
	}
	if len(got) != ConnHistKeep {
		t.Errorf("裁完仍应是 %d 条，实际 %d", ConnHistKeep, len(got))
	}
}

// 状态判据与列表共用一份：未送达中转 / 已阻断 / 失败 都要能落到存档里。
func TestConnStateNameShared(t *testing.T) {
	unrelayed := &connState{dst: net.ParseIP("10.0.0.1"), dport: 80, action: rules.ActionChain}
	unrelayed.unrelayed.Store(true)
	if n := connStateName(unrelayed); n != "未送达中转" {
		t.Errorf("未送达中转: %s", n)
	}
	blocked := &connState{dst: net.ParseIP("10.9.9.9"), dport: 22, action: rules.ActionBlock}
	if n := connStateName(blocked); n != "已阻断" {
		t.Errorf("已阻断: %s", n)
	}
	failed := &connState{dst: net.ParseIP("10.0.0.9"), dport: 22, action: rules.ActionChain}
	failed.fail("上游拒绝")
	if n := connStateName(failed); n != "失败" {
		t.Errorf("失败: %s", n)
	}
}
