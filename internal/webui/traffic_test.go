package webui

import "testing"

// 顶栏流量图的环形：满了挤掉最老的、窗口秒数对、开关状态透传。
func TestTrafficRingWindow(t *testing.T) {
	// 期望值按 trafficSlots 推导，不写死格子数 —— 窗口长度是会调的（60→30 秒那次就撞过，
	// 写死 "69/138" 的断言会假红）。
	const extra = 10
	n := trafficSlots + extra
	var r trafficRing
	for i := 0; i < n; i++ {
		r.push(TrafficPoint{TunUp: uint64(i), TunDown: uint64(i * 2)})
	}
	v := r.snapshot(false, true)
	if len(v.Series) != trafficSlots {
		t.Fatalf("窗口应当是 %d 格，得到 %d 格", trafficSlots, len(v.Series))
	}
	if got := v.Series[0].TunUp; got != extra {
		t.Errorf("挤掉最老的 %d 格后，第一格应当是 %d，得到 %d", extra, extra, got)
	}
	if v.Window != trafficSlots {
		t.Errorf("Window 应当是 %d，得到 %d", trafficSlots, v.Window)
	}
	if v.CountDirect || !v.Running {
		t.Errorf("开关/运行状态要原样透传：%+v", v)
	}
	last := v.Series[len(v.Series)-1]
	wantLast := uint64(n - 1)
	if last.TunUp != wantLast || last.TunDown != wantLast*2 {
		t.Errorf("最后一格应当是 %d/%d，得到 %d/%d", wantLast, wantLast*2, last.TunUp, last.TunDown)
	}
}

// 空窗口不能崩（刚启动、界面先到了）。
func TestTrafficRingEmpty(t *testing.T) {
	var r trafficRing
	v := r.snapshot(true, false)
	if len(v.Series) != 0 || v.Window != trafficSlots || v.Running || !v.CountDirect {
		t.Errorf("空窗口不对：%+v", v)
	}
}

// delta：两拍做差；计数器被清零（Stop → Start）时给 0，不能绕成一个天文数字。
//
// 为什么单测这条：uint64 相减在“后小前大”时**不报错、直接绕回 18EB**，
// 图上会出现一个凭空出现的巨大尖峰，而且只在那一次重启的瞬间出现 —— 没人会去复现它。
func TestTrafficDelta(t *testing.T) {
	if got := delta(1000, 400); got != 600 {
		t.Errorf("正常两拍应当是 600，得到 %d", got)
	}
	if got := delta(0, 5_000_000); got != 0 {
		t.Errorf("计数器被清零时应当是 0，得到 %d", got)
	}
	if got := delta(0, 0); got != 0 {
		t.Errorf("没流量应当是 0，得到 %d", got)
	}
}
