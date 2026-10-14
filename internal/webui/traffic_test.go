package webui

import "testing"

// 顶栏流量图的环形：满了挤掉最老的、窗口秒数对、开关状态透传。
func TestTrafficRingWindow(t *testing.T) {
	var r trafficRing
	for i := 0; i < trafficSlots+10; i++ {
		r.push(TrafficPoint{TunUp: uint64(i), TunDown: uint64(i * 2)})
	}
	v := r.snapshot(false, true)
	if len(v.Series) != trafficSlots {
		t.Fatalf("窗口应当是 %d 格，得到 %d 格", trafficSlots, len(v.Series))
	}
	if got := v.Series[0].TunUp; got != 10 {
		t.Errorf("挤掉最老的一格后，第一格应当是 10，得到 %d", got)
	}
	if v.Window != trafficSlots {
		t.Errorf("Window 应当是 %d，得到 %d", trafficSlots, v.Window)
	}
	if v.CountDirect || !v.Running {
		t.Errorf("开关/运行状态要原样透传：%+v", v)
	}
	last := v.Series[len(v.Series)-1]
	if last.TunUp != 69 || last.TunDown != 138 {
		t.Errorf("最后一格应当是 69/138，得到 %d/%d", last.TunUp, last.TunDown)
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
