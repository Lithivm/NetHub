package webui

import (
	"sync"
	"time"
)

// 顶栏实时流量图的数据源。
//
// 为什么不画在连接页、为什么由后端采样（2026-10-14 用户提的"像 clash/proxifier 那种卷轴"）：
//   - 图放**顶栏**、语义上跟"累计/活跃"两个数字一起回答"现在忙不忙"；放页签带则紧挨导航，
//     而且页签宽度带徽章数字会变，图的左边缘会跟着横move（见 KB:决策/实时流量图放顶栏不放在页签带.md）。
//   - 采样在**引擎进程**里做：界面切页、被现场启动器杀掉重开（见 AGENTS.md 的前后端拆分）之后，
//     曲线不会断 —— 界面回来时拿到的还是完整 60 秒。前端自己差分做不到这一点。
//
// 数据源是**累计字节总数做差**（engine.TrafficTotals），不是 engine.Rates()：
// Rates() 只算当前还开着的连接，一个 200ms 就结束的 HTTP 请求在下一秒采样时已经被归零
// （2026-10-14 实测：curl 连跑 6 轮，Rates() 一直是 0 —— 图是平的）。
// 累计量短连接结束后也留在里面，所以曲线才画得出来。
const (
	trafficSlots = 60 // 60 格 × 1 秒 = 60 秒窗口
	trafficTick  = time.Second
)

// TrafficPoint 一格 = 一秒的字节数，隧道/直连分开存。
//
// 为什么不直接存“合计”：界面上的「也统计直连流量」开关是**整窗生效**的 ——
// 关掉时不仅要停止新增，已经画在窗口里的直连那部分也应该立刻消失（与连接列表里
// 直连行立刻消失是同一个口径，见 AGENTS.md 的“开关类设置改完要立刻重画”）。
// 存分开的两份，前端就能按开关重算整窗，不用等 60 秒慢慢退掉。
type TrafficPoint struct {
	TunUp   uint64 `json:"tunUp"`
	TunDown uint64 `json:"tunDown"`
	DirUp   uint64 `json:"dirUp"`
	DirDown uint64 `json:"dirDown"`
}

// TrafficView 顶栏流量图要的全部数据。
type TrafficView struct {
	// Series 旧 → 新，最多 trafficSlots 格；不足表示刚启动。
	//
	// 前端必须**右对齐**画（新的一格永远贴右边），否则曲线会随着格子从空到满而横向伸缩。
	Series []TrafficPoint `json:"series"`
	// CountDirect：「也统计直连流量」开关的当前值 —— 前端据此决定要不要把 Dir* 算进去。
	CountDirect bool `json:"countDirect"`
	// Window：窗口秒数（前端算横轴步长要用）。
	Window int `json:"window"`
	// Running：引擎在不在跑。
	//
	// 停了要**写 0 格**：累计字节没人再加，两拍做差本来就是 0 —— 但启动瞬间的清零
	// （Start 里 Store(0)）会让差值为负，那种情况也按 0 处理（见 sampleTraffic）。
	Running bool `json:"running"`
}

// trafficRing 定长环形（够满就挤掉最老的）。
type trafficRing struct {
	mu  sync.Mutex
	pts []TrafficPoint
}

func (r *trafficRing) push(p TrafficPoint) {
	r.mu.Lock()
	r.pts = append(r.pts, p)
	if n := len(r.pts) - trafficSlots; n > 0 {
		r.pts = append(r.pts[:0], r.pts[n:]...)
	}
	r.mu.Unlock()
}

func (r *trafficRing) snapshot(countDirect, running bool) TrafficView {
	r.mu.Lock()
	series := make([]TrafficPoint, len(r.pts))
	copy(series, r.pts)
	r.mu.Unlock()
	return TrafficView{Series: series, CountDirect: countDirect, Window: trafficSlots, Running: running}
}

// GetTraffic 顶栏流量图的数据（界面每秒取一次）。
func (b *Backend) GetTraffic() TrafficView {
	return b.traffic.snapshot(b.countDirect(), b.a.Running())
}

// trafficWatch 每秒取一格。跟着进程活着（不是跟着某个界面），见文件头。
func (b *Backend) trafficWatch() {
	tk := time.NewTicker(trafficTick)
	defer tk.Stop()
	var lt, ld, ldu, ldd uint64 // 上一拍的累计值
	for range tk.C {
		tunUp, tunDown, dirUp, dirDown := b.sampleTotals()
		p := TrafficPoint{
			// 差值为负 = 计数器被清零了（Stop → Start）。按 0 处理，不然会画出一个
			// “凭空几十 MB”的假尖峰（uint64 相减还会直接绕成一个天文数字）。
			TunUp:   delta(tunUp, lt),
			TunDown: delta(tunDown, ld),
			DirUp:   delta(dirUp, ldu),
			DirDown: delta(dirDown, ldd),
		}
		lt, ld, ldu, ldd = tunUp, tunDown, dirUp, dirDown
		b.traffic.push(p)
		// 托盘流量图开关跟着配置走：不管是从界面改的、还是外部改了 config.yaml
		// （热重载会把配置换掉），这里每秒对齐一次就都覆盖了。
		if b.tray != nil {
			wantOn, wantMode := b.a.Cfg.TrayTraffic(), b.a.Cfg.TrayTrafficMode()
			if b.tray.TrafficMode() != wantOn || b.tray.TrafficKind() != wantMode {
				b.tray.SetTraffic(wantOn, wantMode)
				if wantOn {
					b.a.Bus.Info("托盘图标：实时流量图（显示 %s）", trayModeLabel(wantMode))
				} else {
					b.a.Bus.Info("托盘图标已恢复为默认图标")
				}
			}
		}
	}
}

// sampleTotals 读一次累计字节（引擎没在跑就是 0，并且把基准也拉回 0）。
func (b *Backend) sampleTotals() (tunUp, tunDown, dirUp, dirDown uint64) {
	if !b.a.Running() {
		return 0, 0, 0, 0
	}
	e := b.a.Engine
	if e == nil {
		return 0, 0, 0, 0
	}
	return e.TrafficTotals()
}

// delta 两拍之间的增量；计数器变小（清零）时给 0 而不是绕成大数。
func delta(now, prev uint64) uint64 {
	if now < prev {
		return 0
	}
	return now - prev
}
