package webui

import (
	"encoding/binary"
	"testing"
)

// 托盘图（方案 5：面积 + 上沿线）：空载时**不能全透明**（否则托盘上什么都看不见）。
func TestDrawTrayIconVisibleWhenIdle(t *testing.T) {
	series := make([]uint64, traySeriesLen) // 全 0
	dib := drawTrayDIB(series, trayPaletteDark)
	if len(dib) < 40 {
		t.Fatalf("DIB 太短：%d 字节", len(dib))
	}
	if w := binary.LittleEndian.Uint32(dib[4:]); w != trayIconSize {
		t.Errorf("宽度应为 %d，得到 %d", trayIconSize, w)
	}
	if h := binary.LittleEndian.Uint32(dib[8:]); h != trayIconSize*2 {
		t.Errorf("高度应为 2×%d，得到 %d", trayIconSize, h)
	}
	if bpp := binary.LittleEndian.Uint16(dib[14:]); bpp != 32 {
		t.Errorf("应当 32bpp，得到 %d", bpp)
	}
	xorLen := trayIconSize * trayIconSize * 4
	maskRow := ((trayIconSize + 31) / 32) * 4
	if want := 40 + xorLen + maskRow*trayIconSize; len(dib) != want {
		t.Errorf("DIB 长度应为 %d，得到 %d", want, len(dib))
	}
	if opaque := countOpaque(dib); opaque == 0 {
		t.Error("空载时图标全透明 —— 托盘上会看不见这个图标（底线必须画出来）")
	}
}

func countOpaque(dib []byte) int {
	n := 0
	xor := dib[40:]
	for i := 3; i < len(xor); i += 4 {
		if xor[i] != 0 {
			n++
		}
	}
	return n
}

// 对数刻度：1 KB/s 起步、1 GB/s 满格；跨两个数量级都必须单调增长。
func TestRateLevel(t *testing.T) {
	if v := rateLevel(0); v != 0 {
		t.Errorf("没流量应当是 0，得到 %v", v)
	}
	if v := rateLevel(512); v != 0 {
		t.Errorf("低于 1 KB/s 应当是 0，得到 %v", v)
	}
	prev := 0.0
	for _, bps := range []uint64{1 << 10, 1 << 15, 1 << 20, 1 << 25, 1 << 30} {
		v := rateLevel(bps)
		if v <= prev {
			t.Errorf("速率变大应当变大：%d B/s → %v（上一个 %v）", bps, v, prev)
		}
		prev = v
	}
	if v := rateLevel(1 << 40); v != 1 {
		t.Errorf("超量程应当封顶 1，得到 %v", v)
	}
}

// 有流量时面积必须真的画出来（防止“编码对了但画空了”），且流量越大画得越多。
func TestDrawTrayIconGrowsWithRate(t *testing.T) {
	idle := make([]uint64, traySeriesLen)
	low := make([]uint64, traySeriesLen)
	high := make([]uint64, traySeriesLen)
	for i := range low {
		low[i] = 2 << 10   // 2 KB/s
		high[i] = 20 << 20 // 20 MB/s
	}
	pal := trayPaletteDark
	nIdle := countOpaque(drawTrayDIB(idle, pal))
	nLow := countOpaque(drawTrayDIB(low, pal))
	nHigh := countOpaque(drawTrayDIB(high, pal))
	if !(nIdle < nLow && nLow < nHigh) {
		t.Errorf("面积应当随速率增长：idle=%d low=%d high=%d", nIdle, nLow, nHigh)
	}
}

// 三种显示模式：total = 上+下、up 只取上行、down 只取下行。
func TestTraySeriesFor(t *testing.T) {
	up := []uint64{100, 200, 300}
	down := []uint64{1, 2, 3}
	if got := traySeriesFor(up, down, trayModeTotal); got[0] != 101 || got[2] != 303 {
		t.Errorf("总量应当是两条相加，得到 %v", got)
	}
	if got := traySeriesFor(up, down, trayModeUp); got[1] != 200 {
		t.Errorf("上行模式应当只取上行，得到 %v", got)
	}
	if got := traySeriesFor(up, down, trayModeDown); got[1] != 2 {
		t.Errorf("下行模式应当只取下行，得到 %v", got)
	}
	// 长度不等时按短的那条截断（不越界）
	if got := traySeriesFor([]uint64{1, 2, 3}, []uint64{9}, trayModeTotal); len(got) != 1 || got[0] != 10 {
		t.Errorf("长度不等应当按短的截断，得到 %v", got)
	}
}

// 认不出的模式回 total（拼错的代价不能是“图变空了”）。
func TestParseTrayMode(t *testing.T) {
	for in, want := range map[string]trayMode{
		"":   trayModeTotal,
		"up": trayModeUp, "out": trayModeUp, "OUTGOING": trayModeUp,
		"down": trayModeDown, "in": trayModeDown,
		"total": trayModeTotal, "verbos": trayModeTotal,
	} {
		if got := parseTrayMode(in); got != want {
			t.Errorf("parseTrayMode(%q) = %q，想要 %q", in, got, want)
		}
	}
}

// 浅色任务栏的调色板必须比深色版的蓝/绿更深（否则在 #f3f3f3 上看不清）。
func TestPaletteLightIsDarker(t *testing.T) {
	d, l := paletteFor(false, trayModeTotal), paletteFor(true, trayModeTotal)
	lum := func(c uint8) int { return int(c) }
	if lum(l.line.B)+lum(l.line.G)+lum(l.line.R) >= lum(d.line.B)+lum(d.line.G)+lum(d.line.R) {
		t.Errorf("浅色版的线色应当更深：dark=%v light=%v", d.line, l.line)
	}
	if paletteFor(true, trayModeDown).line.G <= paletteFor(true, trayModeDown).line.R {
		t.Error("下行模式应当用绿色（G > R）")
	}
}
