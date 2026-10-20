package webui

import (
	"encoding/binary"
	"testing"
)

// 托盘流量图：空载时**不能全透明**（否则托盘上什么都看不见），有流量时柱子要长出来。
func TestDrawTrayIconVisibleWhenIdle(t *testing.T) {
	dib := drawTrayDIB(0, 0)
	if len(dib) < 40 {
		t.Fatalf("DIB 太短：%d 字节", len(dib))
	}
	// BITMAPINFOHEADER：宽 32、高 2×32（XOR + AND）、32bpp
	if w := binary.LittleEndian.Uint32(dib[4:]); w != trayIconSize {
		t.Errorf("宽度应为 %d，得到 %d", trayIconSize, w)
	}
	if h := binary.LittleEndian.Uint32(dib[8:]); h != trayIconSize*2 {
		t.Errorf("高度应为 2×%d，得到 %d", trayIconSize, h)
	}
	if bpp := binary.LittleEndian.Uint16(dib[14:]); bpp != 32 {
		t.Errorf("应当 32bpp，得到 %d", bpp)
	}
	// 数据长度 = 头 + XOR(w*h*4) + AND(每行 4 字节对齐 × h)
	xorLen := trayIconSize * trayIconSize * 4
	maskRow := ((trayIconSize + 31) / 32) * 4
	if want := 40 + xorLen + maskRow*trayIconSize; len(dib) != want {
		t.Errorf("DIB 长度应为 %d，得到 %d", want, len(dib))
	}
	// 空载也必须有不透明像素（底线）—— 否则托盘上是个看不见的图标
	opaque := 0
	for i := 40; i < 40+xorLen; i += 4 {
		if dib[i+3] != 0 {
			opaque++
		}
	}
	if opaque == 0 {
		t.Error("空载时图标全透明 —— 托盘上会看不见这个图标")
	}
}

// 对数刻度：1 KB/s 起步、1 GB/s 满格；跨两个数量级都必须有可见的柱。
func TestRateBarHeight(t *testing.T) {
	if h := rateBarHeight(0); h != 0 {
		t.Errorf("没流量应当不画柱，得到 %d", h)
	}
	if h := rateBarHeight(512); h != 0 {
		t.Errorf("低于 1 KB/s 不画柱，得到 %d", h)
	}
	prev := 0
	for _, bps := range []uint64{1 << 10, 1 << 15, 1 << 20, 1 << 25, 1 << 30} {
		h := rateBarHeight(bps)
		if h <= prev {
			t.Errorf("速率变大柱高应当变大：%d B/s → %dpx（上一个 %dpx）", bps, h, prev)
		}
		prev = h
	}
	if h := rateBarHeight(1 << 40); h != trayIconSize-5 {
		t.Errorf("超量程应当封顶在 %d，得到 %d", trayIconSize-5, h)
	}
}

// 有流量时柱子所在的像素必须真的被点亮（防止“编码对了但画空了”）。
func TestDrawTrayIconHasBars(t *testing.T) {
	img := drawTrayImage(20<<20, 20<<20)
	// 取靠近底部一行：两根柱都应该有颜色
	row := trayIconSize - 5
	upPix := img.RGBAAt(3, row)
	downPix := img.RGBAAt(trayIconSize/2+2, row)
	if upPix.A == 0 || downPix.A == 0 {
		t.Fatalf("有流量时两根柱都该画出来：up=%v down=%v", upPix, downPix)
	}
	if upPix == downPix {
		t.Error("上行/下行应当用不同颜色（蓝/绿），否则分不出方向")
	}
}
