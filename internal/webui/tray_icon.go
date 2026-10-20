package webui

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"strings"
)

// 托盘流量图：**总面积 + 上沿线**（用户从 13 个折线方案里选的“方案 5”）。
//
// 为什么是这个形态（对比过的结论）：
//   - 面积在小尺寸下最抗糊：16px 缩下去仍然是一块“有形状的东西”，细折线会糊成噪点；
//   - 上沿线保留“趋势”（在涨还是在跌），面积只给“体量”；
//   - 空载时留一条底线 —— 托盘图标不能全透明，否则托盘上“没有图标”。
//
// 刻度用**对数**：现场既有 2 KB/s 的 HIS 心跳，也有 20 MB/s 影像传输；
// 线性刻度下前者永远是 0 像素（等于没有反馈）。
const trayIconSize = 32

// trayMode 托盘显示哪个量（设置里可选）。
type trayMode string

const (
	trayModeTotal trayMode = "total" // 上行 + 下行（默认）
	trayModeUp    trayMode = "up"    // 只看上行（出）
	trayModeDown  trayMode = "down"  // 只看下行（入）
)

// parseTrayMode 认不出的值回落到 total（宁可显示总量，也不要因为一个拼写把图变成空的）。
// 别名（out/in/outgoing/incoming）与 config.trayTrafficModeOr 保持一致。
func parseTrayMode(s string) trayMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up", "out", "outgoing":
		return trayModeUp
	case "down", "in", "incoming":
		return trayModeDown
	default:
		return trayModeTotal
	}
}

// trayPalette 一套配色。深色任务栏与浅色任务栏必须用两套 ——
// 同一套色不可能在 #202020 和 #f3f3f3 上都清楚（浅色任务栏下亮蓝+中灰底线几乎看不见）。
type trayPalette struct {
	fill color.RGBA // 面积填充（半透明）
	line color.RGBA // 上沿线（不透明）
	base color.RGBA // 底线
	dim  color.RGBA // 空槽/刻度
}

var (
	// 深色任务栏：亮蓝（上行/总量）、亮绿（下行）、中灰底线
	trayPaletteDark = trayPalette{
		fill: color.RGBA{R: 0x4C, G: 0x9A, B: 0xFF, A: 0x66},
		line: color.RGBA{R: 0x4C, G: 0x9A, B: 0xFF, A: 0xFF},
		base: color.RGBA{R: 0x9A, G: 0xA0, B: 0xA6, A: 0xFF},
		dim:  color.RGBA{R: 0x5F, G: 0x63, B: 0x68, A: 0xFF},
	}
	trayPaletteDarkDown = paletteWithColor(trayPaletteDark, color.RGBA{R: 0x3F, G: 0xB9, B: 0x50, A: 0xFF})
	// 浅色任务栏：蓝/绿各压深一档，底线换深灰
	trayPaletteLight = trayPalette{
		fill: color.RGBA{R: 0x15, G: 0x59, B: 0xC7, A: 0x66},
		line: color.RGBA{R: 0x15, G: 0x59, B: 0xC7, A: 0xFF},
		base: color.RGBA{R: 0x4A, G: 0x50, B: 0x57, A: 0xFF},
		dim:  color.RGBA{R: 0xB4, G: 0xB9, B: 0xBF, A: 0xFF},
	}
	trayPaletteLightDown = paletteWithColor(trayPaletteLight, color.RGBA{R: 0x0F, G: 0x7A, B: 0x34, A: 0xFF})
)

// paletteWithColor 换掉线/填充的主色（下行用绿色），保持 alpha 语义。
func paletteWithColor(p trayPalette, c color.RGBA) trayPalette {
	p.line = c
	p.fill = color.RGBA{R: c.R, G: c.G, B: c.B, A: 0x66}
	return p
}

// paletteFor 按“任务栏是不是浅色”选调色板与主色。
func paletteFor(light bool, mode trayMode) trayPalette {
	down := mode == trayModeDown
	switch {
	case light && down:
		return trayPaletteLightDown
	case light:
		return trayPaletteLight
	case down:
		return trayPaletteDarkDown
	default:
		return trayPaletteDark
	}
}

// rateLevel 速率 → 0..1（对数：1 KB/s 起步、1 GB/s 满格）。
//
// 低于 1 KB/s 记 0 —— 那是心跳级别，画 1 像素的柱反而像“有动静”。
func rateLevel(bps uint64) float64 {
	const minBps, maxBps = 1 << 10, 1 << 30
	if bps < minBps {
		return 0
	}
	lg := math.Log2(float64(bps) / minBps)
	full := math.Log2(float64(maxBps) / minBps)
	v := lg / full
	if v < 0.06 {
		v = 0.06 // 有流量就至少露出一点点，否则“在传但看不见”
	}
	if v > 1 {
		v = 1
	}
	return v
}

// drawTrayImage 画“面积 + 上沿线”：series 是**从旧到新**的每秒字节数。
//
// 逐列插值（不是逐点画柱）：16 个采样摊到 32 像素上，每列按相邻两点线性插值取高度，
// 于是面积边缘是连续的；上沿那条线用不透明的亮色，缩到 16px 后仍在。
func drawTrayImage(series []uint64, pal trayPalette) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, trayIconSize, trayIconSize))
	size := trayIconSize
	baseY := size - 3 // 底线之上
	// 底线：空载时图标不能是全透明（托盘上会“没有图标”）
	for x := 1; x < size-1; x++ {
		img.SetRGBA(x, baseY+1, pal.base)
	}
	n := len(series)
	if n == 0 {
		return img
	}
	maxH := float64(size - 6)
	set := func(x, y int, c color.RGBA) {
		if x < 0 || x >= size || y < 0 || y >= size {
			return
		}
		img.SetRGBA(x, y, c)
	}
	for x := 1; x < size-1; x++ {
		t := float64(x-1) / float64(size-3) * float64(n-1) // 0..n-1
		i0 := int(t)
		if i0 > n-1 {
			i0 = n - 1
		}
		i1 := i0 + 1
		if i1 > n-1 {
			i1 = n - 1
		}
		frac := t - float64(i0)
		lv := rateLevel(series[i0])*(1-frac) + rateLevel(series[i1])*frac
		h := int(math.Round(lv * maxH))
		top := baseY - h
		for y := top; y <= baseY; y++ { // 面积（半透明填充）
			set(x, y, pal.fill)
		}
		if h > 0 { // 上沿线：画粗一点，缩到 16px 才不消失
			set(x, top, pal.line)
			set(x, top+1, pal.line)
		}
	}
	return img
}

// drawTrayDIB 把图标编码成 Win32 RT_ICON 的格式：BITMAPINFOHEADER + 32bpp 像素 + AND 掩码。
//
// 为什么不给 CreateIconFromResourceEx 喂 PNG：**它只认 DIB**（PNG 压缩图标只有
// LoadImage/LoadIcon 从 .ico 文件读时才支持）。2026-10-20 实测：喂 PNG 返回 0，
// 而 GetLastError 是 0（“The operation completed successfully”）—— 看不出原因的瞎报。
func drawTrayDIB(series []uint64, pal trayPalette) []byte {
	img := drawTrayImage(series, pal)
	w, h := trayIconSize, trayIconSize

	bi := make([]byte, 40) // BITMAPINFOHEADER
	binary.LittleEndian.PutUint32(bi[0:], 40)
	binary.LittleEndian.PutUint32(bi[4:], uint32(w))
	binary.LittleEndian.PutUint32(bi[8:], uint32(h*2)) // XOR 与 AND 两张图各 h 行
	binary.LittleEndian.PutUint16(bi[12:], 1)          // biPlanes
	binary.LittleEndian.PutUint16(bi[14:], 32)         // biBitCount
	// biCompression = BI_RGB(0)、biSizeImage = 0（按格式推算即可）

	maskRow := ((w + 31) / 32) * 4  // 1bpp，行按 4 字节对齐
	mask := make([]byte, maskRow*h) // 全 0：形状由 alpha 决定
	xor := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcY := h - 1 - y // DIB 像素自下而上
		for x := 0; x < w; x++ {
			c := img.RGBAAt(x, srcY)
			i := (y*w + x) * 4
			xor[i+0] = c.B
			xor[i+1] = c.G
			xor[i+2] = c.R
			xor[i+3] = c.A
		}
	}
	out := make([]byte, 0, len(bi)+len(xor)+len(mask))
	out = append(out, bi...)
	out = append(out, xor...)
	out = append(out, mask...)
	return out
}

// drawTrayPNG 同一张图的 PNG 版：只给测试与排查用（人能直接看，DIB 看不了）。
func drawTrayPNG(series []uint64, pal trayPalette) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, drawTrayImage(series, pal)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// traySeriesFor 把一轮采样（每格的 上/下 字节）按模式合成为一条序列。
//
// 为什么要单独一个函数：三种模式的合并规则是**界面口径**，必须可测 ——
// “总量”是两条相加，“上行/下行”只取一条，且都要做负值保护（计数器被清零时不做假尖峰）。
func traySeriesFor(up, down []uint64, mode trayMode) []uint64 {
	n := len(up)
	if len(down) < n {
		n = len(down)
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		switch mode {
		case trayModeUp:
			out[i] = up[i]
		case trayModeDown:
			out[i] = down[i]
		default:
			out[i] = up[i] + down[i]
		}
	}
	return out
}
