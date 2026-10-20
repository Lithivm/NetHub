package webui

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// 托盘流量图：把两个方向的速率画成两根柱（Proxifier 的托盘图标也是迷你流量图）。
//
// 为什么是柱不是折线：托盘实际观感只有 16×16，折线在这个尺度上是一片噪点；
// 两根柱能一眼回答“有没有流量、哪个方向多”。
//
// 为什么刻度用对数：现场既有 2 KB/s 的 HIS 心跳，也有 20 MB/s 影像传输。
// 线性刻度下前者永远是 0 像素（等于没有反馈），对数刻度两者都看得见。
const trayIconSize = 32

var (
	// 上行偏蓝、下行偏绿（与顶栏流量图同一套语义，见 DESIGN 的配色约定）
	trayColorUp   = color.RGBA{R: 0x4C, G: 0x9A, B: 0xFF, A: 0xFF}
	trayColorDown = color.RGBA{R: 0x3F, G: 0xB9, B: 0x50, A: 0xFF}
	// 底线：没有流量时图标不能是**全透明**（那样托盘上什么都看不见）
	trayColorBase = color.RGBA{R: 0x9A, G: 0xA0, B: 0xA6, A: 0xFF}
)

// drawTrayImage 画出托盘图标（透明底 + 底线 + 两根柱）。
func drawTrayImage(upBps, downBps uint64) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, trayIconSize, trayIconSize))
	// 底线：固定在倒数第二行
	for x := 2; x < trayIconSize-2; x++ {
		img.SetRGBA(x, trayIconSize-2, trayColorBase)
	}
	barW := trayIconSize/2 - 3
	drawTrayBar(img, 2, barW, rateBarHeight(upBps), trayColorUp)
	drawTrayBar(img, trayIconSize/2+1, barW, rateBarHeight(downBps), trayColorDown)
	return img
}

// drawTrayBar 在 (x, 底部往上 h 像素) 处画一根宽 w 的柱。
func drawTrayBar(img *image.RGBA, x, w, h int, c color.RGBA) {
	if h <= 0 {
		return
	}
	bottom := trayIconSize - 3 // 底线上一格
	top := bottom - h
	if top < 0 {
		top = 0
	}
	for y := top; y < bottom; y++ {
		for dx := 0; dx < w; dx++ {
			img.SetRGBA(x+dx, y, c)
		}
	}
}

// rateBarHeight 速率 → 柱高（像素）：1 KB/s 起步、1 GB/s 满格，对数刻度。
//
// 小于 1 KB/s 返回 0（不画柱，只留底线）—— 那是心跳级别的流量，
// 画一个 1px 的柱反而像"有动静"。
func rateBarHeight(bps uint64) int {
	const minBps, maxBps = 1 << 10, 1 << 30
	if bps < minBps {
		return 0
	}
	const maxH = trayIconSize - 5
	lg := math.Log2(float64(bps) / minBps)
	full := math.Log2(float64(maxBps) / minBps)
	h := int(math.Round(lg / full * maxH))
	if h < 1 {
		h = 1
	}
	if h > maxH {
		h = maxH
	}
	return h
}

// drawTrayDIB 把图标编码成 Win32 RT_ICON 资源的格式：BITMAPINFOHEADER + 32bpp 像素 + AND 掩码。
//
// 为什么不给 CreateIconFromResourceEx 喂 PNG：**它只认 DIB**（PNG 压缩的图标只有
// LoadImage/LoadIcon 从 .ico 文件读时才支持）。2026-10-20 实测：喂 PNG 返回 0，
// 而 GetLastError 是 0（"The operation completed successfully"）—— 看不出原因的瞎报。
//
// 32bpp 时 AND 掩码全 0，透明度由 alpha 通道表达（Vista+ 的行为；XP 不考虑）。
func drawTrayDIB(upBps, downBps uint64) []byte {
	img := drawTrayImage(upBps, downBps)
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
		srcY := h - 1 - y // DIB 像素是自下而上存的
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
func drawTrayPNG(upBps, downBps uint64) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, drawTrayImage(upBps, downBps)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
