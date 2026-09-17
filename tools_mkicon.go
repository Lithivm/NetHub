//go:build ignore

// 从 logo 源图生成 nethub.ico（多尺寸）+ 一张 256px 的 PNG 供参考。
//
//	go run tools_mkicon.go assets/logo.png nethub.ico
//
// 为什么不用 PowerShell/GDI+ 生成：GDI+ 缩放对带 alpha 的图会引入灰边
// （它不按预乘 alpha 重采样）。这里自己做 Lanczos3 + 预乘 alpha，
// 边缘干净，也不给项目引入任何第三方依赖。
//
// 源图背景是透明的，但边缘有零星残余像素，所以裁剪时用 alpha 阈值忽略它们，
// 再补一圈留白 —— 这样 16x16 下图形才不会贴着边、糊成一团。
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const (
	cropAlphaThresh = 0.25 // alpha 超过它才算“图形本体”
	cropPadRatio    = 0.04 // 裁剪后四周留白占比
)

// rgbaF 是预乘 alpha 的浮点图像（Go 的 color.Color.RGBA() 返回的就是预乘值）。
type rgbaF struct {
	w, h int
	p    []float64 // len = w*h*4，顺序 R,G,B,A
}

func decode(src image.Image) *rgbaF {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	f := &rgbaF{w: w, h: h, p: make([]float64, w*h*4)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, bb, a := src.At(b.Min.X+x, b.Min.Y+y).RGBA()
			i := (y*w + x) * 4
			f.p[i+0] = float64(r) / 65535
			f.p[i+1] = float64(g) / 65535
			f.p[i+2] = float64(bb) / 65535
			f.p[i+3] = float64(a) / 65535
		}
	}
	return f
}

func (f *rgbaF) at(x, y int) (r, g, b, a float64) {
	if x < 0 || y < 0 || x >= f.w || y >= f.h {
		return 0, 0, 0, 0 // 界外视为全透明
	}
	i := (y*f.w + x) * 4
	return f.p[i], f.p[i+1], f.p[i+2], f.p[i+3]
}

// cropSquare 找到图形本体（alpha 超阈值）的包围盒，居中裁成正方形并补留白。
func cropSquare(f *rgbaF) (*rgbaF, string) {
	minX, minY, maxX, maxY := f.w, f.h, -1, -1
	for y := 0; y < f.h; y++ {
		for x := 0; x < f.w; x++ {
			if f.p[(y*f.w+x)*4+3] > cropAlphaThresh {
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}
	if maxX < 0 {
		return f, "源图全透明，不裁剪"
	}
	bw, bh := maxX-minX+1, maxY-minY+1
	side := bw
	if bh > side {
		side = bh
	}
	side = int(float64(side) * (1 + 2*cropPadRatio))
	if side > f.w && side > f.h {
		side = f.w
		if f.h < side {
			side = f.h
		}
	}
	// 以包围盒中心为中心
	cx := float64(minX+maxX+1) / 2
	cy := float64(minY+maxY+1) / 2
	ox := int(math.Round(cx - float64(side)/2))
	oy := int(math.Round(cy - float64(side)/2))

	out := &rgbaF{w: side, h: side, p: make([]float64, side*side*4)}
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			r, g, b, a := f.at(ox+x, oy+y)
			i := (y*side + x) * 4
			out.p[i], out.p[i+1], out.p[i+2], out.p[i+3] = r, g, b, a
		}
	}
	return out, fmt.Sprintf("本体 %dx%d（x %d..%d, y %d..%d）→ 方裁 %dx%d（偏移 %d,%d）",
		bw, bh, minX, maxX, minY, maxY, side, side, ox, oy)
}

func lanczos3(x float64) float64 {
	if x < 0 {
		x = -x
	}
	if x < 1e-8 {
		return 1
	}
	if x >= 3 {
		return 0
	}
	px := math.Pi * x
	return 3 * math.Sin(px) * math.Sin(px/3) / (px * px)
}

type weight struct {
	idx int
	w   float64
}

// buildWeights 预算每个输出位置到输入的权重（缩小时核随之变宽，避免丢细节/摩尔纹）。
func buildWeights(srcLen, dstLen int) [][]weight {
	scale := float64(srcLen) / float64(dstLen)
	if scale < 1 {
		scale = 1 // 放大时核半径固定为 3
	}
	support := 3 * scale
	ws := make([][]weight, dstLen)
	for i := 0; i < dstLen; i++ {
		center := (float64(i)+0.5)*scale - 0.5
		lo := int(math.Ceil(center - support))
		hi := int(math.Floor(center + support))
		var row []weight
		sum := 0.0
		for j := lo; j <= hi; j++ {
			w := lanczos3((center - float64(j)) / scale)
			if w == 0 {
				continue
			}
			idx := j
			if idx < 0 {
				idx = 0
			}
			if idx >= srcLen {
				idx = srcLen - 1
			}
			row = append(row, weight{idx, w})
			sum += w
		}
		if sum != 0 {
			for k := range row {
				row[k].w /= sum
			}
		}
		ws[i] = row
	}
	return ws
}

func resample(f *rgbaF, dw, dh int) *rgbaF {
	// 横向
	wx := buildWeights(f.w, dw)
	hx := &rgbaF{w: dw, h: f.h, p: make([]float64, dw*f.h*4)}
	for y := 0; y < f.h; y++ {
		rb, ob := y*f.w*4, y*dw*4
		for x := 0; x < dw; x++ {
			var c [4]float64
			for _, t := range wx[x] {
				s := rb + t.idx*4
				c[0] += f.p[s] * t.w
				c[1] += f.p[s+1] * t.w
				c[2] += f.p[s+2] * t.w
				c[3] += f.p[s+3] * t.w
			}
			d := ob + x*4
			hx.p[d], hx.p[d+1], hx.p[d+2], hx.p[d+3] = c[0], c[1], c[2], c[3]
		}
	}
	// 纵向
	wy := buildWeights(f.h, dh)
	out := &rgbaF{w: dw, h: dh, p: make([]float64, dw*dh*4)}
	for x := 0; x < dw; x++ {
		for y := 0; y < dh; y++ {
			var c [4]float64
			for _, t := range wy[y] {
				s := (t.idx*dw + x) * 4
				c[0] += hx.p[s] * t.w
				c[1] += hx.p[s+1] * t.w
				c[2] += hx.p[s+2] * t.w
				c[3] += hx.p[s+3] * t.w
			}
			d := (y*dw + x) * 4
			out.p[d], out.p[d+1], out.p[d+2], out.p[d+3] = c[0], c[1], c[2], c[3]
		}
	}
	return out
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// toRGBA 落回 8 位；预乘约束必须满足 R,G,B <= A，否则 Windows 渲染会出彩边。
func (f *rgbaF) toRGBA() *image.RGBA {
	im := image.NewRGBA(image.Rect(0, 0, f.w, f.h))
	for y := 0; y < f.h; y++ {
		for x := 0; x < f.w; x++ {
			i := (y*f.w + x) * 4
			a := clamp01(f.p[i+3])
			r, g, b := clamp01(f.p[i]), clamp01(f.p[i+1]), clamp01(f.p[i+2])
			if r > a {
				r = a
			}
			if g > a {
				g = a
			}
			if b > a {
				b = a
			}
			im.SetRGBA(x, y, color.RGBA{
				R: uint8(r*255 + 0.5), G: uint8(g*255 + 0.5),
				B: uint8(b*255 + 0.5), A: uint8(a*255 + 0.5),
			})
		}
	}
	return im
}

// encodeDIB 生成 ICO 条目要的 DIB：BITMAPINFOHEADER + 32bpp BGRA + AND 掩码。
//
// 为什么不全部用 PNG：ICO 里的 PNG 条目虽然 Windows Shell（Explorer/任务栏/LoadImageW）都支持，
// 但 **GDI+（System.Drawing.Icon）、部分老工具和安装程序读不了** —— 它们按 DIB 解释，
// 结果是一堆彩色噪点。所以小尺寸（<=64）用 DIB，只有 128/256 用 PNG，
// 这也是 Windows SDK 自己的做法。
func encodeDIB(im *image.RGBA) []byte {
	w, h := im.Bounds().Dx(), im.Bounds().Dy()
	var b bytes.Buffer

	// BITMAPINFOHEADER（40 字节）
	_ = binary.Write(&b, binary.LittleEndian, uint32(40))
	_ = binary.Write(&b, binary.LittleEndian, int32(w))
	_ = binary.Write(&b, binary.LittleEndian, int32(h*2)) // 高度翻倍：XOR 图 + AND 掩码图
	_ = binary.Write(&b, binary.LittleEndian, uint16(1))  // planes
	_ = binary.Write(&b, binary.LittleEndian, uint16(32)) // bpp
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))  // BI_RGB
	_ = binary.Write(&b, binary.LittleEndian, uint32(w*h*4))
	_ = binary.Write(&b, binary.LittleEndian, int32(0)) // 分辨率：不关心
	_ = binary.Write(&b, binary.LittleEndian, int32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // clrUsed
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // clrImportant

	// XOR 图：自下而上，BGRA，**非预乘**（ICO 的 DIB 存直通值，不是预乘值）
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := im.RGBAAt(x, y)
			r, g, bl := c.R, c.G, c.B
			if c.A != 0 && c.A != 255 {
				r = uint8(minInt(255, int(r)*255/int(c.A)))
				g = uint8(minInt(255, int(g)*255/int(c.A)))
				bl = uint8(minInt(255, int(bl)*255/int(c.A)))
			}
			b.WriteByte(bl)
			b.WriteByte(g)
			b.WriteByte(r)
			b.WriteByte(c.A)
		}
	}

	// AND 掩码：1bpp，行按 4 字节对齐；1 = 透明。
	// 现代 Windows 看 alpha 通道，但掩码必须存在，否则部分工具会渲染成黑块。
	rowBytes := ((w + 31) / 32) * 4
	row := make([]byte, rowBytes)
	for y := h - 1; y >= 0; y-- {
		for i := range row {
			row[i] = 0
		}
		for x := 0; x < w; x++ {
			if im.RGBAAt(x, y).A < 128 {
				row[x/8] |= 0x80 >> uint(x%8)
			}
		}
		b.Write(row)
	}
	return b.Bytes()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: go run tools_mkicon.go <源图.png> <输出.ico>")
		os.Exit(2)
	}
	srcPath, outPath := os.Args[1], os.Args[2]

	raw, err := os.Open(srcPath)
	if err != nil {
		panic(err)
	}
	img, _, err := image.Decode(raw)
	raw.Close()
	if err != nil {
		panic(err)
	}
	src := decode(img)
	fmt.Printf("源图 %s: %dx%d\n", filepath.Base(srcPath), src.w, src.h)

	cropped, info := cropSquare(src)
	fmt.Println("裁剪:", info)

	sizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	type entry struct {
		size int
		data []byte
	}
	var entries []entry
	for _, s := range sizes {
		im := resample(cropped, s, s).toRGBA()
		if s <= 64 {
			entries = append(entries, entry{s, encodeDIB(im)})
		} else {
			var buf bytes.Buffer
			if err := png.Encode(&buf, im); err != nil {
				panic(err)
			}
			entries = append(entries, entry{s, buf.Bytes()})
		}
	}

	// ICO 容器：6 字节头 + 每张 16 字节目录项 + 数据
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&out, binary.LittleEndian, uint16(1)) // type = icon
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		b := byte(e.size)
		if e.size >= 256 {
			b = 0 // ICO 里 256 用 0 表示
		}
		out.WriteByte(b)
		out.WriteByte(b)
		out.WriteByte(0)                                        // 调色板数
		out.WriteByte(0)                                        // reserved
		_ = binary.Write(&out, binary.LittleEndian, uint16(1))  // planes
		_ = binary.Write(&out, binary.LittleEndian, uint16(32)) // bpp
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(e.data)))
		_ = binary.Write(&out, binary.LittleEndian, uint32(offset))
		offset += len(e.data)
	}
	for _, e := range entries {
		out.Write(e.data)
	}
	if err := os.WriteFile(outPath, out.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("已写 %s（%d 个尺寸: %v，共 %d 字节；<=64 用 DIB，128/256 用 PNG）\n",
		outPath, len(entries), sizes, out.Len())

	// 附赠一张 256px PNG（文档/预览用）
	big := resample(cropped, 256, 256).toRGBA()
	if f, err := os.Create("nethub-256.png"); err == nil {
		_ = png.Encode(f, big)
		f.Close()
		fmt.Println("已写 nethub-256.png（预览用）")
	}
}
