//go:build ignore

// 从 logo 源图生成：
//
//	  nethub.ico        多尺寸托盘/程序图标
//	  nethub-256.png    预览图
//	  frontend/logo.png 界面标题栏用的透明 PNG
//
//		go run tools_mkicon.go assets/logo.jpg nethub.ico
//
// 源图要求/处理：
//   - 带 alpha 的 PNG → 直接用它的 alpha
//   - 不透明白底图（JPG）→ 自动抠白底（见 knockoutWhite）
//   - 图上同时有图标和文字（如完整字标）→ 自动只取【最大的一块连通图形】，
//     也就是那个图标，不带文字（文字在 16px 下会糊成一团）
//
// 为什么缩放自己写：GDI+ 不按预乘 alpha 重采样，带透明的图会出灰边。
// 这里用 Lanczos3 + 预乘 alpha，不引第三方依赖。
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const (
	padRatio         = 0.06 // 裁剪后四周留白占比
	interiorThresh   = 0.40 // 归一化“离白距离”超过它 → 确定是图形本体
	backgroundThresh = 0.04 // 低于它 → 确定是背景
	minAlpha         = 0.08 // 低于它直接判为透明（干掉淡淡的投影）
)

// rgbaF 是预乘 alpha 的浮点图像。
type rgbaF struct {
	w, h int
	p    []float64 // len = w*h*4，顺序 R,G,B,A（预乘）
}

func (f *rgbaF) at(x, y int) (r, g, b, a float64) {
	if x < 0 || y < 0 || x >= f.w || y >= f.h {
		return 0, 0, 0, 0 // 界外视为全透明
	}
	i := (y*f.w + x) * 4
	return f.p[i], f.p[i+1], f.p[i+2], f.p[i+3]
}

// ── 解码 ─────────────────────────────────────────────────────

func decode(src image.Image) *rgbaF {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()

	straight := make([]float64, w*h*3) // 直通色（非预乘）
	alpha := make([]float64, w*h)
	transparent := 0

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, bb, a := src.At(b.Min.X+x, b.Min.Y+y).RGBA()
			i := y*w + x
			af := float64(a) / 65535
			if af > 0 {
				// RGBA() 返回预乘值，这里还原成直通色
				straight[i*3+0] = clamp01(float64(r) / 65535 / af)
				straight[i*3+1] = clamp01(float64(g) / 65535 / af)
				straight[i*3+2] = clamp01(float64(bb) / 65535 / af)
			}
			alpha[i] = af
			if af < 0.5 {
				transparent++
			}
		}
	}

	// 几乎没有透明像素 → 当成白底图，抠白底
	if transparent < w*h/50 {
		straight, alpha = knockoutWhite(straight, alpha, w, h)
	}

	out := &rgbaF{w: w, h: h, p: make([]float64, w*h*4)}
	for i := 0; i < w*h; i++ {
		a := alpha[i]
		out.p[i*4+0] = straight[i*3+0] * a
		out.p[i*4+1] = straight[i*3+1] * a
		out.p[i*4+2] = straight[i*3+2] * a
		out.p[i*4+3] = a
	}
	return out
}

// knockoutWhite 把“白底图”变成带 alpha 的图。
//
// 白底混合模型：P = a*C + (1-a)*255（P 是观测到的像素，C 是图形真实颜色）。
// 一个方程两个未知数，但如果知道该处图形的真实颜色 C，就能解出 a：
//
//	a = (255 - P) / (255 - C)
//
// 而 C 取【最近的图形本体的颜色】（边界像素的颜色必然接近相邻的本体像素）。
// 这就是下面 BFS 的作用：给每个边界像素找到最近的“确定是图形”的像素颜色。
func knockoutWhite(straight []float64, alpha []float64, w, h int) ([]float64, []float64) {
	n := w * h
	// 归一化离白距离
	dist := make([]float64, n)
	isInterior := make([]bool, n)
	isBackground := make([]bool, n)
	for i := 0; i < n; i++ {
		r, g, b := straight[i*3], straight[i*3+1], straight[i*3+2]
		d := math.Max(255-r*255, math.Max(255-g*255, 255-b*255)) / 255
		dist[i] = d
		isInterior[i] = d >= interiorThresh
		isBackground[i] = d < backgroundThresh
	}

	// 多源 BFS：从所有“确定是图形”的像素出发向外扩散，记录最近的图形颜色
	nearR := make([]float64, n)
	nearG := make([]float64, n)
	nearB := make([]float64, n)
	seen := make([]bool, n)
	queue := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if isInterior[i] {
			nearR[i], nearG[i], nearB[i] = straight[i*3], straight[i*3+1], straight[i*3+2]
			seen[i] = true
			queue = append(queue, i)
		}
	}
	for head := 0; head < len(queue); head++ {
		i := queue[head]
		x, y := i%w, i/w
		for dy := -1; dy <= 1; dy++ {
			for dx := -1; dx <= 1; dx++ {
				if dx == 0 && dy == 0 {
					continue
				}
				nx, ny := x+dx, y+dy
				if nx < 0 || ny < 0 || nx >= w || ny >= h {
					continue
				}
				j := ny*w + nx
				if seen[j] {
					continue
				}
				seen[j] = true
				nearR[j], nearG[j], nearB[j] = nearR[i], nearG[i], nearB[i]
				queue = append(queue, j)
			}
		}
	}

	outC := make([]float64, n*3)
	copy(outC, straight)
	outA := make([]float64, n)
	for i := 0; i < n; i++ {
		switch {
		case isInterior[i]:
			outA[i] = 1
		case isBackground[i]:
			outA[i] = 0
		default:
			nr, ng, nb := nearR[i], nearG[i], nearB[i]
			// 挑“最不白”的通道来解 alpha，数值最稳
			ch, denom := 0, 255-nr*255
			if v := 255 - ng*255; v > denom {
				ch, denom = 1, v
			}
			if v := 255 - nb*255; v > denom {
				ch, denom = 2, v
			}
			_ = ch
			if denom < 1 {
				outA[i] = 0
				break
			}
			p := straight[i*3+0]
			switch ch {
			case 1:
				p = straight[i*3+1]
			case 2:
				p = straight[i*3+2]
			}
			a := clamp01((255 - p*255) / denom)
			if a < minAlpha {
				a = 0
			}
			outA[i] = a
			if a > 0 {
				// 把该像素的颜色也反解成图形真实颜色，避免边缘发白
				for c := 0; c < 3; c++ {
					outC[i*3+c] = clamp01((1 - (1-straight[i*3+c])/a))
				}
			}
		}
	}
	return outC, outA
}

// ── 只取最大的一块连通图形 ────────────────────────────────────

// keepLargestBlob 把 alpha>0.5 的像素做连通域标记，只保留最大的一块。
// 完整字标（图标 + 文字）用这个能自动只留下图标。
func keepLargestBlob(f *rgbaF) (*rgbaF, string) {
	w, h, n := f.w, f.h, f.w*f.h
	label := make([]int, n)
	for i := range label {
		label[i] = -1
	}
	best, bestSize := -1, 0
	sizes := []int{}
	stack := make([]int, 0, 1024)

	for start := 0; start < n; start++ {
		if label[start] >= 0 || f.p[start*4+3] <= 0.5 {
			continue
		}
		id := len(sizes)
		sizes = append(sizes, 0)
		label[start] = id
		stack = stack[:0]
		stack = append(stack, start)
		for len(stack) > 0 {
			i := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			sizes[id]++
			x, y := i%w, i/w
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					if dx == 0 && dy == 0 {
						continue
					}
					nx, ny := x+dx, y+dy
					if nx < 0 || ny < 0 || nx >= w || ny >= h {
						continue
					}
					j := ny*w + nx
					if label[j] >= 0 || f.p[j*4+3] <= 0.5 {
						continue
					}
					label[j] = id
					stack = append(stack, j)
				}
			}
		}
		if sizes[id] > bestSize {
			best, bestSize = id, sizes[id]
		}
	}
	if best < 0 {
		return f, "没有可见图形"
	}
	out := &rgbaF{w: w, h: h, p: make([]float64, n*4)}
	kept := 0
	for i := 0; i < n; i++ {
		if label[i] == best {
			copy(out.p[i*4:i*4+4], f.p[i*4:i*4+4])
			kept++
		}
	}
	info := fmt.Sprintf("共 %d 块连通图形，保留最大的一块（%d 像素，占 %.1f%%）",
		len(sizes), kept, float64(kept)*100/float64(n))
	return out, info
}

// ── 裁剪 / 缩放 ──────────────────────────────────────────────

// cropSquare 按 alpha>阈值 的包围盒居中裁成正方形并补留白。
func cropSquare(f *rgbaF) (*rgbaF, string) {
	minX, minY, maxX, maxY := f.w, f.h, -1, -1
	for y := 0; y < f.h; y++ {
		for x := 0; x < f.w; x++ {
			if f.p[(y*f.w+x)*4+3] > 0.3 {
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
		return f, "全透明，不裁剪"
	}
	bw, bh := maxX-minX+1, maxY-minY+1
	side := bw
	if bh > side {
		side = bh
	}
	side = int(float64(side) * (1 + 2*padRatio))
	if side > f.w {
		side = f.w
	}
	if side > f.h {
		side = f.h
	}
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
	return out, fmt.Sprintf("包围盒 %dx%d（x %d..%d, y %d..%d）→ 方裁 %dx%d",
		bw, bh, minX, maxX, minY, maxY, side, side)
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

func buildWeights(srcLen, dstLen int) [][]weight {
	scale := float64(srcLen) / float64(dstLen)
	if scale < 1 {
		scale = 1
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

// toRGBA 落回 8 位。预乘约束必须成立（R,G,B <= A），否则渲染会出彩边。
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

// ── ICO ──────────────────────────────────────────────────────

// encodeDIB 生成 ICO 条目要的 DIB：BITMAPINFOHEADER + 32bpp BGRA + AND 掩码。
//
// 为什么不全部用 PNG：ICO 里的 PNG 条目 Windows Shell 认，
// 但 **GDI+（System.Drawing.Icon）、部分老工具和安装程序读不了** ——
// 它们按 DIB 解释，结果是一堆彩色噪点。所以 <=64 用 DIB，128/256 用 PNG。
func encodeDIB(im *image.RGBA) []byte {
	w, h := im.Bounds().Dx(), im.Bounds().Dy()
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(40))
	_ = binary.Write(&b, binary.LittleEndian, int32(w))
	_ = binary.Write(&b, binary.LittleEndian, int32(h*2)) // 高度翻倍：XOR 图 + AND 掩码图
	_ = binary.Write(&b, binary.LittleEndian, uint16(1))
	_ = binary.Write(&b, binary.LittleEndian, uint16(32))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(w*h*4))
	_ = binary.Write(&b, binary.LittleEndian, int32(0))
	_ = binary.Write(&b, binary.LittleEndian, int32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))

	// XOR 图：自下而上，BGRA，非预乘
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
	// AND 掩码：1bpp，行按 4 字节对齐，1 = 透明
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

// ── main ────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: go run tools_mkicon.go <源图(png/jpg)> <输出.ico>")
		os.Exit(2)
	}
	srcPath, outPath := os.Args[1], os.Args[2]

	fh, err := os.Open(srcPath)
	if err != nil {
		panic(err)
	}
	img, _, err := image.Decode(fh)
	fh.Close()
	if err != nil {
		panic(err)
	}
	src := decode(img)
	fmt.Printf("源图 %s: %dx%d\n", filepath.Base(srcPath), src.w, src.h)

	// 完整字标（图标 + 文字）→ 只留图标那一块
	blob, blobInfo := keepLargestBlob(src)
	fmt.Println("连通域:", blobInfo)

	cropped, cropInfo := cropSquare(blob)
	fmt.Println("裁剪:", cropInfo)

	// ICO
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
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		b := byte(e.size)
		if e.size >= 256 {
			b = 0
		}
		out.WriteByte(b)
		out.WriteByte(b)
		out.WriteByte(0)
		out.WriteByte(0)
		_ = binary.Write(&out, binary.LittleEndian, uint16(1))
		_ = binary.Write(&out, binary.LittleEndian, uint16(32))
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
	fmt.Printf("已写 %s（%d 个尺寸，共 %d 字节；<=64 DIB / 128+ PNG）\n", outPath, len(entries), out.Len())

	// 预览图
	if f, err := os.Create("nethub-256.png"); err == nil {
		_ = png.Encode(f, resample(cropped, 256, 256).toRGBA())
		f.Close()
		fmt.Println("已写 nethub-256.png")
	}

	// 界面用的透明 PNG（标题栏 logo）
	webDir := filepath.Join(filepath.Dir(outPath), "frontend")
	if st, err := os.Stat(webDir); err == nil && st.IsDir() {
		name := filepath.Join(webDir, "logo.png")
		if f, err := os.Create(name); err == nil {
			_ = png.Encode(f, resample(cropped, 128, 128).toRGBA())
			f.Close()
			fmt.Println("已写 " + strings.ReplaceAll(name, "\\", "/") + "（界面标题栏用）")
		}
	}
}
