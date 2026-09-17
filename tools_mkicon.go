//go:build ignore

// 生成托盘/exe 图标：蓝底圆角方块 + 白色双箭头（代理语义）。
// 用法：go run tools_mkicon.go netproxy.ico
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"

	"image/png"
	"os"
)

func render(size int) *image.RGBA {
	im := image.NewRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	r := s * 0.22 // 圆角半径
	bg := color.RGBA{0x1E, 0x3A, 0x8A, 0xFF}
	fg := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+.5, float64(y)+.5
			// 圆角矩形内部判定
			in := func(cx, cy float64) bool {
				dx, dy := fx-cx, fy-cy
				if dx < 0 {
					dx = -dx
				}
				if dy < 0 {
					dy = -dy
				}
				ax, ay := s/2-r, s/2-r
				if dx <= ax || dy <= ay {
					return true
				}
				ddx, ddy := dx-ax, dy-ay
				return ddx*ddx+ddy*ddy <= r*r
			}
			if in(s/2, s/2) {
				im.Set(x, y, bg)
			}
		}
	}
	// 双箭头：上箭头→ 下箭头←，用两个平行四边形 + 三角头
	bar := func(x0, x1, y0, y1 int) {
		for y := y0; y < y1; y++ {
			for x := x0; x < x1; x++ {
				if x >= 0 && y >= 0 && x < size && y < size {
					im.Set(x, y, fg)
				}
			}
		}
	}
	th := size / 8
	if th < 1 {
		th = 1
	}
	// 上：向右
	bar(int(s*0.28), int(s*0.66), int(s*0.33), int(s*0.33)+th)
	// 上箭头三角
	for i := 0; i < int(s*0.16); i++ {
		bar(int(s*0.66)+i, int(s*0.66)+i+1, int(s*0.33)-int(s*0.08)+i, int(s*0.33)+th+int(s*0.08)-i)
	}
	// 下：向左
	bar(int(s*0.34), int(s*0.72), int(s*0.67)-th, int(s*0.67))
	for i := 0; i < int(s*0.16); i++ {
		bar(int(s*0.34)-i-1, int(s*0.34)-i, int(s*0.67)-th-int(s*0.08)+i, int(s*0.67)+int(s*0.08)-i)
	}
	return im
}

func main() {
	if len(os.Args) < 2 {
		panic("usage: go run tools_mkicon.go out.ico")
	}
	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	var pngs [][]byte
	for _, s := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, render(s)); err != nil {
			panic(err)
		}
		pngs = append(pngs, buf.Bytes())
	}
	// ICO 容器：6 字节头 + 每张 16 字节目录项 + 数据
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&out, binary.LittleEndian, uint16(1)) // type = icon
	binary.Write(&out, binary.LittleEndian, uint16(len(sizes)))
	offset := 6 + 16*len(sizes)

	for i, s := range sizes {
		b := byte(s)
		if s >= 256 {
			b = 0
		}
		out.WriteByte(b)                                   // width
		out.WriteByte(b)                                   // height
		out.WriteByte(0)                                   // palette
		out.WriteByte(0)                                   // reserved
		binary.Write(&out, binary.LittleEndian, uint16(1)) // planes
		binary.Write(&out, binary.LittleEndian, uint16(32))
		binary.Write(&out, binary.LittleEndian, uint32(len(pngs[i])))
		binary.Write(&out, binary.LittleEndian, uint32(offset))
		offset += len(pngs[i])
		_ = i
	}
	for _, p := range pngs {
		out.Write(p)
	}
	if err := os.WriteFile(os.Args[1], out.Bytes(), 0o644); err != nil {
		panic(err)
	}
	// 同时输出一张 256 png 给 exe 图标参考
	f, _ := os.Create("netproxy-256.png")
	png.Encode(f, render(256))
	if f != nil {
		f.Close()
	}
}
