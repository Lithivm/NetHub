// Package gui 的自绘控件层。
//
// 为什么必须自己画：govcl/LCL 包的是原生 Win32 控件，
//   - TButton 连 SetColor 都没有（vcl/button.go 里一个 Color 都没有），底色由系统主题绘制
//   - TPanel 有 SetColor，但 Win32 面板画不出圆角/阴影
//
// 结果就是"Win7 工程软件"观感。要圆角、阴影、hover 态，只能在 TPanel 上挂 OnPaint 自己画。
//
// 所以本文件里的控件都是「TPanel + OnPaint + 鼠标事件」手搓出来的：
//
//	Card       圆角卡片（可带 1px 描边 + 模拟阴影），用来装内容分组
//	FlatButton 扁平按钮（主/次/幽灵/危险四种），带 hover/press 态
//	TabChip    圆角标签条（选中 = 主色块）
//	InputCard  圆角输入框容器（内嵌无边框原生输入控件，焦点时描边变主色）
//
// 输入框/多行文本/表格仍然用原生控件（键盘输入、滚动、文本选择这些不值得重造），
// 但通过 SetBorderStyle(bsNone) 去掉原生边框，塞进手绘的圆角容器里 —— 视觉上就统一了。
package gui

import (
	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// ───────────────────────── 基础绘制 ─────────────────────────

// selfPainted 记录"自己负责绘制"的 Panel。
// 主题遍历时必须跳过它们，否则会把圆角外的补色刷成画布色，圆角就脏了。
var selfPainted = map[uintptr]bool{}

func registerSelfPainted(o vcl.IWinControl) {
	if o != nil {
		selfPainted[o.Instance()] = true
	}
}

// paintRoundRect 画一个圆角矩形（填充 + 可选描边）。
func paintRoundRect(c *vcl.TCanvas, x1, y1, x2, y2, r int32, fill, border types.TColor) {
	c.Brush().SetStyle(types.BsSolid)
	c.Brush().SetColor(fill)
	if border == 0 {
		c.Pen().SetStyle(types.PsClear)
	} else {
		c.Pen().SetStyle(types.PsSolid)
		c.Pen().SetColor(border)
		c.Pen().SetWidth(1)
	}
	c.RoundRect(x1, y1, x2, y2, r, r)
}

// paintShadow 用几层递减色模拟阴影（Win32 画布没有 alpha 混合，只能这样堆）。
// 阴影必须画在卡片之前，从最外层（最淡）往里画。
func paintShadow(c *vcl.TCanvas, x1, y1, x2, y2, r int32, tones []types.TColor) {
	for i := len(tones); i >= 1; i-- {
		t := tones[i-1]
		if t == 0 {
			continue
		}
		d := int32(i)
		c.Brush().SetStyle(types.BsSolid)
		c.Brush().SetColor(t)
		c.Pen().SetStyle(types.PsClear)
		c.RoundRect(x1-d, y1-d+1, x2+d, y2+d, r+d, r+d)
	}
}

// drawTextCentered 在指定矩形里居中画一行字（无底色）。
func drawTextCentered(c *vcl.TCanvas, x1, y1, x2, y2 int32, s string, f *vcl.TFont, color types.TColor) {
	c.Brush().SetStyle(types.BsClear)
	c.Pen().SetStyle(types.PsClear)
	c.SetFont(f)
	c.Font().SetColor(color)
	ts := c.TextExtent(s)
	c.TextOut(x1+(x2-x1-ts.Cx)/2, y1+(y2-y1-ts.Cy)/2, s)
}

// drawIconDot 画状态圆点。
func drawIconDot(c *vcl.TCanvas, cx, cy, radius int32, color types.TColor) {
	c.Brush().SetStyle(types.BsSolid)
	c.Brush().SetColor(color)
	c.Pen().SetStyle(types.PsClear)
	c.Ellipse(cx-radius, cy-radius, cx+radius, cy+radius)
}

// ───────────────────────── 卡片 ─────────────────────────

// Card 圆角卡片容器：装一组内容，能带描边和投影。
type Card struct {
	*vcl.TPanel
	Shadow     bool
	Fill       func(th Theme) types.TColor // 允许调用方指定填充色
	BorderOnly bool
}

// mkCard 建一张圆角卡片。父容器底色即卡片圆角外的补色（所以父容器必须先设成主题底色）。
func mkCard(parent vcl.IWinControl, shadow bool) *Card {
	p := vcl.NewPanel(parent)
	p.SetParent(parent)
	p.SetBevelOuter(types.BvNone)
	p.SetColor(CurrentTheme.Canvas) // 圆角外露出的部分跟父容器同色
	c := &Card{TPanel: p, Shadow: shadow}
	p.SetOnPaint(func(vcl.IObject) { c.paint() })
	registerSelfPainted(p)
	return c
}

func (c *Card) paint() {
	th := CurrentTheme
	cv := c.Canvas()
	w, h := c.ClientWidth(), c.ClientHeight()
	fill := th.Card
	if c.BorderOnly {
		fill = th.Canvas
	}
	if c.Fill != nil {
		fill = c.Fill(th)
	}
	if c.Shadow {
		paintShadow(cv, 0, 0, w-1, h-1, th.RadiusCard, th.ShadowTones)
	}
	paintRoundRect(cv, 0, 0, w-1, h-1, th.RadiusCard, fill, th.Hairline)
	c.SetColor(fill)
}

// ───────────────────────── 扁平按钮 ─────────────────────────

// BtnVariant 按钮语义。
type BtnVariant int

const (
	BtnPrimary   BtnVariant = iota // 主路径：实心主色
	BtnSecondary                   // 次要：浅底 + 描边
	BtnGhost                       // 幽灵：无底，hover 才出底
	BtnDanger                      // 危险：红字
)

// FlatButton 自绘扁平圆角按钮（替代原生 TButton）。
type FlatButton struct {
	*vcl.TPanel
	Caption string
	Variant BtnVariant
	Icon    string // 可选前缀字符（✓ ✗ ⟳ 等），空则不加

	hover   bool
	press   bool
	enabled bool
	onClick func()
}

// mkBtn 建扁平按钮。
func mkBtn(parent vcl.IWinControl, caption string, left, top, width, height int32,
	variant BtnVariant, fn func()) *FlatButton {

	p := vcl.NewPanel(parent)
	p.SetParent(parent)
	p.SetLeft(left)
	p.SetTop(top)
	p.SetWidth(width)
	p.SetHeight(height)
	p.SetBevelOuter(types.BvNone)
	p.SetColor(CurrentTheme.Canvas)
	p.SetCursor(types.CrHandPoint)

	b := &FlatButton{TPanel: p, Caption: caption, Variant: variant, enabled: true, onClick: fn}
	b.colorize()
	registerSelfPainted(p)

	p.SetOnPaint(func(vcl.IObject) { b.paint() })
	p.SetOnMouseEnter(func(vcl.IObject) { b.hover = true; p.Invalidate() })
	p.SetOnMouseLeave(func(vcl.IObject) { b.hover = false; b.press = false; p.Invalidate() })
	p.SetOnMouseDown(func(vcl.IObject, types.TMouseButton, types.TShiftState, int32, int32) {
		b.press = true
		p.Invalidate()
	})
	p.SetOnMouseUp(func(vcl.IObject, types.TMouseButton, types.TShiftState, int32, int32) {
		b.press = false
		p.Invalidate()
	})
	p.SetOnClick(func(vcl.IObject) {
		if b.enabled && b.onClick != nil {
			b.onClick()
		}
	})
	return b
}

// colorize 设置面板底色 = 按钮圆角外的补色（父容器底色）。
func (b *FlatButton) colorize() {
	parent := b.Parent()
	if parent != nil {
		b.SetColor(vcl.AsPanel(parent).Color())
	}
}

// SetEnabledUI 启用/禁用（视觉 + 交互）。
func (b *FlatButton) SetEnabledUI(on bool) {
	b.enabled = on
	b.SetCursor(types.CrDefault)
	if on {
		b.SetCursor(types.CrHandPoint)
	}
	b.Invalidate()
}

// SetCaptionText 改标题并重画。
func (b *FlatButton) SetCaptionText(s string) {
	b.Caption = s
	b.Invalidate()
}

func (b *FlatButton) fillColor(th Theme) (fill, text types.TColor) {
	if !b.enabled {
		return th.CardStrong, th.MutedSoft
	}
	switch b.Variant {
	case BtnPrimary:
		if b.press {
			return th.PrimaryActive, th.OnPrimary
		}
		if b.hover {
			return th.PrimaryActive, th.OnPrimary
		}
		return th.Primary, th.OnPrimary
	case BtnDanger:
		if b.hover {
			return th.CardStrong, th.Error
		}
		return th.Canvas, th.Error
	case BtnGhost:
		if b.press || b.hover {
			return th.CanvasSoft, th.Ink
		}
		return th.Canvas, th.Muted
	default: // BtnSecondary
		if b.press {
			return th.CardStrong, th.Ink
		}
		if b.hover {
			return th.CanvasSoft, th.Ink
		}
		return th.Card, th.Body
	}
}

func (b *FlatButton) paint() {
	th := CurrentTheme
	fill, text := b.fillColor(th)

	// 卡片内/外的按钮，圆角外补色取父容器色
	if p := b.Parent(); p != nil {
		if pp := vcl.AsPanel(p); pp != nil {
			b.SetColor(pp.Color())
		}
	}
	cv := b.Canvas()
	w, h := b.ClientWidth(), b.ClientHeight()

	border := th.Hairline
	if b.Variant == BtnPrimary && b.enabled {
		border = 0 // 主按钮不描边（实心色块自身就是边界）
	}
	if b.Variant == BtnGhost && !b.hover && !b.press {
		border = 0
	}
	paintRoundRect(cv, 0, 0, w-1, h-1, th.RadiusBtn, fill, border)

	label := b.Caption
	if b.Icon != "" {
		label = b.Icon + "  " + b.Caption
	}
	drawTextCentered(cv, 0, 0, w, h, label, b.Font(), text)
}

// ───────────────────────── 标签条 ─────────────────────────

// TabChip 圆角标签条：选中 = 主色块 + 白字。
type TabChip struct {
	*vcl.TPanel
	Index   int
	Caption string

	active bool
	hover  bool
	onPick func(int)
}

func mkTabChip(parent vcl.IWinControl, idx int, caption string, left, top, width, height int32, onPick func(int)) *TabChip {
	p := vcl.NewPanel(parent)
	p.SetParent(parent)
	p.SetLeft(left)
	p.SetTop(top)
	p.SetWidth(width)
	p.SetHeight(height)
	p.SetBevelOuter(types.BvNone)
	p.SetCursor(types.CrHandPoint)
	p.SetColor(CurrentTheme.CanvasSoft)

	t := &TabChip{TPanel: p, Index: idx, Caption: caption, onPick: onPick}
	p.SetOnPaint(func(vcl.IObject) { t.paint() })
	registerSelfPainted(p)
	p.SetOnMouseEnter(func(vcl.IObject) { t.hover = true; p.Invalidate() })
	p.SetOnMouseLeave(func(vcl.IObject) { t.hover = false; p.Invalidate() })
	p.SetOnClick(func(vcl.IObject) {
		if t.onPick != nil {
			t.onPick(t.Index)
		}
	})
	return t
}

// SetActive 由外部（showTab）设置选中态。
func (t *TabChip) SetActive(on bool) {
	t.active = on
	if p := t.Parent(); p != nil {
		if pp := vcl.AsPanel(p); pp != nil {
			t.SetColor(pp.Color())
		}
	}
	t.Invalidate()
}

func (t *TabChip) paint() {
	th := CurrentTheme
	cv := t.Canvas()
	w, h := t.ClientWidth(), t.ClientHeight()

	fill, text := th.CanvasSoft, th.Muted
	border := types.TColor(0)
	if t.active {
		fill, text = th.Primary, th.OnPrimary
	} else if t.hover {
		fill, text, border = th.Card, th.Ink, th.Hairline
	}
	paintRoundRect(cv, 0, 0, w-1, h-1, th.RadiusChip, fill, border)
	drawTextCentered(cv, 0, 0, w, h, t.Caption, t.Font(), text)
}

// ───────────────────────── 输入框容器 ─────────────────────────

// InputCard 圆角输入容器：内嵌一个无边框的原生输入控件，焦点时描边变主色。
// 原生控件负责键盘/选择/滚动，容器负责圆角与焦点描边。
type InputCard struct {
	*vcl.TPanel
	focused bool
}

// mkInputCard 建容器并接管 inner 的焦点事件（inner 需要自己 SetParent 到返回的容器上）。
func mkInputCard(parent vcl.IWinControl, left, top, width, height int32, inner vcl.IWinControl,
	onFocusIn, onFocusOut func()) *InputCard {

	p := vcl.NewPanel(parent)
	p.SetParent(parent)
	p.SetLeft(left)
	p.SetTop(top)
	p.SetWidth(width)
	p.SetHeight(height)
	p.SetBevelOuter(types.BvNone)
	p.SetColor(CurrentTheme.Canvas)

	ic := &InputCard{TPanel: p}
	p.SetOnPaint(func(vcl.IObject) { ic.paint() })
	registerSelfPainted(p)

	if inner != nil {
		inner.SetParent(p)
		// 内嵌控件铺满容器，留 1px 给描边
		if w := vcl.AsWinControl(inner); w != nil {
			w.SetAlign(types.AlClient)
		}
		wireFocus(inner, func() {
			ic.focused = true
			ic.Invalidate()
			if onFocusIn != nil {
				onFocusIn()
			}
		}, func() {
			ic.focused = false
			ic.Invalidate()
			if onFocusOut != nil {
				onFocusOut()
			}
		})
	}
	return ic
}

// wireFocus 给不同类型的原生控件挂上焦点事件。
func wireFocus(c vcl.IWinControl, onIn, onOut func()) {
	if e := vcl.AsEdit(c); e != nil {
		e.SetOnEnter(func(vcl.IObject) { onIn() })
		e.SetOnExit(func(vcl.IObject) { onOut() })
		return
	}
	if m := vcl.AsMemo(c); m != nil {
		m.SetOnEnter(func(vcl.IObject) { onIn() })
		m.SetOnExit(func(vcl.IObject) { onOut() })
		return
	}
	if cb := vcl.AsComboBox(c); cb != nil {
		cb.SetOnEnter(func(vcl.IObject) { onIn() })
		cb.SetOnExit(func(vcl.IObject) { onOut() })
		return
	}
	if g := vcl.AsStringGrid(c); g != nil {
		g.SetOnEnter(func(vcl.IObject) { onIn() })
		g.SetOnExit(func(vcl.IObject) { onOut() })
	}
}

func (ic *InputCard) paint() {
	th := CurrentTheme
	cv := ic.Canvas()
	w, h := ic.ClientWidth(), ic.ClientHeight()
	border := th.Hairline
	if ic.focused {
		border = th.Primary
	}
	paintRoundRect(cv, 0, 0, w-1, h-1, th.RadiusInput, th.Canvas, border)
}

// ───────────────────────── 分组标题 ─────────────────────────

// SectionTitle 分组标题：字重加粗 + 可选状态圆点（替代原来的 "── xx ──" 纯文字）。
type SectionTitle struct {
	*vcl.TPanel
	Text   string
	Dot    types.TColor // 0 = 不画点
	Muted  bool
	sub    string
	th     *Theme
	height int32
}

func mkSectionTitle(parent vcl.IWinControl, text string, left, top, width int32, muted bool) *SectionTitle {
	p := vcl.NewPanel(parent)
	p.SetParent(parent)
	p.SetLeft(left)
	p.SetTop(top)
	p.SetWidth(width)
	p.SetHeight(24)
	p.SetBevelOuter(types.BvNone)

	st := &SectionTitle{TPanel: p, Text: text, Muted: muted}
	p.SetOnPaint(func(vcl.IObject) { st.paint() })
	registerSelfPainted(p)
	return st
}

func (st *SectionTitle) paint() {
	th := CurrentTheme
	cv := st.Canvas()
	st.SetColor(th.Canvas)

	cv.Brush().SetStyle(types.BsClear)
	cv.Pen().SetStyle(types.PsClear)
	cv.SetFont(st.Font())

	text := th.Ink
	size := th.FontSize
	if st.Muted {
		text = th.Muted
		size = th.FontSize - 1
	}
	st.Font().SetSize(size)
	st.Font().SetColor(text)
	st.Font().SetStyle(types.NewSet(types.FsBold))

	x := int32(0)
	if st.Dot != 0 {
		drawIconDot(cv, 5, 12, 4, st.Dot)
		x = 18
	}
	cv.TextOut(x, 5, st.Text)
}
