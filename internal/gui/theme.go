// Package gui 的主题层：深浅双模式的色板与应用逻辑。
//
// 色板严格对齐本项目的 DESIGN.md（源自 bid-copilot 设计系统）：
//
//	浅色 = 中性白底 + 深蓝主色 #1e3a8a（产品感、高对比）
//	深色 = 暖黑画布 + 提亮蓝主色
//
// **唯一有意偏离原设计系统的地方**（用户明确要求）：
// 深色主色不用旧主色 #d99c96，改成与浅色同色相的提亮蓝 #3b82f6
// （白字对比度 3.1:1，与原旧主色的 3.0:1 同级，属于规范认可的区间）。
//
// 为什么是"手动遍历控件树刷颜色"而不是跟随系统主题：
// govcl/LCL 走原生 Win32 控件，TButton/TPageControl/TTabSheet 在 govcl 里
// **根本没有 Color 方法**（见 vcl/button.go、pagecontrol.go、tabsheet.go，一个都没有）。
// 所以主界面改用「自绘标签条(TPanel/Label) + 互斥显示的内容面板(TPanel)」，
// 因为这些类型有 SetColor，能被完整主题化；按钮则只能保留系统原生外观。
package gui

import (
	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
	"github.com/ying32/govcl/vcl/types/colors"
)

// Theme 一套完整的颜色 + 字体 + 圆角 token。命名与 DESIGN.md 一致。
type Theme struct {
	Dark bool

	Canvas     types.TColor // canvas 页面底色
	CanvasSoft types.TColor // canvas-soft hover 底、分隔带
	Card       types.TColor // surface-card 卡片底（比 canvas 亮一档，做层次）
	CardStrong types.TColor // surface-card-strong 深/亮一档色块、表格固定行
	Hairline   types.TColor // 1px 边框、分隔线、网格线

	Ink       types.TColor // ink 标题、主文字
	Body      types.TColor // body 正文
	Muted     types.TColor // muted 次级说明
	MutedSoft types.TColor // muted-soft 提示、占位
	OnPrimary types.TColor // on-primary 主色上的文字

	Primary       types.TColor // primary 主按钮、激活态、选中高亮
	PrimaryActive types.TColor // primary-active hover/按下

	Success types.TColor
	Warning types.TColor
	Error   types.TColor

	// 模拟阴影的三层底色（由外到内递深），必须是画布底色的近似色
	ShadowTones []types.TColor

	RadiusCard  int32 // 卡片
	RadiusBtn   int32 // 按钮
	RadiusChip  int32 // 标签条
	RadiusInput int32 // 输入框

	FontName string
	MonoName string
	FontSize int32
}

// Light 浅色（中性语言）：白底 + 中性纯灰阶 + 深蓝主色。
func Light() Theme {
	return Theme{
		Canvas:     rgba(0xFF, 0xFF, 0xFF),
		CanvasSoft: rgba(0xF4, 0xF4, 0xF5),
		Card:       rgba(0xFF, 0xFF, 0xFF),
		CardStrong: rgba(0xEC, 0xEC, 0xEE),
		Hairline:   rgba(0xDC, 0xDD, 0xE1),

		Ink:       rgba(0x0A, 0x0A, 0x0A),
		Body:      rgba(0x2A, 0x2A, 0x2A),
		Muted:     rgba(0x70, 0x70, 0x73),
		MutedSoft: rgba(0xA1, 0xA1, 0xA5),
		OnPrimary: rgba(0xFF, 0xFF, 0xFF),

		Primary:       rgba(0x1E, 0x3A, 0x8A), // 深蓝 blue-900
		PrimaryActive: rgba(0x17, 0x25, 0x54),
		Success:       rgba(0x2F, 0x7D, 0x44),
		Warning:       rgba(0x8A, 0x62, 0x08),
		Error:         rgba(0xB8, 0x38, 0x38),

		// 阴影：在 0 页白底上从外到内递深
		ShadowTones: []types.TColor{
			rgba(0xFA, 0xFA, 0xFB), rgba(0xF3, 0xF3, 0xF5), rgba(0xEA, 0xEA, 0xED),
		},

		RadiusCard:  10,
		RadiusBtn:   6,
		RadiusChip:  7,
		RadiusInput: 6,

		FontName: "Noto Sans SC", // 已安装；比雅黑更现代，字形更开
		MonoName: "Cascadia Code",
		FontSize: 9,
	}
}

// Dark 深色：暖黑画布 + 提亮蓝（主色相与浅色一致）。
// 层次靠"卡片比画布亮"而不是阴影（深色下阴影几乎不可见）。
func Dark() Theme {
	return Theme{
		Canvas:     rgba(0x14, 0x13, 0x12),
		CanvasSoft: rgba(0x1C, 0x1B, 0x19),
		Card:       rgba(0x23, 0x21, 0x1F),
		CardStrong: rgba(0x2C, 0x2A, 0x27),
		Hairline:   rgba(0x3A, 0x37, 0x33),

		// 正文提亮到接近白 —— 之前的 #dcd8d2 在暖黑上偏灰，长时间看类
		Ink:       rgba(0xFA, 0xF9, 0xF6),
		Body:      rgba(0xEC, 0xE9, 0xE4),
		Muted:     rgba(0xB4, 0xAE, 0xA4),
		MutedSoft: rgba(0x8A, 0x84, 0x7B),
		OnPrimary: rgba(0xFF, 0xFF, 0xFF),

		// 提亮蓝：与浅色深蓝同色相，深色画布上可见（白字对比度约 3.1:1）
		Primary:       rgba(0x3B, 0x82, 0xF6),
		PrimaryActive: rgba(0x60, 0xA5, 0xFA),
		Success:       rgba(0x5A, 0xBE, 0x74),
		Warning:       rgba(0xD4, 0xA4, 0x2A),
		Error:         rgba(0xE8, 0x6B, 0x6B),

		ShadowTones: []types.TColor{
			rgba(0x11, 0x10, 0x0F), rgba(0x0E, 0x0D, 0x0C), rgba(0x0B, 0x0A, 0x09),
		},

		RadiusCard:  10,
		RadiusBtn:   6,
		RadiusChip:  7,
		RadiusInput: 6,

		Dark:     true,
		FontName: "Noto Sans SC",
		MonoName: "Cascadia Code",
		FontSize: 9,
	}
}

func rgba(r, g, b byte) types.TColor {
	return types.TColor(colors.RGB(r, g, b))
}

// ByName 按配置里的字符串取主题（空/未知 → 浅色）。
func ByName(name string) Theme {
	if name == "dark" {
		return Dark()
	}
	return Light()
}

// ───────────────────────── 应用 ─────────────────────────

// applyTheme 从窗体开始刷主题：先窗体自身（含深色标题栏），再递归所有子控件。
//
// 注意 TControl 没有统一的 SetColor/Font（govcl 是按类型生成的），
// 所以必须用 As* 断言按类型分派；递归只能用 IWinControl 接口
// （TForm 里嵌的是接口 IWinControl，不是 *TWinControl）。
func applyTheme(f *vcl.TForm, th Theme) {
	if f == nil {
		return
	}
	f.SetColor(th.Canvas)
	setFont(f.Font(), th, th.Body, false, false)
	setDarkTitleBar(f, th.Dark)
	applyChildren(vcl.AsWinControl(f), th)
}

func applyChildren(w vcl.IWinControl, th Theme) {
	if w == nil {
		return
	}
	for i := int32(0); i < w.ControlCount(); i++ {
		applyToControl(w.Controls(i), th)
	}
}

func applyToControl(c *vcl.TControl, th Theme) {
	if c == nil {
		return
	}
	switch {
	case vcl.AsLabel(c) != nil:
		l := vcl.AsLabel(c)
		l.SetColor(th.Canvas)
		setFont(l.Font(), th, th.Body, false, false)

	case vcl.AsEdit(c) != nil:
		e := vcl.AsEdit(c)
		e.SetColor(th.Canvas)
		setFont(e.Font(), th, th.Ink, false, false)

	case vcl.AsComboBox(c) != nil:
		cb := vcl.AsComboBox(c)
		cb.SetColor(th.Canvas)
		setFont(cb.Font(), th, th.Ink, false, false)

	case vcl.AsMemo(c) != nil:
		m := vcl.AsMemo(c)
		m.SetColor(th.Canvas)
		setFont(m.Font(), th, th.Body, true, false)

	case vcl.AsCheckBox(c) != nil:
		ck := vcl.AsCheckBox(c)
		ck.SetColor(th.Canvas)
		setFont(ck.Font(), th, th.Body, false, false)

	case vcl.AsStringGrid(c) != nil:
		g := vcl.AsStringGrid(c)
		g.SetColor(th.Canvas)
		g.SetFixedColor(th.CardStrong)
		g.SetGridLineColor(th.Hairline)
		g.SetSelectedColor(th.Primary)
		setFont(g.Font(), th, th.Body, false, false)

	case vcl.AsPanel(c) != nil:
		p := vcl.AsPanel(c)
		p.SetColor(th.Canvas)
		setFont(p.Font(), th, th.Body, false, false)

	case vcl.AsButton(c) != nil:
		// 按钮底色由系统主题绘制（govcl 里 TButton 没有 SetColor），
		// 所以刻意不改它的字体颜色：浅底浅字会直接看不见。
	}

	// 容器就继续往下刷
	if w := vcl.AsWinControl(c); w != nil {
		applyChildren(w, th)
	}
}

// setFont 统一字体。LCL 只能指定单个字体名（没有 CSS 那样的字体栈回退），
// 所以 DESIGN.md 里的字体栈在这里退化为 Windows 上必然存在的第一个：
// HarmonyOS Sans SC → PingFang SC → Microsoft YaHei UI 取 YaHei UI。
// 标题层级靠字重（bold）而不是字号拉开，与设计系统一致。
func setFont(f *vcl.TFont, th Theme, color types.TColor, mono, bold bool) {
	if f == nil {
		return
	}
	name := th.FontName
	if mono {
		name = th.MonoName
	}
	f.SetName(name)
	f.SetSize(th.FontSize)
	f.SetColor(color)
	if bold {
		f.SetStyle(types.NewSet(types.FsBold))
	} else {
		f.SetStyle(types.NewSet())
	}
}

// CurrentTheme 记住当前主题，便于后续新建控件时沿用。
var CurrentTheme = Light()
