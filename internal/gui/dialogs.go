// Package gui 的模态编辑框：链路（≈ Proxifier 的 Proxy Servers）与规则（≈ Proxifier 的 Rules）。
//
// 全部是运行时创建的窗口（NewForm + ShowModal），不依赖 .gfm 设计器资源；
// 事件用闭包绑，不用 govcl 的反射自动绑定（那套要求结构体方法名匹配，运行时窗口用不上）。
package gui

import (
	"strings"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"

	"netproxy/internal/config"
	"netproxy/internal/gostproc"
)

const (
	dlgLabelLeft = 16
	dlgLabelW    = 100
	dlgInputLeft = 124
)

func dlgForm(caption string, w, h int32) *vcl.TForm {
	f := vcl.NewForm(nil)
	f.SetCaption(caption)
	f.SetBorderStyle(types.BsDialog)
	f.SetPosition(types.PoScreenCenter)
	f.SetClientWidth(w)
	f.SetClientHeight(h)
	f.SetShowHint(true)
	return f
}

func dlgLabel(f *vcl.TForm, text string, left, top int32) *vcl.TLabel {
	l := vcl.NewLabel(f)
	l.SetParent(f)
	l.SetLeft(left)
	l.SetTop(top + 4)
	l.SetWidth(dlgLabelW)
	l.SetCaption(text)
	return l
}

// dlgHint 辅助提示文字。
func dlgHint(f *vcl.TForm, text string, left, top, width int32) *vcl.TLabel {
	l := vcl.NewLabel(f)
	l.SetParent(f)
	l.SetLeft(left)
	l.SetTop(top + 4)
	l.SetWidth(width)
	l.SetCaption(text)
	return l
}

func dlgEdit(f *vcl.TForm, left, top, width int32) *vcl.TEdit {
	e := vcl.NewEdit(f)
	e.SetParent(f)
	e.SetLeft(left)
	e.SetTop(top)
	e.SetWidth(width)
	e.SetHeight(24)
	return e
}

// dlgButton 建按钮；mr 传 types.MrNone 表示"自己处理点击"（不自动关窗）。
func dlgButton(f *vcl.TForm, caption string, left, top, width int32, mr types.TModalResult) *vcl.TButton {
	b := vcl.NewButton(f)
	b.SetParent(f)
	b.SetLeft(left)
	b.SetTop(top)
	b.SetWidth(width)
	b.SetHeight(28)
	b.SetCaption(caption)
	if mr != types.MrNone {
		b.SetModalResult(mr)
	}
	return b
}

// chainNameFromBat 从 bat 文件名猜链名：gost-proxy-a.bat → proxy-a。
func chainNameFromBat(file string) string {
	n := file
	if i := strings.LastIndex(n, "."); i > 0 {
		n = n[:i]
	}
	n = strings.TrimPrefix(n, "gost-")
	n = strings.TrimPrefix(n, "gost_")
	return strings.TrimSpace(n)
}

// ───────────────────────── 链路编辑框 ─────────────────────────

// EditChainDialog 弹出链路编辑框。ok=false 表示用户取消。
// others 传全部链（含自己），内部会跳过自己那条来查重。
func EditChainDialog(isNew bool, ch config.Chain, others []config.Chain) (config.Chain, bool) {
	title := "编辑链路"
	if isNew {
		title = "添加链路"
	}
	f := dlgForm(title, 660, 220)

	dlgLabel(f, "链名", dlgLabelLeft, 16)
	eName := dlgEdit(f, dlgInputLeft, 16, 512)
	eName.SetHint("规则里用这个名字引用它")

	dlgLabel(f, "本地监听", dlgLabelLeft, 48)
	eListen := dlgEdit(f, dlgInputLeft, 48, 250)
	dlgHint(f, "host:port，如 127.0.0.1:1082", dlgInputLeft+258, 48, 254)

	dlgLabel(f, "上游转发", dlgLabelLeft, 80)
	eFwd := dlgEdit(f, dlgInputLeft, 80, 512)
	eFwd.SetHint("gost -F 的值")

	dlgHint(f, "凭据会明文保存在 config.yaml，别外传", dlgInputLeft+180, 112, 332)
	impBtn := dlgButton(f, "从 gost .bat 导入…", dlgInputLeft, 108, 172, types.MrNone)

	dlgLabel(f, "备注", dlgLabelLeft, 144)
	eNote := dlgEdit(f, dlgInputLeft, 144, 512)

	okBtn := dlgButton(f, "确定", 452, 182, 88, types.MrNone)
	cancelBtn := dlgButton(f, "取消", 548, 182, 88, types.MrCancel)
	cancelBtn.SetCancel(true)
	okBtn.SetDefault(true)

	eName.SetText(ch.Name)
	eListen.SetText(ch.Listen)
	eFwd.SetText(ch.Forward)
	eNote.SetText(ch.Note)

	// 打开对话框时就初始化好，后面重复点不用反复创建
	od := vcl.NewOpenDialog(f)
	od.SetTitle("选择 gost 批处理")
	od.SetFilter("gost 批处理 (*.bat)|*.bat|所有文件 (*.*)|*.*")

	result, ok := ch, false

	impBtn.SetOnClick(func(vcl.IObject) {
		if !od.Execute() {
			return
		}
		path := od.FileName()
		be, good := gostproc.ParseBatFile(path)
		if !good {
			vcl.ShowMessage("这个文件里没找到成对的 -L \"…\" / -F \"…\"：\r\n" + path)
			return
		}
		eListen.SetText(be.Listen)
		eFwd.SetText(be.Forward)
		if strings.TrimSpace(eName.Text()) == "" {
			eName.SetText(chainNameFromBat(be.File))
		}
	})

	okBtn.SetOnClick(func(vcl.IObject) {
		name := strings.TrimSpace(eName.Text())
		listen := config.NormalizeListenLoose(strings.TrimSpace(eListen.Text()))
		forward := strings.TrimSpace(eFwd.Text())

		if name == "" {
			vcl.ShowMessage("链名不能为空 —— 规则里要用这个名字引用它")
			return
		}
		if _, _, err := gostproc.SplitListen(listen); err != nil {
			vcl.ShowMessage("本地监听要写成 host:port，例如 127.0.0.1:1082")
			return
		}
		if forward == "" {
			vcl.ShowMessage("上游转发 URL 不能为空：它是 gost -F 的值，\r\n形如 socks5+tls://IP:端口?auth=…")
			return
		}
		for _, o := range others {
			if o.Name == ch.Name {
				continue // 自己，跳过
			}
			if o.Name == name {
				vcl.ShowMessage("链名 " + name + " 已被占用")
				return
			}
			if o.Listen == listen {
				vcl.ShowMessage("本地监听 " + listen + " 已被链 " + o.Name + " 占用\r\n" +
					"（两条链监听同一端口的话，后启动的 gost 会绑定失败）")
				return
			}
		}

		result = config.Chain{
			Name:    name,
			Listen:  listen,
			Forward: forward,
			Note:    strings.TrimSpace(eNote.Text()),
		}
		ok = true
		f.SetModalResult(types.MrOk)
	})

	f.ShowModal()
	f.Free()
	return result, ok
}

// ───────────────────────── 规则编辑框 ─────────────────────────

// EditRouteDialog 弹出规则编辑框。ok=false 表示取消。
// taken 是"其它规则已经占用的目标"（调用方负责排除正在编辑的那条）。
func EditRouteDialog(isNew bool, rt config.Route, chains []config.Chain, taken []string) (config.Route, bool) {
	title := "编辑规则"
	if isNew {
		title = "添加规则"
	}
	f := dlgForm(title, 600, 170)

	dlgLabel(f, "目标", dlgLabelLeft, 12)
	eTarget := dlgEdit(f, dlgInputLeft, 12, 456)
	eTarget.SetHint("单个 IP 或网段")
	dlgHint(f, "单个 IP 会自动存成 /32；也可直接写网段，如 10.0.0.0/24", dlgInputLeft, 40, 456)

	dlgLabel(f, "走哪条链", dlgLabelLeft, 68)
	cb := vcl.NewComboBox(f)
	cb.SetParent(f)
	cb.SetLeft(dlgInputLeft)
	cb.SetTop(68)
	cb.SetWidth(240)
	cb.SetStyle(types.CsDropDownList)
	for _, c := range chains {
		cb.Items().Add(c.Name)
	}
	sel := 0
	for i, c := range chains {
		if c.Name == rt.Chain {
			sel = i
		}
	}
	if len(chains) > 0 {
		cb.SetItemIndex(int32(sel))
	}

	lh := dlgHint(f, "", dlgInputLeft, 96, 456)
	updHint := func() {
		i := int(cb.ItemIndex())
		if i >= 0 && i < len(chains) {
			lh.SetCaption("→ 经 gost 本地 socks5 监听 " + chains[i].Listen + " 转发出去")
		} else {
			lh.SetCaption("")
		}
	}
	cb.SetOnChange(func(vcl.IObject) { updHint() })
	updHint()

	eTarget.SetText(rt.Target)

	okBtn := dlgButton(f, "确定", 392, 128, 88, types.MrNone)
	cancelBtn := dlgButton(f, "取消", 488, 128, 88, types.MrCancel)
	cancelBtn.SetCancel(true)
	okBtn.SetDefault(true)

	result, ok := rt, false

	okBtn.SetOnClick(func(vcl.IObject) {
		t, err := config.NormalizeTarget(eTarget.Text())
		if err != nil {
			vcl.ShowMessage("目标不合法：" + err.Error() + "\r\n\r\n" +
				"可以写单个 IP（10.0.1.10）或网段（10.0.1.0/24）")
			return
		}
		for _, s := range taken {
			if strings.EqualFold(s, t) {
				vcl.ShowMessage("目标 " + t + " 已经有一条规则了\r\n" +
					"（规则按顺序匹配，重复的话必有一条永远不生效）")
				return
			}
		}
		i := int(cb.ItemIndex())
		if i < 0 || i >= len(chains) {
			vcl.ShowMessage("请选择一条链")
			return
		}
		result = config.Route{Target: t, Chain: chains[i].Name}
		ok = true
		f.SetModalResult(types.MrOk)
	})

	f.ShowModal()
	f.Free()
	return result, ok
}
