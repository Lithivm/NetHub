package webui

import (
	"fmt"
	"net"
	"strings"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"nethub/internal/config"
	"nethub/internal/gostbat"
)

// ───────────────────────── 链路（≈ Proxifier 的 Proxy Servers）─────────────────────────

func (b *Backend) AddChain(in ChainInput) error {
	if err := b.a.Cfg.AddChain(in.toChain()); err != nil {
		return err
	}
	return b.save("添加链路 " + in.Name)
}

func (b *Backend) UpdateChain(oldName string, in ChainInput) error {
	if err := b.a.Cfg.UpdateChain(oldName, in.toChain()); err != nil {
		return err
	}
	return b.save("更新链路 " + in.Name)
}

func (b *Backend) DeleteChain(name string) error {
	if err := b.a.Cfg.RemoveChain(name); err != nil {
		return err
	}
	return b.save("删除链路 " + name)
}

func (b *Backend) MoveChain(from, to int) error {
	if err := b.a.Cfg.MoveChain(from, to); err != nil {
		return err
	}
	return b.save("调整链路顺序")
}

func (in ChainInput) toChain() config.Chain {
	fwd := strings.TrimSpace(in.Forward)
	forwards := make([]string, 0, len(in.Forwards))
	for _, f := range in.Forwards {
		if t := strings.TrimSpace(f); t != "" {
			forwards = append(forwards, t)
		}
	}
	if len(forwards) == 0 && fwd != "" {
		forwards = []string{fwd}
	}
	return config.Chain{
		Name:     strings.TrimSpace(in.Name),
		Forwards: forwards,
		Strategy: strings.TrimSpace(in.Strategy),
		Probe:    strings.TrimSpace(in.Probe),
		Note:     strings.TrimSpace(in.Note),
	}
}

// ───────────────────────── 规则（≈ Proxifier 的 Rules）─────────────────────────

// RouteInput 界面上一条规则的完整输入（字段与表单一一对应）。
// 目标/端口/进程都可以一次填多个（换行/逗号/顿号/空格分隔）。
type RouteInput struct {
	Name      string `json:"name"`
	Targets   string `json:"targets"`
	Chain     string `json:"chain"`
	Ports     string `json:"ports"`
	LocalNets string `json:"localNets"`
	Apps      string `json:"apps"`
	// AllowQUIC 放行 QUIC（allow_quic）：勾上 = 这条规则的目标不拦 UDP 443
	AllowQUIC bool `json:"allowQuic"`
}

// ruleFromInput 把界面输入整理成 config.Route。
func ruleFromInput(in RouteInput) (config.Route, error) {
	return ruleFrom(in.Name, in.Targets, in.Chain, in.Ports, in.LocalNets, in.Apps, in.AllowQUIC)
}

// SaveRoute 保存一条规则：index < 0 = 新增，否则替换第 index 条。
// 这是界面当前用的入口（老方法保留给已有调用方，行为一致）。
func (b *Backend) SaveRoute(index int, in RouteInput) error {
	rt, err := ruleFromInput(in)
	if err != nil {
		return err
	}
	if index < 0 {
		base := b.a.Cfg.RouteCount()
		if err := b.a.Cfg.AddRoute(rt); err != nil {
			return err
		}
		return b.saveHint(base, ruleSaved("添加", rt))
	}
	old := ""
	if cur, ok := b.a.Cfg.RouteAt(index); ok {
		// 规则开关由列表上的开关控制，不是表单字段 —— 编辑内容时**必须继承原状态**，
		// 否则“改个名字/加个目标”会悳悹把停用的规则重新启用。
		rt.Enabled = cur.Enabled
		old = cur.Name
		if strings.TrimSpace(old) == "" {
			old = cur.Describe()
		}
	}
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		return err
	}
	if old != "" && strings.TrimSpace(in.Name) != "" && old != in.Name {
		return b.saveHint(index, fmt.Sprintf("%s→%s（%d 个目标）", old, in.Name, len(rt.Targets)))
	}
	return b.saveHint(index, ruleSaved("修改", rt))
}

// ruleFrom 把界面传来的"一条规则"整理成 config.Route：目标与端口文本都可以一次填多个
// （换行/逗号/顿号/空格分隔），这里负责拆分 + 归一化。端口留空 = 任意端口。
func ruleFrom(name, targets, chain, ports, localNets, apps string, allowQUIC bool) (config.Route, error) {
	ts, _, err := config.NormalizeTargets(targets)
	if err != nil {
		return config.Route{}, err
	}
	as, err := normalizeApps(apps)
	if err != nil {
		return config.Route{}, err
	}
	if len(ts) == 0 && len(as) == 0 {
		return config.Route{}, fmt.Errorf("至少要填一个目标（或一个进程条件）")
	}
	ps, _, err := config.NormalizePorts(ports)
	if err != nil {
		return config.Route{}, err
	}
	// A16：可选的“仅在这些本机网段下生效”（逗号/分号/空白分隔都行）
	var lns []string
	for _, ln := range strings.FieldsFunc(localNets, func(r rune) bool {
		switch r {
		case ',', '，', ';', '；', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	}) {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(ln); err != nil && net.ParseIP(ln) == nil {
			return config.Route{}, fmt.Errorf("本机网段 %q 不是合法的 IP/网段", ln)
		}
		lns = append(lns, ln)
	}
	return config.Route{Name: name, Targets: ts, Ports: ps, Chain: chain, LocalNets: lns, Apps: as,
		AllowQUIC: allowQUIC}, nil
}

// normalizeApps 拆分并校验进程条件：进程名（可带 * 通配，也可写完整路径）。
// 这里只挡明显的写法错误，真正的匹配在 rules.MatchAppName。
func normalizeApps(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', '，', '、', ';', '；', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	}) {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		if strings.ToLower(a) != a {
			// 大小写保留原样（匹配时不分大小写）
		}
		if strings.ContainsAny(a, `<>|"`) {
			return nil, fmt.Errorf("进程条件 %q 含非法字符", a)
		}
		// 写完整路径也照原样存（匹配时只比文件名，见 rules.MatchAppName）——
		// 不替用户改写输入，界面显示原形。

		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// ruleSaved 保存成功后给日志/界面的回执文案。
func ruleSaved(verb string, rt config.Route) string {
	if len(rt.Targets) == 0 && len(rt.Apps) > 0 {
		return fmt.Sprintf("%s规则%s（进程 %s）", verb, rt.Describe(), strings.Join(rt.Apps, " "))
	}
	if len(rt.Ports) > 0 {
		return fmt.Sprintf("%s规则%s（%d 个目标，端口 %s）", verb, rt.Describe(), len(rt.Targets), config.PortText(rt.Ports))
	}
	return fmt.Sprintf("%s规则%s（%d 个目标）", verb, rt.Describe(), len(rt.Targets))
}

// AddRoute 添加一条规则。名字可留空；目标与端口都可以一次填多个 ——
// 多个目标属于**同一条规则**（对齐 Proxifier：一个动作挂一组目标 + 一组端口）。
func (b *Backend) AddRoute(name, targets, chain, ports, localNets string) error {
	rt, err := ruleFrom(name, targets, chain, ports, localNets, "", false)
	if err != nil {
		return err
	}
	if err := b.a.Cfg.AddRoute(rt); err != nil {
		return err
	}
	return b.saveHint(b.a.Cfg.RouteCount()-1, ruleSaved("添加", rt))
}

// UpdateRoute 替换第 index 条规则（同样支持多目标 + 端口条件）。
func (b *Backend) UpdateRoute(index int, name, targets, chain, ports, localNets string) error {
	rt, err := ruleFrom(name, targets, chain, ports, localNets, "", false)
	if err != nil {
		return err
	}
	// 这个入口（老 API）不带 allow_quic 参数：像 SaveRoute 对 Enabled 那样**继承原值**，
	// 否则“用老接口改个名字”会静默把“不拦 QUIC”抹掉。
	if cur, ok := b.a.Cfg.RouteAt(index); ok {
		rt.AllowQUIC = cur.AllowQUIC
	}
	if err := b.a.Cfg.UpdateRoute(index, rt); err != nil {
		return err
	}
	return b.saveHint(index, ruleSaved("更新", rt))
}

func (b *Backend) DeleteRoute(index int) error {
	if err := b.a.Cfg.RemoveRoute(index); err != nil {
		return err
	}
	return b.save("删除规则")
}

func (b *Backend) MoveRoute(from, to int) error {
	if err := b.a.Cfg.MoveRoute(from, to); err != nil {
		return err
	}
	return b.save("调整规则顺序")
}

// ───────────────────────── 导入 gost 批处理 ─────────────────────────

// PickBatFile 弹文件框选一个 gost .bat，解析出 -L/-F 回填给表单（不直接写配置）。
func (b *Backend) PickBatFile() (*BatEntryView, error) {
	path, err := b.uiOrNoop().OpenFile(wruntime.OpenDialogOptions{
		Title: "选择 gost 批处理",
		Filters: []wruntime.FileFilter{
			{DisplayName: "gost 批处理 (*.bat)", Pattern: "*.bat"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil // 用户取消
	}
	be, ok := gostbat.ParseBatFile(path)
	if !ok {
		return nil, fmt.Errorf("这个文件里没找到成对的 -L \"…\" / -F \"…\"：\n%s", path)
	}
	return &BatEntryView{File: be.File, Forward: be.Forward, Name: be.Name()}, nil
}

// ImportBatDir 选一个目录，批量把里面的 gost .bat 加为链（同名则更新上游）。
func (b *Backend) ImportBatDir() (*ImportResult, error) {
	dir, err := b.uiOrNoop().OpenDir(wruntime.OpenDialogOptions{
		Title: "选择 gost 脚本所在目录",
	})
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, nil
	}
	got := gostbat.ScanBatDir(dir)
	if len(got) == 0 {
		return nil, fmt.Errorf("这个目录里没找到含成对 -L/-F 的 gost 批处理：\n%s", dir)
	}
	res, err := b.applyBatEntries(got)
	if err != nil {
		return res, err
	}
	if err := b.save("从 .bat 导入"); err != nil {
		return res, err
	}
	return res, nil
}

// applyBatEntries 把扫描到的 gost 批处理套到配置上（不落盘，便于测试）。
func (b *Backend) applyBatEntries(got []gostbat.BatEntry) (*ImportResult, error) {
	res := &ImportResult{}
	for _, be := range got {
		name := be.Name()
		if idx := b.a.Cfg.FindChain(name); idx >= 0 {
			// 同名链已存在 → 只更新 upstream（最常见的"换服务器"场景）
			cur, _ := b.a.Cfg.ChainAt(idx)
			cur.SetUpstreams([]string{be.Forward}) // 必须整体替换，不能只写 Forward（见 SetUpstreams 注释）
			if err := b.a.Cfg.UpdateChain(name, cur); err != nil {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s：更新失败（%v）", name, err))
			} else {
				res.Added = append(res.Added, fmt.Sprintf("%s：已更新上游（来自 %s）", name, be.File))
			}
			continue
		}
		err := b.a.Cfg.AddChain(config.Chain{
			Name: name, Forward: be.Forward,
			Note: "从 " + be.File + " 导入",
		})
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s：跳过（%v）", name, err))
		} else {
			res.Added = append(res.Added, fmt.Sprintf("%s：已更新上游（来自 %s）", name, be.File))
		}
	}
	return res, nil
}
