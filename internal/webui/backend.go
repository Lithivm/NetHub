// Package webui 是 Wails 的 Go 侧：把 app.App 的能力暴露给前端。
//
// 前端约定（Wails 用 Go 包名 + 结构体名 + 方法名做命名空间，运行时自动生成 bindings，
// **不需要 wails CLI 也不需要 npm**）：
//
//	await window.go.webui.Backend.GetState()
//	await window.go.webui.Backend.AddChain({name, listen, forward, note})
//
// 返回值末尾带 error 的方法，前端 Promise 会 reject（catch 到错误文本）。
package webui

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"netproxy/internal/app"
	"netproxy/internal/autostart"
	"netproxy/internal/config"
	"netproxy/internal/gostbat"
	"netproxy/internal/hostsmgr"
	"netproxy/internal/logbus"
	"netproxy/internal/upstream"
	"netproxy/internal/winrun"
)

// Backend 是绑定给前端的对象。
type Backend struct {
	a   *app.App
	ctx context.Context

	mu       sync.Mutex
	logCh    chan logbus.Line
	tray     *Tray
	quitting bool

	// 自启状态缓存：schtasks 是外部进程，不能在 GetState（前端每 1.5s 调一次）里跑，
	// 否则会不断创建进程；而且 GUI 子系统没控制台，会表现为窗口一直闪、抢焦点。
	autoMu      sync.RWMutex
	autoEnabled bool
	autoDetail  string
}

func New(a *app.App) *Backend {
	return &Backend{a: a, logCh: make(chan logbus.Line, 256)}
}

// OnStartup Wails 启动回调：拿 ctx、接管通知、把日志推给前端、拉起服务。
func (b *Backend) OnStartup(ctx context.Context) {
	b.ctx = ctx
	b.refreshAutostart()
	b.a.Notify = func(title, text string, kind app.NotifyKind) {
		b.emit("notify", NotifyView{Title: title, Text: text, Kind: kind.String()})
		if b.tray != nil {
			b.tray.Balloon(title, text, kind)
		}
	}
	sub := b.a.Bus.Subscribe()
	go func() {
		for l := range sub {
			b.emit("log", logView(l))
		}
	}()

	// 后台巡检 Clash 绕过覆盖：内网被交给 Clash 是红线（DNS 外泄/封号风险），
	// 不能只靠用户打开界面才发现 —— 每 60 秒查一次（只读注册表，不发网络请求）
	go b.clashWatch()

	// 起来就把服务拉起（计划任务开机自启靠这个：进程起来 = 隧道就绪）
	go func() {
		time.Sleep(600 * time.Millisecond)
		b.a.Bus.Info("开始自动启动服务…")
		if err := b.a.Start(); err != nil {
			b.a.Bus.Error("自动启动失败（可在界面上手动重试）: %v", err)
		}
	}()
}

// OnDomReady 页面就绪。
func (b *Backend) OnDomReady(ctx context.Context) {
	b.a.Bus.Info("界面已就绪")
}

// OnBeforeClose 点 X → 收进托盘继续跑，返回 true 阻止关闭。
func (b *Backend) OnBeforeClose(ctx context.Context) bool {
	if b.quitting {
		return false
	}
	wruntime.WindowHide(ctx)
	if b.tray != nil {
		b.tray.Balloon("netproxy 仍在运行", "已最小化到托盘，双击托盘图标恢复窗口", app.NotifyInfo)
	}
	return true
}

func (b *Backend) emit(name string, data any) {
	if b.ctx == nil {
		return
	}
	wruntime.EventsEmit(b.ctx, name, data)
}

// ───────────────────────── 视图类型（与前端 JSON 对齐）─────────────────────────

type StateView struct {
	Running     bool   `json:"running"`
	Relay       string `json:"relay"`
	GostPIDs    string `json:"gostPids"`
	TotalConns  uint64 `json:"totalConns"`
	ActiveConns int    `json:"activeConns"`
	ConfigPath  string `json:"configPath"`
	LogPath     string `json:"logPath"`
	Theme       string `json:"theme"`
	HostsPath   string `json:"hostsPath"`
	HostsInFile bool   `json:"hostsInFile"` // hosts 里已存在我们的标记区块
	Autostart   bool   `json:"autostart"`
	AutoDetail  string `json:"autoDetail"`
}

type ChainView struct {
	Name    string   `json:"name"`
	_       struct{} `json:"-"`
	Forward string   `json:"forward"` // 已遮蔽凭据
	Note    string   `json:"note"`
}

type RouteView struct {
	Index  int    `json:"index"`
	Target string `json:"target"`
	Chain  string `json:"chain"`
	Note   string `json:"note"`
}

type LogView struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

type NotifyView struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	Kind  string `json:"kind"` // info | warn | error
}

type SettingsView struct {
	Relay        string   `json:"relay"`
	HostsManage  bool     `json:"hostsManage"`
	HostsEntries []string `json:"hostsEntries"`
	Theme        string   `json:"theme"`
}

type ChainInput struct {
	Name    string   `json:"name"`
	_       struct{} `json:"-"`
	Forward string   `json:"forward"`
	Note    string   `json:"note"`
}

type BatEntryView struct {
	File    string   `json:"file"`
	_       struct{} `json:"-"`
	Forward string   `json:"forward"`
	Name    string   `json:"name"`
}

type ImportResult struct {
	Added   []string `json:"added"`
	Skipped []string `json:"skipped"`
}

type ProbeView struct {
	Target string `json:"target"`
	Port   int    `json:"port"` // 命中的端口，0 = 没连上
	OK     bool   `json:"ok"`
	Err    string `json:"err"`
}

func logView(l logbus.Line) LogView {
	return LogView{Time: l.Time.Format("15:04:05.000"), Level: l.Level, Text: l.Text}
}

// ───────────────────────── 读取 ─────────────────────────

// GetState 一次性拿界面需要的所有状态（前端每秒轮询，比推事件简单可靠）。
func (b *Backend) GetState() StateView {
	total, active := b.a.Engine.Stats()
	relay := b.a.Engine.RelayAddr()
	pids := "-" // 上游为原生实现，不再有子进程
	_, hostsInFile, _, _ := hostsmgr.Read()
	return StateView{
		Running:     b.a.Running(),
		Relay:       relay,
		GostPIDs:    pids,
		TotalConns:  total,
		ActiveConns: active,
		ConfigPath:  b.a.Cfg.Path(),
		LogPath:     b.a.Bus.FilePath(),
		Theme:       b.a.Cfg.UI.Theme,
		HostsPath:   hostsmgr.Path(),
		HostsInFile: hostsInFile,
		Autostart:   b.autostartCached(),
		AutoDetail:  b.autostartDetailCached(),
	}
}

// refreshAutostart 跑一次 schtasks 并把结果缓存起来（只在启动、切换自启时调）。
func (b *Backend) refreshAutostart() {
	on := autostart.Enabled()
	detail := ""
	if on {
		detail = autostart.Detail()
	}
	b.autoMu.Lock()
	b.autoEnabled, b.autoDetail = on, detail
	b.autoMu.Unlock()
}

func (b *Backend) autostartCached() bool {
	b.autoMu.RLock()
	defer b.autoMu.RUnlock()
	return b.autoEnabled
}

func (b *Backend) autostartDetailCached() string {
	b.autoMu.RLock()
	defer b.autoMu.RUnlock()
	return b.autoDetail
}

func (b *Backend) GetChains() []ChainView {
	out := make([]ChainView, 0, len(b.a.Cfg.Chains))
	for _, c := range b.a.Cfg.Chains {
		out = append(out, ChainView{
			Name:    c.Name,
			Forward: gostbat.Redact(c.Forward), Note: c.Note,
		})
	}
	return out
}

func (b *Backend) GetRoutes() []RouteView {
	note := map[string]string{}
	for _, c := range b.a.Cfg.Chains {
		note[c.Name] = c.Note
	}
	out := make([]RouteView, 0, len(b.a.Cfg.Routes))
	for i, r := range b.a.Cfg.Routes {
		out = append(out, RouteView{Index: i, Target: r.Target, Chain: r.Chain, Note: note[r.Chain]})
	}
	return out
}

func (b *Backend) GetLogs() []LogView {
	src := b.a.Bus.Snapshot()
	out := make([]LogView, 0, len(src))
	for _, l := range src {
		out = append(out, logView(l))
	}
	return out
}

func (b *Backend) GetSettings() SettingsView {
	entries := b.a.Cfg.Hosts.Entries
	if len(entries) == 0 {
		if block, ok, _, err := hostsmgr.Read(); err == nil && ok {
			entries = block
		}
	}
	if len(entries) == 0 {
		entries = defaultHostsEntries()
	}
	return SettingsView{
		Relay:        b.a.Cfg.Relay,
		HostsManage:  b.a.Cfg.Hosts.Manage,
		HostsEntries: entries,
		Theme:        b.a.Cfg.UI.Theme,
	}
}

func defaultHostsEntries() []string {
	return []string{
		"10.0.0.10 app.example.com",
		"10.0.0.10 opm.example.com",
		"192.168.100.10 site-b.example.com",
		"192.168.100.10 site-c.example.com",
	}
}

// ───────────────────────── 启停 ─────────────────────────

func (b *Backend) Start() error   { return b.a.Start() }
func (b *Backend) Stop()          { b.a.Stop() }
func (b *Backend) Restart() error { return b.a.Restart() }

// Quit 真正退出：先停服务再关窗。
func (b *Backend) Quit() {
	b.quitting = true
	b.a.Stop()
	if b.tray != nil {
		b.tray.Remove()
	}
	wruntime.Quit(b.ctx)
}

// HideToTray 自绘标题栏的"最小化到托盘"按钮。
func (b *Backend) HideToTray() {
	wruntime.WindowHide(b.ctx)
}

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
	return config.Chain{
		Name: strings.TrimSpace(in.Name),

		Forward: strings.TrimSpace(in.Forward),
		Note:    strings.TrimSpace(in.Note),
	}
}

// ───────────────────────── 规则（≈ Proxifier 的 Rules）─────────────────────────

func (b *Backend) AddRoute(target, chain string) error {
	if err := b.a.Cfg.AddRoute(config.Route{Target: target, Chain: chain}); err != nil {
		return err
	}
	return b.save("添加规则")
}

func (b *Backend) UpdateRoute(index int, target, chain string) error {
	if err := b.a.Cfg.UpdateRoute(index, config.Route{Target: target, Chain: chain}); err != nil {
		return err
	}
	return b.save("更新规则")
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
	path, err := wruntime.OpenFileDialog(b.ctx, wruntime.OpenDialogOptions{
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
	dir, err := wruntime.OpenDirectoryDialog(b.ctx, wruntime.OpenDialogOptions{
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
	res := &ImportResult{}
	for _, be := range got {
		name := be.Name()
		if idx := b.a.Cfg.FindChain(name); idx >= 0 {
			// 同名链已存在 → 只更新 listen/forward（最常见的"换服务器"场景）
			cur := b.a.Cfg.Chains[idx]
			cur.Forward = be.Forward
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
	if err := b.save("从 .bat 导入"); err != nil {
		return res, err
	}
	return res, nil
}

// ───────────────────────── 设置 ─────────────────────────

func (b *Backend) SaveSettings(s SettingsView) error {
	cfg := b.a.Cfg
	cfg.Relay = strings.TrimSpace(s.Relay)
	cfg.Hosts.Manage = s.HostsManage
	if len(s.HostsEntries) > 0 {
		cfg.Hosts.Entries = s.HostsEntries
	}
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("设置已保存（relay=%s，hosts 托管=%v）", cfg.Relay, cfg.Hosts.Manage)
	return nil
}

// SetTheme 切换深浅色并记住（同时切换窗口标题栏配色）。
func (b *Backend) SetTheme(mode string) error {
	if mode != "dark" {
		mode = "light"
	}
	b.a.Cfg.UI.Theme = mode
	if mode == "dark" {
		wruntime.WindowSetDarkTheme(b.ctx)
		wruntime.WindowSetBackgroundColour(b.ctx, 0x14, 0x13, 0x12, 0xff)
	} else {
		wruntime.WindowSetLightTheme(b.ctx)
		wruntime.WindowSetBackgroundColour(b.ctx, 0xff, 0xff, 0xff, 0xff)
	}
	return b.a.Cfg.Save()
}

// SetAutostart 开关开机自启（立即生效，不等"保存"）。
func (b *Backend) SetAutostart(on bool) error {
	var err error
	if on {
		err = autostart.Enable()
	} else {
		err = autostart.Disable()
	}
	if err != nil {
		return err
	}
	b.refreshAutostart()
	if on {
		b.a.Bus.Info("已设置开机自启（计划任务 %s，最高权限，登录后静默启动）", autostart.TaskName)
	} else {
		b.a.Bus.Info("已取消开机自启")
	}
	return nil
}

// ───────────────────────── hosts ─────────────────────────

// ApplyHosts 立即把编辑框里的条目写进 hosts（同时打开托管开关）。
func (b *Backend) ApplyHosts(entries []string) error {
	clean := make([]string, 0, len(entries))
	for _, e := range entries {
		if s := strings.TrimSpace(e); s != "" && !strings.HasPrefix(s, "#") {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return fmt.Errorf("条目是空的，没什么可写的")
	}
	if err := hostsmgr.Apply(clean); err != nil {
		return err
	}
	b.a.Cfg.Hosts.Entries = clean
	b.a.Cfg.Hosts.Manage = true
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("hosts 已写入 %d 条内网域名映射", len(clean))
	return nil
}

// RemoveHosts 从 hosts 移除我们的标记区块。
func (b *Backend) RemoveHosts() error {
	if err := hostsmgr.Remove(); err != nil {
		return err
	}
	b.a.Cfg.Hosts.Manage = false
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("已从 hosts 移除本程序的标记区块")
	return nil
}

// ───────────────────────── 链路自检 ─────────────────────────

// SelfTest 对每条链做端到端探测：本地 socks5 通不通 + 经它能不能真连到内网目标。
// 走 gost 的本地监听，不经过 WinDivert，所以它单独验证"链路"这一段。
func (b *Backend) SelfTest() {
	chains := append([]config.Chain(nil), b.a.Cfg.Chains...)
	_ = b.a.Cfg.Routes // 探针目标改为从 hosts 取真实主机 IP，不再用规则网段
	if len(chains) == 0 {
		b.emit("notify", NotifyView{Title: "无法自检", Text: "还没有配置任何链", Kind: "warn"})
		return
	}

	go func() {
		b.a.Bus.Info("=== 链路自检开始（%d 条链）===", len(chains))
		bad := 0
		for _, ch := range chains {
			// 选定该链真实要走的路径：优先原生上游，其次本地 socks5 监听
			var dial func(ip net.IP, port uint16) (net.Conn, error)
			desc := ""
			if fwd := strings.TrimSpace(ch.Forward); fwd != "" {
				up, perr := upstream.Parse(fwd)
				if perr == nil {
					dial = func(ip net.IP, port uint16) (net.Conn, error) {
						return up.Dial(ip, port, 6*time.Second)
					}
					desc = "原生上游 " + up.String()
				} else {
					b.a.Bus.Error("[%s] 上游无法解析，跳过：%v", ch.Name, perr)
					bad++
					continue
				}
			}

			// 探针用真实主机 IP（hosts 里的），不用网段的 .1（那不是真主机）
			ip := probeIPForChain(b.a.Cfg, ch.Name)
			if ip == nil {
				b.a.Bus.Warn("[%s] 找不到可用于探测的真实内网 IP（hosts 条目为空？）", ch.Name)
				continue
			}

			hit := 0
			for _, port := range []uint16{443, 80, 5432, 6446, 5000, 9056} {
				conn, derr := dial(ip, port)
				if derr == nil {
					conn.Close()
					hit = int(port)
					break
				}
			}
			if hit > 0 {
				b.a.Bus.Info("[%s] ✓ 端到端可达：%s → %s:%d", ch.Name, desc, ip, hit)
				b.emit("selftest", ProbeView{Target: ip.String(), Port: hit, OK: true})
			} else {
				b.a.Bus.Error("[%s] ✗ 经该链连不上 %s 的任何常见端口（上游挂了？上游限制了目标？）", ch.Name, ip)
				bad++
				b.emit("selftest", ProbeView{Target: ip.String(), OK: false, Err: "经该链不可达"})
			}
		}
		if bad == 0 {
			b.a.Bus.Info("=== 链路自检通过：%d 条链全部可用 ===", len(chains))
			b.emit("notify", NotifyView{Title: "链路自检通过", Text: fmt.Sprintf("%d 条链全部可用", len(chains)), Kind: "info"})
		} else {
			b.a.Bus.Error("=== 链路自检结束：%d 条链有问题（详见上方日志）===", bad)
			b.emit("notify", NotifyView{Title: "链路自检有问题", Text: fmt.Sprintf("%d 条链不可用，请看日志", bad), Kind: "error"})
		}
	}()
}

func targetIPv4(target string) net.IP {
	if ip, _, err := net.ParseCIDR(target); err == nil {
		return ip.To4()
	}
	if p := net.ParseIP(target); p != nil {
		return p.To4()
	}
	return nil
}

// probeIPForChain 取该链网段内的一个【真实主机 IP】用于探测。
// 不用网段的 .1 —— 那不是真主机，会得到 host unreachable 而误判为“链路不通”。
func probeIPForChain(cfg *config.Config, chainName string) net.IP {
	var nets []*net.IPNet
	for _, rt := range cfg.Routes {
		if rt.Chain != chainName {
			continue
		}
		if _, n, err := net.ParseCIDR(rt.Target); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(rt.Target); ip != nil {
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
		}
	}
	for _, e := range hostsEntriesFrom(cfg) {
		f := strings.Fields(e)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return ip.To4()
			}
		}
	}
	return nil
}

// ───────────────────────── 打开文件/目录 ─────────────────────────

func (b *Backend) OpenConfigFile() { openPath(b.a.Cfg.Path()) }
func (b *Backend) OpenProgramDir() { openPath(dirOf(b.a.Cfg.Path())) }
func (b *Backend) OpenLogDir()     { openPath(dirOf(b.a.Bus.FilePath())) }

func openPath(p string) {
	if p == "" {
		return
	}
	_ = winrun.Command("explorer.exe", p).Start()
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}

// save 落盘 + 记日志（编辑类操作的统一收尾）。
func (b *Backend) save(what string) error {
	if err := b.a.SaveConfig(); err != nil {
		return err
	}
	b.a.Bus.Info("%s（已保存到 config.yaml）", what)
	return nil
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

var _ = runtime.GOOS

// SetTray 由 main 注入托盘（Backend 不自己建，避免依赖倒置）。
func (b *Backend) SetTray(t *Tray) { b.tray = t }

// ShowMainWindow 从托盘/第二实例唤回窗口。
func ShowMainWindow(b *Backend) {
	if b.ctx == nil {
		return
	}
	wruntime.WindowShow(b.ctx)
	wruntime.WindowUnminimise(b.ctx)
}

// ───────────────────────── 导出 / 导入设置 ─────────────────────────

// ExportConfig 把当前配置（链路上游 + 路由规则 + 其它设置）另存为一个 yaml，
// 同事拿到后放在 exe 同目录改名 config.yaml 即可直接用。
//
// ⚠️ 导出内容**包含上游凭据**（forward 里的 auth=），所以：
//   - 界面上的按钮要有明确提示
//   - 日志里不打印导出内容，只打印路径
func (b *Backend) ExportConfig() (string, error) {
	name := "netproxy-config.yaml"
	if p := b.a.Cfg.Path(); p != "" {
		dir := dirOf(p)
		name = filepath.Join(dir, "netproxy-config.yaml")
	}
	path, err := wruntime.SaveFileDialog(b.ctx, wruntime.SaveDialogOptions{
		Title:           "导出设置（含上游凭据，请通过安全渠道分发）",
		DefaultFilename: name,
		Filters: []wruntime.FileFilter{
			{DisplayName: "配置文件 (*.yaml)", Pattern: "*.yaml"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil // 用户取消
	}
	if !strings.HasSuffix(strings.ToLower(path), ".yaml") && !strings.HasSuffix(strings.ToLower(path), ".yml") {
		path += ".yaml"
	}
	if err := b.a.Cfg.SaveAs(path); err != nil {
		return "", err
	}
	b.a.Bus.Info("设置已导出到 %s（含上游凭据，请通过安全渠道分发）", path)
	return path, nil
}

// ExportSummary 导出一份**不含凭据**的纯文本说明：上游（遮蔽后）+ 规则 + 用法。
// 适合贴在群里让人先看懂配置，需要真配置时再单独发 ExportConfig 的产物。
func (b *Backend) ExportSummary() (string, error) {
	name := "netproxy-配置说明.txt"
	path, err := wruntime.SaveFileDialog(b.ctx, wruntime.SaveDialogOptions{
		Title:           "导出配置说明（不含凭据）",
		DefaultFilename: name,
		Filters: []wruntime.FileFilter{
			{DisplayName: "文本文件 (*.txt)", Pattern: "*.txt"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	if !strings.HasSuffix(strings.ToLower(path), ".txt") {
		path += ".txt"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "netproxy 配置说明（不含凭据）\n")
	fmt.Fprintf(&sb, "生成时间：%s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	sb.WriteString("【链路 / 上游】\n")
	for _, c := range b.a.Cfg.Chains {
		fmt.Fprintf(&sb, "  %s\n    上游：%s\n", c.Name, gostbat.Redact(c.Forward))
		if c.Note != "" {
			fmt.Fprintf(&sb, "    说明：%s\n", c.Note)
		}
	}

	sb.WriteString("\n【路由规则】（自上而下匹配，命中即止）\n")
	for i, r := range b.a.Cfg.Routes {
		fmt.Fprintf(&sb, "  %d. %s  →  %s\n", i+1, r.Target, r.Chain)
	}

	sb.WriteString("\n【其它设置】\n")
	fmt.Fprintf(&sb, "  relay：%s\n", b.a.Cfg.Relay)
	fmt.Fprintf(&sb, "  hosts 托管：%v（%d 条映射）\n", b.a.Cfg.Hosts.Manage, len(b.a.Cfg.Hosts.Entries))
	fmt.Fprintf(&sb, "  界面主题：%s\n", b.a.Cfg.UI.Theme)

	sb.WriteString("\n【同事怎么用】\n")
	sb.WriteString("  1. 把 netproxy.exe、WinDivert.dll、WinDivert64.sys、netproxy.ico 和 config.yaml\n")
	sb.WriteString("     放在同一个文件夹里\n")
	sb.WriteString("  2. 双击 netproxy.exe（会弹一次 UAC，因为要加载内核驱动）\n")
	sb.WriteString("  3. 界面会显示「内网 N/N 全部走直连 …… 走向正确」就说明好了\n")
	sb.WriteString("  4. 如需开机自启：界面「设置 → 开机自启」勾上（计划任务 + 最高权限，不弹 UAC）\n")
	sb.WriteString("\n【注意】\n")
	sb.WriteString("  · 本文件不含上游凭据；真正的 config.yaml 含凭据，请通过安全渠道分发\n")
	sb.WriteString("  · 内网域名需要同事本机 hosts 里有映射（或让程序托管：设置 → hosts 接管）\n")
	sb.WriteString("  · Clash 必须让内网走直连：设置 → 与 Clash 共存 会检测并给出要填的绕过地址\n")

	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return "", err
	}
	b.a.Bus.Info("配置说明已导出到 %s", path)
	return path, nil
}
