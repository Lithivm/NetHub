package webui

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"nethub/internal/config"
	"nethub/internal/gostbat"
	"nethub/internal/logbus"
	"nethub/internal/upstream"
)

// ───────────────────────── 导出 / 导入设置 ─────────────────────────

// ExportConfig 把当前配置（链路上游 + 路由规则 + 其它设置）另存为一个 yaml，
// 同事拿到后放在 exe 同目录改名 config.yaml 即可直接用。
//
// ⚠️ 导出内容**包含上游凭据**（forward 里的 auth=），所以：
//   - 界面上的按钮要有明确提示
//   - 日志里不打印导出内容，只打印路径
func (b *Backend) ExportConfig() (string, error) {
	name := "nethub-config.yaml"
	if p := b.a.Cfg.Path(); p != "" {
		dir := dirOf(p)
		name = filepath.Join(dir, "nethub-config.yaml")
	}
	path, err := b.uiOrNoop().SaveFile(wruntime.SaveDialogOptions{
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
	b.a.Bus.Info("设置已导出到 %s（含明文口令，别发到群里/仓库）", path)
	return path, nil
}

// LoopInfo 疑似环路统计（与 Clash 共存那张卡一起显示：最典型的环就是被别的代理绕回来）。
type LoopInfo struct {
	Alerts uint64 `json:"alerts"`
	Last   string `json:"last"`
	At     string `json:"at"`
}

// GetLoopInfo 环路检测结果。
func (b *Backend) GetLoopInfo() LoopInfo {
	if b.a.Engine == nil {
		return LoopInfo{}
	}
	n, last, at := b.a.Engine.LoopAlerts()
	return LoopInfo{Alerts: n, Last: last, At: at}
}

// CountDirectView 直连统计开关（「连接」页上的一个勾）。
type CountDirectView struct {
	On bool `json:"on"`
}

// GetCountDirect 当前是否统计直连流量。
func (b *Backend) GetCountDirect() CountDirectView {
	return CountDirectView{On: b.countDirect()}
}

// countDirect 「也统计直连流量」开关的当前值。
//
// 抽成小方法是因为顶栏流量图也要读它（决定整窗算不算直连那部分，见 traffic.go）。
func (b *Backend) countDirect() bool { return b.a.Cfg.CountDirectEnabled() }

// SetCountDirect 开关直连统计。
//
// 以前这里要重启（过滤器在启动时装配）；现在规则改动是热的（含直连统计开关引起的
// 过滤器变化），所以**不重启** —— 现场不会因为点个开关就把在跑的连接全断掉。
func (b *Backend) SetCountDirect(on bool) error {
	b.a.Cfg.SetCountDirect(on)
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, "直连统计开关")
	if on {
		b.a.Bus.Info("已开启直连流量统计（直连网段会进内核过滤器，每包有一点开销）")
	} else {
		b.a.Bus.Info("已关闭直连流量统计（直连流量不再经过我们，回到零开销）")
	}
	return nil
}

// SetLogLevel 切日志档位（normal | verbose | debug）。
//
// 即时生效、只影响**之后**写的行（日志总线上的一个档位，不碰过滤器也不重启）：
//
//	normal  = 现场面：连接开/关、启停、链与目标状态翻转、错误
//	verbose = + 判定面：每条连接为什么这么走、DNS 请求与应答、名字学习
//	debug   = + 内部面：名字表/假 IP 池维护、内核层开关、过滤器原文
//
// 档位没变就不重复写行（界面上点回当前档位时不该多一行噪声）。
func (b *Backend) SetLogLevel(level string) error {
	lv := logbus.ParseLevel(level)
	old := b.a.Cfg.LocalPrefs()
	changed := lv != b.a.Bus.Level()
	b.a.Cfg.SetLogLevel(lv.String())
	res, err := b.a.SaveConfig()
	if err != nil {
		// 存不下去就把**内存里的档位也退回去**：否则界面显示新档、总线还是旧档，
		// 看起来像“切了但没生效”，重启后又变回旧值 —— 那正是“档位存不住”的观感来源。
		b.a.Cfg.SetLocalPrefs(old)
		return fmt.Errorf("日志档位没改成（配置没存下去，已退回 %s）：%w", old.LogLevel, err)
	}
	b.a.SetLogLevel(lv) // 先落盘再切，保证“界面看到的 = 日志的”；切到 debug 会顺带转储一份当前状态
	b.afterSave(res, "日志档位")
	if changed {
		b.a.Bus.Info("日志: 档位已切到 %s%s", lv, logLevelBlurb(lv))
	}
	return nil
}

// SetLogLevelFile 切**日志文件**的档位（传空串 = 跟随屏幕档）。
//
// 为什么单独一个：屏幕与文件是两个受众 —— 现场看着要清爽（normal），
// 事后把日志发给 agent 时要能看到“为什么”（verbose）。不能分开设就只能二选一。
// 持久化与屏幕档一样走本机偏好（见 config.LocalPrefs）。
func (b *Backend) SetLogLevelFile(level string) error {
	old := b.a.Cfg.LocalPrefs()
	b.a.Cfg.SetLogLevelFile(level)
	res, err := b.a.SaveConfig()
	if err != nil {
		b.a.Cfg.SetLocalPrefs(old) // 存不下去就退回去，别让界面显示一个没保存的值
		return fmt.Errorf("日志文件档位没改成（配置没存下去，已退回）：%w", err)
	}
	b.a.SetLogLevel(logbus.ParseLevel(b.a.Cfg.LogLevel())) // 让文件档立即生效
	b.afterSave(res, "日志文件档位")
	if strings.TrimSpace(level) == "" {
		b.a.Bus.Info("日志文件档位：跟随屏幕档（%s）", b.a.Cfg.LogLevelFile())
	} else {
		b.a.Bus.Info("日志文件档位：%s（屏幕的是 %s）", b.a.Cfg.LogLevelFile(), b.a.Cfg.LogLevel())
	}
	return nil
}

// logLevelBlurb 给档位配一句“这一档多出什么”（Proxifier 的菜单说明那类）。
func logLevelBlurb(lv logbus.Level) string {
	switch lv {
	case logbus.LevelVerbose:
		return " —— 会多出每条连接为什么这么走、DNS 请求与应答、实际走了哪个上游、分段耗时"
	case logbus.LevelDebug:
		return " —— 会多出引擎内部状态与装配细节（过滤器原文、名字表/假 IP 池、内核层）"
	default:
		return " —— 只写现场要看的（连接开/关、启停、状态翻转、错误）"
	}
}

// QuicBlockView QUIC 阻断开关（「连接」页上的一个勾）。
type QuicBlockView struct {
	On bool `json:"on"`
	// Blocked 累计拦下的包数；Recent 最近被拦的目标（最多 5 个，新的在前）
	Blocked uint64   `json:"blocked"`
	Recent  []string `json:"recent"`
}

// GetQuicBlock 当前是否阻断 QUIC（UDP 443）+ 拦了多少、拦了谁。
func (b *Backend) GetQuicBlock() QuicBlockView {
	n, recent := b.a.Engine.QUICStats()
	return QuicBlockView{On: b.a.Cfg.QuicBlockEnabled(), Blocked: n, Recent: recent}
}

// SetQuicBlock 开关 QUIC 阻断（tuning.quic_block_disabled 的反面）。
//
// 它是主过滤器的一部分（UDP 子句），所以和规则改动一样是热的：改完立即生效，
// 不重启、不断已有连接。
func (b *Backend) SetQuicBlock(on bool) error {
	b.a.Cfg.SetQuicBlock(on)
	res, err := b.a.SaveConfig()
	if err != nil {
		return err
	}
	b.afterSave(res, "QUIC 阻断开关")
	if on {
		b.a.Bus.Info("已开启 QUIC 阻断（本该走隧道的 UDP 443 会被拦下并记一行，不再直连漏出）")
	} else {
		b.a.Bus.Info("已关闭 QUIC 阻断（UDP 443 不再经过我们）")
	}
	return nil
}

// udpProbeTarget 探测用的公网 UDP 目标（**不碰客户内网**）：一个公开 DNS。
const udpProbeTarget = "114.114.114.114:53"

// ProbeUDPRelay 探每条链的 UDP 中继能力（只读探测：不改配置、不碰客户内网）。
//
// 为什么要这个按钮：现在被问“你们支持 UDP 吗”，界面只能答一句“不支持”（设计如此）。
// 有了它，答案变成**实测**：“上游接受了 ASSOCIATE，但真实往返没有回包 —— 上游侧大概率
// 没放行 UDP 端口”。上游一改就能点一下复测，不用凭感觉改架构。
//
// 每条链并行，整体耗时 ≈ 单条超时。
func (b *Backend) ProbeUDPRelay() []string {
	chains := b.a.Cfg.ChainsSnapshot()
	if len(chains) == 0 {
		return []string{"还没有配置任何链"}
	}
	dstHost, dstPortStr, _ := net.SplitHostPort(udpProbeTarget)
	dstIP := net.ParseIP(dstHost)
	dstPort, _ := strconv.Atoi(dstPortStr)

	lines := make([]string, len(chains))
	var wg sync.WaitGroup
	for i := range chains {
		ch := chains[i]
		ups := b.a.Cfg.UpstreamsResolved(ch)
		if len(ups) == 0 {
			lines[i] = "链 " + ch.Name + "：没有上游"
			continue
		}
		wg.Add(1)
		go func(i int, name, raw string) {
			defer wg.Done()
			up, err := upstream.Parse(raw)
			if err != nil {
				lines[i] = fmt.Sprintf("链 %s：上游地址看不懂（%v）", name, err)
				return
			}
			r := upstream.ProbeUDP(up, dstIP, uint16(dstPort), 4*time.Second)
			shown := gostbat.Redact(raw)
			if r.Supported {
				lines[i] = fmt.Sprintf("✓ 链 %s（%s）：UDP 中继可用，往返 %s", name, shown, r.RTT.Round(time.Millisecond))
				b.a.Bus.Info("udp.probe: chain=%s supported=true rtt=%s bnd=%s", name, r.RTT.Round(time.Millisecond), r.BND)
				return
			}
			lines[i] = fmt.Sprintf("✗ 链 %s（%s）：%s", name, shown, r.Reason)
			b.a.Bus.Info("udp.probe: chain=%s supported=false reason=%s", name, r.Reason)
		}(i, ch.Name, ups[0])
	}
	wg.Wait()

	head := fmt.Sprintf("本版本不转发 UDP（QUIC 只拦不转）—— 这里只探上游有没有这个能力。目标 %s：", udpProbeTarget)
	return append([]string{head}, lines...)
}

// CaptureView 抓包状态（界面用）。
type CaptureView struct {
	On      bool   `json:"on"`
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	Packets uint64 `json:"packets"`
	Reason  string `json:"reason"`
}

// GetCaptureStatus 抓包状态。
func (b *Backend) GetCaptureStatus() CaptureView {
	if b.a.Engine == nil {
		return CaptureView{}
	}
	on, path, n, pkts, reason := b.a.Engine.CaptureStatus()
	return CaptureView{On: on, Path: path, Bytes: n, Packets: pkts, Reason: reason}
}

// StartCapture 开始抓包（写到程序目录的 pcap/nethub-capture.pcap）。
func (b *Backend) StartCapture() (CaptureView, error) {
	if b.a.Engine == nil {
		return CaptureView{}, fmt.Errorf("引擎未初始化")
	}
	dir := dirOf(b.a.Cfg.Path())
	if err := b.a.Engine.StartCapture(dir, 64); err != nil {
		return CaptureView{}, err
	}
	b.a.Bus.Warn("已开始抓包（写 %s/pcap/nethub-capture.pcap，上限 64MB；抓到的东西含内网数据，别随便外发）", dir)
	return b.GetCaptureStatus(), nil
}

// StopCapture 停止抓包。
func (b *Backend) StopCapture() CaptureView {
	if b.a.Engine != nil {
		if reason := b.a.Engine.StopCapture(); reason != "" {
			b.a.Bus.Info("已停止抓包")
		}
	}
	return b.GetCaptureStatus()
}

// OpenCaptureDir 打开抓包所在目录（方便用 Wireshark 打开）。
func (b *Backend) OpenCaptureDir() error {
	dir := dirOf(b.a.Cfg.Path())
	if dir == "" {
		dir = "."
	}
	openPath(filepath.Join(dir, "pcap"))
	return nil
}

// ───────── 规则重叠检查（用户点按钮才跑）─────────

// OverlapView 一处重叠（给人看的）。
type OverlapView struct {
	Kind        string   `json:"kind"` // dead | shadowed | fine
	Earlier     int      `json:"earlier"`
	Later       int      `json:"later"`
	EarlierName string   `json:"earlierName"`
	LaterName   string   `json:"laterName"`
	Targets     []string `json:"targets"`
	Ports       []string `json:"ports"`
	Resolution  string   `json:"resolution"`
	Action      string   `json:"action"`
	LaterAction string   `json:"laterAction"`
}

// OverlapResult 一次重叠检查的结果。
type OverlapResult struct {
	Rows    []OverlapView `json:"rows"`
	Summary string        `json:"summary"`
}

// CheckOverlaps 检查规则重叠。刻意做成"按钮触发"：重叠不一定错
// （宽兜底 + 窄例外是常见写法），我们只摆事实，不替用户改顺序。
func (b *Backend) CheckOverlaps() OverlapResult {
	ov := b.a.Cfg.CheckOverlaps()
	res := OverlapResult{Rows: make([]OverlapView, 0, len(ov)), Summary: config.OverlapSummary(ov)}
	for _, o := range ov {
		res.Rows = append(res.Rows, OverlapView{
			Kind: o.Kind, Earlier: o.Earlier + 1, Later: o.Later + 1,
			EarlierName: o.EarlierName, LaterName: o.LaterName,
			Targets: o.Targets, Ports: o.Ports, Resolution: o.Resolution,
			Action: o.ActionText, LaterAction: o.LaterAction,
		})
	}
	return res
}

// ───────── 凭据加密开关（A18）─────────

// intPtr 取个指针（给"区分没传与传了 0"的字段用）。
func intPtr(v int) *int { return &v }

// ───────── 关于 ─────────

// Version 版本号（发布构建可用 -ldflags -X 覆盖）。
var Version = "dev"

// AboutView 关于卡的信息。
type AboutView struct {
	Version   string `json:"version"`
	Repo      string `json:"repo"`
	Releases  string `json:"releases"`
	Elevated  bool   `json:"elevated"`
	GoVersion string `json:"goVersion"`
	ConfigDir string `json:"configDir"`
}

const (
	repoURL     = "https://github.com/Lithivm/NetHub"
	releasesURL = "https://github.com/Lithivm/NetHub/releases"
)

// GetAbout 版本与项目地址（界面「关于」卡用）。
func (b *Backend) GetAbout() AboutView {
	return AboutView{
		Version:   Version,
		Repo:      repoURL,
		Releases:  releasesURL,
		Elevated:  isElevated(),
		GoVersion: runtime.Version(),
		ConfigDir: dirOf(b.a.Cfg.Path()),
	}
}

// OpenRepo / OpenReleases 打开浏览器。
func (b *Backend) OpenRepo() { openPath(repoURL) }
