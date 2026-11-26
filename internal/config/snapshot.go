package config

import (
	"fmt"

	"strings"
	"time"
)

// ───────── 快照与受控修改（给引擎/界面用）─────────

// ConfigSnapshot 配置的只读快照（不含锁，可安全传阅）。
//
// Chains/Routes 是新切片：配合写入路径的 copy-on-write，拿到快照后
// 可以任意遍历，不会再与后到的修改竞争。
//
// Config 里含 sync.RWMutex，**不能按值拷 Config**（go vet copylocks）；
// 外部要快照就用这个类型。
func (c *Config) Snapshot() ConfigSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshotLocked()
}

func (c *Config) snapshotLocked() ConfigSnapshot {
	return ConfigSnapshot{
		Relay:  c.Relay,
		Chains: append([]Chain(nil), c.Chains...),
		Routes: append([]Route(nil), c.Routes...),
		Patrol: c.Patrol,
		Tuning: c.Tuning,
		Hosts:  c.Hosts,
		UI:     c.UI,
	}
}

// ConfigSnapshot 配置的只读快照（不含锁）。
type ConfigSnapshot struct {
	Relay  string
	Chains []Chain
	Routes []Route
	Patrol Patrol
	Tuning Tuning
	Hosts  HostsCfg
	UI     UICfg
}

// config 把快照还原成可 marshal 的 *Config（深拷贝切片；mutex 为零值、不使用）。
func (s ConfigSnapshot) config() *Config {
	return &Config{
		Relay:  s.Relay,
		Chains: append([]Chain(nil), s.Chains...),
		Routes: append([]Route(nil), s.Routes...),
		Patrol: s.Patrol,
		Tuning: s.Tuning,
		Hosts:  s.Hosts,
		UI:     s.UI,
	}
}

// RelayAddr relay 地址快照（只读）。
func (c *Config) RelayAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Relay
}

// ChainsSnapshot 链列表快照（新切片）。
func (c *Config) ChainsSnapshot() []Chain {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Chain(nil), c.Chains...)
}

// RoutesSnapshot 规则列表快照（新切片）。
func (c *Config) RoutesSnapshot() []Route {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Route(nil), c.Routes...)
}

// RouteCount 规则条数（快照）。
func (c *Config) RouteCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Routes)
}

// ChainCount 链条数（快照）。
func (c *Config) ChainCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Chains)
}

// ReplaceFrom 用另一份配置整体替换（导入/回滚用）。
//
// 比调用方直接 *c = *cur 安全：后者会连同一把被用过的 mutex 一起拷（copylocks），
// 而且拷贝期间没有任何同步。
func (c *Config) ReplaceFrom(src *Config) {
	s := src.Snapshot()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Relay, c.Chains, c.Routes = s.Relay, s.Chains, s.Routes
	c.Patrol, c.Tuning, c.Hosts, c.UI = s.Patrol, s.Tuning, s.Hosts, s.UI
	if p := src.Path(); p != "" {
		c.path = p
	}
}

// SetPatrol 修改巡检设置。
func (c *Config) SetPatrol(interval string, count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Patrol.Interval = interval
	if count > 0 {
		c.Patrol.Count = count
	}
}

// SetHosts 修改 hosts 托管设置。entries 为 nil 表示不改动条目。
func (c *Config) SetHosts(manage bool, entries []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Hosts.Manage = manage
	if entries != nil {
		c.Hosts.Entries = append([]string(nil), entries...)
	}
}

// HostsCopy hosts 设置的快照。
func (c *Config) HostsCopy() HostsCfg {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Hosts
}

// SetTheme 修改界面主题偏好（存 "system"/"light"/"dark"）。
// 注意这里存的是**偏好**，不是生效值：system 要由界面层读系统设置再解析。
func (c *Config) SetTheme(mode string) {
	if mode != "dark" && mode != "light" {
		mode = "system"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UI.Theme = mode
}

// Theme 界面主题**偏好**快照（system | light | dark）。
func (c *Config) Theme() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.Theme
}

// themeOr 归一化主题字面量：认不出的值回 system（跟随系统在任何机器上都不会错）。
func themeOr(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "dark":
		return "dark"
	case "light":
		return "light"
	default:
		return "system"
	}
}

// TrayTraffic 托盘图标是否显示实时流量图。
func (c *Config) TrayTraffic() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.TrayTraffic
}

// SetTrayTraffic 开启/关掉托盘流量图（下次读取时生效，具体重绘在 Tray.iconLoop 里）。
func (c *Config) SetTrayTraffic(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UI.TrayTraffic = on
}

// TrayTrafficMode 托盘图显示哪个量：total（默认）| up | down。
func (c *Config) TrayTrafficMode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return trayTrafficModeOr(c.UI.TrayTrafficMode)
}

// SetTrayTrafficMode 设置托盘图显示的量；认不出的值落成 total。
func (c *Config) SetTrayTrafficMode(mode string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UI.TrayTrafficMode = trayTrafficModeOr(mode)
}

// trayTrafficModeOr 归一化托盘显示模式。认不出的值回 total ——
// 宁可显示总量，也不要因为一个拼写把图变成空的。
func trayTrafficModeOr(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up", "out", "outgoing":
		return "up"
	case "down", "in", "incoming":
		return "down"
	default:
		return "total"
	}
}

// LogLevel 日志档位的字面量（normal | verbose | debug）。
func (c *Config) LogLevel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return logLevelOr(c.UI.LogLevel, c.UI.LogVerbose)
}

// SetLogLevel 定档（屏幕）。认不出的值一律落成 normal（并且算“明确写了”—— 这是界面/命令的选择）。
// 文件档不跟着动：它有自己的设置（空 = 跟随屏幕，见 SetLogLevelFile）。
func (c *Config) SetLogLevel(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UI.LogLevel = logLevelOr(s, false)
	c.UI.logLevelSeen = true
	c.UI.logLevelDirty = ""
}

// LogLevelFile 日志**文件**档位；没单独设就跟随屏幕档。
func (c *Config) LogLevelFile() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.UI.LogLevelFile == "" {
		return logLevelOr(c.UI.LogLevel, c.UI.LogVerbose)
	}
	return logLevelOr(c.UI.LogLevelFile, false)
}

// SetLogLevelFile 定文件档；传空串 = 跟随屏幕档（写回文件时也就不留这个键）。
func (c *Config) SetLogLevelFile(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(s) == "" {
		c.UI.LogLevelFile = ""
		c.UI.logLevelFileDirty = ""
		return
	}
	c.UI.LogLevelFile = logLevelOr(s, false)
	c.UI.logLevelFileDirty = ""
}

// LogLevelFileSet 日志文件档是不是单独设的（false = 跟随屏幕档）。
func (c *Config) LogLevelFileSet() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.LogLevelFile != ""
}

// LogLevelFileDirty 文件档里那个认不出、已落成 normal 的原始值。
func (c *Config) LogLevelFileDirty() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.logLevelFileDirty
}

// LogLevelExplicit 这份配置里**明确写了**日志档位（而不是“没写、默认 normal”）。
//
// 为什么要区分：档位是本机偏好 —— 文件里压根没这个键时，整份替换（导入/回滚/部署）
// 不该把本机正在用的档位打回 normal；而明确写了 normal 的，就该按 normal 走。
func (c *Config) LogLevelExplicit() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.logLevelSeen
}

// LogLevelDirty 配置里那个认不出、已被落成 normal 的原始值（没有就是空串）。
//
// 留着它是为了启动时 WARN 一行：静默降档的后果是“我明明存了 verbose，一重启就没了”，
// 而真正的原因只是拼写不对。
func (c *Config) LogLevelDirty() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.logLevelDirty
}

// LocalPrefs 本机偏好：描述“这台机器上怎么看”，不是“要派发给谁的配置内容”。
//
// 目前只有日志档位。凡是整份配置被替换的地方（-apply / 导入 / 回滚 / 部署），
// 都要用 KeepLocalPrefsFrom 把旧值搬回来 —— 否则现场每换一次配置，日志档位就被
// 打回 normal，事后回去查“当时为什么不通”时连判定面都没有了。
type LocalPrefs struct {
	LogLevel string
	// LogLevelFile 文件档（空 = 跟随 LogLevel）
	LogLevelFile string
	// Theme 界面主题偏好（system | light | dark）
	Theme string
	// TrayTraffic 托盘图标是否显示实时流量图
	TrayTraffic bool
	// TrayTrafficMode 托盘图显示哪个量（total | up | down）
	TrayTrafficMode string
}

// LocalPrefs 取本机偏好快照。
func (c *Config) LocalPrefs() LocalPrefs {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p := LocalPrefs{
		LogLevel:        logLevelOr(c.UI.LogLevel, c.UI.LogVerbose),
		Theme:           c.UI.Theme,
		TrayTraffic:     c.UI.TrayTraffic,
		TrayTrafficMode: trayTrafficModeOr(c.UI.TrayTrafficMode),
	}
	if c.UI.LogLevelFile != "" {
		p.LogLevelFile = logLevelOr(c.UI.LogLevelFile, false)
	}
	return p
}

// SetLocalPrefs 应用一份本机偏好，返回是否真的改了。
func (c *Config) SetLocalPrefs(p LocalPrefs) bool {
	lv := logLevelOr(p.LogLevel, false)
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := logLevelOr(c.UI.LogLevel, c.UI.LogVerbose) != lv
	c.UI.LogLevel = lv
	c.UI.logLevelSeen = true
	c.UI.logLevelDirty = ""
	// 文件档：空 = 跟随（与“没设过”同一语义）
	file := ""
	if strings.TrimSpace(p.LogLevelFile) != "" {
		file = logLevelOr(p.LogLevelFile, false)
	}
	fileNow := ""
	if c.UI.LogLevelFile != "" {
		fileNow = logLevelOr(c.UI.LogLevelFile, false)
	}
	if fileNow != file {
		c.UI.LogLevelFile = file
		c.UI.logLevelFileDirty = ""
		changed = true
	}
	// 主题、托盘流量图（开关 + 显示内容）同理：它们是“这台机器怎么看”的偏好，
	// 不是要派发给别人的配置内容 —— 换一份配置不该把它们换掉。
	if th := themeOr(p.Theme); th != c.UI.Theme {
		c.UI.Theme = th
		changed = true
	}
	if c.UI.TrayTraffic != p.TrayTraffic {
		c.UI.TrayTraffic = p.TrayTraffic
		changed = true
	}
	if mode := trayTrafficModeOr(p.TrayTrafficMode); mode != c.UI.TrayTrafficMode {
		c.UI.TrayTrafficMode = mode
		changed = true
	}
	return changed
}

// KeepLocalPrefsFrom 把 old 的本机偏好搬到 c 身上（old 为 nil 时什么都不做）。
// 返回是否改了 —— 调用方据此决定要不要重写文件、要不要打一行说明。
func (c *Config) KeepLocalPrefsFrom(old *Config) bool {
	if old == nil {
		return false
	}
	return c.SetLocalPrefs(old.LocalPrefs())
}

// logLevelOr 归一化档位字面量，并把旧的 log_verbose: true 折成 verbose。
func logLevelOr(s string, legacyVerbose bool) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "verbose":
		return "verbose"
	case "debug":
		return "debug"
	case "normal":
		return "normal"
	}
	if legacyVerbose {
		return "verbose" // 旧配置迁移：以前只有“详细开/关”两种，开着就是 verbose
	}
	return "normal"
}

// AutostartDelayDur 开机自启的登录后延迟（默认 20s；"0s" = 不延迟；上限 10 分钟）。
//
// 刻意不用 clampDur：它把 "0s" 当非法值回落到默认，而这里 0 是合法取值
// （用户就是要"登录后立刻启动"）。
func (c *Config) AutostartDelayDur() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.autostartDelayLocked()
}

func (c *Config) autostartDelayLocked() time.Duration {
	s := strings.TrimSpace(c.AutostartDelay)
	if s == "" {
		return defaultAutostartDelay
	}
	d, err := time.ParseDuration(strings.ToLower(s))
	if err != nil || d < 0 {
		return defaultAutostartDelay
	}
	if d > 10*time.Minute {
		d = 10 * time.Minute
	}
	return d
}

// SetAutostartDelay 设置开机自启延迟（负数按 0 处理）。
func (c *Config) SetAutostartDelay(d time.Duration) {
	if d < 0 {
		d = 0
	}
	if d > 10*time.Minute {
		d = 10 * time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AutostartDelay = d.String()
}

// SetCountDirect 切换“统计直连流量”。
func (c *Config) SetCountDirect(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Tuning.CountDirect = on
}

// SetQuicBlock 开关 QUIC（UDP 443）阻断（on = 拦下来）。
func (c *Config) SetQuicBlock(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Tuning.QuicBlockDisabled = !on
}

// UpdateTuning 在锁下修改 Tuning（界面保存拨号调优用）。
func (c *Config) UpdateTuning(fn func(*Tuning)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.Tuning)
}

// SetRouteEnabled 启用/停用第 i 条规则（COW）。
func (c *Config) SetRouteEnabled(i int, on bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.Routes) {
		return fmt.Errorf("规则下标越界")
	}
	routes := append([]Route(nil), c.Routes...)
	routes[i].SetEnabled(on)
	c.Routes = routes
	return nil
}

// RouteAt 取第 i 条规则的副本。
func (c *Config) RouteAt(i int) (Route, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if i < 0 || i >= len(c.Routes) {
		return Route{}, false
	}
	return c.Routes[i], true
}

// ChainAt 取第 i 条链的副本。
func (c *Config) ChainAt(i int) (Chain, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if i < 0 || i >= len(c.Chains) {
		return Chain{}, false
	}
	return c.Chains[i], true
}
