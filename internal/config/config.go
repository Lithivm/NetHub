// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"
	"net"

	"nethub/internal/dnsmap"
	"nethub/internal/netx"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"nethub/internal/upstream"
)

// Chain 一条隧道链 = 一个或多个上游代理（可故障转移/负载均衡）。
//
// 没有本地监听字段：上游是原生实现的，不需要本地 gost，也不需要 socks5 中转。
//
// Forward 是单上游的老写法（继续支持）；Forwards 是多上游。载入时两者归一到
// Upstreams()，保存时单个写回 forward:、多个写 forwards:，让文件保持好读。
type Chain struct {
	Name     string   `yaml:"name"`
	Forward  string   `yaml:"forward,omitempty"`  // 上游代理 URL（单上游，老写法）
	Forwards []string `yaml:"forwards,omitempty"` // 多个上游：按策略挑一个用，坏了自动换
	Strategy string   `yaml:"strategy,omitempty"` // failover(默认) | round | random
	Probe    string   `yaml:"probe,omitempty"`    // 健康探测间隔（30s / 1m / off），默认 30s
	Note     string   `yaml:"note,omitempty"`

	// Secret 口令在 secrets.dat（DPAPI 加密）里的名字（A18）。
	// 有它时 forward 里不含凭据，运行时由 UpstreamsResolved 还原。
	Secret string `yaml:"secret,omitempty"`
}

// 上游选择策略。
const (
	StrategyFailover = "failover" // 按顺序试，第一个能用的就用（默认）
	StrategyRound    = "round"    // 轮询（负载均衡）
	StrategyRandom   = "random"   // 随机
	// StrategyHash 按「粘性键」（一般是客户端 IP）一致性哈希选上游：
	// 同一台机器固定从同一条上游出去（对方按来源 IP 做白名单/会话时才有意义）。
	StrategyHash = "hash"
)

// Upstreams 这条链的上游列表（Forward 与 Forwards 合并后的结果）。
func (ch Chain) Upstreams() []string {
	if len(ch.Forwards) > 0 {
		return ch.Forwards
	}
	if strings.TrimSpace(ch.Forward) != "" {
		return []string{ch.Forward}
	}
	return nil
}

// SetUpstreams 用给定上游整体替换这条链的上游列表。
//
// 必须同时清掉 Forwards —— Upstreams() 优先返回 Forwards，只写 Forward 的话
// 会被旧值盖住（“从 .bat 导入”曾经就是这样：界面报“已更新”，实际什么都没变）。
func (ch *Chain) SetUpstreams(list []string) {
	ch.Forward, ch.Forwards = "", nil
	switch len(list) {
	case 0:
		return
	case 1:
		ch.Forward = list[0]
	default:
		ch.Forwards = append([]string(nil), list...)
	}
}

// StrategyName 归一化后的策略名（默认 failover）。
func (ch Chain) StrategyName() string {
	switch strings.ToLower(strings.TrimSpace(ch.Strategy)) {
	case StrategyRound:
		return StrategyRound
	case StrategyRandom:
		return StrategyRandom
	case StrategyHash:
		return StrategyHash
	default:
		return StrategyFailover
	}
}

// ProbeInterval 健康探测间隔；0 = 关闭探测。默认 30 秒。
func (ch Chain) ProbeInterval() time.Duration {
	s := strings.ToLower(strings.TrimSpace(ch.Probe))
	switch s {
	case "off", "none", "0":
		return 0
	case "":
		return 30 * time.Second
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 30 * time.Second
}

// normalize 归一化链：forward → forwards、去空白/去重、策略合法化。
// 返回是否改动过（调用方据此决定要不要写回文件）。
func (ch *Chain) normalize() (changed bool, err error) {
	if n := strings.TrimSpace(ch.Name); n != ch.Name {
		ch.Name, changed = n, true
	}
	if ch.Forward != strings.TrimSpace(ch.Forward) {
		ch.Forward, changed = strings.TrimSpace(ch.Forward), true
	}
	if len(ch.Forwards) == 0 && ch.Forward != "" {
		ch.Forwards = []string{ch.Forward}
		changed = true
	}
	if len(ch.Forwards) > 0 {
		out := make([]string, 0, len(ch.Forwards))
		seen := map[string]bool{}
		for _, f := range ch.Forwards {
			t := strings.TrimSpace(f)
			if t == "" || seen[t] {
				changed = true
				continue
			}
			seen[t] = true
			if t != f {
				changed = true
			}
			out = append(out, t)
		}
		if len(out) != len(ch.Forwards) {
			changed = true
		}
		ch.Forwards = out
	}
	if s := strings.TrimSpace(ch.Strategy); s != ch.Strategy {
		ch.Strategy, changed = s, true
	}
	if ch.Strategy != "" && ch.StrategyName() != strings.ToLower(ch.Strategy) {
		return changed, fmt.Errorf("策略 %q 不认识（可选 failover / round / random）", ch.Strategy)
	}
	if ch.Strategy != strings.ToLower(ch.Strategy) {
		ch.Strategy, changed = strings.ToLower(ch.Strategy), true
	}
	return changed, nil
}

// MarshalYAML 让配置文件保持好读：单个上游写 forward:，多个写 forwards:。
func (ch Chain) MarshalYAML() (any, error) {
	type plain Chain // 防止递归调用自己
	out := plain(ch)
	if len(ch.Forwards) == 1 {
		out.Forward = ch.Forwards[0]
		out.Forwards = nil
	} else if len(ch.Forwards) > 1 {
		out.Forward = ""
	}
	return out, nil
}

// DirectChain / BlockChain 是保留链名：规则指向它们 = 一个直接的动作，而不是一条链。
//
//	direct —— 直连（不进隧道）
//	block  —— 阻断（丢弃，并尽力回一个 RST 让应用立刻失败）
//
// 典型用途：direct 留给本机网段、局域网邻居（打印机/共享盘，送进隧道反而不可达）；
// block 用来硬阻断某些地址（不该访问的后台上报、扫描源等）。
const (
	DirectChain = "direct"
	BlockChain  = "block"
)

// Route 一条路由规则 —— 形状对齐 Proxifier 的 Proxification Rule：
// **一个动作挂一组目标**。判定维度是目标 IP/CIDR + 端口（见 internal/rules），
// 所以这里没有 Proxifier 的 Applications。
//
// 动作有三种：走某条链（chain = 链名）、直连、阻断（见上面两个保留名）。
// 规则自上而下匹配、命中即停；一条规则内**任一**目标命中即算该规则命中。
//
// Ports 是规则级条件（对齐 Proxifier）：留空 = 任意端口；填了就要求
// “目标命中 **且** 端口命中”。想“排除某端口”，就把它写成前面一条直连规则的
// ports（例外在前、通例在后，与目标维度同一套心法）。
type Route struct {
	Name    string   `yaml:"name,omitempty"`  // 规则名，可留空
	Targets []string `yaml:"targets"`         // 目标 IP/CIDR，可多个
	Ports   []string `yaml:"ports,omitempty"` // 端口/区间，可多个；留空 = 任意端口
	Chain   string   `yaml:"chain"`           // 动作：走哪条链，或 direct / block

	// Enabled 规则开关（缺省 = 启用，兼容老配置）。
	// 为什么要它：一台机器上常常堆着十几个内网环境的规则（不同客户、不同网段），
	// 但同时只应有少数几条生效 —— 停用的规则**不进过滤器也不进匹配**，
	// 于是既不会互相冲突，也不会白白把包拉进用户态（零开销，不是“匹配到再忽略”）。
	// 用指针：区分"没写"（= 启用）与"写了 false"（= 停用）。
	Enabled *bool `yaml:"enabled,omitempty"`

	// LocalNets 仅当本机的网卡地址落在这些网段里时，这条规则才生效（A16）。
	// 空 = 总是生效。用于“公司网走隧道、家里直连”这类场景，不用手动改配置。
	LocalNets []string `yaml:"local_nets,omitempty"`

	// Apps 进程条件（A20，可选），写成进程名，支持 * 通配：chrome.exe / *.exe / *weixin*。
	// 与 Targets 是 AND：只填 Apps 时，该进程的所有 TCP 连接都算命中（此时会拦全部流量）。
	// 定位：只用来写“例外”（某程序必须走 / 绝不许走隧道），主用法仍是按目标。
	Apps []string `yaml:"apps,omitempty"`

	// Target 是 v1 的旧写法（一条规则一个目标），只为读老 config.yaml 保留：
	// 载入时由 Normalize 并进 Targets，保存时不再写出。
	Target string `yaml:"target,omitempty"`

	// AllowQUIC 这条规则的目标**不拦 QUIC**（它的 UDP 443 正常直连出去）。
	//
	// 默认（不写）跟着全局 QUIC 阻断走：本该走链 / 阻断的目标，它们的 UDP 443 会被拦下
	// 并记一行 quic.block —— 因为 UDP 不走隧道，不拦就等于绕过隧道直连漏出。
	// 但现场也可能真有“只认 HTTP/3”的系统，拦它就是打断业务；那时把这一条勾上，
	// 只放它的 QUIC 直连（同目标的 TCP 那条路仍按规则走链）。
	//
	// 实现上**不进 UDP 侧的过滤器区间** —— 这些目标的 UDP 443 在驱动层就被放行，
	// 一个包也不用收回用户态（零开销，而不是“收上来再放回去”）。
	AllowQUIC bool `yaml:"allow_quic,omitempty"`
}

// IsDirect 这条规则的动作是不是直连（不走代理）。
func (r Route) IsDirect() bool { return r.Chain == DirectChain }

// IsEnabled 规则是否生效（没写 Enabled = 启用）。
func (r Route) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// SetEnabled 改开关（nil 指针 → 明确写成 true/false，保证存盘后状态确定）。
func (r *Route) SetEnabled(on bool) { v := on; r.Enabled = &v }

// IsBlock 这条规则的动作是不是阻断（丢弃）。
func (r Route) IsBlock() bool { return r.Chain == BlockChain }

// AllowsQUIC 这条规则明确放行 QUIC（UDP 443 直连，不拦不记）。
func (r Route) AllowsQUIC() bool { return r.AllowQUIC }

// NeedsChain 这条规则需不需要引用真实的链（direct / block 不需要）。
func (r Route) NeedsChain() bool { return !r.IsDirect() && !r.IsBlock() }

// ActionText 动作的人话描述（日志/界面用）。
func (r Route) ActionText() string {
	switch {
	case r.IsDirect():
		return "直连（不走代理）"
	case r.IsBlock():
		return "阻断"
	default:
		return "链 " + r.Chain
	}
}

// ActionChains 界面下拉里“不是链的动作”：配置写法 → 显示名。
var ActionChains = []struct {
	Value string
	Label string
}{
	{DirectChain, "直连（不走代理）"},
	{BlockChain, "阻断（丢弃）"},
}

// Label 一行式描述（日志、导出说明用）：带名字就带上，目标用逗号隔开。
func (r Route) Label() string {
	ts := strings.Join(r.Targets, ", ")
	if len(r.Ports) > 0 {
		ts += "  端口 " + strings.Join(r.Ports, ",")
	}
	if n := strings.TrimSpace(r.Name); n != "" {
		return n + "：" + ts
	}
	return ts
}

// Describe 给报错指代用："「规则名」"或"（前两个目标 …）"。
func (r Route) Describe() string {
	if n := strings.TrimSpace(r.Name); n != "" {
		return "「" + n + "」"
	}
	if len(r.Targets) == 0 {
		if len(r.Apps) > 0 {
			return "（进程 " + strings.Join(r.Apps, " ") + "）"
		}
		return "（无目标）"
	}
	ts := r.Targets
	if len(ts) > 2 {
		ts = append(append([]string{}, ts[:2]...), "…")
	}
	return "（" + strings.Join(ts, " ") + "）"
}

// HostsCfg 系统 hosts 标记区块的内容。
type HostsCfg struct {
	Manage  bool     `yaml:"manage"`  // 是否由我们维护这段 hosts
	Entries []string `yaml:"entries"` // 每行是一条 "IP 域名"
}

// UICfg 界面相关设置。
type UICfg struct {
	Theme string `yaml:"theme"` // system | light | dark

	// TrayTraffic 托盘图标是否显示实时流量（迷你柱图）。
	//
	// 默认**关** = 用 nethub.ico 那个默认图标：换图标这件事不替用户做主
	// （托盘是系统级外观，有人就想要品牌图标）。开了才每秒重绘一张。
	TrayTraffic bool `yaml:"tray_traffic,omitempty"`
	// TrayTrafficMode 托盘图显示哪个量：total（上行+下行，默认）| up | down。
	//
	// 为什么做成三选：小图标里同时画两个方向必然有一方被压扁（面积方案尤其明显），
	// 而现场有时只关心"是不是在回传影像"（up）或"是不是在拉资料"（down）。
	TrayTrafficMode string `yaml:"tray_traffic_mode,omitempty"`

	// LogLevel 日志档位：normal（默认）| verbose | debug。
	//
	// 三档的语义、每档装什么，见 logbus.Level 的注释（照抄 Proxifier 的
	// Normal / Verbose / Debug 定义）。写空 = normal。
	//
	// 旧字段（v0.5.x）：log_verbose bool。下面还留着读取兼容，读到 true
	// 就在 normalize 里折成 verbose，写回时就不再出现。
	//
	// **不带 omitempty**：这是本机偏好，必须每次都写进文件。带了 omitempty 时
	// “默认 normal”的配置里根本没有这个键，于是谁也分不清“用户选了 normal”与
	// “这份配置没提到档位”（比如导入/回滚/部署一份别人的配置）—— 而后者应当
	// 保住本机现有档位（见 LocalPrefs）。
	LogLevel   string `yaml:"log_level"`
	LogVerbose bool   `yaml:"log_verbose,omitempty"` // 已弃用，只读

	// LogLevelFile 日志**文件**的档位（光标照 Proxifier 的 Screen Log / File Log 分开设）。
	//
	// 空 = 跟随屏幕档（旧配置与“一个档位就够”的人不用管它）。
	// 典型用法：屏幕 normal（现场看着清爽）+ 文件 verbose（出事回去查有判定面）。
	LogLevelFile string `yaml:"log_level_file,omitempty"`

	// logLevelSeen 这份配置里**明确写了** log_level（不落盘，只在内存里用）。
	logLevelSeen bool
	// logLevelDirty 配置里那个认不出、已被落成 normal 的原始值（不落盘）。
	// 启动时 WARN 一行用 —— 静默降档会让人以为“档位存不住”。
	logLevelDirty     string
	logLevelFileDirty string
}

// defaultAutostartDelay 开机自启的默认登录后延迟。
//
// 20 秒是现场试出来的：开机瞬间网络（VPN/其它代理）与其它自启程序还没就绪，
// 抢跑会让首次拦截不可用；20 秒足够所有开机项安定下来。
const defaultAutostartDelay = 20 * time.Second

// Config 顶层配置。
type Config struct {
	// mu 保护下面所有可变字段（Chains/Routes/Patrol/Tuning/Hosts/UI/Relay）。
	//
	// 背景：引擎在后台 goroutine 里持续读配置（探活 5s、拨号、巡检），
	// 而界面线程会改配置（增删规则/链、保存、导入/回滚），两边以前没有任何同步 ——
	// 轻则读到半新半旧的值（拨号到垃圾地址），重则 *cfg = *cur 整块替换时越界崩溃。
	//
	// 约定：**公共方法内部加锁**；*Locked 后缀的内部方法假定调用方已持锁，不再加锁
	//（否则会重入死锁 —— sync.RWMutex 不可重入）。
	mu sync.RWMutex

	Relay  string   `yaml:"relay"` // relay 监听地址，端口写 0 表示自动分配
	Chains []Chain  `yaml:"chains"`
	Routes []Route  `yaml:"routes"`
	Patrol Patrol   `yaml:"patrol,omitempty"` // 业务目标巡检（间隔/每轮数量）
	Tuning Tuning   `yaml:"tuning,omitempty"` // 网络调优（上游拨号超时/总预算）
	Hosts  HostsCfg `yaml:"hosts"`
	UI     UICfg    `yaml:"ui"`

	// AutostartDelay 开机自启（计划任务）在登录后的延迟，如 "20s"；空 = 默认 20s。
	// 现场要能调它：开机瞬间网络与其它自启程序还没就绪，抢跑会导致首次拦截不可用。
	AutostartDelay string `yaml:"autostart_delay,omitempty"`

	path string
}

// Path 返回配置文件路径。
func (c *Config) Path() string { return c.path }

// Default 返回一份内置默认配置（首次运行且没有现成 config.yaml 时写出来给用户改）。
//
// 刻意地"什么都不预设"：链名是示例、forward 留空、不预置任何网段。
// 默认配置绝不指向任何真实环境 —— 否则新机器一启动就会去接管别人的网段。
//
// 只用**一条**示例链（不是两条）：保存配置时要过校验，两条空链会让人
// "只填了一条却存不下去"，而界面里完全可以再加。
func Default() *Config {
	return &Config{
		Relay: "127.0.0.1:0",
		Chains: []Chain{
			{Name: "proxy-a", Note: "示例链路 —— 把 forward 换成你自己的上游"},
		},
		Routes: nil,
		// 默认关掉两个“会動别人东西 / 会发多余流量”的开关：
		//   hosts 接管 —— 会改系统 hosts（那是别人也在改的文件）
		//   巡检 —— 会定期向业务目标发真实连接
		// 两者都在设置里一键可开，默认值不替用户做主。
		Patrol: Patrol{Interval: "off"},
		Hosts:  HostsCfg{Manage: false},
		// 默认跟随系统：Windows 自己管深/浅色，用户在那里改一次比在我们这里改一次更自然。
		// 日志档位显式写 normal：不带 omitempty 后它总会落盘，默认配置里就该看得见这一项，
		// 现场打开 config.yaml 才知道“这个开关存在”。
		UI: UICfg{Theme: "system", LogLevel: "normal", logLevelSeen: true},
	}
}

// Load 读配置；文件不存在则写一份默认的并返回。
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		c := Default()
		c.path = path
		if e := c.Save(); e != nil {
			return nil, fmt.Errorf("写默认配置失败: %w", e)
		}
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	c.path = path
	if c.Relay == "" {
		c.Relay = "127.0.0.1:0"
	}
	// 非法值一律回 "system"（默认值）——"跟随系统"在任何机器上都不会错，
	// 而错认成 light/dark 会在与系统相反的机器上“一装上就刺眼”。
	if c.UI.Theme != "dark" && c.UI.Theme != "light" {
		c.UI.Theme = "system"
	}
	if _, err := c.Normalize(); err != nil { // 旧写法/手写配置也安全进来		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadExisting 读一份**已经存在**的配置文件；文件不在就直接报错，
// 绝不凭空造一份默认的。
//
// 为什么必须单独有这个入口（2026-10-14 实测的丢配置事故）：
// `-apply -apply-force <file>` 在 Go 的 flag 里会被解析成 `-apply="-apply-force"`
// （字符串 flag 会把下一个参数整个吃掉）—— 那个路径不存在 → Load 静静地造一份
// 默认配置并返回 → cmdApply 校验、把这份“默认”**写进了真正的目标配置**：
// 用户的 5 条链 / 7 条规则被打成 1 条示例链 proxy-a、0 条规则。
// 凡是“路径来自命令行参数”的入口（-apply / -check / -status）一律走这里。
func LoadExisting(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("配置文件不存在：%s\n"+
				"（路径打错了吗？本命令不会新建配置；顺带一提：选项要写全，"+
				"如 `-apply <文件>`，写成 `-apply -apply-force <文件>` 会被当成路径）", path)
		}
		return nil, err
	}
	return Load(path)
}

// Normalize 就地整理全部规则，让 v1/手写配置也符合 Proxifier 形状：
// v1 的 `target:` 并进 `targets:`、目标归一化成 CIDR、组内去重、清掉两侧空白。
// 返回是否改动过（调用方据此决定要不要写回文件）。
func (c *Config) Normalize() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.normalizeLocked()
}

func (c *Config) normalizeLocked() (bool, error) {
	// copy-on-write：读方可能正持旧切片遍历，归一化不能在原切片上就地改
	chains := append([]Chain(nil), c.Chains...)
	routes := append([]Route(nil), c.Routes...)
	changed := false
	for i := range chains {
		ch, err := chains[i].normalize()
		if err != nil {
			return changed, fmt.Errorf("第 %d 条链 %s: %v", i+1, chains[i].Name, err)
		}
		changed = changed || ch
	}
	for i := range routes {
		ch, _, err := routes[i].normalize()
		if err != nil {
			return changed, fmt.Errorf("第 %d 条规则: %v", i+1, err)
		}
		changed = changed || ch
	}
	// 日志档位：认不出的值落成 normal；旧的 log_verbose: true 折成 verbose 后清掉。
	//
	// 顺带记两件**不落盘**的事（见 UICfg.logLevelSeen / logLevelDirty）：
	//   · 这个档位是不是配置里明确写的 → 决定整份替换要不要保住本机档位；
	//   · 原来是哪个认不出的值 → 启动时 WARN，别让它静默变成 normal。
	if c.UI.LogLevel == "" && c.UI.LogVerbose {
		c.UI.LogLevel = "verbose"
	}
	if c.UI.LogVerbose {
		c.UI.LogVerbose = false
		changed = true
	}
	if c.UI.LogLevel != "" {
		c.UI.logLevelSeen = true
		if lv := logLevelOr(c.UI.LogLevel, false); lv != c.UI.LogLevel {
			c.UI.logLevelDirty = c.UI.LogLevel
			c.UI.LogLevel = lv
			changed = true
		}
	}
	// 文件档：空 = 跟随屏幕档（不落盘也就不会把“跟随”变成固定值）
	if c.UI.LogLevelFile != "" {
		if lv := logLevelOr(c.UI.LogLevelFile, false); lv != c.UI.LogLevelFile {
			c.UI.logLevelFileDirty = c.UI.LogLevelFile
			c.UI.LogLevelFile = lv
			changed = true
		}
	}
	if changed {
		c.Chains, c.Routes = chains, routes
	}
	return changed, nil
}

// Save 原子写回配置文件。
// Save 落盘。
//
// 刻意**不加密**上游口令（与 gost 的启动脚本一样是明文）：
//
//	· 要防的是“配置被误传/推到 GitHub” —— 那靠 .gitignore 与人工注意，不靠加密；
//	· 加密带来的是一整套麻烦（换机器解不开、导出要还原、编辑时看不到口令、
//	  还多一个 secrets.dat 要管），而这些麻烦在真实现场都是实打实的成本。
//
// 历史遗留：早先版本用 DPAPI 存过（配置里是 `secret: xxx` 引用），
// 那些配置仍然读得出来（见 UpstreamsResolved），下一次保存就会自动变成明文。
func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("配置路径未设置")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeToLocked(c.path)
}

// writeToLocked 落盘（调用方已持写锁）。
func (c *Config) writeToLocked(path string) error {
	c.flattenSecretsLocked() // 老配置里的 secret: 引用在这里摊平成明文（只做一次，之后就没引用了）
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	header := "# NetHub 配置 —— 由程序读写，手工改也生效\n"
	header += "# ⚠ 下面 forward 里是上游明文口令（和 gost 脚本一样）。不要把本文件提交进 git、不要贴到群里。\n"
	// 覆盖前先备份一份（backups/ 目录，只留最新 3 份），改坏了能回滚
	if err := c.backupLocked(); err != nil {
		return fmt.Errorf("备份旧配置失败: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate 结构校验：链名唯一、路由引用的链存在、地址格式合法。
func (c *Config) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validateLocked()
}

func (c *Config) validateLocked() error {
	if len(c.Chains) == 0 {
		return fmt.Errorf("至少要配置一条链")
	}
	seen := map[string]bool{}
	for i, ch := range c.Chains {
		if strings.TrimSpace(ch.Name) == "" {
			return fmt.Errorf("第 %d 条链: name 不能为空", i+1)
		}
		if seen[ch.Name] {
			return fmt.Errorf("链名重复: %s", ch.Name)
		}
		if ch.Name == DirectChain || ch.Name == BlockChain {
			return fmt.Errorf("链名 %q 是保留名（direct=直连、block=阻断，是动作不是链），请换一个", ch.Name)
		}
		seen[ch.Name] = true
		ups := ch.Upstreams()
		if len(ups) == 0 {
			return fmt.Errorf("链 %s: 至少填一个上游（forward 或 forwards）", ch.Name)
		}
		for _, f := range ups {
			if _, err := upstream.Parse(f); err != nil {
				return fmt.Errorf("链 %s 的上游无法实现: %v", ch.Name, err)
			}
		}
	}
	for i, r := range c.Routes {
		// 停用的规则：只查“写法对不对”，不查链是否存在。
		//
		// 这里**不再**拦“引用了不存在的链”—— 引擎遇到这种情况是优雅处理的：
		// 每条连接打一行 `链 X 不存在，丢弃 ip:port`，服务照常跑。
		// 少一条保存时的拦截，就少一个“明明只是先写规则、链稍后建”的死角。
		if len(r.Targets) == 0 && len(r.Apps) == 0 {
			return fmt.Errorf("第 %d 条规则%s: 至少要有一个目标（或一个进程条件）", i+1, r.Describe())
		}
		for _, a := range r.Apps {
			if strings.TrimSpace(a) == "" {
				return fmt.Errorf("第 %d 条规则%s: 进程条件里有空白项", i+1, r.Describe())
			}
		}
		for _, t := range r.Targets {
			if _, err := NormalizeTargetExpr(t); err != nil {
				return fmt.Errorf("第 %d 条规则%s: 目标 %q 不是合法 IP 或 CIDR（%v）", i+1, r.Describe(), t, err)
			}
		}
		for _, p := range r.Ports {
			if _, err := NormalizePort(p); err != nil {
				return fmt.Errorf("第 %d 条规则%s: 端口 %q 不合法（%v）", i+1, r.Describe(), p, err)
			}
		}
		// 下面两项 rules.Load 会报错，但以前 Validate 不查 —— 于是界面能把这种规则
		// 存进 config.yaml，之后启动引擎直接起不来。校验集合必须和 rules.Load 对齐。
		if r.IsEnabled() && strings.TrimSpace(r.Chain) == "" {
			return fmt.Errorf("第 %d 条规则%s: 必须选一个动作（链 / 直连 / 阻断）", i+1, r.Describe())
		}
		for _, ln := range r.LocalNets {
			if err := validLocalNet(ln); err != nil {
				return fmt.Errorf("第 %d 条规则%s: 本机网段 %q 不合法（%v）", i+1, r.Describe(), ln, err)
			}
		}
	}
	if err := validListen(c.Relay); err != nil {
		return err
	}
	if iv := strings.TrimSpace(c.Patrol.Interval); iv != "" && !strings.EqualFold(iv, "off") {
		if d, err := time.ParseDuration(iv); err != nil || d <= 0 {
			return fmt.Errorf("patrol.interval 应形如 5m / 30s，或写 off 关闭（当前 %q）", iv)
		}
	}
	return nil
}

// ───────────────────── 链 / 规则的编辑操作（供 GUI 调用）─────────────────────

// NormalizeTarget 把目标写成 CIDR：单 IP → /32，并校验合法性。
// NormalizeTarget 归一化一个规则目标：IP / CIDR / **域名**。
//
// 域名的处理（和 IP 不同）：IP 会被拆成 /32、CIDR 会被规整；而域名**原样保留**——
// 不把域名换成 IP 写进配置：
//
//	· IP 会变（多 A 记录/备用机房），写死的 IP 很快就是错的
//	· 运行时我们同时准备了两条路：本机解析（供匹配）+ 把域名交给上游去解析
//
// 通配域名（*.x.com）会在运行时靠“观察到的 DNS 应答”匹配（见 rules 包与 engine 的 dnsWatch）。
func NormalizeTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("不能为空")
	}
	// IP 区间（10.1.1.1-10.1.1.255）会展开成**多条** CIDR —— 那是列表级的写法，
	// 这个入口只对应"一个写法一个目标"（见 NormalizeTargetExpr）。
	// 报一句能照着改的提示，别甩一句没有信息量的"解析失败"。
	if netx.IsIPRange(s) {
		return "", fmt.Errorf("%q 是 IP 区间 —— 区间展开后是多条网段，请填在规则的目标框里"+
			"（那里支持一次填多个目标）；单个目标请写 CIDR（如 10.1.1.0/24）", s)
	}
	// IP 通配（Proxifier 的写法：198.51.100.* = 一整段）→ 展开成 CIDR
	if strings.HasSuffix(s, ".*") {
		cidr, err := ipWildcardToCIDR(s)
		if err != nil {
			return "", err
		}
		s = cidr
	}
	// 带 * 的都先当通配域名校验（报错最具体：哪个字符不行、为什么不给过），
	// 比后面的 IP 提示更贴切。
	if strings.Contains(s, "*") && isHostname(s) {
		pattern, err := dnsmap.WildcardPattern(s)
		if err != nil {
			return "", err
		}
		// 纯数字+点的写法（如 198.51.100.*）其实是 IP 通配，更推荐用那个：
		// 它会被折成 CIDR、在 IP 层匹配，不依赖任何解析。
		if isAllDigits(strings.ReplaceAll(pattern, "*", "")) {
			return "", fmt.Errorf("%q 看起来是 IP 通配 —— IP 请写 198.51.100.*（整段）或 CIDR；"+
				"域名通配用于主机名（如 *.example.com、db-*.example.com）", s)
		}
		return pattern, nil
	}
	// 剩下 * 且不是域名（如 10.*.100.5）→ 直接说清改写方式，
	// 别拖到最后报一句没有信息量的“解析失败”。
	if strings.Contains(s, "*") && !isHostname(s) {
		return "", fmt.Errorf("这种写法猜不出范围 —— 末尾一段才能用 *（如 198.51.100.*）；" +
			"其他情况请写 CIDR（如 10.100.0.0/16）")
	}
	if !strings.Contains(s, "/") && !isHostname(s) {
		s += "/32"
	} else if isHostname(s) {
		// 统一去掉尾点：名字表（dnsmap）的 key 都是不带尾点的，
		// 否则 "main.example.com." 这条规则会静默地永不匹配（也查不出原因）。
		s = strings.TrimSuffix(strings.ToLower(s), ".")
		if !validHostname(s) {
			return "", fmt.Errorf("不是合法的域名")
		}
		return s, nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("解析失败")
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("只支持 IPv4")
	}
	// 归一化：让 10.0.1.5/24 这类写法变成 10.0.1.0/24
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return "", fmt.Errorf("只支持 IPv4")
	}
	return fmt.Sprintf("%s/%d", n.IP.String(), ones), nil
}

// NormalizeTargetExpr 归一化一个目标写法 —— 它可能对应**多个**目标：IP 区间会展开成一批 CIDR。
//
// 为什么要多这一层：区间是列表级的写法（一条规则的目标框能一次填多条），而配置层的不变量是
// "目标是 CIDR"，所以展开必须发生在**写进配置之前**。其余入口（Validate / 规则归一化 /
// 界面里的多目标输入）统一走这里，就不必各自记得"还有区间这回事"。
func NormalizeTargetExpr(s string) ([]string, error) {
	if netx.IsIPRange(s) {
		return netx.RangeToCIDRs(s)
	}
	n, err := NormalizeTarget(s)
	if err != nil {
		// 形状像区间但写坏了（10.1.1.0-10.1.1.300）：用区间的报错——它会指明是**哪一侧**
		// 不对，比甩一句"解析失败"有用得多。
		// 只在不含字母时走这条：带字母的 main-1.example.com 是**域名**，不能拿区间去报错。
		if hasRangeDash(s) && !strings.ContainsFunc(s, unicode.IsLetter) {
			if _, rerr := netx.RangeToCIDRs(s); rerr != nil {
				return nil, rerr
			}
		}
		return nil, err
	}
	return []string{n}, nil
}

// hasRangeDash 字符串里有横线（三种写法任一）。
func hasRangeDash(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return netx.IsRangeDash(string(r)) })
}

// isHostname 目标写法是不是域名（而不是 IP/CIDR）。
func isHostname(s string) bool {
	if s == "" || strings.Contains(s, "/") || net.ParseIP(s) != nil {
		return false
	}
	return strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// isAllDigits 字符串是否只由数字和点组成（用来看“通配域名后面跟的其实是 IP”）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

// validHostname 粗校域名（不追求 RFC 完备：拦下空格/下划线以外明显不对的写法）。
func validHostname(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
			if r == '-' && (i == 0 || s[i-1] == '.') {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ipWildcardToCIDR 把 198.51.100.* 这种写法展开成整段 CIDR。
//
// 为什么单独支持它：这是 Proxifier 的写法（从它那儿搬过来的规则与工单里到处都是），
// 语义就是“最后一段随便填”= 一整段网段。不展开的话用户会以为我们连“通配”都不支持。
// 只允许**末尾一段**是 *（198.51.100.* ✓）；中间带 * 的（10.*.100.5）猜不出范围，不要猜。
// ipWildcardToCIDR 已挪到 internal/netx（规则包也要用，避免两份实现）。
func ipWildcardToCIDR(s string) (string, error) { return netx.WildcardToCIDR(s) }

// targetSep 判断多目标输入里的分隔符：换行、Tab、空格等所有空白，
// 外加中英文逗号、分号、顿号。用户从工单/表格里粘一串 IP 是最常见的用法。
func targetSep(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case ',', '，', ';', '；', '、':
		return true
	}
	return false
}

// NormalizeTargets 把一次手输/粘贴的多目标文本解析成目标列表，
// 供"一条规则填多个目标"用。分隔符：所有空白 + 中英文逗号/分号/顿号。
//
//	out  归一化后的 CIDR，保持输入顺序，组内去重（IP 区间会展开成多条）
//	dup  被去掉的重复项（归一化形式，供界面如实告知）
//	err  第一个非法目标 —— 整条规则都不落地，不留半生效状态
func NormalizeTargets(raw string) (out, dup []string, err error) {
	seen := map[string]bool{}
	for _, f := range mergeSpacedRanges(strings.FieldsFunc(raw, targetSep)) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if netx.IsRangeDash(f) {
			return nil, nil, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（这是一根单独的横线："+
				"区间要写成 10.1.1.1-10.1.1.255，两端都必须是 IP）", f)
		}
		ns, nerr := NormalizeTargetExpr(f)
		if nerr != nil {
			return nil, nil, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（%v）", f, nerr)
		}
		for _, n := range ns {
			key := strings.ToLower(n)
			if seen[key] {
				dup = append(dup, n)
				continue
			}
			seen[key] = true
			out = append(out, n)
		}
	}
	return out, dup, nil
}

// mergeSpacedRanges 把"被空白拆散的区间"拼回去：
// ["10.1.1.1", "-", "10.1.1.255"] → ["10.1.1.1-10.1.1.255"]。
//
// 为什么要做：区间是从工单/文档里粘过来的，写的人常在横线两边留空格（文档还会把它排成
// en dash）。而多目标输入的**分隔符就是空白** —— 不拼回去，一个区间会被拆成三个目标，
// 报一句让人摸不着头脑的错（"目标 - 不是合法 IP"）。
//
// 只在**两侧都是 IPv4 字面量**时才拼：否则 "a.com - b.com" 这种会被拼成一个怪域名。
func mergeSpacedRanges(fields []string) []string {
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		if netx.IsRangeDash(fields[i]) && len(out) > 0 && i+1 < len(fields) &&
			netx.IsIPv4Literal(out[len(out)-1]) && netx.IsIPv4Literal(fields[i+1]) {
			out[len(out)-1] += "-" + fields[i+1]
			i++
			continue
		}
		out = append(out, fields[i])
	}
	return out
}

// PortText 端口集合的人话描述：空 = 全部端口。
func PortText(ports []string) string {
	if len(ports) == 0 {
		return "全部端口"
	}
	return strings.Join(ports, ",")
}

// NormalizePort 归一化单个端口或端口区间：443 / 8000-9000（也接受 8000~9000）。
// 区间写反了自动换过来；只支持 1-65535。
func NormalizePort(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("不能为空")
	}
	lo, hi, hasSep := s, "", false
	if i := strings.IndexAny(s, "-~"); i >= 0 {
		lo, hi, hasSep = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
	}
	a, err := parsePortNum(lo)
	if err != nil {
		return "", err
	}
	if !hasSep {
		return strconv.Itoa(a), nil
	}
	b, err := parsePortNum(hi)
	if err != nil {
		return "", err
	}
	if a > b {
		a, b = b, a
	}
	if a == b {
		return strconv.Itoa(a), nil
	}
	return fmt.Sprintf("%d-%d", a, b), nil
}

func parsePortNum(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("不是数字")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("端口要在 1-65535")
	}
	return n, nil
}

// NormalizePorts 把一次手输/粘贴的多端口文本解析成端口列表（留空 = nil = 任意端口）。
// 分隔符与目标一致：所有空白 + 中英文逗号/分号/顿号。
func NormalizePorts(raw string) (out, dup []string, err error) {
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, targetSep) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, nerr := NormalizePort(f)
		if nerr != nil {
			return nil, nil, fmt.Errorf("端口 %q 不合法（%v）", f, nerr)
		}
		if seen[n] {
			dup = append(dup, n)
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, dup, nil
}

// portSpan 归一化后的端口区间（供“是否被覆盖”判断用）。
type portSpan struct{ lo, hi int }

func portSpans(ports []string) []portSpan {
	out := make([]portSpan, 0, len(ports))
	for _, p := range ports {
		lo, hi := p, ""
		if i := strings.IndexByte(p, '-'); i >= 0 {
			lo, hi = p[:i], p[i+1:]
		}
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if hi != "" {
			if v, err := strconv.Atoi(hi); err == nil {
				b = v
			}
		}
		out = append(out, portSpan{a, b})
	}
	return out
}

// PortsCover 判断端口集合 a 是否覆盖 b（a 留空 = 任意端口，覆盖一切）。
// 用来判断“这条规则是不是永远不会生效”：目标相同、端口又被上面全覆盖。
func PortsCover(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	as := portSpans(a)
	for _, br := range portSpans(b) {
		covered := false
		for _, ar := range as {
			if ar.lo <= br.lo && br.hi <= ar.hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Patrol 业务目标巡检：只探“最近真的被访问过”的内网目标（经隧道连一次、不发数据）。
type Patrol struct {
	Interval string `yaml:"interval,omitempty"` // 5m / 30s / off（默认 5m；off = 关闭巡检）
	Count    int    `yaml:"count,omitempty"`    // 每轮最多探几个目标（默认 8，上限 32）
}

// PatrolInterval 归一化后的巡检间隔（0 = 关闭）。**默认关闭**（空值 = 关）。
func (c *Config) PatrolInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := strings.ToLower(strings.TrimSpace(c.Patrol.Interval))
	switch s {
	case "off", "none", "0":
		return 0
	case "":
		// 空 = 默认关（与 Default() 里写的一致）。
		//
		// 实测考虑：巡检会定期向业务目标发起真实连接（相当于模拟业务流量），
		// 对客户内网来说这是“多余的动作”—— 需要时在设置里显式打开。
		return 0
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

// Tuning 网络调优。默认值对现网够用，异常网络（上游常常半死）时才调。
//
// 两个旋钮的分工：
//   - DialTimeout 管“一条上游最多等多久” —— 越小越快切换，太小会把慢链路误杀。
//     （实测：现网上游 TCP+TLS 握手中位 84～585ms，RTT 抖动到 2s+，所以 3s 留了余量）
//   - DialBudget 管“一次连接总共最多花多久” —— 防止候选多时逐个等满、用户等到 20s。
//     拒绝（端口不通）几乎不花时间，所以总预算只吃“超时型”失败。
//
// 说明：现网上游 TCP+TLS 握手中位 84～585ms，RTT 有抖动（实测峰值 2.4s），
// 所以默认 5s —— 既给了慢链路余量，又把“一条半死时等多久才换下一条”
// 从老的 10s 降到 5s（两条上游全死时从 20s 降到 10s）。
type Tuning struct {
	DialTimeout string `yaml:"dial_timeout,omitempty"` // 如 5s（默认 5s）
	DialBudget  string `yaml:"dial_budget,omitempty"`  // 默认 2×dial_timeout；一般不用写
	// RaceAfter 首跳等多久还没连上就并发试其他候选（默认 300ms；0 = 关）。
	// 竞速会成倍放大连接数，所以只在“第一条明显慢”时才值得。
	RaceAfter string `yaml:"race_after,omitempty"`
	// CountDirect 是否把直连流量也纳入统计（默认 false：直连不进内核过滤器，完全零开销）。
	CountDirect bool `yaml:"count_direct,omitempty"`
	// BuiltinDirectDisabled 关掉“内置直连端口”（默认不写 = 内置生效）。
	// 目前内置的是 TCP 7680（Windows 更新传递优化）：它在客户内网里不该进隧道。
	BuiltinDirectDisabled bool `yaml:"builtin_direct_disabled,omitempty"`
	// TLSSniff 是否只读噢探 TLS SNI / HTTP Host（默认开，但**只有写了通配域名规则时才真的干活**）。
	//
	// 为什么需要：通配域名的名字原本靠“看明文 DNS 应答”学；一旦应用用了加密 DNS
	// （DoH/DoT）或自带解析器，DNS 层就什么都看不到——那时名字只剩下 SNI / Host
	// 两个明文可见的地方。这是“防患于未然”：现在的环境没在用 DoH，以后可能会。
	//
	// 关掉它 = 只靠 DNS：零额外开销，但遇到 DoH 就学不到名字。
	TLSSniffDisabled bool `yaml:"tls_sniff_disabled,omitempty"`
	// DNSTakeoverDisabled 是否关掉 **DNS 接管（发假 IP）**。默认**开**
	// （只有写了通配域名规则时才真的干活），写成 dns_takeover_disabled: true 才关。
	//
	// 干什么：应用问一个命中通配规则的名字时，我们额外塞一条假 IP 应答（如 198.19.0.7）；
	// 应用去连这个假 IP，我们一看就知道它要去哪个域名 —— 名字在**连接之前**
	// 就到了，不需要猜（那是已删的“先接后判”）。
	//
	// 重要前提（实测教训）：**除指定域名外的解析必须照常**。
	// 早期“抢包式”实现（把查询抢走自己答、再把不接管的放回去）在本机有第二个
	// 拦戴器时会乒乓，把 DNS 拖死 —— 现在改成**只读嗅探 + 额外塞应答**，
	// 永远不消费包，结构上不可能把别人的 DNS 拖死。
	// 另：起来之后还会**自检**一次（见 dnsTakeoverSelfCheck）：不相干名字
	// 解不出或返回假 IP → 自动关掉自己并报错。
	DNSTakeoverDisabled bool `yaml:"dns_takeover_disabled,omitempty"`
	// QuicBlockDisabled 关掉 **QUIC（UDP 443）阻断**（默认不写 = 阻断生效）。
	//
	// 于什么要阻断：QUIC（HTTP/3）走 UDP，而我们不中继 UDP —— 不阻断的话，
	// “该走隧道”的目标一上来先试 QUIC，那部分流量是**静默直连漏出**的
	// （不经过我们、日志里一个字都没有）；阻断后回 ICMP 端口不可达，
	// 应用立刻回落 TCP（TCP 那条路是我们接管的）。
	//
	// 只拦“要走链 / 阻断”的目标；直连目标的 QUIC 一个包不碰。
	// 确实有应用非 QUIC 不可（少见）时：quic_block_disabled: true。
	QuicBlockDisabled bool `yaml:"quic_block_disabled,omitempty"`
	// DNSBlackbox 排查用：把 DNS 接管看到的每个查询/每次回答写进
	// logs/dns-blackbox.log（默认关；排查“DNS 到底是谁弄坏的”时打开）。
	DNSBlackbox bool `yaml:"dns_blackbox,omitempty"`
	// FakeIPRange 假 IP 段（默认 198.19.0.0/16，仅在 dns_takeover 打开时用）。
	//
	// **不能用 198.18.0.0/16** —— 那是 Clash/mihomo 的 fake-ip 默认段，
	// 两个程序抢同一段会互相误判（配了会被直接拒绝，见 internal/fakeip）。
	FakeIPRange string `yaml:"fake_ip_range,omitempty"`
	// DomainResolve 规则里的域名怎么变成实际连接：
	//
	//	local（默认）本机解析出 IP 后按 IP 连 —— 客户内网域名通常只有本机能解答
	//	upstream       把域名交给上游去解析（域名不出本机；适合同一个域名两边解析不同的场景）
	//	auto           本机优先，连不上再把域名交给上游试一次
	//
	// 实测教训：我们这套环境里内网域名（main.example.com）**只有客户网内的 DNS 能解答**，
	// 上游是公网中转服务器、根本解析不到 —— 所以默认必须是 local，不能默认透传。
	DomainResolve string `yaml:"domain_resolve,omitempty"`
	// DomainResolveLocal 这些域名**强制本机解析**（一行一个，支持 `*.example.com` 通配）。
	//
	// 为什么需要它：DomainResolve 是**全局**一个策略，而现场常见的是混合的 ——
	// 公网域名交给上游解析（域名不出本机），客户内网域名却只有客户网内的 DNS
	// 能解答。二选一那种配置在这个场景下总是错的。
	// 命中这里就压过 DomainResolve（除了一种例外：假 IP 又没本机真实 IP 时，
	// 只能交给上游 —— 本机解不开时白名单也无能为力）。
	DomainResolveLocal []string `yaml:"domain_resolve_local,omitempty"`
	// Secrets 上游凭据是否加密保存（默认 true；显式写 false 才关）。
	Secrets *bool `yaml:"secrets_encrypted,omitempty"`
	// WarmSessions 每条上游预热几条"已握手、只差 CONNECT"的会话（默认 2；0 = 关）。
	// 实测每条能省 193～258ms 的等待（TCP+TLS+招呼那三段）。
	WarmSessions string `yaml:"warm_sessions,omitempty"`
}

// DialTimeoutDur 单次尝试上游的超时（默认 5s，夹在 1s～30s）。
func (c *Config) DialTimeoutDur() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dialTimeoutLocked()
}

func (c *Config) dialTimeoutLocked() time.Duration {
	return clampDur(c.Tuning.DialTimeout, 5*time.Second, time.Second, 30*time.Second)
}

// DialBudgetDur 一次连接在所有上游上最多花多久。
// 默认 = 2×单次超时（即“最多两轮”）：拒绝型失败几乎不花时间，所以
// 候选多时照样会一路试下去；只有“超时型”失败才会把预算吃光。
func (c *Config) DialBudgetDur() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	per := c.dialTimeoutLocked()
	d := clampDur(c.Tuning.DialBudget, 2*per, per, time.Minute)
	if d < per { // 配置里总预算比单次还小 → 以单次为准，否则第一条就被预算卡掉
		d = per
	}
	return d
}

// RaceAfterDur 竞速起跑时间（默认 300ms）。
// 显式写 0 / off 表示关闭竞速；非法值回默认。
func (c *Config) RaceAfterDur() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := strings.ToLower(strings.TrimSpace(c.Tuning.RaceAfter))
	switch s {
	case "0", "off", "none", "false":
		return 0
	case "":
		return 300 * time.Millisecond
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 300 * time.Millisecond
}

// clampDur 解析 duration 字符串；空/非法取 def，并夹到 [lo, hi]。
func clampDur(s string, def, lo, hi time.Duration) time.Duration {
	d := def
	if v, err := time.ParseDuration(strings.ToLower(strings.TrimSpace(s))); err == nil && v > 0 {
		d = v
	}
	if d < lo {
		d = lo
	}
	if d > hi {
		d = hi
	}
	return d
}

// PatrolCount 每轮巡检的目标数（默认 8，上限 32，免得一下探爆客户内网）。
func (c *Config) PatrolCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := c.Patrol.Count
	if n <= 0 {
		return 8
	}
	if n > 32 {
		return 32
	}
	return n
}

// PatrolEnabled 巡检是否开着。
func (c *Config) PatrolEnabled() bool { return c.PatrolInterval() > 0 }

// FindChain 按下标找链，找不到返回 -1。
func (c *Config) FindChain(name string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.findChainLocked(name)
}

func (c *Config) findChainLocked(name string) int {
	for i := range c.Chains {
		if c.Chains[i].Name == name {
			return i
		}
	}
	return -1
}

// AddChain 追加一条链。
func (c *Config) AddChain(ch Chain) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(ch.Name) == "" {
		return fmt.Errorf("链名不能为空")
	}
	if c.findChainLocked(ch.Name) >= 0 {
		return fmt.Errorf("链名 %q 已存在", ch.Name)
	}
	old := c.Chains
	// copy-on-write：读方（引擎）可能正持着旧切片遍历，绝不原地改它
	c.Chains = append(append([]Chain(nil), c.Chains...), ch)
	if err := c.validateLocked(); err != nil {
		c.Chains = old // 回滚，不留非法状态
		return err
	}
	return nil
}

// chainHasCreds 这条链的上游 URL 里有没有明文凭据（user:pass@ 或 ?auth=）。
func chainHasCreds(ch Chain) bool {
	for _, raw := range ch.Upstreams() {
		up, err := upstream.Parse(raw)
		if err != nil {
			continue
		}
		if up.Creds.User != "" || up.Creds.Pass != "" {
			return true
		}
	}
	return false
}

// ChainCredUser 已封存口令的账号名（只给界面显示"账号还是那个"，不暴露口令）。
func (c *Config) ChainCredUser(ch Chain) string {
	if ch.Secret == "" {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	store := c.Secrets()
	if store == nil {
		return ""
	}
	cred := store.Get(ch.Secret)
	if i := strings.Index(cred, ":"); i >= 0 {
		return cred[:i]
	}
	return cred
}

// UpdateChain 把 oldName 这条链替换成 ch（允许改名）。
func (c *Config) UpdateChain(oldName string, ch Chain) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.findChainLocked(oldName)
	if i < 0 {
		return fmt.Errorf("找不到链 %q", oldName)
	}
	if ch.Name != oldName && c.findChainLocked(ch.Name) >= 0 {
		return fmt.Errorf("链名 %q 已存在", ch.Name)
	}
	// copy-on-write：先拿旧切片做快照（引擎可能正在遍历），改的是一份新切片
	oldChains, oldRoutes := c.Chains, c.Routes
	chains := append([]Chain(nil), c.Chains...)
	routes := append([]Route(nil), c.Routes...)
	old := chains[i]
	// ⚠ 关键：界面上编辑链路时，表单里看不到已封存的口令（forward 只剩 host:port），
	// 如果直接整体替换，就会把 secret: 引用一并抹掉 —— 那才是真丢口令。
	// 所以：新写法里没有凭据时，继承旧的 secret 引用；
	// 若用户确实填了新凭据（URL 里带 user:pass@），则丢掉旧引用，交给保存时重新封存。
	if ch.Secret == "" && old.Secret != "" && !chainHasCreds(ch) {
		ch.Secret = old.Secret
	}
	if chainHasCreds(ch) {
		ch.Secret = ""
	}
	chains[i] = ch
	if ch.Name != oldName {
		// 改名同步改所有引用
		for j := range routes {
			if routes[j].Chain == oldName {
				routes[j].Chain = ch.Name
			}
		}
	}
	c.Chains, c.Routes = chains, routes
	if err := c.validateLocked(); err != nil {
		// 回滚：链本体 + 改名连带改过的规则引用（只还原链会留下“规则指向不存在的链”）
		c.Chains, c.Routes = oldChains, oldRoutes
		return err
	}
	return nil
}

// ChainUsage 返回引用了该链的规则条数。
func (c *Config) ChainUsage(name string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.chainUsageLocked(name)
}

func (c *Config) chainUsageLocked(name string) int {
	n := 0
	for _, r := range c.Routes {
		if r.Chain == name {
			n++
		}
	}
	return n
}

// RemoveChain 删除链；还被规则引用时拒绝，避免静默产生悬空规则。
func (c *Config) RemoveChain(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.findChainLocked(name)
	if i < 0 {
		return fmt.Errorf("找不到链 %q", name)
	}
	if n := c.chainUsageLocked(name); n > 0 {
		return fmt.Errorf("链 %q 还被 %d 条规则引用，请先改掉那些规则", name, n)
	}
	if len(c.Chains) <= 1 {
		return fmt.Errorf("至少要保留一条链")
	}
	out := make([]Chain, 0, len(c.Chains)-1)
	out = append(out, c.Chains[:i]...)
	out = append(out, c.Chains[i+1:]...)
	c.Chains = out
	return nil
}

// MoveChain 把第 from 条链移到第 to 条位置。
func (c *Config) MoveChain(from, to int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.Chains)
	if from < 0 || from >= n || to < 0 || to >= n || from == to {
		return fmt.Errorf("位置越界")
	}
	ch := c.Chains[from]
	rest := append(append([]Chain{}, c.Chains[:from]...), c.Chains[from+1:]...)
	out := append([]Chain{}, rest[:to]...)
	out = append(out, ch)
	out = append(out, rest[to:]...)
	c.Chains = out
	return nil
}

// normalize 就地规范一条规则：清掉名字/链两侧空白、旧 target 并进 targets、
// 目标归一化成 CIDR 并组内去重。返回是否改动过、被丢掉的重复项。
