// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"

	"strings"
	"sync"
	"time"
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
