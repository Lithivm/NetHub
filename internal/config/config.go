// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"
	"net"

	"nethub/internal/dnsmap"
	"nethub/internal/fakeip"
	"nethub/internal/netx"
	"os"
	"path/filepath"
	"sort"
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
}

// IsDirect 这条规则的动作是不是直连（不走代理）。
func (r Route) IsDirect() bool { return r.Chain == DirectChain }

// IsEnabled 规则是否生效（没写 Enabled = 启用）。
func (r Route) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// SetEnabled 改开关（nil 指针 → 明确写成 true/false，保证存盘后状态确定）。
func (r *Route) SetEnabled(on bool) { v := on; r.Enabled = &v }

// IsBlock 这条规则的动作是不是阻断（丢弃）。
func (r Route) IsBlock() bool { return r.Chain == BlockChain }

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
	Theme string `yaml:"theme"` // light | dark
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
		UI:     UICfg{Theme: "dark"}, // 默认深色：这程序多数时间在盯日志/连接表，深色看久了不刺眼
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
	if c.UI.Theme != "dark" {
		c.UI.Theme = "light"
	}
	if _, err := c.Normalize(); err != nil { // 旧写法/手写配置也安全进来
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
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
			if _, err := NormalizeTarget(t); err != nil {
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
	// IP 通配（Proxifier 的写法：10.100.100.* = 一整段）→ 展开成 CIDR
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
		// 纯数字+点的写法（如 10.100.100.*）其实是 IP 通配，更推荐用那个：
		// 它会被折成 CIDR、在 IP 层匹配，不依赖任何解析。
		if isAllDigits(strings.ReplaceAll(pattern, "*", "")) {
			return "", fmt.Errorf("%q 看起来是 IP 通配 —— IP 请写 10.100.100.*（整段）或 CIDR；"+
				"域名通配用于主机名（如 *.his.com、db-*.his.com）", s)
		}
		return pattern, nil
	}
	// 剩下 * 且不是域名（如 10.*.100.5）→ 直接说清改写方式，
	// 别拖到最后报一句没有信息量的“解析失败”。
	if strings.Contains(s, "*") && !isHostname(s) {
		return "", fmt.Errorf("这种写法猜不出范围 —— 末尾一段才能用 *（如 10.100.100.*）；" +
			"其他情况请写 CIDR（如 10.100.0.0/16）")
	}
	if !strings.Contains(s, "/") && !isHostname(s) {
		s += "/32"
	} else if isHostname(s) {
		// 统一去掉尾点：名字表（dnsmap）的 key 都是不带尾点的，
		// 否则 "main.his.com." 这条规则会静默地永不匹配（也查不出原因）。
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

// ipWildcardToCIDR 把 10.100.100.* 这种写法展开成整段 CIDR。
//
// 为什么单独支持它：这是 Proxifier 的写法（从它那儿搬过来的规则与工单里到处都是），
// 语义就是“最后一段随便填”= 一整段网段。不展开的话用户会以为我们连“通配”都不支持。
// 只允许**末尾一段**是 *（10.100.100.* ✓）；中间带 * 的（10.*.100.5）猜不出范围，不要猜。
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
//	out  归一化后的 CIDR，保持输入顺序，组内去重
//	dup  被去掉的重复项（归一化形式，供界面如实告知）
//	err  第一个非法目标 —— 整条规则都不落地，不留半生效状态
func NormalizeTargets(raw string) (out, dup []string, err error) {
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, targetSep) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, nerr := NormalizeTarget(f)
		if nerr != nil {
			return nil, nil, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（%v）", f, nerr)
		}
		key := strings.ToLower(n)
		if seen[key] {
			dup = append(dup, n)
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out, dup, nil
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
	// 实测教训：我们这套环境里内网域名（main.his.com）**只有客户网内的 DNS 能解答**，
	// 上游是公网中转服务器、根本解析不到 —— 所以默认必须是 local，不能默认透传。
	DomainResolve string `yaml:"domain_resolve,omitempty"`
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
func (r *Route) normalize() (changed bool, dup []string, err error) {
	if n := strings.TrimSpace(r.Name); n != r.Name {
		r.Name, changed = n, true
	}
	if ch := strings.TrimSpace(r.Chain); ch != r.Chain {
		r.Chain, changed = ch, true
	}
	if r.Target != "" { // v1 旧写法：并进 targets（两者都在就以 targets 为准）
		if len(r.Targets) == 0 {
			r.Targets = []string{r.Target}
		}
		r.Target, changed = "", true
	}
	out := make([]string, 0, len(r.Targets))
	seen := map[string]bool{}
	for _, t := range r.Targets {
		n, nerr := NormalizeTarget(t)
		if nerr != nil {
			return changed, dup, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（%v）", t, nerr)
		}
		key := strings.ToLower(n)
		if seen[key] {
			dup, changed = append(dup, n), true
			continue
		}
		seen[key] = true
		if n != t {
			changed = true
		}
		out = append(out, n)
	}
	if len(out) == 0 && len(r.Apps) == 0 {
		return changed, dup, fmt.Errorf("至少要有一个目标（或一个进程条件）")
	}
	if len(out) != len(r.Targets) {
		changed = true
	}
	r.Targets = out

	// 端口：留空 = 任意端口。写法归一化（区间方向、去重），顺序保持输入顺序
	if len(r.Ports) > 0 {
		pout := make([]string, 0, len(r.Ports))
		pseen := map[string]bool{}
		for _, p := range r.Ports {
			n, perr := NormalizePort(p)
			if perr != nil {
				return changed, dup, fmt.Errorf("端口 %q 不合法（%v）", p, perr)
			}
			if n != strings.TrimSpace(p) {
				changed = true
			}
			if pseen[n] {
				dup, changed = append(dup, n), true
				continue
			}
			pseen[n] = true
			pout = append(pout, n)
		}
		if len(pout) != len(r.Ports) {
			changed = true
		}
		r.Ports = pout
	}

	// A20 进程条件：去空白、去重（不区分大小写），顺序保持输入顺序。
	// 注意：这里**不能**把 Apps 漏掉 —— 少了这一趟，界面里填的进程条件
	// 一保存就消失（规则会被当成“只按目标”，且没目标时直接报错）。
	if len(r.Apps) > 0 {
		aout := make([]string, 0, len(r.Apps))
		aseen := map[string]bool{}
		for _, a := range r.Apps {
			n := strings.TrimSpace(a)
			if n == "" {
				changed = true
				continue
			}
			if n != a {
				changed = true
			}
			key := strings.ToLower(n)
			if aseen[key] {
				dup, changed = append(dup, n), true
				continue
			}
			aseen[key] = true
			aout = append(aout, n)
		}
		if len(aout) != len(r.Apps) {
			changed = true
		}
		r.Apps = aout
	}
	if len(r.Targets) == 0 && len(r.Apps) == 0 {
		return changed, dup, fmt.Errorf("至少要有一个目标（或一个进程条件）")
	}
	return changed, dup, nil
}

// ShadowedTargets 这条规则里哪些目标已经被**前面的**规则完全覆盖
// （目标被包含 且 端口被包含）—— 那些永远轮不到，界面要标出来。
//
// 覆盖算两种情况：目标写法完全相同，或者前面那条是**更宽的网段**把这条整个包住。
// 后者才是最常踩的排序错误：先写 10.0.0.0/24 走链、再写 10.0.0.5/32 直连 ——
// 自上而下命中即止，那条 /32 永远轮不到。
func (c *Config) ShadowedTargets(i int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return shadowedTargetsIn(c.Routes, i)
}

func shadowedTargetsIn(routes []Route, i int) []string {
	if i < 0 || i >= len(routes) {
		return nil
	}
	rt := routes[i]
	if !rt.IsEnabled() {
		return nil // 停用的规则谈不上“被覆盖”
	}
	// 带进程/本机网段条件的规则，覆盖关系不再简单可比（它们不是总能命中），
	// 轻率判“被覆盖”会误导用户去删一条实际在工作的规则。
	if len(rt.Apps) > 0 || len(rt.LocalNets) > 0 {
		return nil
	}
	var out []string
	for _, t := range rt.Targets {
		tn := targetNet(t)
		if tn == nil {
			continue
		}
		covered := false
		for j := 0; j < i && !covered; j++ {
			r := routes[j]
			if !r.IsEnabled() {
				continue // 前面那条本来就是关着的，盖不住谁
			}
			if len(r.Apps) > 0 || len(r.LocalNets) > 0 {
				continue // 它只对某些进程/网段生效，盖不住整条
			}
			if !PortsCover(r.Ports, rt.Ports) {
				continue // 端口没被盖住，那这条还有活干
			}
			for _, o := range r.Targets {
				if strings.EqualFold(o, t) {
					covered = true
					break
				}
				if on := targetNet(o); on != nil && netContains(on, tn) {
					covered = true
					break
				}
			}
		}
		if covered {
			out = append(out, t)
		}
	}
	return out
}

// validListen 校验 relay 地址（host:port，端口 0 = 自动分配）。
// 以前用 strings.Contains(s,":") 当校验，"abc:" / "::" 全放过，直到 net.Listen 才报错。
func validListen(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("relay 不能为空")
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("relay 应为 host:port（如 127.0.0.1:0），当前 %q", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("relay 端口不合法（0-65535），当前 %q", s)
	}
	return nil
}

// targetPrefixLen 目标的具体度（前缀长度）：CIDR 取掩码位数，裸 IP = 32，域名/其他 = 0。
// 统一“谁更具体”的尺子（排序按钮、体检、重叠报告共用）。
func targetPrefixLen(t string) int {
	t = strings.TrimSpace(t)
	if t == "" {
		return 0
	}
	if !strings.Contains(t, "/") {
		if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
			return 32
		}
		return 0
	}
	if _, n, err := net.ParseCIDR(t); err == nil {
		if ones, bits := n.Mask.Size(); bits == 32 {
			return ones
		}
	}
	return 0
}

// targetNet 归一化后的 CIDR → *net.IPNet（解析失败返回 nil）。
func targetNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return n
}

// netContains outer 是否把 inner 整个包住（含自己）。
func netContains(outer, inner *net.IPNet) bool {
	if outer == nil || inner == nil {
		return false
	}
	oo, _ := outer.Mask.Size()
	io, _ := inner.Mask.Size()
	return oo <= io && outer.Contains(inner.IP)
}

// validLocalNet 校验一条“本机网段”条件（只允许 IPv4 的 IP/CIDR）。
func validLocalNet(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("不能为空")
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("只支持 IPv4")
		}
		return nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("不是合法 IP 或 CIDR，且只支持 IPv4")
	}
	if _, bits := n.Mask.Size(); bits != 32 {
		return fmt.Errorf("只支持 IPv4")
	}
	return nil
}

// SortRoutesBySpecificity 按“最具体优先”重排：前缀长（/32 → /24）的靠前，
// 同前缀时带端口条件的靠前；同具体程度保持原有相对顺序。
//
// 两个例外（都是**不改变行为**的整理）：
//   - “本机自身/环回”类（127.0.0.0/8）**永远排到最后** —— 它的语义是兜底
//     （“别把我们自己的流量拿去代理”），而不是“最具体的例外”；
//     只覆盖环回地址，与任何内网网段不重叠，所以挪到最后不会抢谁的位置。
//   - 停用的规则原地不动（用户摆在那里就是“备着用”）。
//
// 返回是否有改动。
func (c *Config) SortRoutesBySpecificity() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	type key struct {
		prefix int
		ports  int
		self   bool // “本机自身/环回”类 → 永远排最后
	}
	keys := make([]key, len(c.Routes))
	sorted := true
	var live []int // 参与排序的（启用的、非兜底类）规则下标；停用的原地不动
	var self []int // “本机自身/环回”类：永远排最后
	var liveAll []int
	for i, r := range c.Routes {
		if !r.IsEnabled() {
			keys[i] = key{-1, -1, false}
			continue
		}
		liveAll = append(liveAll, i)
		if selfRule(r) {
			self = append(self, i)
			keys[i] = key{-1, -1, true}
			continue
		}
		live = append(live, i)
		best := 0
		for _, t := range r.Targets {
			if n := targetPrefixLen(t); n > best {
				best = n
			}
		}
		keys[i] = key{best, len(r.Ports), false}
	}
	for k := 1; k < len(liveAll); k++ {
		p, q := keys[liveAll[k-1]], keys[liveAll[k]]
		if q.self != p.self {
			if !q.self { // 非兜底类跑到兜底类后面了 → 需要把兜底类挪到后面
				sorted = false
				break
			}
			continue // 兜底类已在后面 → 正是我们要的顺序
		}
		if q.self {
			continue // 兜底类之间保持原顺序
		}
		if q.prefix > p.prefix || (q.prefix == p.prefix && q.ports > 0 && p.ports == 0) {
			sorted = false
			break
		}
	}
	if sorted {
		return false
	}
	// slots = 启用规则原来占的位置（升序）；order = 排好后依次填进去的规则下标
	slots := append([]int{}, liveAll...)
	order := append([]int{}, live...)
	sort.SliceStable(order, func(a, b int) bool {
		ka, kb := keys[order[a]], keys[order[b]]
		if ka.prefix != kb.prefix {
			return ka.prefix > kb.prefix
		}
		return ka.ports > 0 && kb.ports == 0
	})
	order = append(order, self...) // 兜底类接在最后
	out := make([]Route, len(c.Routes))
	copy(out, c.Routes)
	for k := range slots {
		out[slots[k]] = c.Routes[order[k]]
	}
	c.Routes = out
	return true
}

// selfRule 这条规则是不是“本机/兜底”类 —— 自动排序时统一放最后。
//
// 两类都算：
//
//	① 目标全在环回（127.0.0.0/8）—— “别把我们自己的流量拿去代理”
//	② 动作是**直连**且目标全是私网地址（10/8、172.16/12、192.168/16、环回…）——
//	   “这些地址不走隧道”这种本机/局域网兜底规则。
//
// 为什么不按“具体的例外”排：这类规则的前缀往往很短（/20、/24），按前缀排会夹在
// 业务网段中间（真实反馈：“bs 排在两个本机中间”），而它的语义是**兜底**，
// 该待在最后。代价：若某条直连规则与更宽的走链规则重叠，排序后会变成“直连胜” ——
// 所以这仍然只在你亲手点「按优先级排序」时发生，且可用「检查重叠」提前看出来。
func selfRule(r Route) bool {
	if len(r.Targets) == 0 {
		return false
	}
	allLoopback := true
	allPrivate := true
	for _, t := range r.Targets {
		n := targetNet(t)
		if n == nil {
			return false
		}
		if !loopbackNet.Contains(n.IP) {
			allLoopback = false
		}
		if !containsNet(privateNets, n.IP) {
			allPrivate = false
		}
	}
	if allLoopback {
		return true
	}
	return r.IsDirect() && allPrivate
}

// loopbackNet 127.0.0.0/8；privateNets 全部私有/本机地址段。
var (
	loopbackNet = mustCIDR("127.0.0.0/8")
	privateNets = parseCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10")
)

// containsNet 某个 IP 是否落在这些网段里的任意一个。
func containsNet(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("内置网段写错了: " + s)
	}
	return n
}

func parseCIDRs(list ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		out = append(out, mustCIDR(s))
	}
	return out
}

// Precheck 启动前的体检：返回人话报告（✓ 正常 / ⚠ 提醒 / ✗ 问题）。
// 不修任何东西，只回答“这份配置能不能干活、有没有埋雷”。
func (c *Config) Precheck() []string {
	snap := c.Snapshot() // 一次性快照，后续不再碰活配置（避免持锁重入）
	var out []string
	if err := c.Validate(); err != nil {
		return []string{"✗ 配置校验失败：" + err.Error()}
	}
	out = append(out, fmt.Sprintf("✓ 配置可载入：%d 条链，%d 条规则", len(snap.Chains), len(snap.Routes)))

	tunnel := 0
	for _, r := range snap.Routes {
		if r.NeedsChain() {
			tunnel++
		}
	}
	if tunnel == 0 {
		out = append(out, "✗ 没有任何“走链”的规则 —— 服务起来也无事可做")
	} else {
		out = append(out, fmt.Sprintf("✓ %d 条隧道规则会进内核过滤器（其余流量不经过我们）", tunnel))
	}

	for i := range snap.Routes {
		if s := shadowedTargetsIn(snap.Routes, i); len(s) > 0 {
			out = append(out, fmt.Sprintf("⚠ 第 %d 条规则%s 里有 %d 个目标被前面的规则完全覆盖（永远不生效）：%s",
				i+1, snap.Routes[i].Describe(), len(s), strings.Join(s, ", ")))
		}
	}
	for _, ch := range snap.Chains {
		n := len(ch.Upstreams())
		if n == 0 {
			out = append(out, "✗ 链 "+ch.Name+" 没有上游")
			continue
		}
		detail := fmt.Sprintf("✓ 链 %s：%d 个上游，策略 %s，探测 %s", ch.Name, n, ch.StrategyName(), ch.ProbeInterval())
		if n == 1 {
			detail += "（只有一条上游，它挂了业务就断）"
		}
		out = append(out, detail)
	}
	if validListen(snap.Relay) != nil {
		out = append(out, "✗ relay 不是 host:port")
	}

	// 拨号调优：只报“会让人等太久”或“会误杀慢链路”的组合
	dt, db := c.DialTimeoutDur(), c.DialBudgetDur()
	switch {
	case dt >= 10*time.Second:
		out = append(out, fmt.Sprintf("⚠ 单次上游超时 %s 偏大：一条上游半死时，业务要等这么久才换下一条（默认 5s）", dt))
	case dt <= time.Second && db <= time.Second:
		out = append(out, fmt.Sprintf("⚠ 单次超时 %s 偏小：现网上游握手中位到 585ms、抖动上过 2s，可能误杀慢链路", dt))
	}
	if db > 15*time.Second {
		out = append(out, fmt.Sprintf("⚠ 拨号总预算 %s 偏大：所有上游都半死时，用户要等这么久才拿到“连不上”", db))
	}
	return out
}

// BackupDir 备份目录（与 config 同级）。
func (c *Config) BackupDir() string {
	if c.path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(c.path), "backups")
}

// Backups 列出已有备份（新的排前面）。
func (c *Config) Backups() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backupsLocked()
}

func (c *Config) backupsLocked() []string {
	d := c.BackupDir()
	if d == "" {
		return nil
	}
	ents, err := os.ReadDir(d)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// RestoreBackup 用某个备份覆盖当前配置（覆盖前先把当前配置也备一份），并重新载入。
// 返回载入后的配置。
func (c *Config) RestoreBackup(name string) (*Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := filepath.Join(c.BackupDir(), filepath.Base(name))
	b, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("读备份失败: %w", err)
	}
	if err := c.backupLocked(); err != nil { // 回滚前先备当前
		return nil, err
	}
	if err := os.WriteFile(c.path, b, 0o600); err != nil {
		return nil, err
	}
	return Load(c.path)
}

// backupLocked 把当前配置文件复制进 backups/，并只保留最新的 keepBackups 份。
//
// 为什么是 3 份：回滚的实用场景是"刚才改坏了"，3 份足够覆盖连续的几次改动；
// 留几十份只会让 backups/ 目录变成另一个没人看的日志。
const keepBackups = 3

func (c *Config) backupLocked() error {
	d := c.BackupDir()
	if d == "" {
		return fmt.Errorf("配置路径未设置")
	}
	cur, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 还没有配置文件，没什么好备的
		}
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	name := "config-" + time.Now().Format("20060102-150405.000") + ".yaml"
	for i := 2; ; i++ { // 同一毫秒里连存两次也不覆盖（改用 -2/-3…）
		if _, err := os.Stat(filepath.Join(d, name)); os.IsNotExist(err) {
			break
		}
		name = fmt.Sprintf("config-%s-%d.yaml", time.Now().Format("20060102-150405.000"), i)
	}
	if err := os.WriteFile(filepath.Join(d, name), cur, 0o600); err != nil {
		return err
	}
	// 只留最新 keepBackups 份（够回滚就行；留太多反而让人在列表里挑半天）
	if all := c.backupsLocked(); len(all) > keepBackups {
		for _, old := range all[keepBackups:] {
			_ = os.Remove(filepath.Join(d, old))
		}
	}
	return nil
}

// occupiedHint 目标“看起来被前面的规则盖住了”时的提示（**只提示，不拦保存**）。
//
// 历史：这里以前是拦截（AddRoute/UpdateRoute 直接报错不让存）。用户反馈“会自己和自己冲突”，
// 而且真实配置里就是有一堆合法的重叠（同一段内网地址在不同环境指向不同链、先宽后窄做兜底…），
// 拦下来反而耽误干活。现在改成纯提示：
//
//   - 规则页那一行会自己标“被前面的规则覆盖”（Shadowed，逐条目标级）
//   - 「重叠检查」按钮能看到完整结论与建议
//   - 真出问题日志里也会报（引擎对“链不存在”“永远轮不到”都有交代）
//
// 只判断“**完全一样**的目标 + 端口被上面那条全盖住”这一种（即上面空端口、下面任何端口都算），
// 网段包含关系与不同端口本就该由用户自由组合。
func (c *Config) occupiedHint(rt Route, skip int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return occupiedHintIn(c.Routes, rt, skip)
}

func occupiedHintIn(routes []Route, rt Route, skip int) []string {
	if !rt.IsEnabled() {
		return nil
	}
	var out []string
	for j, r := range routes {
		if j == skip || j > skip || !r.IsEnabled() {
			continue // 只看“排在它前面”的：后面的盖不住它
		}
		for _, t := range rt.Targets {
			for _, o := range r.Targets {
				if !strings.EqualFold(o, t) || !PortsCover(r.Ports, rt.Ports) {
					continue
				}
				if len(r.Ports) == 0 {
					out = append(out, fmt.Sprintf("目标 %s 也在第 %d 条规则%s 里（它在前面，会先命中）", t, j+1, r.Describe()))
				} else {
					out = append(out, fmt.Sprintf("目标 %s 的端口 %s 已被第 %d 条规则%s（端口 %s）盖住",
						t, PortText(rt.Ports), j+1, r.Describe(), PortText(r.Ports)))
				}
			}
		}
	}
	return out
}

// AddRoute 追加一条规则：名字/目标/链都会归一化，组内重复目标去掉。
func (c *Config) AddRoute(rt Route) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, _, err := rt.normalize(); err != nil {
		return err
	}
	old := c.Routes
	c.Routes = append(append([]Route(nil), c.Routes...), rt)
	if err := c.validateLocked(); err != nil {
		c.Routes = old // 回滚，不留非法状态
		return err
	}
	return nil
}

// RouteHints 保存后“值得知道但不拦”的提示（目标被前面的规则盖住之类）。
// 调用方（界面）把它们记进日志即可，不影响保存成功。
func (c *Config) RouteHints(i int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if i < 0 || i >= len(c.Routes) {
		return nil
	}
	return occupiedHintIn(c.Routes, c.Routes[i], i)
}

// UpdateRoute 替换第 i 条规则。
func (c *Config) UpdateRoute(i int, rt Route) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.Routes) {
		return fmt.Errorf("规则下标越界")
	}
	if _, _, err := rt.normalize(); err != nil {
		return err
	}
	old := c.Routes
	routes := append([]Route(nil), c.Routes...)
	routes[i] = rt
	c.Routes = routes
	if err := c.validateLocked(); err != nil {
		c.Routes = old // 回滚
		return err
	}
	return nil
}

// RemoveRoute 删除第 i 条规则。
func (c *Config) RemoveRoute(i int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.Routes) {
		return fmt.Errorf("规则下标越界")
	}
	out := make([]Route, 0, len(c.Routes)-1)
	out = append(out, c.Routes[:i]...)
	out = append(out, c.Routes[i+1:]...)
	c.Routes = out
	return nil
}

// MoveRoute 把第 from 条规则移到第 to 条位置（顺序即匹配优先级）。
func (c *Config) MoveRoute(from, to int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.Routes)
	if from < 0 || from >= n || to < 0 || to >= n || from == to {
		return fmt.Errorf("位置越界")
	}
	rt := c.Routes[from]
	rest := append(append([]Route{}, c.Routes[:from]...), c.Routes[from+1:]...)
	out := append([]Route{}, rest[:to]...)
	out = append(out, rt)
	out = append(out, rest[to:]...)
	c.Routes = out
	return nil
}

// NormalizeListenLoose 把 ":1080"/"0.0.0.0:1080" 统一成 "127.0.0.1:1080"（回环收紧）。
func NormalizeListenLoose(s string) string {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s
	}
	host, port := s[:i], s[i+1:]
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return host + ":" + port
}

// ChainByName 按名字取链。
func (c *Config) ChainByName(name string) (Chain, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, ch := range c.Chains {
		if ch.Name == name {
			return ch, true
		}
	}
	return Chain{}, false
}

// DefaultPath 返回 <exe 同目录>/config.yaml。
func DefaultPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(filepath.Dir(exe), "config.yaml")
}

// SaveAs 把当前配置写到另一个路径（导出用）。
//
// 不改变 c.path —— 导出不应该影响程序正在用的配置。
func (c *Config) SaveAs(path string) error {
	// 在副本上把历史遗留的 secret: 引用摊平成明文 —— 否则导出的文件头声称
	// “forward 里含凭据”，实际却是无凭据版，换台机器这条链必然认证失败。
	// 必须在快照副本上做，不能改动程序正在用的配置。
	cp := c.Snapshot().config()
	cp.path = c.Path()
	cp.flattenSecretsLocked()
	b, err := yaml.Marshal(cp)
	if err != nil {
		return err
	}
	header := "# NetHub 配置 —— 由程序导出\n" +
		"# 同事拿到后放到 nethub.exe 同目录、改名 config.yaml 即可使用。\n" +
		"# ⚠ forward 里含上游凭据（auth= 是 用户:口令 的 base64），请通过安全渠道分发。\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WarmTarget 每条上游预热几条"已握手、只差 CONNECT"的会话（A11）。
//
//	""(没写) → 默认 2 条
//	off/0    → 关闭预热
//	1～8     → 指定条数（超过 8 按 8，别养一堆让上游嫌弃）
//
// DomainResolveMode 域名解析策略：local（默认）| upstream | auto。
func (c *Config) DomainResolveMode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := strings.ToLower(strings.TrimSpace(c.Tuning.DomainResolve))
	switch s {
	case "upstream", "remote", "proxy":
		return "upstream"
	case "auto", "both":
		return "auto"
	default:
		return "local"
	}
}

// WarmTarget 每条上游预热几条"已握手、只差 CONNECT"的会话。
func (c *Config) WarmTarget() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := strings.ToLower(strings.TrimSpace(c.Tuning.WarmSessions))
	switch s {
	case "off", "none", "0", "false":
		return 0
	case "":
		return 2
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 2
	}
	if n > 8 {
		return 8
	}
	return n
}

// ───────── 配置导出（无凭据版）─────────
//
// 与"打码"（gostbat.Redact 把口令换成 ***）不同：这里要的是**能导入**，
// 所以是把用户名/口令**剔除**掉 —— 打码后的 auth= 不是合法 base64，导入会直接校验失败。

// stripCreds 去掉上游 URL 里的凭据，保留协议与地址（结果仍可被 upstream.Parse 解析）。
func stripCreds(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	up, err := upstream.Parse(raw)
	if err != nil {
		// 解析不了也不能原样返回 —— 这个函数存在的唯一理由就是“无凭据版”。
		// 用兜底抹掉 userinfo 与 ?auth=，避免把 user:pass@ 带进导出文件。
		return redactUserinfo(raw)
	}
	if up.Creds.User == "" && up.Creds.Pass == "" {
		return raw
	}
	switch {
	case up.Protocol == "http" && up.TLS:
		return "https://" + up.Addr
	case up.Protocol == "http":
		return "http://" + up.Addr
	case up.TLS:
		return up.Protocol + "+tls://" + up.Addr
	default:
		return up.Protocol + "://" + up.Addr
	}
}

// redactUserinfo 解析失败时的兜底脱敏：去掉 ?auth=，抹掉 scheme://userinfo@ 里的 userinfo。
// 宁可把地址弄得不完整（导入时校验会报），也不能把口令泄进“无凭据版”。
func redactUserinfo(raw string) string {
	s := raw
	if i := strings.Index(s, "?"); i >= 0 {
		base, q := s[:i], s[i+1:]
		kept := make([]string, 0, 2)
		for _, kv := range strings.Split(q, "&") {
			k, _, _ := strings.Cut(kv, "=")
			if k == "auth" {
				continue
			}
			kept = append(kept, kv)
		}
		s = base
		if len(kept) > 0 {
			s += "?" + strings.Join(kept, "&")
		}
	}
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			if cut := strings.IndexAny(rest, "/?#"); cut < 0 || at < cut {
				s = s[:i+3] + rest[at+1:]
			}
		}
	}
	return s
}

// SaveAsRedacted 导出一份"无凭据但可导入"的配置。
func (c *Config) SaveAsRedacted(path string) error {
	snapshot := c.Snapshot()
	cp := snapshot.config()
	cp.Chains = make([]Chain, len(snapshot.Chains))
	for i, ch := range snapshot.Chains {
		n := ch
		n.Forward = stripCreds(ch.Forward)
		if len(ch.Forwards) > 0 {
			n.Forwards = make([]string, 0, len(ch.Forwards))
			for _, f := range ch.Forwards {
				n.Forwards = append(n.Forwards, stripCreds(f))
			}
		}
		// 历史遗留的 secret: 引用也要清掉：导出文件不会带 secrets.dat，
		// 留个悬空引用只会在目标机器上报“解不开”。
		n.Secret = ""
		cp.Chains[i] = n
	}
	b, err := yaml.Marshal(&cp)
	if err != nil {
		return err
	}
	header := "# NetHub 配置（无凭据版）\n" +
		"# 上游地址里的用户名/口令已剔除 —— 这个文件**可以直接导入**，导入后请补上口令。\n" +
		"# 生成时间：" + time.Now().Format("2006-01-02 15:04:05") + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// BackupNow 立刻备份当前配置（导入/回滚前用）。
func (c *Config) BackupNow() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backupLocked()
}

// CountDirectEnabled 是否把直连流量也纳入统计（默认关）。
//
// 关（默认）：直连网段不进内核过滤器 —— 一个包都不碰，统计里只看到它的 SYN。
// 开：直连网段也装进过滤器，我们不改包、只数双向字节（换来一点每包开销）。
// 需要在「连接」页勾选，改完要重启服务（过滤器在启动时装配）。
func (c *Config) CountDirectEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Tuning.CountDirect
}

// BuiltinDirectEnabled 是否启用“内置直连端口”（默认开）。
//
// 现在内置的是 TCP 7680（Windows 更新传递优化）：客户内网里这些连接不该走隧道。
// 以前靠配置里写一条 direct 规则实现；现在内置，规则列表里少一条噪音。
func (c *Config) BuiltinDirectEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.BuiltinDirectDisabled
}

// TLSSniffEnabled 是否只读嗅探 TLS SNI / HTTP Host（默认开）。
// 注意：即使开着，没有通配域名规则时也不会开第二只句柄（一分钱不花）。
func (c *Config) TLSSniffEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.TLSSniffDisabled
}

// DNSTakeoverEnabled 是否开启 DNS 接管（发假 IP）。默认开，只有通配域名规则时才生效。
func (c *Config) DNSTakeoverEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.Tuning.DNSTakeoverDisabled
}

// DNSBlackboxEnabled 是否开 DNS 黑匣子（排查用，默认关）。
func (c *Config) DNSBlackboxEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Tuning.DNSBlackbox
}

// FakeIPRangeOr 假 IP 段（未配则用 fakeip 包的默认值）。
func (c *Config) FakeIPRangeOr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if s := strings.TrimSpace(c.Tuning.FakeIPRange); s != "" {
		return s
	}
	return fakeip.DefaultRange
}

// ProbeNetsParsed 已删除（随“先接后判”一起去掉）：域名通配的名字来源现在
// 只有两条只读通道（明文 DNS 嗅探 + TLS SNI/HTTP Host 嗅探），不再揣测。

// EnabledRoutes 只返回启用的规则（引擎、界面统计用）。
//
// 注意：真正的"停用"效果发生在 app.toRules（停用规则根本不进规则集与内核过滤器），
// 这个函数是给需要显式过滤的调用方用的（比如规则模拟器、体检）。
func (c *Config) EnabledRoutes() []Route {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Route, 0, len(c.Routes))
	for _, r := range c.Routes {
		if r.IsEnabled() {
			out = append(out, r)
		}
	}
	return out
}

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

// SetTheme 修改界面主题（只存 "dark"/"light"）。
func (c *Config) SetTheme(mode string) {
	if mode != "dark" {
		mode = "light"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UI.Theme = mode
}

// Theme 界面主题快照。
func (c *Config) Theme() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UI.Theme
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
