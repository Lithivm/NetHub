// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
}

// 上游选择策略。
const (
	StrategyFailover = "failover" // 按顺序试，第一个能用的就用（默认）
	StrategyRound    = "round"    // 轮询（负载均衡）
	StrategyRandom   = "random"   // 随机
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

// StrategyName 归一化后的策略名（默认 failover）。
func (ch Chain) StrategyName() string {
	switch strings.ToLower(strings.TrimSpace(ch.Strategy)) {
	case StrategyRound:
		return StrategyRound
	case StrategyRandom:
		return StrategyRandom
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

	// Target 是 v1 的旧写法（一条规则一个目标），只为读老 config.yaml 保留：
	// 载入时由 Normalize 并进 Targets，保存时不再写出。
	Target string `yaml:"target,omitempty"`
}

// IsDirect 这条规则的动作是不是直连（不走代理）。
func (r Route) IsDirect() bool { return r.Chain == DirectChain }

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

// Config 顶层配置。
type Config struct {
	Relay  string   `yaml:"relay"` // relay 监听地址，端口写 0 表示自动分配
	Chains []Chain  `yaml:"chains"`
	Routes []Route  `yaml:"routes"`
	Patrol Patrol   `yaml:"patrol,omitempty"` // 业务目标巡检（间隔/每轮数量）
	Hosts  HostsCfg `yaml:"hosts"`
	UI     UICfg    `yaml:"ui"`

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
		Hosts:  HostsCfg{Manage: false},
		UI:     UICfg{Theme: "light"},
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
	changed := false
	for i := range c.Chains {
		ch, err := c.Chains[i].normalize()
		if err != nil {
			return changed, fmt.Errorf("第 %d 条链 %s: %v", i+1, c.Chains[i].Name, err)
		}
		changed = changed || ch
	}
	for i := range c.Routes {
		ch, _, err := c.Routes[i].normalize()
		if err != nil {
			return changed, fmt.Errorf("第 %d 条规则: %v", i+1, err)
		}
		changed = changed || ch
	}
	return changed, nil
}

// Save 原子写回配置文件。
func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("配置路径未设置")
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	header := "# NetHub 配置 —— 由程序读写，手工改也生效\n" +
		"# forward 里的凭据是本机敏感信息，不要外传、不要提交进 git。\n"
	// 覆盖前先备份一份（backups/ 目录，只留最新 20 份），改坏了能回滚
	if err := c.backupLocked(); err != nil {
		return fmt.Errorf("备份旧配置失败: %w", err)
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), b...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Validate 结构校验：链名唯一、路由引用的链存在、地址格式合法。
func (c *Config) Validate() error {
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
		if r.NeedsChain() && !seen[r.Chain] {
			return fmt.Errorf("第 %d 条规则%s: 引用了不存在的链 %q", i+1, r.Describe(), r.Chain)
		}
		if len(r.Targets) == 0 {
			return fmt.Errorf("第 %d 条规则%s: 至少要有一个目标", i+1, r.Describe())
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
	}
	if !strings.Contains(c.Relay, ":") {
		return fmt.Errorf("relay 应为 host:port，当前 %q", c.Relay)
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
func NormalizeTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("不能为空")
	}
	if !strings.Contains(s, "/") {
		s += "/32"
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

// PatrolInterval 归一化后的巡检间隔（0 = 关闭）。默认 5 分钟。
func (c *Config) PatrolInterval() time.Duration {
	s := strings.ToLower(strings.TrimSpace(c.Patrol.Interval))
	switch s {
	case "off", "none", "0":
		return 0
	case "":
		return 5 * time.Minute
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

// PatrolCount 每轮巡检的目标数（默认 8，上限 32，免得一下探爆客户内网）。
func (c *Config) PatrolCount() int {
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
	for i := range c.Chains {
		if c.Chains[i].Name == name {
			return i
		}
	}
	return -1
}

// AddChain 追加一条链。
func (c *Config) AddChain(ch Chain) error {
	if strings.TrimSpace(ch.Name) == "" {
		return fmt.Errorf("链名不能为空")
	}
	if c.FindChain(ch.Name) >= 0 {
		return fmt.Errorf("链名 %q 已存在", ch.Name)
	}
	c.Chains = append(c.Chains, ch)
	if err := c.Validate(); err != nil {
		c.Chains = c.Chains[:len(c.Chains)-1] // 回滚，不留非法状态
		return err
	}
	return nil
}

// UpdateChain 把 oldName 这条链替换成 ch（允许改名）。
func (c *Config) UpdateChain(oldName string, ch Chain) error {
	i := c.FindChain(oldName)
	if i < 0 {
		return fmt.Errorf("找不到链 %q", oldName)
	}
	if ch.Name != oldName && c.FindChain(ch.Name) >= 0 {
		return fmt.Errorf("链名 %q 已存在", ch.Name)
	}
	old := c.Chains[i]
	c.Chains[i] = ch
	if ch.Name != oldName {
		// 改名同步改所有引用
		for j := range c.Routes {
			if c.Routes[j].Chain == oldName {
				c.Routes[j].Chain = ch.Name
			}
		}
	}
	if err := c.Validate(); err != nil {
		c.Chains[i] = old // 回滚，不要留下非法状态
		return err
	}
	return nil
}

// ChainUsage 返回引用了该链的规则条数。
func (c *Config) ChainUsage(name string) int {
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
	i := c.FindChain(name)
	if i < 0 {
		return fmt.Errorf("找不到链 %q", name)
	}
	if n := c.ChainUsage(name); n > 0 {
		return fmt.Errorf("链 %q 还被 %d 条规则引用，请先改掉那些规则", name, n)
	}
	if len(c.Chains) <= 1 {
		return fmt.Errorf("至少要保留一条链")
	}
	c.Chains = append(c.Chains[:i], c.Chains[i+1:]...)
	return nil
}

// MoveChain 把第 from 条链移到第 to 条位置。
func (c *Config) MoveChain(from, to int) error {
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
	if len(out) == 0 {
		return changed, dup, fmt.Errorf("至少要有一个目标")
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
	return changed, dup, nil
}

// ShadowedTargets 这条规则里哪些目标已经被**前面的**规则完全覆盖
// （目标被包含 且 端口被包含）—— 那些永远轮不到，界面要标出来。
//
// 覆盖算两种情况：目标写法完全相同，或者前面那条是**更宽的网段**把这条整个包住。
// 后者才是最常踩的排序错误：先写 10.0.0.0/24 走链、再写 10.0.0.5/32 直连 ——
// 自上而下命中即止，那条 /32 永远轮不到。
func (c *Config) ShadowedTargets(i int) []string {
	if i < 0 || i >= len(c.Routes) {
		return nil
	}
	rt := c.Routes[i]
	var out []string
	for _, t := range rt.Targets {
		tn := targetNet(t)
		if tn == nil {
			continue
		}
		covered := false
		for j := 0; j < i && !covered; j++ {
			r := c.Routes[j]
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

// SortRoutesBySpecificity 按“最具体优先”重排：前缀长（/32 → /24）的靠前，
// 同前缀时带端口条件的靠前；同具体程度保持原有相对顺序。
// 返回是否有改动。
func (c *Config) SortRoutesBySpecificity() bool {
	type key struct {
		prefix int
		ports  int
	}
	keys := make([]key, len(c.Routes))
	sorted := true
	for i, r := range c.Routes {
		best := 0
		for _, t := range r.Targets {
			if j := strings.IndexByte(t, '/'); j >= 0 {
				if n, err := strconv.Atoi(t[j+1:]); err == nil && n > best {
					best = n
				}
			}
		}
		keys[i] = key{best, len(r.Ports)}
		if i > 0 {
			p, q := keys[i-1], keys[i]
			if q.prefix > p.prefix || (q.prefix == p.prefix && q.ports > 0 && p.ports == 0) {
				sorted = false
			}
		}
	}
	if sorted {
		return false
	}
	idx := make([]int, len(c.Routes))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ka, kb := keys[idx[a]], keys[idx[b]]
		if ka.prefix != kb.prefix {
			return ka.prefix > kb.prefix
		}
		return ka.ports > 0 && kb.ports == 0
	})
	out := make([]Route, len(c.Routes))
	for i, j := range idx {
		out[i] = c.Routes[j]
	}
	c.Routes = out
	return true
}

// Precheck 启动前的体检：返回人话报告（✓ 正常 / ⚠ 提醒 / ✗ 问题）。
// 不修任何东西，只回答“这份配置能不能干活、有没有埋雷”。
func (c *Config) Precheck() []string {
	var out []string
	if err := c.Validate(); err != nil {
		return []string{"✗ 配置校验失败：" + err.Error()}
	}
	out = append(out, fmt.Sprintf("✓ 配置可载入：%d 条链，%d 条规则", len(c.Chains), len(c.Routes)))

	tunnel := 0
	for _, r := range c.Routes {
		if r.NeedsChain() {
			tunnel++
		}
	}
	if tunnel == 0 {
		out = append(out, "✗ 没有任何“走链”的规则 —— 服务起来也无事可做")
	} else {
		out = append(out, fmt.Sprintf("✓ %d 条隧道规则会进内核过滤器（其余流量不经过我们）", tunnel))
	}

	for i := range c.Routes {
		if s := c.ShadowedTargets(i); len(s) > 0 {
			out = append(out, fmt.Sprintf("⚠ 第 %d 条规则%s 里有 %d 个目标被前面的规则完全覆盖（永远不生效）：%s",
				i+1, c.Routes[i].Describe(), len(s), strings.Join(s, ", ")))
		}
	}
	for _, ch := range c.Chains {
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
	if !strings.Contains(c.Relay, ":") {
		out = append(out, "✗ relay 不是 host:port")
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

// backupLocked 把当前配置文件复制进 backups/，并只保留最新的 20 份。
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
	// 只留最新 20 份
	if all := c.Backups(); len(all) > 20 {
		for _, old := range all[20:] {
			_ = os.Remove(filepath.Join(d, old))
		}
	}
	return nil
}

// checkTargetsFree 检查 rt 的目标有没有落在别的规则里。
// skip 是正在编辑那条规则的下标（-1 表示新增）。
//
// 只拦**完全没用**的规则：目标相同 **且** 端口被上面那条全覆盖（上面那条留空端口
// 就是全覆盖）。规则自上而下命中即止，被完全覆盖的那条永远轮不到，
// 留着只会让人以为它生效了。
//
// 网段包含关系（10.0.0.0/8 之后再写 10.1.1.0/24）是 Proxifier 的正常用法 ——
// 先宽后窄或先窄后宽都由用户说了算，不拦；同一目标不同端口也不拦
// （10.0.0.5:443 走一条链、10.0.0.5:5432 走另一条，这是端口维度的正当用法）。
func (c *Config) checkTargetsFree(rt Route, skip int) error {
	for j, r := range c.Routes {
		if j == skip {
			continue
		}
		for _, t := range rt.Targets {
			for _, o := range r.Targets {
				if !strings.EqualFold(o, t) || !PortsCover(r.Ports, rt.Ports) {
					continue
				}
				if len(r.Ports) == 0 {
					return fmt.Errorf("目标 %s 已在第 %d 条规则%s 里了（规则自上而下匹配，这一条永远轮不到）", t, j+1, r.Describe())
				}
				return fmt.Errorf("目标 %s 的端口 %s 已被第 %d 条规则%s（端口 %s）全部覆盖（规则自上而下匹配，这一条永远轮不到）",
					t, PortText(rt.Ports), j+1, r.Describe(), PortText(r.Ports))
			}
		}
	}
	return nil
}

// AddRoute 追加一条规则：名字/目标/链都会归一化，组内重复目标去掉。
func (c *Config) AddRoute(rt Route) error {
	if _, _, err := rt.normalize(); err != nil {
		return err
	}
	if err := c.checkTargetsFree(rt, -1); err != nil {
		return err
	}
	c.Routes = append(c.Routes, rt)
	if err := c.Validate(); err != nil {
		c.Routes = c.Routes[:len(c.Routes)-1] // 回滚，不留非法状态
		return err
	}
	return nil
}

// UpdateRoute 替换第 i 条规则。
func (c *Config) UpdateRoute(i int, rt Route) error {
	if i < 0 || i >= len(c.Routes) {
		return fmt.Errorf("规则下标越界")
	}
	if _, _, err := rt.normalize(); err != nil {
		return err
	}
	if err := c.checkTargetsFree(rt, i); err != nil {
		return err
	}
	old := c.Routes[i]
	c.Routes[i] = rt
	if err := c.Validate(); err != nil {
		c.Routes[i] = old // 回滚
		return err
	}
	return nil
}

// RemoveRoute 删除第 i 条规则。
func (c *Config) RemoveRoute(i int) error {
	if i < 0 || i >= len(c.Routes) {
		return fmt.Errorf("规则下标越界")
	}
	c.Routes = append(c.Routes[:i], c.Routes[i+1:]...)
	return nil
}

// MoveRoute 把第 from 条规则移到第 to 条位置（顺序即匹配优先级）。
func (c *Config) MoveRoute(from, to int) error {
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
	b, err := yaml.Marshal(c)
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
