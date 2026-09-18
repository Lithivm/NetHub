// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"nethub/internal/upstream"
)

// Chain 一条隧道链 = 一个上游代理。
//
// 没有本地监听字段：上游是原生实现的，不需要本地 gost，也不需要 socks5 中转。
type Chain struct {
	Name    string `yaml:"name"`
	Forward string `yaml:"forward"` // 上游代理 URL，例如 socks5+tls://host:port?auth=...
	Note    string `yaml:"note,omitempty"`
}

// Route 一条路由规则 —— 形状对齐 Proxifier 的 Proxification Rule：
// **一个动作挂一组目标**。判定维度只有目标 IP/CIDR（见 internal/rules），
// 所以这里没有 Proxifier 的 Applications / Ports，动作就是"走哪条链"。
//
// 规则自上而下匹配、命中即止；一条规则内**任一**目标命中即算该规则命中。
type Route struct {
	Name    string   `yaml:"name,omitempty"` // 规则名，可留空
	Targets []string `yaml:"targets"`        // 目标 IP/CIDR，可多个
	Chain   string   `yaml:"chain"`          // 动作：走哪条链

	// Target 是 v1 的旧写法（一条规则一个目标），只为读老 config.yaml 保留：
	// 载入时由 Normalize 并进 Targets，保存时不再写出。
	Target string `yaml:"target,omitempty"`
}

// Label 一行式描述（日志、导出说明用）：带名字就带上，目标用逗号隔开。
func (r Route) Label() string {
	ts := strings.Join(r.Targets, ", ")
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
	Hosts  HostsCfg `yaml:"hosts"`
	UI     UICfg    `yaml:"ui"`

	path string
}

// Path 返回配置文件路径。
func (c *Config) Path() string { return c.path }

// Default 返回一份内置默认配置（首次运行且没有现成 config.yaml 时写出来给用户改）。
//
// 刻意地"什么都不预设"：链名是示例、forward 留空、不预置任何网段。
// 默认配置绝不指向任何真实环境 —— 否则新机器一启动就会去接管别人的网段，
// 而 forward 为空会让 Validate 直接拒绝启动，用户必须先填自己的上游。
func Default() *Config {
	return &Config{
		Relay: "127.0.0.1:0",
		Chains: []Chain{
			{Name: "proxy-a", Note: "示例链路 A —— 把 forward 换成你自己的上游"},
			{Name: "proxy-b", Note: "示例链路 B"},
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
		seen[ch.Name] = true
		fwd := strings.TrimSpace(ch.Forward)
		if fwd == "" {
			return fmt.Errorf("链 %s: 必须填 forward（上游代理 URL）", ch.Name)
		}
		if _, err := upstream.Parse(fwd); err != nil {
			return fmt.Errorf("链 %s 的上游无法实现: %v", ch.Name, err)
		}
	}
	for i, r := range c.Routes {
		if !seen[r.Chain] {
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
	}
	if !strings.Contains(c.Relay, ":") {
		return fmt.Errorf("relay 应为 host:port，当前 %q", c.Relay)
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
	return changed, dup, nil
}

// checkTargetsFree 检查 rt 的目标有没有落在别的规则里。
// skip 是正在编辑那条规则的下标（-1 表示新增）。
//
// 只拦**完全相同**的目标：规则自上而下命中即止，重复的那个永远轮不到，
// 留着只会让人以为它生效了。网段包含关系（10.0.0.0/8 之后再写 10.1.1.0/24）
// 是 Proxifier 的正常用法 —— 先宽后窄或先窄后宽都由用户说了算，不拦。
func (c *Config) checkTargetsFree(rt Route, skip int) error {
	for j, r := range c.Routes {
		if j == skip {
			continue
		}
		for _, t := range rt.Targets {
			for _, o := range r.Targets {
				if strings.EqualFold(o, t) {
					return fmt.Errorf("目标 %s 已在第 %d 条规则%s 里了（规则自上而下匹配，这一条永远轮不到）", t, j+1, r.Describe())
				}
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
