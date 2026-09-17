// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"netproxy/internal/upstream"
)

// Chain 一条隧道链：一个上游代理（url）+ 可选的本地 socks5 监听。
type Chain struct {
	Name    string `yaml:"name"`
	Listen  string `yaml:"listen,omitempty"` // 可选的本地 socks5（只在用外置 socks5 时才需要）
	Forward string `yaml:"forward"`          // 上游代理 URL，例如 socks5+tls://host:port?auth=...
	Note    string `yaml:"note,omitempty"`
}

// Route 目标 → 链 的规则，见 internal/rules。
type Route struct {
	Target string `yaml:"target"`
	Chain  string `yaml:"chain"`
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

// Default 返回一份内置默认配置（首次运行、且没有旧 bat 可导入时用）。
func Default() *Config {
	return &Config{
		Relay: "127.0.0.1:0",
		Chains: []Chain{
			{Name: "proxy-a", Listen: "127.0.0.1:1080", Forward: "", Note: "内网主体链路（10.0.0.* / 10.0.1.*）"},
			{Name: "proxy-b", Listen: "127.0.0.1:1081", Forward: "", Note: "proxy-b 链路（192.168.100.*）"},
		},
		Routes: []Route{
			{Target: "10.0.0.0/24", Chain: "proxy-a"},
			{Target: "10.0.1.0/24", Chain: "proxy-a"},
			{Target: "192.168.100.0/24", Chain: "proxy-b"},
		},
		Hosts: HostsCfg{Manage: false},
		UI:    UICfg{Theme: "light"},
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
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
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
	header := "# netproxy 配置 —— 由程序读写，手工改也生效\n" +
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
	seenListen := map[string]string{}
	for i, ch := range c.Chains {
		if strings.TrimSpace(ch.Name) == "" {
			return fmt.Errorf("第 %d 条链: name 不能为空", i+1)
		}
		if seen[ch.Name] {
			return fmt.Errorf("链名重复: %s", ch.Name)
		}
		seen[ch.Name] = true
		if strings.TrimSpace(ch.Forward) == "" && strings.TrimSpace(ch.Listen) == "" {
			return fmt.Errorf("链 %s: forward（上游 URL）与 listen（本地 socks5）至少要有一个。"+
				"正常只需 forward：上游能力已内置，不需要本地 gost", ch.Name)
		}
		if fwd := strings.TrimSpace(ch.Forward); fwd != "" {
			if _, err := upstream.Parse(fwd); err != nil {
				return fmt.Errorf("链 %s 的上游无法原生实现：%v", ch.Name, err)
			}
		}
		if ch.Listen != "" && !strings.Contains(ch.Listen, ":") {
			return fmt.Errorf("链 %s: listen 应为 host:port，当前 %q", ch.Name, ch.Listen)
		}
		// 两条链监听同一个端口会直接绑定失败
		if ch.Listen != "" {
			if other, dup := seenListen[ch.Listen]; dup {
				return fmt.Errorf("链 %s 和链 %s 的监听端口相同（%s）", ch.Name, other, ch.Listen)
			}
			seenListen[ch.Listen] = ch.Name
		}
	}
	for i, r := range c.Routes {
		if !seen[r.Chain] {
			return fmt.Errorf("第 %d 条规则(%s): 引用了不存在的链 %q", i+1, r.Target, r.Chain)
		}
		if _, err := NormalizeTarget(r.Target); err != nil {
			return fmt.Errorf("第 %d 条规则: 目标 %q 不是合法 IP 或 CIDR（%v）", i+1, r.Target, err)
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
	ch.Listen = NormalizeListenLoose(ch.Listen)
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
	ch.Listen = NormalizeListenLoose(ch.Listen)
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

// AddRoute 追加一条规则（target 会被归一化成 CIDR）。
func (c *Config) AddRoute(rt Route) error {
	t, err := NormalizeTarget(rt.Target)
	if err != nil {
		return fmt.Errorf("目标 %q: %v", rt.Target, err)
	}
	for _, r := range c.Routes {
		if strings.EqualFold(r.Target, t) {
			return fmt.Errorf("目标 %s 已经有一条规则了（规则按顺序匹配，重复必有一条永远不生效）", t)
		}
	}
	rt.Target = t
	c.Routes = append(c.Routes, rt)
	if err := c.Validate(); err != nil {
		c.Routes = c.Routes[:len(c.Routes)-1]
		return err
	}
	return nil
}

// UpdateRoute 替换第 i 条规则。
func (c *Config) UpdateRoute(i int, rt Route) error {
	if i < 0 || i >= len(c.Routes) {
		return fmt.Errorf("规则下标越界")
	}
	t, err := NormalizeTarget(rt.Target)
	if err != nil {
		return fmt.Errorf("目标 %q: %v", rt.Target, err)
	}
	for j, r := range c.Routes {
		if j != i && strings.EqualFold(r.Target, t) {
			return fmt.Errorf("目标 %s 已被第 %d 条规则占用", t, j+1)
		}
	}
	rt.Target = t
	old := c.Routes[i]
	c.Routes[i] = rt
	if err := c.Validate(); err != nil {
		c.Routes[i] = old
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
