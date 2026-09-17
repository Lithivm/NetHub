// Package config 负责配置文件的读写与校验。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Chain 一条隧道链：本地 gost 监听的 socks5 地址 + gost 连上游的转发 URL。
type Chain struct {
	Name    string `yaml:"name"`
	Listen  string `yaml:"listen"`  // 例如 127.0.0.1:1080（gost -L，也是我们 relay 的出口）
	Forward string `yaml:"forward"` // 例如 socks5+tls://host:port?auth=...
	Note    string `yaml:"note,omitempty"`
}

// Route 目标 → 链 的规则，见 internal/rules。
type Route struct {
	Target string `yaml:"target"`
	Chain  string `yaml:"chain"`
}

// GostCfg gost 子进程配置。
type GostCfg struct {
	Enabled bool   `yaml:"enabled"` // 关掉的话就假定 gost 已经在外面跑着
	Exe     string `yaml:"exe"`
	// ExtraArgs 追加到 gost 命令行末尾（进阶用，一般留空）
	ExtraArgs []string `yaml:"extraArgs,omitempty"`
}

// HostsCfg 系统 hosts 标记区块的内容。
type HostsCfg struct {
	Manage  bool     `yaml:"manage"` // 是否由我们维护这段 hosts
	Entries []string `yaml:"entries"`  // 每行是一条 "IP 域名"
}

// Config 顶层配置。
type Config struct {
	Relay  string   `yaml:"relay"` // relay 监听地址，端口写 0 表示自动分配
	Chains []Chain  `yaml:"chains"`
	Routes []Route  `yaml:"routes"`
	Gost   GostCfg  `yaml:"gost"`
	Hosts  HostsCfg `yaml:"hosts"`

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
		Gost:  GostCfg{Enabled: true, Exe: `C:\Users\Administrator\Desktop\gost\gost.exe`},
		Hosts: HostsCfg{Manage: false},
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
	for i, ch := range c.Chains {
		if strings.TrimSpace(ch.Name) == "" {
			return fmt.Errorf("第 %d 条链: name 不能为空", i+1)
		}
		if seen[ch.Name] {
			return fmt.Errorf("链名重复: %s", ch.Name)
		}
		seen[ch.Name] = true
		if !strings.Contains(ch.Listen, ":") {
			return fmt.Errorf("链 %s: listen 应为 host:port，当前 %q", ch.Name, ch.Listen)
		}
		if c.Gost.Enabled && strings.TrimSpace(ch.Forward) == "" {
			return fmt.Errorf("链 %s: 开了 gost 托管就必须填 forward（上游转发 URL）", ch.Name)
		}
	}
	for i, r := range c.Routes {
		if !seen[r.Chain] {
			return fmt.Errorf("第 %d 条规则(%s): 引用了不存在的链 %q", i+1, r.Target, r.Chain)
		}
	}
	if !strings.Contains(c.Relay, ":") {
		return fmt.Errorf("relay 应为 host:port，当前 %q", c.Relay)
	}
	return nil
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
