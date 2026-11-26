package config

import (
	"fmt"

	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"nethub/internal/upstream"
)

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
