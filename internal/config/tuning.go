package config

import (
	"strings"
	"time"
)

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
