package config

import (
	"fmt"
	"net"

	"nethub/internal/dnsmap"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
		ns, nerr := NormalizeTargetExpr(t)
		if nerr != nil {
			return changed, dup, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（%v）", t, nerr)
		}
		for _, n := range ns {
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

	// QUIC：勾了“不拦 QUIC”的规则会放它的 UDP 443 直连 —— 这是有意为之，只如实报数。
	var quicAllow, quicRedundant []string
	for i, r := range snap.Routes {
		if !r.AllowsQUIC() {
			continue
		}
		quicAllow = append(quicAllow, fmt.Sprintf("第 %d 条", i+1))
		if r.IsDirect() {
			quicRedundant = append(quicRedundant, fmt.Sprintf("第 %d 条", i+1))
		}
	}
	if len(quicAllow) > 0 {
		out = append(out, fmt.Sprintf("✓ %s规则勾了“不拦 QUIC”：它们的 UDP 443 直连出去（不进过滤器）—— 确认这是你要的", strings.Join(quicAllow, "、")))
	}
	if len(quicRedundant) > 0 {
		out = append(out, fmt.Sprintf("⚠ %s规则已经是「直连」，直连本来就不拦 QUIC —— 那一勾是多余的", strings.Join(quicRedundant, "、")))
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
	// 回滚的是“配置内容”，不是“这台机器看日志的习惯”：
	// 备份是几天前的，里面的档位不该把现在切好的 verbose / debug 拖回 normal。
	prefs := LocalPrefs{LogLevel: logLevelOr(c.UI.LogLevel, c.UI.LogVerbose), LogLevelFile: c.UI.LogLevelFile}
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
	nc, err := Load(c.path)
	if err != nil {
		return nil, err
	}
	if nc.SetLocalPrefs(prefs) {
		// 备份里的档位与本机不同 -> 写回文件，别只改内存（否则重启又变回备份那份的档位）
		if err := nc.Save(); err != nil {
			return nil, fmt.Errorf("已回滚，但保不住本机日志档位（%s）：%w", prefs.LogLevel, err)
		}
	}
	return nc, nil
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

// SaveFile 把一份配置按**标准格式**写到指定路径（先备份旧的、原子替换），
// 不改动 c 自己的 path —— 供 CLI `-apply` 用（把校验过的新配置盖到正在用的那份上）。
//
// 与 SaveAs 的区别：SaveAs 是导出（换文件头、不备份），这里是“接管现场那份配置”，
// 走的是和程序自己保存完全一样的路径（备份 + 明文凭据 + 标准文件头）。
func (c *Config) SaveFile(path string) error {
	cp := c.Snapshot().config()
	cp.path = path
	return cp.Save()
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

// LocalResolveDomains 强制本机解析的域名列表（配置原样，界面展示用）。
func (c *Config) LocalResolveDomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.Tuning.DomainResolveLocal) == 0 {
		return nil
	}
	return append([]string(nil), c.Tuning.DomainResolveLocal...)
}

// ForceLocalResolve 这个域名是不是被指定为“必须本机解析”。
//
// 匹配用通配（`*.example.com` 不包含裸域名 `example.com`，与规则里的通配域名同一个语义）。
func (c *Config) ForceLocalResolve(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	c.mu.RLock()
	list := c.Tuning.DomainResolveLocal
	c.mu.RUnlock()
	for _, pat := range list {
		pat = strings.TrimSpace(pat)
		if pat == "" || strings.HasPrefix(pat, "#") {
			continue
		}
		if dnsmap.MatchWildcard(pat, host) {
			return true
		}
	}
	return false
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
