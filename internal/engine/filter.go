package engine

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"errors"
	"fmt"
	"net"
	"nethub/internal/winrun"
	"strings"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// ───────────────────────── 过滤器与工具 ─────────────────────────

// buildFilter 拼 WinDivert 过滤器。
//
// 只有“需要隧道”的区间才进来（直连规则的目标不进），带端口的规则会把端口条件
// 一并写进过滤条件 —— 这样未列入的端口在驱动层就被放行，一次用户态都不用来。
// buildMainFilter 用规则集拼主过滤器（含 DNS 接管覆盖的假 IP 段 + QUIC 的 UDP 侧）。
//
// 抽出来是为了让**启动**与**热重载**走同一条装配路径 —— 两处各写一遍必然漂移
// （最典型的漂移就是漏掉假 IP 段，表现为“接管之后应用连不上假 IP”）。
// 返回 (过滤器原文, 区间数)；返回空串表示“没有需要拦截的规则”（调用方决定怎么报）。
// buildMainFilter 只要**未分片**的原文（诊断 / 老测试用）。
// 真实启动走的是 buildMainFilters（每片一份）。
func (e *Engine) buildMainFilter(s *rules.Set, relayPort uint16) (string, int) {
	base, _, n := e.buildMainFilters(s, relayPort, 1)
	return base, n
}

// buildMainFilters 生成本过滤器：**未分片**的原文（比对 / 诊断用）+ N 份互不相交的分片。
//
// 为什么要分片（2026-10-15 实测结论）：单线程每包 44 µs，其中 43 µs 是 `h.Send()` 的
// 内核往返，而引擎**只吃 0.70 个核** —— 瓶颈是串行等待。N 个句柄 + N 个循环把这份
// 等待摊到多核上（每包只落进一个句柄）。
//
// 分片键是**客户端本地端口**（同一条连接的出 / 入方向都用它）：
//
//	· 出方向（应用 → 目标）：`tcp.SrcPort` = 应用端口
//	· 入方向（relay → 应用）：`tcp.SrcPort` = relay 端口，但 `tcp.DstPort` = 应用端口
//
// 这样同一条连接的两个方向**必然落在同一片**上 —— 否则连接状态就得跳线程共享。
//
// 踩过的坑：WinDivert 的 filter 语言**不支持 `%` 取模**（写上去句柄直接打不开），
// 分片只能写区间比较。
func (e *Engine) buildMainFilters(s *rules.Set, relayPort uint16, n int) (string, []string, int) {
	if n < 1 {
		n = 1
	}
	rs := s.FilterRanges(e.cfg.CountDirectEnabled())
	var fake *rules.Range
	if e.fake != nil {
		if r := e.fake.Range(); r != nil {
			first := rules.IP2U(r.IP.To4())
			mask := rules.IP2U(net.IP(r.Mask).To4())
			fr := rules.Range{First: first, Last: first | ^mask}
			rs = append(rs, fr)
			fake = &fr
		}
	}
	if len(rs) == 0 {
		return "", nil, 0
	}
	base := buildFilter(rs, relayPort)

	// UDP 侧（QUIC 阻断）：只拿“走链 / 阻断”的区间 ——
	// **直连目标不进来**，它们的 QUIC 我们一个包也不该碰；
	// 勾了“不拦 QUIC”（allow_quic）的规则同样不进来（见 rules.QUICFilterRanges）。
	// 假 IP 段要带上：应用拿着假 IP 去连 QUIC，那边根本没人在听，
	// 回个 ICMP 让它回落 TCP（真 IP 由 TCP 那条路换回来）。
	quicClause := ""
	if e.cfg.QuicBlockEnabled() {
		urs := rules.RangesForPort(s.QUICFilterRanges(), quicPort)
		if fake != nil {
			urs = append(urs, *fake)
		}
		if len(urs) > 0 {
			quicClause = rangeClause(urs)
			base += fmt.Sprintf(" or (outbound and udp and udp.DstPort == %d and (%s))", quicPort, quicClause)
		}
	}

	shards := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lo, hi := shardRange(i, n)
		f := buildFilterShard(rs, relayPort, lo, hi)
		if quicClause != "" {
			// UDP 没有“连接”，按源端口分片就够（同一个应用的 QUIC 包落同一片）。
			f += fmt.Sprintf(" or (outbound and udp and udp.DstPort == %d and (%s) and udp.SrcPort >= %d and udp.SrcPort <= %d)",
				quicPort, quicClause, lo, hi)
		}
		shards = append(shards, f)
	}
	// 把分片区间写进日志（debug 档）：现场若发现“只有一片在忙”，第一眼看这里
	// ——动态端口范围被改过的机器上，分片会偏。
	e.bus.Debug("filter.shards: n=%d %s", n, shardSpanText(n))
	return base, shards, len(rs)
}

// shardSpanText 列出各片覆盖的本地端口区间（日志/诊断用）。
func shardSpanText(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		lo, hi := shardRange(i, n)
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "[%d:%d..%d]", i, lo, hi)
	}
	return b.String()
}

// dynPortLo 客户端临时端口的起点（Windows 7+ 默认 49152，共 16384 个）。
// 分片必须对齐它，见 shardRange。
const dynPortLo = 49152

// shardRange 第 i 片（共 n 片）覆盖的本地端口区间。
//
// ⚠ **不能对 0..65535 平均分**：Windows 客户端的临时端口几乎全在 49152-65535，
// 平均分四段的话四条连接会**全落在最后一段**（49152-65535），其余三片空转 ——
// 分片等于没分，而现象很像“多线程改造根本没效果”。
//
// 做法：把动态范围 N 等分，**第 0 片额外把 0..49151 也包进来**（那是显式固定
// 本地端口的应用，量极小）。区间连续、比较运算即可表达，且 100% 覆盖 0..65535
// （分片漏一个端口 = 那个端口的包没人收 = 静默漏出，绝不能出现）。
func shardRange(i, n int) (int, int) {
	if n <= 1 {
		return 0, 65535
	}
	span := (65536 - dynPortLo) / n
	lo := dynPortLo + i*span
	hi := lo + span - 1
	if i == 0 {
		lo = 0 // 第 0 片从 0 起：把“非动态端口”那一段也收进来
	}
	if i == n-1 {
		hi = 65535
	}
	return lo, hi
}

// buildFilterShard 单片过滤器：TCP 两个方向各带一条本地端口区间条件。
func buildFilterShard(rs []rules.Range, relayPort uint16, lo, hi int) string {
	return fmt.Sprintf("(outbound and tcp and (%s) and tcp.SrcPort >= %d and tcp.SrcPort <= %d) or "+
		"(outbound and tcp and tcp.SrcPort == %d and tcp.DstPort >= %d and tcp.DstPort <= %d)",
		rangeClause(rs), lo, hi, relayPort, lo, hi)
}

func buildFilter(rs []rules.Range, relayPort uint16) string {
	return fmt.Sprintf("(outbound and tcp and (%s)) or (outbound and tcp and tcp.SrcPort == %d)",
		rangeClause(rs), relayPort)
}

// rangeClause 把规则区间拼成一个布尔表达式（拿掉外层的方向/协议条件）。
// 单独抽出来是因为“先接后判”的过滤器要把它放进 `not (...)` 里。
func rangeClause(rs []rules.Range) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		clause := fmt.Sprintf("ip.DstAddr >= %s and ip.DstAddr <= %s",
			rules.U2IP(r.First), rules.U2IP(r.Last))
		if len(r.Ports) > 0 {
			clause += " and (" + portFilter(r.Ports) + ")"
		}
		parts = append(parts, "("+clause+")")
	}
	return strings.Join(parts, " or ")
}

// portFilter 把端口区间拼成 WinDivert 的端口条件（形如 tcp.DstPort == 443）。
func portFilter(ps []rules.PortRange) string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.First == p.Last {
			out = append(out, fmt.Sprintf("tcp.DstPort == %d", p.First))
			continue
		}
		out = append(out, fmt.Sprintf("(tcp.DstPort >= %d and tcp.DstPort <= %d)", p.First, p.Last))
	}
	return strings.Join(out, " or ")
}

// ErrDriverBlocked 表示 WinDivert 驱动装不上，而且**几乎总是安全软件在内核层把它拦了**。
//
// 为什么值得单独一个哨兵错误：WinDivert 这时报的是 1450 ERROR_NO_SYSTEM_RESOURCES
// （「系统资源不足，无法完成请求的服务」），字面把人往内存/权限/“残留状态”上带 ——
// 实测（火绒 6.0）内核池完全健康、以管理员跑、服务条目干净、驱动签名有效，照样 1450。
// 真正的原因要看杀软自己的日志：火绒把 WinDivert64.sys 判成 BYOVD_network_redirect
// 并写了 modblock（原话在 C:\ProgramData\Huorong\Sysdiag\log.db-wal 里）。
//
// 有它之后，上层就能把“驱动被拦”和“别的原因起不来”分开报，而不是让现场去猜。
var ErrDriverBlocked = errors.New("内核驱动被安全软件拦下")

// isDriverBlocked 判断这个错是不是“被安全软件拦了”。
//
// 两个码都算：1275 ERROR_DRIVER_BLOCKED（WinDivert 文档点名的“安全软件拦截”）、
// 1450 ERROR_NO_SYSTEM_RESOURCES（火绒拦驱动时回的就是它）。
// 按错误码判，不按英文消息认 —— 消息随系统语言变，正则一漂就是虚警。
func isDriverBlocked(err error) bool {
	if err == nil {
		return false
	}
	var de divert.Error
	if errors.As(err, &de) {
		return de == divert.Error(windows.ERROR_DRIVER_BLOCKED) ||
			de == divert.Error(windows.ERROR_NO_SYSTEM_RESOURCES)
	}
	// 兜底：包装过一层、错误码拿不到了，再认一次消息里最不可能误伤的那几个词。
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no_system_resources") || strings.Contains(s, "driver blocked") ||
		strings.Contains(s, "insufficient system resources")
}

// DriverSysPath 驱动文件在哪（安全软件白名单要填的就是它）。
// 给界面「复制驱动路径」与诊断报告用 —— 它们是同一个文件，只能有一处定义。
func DriverSysPath() string { return driverSysPath() }

// driverSysPath 本程序旁边那个驱动文件 —— 安全软件的“例外/白名单”要填的就是它。
// 注意：**不是** nethub.exe。
func driverSysPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "WinDivert64.sys"
	}
	return filepath.Join(filepath.Dir(exe), "WinDivert64.sys")
}

// driverBlockHint 驱动被拦时给的那几句 —— 要能照着直接做完。
//
// 特意不写“重启系统试试”：那个提示在真因是杀软时会把人带偏一整天。
func driverBlockHint() string {
	return "  这不是真的缺资源（内核池/内存都可能是健康的）。这个错误码基本只有一种原因：" +
		"安全软件把内核驱动拦了 —— 它按文件判定，跟你把程序装在哪个目录、改不改名无关。\n" +
		"    火绒 6.0：系统防护 → 漏洞驱动拦截 → 例外驱动 → 添加 " + driverSysPath() + "\n" +
		"    360 / 腾讯管家：在驱动（内核）防护白名单里放行同一个文件\n" +
		"  只把 nethub.exe 加进信任区没用：拦的是**内核装驱动那一步**（火绒日志里发起方是 System）。\n" +
		"  加完要重启安全软件 —— 例外/白名单是它启动时读进内存的，不重启不生效。\n" +
		"  想看杀软自己的判定：C:\\ProgramData\\Huorong\\Sysdiag\\log.db-wal 里搜 WinDivert64。"
}

// driverPathMatches 看驱动服务登记的 .sys 是不是就在当前目录旁边。
// 返回 (路径相符/无法判断, 当前登记的路径)。
func driverPathMatches() (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return true, "" // 判断不了就不要动它
	}
	want := filepath.Join(filepath.Dir(exe), "WinDivert64.sys")

	out, err := winrun.Command("sc", "qc", "WinDivert").CombinedOutput()
	if err != nil {
		return true, "" // 服务不存在，WinDivert 会自己装
	}
	i := strings.Index(string(out), "BINARY_PATH_NAME")
	if i < 0 {
		return true, ""
	}
	line := string(out)[i:]
	if j := strings.IndexAny(line, "\r\n"); j >= 0 {
		line = line[:j]
	}
	if !strings.Contains(line, ".sys") {
		return true, "" // 解析不出路径就别乱动
	}
	cur := strings.TrimSpace(line[strings.Index(line, ":")+1:])
	cur = strings.TrimSpace(strings.TrimPrefix(cur, `\??\`))
	return strings.EqualFold(cur, want), cur
}

// serviceState 查服务状态（STOPPED / RUNNING / 不存在）。
func serviceState(name string) string {
	out, err := winrun.Command("sc", "query", name).CombinedOutput()
	if err != nil {
		return "MISSING"
	}
	s := string(out)
	for _, st := range []string{"RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING"} {
		if strings.Contains(s, st) {
			return st
		}
	}
	return "UNKNOWN"
}

// rebuildDriverService 把驱动服务重建到当前目录。
//
// **关键（这是踩过的坑）**：不能“停一下马上就删”。驱动还挂在内核里的时候强行删服务，
// 会留下残留状态，之后加载会一直报 1450（Insufficient system resources）——
// 而且这个错误会把人往“杀毒软件拦截”上带，很难查。
// 所以：先 stop，**轮询等它真的 STOPPED**，再 delete，**再等它真的消失**。
func rebuildDriverService(bus *logbus.Bus, oldPath string) {
	want := driverSysPath()
	bus.Warn("驱动服务指向旧路径（%s），重建为 %s", oldPath, want)

	_ = winrun.Command("sc", "stop", "WinDivert").Run()
	if !waitFor(func() bool { return serviceState("WinDivert") != "RUNNING" }, 15*time.Second) {
		bus.Warn("驱动服务 15 秒内没停下来，仍继续尝试重建")
	}
	_ = winrun.Command("sc", "delete", "WinDivert").Run()
	if !waitFor(func() bool { return serviceState("WinDivert") == "MISSING" }, 15*time.Second) {
		bus.Warn("驱动服务 15 秒内没删除干净（可能还有句柄），继续尝试")
	}
}

func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// openDivert 打开 WinDivert；首次安装驱动会失败一次（服务被创建但启动失败，
// 报 ERROR_NO_SYSTEM_RESOURCES），所以这里带重试 + 主动拉起服务。
func openDivert(bus *logbus.Bus, filter string) (*divert.Handle, error) {
	var lastErr error
	// 先直接试。【不要】一上来就动驱动服务 —— 服务重建本身有风险，
	// 而且如果服务路径只是“看起来旧”但驱动已经加载着，它其实能用。
	for attempt := 1; attempt <= 6; attempt++ {
		h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err == nil {
			if attempt > 1 {
				bus.Debug("WinDivert 第 %d 次尝试成功", attempt)
			}
			return h, nil
		}
		lastErr = err

		// 失败时区分两种情况：只在“路径确实不符”时重建服务，否则只是把服务启起来
		if ok, cur := driverPathMatches(); !ok && attempt == 1 {
			rebuildDriverService(bus, cur)
			continue
		}

		bus.Warn("WinDivert 打开失败(第 %d/6 次): %v", attempt, err)
		out, serr := winrun.Command("sc", "start", "WinDivert").CombinedOutput()
		if serr != nil {
			bus.Debug("  sc start WinDivert -> %s", strings.TrimSpace(string(out)))
		} else {
			bus.Debug("  已尝试启动 WinDivert 驱动服务")
		}
		time.Sleep(time.Duration(attempt) * 700 * time.Millisecond)
	}

	// 报错要能指向正确方向：1450/1275 基本只有一种原因 —— 安全软件把驱动在内核层拦了，
	// 别让人去查内存、权限或“残留状态”。
	if isDriverBlocked(lastErr) {
		return nil, fmt.Errorf("%w（已重试 6 次）: %v\n%s", ErrDriverBlocked, lastErr, driverBlockHint())
	}
	return nil, fmt.Errorf("重试 6 次仍失败: %w", lastErr)
}

func parseIPv4(p []byte) (src, dst net.IP, ihl int, proto uint8, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl = int(p[0]&0x0f) * 4
	if len(p) < ihl {
		return
	}
	src = net.IPv4(p[offSrcIP], p[offSrcIP+1], p[offSrcIP+2], p[offSrcIP+3]).To4()
	dst = net.IPv4(p[offDstIP], p[offDstIP+1], p[offDstIP+2], p[offDstIP+3]).To4()
	proto = p[offProto]
	ok = true
	return
}

func be16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return uint16(b[off])<<8 | uint16(b[off+1])
}

func putBE16(b []byte, off int, v uint16) {
	if off+2 > len(b) {
		return
	}
	b[off] = byte(v >> 8)
	b[off+1] = byte(v)
}

func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return "127.0.0.1"
	}
	return h
}

func portOf(hostport string) uint16 {
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0
	}
	var v uint16
	fmt.Sscanf(p, "%d", &v)
	return v
}
