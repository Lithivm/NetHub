package engine

// ───────────────────── 性能实验：包路径分层计时 + 只读嗅探计数 ─────────────────────
//
// 为什么要这套东西（2026-10-15 起）：
//
//	端到端实测 5.3 MB/s（≈96 µs/包），而微基准「完整出方向改写」只要 869 ns/包 ——
//	差两个数量级的那部分在 **I/O 形态**里，不在计算里。要动它，先得知道时间花在哪一段：
//
//	  wait    —— 阻塞在 Recv 里等下一个包（内核队列 → 用户态的唤醒延迟）
//	  parse   —— 我们自己解析（udpSrcPort + parseIPv4）
//	  decide  —— 判定面（flowProc 查进程表 + 规则匹配 + 名字反查）
//	  rewrite —— 改地址 + 重算校验和（CalcChecksums 要扫过整个包）
//	  send    —— 把包注入回去（回到内核）
//
//	外加一组**独立于主循环**的只读嗅探句柄（FlagSniff|FlagRecvOnly，只收不拦）：
//	它们回答另一个问题 ——「单线程 Recv 能拉多少 pps？多开句柄能不能线性扩展？」
//	这一问直接决定「要不要把包循环做成多线程 + 按流分片」，而且**不动主流程**
//	（嗅探句柄不参与放行，业务照常跑）。
//
// 为什么不用 Go 的 CPU profile：Windows 上它把阻塞等待也计进样本，样本数能超过逻辑核数
// （实测 Total samples 571 s / 1143%，而机器只有 4 核）—— 整份 profile 不能用，
// 只能自己在关键位置掐表。见 `教训/批量收发不解决WinDivert吞吐.md`。
//
// 开关：**程序目录**下的 `perf.cfg`（不存在 = 全关，包路径上只剩一次 bool 判断）：
//
//	probe=1     分层计时 + 每 2 秒往 <日志目录>/perf.log 追一行
//	sniff=2     额外开 2 个只读嗅探句柄（各自一个死循环 Recv，只计数）
//	shards=N    包循环的分片数（**默认 1 = 不分片**）。这是留给现场的调优开关：
//	            只有“同时有多条大流量连接”时才值得开（件 2~4，见 defaultShards 的注释）。
//	sniff_filter=<WinDivert 表达式>
//	             嗅探句柄用哪份过滤器（不写 = 用主过滤器，即“和主句柄看同一批包”）。
//	             里面可以写 `{lo}` / `{hi}`（该句柄分到的源端口区间）与 `{i}`（句柄号）。
//	             典型写法：`outbound and tcp and tcp.DstPort == 1080 and tcp.SrcPort >= {lo} and tcp.SrcPort <= {hi}`
//	             —— 包只会落进一个句柄，这样才能回答“多句柄能不能并行扩展”。
//	             注意：**别用 `%` 取模**（WinDivert 的 filter 语言不支持，实测“invalid packet
//	             filter string”，句柄直接打不开）；区间比较是确定支持的。
//	             两种用法的差别很重要：
//	               · 同一批包（N 个句柄各收一份）= 纯复制开销，只会拖慢
//	               · 按流分片（不相交）= 才能真正回答“多句柄能不能并行扩展”
//	             为什么需要后者：主句柄是**串行处理**的，它看得到的那批包已经被它限速了；
//	             而要回答“值不值得把包循环改多线程”，就必须让包源绕开主句柄
//	             （实验里用 `outbound and tcp and tcp.DstPort == 1080` 指到本机台架的
//	              环回高速流：主过滤器不匹配它，零干扰）。
//
// 输出刻意写**独立的文件**而不是 nethub.log：normal 档只写业务面，这些行是仪器读数；
// 走 debug 档又会把别的内部面日志一起打开 —— 那些格式化 + 写盘会污染测量本身。

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/logbus"
)

const (
	perfCfgName  = "perf.cfg"
	perfLogName  = "perf.log"
	perfInterval = 2 * time.Second
	// maxShardSlots 分片计数的槽位数（> maxShards，留点余量；不会影响到性能）。
	maxShardSlots = 8
)

// perfTimes 一趟包处理的各个时刻（零值 = 这一步没走到）。
type perfTimes struct {
	enter   time.Time // 循环顶部（= 开始等下一个包）
	recv    time.Time // Recv 返回
	parsed  time.Time // 我们自己的解析做完
	decided time.Time // 判定面做完（准备改写/放行）
	sent    time.Time // 改写 + 校验和 + 注入全部做完
}

// perfIdleCut 超过这个时长的“等包”算**空转**（没包可收），不计入每包成本。
//
// 为什么必须切一刀：引擎一启动就阻塞在 Recv 上等包，第一个包可能几秒后才来 ——
// 那几秒会被记到“第一包的等待”上，把均值拉到毫秒级（实测 1152 µs/包，
// = 整段空转时长 ÷ 包数，对得上）。每包成本里只应留“有包在流时”的等包时间。
const perfIdleCut = time.Millisecond

// perfKind 这个包走的是哪条分支（分段口径不同，分开统计）。
type perfKind int

const (
	pkOut   perfKind = iota // 出方向：改写成 relay（走隧道）
	pkIn                    // 入方向：relay 回来的包
	pkOther                 // 其它分支（QUIC 阻断、非 TCP、直连/阻断、无规则命中）
)

type perfProbe struct {
	on     bool // 分层计时
	sniffN int  // 嗅探句柄数
	// shardsOverride >0 时强制包循环的分片数（见 perf.cfg 的 shards）——
	// 改造前后对比靠它：shards=1 就是改造前的单线程行为。
	shardsOverride int
	// sniffFilter 嗅探句柄的过滤器；空 = 用主过滤器（见文件头注释）。
	sniffFilter string

	// 窗口计数（每次输出后清零）与累计
	packets, bytes  atomic.Int64
	wPkts, wBytes   atomic.Int64
	wOut, wIn, wOth atomic.Int64

	// 分段累计（纳秒）与各自的样本数。
	// wait = 有包在流时的等包；idle = 空转（无包可收，单独算）；io = 改写+校验和+注入。
	waitNS, parseNS, decideNS, ioNS, idleNS    atomic.Int64
	nWait, nParse, nDecide, nIO, nIdle, nWhole atomic.Int64

	// lastXxx 上一次 dump 时的累计值（用来算窗口增量 → 用户态 CPU 占比）
	lastWait, lastParse, lastDecide, lastIO, lastIdle atomic.Int64

	// 每个分片各收了多少包/字节：**只看总和会被“包全落一片”骗过去** ——
	// 实测（2026-10-15）分了 4 片但 cores 还是 0.7，就是所有连接挤在同一片。
	// 下标 = 分片号，长度固定 maxShardSlots（分片数上限 4，留余量）。
	shardPkts  []atomic.Int64
	shardBytes []atomic.Int64

	// 嗅探句柄的分包计数（下标 = 句柄号）
	sniffPkts  []atomic.Int64
	sniffBytes []atomic.Int64

	file *os.File
}

// newPerfProbe 读 perf.cfg 并建好输出文件。文件不存在 → 返回一个全关的探针（零开销）。
func newPerfProbe(bus *logbus.Bus) *perfProbe {
	p := &perfProbe{}
	on, n, sniffFilter, shards := loadPerfCfg()
	p.on = on
	p.sniffN = n
	p.sniffFilter = sniffFilter
	p.shardsOverride = shards
	if !on && n <= 0 {
		return p
	}
	p.sniffPkts = make([]atomic.Int64, n)
	p.sniffBytes = make([]atomic.Int64, n)
	p.shardPkts = make([]atomic.Int64, maxShardSlots)
	p.shardBytes = make([]atomic.Int64, maxShardSlots)

	dir := perfLogDir(bus)
	f, err := os.OpenFile(filepath.Join(dir, perfLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// 打不开就退化成"只计时不输出"（别让实验工具把引擎弄坏）
		bus.Warn("性能探针：无法写 %s（%v）—— 只计时，不输出", perfLogName, err)
		return p
	}
	p.file = f
	fmt.Fprintf(f, "\n=== perf.probe 开始 %s · probe=%v sniff=%d · pid=%d ===\n",
		time.Now().Format("2006-01-02 15:04:05"), on, n, os.Getpid())
	return p
}

// effectiveShards 实验用的分片数覆盖：perf.cfg 写了 shards=N 就用它，否则用自动值。
func (p *perfProbe) effectiveShards(auto int) int {
	if p == nil || p.shardsOverride <= 0 {
		return auto
	}
	return p.shardsOverride
}

// loadPerfCfg 读程序目录下的 perf.cfg（简单 key=value，允许 # 注释）。
func loadPerfCfg() (probe bool, sniff int, sniffFilter string, shards int) {
	b, err := os.ReadFile(filepath.Join(perfDir(), perfCfgName))
	if err != nil {
		return false, 0, "", 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "probe":
			v := strings.TrimSpace(v)
			probe = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
		case "sniff":
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err == nil && n > 0 && n <= 16 {
				sniff = n
			}
		case "shards":
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err == nil && n >= 1 && n <= 16 {
				shards = n
			}
		case "sniff_filter":
			sniffFilter = strings.TrimSpace(v)
		}
	}
	return probe, sniff, sniffFilter, shards
}

// perfDir 程序目录（perf.cfg 所在）。
func perfDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// perfLogDir 日志目录：跟着 nethub.log 走（现场一致的落点），拿不到就退程序目录。
func perfLogDir(bus *logbus.Bus) string {
	if bus != nil {
		if p := bus.FilePath(); p != "" {
			return filepath.Dir(p)
		}
	}
	return perfDir()
}

// record 记一趟包。kind 决定分段口径：只有出/入方向有完整分段。shard = 哪个分片处理的（-1 = 不分片）。
func (p *perfProbe) record(pt *perfTimes, n uint, kind perfKind, shard int) {
	if p == nil || !p.on {
		return
	}
	if shard >= 0 && shard < len(p.shardPkts) {
		p.shardPkts[shard].Add(1)
		p.shardBytes[shard].Add(int64(n))
	}
	p.packets.Add(1)
	p.wPkts.Add(1)
	p.bytes.Add(int64(n))
	p.wBytes.Add(int64(n))
	switch kind {
	case pkOut:
		p.wOut.Add(1)
	case pkIn:
		p.wIn.Add(1)
	default:
		p.wOth.Add(1)
	}

	if !pt.recv.IsZero() {
		d := pt.recv.Sub(pt.enter)
		if d > perfIdleCut {
			p.idleNS.Add(int64(d))
			p.nIdle.Add(1)
		} else {
			p.waitNS.Add(int64(d))
			p.nWait.Add(1)
		}
	}
	if !pt.parsed.IsZero() {
		p.parseNS.Add(int64(pt.parsed.Sub(pt.recv)))
		p.nParse.Add(1)
	}
	if !pt.decided.IsZero() {
		p.decideNS.Add(int64(pt.decided.Sub(pt.parsed)))
		p.nDecide.Add(1)
	}
	if !pt.sent.IsZero() {
		// 这一段 = 决定之后到注入完：改地址 + 重算校验和 + Send（第一版不拆开）。
		p.ioNS.Add(int64(pt.sent.Sub(pt.decided)))
		p.nIO.Add(1)
		p.nWhole.Add(1)
	}
}

// ticker 每 2 秒往 perf.log 追一行（只读那份数据的人不需要去翻 nethub.log）。
func (p *perfProbe) ticker(stop <-chan struct{}) {
	if p == nil || p.file == nil || (!p.on && p.sniffN == 0) {
		return
	}
	go func() {
		t := time.NewTicker(perfInterval)
		defer t.Stop()
		last := time.Now()
		for {
			select {
			case <-stop:
				p.dump(time.Since(last))
				return
			case now := <-t.C:
				p.dump(now.Sub(last))
				last = now
			}
		}
	}()
}

// avg 每包平均微秒（样本为 0 时返回 0）。
func avgUs(sum, n *atomic.Int64) float64 {
	c := n.Load()
	if c == 0 {
		return 0
	}
	return float64(sum.Load()) / float64(c) / 1000
}

// dump 输出一行窗口读数，并把窗口计数清零。
func (p *perfProbe) dump(window time.Duration) {
	if p == nil || p.file == nil {
		return
	}
	sec := window.Seconds()
	if sec <= 0 {
		sec = 1
	}
	w := p.wBytes.Load()
	line := fmt.Sprintf("%s perf.probe: pps=%.0f MB/s=%.2f pkts=%d out=%d in=%d other=%d bytes=%d",
		time.Now().Format("15:04:05"),
		float64(p.wPkts.Load())/sec, float64(w)/sec/1e6,
		p.packets.Load(), p.wOut.Load(), p.wIn.Load(), p.wOth.Load(), p.bytes.Load())

	if p.on {
		wWait := avgUs(&p.waitNS, &p.nWait)
		wParse := avgUs(&p.parseNS, &p.nParse)
		wDecide := avgUs(&p.decideNS, &p.nDecide)
		wIO := avgUs(&p.ioNS, &p.nIO)

		// 窗口增量 → 「用户态真正花掉的时间 / 秒」= 占用了几个核。
		// 这是对账的关键一环：pps × 每包成本 应该就等于它。
		dParse := p.parseNS.Load() - p.lastParse.Swap(p.parseNS.Load())
		dDecide := p.decideNS.Load() - p.lastDecide.Swap(p.decideNS.Load())
		dIO := p.ioNS.Load() - p.lastIO.Swap(p.ioNS.Load())
		dIdle := p.idleNS.Load() - p.lastIdle.Swap(p.idleNS.Load())
		_ = p.waitNS.Load() - p.lastWait.Swap(p.waitNS.Load())
		cores := float64(dParse+dDecide+dIO) / sec / 1e9

		line += fmt.Sprintf(" | wait=%.1fus(%d) parse=%.2fus decide=%.2fus io=%.1fus(%d) idle=%d_s%.1f cores=%.2f per-pkt=%.1fus",
			wWait, p.nWait.Load(), wParse, wDecide, wIO, p.nIO.Load(),
			p.nIdle.Load(), float64(dIdle)/1e9, cores, wParse+wDecide+wIO)
	}
	if p.sniffN > 0 {
		line += " | sniff:"
		for i := range p.sniffPkts {
			line += fmt.Sprintf(" h%d=%.0fpps/%d", i, float64(p.sniffPkts[i].Load())/sec, p.sniffBytes[i].Load())
		}
	}
	if p.shardPkts != nil {
		// 分片是否真的分散了负载 —— 全落一片时这里一眼就能看出来。
		line += " | shards:"
		busy := 0
		for i := range p.shardPkts {
			v := p.shardPkts[i].Load()
			if v > 0 {
				busy++
			}
			line += fmt.Sprintf(" s%d=%.0fpps", i, float64(v)/sec)
		}
		line += fmt.Sprintf(" busy=%d", busy)
	}
	fmt.Fprintln(p.file, line)

	p.wPkts.Store(0)
	p.wBytes.Store(0)
	p.wOut.Store(0)
	p.wIn.Store(0)
	p.wOth.Store(0)
	for i := range p.sniffPkts {
		p.sniffPkts[i].Store(0)
	}
	for i := range p.shardPkts {
		p.shardPkts[i].Store(0)
	}
}

// close 收尾（引擎停止时调）。
func (p *perfProbe) close() {
	if p == nil || p.file == nil {
		return
	}
	p.dump(perfInterval)
	_ = p.file.Close()
	p.file = nil
}

// startSniffers 开 N 个只读嗅探句柄，每个一个死循环 Recv 并计数。
//
// 它们**不参与放行**（FlagSniff|FlagRecvOnly：包照常交给系统与应用），所以开着它们
// 业务照跑 —— 这一组数是"内核把包交到用户态"的纯上限，与我们的处理逻辑无关。
// 代价：每个句柄会各收一份拷贝，句柄越多内核侧的复制越多（这也是结论的一部分）。
func (e *Engine) startSniffers(filter string) {
	if e.perf == nil || e.perf.sniffN <= 0 {
		return
	}
	if e.perf.sniffFilter != "" {
		filter = e.perf.sniffFilter
	}
	if filter == "" {
		return
	}
	for i := 0; i < e.perf.sniffN; i++ {
		idx := i
		f := filter
		// {lo}/{hi}：把源端口 0..65535 等分成 N 段，让每个句柄只看自己那一段
		// （互不相交 = 包只落进一个句柄）。
		if strings.Contains(f, "{lo}") || strings.Contains(f, "{hi}") {
			span := 65536 / e.perf.sniffN
			lo := idx * span
			hi := lo + span - 1
			if idx == e.perf.sniffN-1 {
				hi = 65535
			}
			f = strings.ReplaceAll(f, "{lo}", strconv.Itoa(lo))
			f = strings.ReplaceAll(f, "{hi}", strconv.Itoa(hi))
		}
		f = strings.ReplaceAll(f, "{n}", strconv.Itoa(e.perf.sniffN))
		f = strings.ReplaceAll(f, "{i}", strconv.Itoa(idx))
		e.startLoop(fmt.Sprintf("perfSniff%d", idx), func() { e.perfSniffLoop(idx, f) })
	}
	e.bus.Info("性能探针：已开 %d 个只读嗅探句柄（只计数，不影响放行）filter_bytes=%d", e.perf.sniffN, len(filter))
}

func (e *Engine) perfSniffLoop(idx int, filter string) {
	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("性能探针：嗅探句柄 %d 打不开: %v", idx, err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止
	}
	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	for {
		n, err := h.Recv(buf, addr)
		if err != nil {
			return
		}
		e.perf.sniffPkts[idx].Add(1)
		e.perf.sniffBytes[idx].Add(int64(n))
	}
}
