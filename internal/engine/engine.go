// Package engine 是核心：用 WinDivert 在内核层拦截"目标落在规则网段内的 TCP 连接"，
// 改写地址把它劫持到本地 relay，再由 relay 经 gost 的本地 socks5 端口转发出去。
//
// 为什么这样设计（而不是 PAC / 应用配合）：
//   - 数据库协议（PostgreSQL/MySQL）、Navicat、以及任何未知客户端都不认系统代理，
//     只有驱动级透明接管才能一次覆盖全部，且应用零改动。
//   - WinDivert 的 filter 在内核层生效，只有命中网段的包进用户态，
//     其余流量（公网、视频、微信）根本不经过我们 —— 顺带天然防循环。
//
// 关键实现细节（都是实测踩出来的，别改）：
//   - 改写目标的同时**必须把源 IP 也改成 relay 的 IP**，否则 Windows 在环回口
//     丢弃"非环回源地址"的包，劫持会静默失败。
//   - 注入时保留 addr 的 Outbound 标志（Flags 的 bit1），不要去翻转它。
package engine

import (
	"errors"
	"fmt"
	"net"
	"nethub/internal/dnsmap"
	"nethub/internal/dnssniff"
	"nethub/internal/fakeip"
	"nethub/internal/tlsname"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/config"
	"nethub/internal/logbus"
	"nethub/internal/proc"
	"nethub/internal/rules"
	"nethub/internal/upstream"
)

const (
	offSrcIP   = 12
	offDstIP   = 16
	offProto   = 9
	offSrcPort = 0
	offDstPort = 2
	offFlags   = 13 // FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10
)

// connState 一条被接管的连接（隧道/直连/阻断共用一张表，按源端口索引）。
//
// 计数与时间戳用原子操作：字节累加发生在 relay 的两条拷贝协程里，包计数发生在
// packetLoop 里，两条路径并发，不能共用 e.mu（否则每个包都要抢锁）。
//
// 连接结束后条目**不删**：留着让界面能看到最后状态与字节数，由 janitor 按
// 更短的时限回收（已结束 2 分钟 / 进行中 10 分钟）。
type connState struct {
	dst     net.IP
	dport   uint16
	app     net.IP
	appPort uint16
	chain   string
	action  rules.Action
	start   time.Time

	// ruleNo / ruleName：这条连接命中了哪条规则（1 起；0 = 没命中）。
	// 日志与界面都拿它回答“为什么走了这条链”，与 chain 一样**发布后不再改**。
	ruleNo   int
	ruleName string

	// 进程名 / PID（A20）：SYN 时查一次，建 connState 前就写定 → 发布后不再改，无需加锁。
	// 空串 = 查不到（受保护进程/系统服务/已消失）——界面显示“未知”。
	procName string
	pid      uint32
	// procTries / procNext：已查几次、以及下一次最早什么时候再查。
	//
	// 为什么不缓存“查不到”，也不连着重试：实测（proc.lookup 详细日志）连接刚建时
	// 这个端口**还不在 TCP 表里**（后台 500ms 一刷，短连接总是差一拍），
	// 而连着重试三次也都在几十毫秒内用完了（表还是没刷新）。
	// 所以按**时间间隔**重试（最多 5 次、每次至少隔 200ms）：
	// 短连接只试一次（便宜），长会话（真正要排障的那些）会被后续包补上。
	procTries atomic.Int32
	procNext  atomic.Int64

	// counted 建这条条目时加过 statActive（只有走 relay 的连接加）。
	// finish 据此决定要不要扣 —— 否则直连/阻断的条目会把活跃数越扣越少。
	counted bool
	// self 这条是我们**本进程自己的探针**发起的（见 selfconn.go）：不计数、不进列表。
	self bool
	// statsOnly 这条直连连接**只有开着“直连流量统计”时才看得到**（是那个开关把它拉进内核过滤器的）。
	// 关掉那个开关后它必须从列表里消失 —— 否则界面会挂着一批“已经不再被观察”的连接，
	// 字节数也停在那一刻，看着像还在跑（用户报的不一致）。
	statsOnly bool

	// fakeName/realDst：DNS 接管相关。目标是我们发的假 IP 时，fakeName 是它对应的
	// 域名，realDst 是这个域名在本机解析出的**真实 IP**（假 IP 绝不能拿去连）。
	//
	// ⚠ st.dst 是“**应用实际连的那个地址**”（假 IP 场景下就是假 IP），**发布后不再修改**：
	//   - rewriteInbound 必须用它作回包源地址，否则应用内核不认（它连的是假 IP）；
	//   - 它同时还被 Conns/recentTargets/checkUnrelayed 在锁下读，改了就是数据竞争。
	// 真实 IP 只用于拨号与展示，存在 realDst（原子，允许在包路径之外写）。
	fakeName string
	realDst  atomic.Value // net.IP：本机解析出的真实 IP（未解析到时为 nil）

	// killMu 保护下面三个字段：用户**手动结束一条连接**用（不在包路径上，所以加锁不影响性能）。
	//
	// c   = 应用侧那条（relay accept 来的）；up = 上游侧（拨通后才有，拨号期间为 nil）。
	// killed = 已经结束过了（防手滑连点，也防“拨号期间点结束”后白连一条上游）。
	killMu sync.Mutex
	c      net.Conn
	upConn net.Conn
	killed bool

	last    atomic.Int64  // unix nano：最后一次看到包/数据的时间
	up      atomic.Uint64 // 应用 → 目标 的字节（环回直连含回包时按方向分账，见 passCount）
	down    atomic.Uint64 // 目标 → 应用 的字节
	packets atomic.Uint64 // 包数（直连/阻断时用得上）
	ended   atomic.Bool
	errText atomic.Value // string：失败原因（如隧道建立失败）

	// 速率：上面三个累计值只告诉"一共多少"，速率靠**两拍采样做差**（rateLoop）。
	//
	// 为什么把"上一拍"记在连接自己身上、而不是在引擎里留一张表：
	// 连接被回收时它的上一拍也跟着消失，不存在"表越长越大"要额外清扫的问题；
	// 端口被复用时会新建一个 connState，上一拍自然归零，**不会算出跨两条连接的速度**。
	//
	// 用原子：采样在 rateLoop 里，包路径在同一时刻还在加 up/down。
	rateUp   atomic.Uint64 // 字节/秒（采样结果，界面直接读）
	rateDown atomic.Uint64
	prevUp   atomic.Uint64 // 上一拍的字节数
	prevDown atomic.Uint64
	prevAt   atomic.Int64 // 上一拍的时刻（unix nano；0 = 还没采过）

	// relayed / unrelayed：看门狗用（真实事故，见 AGENTS.md）。
	// relayed = relay 真的收到了这条连接（handleConn 开始处理时置位）；
	// 如果 SYN 被改写注入后**迟迟没有**送达 relay，客户端会卡到 SYN 重传耗尽（约 30s）
	// 然后重试 —— 而旧版代码在这条路径上一条日志都不打，看着“一切正常”。
	relayed   atomic.Bool
	unrelayed atomic.Bool
}

type Engine struct {
	bus *logbus.Bus
	// rules 当前生效的规则集。用**原子指针**而不是普通字段：规则可以热替换
	// （见 ReloadRules），而包路径上每个包都要匹配一次 —— 不能被锁挡住，
	// 也不能读到半更新的状态（读到旧集或新集都可以，读到半个就是崩溃）。
	rules atomic.Pointer[rules.Set]
	cfg   *config.Config

	mu sync.RWMutex
	// handles 主过滤器的**分片**句柄（N 份，见 buildMainFilters 的注释）。
	//
	// 为什么要 N 个而不是 1 个：实测（2026-10-15）单线程每包 44 µs，其中 43 µs 花在
	// `h.Send()` 的内核往返上，而引擎**只吃 0.70 个核** —— 瓶颈是串行等待，不是算力。
	// N 个句柄 + N 个循环把这份等待摊到多核上（每包只落进一个句柄，互不相交）。
	handles []*divert.Handle
	// mainStops 与 handles 一一对应：热重载 / 停止时靠它告诉对应循环
	// “不是在出错，是我们在换 / 停”（否则会被当成过滤器失效去重建）。
	mainStops []chan struct{}
	// mainFilter 主过滤器**未分片**的原文：只用于「过滤器没变就不折腾句柄」的比较
	// 与诊断显示（分片后每份都不同，逐份比对没有意义）。
	mainFilter string
	// mainRanges 主过滤器里的地址区间数（诊断页“接管状态”卡直显，不用重算）
	mainRanges int
	// shards 分片数（1 = 不分片，行为与改造前基本一致）。默认 1，见 defaultShards。
	shards int
	// dynHandle 第二只句柄：只装「通配域名当前覆盖到的 IP」。
	// 通配域名没法主动解析，只能等观察到应用的 DNS 应答才知道 IP，
	// 所以它必须可热替换（先开新的、再关旧的，中间不丢包）。
	dynHandle *divert.Handle
	dynStop   chan struct{}
	dynFilter string
	dynAt     time.Time
	// dnsSeen/dnsLearn/sniLearn 只读嗅探的统计（界面与日志用）。
	dnsSeen  atomic.Uint64
	dnsLearn atomic.Uint64
	sniLearn atomic.Uint64
	// quicBlocked 累计拦下的 QUIC 包数；quicNotices 是日志去重（目标 → 上次报的时间，
	// 一次浏览能刷出上百个 QUIC 包，逐个记会把日志淹掉）。
	quicBlocked atomic.Uint64
	quicNotices map[string]time.Time
	// onceAt 通用的“这件事刚说过”记录（见 noteOnce）：键 → 上次说的时刻。
	// 只给“重复出现也没有新信息”的日志用（如同一个域名又用了 ECH）。
	onceAt map[string]time.Time
	// fake/injector/tookOver/tookSeen：DNS 接管（发假 IP）。
	fake     *fakeip.Pool
	injector *divert.Handle // filter=false 的“只塞”句柄

	// 只读噢探句柄（dnsLoop / sniLoop 各自 Open 的）：它们阻塞在自己的 Recv 上，
	// 关 e.done 唤醒不了 —— Stop 必须主动 Close，否则 wg.Wait() 卡住、退不出去。
	sniffMu      sync.Mutex
	sniffHandles []*divert.Handle
	sniffClosing bool
	tookOver     atomic.Uint64
	tookSeen     map[string]bool
	// netChangedAt 本机网络签名最后一次**真变化**的时刻（localNetLoop 写、DNS 自检读）。
	// 唤醒/插拔网线/换 Wi-Fi 之后那几秒本机 DNS 本来就不可用，自检据此让一步
	// （见 netChangedWithin），别让“机器刚醒”变成“我们把 DNS 弄坏了”。
	netChangedAt atomic.Int64
	// dnsRetry 自检失败后的复测间隔（0 = 用 dnsSelfCheckRetry）。
	// 只给用例用：真等 20 秒的测试没人跑。
	dnsRetry time.Duration
	dnsBox   *dnsBlackbox // 排查用：DNS 黑匣子（tuning.dns_blackbox 打开时才有）
	// tunBlocked 本机已有别的 TUN 模式代理在接管流量（检测到就自动让路）。
	// 每次 Start 都要重新问一次：上一轮开着 Clash TUN、这轮关掉了，
	// 如果这个标记不复位，我们会一直“让路”（不学名字、不接管 DNS）却谁也看不出来。
	tunBlocked bool
	// dohSeen 已报过的加密 DNS 端点（避免刷屏）。
	dohSeen map[string]bool
	// dynDirty/dynLast 动态过滤器的重建节流（见 onWildcardsChanged）。
	dynDirty chan struct{}
	dynLast  atomic.Int64
	ln       net.Listener
	relay    string
	conns    map[uint16]*connState
	notices  map[uint16]noticeSeen    // 直连/阻断日志去重：源端口 → 上次报过的动作+目标
	health   map[string][]*upHealth   // 每条链的上游健康（与 Upstreams() 下标对齐）
	targets  map[string]*targetHealth // 业务目标巡检结果（按 ip:port 索引）
	round    int                      // 轮询策略的游标
	run      bool

	// 统计
	statTotal   uint64
	statActive  int
	statPerRule map[string]uint64
	// stats 统计页的两个维度累计桶与合计（「统计」页的数据源，见 stats.go）。
	stats *statBoard
	// rateUp/rateDown：全表速率合计（字节/秒，出/入方向），由 rateLoop 每秒更新。
	// 界面顶栏/连接页汇总量每次轮询直接读，不必自己遍历连接表。
	//
	// ⚠ 它只算**当前还开着**的连接（已结束的会被归零）——所以不能拿来画历史曲线：
	// 一个 200ms 就结束的 HTTP 请求，在下一秒采样时已经不在了，图上就是 0
	// （2026-10-14 实测：curl 跑了 6 轮，Rates() 一直是 0）。画图请用下面的字节总数做差。
	rateUp   atomic.Uint64
	rateDown atomic.Uint64

	// 字节总数（自本次运行起，走链路的 / 直连的分开记）—— 顶栏流量图的数据源，
	// sampler 每秒读一次做差就是“这一秒传了多少”。
	//
	// 与 rateUp/rateDown 的关键区别：**累计量**。短连接结束后它的字节仍然留在总数里，
	// 所以历史曲线不会被瞬时归零吞掉；代价是只能看到“每秒多少”，看不出逐连接速率。
	tunUp   atomic.Uint64
	tunDown atomic.Uint64
	dirUp   atomic.Uint64
	dirDown atomic.Uint64

	// probing 正在飞的探测（链名 → 在飞次数）；probeRound 正在跑的探测轮数。
	//
	// 为什么要专门记这个状态：探测是**对上游可见**的动作（TCP+TLS+认证+试连一次），
	// 一轮要几秒。而它的结果写回健康表之前，界面上的“待探测”与“探测中”长得一模一样 ——
	// 用户看到的是“切进来显示待探，过一秒自己好了”，不知道到底要不要手点
	// （2026-10-09 用户报的困惑）。所以把“正在探”变成一个能被界面读到的状态。
	//
	// 计数而不是布尔：定时探测与手动探测会叠在同一条链上（探测按链顺序做，一轮可能几十秒）。
	probing    map[string]int
	probeRound atomic.Int32

	// targetRounds / targetCount：业务目标巡检的状态（同上：界面必须看得出“正在巡检”）。
	// 巡检比探测更慢（每个目标都要经隧道连一次，超时 5 秒），所以“点了没反应”的窗口更长。
	targetRounds atomic.Int32
	targetCount  atomic.Int32
	// startedAt 本次启动的时刻（诊断页“运行时长”用）。
	startedAt time.Time
	// statSummaryAt 上一次“5 分钟概览”时的累计连接数（算增量用）。
	statSummaryAt uint64
	// selfPorts 本进程自己探针正在用的本地端口（见 selfconn.go）——
	// 建条目时靠它认出“这不是应用流量”。同一个锁保护。
	selfPorts map[uint16]time.Time

	// hist / histMu：连接历史存档（见 connhist.go）。
	// 定长环形，不参与热路径锁；界面「历史连接」展开区按需拉。
	histMu sync.Mutex
	hist   []ConnHist

	// startMu 串行化 Start/Stop：两者都要能在同一个 Engine 上反复调用
	// （托盘“停止 → 启动”、界面重启都会走到），且不能互相插队。
	startMu sync.Mutex
	stopped bool // 已停过（Stop 幂等用；Start 时清掉）

	// fatalMu/fatal 记下“拦截已中断”的原因（驱动被卸载、句柄被抢等）
	fatalMu sync.Mutex
	fatal   error

	// loop 环路检测（A14）：与其它代理共存时发现自己打转
	loop *loopGuard
	// perf 性能实验探针（见 perf.go）：默认全关，包路径上只剩一次 bool 判断。
	perf *perfProbe

	// unrelayedNotified 上次因“包没送到 relay”弹应用内提示的时间（节流用）
	unrelayedNotified time.Time

	// cap 抓包（A19）：按需把包写成 pcap
	cap *capturer

	// relayConns 在途的 relay 连接（Stop 时逐个关掉）。
	// 以前这些连接不进 wg 也不被关：界面说“已停止”了，隧道还在转发；
	// 而它们跨轮结束后还会去扣**新一轮**的活跃数。
	relayConns map[net.Conn]struct{}

	// pool 预热连接池（A11）：养着“已握手、只差 CONNECT”的会话
	pool *warmPool

	// proc 端口→进程（A20）：只在规则里写了进程条件时才查（见 rules.NeedsProc）
	proc *proc.Resolver

	// sockH / reflectH：WinDivert 的 SOCKET 与 REFLECT 层（详见 divertwatch.go：
	// SOCKET 的 connect 事件给进程名，REFLECT 答"还有谁在用 WinDivert"）。
	sockH, reflectH *divert.Handle
	// divertPeers 别的在用 WinDivert 的进程（pid → 层/优先级/flags）；
	// peersReported 表示"启动时那批"已经汇总过（之后的才逐条告警，避免开机刷一屏）。
	divertPeers   map[uint32]divertPeer
	peersReported bool

	// names 域名↔IP 映射（域名规则 + 把域名交给上游都用它）
	names *dnsmap.Map

	done chan struct{}
	wg   sync.WaitGroup

	// Notify 由上层（App）注入：把"状态变化"变成应用内提示。
	// 第二个参数为 true 表示是不好的消息。
	Notify func(title, text string, bad bool)
}

func New(bus *logbus.Bus, rs *rules.Set, cfg *config.Config) *Engine {
	e := &Engine{
		bus: bus, cfg: cfg,
		conns:       map[uint16]*connState{},
		statPerRule: map[string]uint64{},
		stats:       newStatBoard(time.Now()),
		selfPorts:   map[uint16]time.Time{},
		done:        make(chan struct{}),
		pool:        newWarmPool(),
		loop:        newLoopGuard(),
		cap:         newCapturer(),
		proc:        proc.NewResolver(),
		names:       dnsmap.New(),
		dynDirty:    make(chan struct{}, 1),
		// quicNotices 必须在这里建好：向 nil map 写入会 panic，而在 GUI 构建里
		// （-H=windowsgui，没有控制台）goroutine 的 panic 是**静默**的 ——
		// 整个进程直接消失、日志里一个字都没有。实测踩过这一下。
		quicNotices: map[string]time.Time{},
	}
	e.rules.Store(rs)
	// 性能探针先起来：它的 perf.cfg 里可以强制分片数（shards=N），
	// 改造成败的对比实验靠这一项把“改造后”退回到“改造前”（N=1）。
	e.perf = newPerfProbe(bus)
	e.shards = e.perf.effectiveShards(defaultShards())
	return e
}

// maxShards 分片数上限（通过 perf.cfg 打开时才用得着）。
//
// 实测瓶颈是“每包一次内核往返”的串行等待，理论上限就是核数；而现场机器多是 2~4 核，
// 再多分片只会抢 CPU。
const maxShards = 4

// defaultShards 默认分片数：**1（不分片，行为与改造前完全一致）**。
//
// 为什么做完又默认关掉（2026-10-15）：
//
//	· 分片只对“同时有多条**大流量**连接”有用（台架实测 8 连接 × 16 MB：15.5 → 27 MB/s，+76%）
//	· 而现场的业务连接是 **1.1 KB 级**（日志里 6178 条 `down=1.1 KB`，见 KB 的基准文档），
//	  吞吐从来不是瓶颈 —— 一次请求的耗时由**上游 RTT**（几十 ms）主导；
//	  多路大流量下载在内网场景几乎不存在
//	· 而代价是真实的：每包成本 45 → 60~90 µs（4 片时翻倍），因为 WinDivert 对
//	  **每个句柄都要评估一遍 filter**；单连接还会略慢 5~8%
//
// 所以分片留成**可选开关**（perf.cfg 写 `shards=2..4`）而不是默认行为。
// 实现保留、有测试、默认关闭即零风险；将来真有批量传输场景，改一个数就能开。
func defaultShards() int { return 1 }

// ruleSet 当前生效的规则集（永不为 nil，New 已装入；ReloadRules 只换非 nil 的）。
func (e *Engine) ruleSet() *rules.Set { return e.rules.Load() }

// startLoop 起一个受 WaitGroup 跟踪、且有 panic 兜底的常驻协程。
//
// 每个循环各自 Add(1)，**不要用固定数字** —— 条件分支一多就必然算错：曾经写成
// Add(10)，而没有通配域名规则（或命中 TUN 让路）时只起了 8 个，于是 Stop 里的
// wg.Wait() 永远不返回；开了 TLS 嗅探又多一次 Done，直接把计数打成负数 panic。
//
// 兜底 panic 为什么必需：GUI 构建没有控制台（-H=windowsgui），goroutine 里的 panic
// 会把整个进程直接带走，而 stderr 无处可去 —— 现场只能看到“程序突然没了”，
// 日志里一个字都没有，连个下手的地方都没有（实测踩过）。
func (e *Engine) startLoop(name string, fn func()) {
	e.wg.Add(1)
	go e.guard(name, fn)
}

// guard 跑一个循环并兜住 panic。
//
// 循环自己 defer 的 wg.Done() 在 panic 展开时**照常执行**，所以计数不会漏；
// 这里只负责把栈写进日志、把引擎置成“已中断”，再把消息弹给用户。
func (e *Engine) guard(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			e.reportPanic(name, r)
		}
	}()
	fn()
}

// reportPanic 把一个 panic 变成“能查的东西”：日志里有栈、界面/托盘有提示。
func (e *Engine) reportPanic(name string, r any) {
	err := fmt.Errorf("%s 内部错误: %v", name, r)
	e.bus.Error("engine.panic: loop=%s err=%v", name, r)
	for _, line := range strings.Split(string(debug.Stack()), "\n") {
		e.bus.Error("    %s", line)
	}
	e.setFatal(err)
	if e.Notify != nil {
		e.Notify("引擎内部错误", fmt.Sprintf("%s 出错了：%v（已在日志里记下调用栈，请重启服务）", name, r), true)
	}
}

// trackSniff 登记一个只读噢探句柄；返回 false 表示已经在停止中（调用方直接退出即可）。
func (e *Engine) trackSniff(h *divert.Handle) bool {
	e.sniffMu.Lock()
	defer e.sniffMu.Unlock()
	if e.sniffClosing {
		return false
	}
	e.sniffHandles = append(e.sniffHandles, h)
	return true
}

// closeSniffHandles 关闭所有只读噢探句柄（Stop 时调，用来唤醒卡在 Recv 的循环）。
func (e *Engine) closeSniffHandles() {
	e.sniffMu.Lock()
	e.sniffClosing = true
	hs := e.sniffHandles
	e.sniffHandles = nil
	e.sniffMu.Unlock()
	for _, h := range hs {
		h.Close()
	}
}

// PoolStats 预热连接池的近况：命中次数、建了多少、当前养着几条。
func (e *Engine) PoolStats() (taken, made, warm uint64) { return e.pool.stats() }

// Running 是否在拦截中。
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.run
}

// RelayAddr 当前 relay 监听地址。
func (e *Engine) RelayAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.relay
}

// RuleCount 当前生效的规则条数（运行态自报用：外部据此核验“热重载到底吃进去没有”）。
func (e *Engine) RuleCount() int { return len(e.ruleSet().List()) }

// Stats 返回 (累计连接数, 当前活跃数)。
func (e *Engine) Stats() (uint64, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statTotal, e.statActive
}

// Start 启动拦截。返回后即处于运行状态。
func (e *Engine) Start() error {
	e.startMu.Lock()
	defer e.startMu.Unlock()

	e.setFatal(nil)      // 重新启动就清掉“已中断”状态
	e.tunBlocked = false // 上一轮的让路结论不带进这一轮（见字段注释）
	e.mu.Lock()
	if e.run {
		e.mu.Unlock()
		return fmt.Errorf("已在运行")
	}
	// 允许 Stop 之后再 Start：done/stopped 是“一次性”的，在这里重置。
	// 托盘与界面都有“停止 → 启动”这条路径，不重置的话新协程会立刻读到已关闭的 done。
	e.done = make(chan struct{})
	e.stopped = false
	// 字节总数也归零：顶栏流量图靠**两拍做差**，跨运行不清就会把上一轮的
	// 字节数算成“这一秒突然涨了多少”（重启瞬时出现一个巨大的假尖峰）。
	e.tunUp.Store(0)
	e.tunDown.Store(0)
	e.dirUp.Store(0)
	e.dirDown.Store(0)
	// 清掉上一轮遗留的连接表与活跃计数（句柄、relay 都是新的）
	e.conns = map[uint16]*connState{}
	e.notices = nil
	e.statActive = 0
	// 历史存档也清：它记的是“这次运行发生过什么”，跨运行混在一起看时间会误导
	// （界面上是先入托盘重启、再打开看的那种用法很常见）。
	e.histMu.Lock()
	e.hist = nil
	e.histMu.Unlock()
	// 动态过滤器也要清：旧句柄已在 Stop 里关了，如果不清 dynFilter，
	// 重启后 rebuildDynFilter 会因为“过滤器字符串没变”直接 return，
	// 于是通配域名的第二只句柄永远建不起来（静默失效）。
	e.dynHandle, e.dynStop, e.dynFilter, e.dynAt = nil, nil, "", time.Time{}
	// 主过滤器同理：句柄与过滤器原文一起重置，否则重启后主句柄的字段指向旧句柄。
	e.mainStops, e.mainFilter = nil, ""
	e.mu.Unlock()
	e.sniffMu.Lock()
	e.sniffClosing, e.sniffHandles = false, nil
	e.sniffMu.Unlock()
	if e.proc != nil {
		e.proc.Start() // 端口→进程 的后台刷新（幂等、可重启）
	}
	// SOCKET 层：应用 connect() 那一刻就带 PID，补上"刷表 500ms 快照"那段盲窗（见 divertwatch.go）。
	e.startDivertNameFeed()
	// REFLECT 层：把"还有谁在用 WinDivert"变成一句确定的话（拦包被抢时不再靠猜）。
	e.startDivertReflect()

	// 1) 先起 relay，拿到真实端口（端口可能配的是 0=自动分配，过滤器要用它）
	ln, err := net.Listen("tcp", e.cfg.RelayAddr())
	if err != nil {
		return fmt.Errorf("relay 监听 %s 失败: %w", e.cfg.RelayAddr(), err)
	}
	relay := ln.Addr().String()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 域名规则：先把域名解析成 IP（供匹配与过滤器用），再装配过滤器。
	// 必须在 buildFilter 之前 —— 否则这些 IP 不在过滤器里，包根本不到我们手上。
	// （实测 0ms：域名规则本来就少，hosts 里的名字还是直接查文件的）
	e.resolveHostTargets(false)

	// 启动时读一次 Windows DNS 客户端缓存：把“NetHub 启动之前就解析过”的名字
	// 也灌进名字表（顺带覆盖系统级 DoH —— 那种场景看不到明文报文，但缓存照写）。
	//
	// ⚠ 必须放**后台**：本机实测这一步要 16.3 秒（缓存条目多 + 逐条 DnsQuery_A），
	// 而它只补“按名字匹配的覆盖面”，不影响服务立即可用 —— 以前“服务已就绪”
	// 就被它噎住 16 秒（点完启动半天没反应）。它只动名字表，结果经
	// applyHostIPs → 动态过滤器补上（先开新句柄再关旧的，零丢包）。
	if e.ruleSet().HasWildcards() {
		// seedDNSCache 要 16s 且中途不可中断：**不计入 wg**，否则退出/重启要等它。
		// 它只写名字表（线程安全），跑完顺带重建过滤器，不跑完也不影响服务可用。
		go e.seedDNSCache()
	}

	// DNS 接管（发假 IP）：池子在这里建，它覆盖的**整段**假 IP 要进主过滤器 ——
	// 应用拿到假 IP 后会去连它，那段地址不在过滤器里的话包到不了我们手上。
	var fakeRange *net.IPNet
	if e.ruleSet().HasWildcards() && e.cfg.DNSTakeoverEnabled() {
		pool, perr := fakeip.NewPool(e.cfg.FakeIPRangeOr())
		if perr != nil {
			e.bus.Error("DNS 接管：假 IP 段不可用（%v）—— 退回只读嗅探（域名通配仍能用，但首次连接可能漏）", perr)
		} else {
			e.fake = pool
			fakeRange = pool.Range()
		}
	}

	// 2) 用规则区间拼内核过滤器（直连规则的目标不进过滤器，见 rules.FilterRanges）
	base, shards, nrange := e.buildMainFilters(e.ruleSet(), port, e.shards)
	if len(shards) == 0 {
		ln.Close()
		return fmt.Errorf("没有需要拦截的规则（只填了直连规则时无事可做）")
	}
	if fakeRange != nil {
		e.bus.Debug("DNS 接管：假 IP 段 %s 已并入过滤器", fakeRange)
	}
	// 汇总写一行，**完整原文只在 debug 档里**（见 DumpState —— 切档时也会补一份，
	// 不再只有启动那一下能看到）。
	//
	// 为什么不能直接打全文（实测：3KB 一行的“天书”占满了运行日志页，现场根本读不下去）：
	// 普通模式下需要知道的是“内核收了哪些网段/多少个区间/包不包 QUIC”，
	// 排查“某个包到没到我们手上”时才需要完整条件 —— 所以拆两层：
	// normal 给数据，debug 给原文。
	e.bus.Info("filter.main: rules=%d ranges=%d tcp_clause=%d udp_quic=%v relay_port=%d bytes=%d",
		len(e.ruleSet().List()), nrange, len(shards), e.cfg.QuicBlockEnabled(), port, len(base))

	// 3) 打开 WinDivert（含首次安装驱动的重试）：**每片一个句柄** ——
	// 这是把“每包一次 Send 的串行等待”摊到多核上的地方，所以句柄数 == 分片数。
	handles := make([]*divert.Handle, 0, len(shards))
	stops := make([]chan struct{}, 0, len(shards))
	for i, f := range shards {
		h, herr := openDivert(e.bus, f)
		if herr != nil {
			for _, hh := range handles {
				hh.Close()
			}
			ln.Close()
			return fmt.Errorf("WinDivert 打开失败（分片 %d/%d）: %w", i+1, len(shards), herr)
		}
		handles = append(handles, h)
		stops = append(stops, make(chan struct{}))
	}
	e.mu.Lock()
	e.ln, e.relay, e.handles, e.mainStops, e.mainFilter, e.mainRanges, e.run = ln, relay, handles, stops, base, nrange, true
	e.startedAt = time.Now()
	e.stats.beginRun(e.startedAt) // 「本次运行」口径从这一刻开始数（累计口径不动，见 stats.go）
	e.mu.Unlock()

	e.bus.Info("engine.start: relay=%s rules=%d", relay, len(e.ruleSet().List()))
	// 规则表 / 链表 / 过滤器原文这些**装配信息**现在由 DumpState 统一写（debug 档）：
	// 启动时调一次，切档时再调一次 —— 两处共用一份实现，不会再“只有重启才看得到”。
	if e.cfg.BuiltinDirectEnabled() {
		e.bus.Debug("builtin.direct: tcp dport=%d 直连（Windows 更新传递优化；关掉：tuning.builtin_direct_disabled: true）",
			builtinDirectPort)
	}

	e.startLoop("acceptLoop", e.acceptLoop)
	// 每片一个包循环：它们只看自己那一段本地端口，互不相交（故不需要跨线程共拿连接表锁）。
	for i := range handles {
		hh, ss := handles[i], stops[i]
		e.startLoop(fmt.Sprintf("packetLoop%d", i), func() { e.packetLoop(hh, ss, loopMain, i) })
	}
	if len(handles) > 1 {
		// 分片是**非默认**状态（默认单句柄）：开着的时候值得在 normal 档说一声 ——
		// 否则现场看到“多核都吃满”会以为是别的东西。
		e.bus.Debug("engine.shards: %d 个包循环（每片一个句柄；改回单线程：perf.cfg 写 shards=1）", len(handles))
	}
	// 性能探针（perf.cfg 打开时才真的做事）：分层读数的输出循环 + 只读嗅探句柄。
	// 放这里是因为嗅探要**复用主过滤器** —— 它必须和主句柄看同一批包，否则那一组数不对应。
	e.perf.ticker(e.done)
	e.startSniffers(base)
	e.startLoop("janitor", e.janitor)
	e.startLoop("relayWatch", e.relayWatch)
	e.startLoop("nameLoop", e.nameLoop)
	e.startLoop("healthLoop", e.healthLoop)
	e.startLoop("targetLoop", e.targetLoop)
	e.startLoop("localNetLoop", e.localNetLoop)
	e.startLoop("rateLoop", e.rateLoop)
	// 只读嗅探 DNS + SNI/Host：只有真的用了通配域名才开（否则一分钱不花）。
	// 它们负责把“应用实际要去哪个名字”学回来，并维护动态过滤器。
	if e.ruleSet().HasWildcards() {
		// 先看本机是不是已经有别的程序在用 TUN 模式接管流量（多为 Clash/mihomo）：
		// TUN 与我们的透明接管互斥 —— 那时包根本到不了我们手上，继续“假装在工作”
		// 是最坏的结果，所以直接说清楚并**不开**嗅探/接管（把 DNS 让给对方）。
		tun := detectTun()
		if tun.Active() {
			e.bus.Error("检测到本机已有 TUN 模式的代理在接管流量：%s", tun.Summary())
			e.bus.Error("  —— TUN 模式与 NetHub 的透明接管互斥（全机流量与 DNS 都被它抓走），两者只能二选一。" +
				"域名通配的名字学习与 DNS 接管已自动让路（不启动）；请关掉对方的 TUN，或只用按 IP 段的规则")
			e.tunBlocked = true
		}
	}
	if e.ruleSet().HasWildcards() && !e.tunBlocked {
		e.startLoop("dnsLoop", e.dnsLoop)
		e.startLoop("dynFilterLoop", e.dynFilterLoop)
		// SNI/Host：应对加密 DNS（DoH/DoT）与自带解析器的客户端 ——
		// 那条路看不了 DNS，但握手是明文的。可在设置里关掉。
		if e.cfg.TLSSniffEnabled() {
			e.startLoop("sniLoop", e.sniLoop)
		}
		// 名字表跨重启保留着（学习结果不清空），但动态过滤器是上一轮关掉的，
		// 这里按当前已覆盖到的 IP 直接建起来，否则得等下一次 DNS 观测才恢复。
		e.rebuildDynFilter()
	}
	// DNS 接管：不再新开“看”的句柄（实测过：再开一只句柄即使只读，也会把整个 DNS
	// 搞熄）——看查询复用上面那只早已跑通的 dnsLoop 嗅探句柄；
	// 这里只新开一只 **filter=false** 的“只塞”句柄（什么也不匹配 → 结构上不可能
	// 影响任何流量），用来把假 IP 应答注进去。
	if e.fake != nil && e.tunBlocked {
		e.bus.Warn("DNS 接管：因本机已被 TUN 模式代理接管，本次不启动（让路）")
		e.fake = nil
	}
	if e.fake != nil {
		dh, derr := divert.Open("false", divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if derr != nil {
			e.bus.Warn("DNS 接管：注入句柄打开失败（%v）—— 退回只读嗅探", derr)
			e.fake = nil
		} else {
			e.mu.Lock()
			if e.run {
				e.injector = dh
			} else {
				dh = nil
			}
			e.mu.Unlock()
			if dh != nil {
				if e.cfg.DNSBlackboxEnabled() {
					e.dnsBox = openDNSBlackbox(dnsBlackboxPath(), 4<<20)
					e.bus.Debug("DNS 接管：黑匣子已开启（%s）—— 每个查询/每次回答都记在里面", dnsBlackboxPath())
				}
				e.bus.Debug("dns.takeover: started observe=shared-sniff inject=filter-false range=%s"+
					"（只答命中通配规则的名字：A 给假 IP；其余类型一律答“没有这条记录”——"+
					"AAAA 是防应用走 IPv6 绕过我们，其它类型是防 SVCB/HTTPS 的 ipv4hint 把真实地址漏出去）", e.fake.Range())
				e.startLoop("dnsTakeoverGuard", e.dnsTakeoverGuard)
			}
		}
	}
	// 装配完成 → debug 档立刻补一份当前状态（规则表/链表/过滤器原文/名字表/假 IP 池/内核层）。
	// 放在最后：这时句柄、动态过滤器、DNS 接管都已就位，转储才是完整的。
	e.DumpState("启动")
	return nil
}

// setFatal 记下“拦截已中断”的原因（nil = 正常）。
func (e *Engine) setFatal(err error) {
	e.fatalMu.Lock()
	e.fatal = err
	e.fatalMu.Unlock()
}

// ReasonNotRunning 没在跑的原因（给诊断页直显，省得人猜是停了还是崩了）。
func (e *Engine) ReasonNotRunning() string {
	if err := e.Fatal(); err != nil {
		return "（拦截已中断：" + err.Error() + "）"
	}
	return "（当前进程未接管；可在顶栏「接管引擎」或设置页的服务状态查看）"
}

// Fatal 拦截是否已意外中断；中断后界面不该再显示“运行中”。
func (e *Engine) Fatal() error {
	e.fatalMu.Lock()
	defer e.fatalMu.Unlock()
	return e.fatal
}

// Stop 停止拦截：关句柄（让 packetLoop 的 Recv 立刻返回）、关 relay、等协程退完。
//
// 幂等，且 Stop 之后可以再次 Start（状态在 Start 里重置）。
func (e *Engine) Stop() {
	e.startMu.Lock()
	defer e.startMu.Unlock()

	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return // 已经停过了
	}
	e.stopped = true
	handles, ln, run := e.handles, e.ln, e.run
	mainStops := e.mainStops
	dyn, dynStop := e.dynHandle, e.dynStop
	inj := e.injector
	sockH, reflectH := e.sockH, e.reflectH
	e.sockH, e.reflectH = nil, nil
	done := e.done
	running := make([]net.Conn, 0, len(e.relayConns))
	for c := range e.relayConns {
		running = append(running, c)
	}
	e.handles, e.ln, e.run = nil, nil, false
	e.mainStops = nil
	e.dynHandle, e.dynStop = nil, nil
	e.injector = nil
	e.mu.Unlock()

	e.pool.closeAll() // 池里的会话要主动关，否则退出时留下悬挂连接
	if e.proc != nil {
		e.proc.Stop()
	}

	if done != nil {
		close(done)
	}
	for _, st := range mainStops {
		if st != nil {
			close(st) // 同上：让各片的循环知道“不是出错，是我们在停”
		}
	}
	for _, h := range handles {
		if h != nil {
			h.Close() // 让 packetLoop 的 Recv 立刻返回错误
		}
	}
	if inj != nil {
		inj.Close()
	}
	// SOCKET / REFLECT 的 Recv 也靠关句柄唤醒（同一招）。
	if sockH != nil {
		sockH.Close()
	}
	if reflectH != nil {
		reflectH.Close()
	}
	e.dnsBox.Close()
	if dynStop != nil {
		close(dynStop) // 告诉动态句柄的循环“不是出错，是我们在换它”
	}
	if dyn != nil {
		dyn.Close()
	}
	if ln != nil {
		ln.Close()
	}
	// 在途 relay 连接也要关：否则界面/托盘说“拦截与隧道均已关闭”、hosts 也撤了，
	// 实际上这些隧道还在继续转发（现场表现是“停了服务业务还在跑”）。
	// 关完再 wg.Wait，能确保它们真的收尾了。
	for _, c := range running {
		_ = c.Close()
	}
	// 只读噢探句柄也要关：它们阻塞在 Recv 上，不关就永远不返回（wg.Wait 卡住）。
	e.closeSniffHandles()
	e.wg.Wait()
	if run {
		e.bus.Info("engine.stop")
	}
}

// ErrNotRunning 引擎没在跑时拒绝热重载（调用方当作“已落盘、运行实例在用旧规则”处理）。
var ErrNotRunning = errors.New("引擎没有在运行")

// ReloadRules 用新编译好的规则集替换正在跑的规则集（**不重启**引擎）。
//
// 语义（三条都要说清，界面文案也照这个写）：
//   - **新连接**按新规则判定；**已经在跑的连接不受影响** —— 它们的链/动作在建立时
//     就定好了（relay 不会中途改道），所以改规则不会踢掉正在用的业务。
//   - 内核过滤器按新区间重建：先开新句柄、再关旧句柄，中间不丢包（与动态过滤器同法）。
//     过滤器没变时（只改了链/顺序/进程条件）连句柄都不换。
//   - 学到的状态要继承：本机地址、名字表（通配域名靠它命中）。不继承＝通配规则
//     “忘掉”之前学过的名字，表现为“刚还好好的，重载后不通”。
//
// 不在这里处理的东西（改了仍要重启）：relay 端口、DNS 接管开关与假 IP 段、
// 上游拨号参数（预热池按启动时的 tuning 建）。哪些没生效由 App 说清楚。
func (e *Engine) ReloadRules(ns *rules.Set) error {
	if ns == nil {
		return errors.New("规则集为空")
	}
	// 与 Start/Stop 互斥：否则可能在 Stop 的 wg.Wait() 途中 Add(1)，那是错用法。
	e.startMu.Lock()
	defer e.startMu.Unlock()

	// 学习态继承。本机地址先照搬（localNetLoop 下一轮还会再写，这里先给上不留空窗）。
	ns.SetLocalIPs(e.ruleSet().LocalIPs())
	e.applyHostIPsTo(ns) // 名字表 → hostIPs（含通配规则命中的名字）

	rulesN := len(ns.List())
	e.mu.Lock()
	if !e.run {
		e.mu.Unlock()
		return ErrNotRunning
	}
	// 用当前**真实** relay 端口算新过滤器（配置里可能是 0=自动分配）
	newBase, newShards, nrange := e.buildMainFilters(ns, portOf(e.relay), e.shards)
	changed := len(newShards) > 0 && newBase != e.mainFilter
	e.mu.Unlock()

	if len(newShards) == 0 {
		// 新规则一条都不需要拦（全改成直连/全停用）：规则换掉，旧句柄留着。
		// 旧句柄上还会来包，但已匹配不到任何规则 → packetLoop 原样放回，不影响流量。
		e.rules.Store(ns)
		e.bus.Info("rules.reload: rules=%d ranges=0 filter=none（不再拦截任何网段）", rulesN)
		return nil
	}
	if !changed {
		e.rules.Store(ns)
		e.bus.Info("rules.reload: rules=%d ranges=%d filter=unchanged", rulesN, nrange)
		return nil
	}

	// 先开齐新句柄：开不了就当这次重载没发生（绝不半生效 —— 规则换了但包拦不到
	// 是最坏的结果：新网段的流量会静默直连出去）。
	// 能开齐再换，也是“先接后判”的同一套做法：中间不丢包。
	nhs := make([]*divert.Handle, 0, len(newShards))
	for i, f := range newShards {
		nh, err := openDivert(e.bus, f)
		if err != nil {
			for _, hh := range nhs {
				hh.Close()
			}
			return fmt.Errorf("新过滤器打开失败（分片 %d/%d，规则未生效，仍在用旧规则）: %w", i+1, len(newShards), err)
		}
		nhs = append(nhs, nh)
	}

	e.mu.Lock()
	if !e.run { // 刚好在这中间被停了
		e.mu.Unlock()
		for _, hh := range nhs {
			hh.Close()
		}
		return ErrNotRunning
	}
	oldHs, oldStops := e.handles, e.mainStops
	stops := make([]chan struct{}, len(nhs))
	for i := range stops {
		stops[i] = make(chan struct{})
	}
	e.rules.Store(ns)
	e.handles, e.mainStops, e.mainFilter, e.mainRanges = nhs, stops, newBase, nrange
	e.wg.Add(len(nhs)) // 在锁内 Add：Stop 要先拿 startMu，所以不会与 wg.Wait() 并发
	e.mu.Unlock()

	for i := range nhs {
		hh, ss := nhs[i], stops[i]
		go e.guard(fmt.Sprintf("packetLoop%d", i), func() { e.packetLoop(hh, ss, loopMain, i) })
	}
	for _, st := range oldStops {
		if st != nil {
			close(st)
		}
	}
	for _, h := range oldHs {
		if h != nil {
			h.Close()
		}
	}
	e.bus.Info("rules.reload: rules=%d ranges=%d filter.changed=true shards=%d", rulesN, nrange, len(nhs))
	return nil
}

// ───────────────────────── relay ─────────────────────────

func (e *Engine) acceptLoop() {
	defer e.wg.Done()
	e.mu.Lock()
	ln := e.ln
	e.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("relay accept: %v", err)
				return
			}
		}
		// 在途 relay 连接登记在册（见 relayConns）：Stop 时要主动关掉它们。
		// 否则进度列表里说“已停止”、hosts 已经撤了，实际上隧道还在转发数据。
		e.mu.Lock()
		if e.relayConns == nil {
			e.relayConns = map[net.Conn]struct{}{}
		}
		e.relayConns[c] = struct{}{}
		e.mu.Unlock()
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() {
				e.mu.Lock()
				delete(e.relayConns, c)
				e.mu.Unlock()
			}()
			e.handleConn(c)
		}()
	}
}

// resolveModeFor 决定一条连接的解析策略：全局 domain_resolve + domain_resolve_local 白名单。
//
// 抽成函数是为了能单测（它决定“域名是本机解还是交给上游解”，现场最容易配错的地方）：
//   - 白名单命中 → 一律 local（压过全局策略）
//   - 例外：没有域名（直接按 IP 连）时白名单无意义
//   - 假 IP 且本机解不出真实 IP 的情况不在这里 —— 那种只能交给上游（调用方另有分支）
func (e *Engine) resolveModeFor(host string, hasName bool) string {
	mode := e.cfg.DomainResolveMode()
	if hasName && e.cfg.ForceLocalResolve(host) {
		if mode != "local" {
			e.bus.Detail("resolve.force_local: name=%s（命中 domain_resolve_local，按本机解析；全局策略是 %s）", host, mode)
		}
		return "local"
	}
	return mode
}

// dialUpstream 建立到目标的上游连接。
//
// 一条链可能有多个上游（故障转移/轮询/随机）：按策略拿候选顺序，依次试，
// 第一个成功的就用；每次成/败都记进健康表（被动探测，不靠主动探也能学到东西）。
// dialUpstream 按候选顺序试上游，一个不成马上换下一个。
//
// 两个旋钮（都在 config.tuning 里，默认 5s / 10s）：
//   - 单次超时：一条上游最多等多久。半死上游（TCP 通但不回话）会吃满这个时间，
//     所以它直接决定“业务等多久才换下一条”。老的硬编码 10s 是实测 TTFB 偏高的主因。
//   - 总预算：一整次连接最多花多久，防止候选多时逐个等满。
//     拒绝型失败（端口不通）只花几毫秒，所以不会触发截断；只有超时型才吃预算。
//
// logUpstreamPick 记一行“这条连接实际用了哪个上游”（verbose 档）。
//
// 以前这一片完全是空白：链里配了多条上游、又开着故障转移/竞速/预热池时，
// 事后没有人知道流量到底走了谁 —— “两条上游都是通的，为什么这条特别慢”无从查起。
// 地址用 maskUpstream（保留协议/主机/端口、去掉凭据），日志可以往外发。
func (e *Engine) logUpstreamPick(ch config.Chain, idx int, warm bool, lat time.Duration) {
	if !e.bus.Verbose() {
		return
	}
	raws := e.cfg.UpstreamsResolved(ch)
	raw := "?"
	if idx >= 0 && idx < len(raws) {
		raw = maskUpstream(raws[idx])
	}
	how := "现拨"
	if warm {
		how = "预热会话"
	}
	e.bus.Detail("upstream.pick: chain=%s upstream=#%d/%d %s %s lat_ms=%d",
		ch.Name, idx+1, len(raws), raw, how, lat.Milliseconds())
}

func (e *Engine) dialUpstream(ch config.Chain, dst net.IP, dport uint16) (net.Conn, error) {
	return e.dialUpstreamKeyed(ch, dst, dport, "")
}

// dialUpstreamKeyed 带一个「粘性键」（一般是客户端 IP）：
// 链的策略是 hash 时，同一个键永远落到同一条上游 —— 需要"对方按来源 IP 做白名单/会话"
// 的场景就靠它（A17）。
func (e *Engine) dialUpstreamKeyed(ch config.Chain, dst net.IP, dport uint16, key string) (net.Conn, error) {
	raws := e.cfg.UpstreamsResolved(ch) // A18：还原 DPAPI 保险箱里的口令
	if len(raws) == 0 {
		return nil, fmt.Errorf("链 %s 没有配置上游", ch.Name)
	}
	per, budget := e.cfg.DialTimeoutDur(), e.cfg.DialBudgetDur()
	cands := e.candidatesFor(ch, key)

	// 预热连接池：先看池子里有没有“已握手、只差 CONNECT”的会话（A11）
	if c, ok := e.dialWarm(ch, cands[0], dst, dport); ok {
		e.afterDial(ch, cands[0])
		return c, nil
	}
	// 慢则竞速（A10）：候选有两条以上、且第一条超过 race_after 还没连上时，
	// 把其余的并发拨出去，取先成功的。
	// 为什么不是“总是并发”：平时并发会成倍放大连接数与客户端 IP 的落地请求，
	// 只有在“第一条明显慢”时才值得。实测 site-a 的 CONNECT 阶段要 620ms、site-b 只要 75ms，
	// 这一招能把业务直接拉到快链路。
	if len(cands) > 1 && e.cfg.RaceAfterDur() > 0 {
		c, ok, raced, raceErr := e.dialRacing(ch, raws, cands, dst, dport, per, budget)
		if ok {
			return c, nil
		}
		if raced {
			// 竞速已经把**所有**候选都拨过一遍了，失败就是真失败；
			// 再回退一次顺序试等于把同一批上游拨两遍（白等一个预算）。
			return nil, raceErr
		}
		// 第一条在起跑前就明确失败 → 从第二条开始顺序试（不重复第一条）
		return e.dialSequential(ch, raws, cands[1:], dst, dport, per, budget)
	}
	return e.dialSequential(ch, raws, cands, dst, dport, per, budget)
}

// dialSequential 顺序试（原行为）：一个不成马上换下一个。
func (e *Engine) dialSequential(ch config.Chain, raws []string, cands []int,
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, error) {
	start := time.Now()
	var errs []string
	for n, idx := range cands {
		el := time.Since(start)
		// 第一条无论如何都试（否则预算配小了就永远不会拨号）
		if n > 0 && el >= budget {
			msg := fmt.Sprintf("剩余 %d 条上游未尝试（已用 %s，总预算 %s）",
				len(raws)-n, el.Round(time.Millisecond), budget)
			e.bus.Warn("链 %s 拨号：%s", ch.Name, msg)
			errs = append(errs, msg)
			break
		}
		timeout := per
		if left := budget - el; left > 0 && left < timeout {
			timeout = left
		}
		c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, timeout)
		if err == nil {
			e.afterDial(ch, idx) // 用掉一条就要补一条
			return c, nil
		}
		errs = append(errs, msg)
	}
	return nil, fmt.Errorf("%s", strings.Join(errs, "\n"))
}

// tryUpstream 试一条上游，并把结果记进健康表。
//
// 注意业务拨号的失败**只作为参考**，不直接把上游判成 down（见 noteUpstream）：
// 一个坏掉的内网目标也能连着失败两次，那不代表上游挂了。
func (e *Engine) tryUpstream(ch config.Chain, raw string, idx int, dst net.IP, dport uint16,
	timeout time.Duration) (net.Conn, error, string) {
	up, err := upstream.Parse(raw)
	if err != nil {
		// 被动失败分不出"凭据被拒"与"连不上"（这里的 err 已经是包装过的文案）：
		// 不猜，统一记 false —— 真凭据被拒时探测（30s 一轮）会把它认出来。
		e.markUp(ch.Name, idx, false, 0, err.Error(), false)
		return nil, err, fmt.Sprintf("上游 %d: %v", idx+1, err)
	}
	t0 := time.Now()
	c, err := up.Dial(dst, dport, timeout)
	lat := time.Since(t0)
	if err == nil {
		// 真拨通了：这是比探测更硬的证据，可以直接把状态正过来（也顺带消掉假警报）
		e.markUp(ch.Name, idx, true, lat, "", false)
		e.logUpstreamPick(ch, idx, false, lat)
		return c, nil, ""
	}
	// 失败：只升级“疑似”，等下一次探测确认。否则一条坏业务目标
	// 连续失败两次就能把健康的上游写成 down，随后探测又报一行假的恢复。
	e.noteUpstreamSuspect(ch.Name, idx, err.Error())
	// 每条上游一行、带耗时与本次超时 —— 现场把日志整段复制给 agent 时，
	// “谁、排第几、等了多久、原始报错是什么”都在这一行里。
	// 上游地址用 maskUpstream（保留协议/主机/端口，去掉凭据）。
	return nil, err, fmt.Sprintf("上游 #%d %s（单次超时 %s，已等 %s）：%v",
		idx+1, maskUpstream(up.Raw), timeout, lat.Round(time.Millisecond), err)
}

// dialAttempt 一次拨号尝试的结果（竞速用）。
type dialAttempt struct {
	c   net.Conn
	err error
	msg string
}

// dialRacing 慢则竞速：等 raceAfter，第一条还没好就把剩下的并发拨出去，取先到的。
//
// 返回：conn（成功时）、ok（拿到连接）、raced（是否真的进过竞速阶段）。
// 　　　raced=false 表示第一条在起跑前就明确失败，调用方应从第二条开始顺序试。
func (e *Engine) dialRacing(ch config.Chain, raws []string, cands []int,
	dst net.IP, dport uint16, per, budget time.Duration) (net.Conn, bool, bool, error) {
	race := e.cfg.RaceAfterDur()
	if race <= 0 || race >= per {
		race = per / 2 // 竞速必须早于单次超时，否则没意义
	}
	t0 := time.Now()
	first := make(chan dialAttempt, 1)
	go func(idx int) {
		c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, minDur(per, budget))
		first <- dialAttempt{c, err, msg}
	}(cands[0])

	select {
	case a := <-first:
		if a.err == nil {
			return a.c, true, true, nil
		}
		// 第一条已经明确失败（被拒/解析错）→ 交给顺序试，它从第二条开始
		if a.c != nil {
			a.c.Close()
		}
		return nil, false, false, a.err
	case <-time.After(race):
	}

	// 剩下的并发拨（总超时受剩余预算约束）
	n := len(cands) - 1
	left := budget - time.Since(t0)
	if left <= 0 {
		left = per
	}
	rest := make(chan dialAttempt, n)
	for _, idx := range cands[1:] {
		go func(idx int) {
			c, err, msg := e.tryUpstream(ch, raws[idx], idx, dst, dport, minDur(per, left))
			rest <- dialAttempt{c, err, msg}
		}(idx)
	}
	e.bus.Detail("链 %s：第一条上游还没连上（等满 %.0fms），并发试其余 %d 条",
		ch.Name, race.Seconds()*1000, n)

	errs := []string{}
	readRest, firstRead := 0, 0
	for readRest < n || firstRead == 0 {
		select {
		case a := <-rest:
			readRest++
			if a.err == nil {
				// 其余候选还在跑：它们的连接成功也来不及用了，收尾时关掉
				go drainAttempts(rest, n-readRest, per)
				go drainAttempts(first, 1-firstRead, per)
				return a.c, true, true, nil
			}
			errs = append(errs, a.msg)
		case a := <-first:
			firstRead = 1
			if a.err == nil {
				go drainAttempts(rest, n-readRest, per)
				return a.c, true, true, nil
			}
			errs = append(errs, a.msg)
		}
	}
	e.bus.Warn("链 %s 竞速全失败：\n%s", ch.Name, strings.Join(errs, "\n"))
	detail := strings.Join(errs, "\n")
	if detail == "" {
		detail = "所有上游都连不上"
	}
	return nil, false, true, fmt.Errorf("链 %s：所有上游都连不上\n%s", ch.Name, detail)
}

// drainAttempts 把竞速里多余的尝试收干净：成功的连接要关掉，不能漏。
func drainAttempts(ch chan dialAttempt, n int, wait time.Duration) {
	deadline := time.After(wait + time.Second)
	for i := 0; i < n; i++ {
		select {
		case a := <-ch:
			if a.c != nil {
				a.c.Close()
			}
		case <-deadline:
			return
		}
	}
}

// minDur 取较小值（给拨号超时用）。
func minDur(a, b time.Duration) time.Duration {
	if a < b || b <= 0 {
		return a
	}
	return b
}

func (e *Engine) handleConn(c net.Conn) {
	defer c.Close()

	_, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	var sport uint16
	fmt.Sscanf(portStr, "%d", &sport)

	e.mu.Lock()
	st := e.conns[sport]
	e.mu.Unlock()
	if st == nil {
		e.bus.Warn("relay 收到未知来源连接 sport=%d，丢弃", sport)
		return
	}
	// 看门狗：relay 确实收到了这条连接（这一步以前没有任何记录，
	// 导致“包没到 relay”这种故障在日志里完全看不出来）。
	st.relayed.Store(true)
	// 登记应用侧连接：用户在连接列表里点「结束」时要能把它关掉。
	st.setClient(c)
	// 建链耗时（握手 + 认证 + CONNECT）单独量：一条连接慢到底是“上游慢”
	// 还是“传输慢”，只看总耗时是分不清的 —— 专业日志（HAProxy 的 Tc、squid 的 %tr）也都分开记。
	dialStart := time.Now()

	ch, ok := e.cfg.ChainByName(st.chain)
	if !ok {
		e.bus.Error("链 %s 不存在，丢弃 %s:%d", st.chain, st.dst, st.dport)
		return
	}

	// 域名规则命中时，按配置决定“本机解析”还是“交给上游解析”：
	//
	//	local（默认）   按本机解析出的 IP 连 —— 客户内网域名通常只有本机能解答
	//	upstream        把域名交给上游解析（同一域名两边解析不同时用）
	//	auto            本机优先，连不上再把域名交给上游试一次
	//
	// 实测教训：我们这套环境里 main.example.com 只有客户网内的 DNS 能解答，
	// 上游是公网中转服务器、解析不到（host unreachable）—— 所以不能默认透传。
	host, hasName := e.nameOf(st.dst)
	// 目标是我们发的假 IP：绝不能拿它去连（那是个不存在的地址）。
	// st.dst 保持“应用连的那个地址”（回包改写要用），真实 IP 单独放 st.realDst，
	// 拨号/展示统一走 dialDst。
	if e.isFakeIP(st.dst) {
		name := host
		st.fakeName = name
		if !hasName {
			// 池子里没这个名字：多半是重启前的旧假 IP（映射不落盘）。说清楚，别让人猜。
			e.bus.Warn("DNS 接管：连到未登记的假 IP %s:%d（NetHub 重启前发的旧应答？）—— 这一条连不上",
				st.dst, st.dport)
			st.fail("假 IP 已过期（NetHub 重启过），请重新访问一次")
			e.finish(st)
			return
		}
		real := e.resolveReal(name)
		if real != nil {
			st.realDst.Store(real)
			// 把“名字 → 真实 IP”记进名字表。两个作用：
			//  ① 界面上的通配规则能显示“已覆盖 N 个 IP”（否则接管过的名字永远是空的，
			//     看起来像“这条规则什么都不拦”—— 而它刚刚才拦过）；
			//  ② 应用第二次直接用缓存里的**真实 IP** 连过来时，也能按名字命中这条规则。
			e.noteRealIP(name, real)
			e.bus.Detail("DNS 接管：假 IP %s → %s 的真实 IP %s", st.fakeName, name, real)
		} else {
			e.bus.Detail("DNS 接管：假 IP %s → %s 本机解不开，交给上游解析", st.dst, name)
		}
	}
	dialDst := st.displayTarget() // 假 IP 已解析则用真实 IP，否则保持原地址
	// “域名→IP”这一段到此结束：它是本机解析（可能走 DNS），与“连上游”是两件事。
	// 两者分开量，慢的时候才知道该查 DNS 还是查上游（见下方 conn.stage / close 行）。
	resolveEnd := time.Now()

	// 假 IP 阶段只能按“名字”选链，可能把本该按 IP 走的连接选错
	// （宽通配如 main.*.com 抢走 198.51.100.0/24 的连接）。真实 IP 到手后，
	// 用“IP 优先”的匹配再判一次，以其为准 —— 这就是 v0.2.2 / Proxifier 的语义。
	if e.isFakeIP(st.dst) && st.action == rules.ActionChain {
		if real := st.realTarget(); real != nil {
			if chain2, act2, hit := e.ruleSet().MatchName(host, real, st.dport, st.procName); hit && chain2 != st.chain {
				switch act2 {
				case rules.ActionChain:
					e.bus.Detail("route.fixup: target=%s real_ip=%s %s → %s（真实 IP 命中更靠前的规则）",
						host, real, st.chain, chain2)
					st.chain = chain2
					if c2, ok2 := e.cfg.ChainByName(chain2); ok2 {
						ch = c2
					}
				default:
					// 真实 IP 命中直连/阻断：目前仍按原链走（罕见；给出可操作提示）
					e.bus.Warn("route.fixup: target=%s real_ip=%s 命中 %s 规则而非链 —— 仍按原链处理；"+
						"如需直连/阻断，请把该网段的规则排到前面", host, real, act2)
				}
			}
		}
	}
	mode := e.resolveModeFor(host, hasName)
	var up net.Conn
	var err error
	tryName := func() bool {
		if !hasName {
			return false
		}
		up, err = e.dialViaName(ch, host, st.dport)
		if err == nil {
			e.bus.Detail("[%s] 用域名 %s 建隧道（交给上游解析）", st.chain, host)
			return true
		}
		return false
	}
	// 假 IP 且本机解不开：只能交给上游（不能拿假 IP 当目标）。
	// 其余情况保持原有语义：按 DomainResolve 配置走 local / upstream / auto。
	if e.isFakeIP(st.dst) && st.realTarget() == nil {
		e.bus.Detail("[%s] 目标 %s 是假 IP（无真实 IP），只能交给上游解析域名 %s", st.chain, st.dst, host)
		tryName()
	} else {
		switch {
		case mode == "upstream" && hasName:
			if !tryName() {
				up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
			}
		case mode == "upstream":
			up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
		default: // local / auto：先用本机解析出的 IP
			up, err = e.dialUpstreamKeyed(ch, dialDst, st.dport, st.app.String())
			if err != nil && mode == "auto" && hasName {
				e.bus.Detail("[%s] 按 IP %s 连不上（%v），改用域名 %s 交给上游再试", st.chain, dialDst, err, host)
				tryName()
			}
		}
	}
	if err != nil {
		// 原始报错一字不改地打出来（现场是把日志整段复制给 agent 看的，
		// 任何“翻译成人话”都会把底层信息抹掉）。这里只补几项我们才知道的上下文：
		// 命中哪条链、谁发起的、以及这条链试过哪些上游。
		//
		// 进程定位不到时（系统服务的短连接、受保护进程、连接已消失）：
		// **不进 ERROR**，只打一行 INFO。两个原因：
		//  ① 对用户可操作的信息 = 0（它多半是系统的后台连接，如 Windows 传递优化连局域网邻居）；
		//  ② 以前这里会打 “PID 0” —— PID 0 在 Windows 上是空闲进程、永远不会拥有 TCP 连接，
		//     那只是我们“查不到”的哨兵值，打在日志里纯属误导（用户以为多了个进程）。
		if st.procName == "" {
			e.bus.Info("tunnel.down: chain=%s target=%s:%d proc=unknown src_port=%d err=%s",
				st.chain, dialDst, st.dport, sport, firstLine(err.Error()))
			st.fail(err.Error())
			e.finish(st)
			return
		}
		// 我们自己的探针（DialSelf）**不是业务**：它不进连接列表、不计累计、normal 档不记日志 ——
		// 隧道失败这条也一样。**探针**（DialSelf 开的连接）会周期性去探不存在的地址，
		// 按 ERROR 记就是自己给自己刷日志（实测每 60 秒一条“隧道建立失败 203.0.113.0:65533”，
		// 现场会以为真出了事故）。
		if st.self {
			e.bus.Debug("tunnel.down: chain=%s target=%s:%d proc=nethub(自检探针) src_port=%d err=%s",
				st.chain, dialDst, st.dport, sport, firstLine(err.Error()))
			st.fail(err.Error())
			e.finish(st)
			return
		}
		e.bus.Error("[%s] 隧道建立失败 %s:%d（进程 %s，PID %d，源端口 %d）",
			st.chain, dialDst, st.dport, st.procName, st.pid, sport)
		for _, line := range strings.Split(err.Error(), "\n") {
			e.bus.Error("    %s", line)
		}
		st.fail(err.Error())
		e.finish(st)
		return
	}
	defer up.Close()
	// 拨号花了多少秒都正常：用户可能在这期间点了「结束」。
	// 那就不该再开两条拷贝协程，直接把刚拨通的上游放下走人。
	if st.setUpstream(up) {
		e.finish(st)
		return
	}

	dialEnd := time.Now()
	dialMs := dialEnd.Sub(dialStart).Milliseconds()
	resolveMs := resolveEnd.Sub(dialStart).Milliseconds()
	handshakeMs := dialEnd.Sub(resolveEnd).Milliseconds()

	// 不再单记一行 relay.up：它只是中间态，成功与否看 close（字节数）、
	// 失败看 tunnel.down；每条连接两行（open 开始 / close 结束）就够现场用，
	// 也跟 Proxifier “一条连接 open/close”的粒度对得上，不再把日志刷成三段。

	done := make(chan struct{}, 2)
	// 目标**首个响应字节**的时刻（0 = 到关闭时目标一字未回）。
	// 只记下行：上行那侧的第一个字节是应用刚发的请求，它只能证明“应用很积极”，
	// 证明不了服务端多久才应 —— 那正是排查“连上了但就是慢”要看的东西。
	var firstByte atomic.Int64
	markFirst := func() { firstByte.CompareAndSwap(0, time.Now().UnixNano()) }
	go func() { copyAndClose(up, c, &st.up, e.tunTotal(st, true), nil); done <- struct{}{} }()
	go func() { copyAndClose(c, up, &st.down, e.tunTotal(st, false), markFirst); done <- struct{}{} }()
	<-done

	e.finish(st)
	// 收尾时再补一次进程名：连接刚建那一刻表还没刷新到它（实测的 proc=unknown 根因），
	// 而到收尾时表里通常已经有了（TIME_WAIT 之类的行也在表里）。
	// 每连接一次，不在包路径上。
	if st.procName == "" && e.proc != nil {
		if n, pid, ok := e.proc.ByPort(st.appPort); ok {
			e.mu.Lock()
			st.procName, st.pid = n, pid
			e.mu.Unlock()
		}
	}
	// 与 open 同形（Proxifier 的 open/close 也是同一前缀）：
	//	close: curl.exe (12376) → main.example.com(192.0.2.217):80 via site-a ↑76 B ↓279 B 884ms/997ms
	// 前一个时间是"连上游（含域名解析）"，后一个是"从发起到收尾"。
	e.connInfo(st.self, "close: %s → %s via %s ↑%s ↓%s %dms/%dms",
		connWho(st.procName, st.pid), e.connTargetDial(st.dst, dialDst, st.dport), st.chain,
		humanBytes(st.up.Load()), humanBytes(st.down.Load()),
		dialMs, time.Since(st.start).Milliseconds())
	// verbose：把“慢在哪一步”分开 —— 域名解析 / 连上游握手 / 目标首个响应。
	// normal 的 close 只有一个总数，事后分不清该查 DNS、查上游还是查服务端。
	if !st.self && e.bus.Verbose() {
		first := "未响应"
		if fb := firstByte.Load(); fb > 0 {
			first = fmt.Sprintf("%dms", time.Unix(0, fb).Sub(dialEnd).Milliseconds())
		}
		e.bus.Detail("conn.stage: %s → %s via %s resolve=%dms dial=%dms first_byte=%s total=%dms",
			connWho(st.procName, st.pid), e.connTargetDial(st.dst, dialDst, st.dport), st.chain,
			resolveMs, handshakeMs, first, time.Since(st.start).Milliseconds())
	}
}

// connInfo 连接类日志的分流：真实应用流量走 normal，**我们自己的探针走 verbose**。
//
// 为什么（2026-10-14 用户报“一启动就打印这么多日志”）：自检/共存检测会直接 dial 内网目标
// （DialSelf，见 selfconn.go）—— 它们已经不在连接列表、不计入统计了，但日志还是逐条按 normal 打，
// 于是每次开机都有一串 `proc=nethub.exe` 的“连接”，看日志的人会以为是应用在连。
// 原则与“自己的探针不当应用流量”一致：那是仪器，不是业务（要看它们就切 verbose）。
func (e *Engine) connInfo(self bool, format string, a ...any) {
	if self {
		if e.bus.Verbose() {
			e.bus.Info(format, a...)
		}
		return
	}
	e.bus.Info(format, a...)
}

// KillConn 手动结束一条连接（连接列表里点「结束」）。
//
// 现场诉求：这条连接卡死了（远端重启过、会话粘在一条坏上游上），而应用自己要等到
// 超时才肯重连。关掉两端 → relay 的两条拷贝协程自然返回 → 走正常 finish
// （统计/历史/日志都齐，与“对端断开”同一条路径，不特殊处理）。
//
// **不动判定**：应用下一拍会重新建连，走同一套规则 —— 这才是现场要的“重连”。
func (e *Engine) KillConn(sport uint16) error {
	e.mu.RLock()
	st := e.conns[sport]
	e.mu.RUnlock()
	if st == nil || st.ended.Load() {
		return fmt.Errorf("这条连接已经结束了（列表可能刚刷新）")
	}
	st.killMu.Lock()
	if st.killed {
		st.killMu.Unlock()
		return fmt.Errorf("这条连接已经结束了")
	}
	c, up := st.c, st.upConn
	if c == nil && up == nil {
		st.killMu.Unlock()
		return fmt.Errorf("这条连接不走中转（直连/阻断/还在建链），结束不了它")
	}
	st.killed = true
	st.killMu.Unlock()

	// 记一行（normal 档）：不写的话，现场会把“我手动结束的”当成网络断了，
	// 然后去查上游/驱动 —— 那是 2026-10 实际踩过的排查弯路。
	e.connInfo(st.self, "conn.kill: %s → %s via %s ↑%s ↓%s %dms by=user",
		connWho(st.procName, st.pid), e.connTargetDial(st.dst, st.displayTarget(), st.dport), st.chain,
		humanBytes(st.up.Load()), humanBytes(st.down.Load()), time.Since(st.start).Milliseconds())

	if up != nil {
		up.Close() // 先断上游：让它那侧也收到 FIN，不留下“半死”的会话
	}
	if c != nil {
		c.Close() // 再断应用：应用立刻看到断开，不等超时
	}
	return nil
}

// copyAndClose 单向拷贝并在结束后关闭写端（半关闭，双向都能正常收尾）。
//
// counter = 这条连接的字节数（界面按连接显示）；total = 走链路的字节总数
// （顶栏流量图，见 engine 的 tunUp/tunDown 注释）。两个都要加：前者是“一条多少”，
// 后者是“一共多少”——短连接结束时前者就没人看了，后者才是曲线的基础。
// total 可以是 nil：我们自己的探针不计入总量（见 tunTotal）。
func copyAndClose(dst, src net.Conn, counter, total *atomic.Uint64, onFirst func()) {
	buf := make([]byte, 32*1024)
	add := func(n int) {
		counter.Add(uint64(n))
		if total != nil {
			total.Add(uint64(n))
		}
	}
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if onFirst != nil {
				onFirst() // 首个字节（并发安全由调用方的 CAS 保证；多调几次无妨）
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				add(n)
				break
			}
			add(n)
		}
		if err != nil {
			break
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
	src.Close()
}

// ───────────────────────── 包处理 ─────────────────────────

// recoverHandle Recv 出错后的自愈：按退避重建同一只句柄，成则继续收包。
//
// 为什么要它（审计 P0-2）：主句柄一旦不可用，拦截就完全停了，但进程还活着、界面
// 还显示“运行中” —— 内网流量被系统按原路发出去（直连内网 IP，全不通），
// 只有人工重启才能恢复。触发途径实测存在：驱动被卸、安全软件临时拦、句柄失效。
//
// 退避 1s/2s/5s/10s/30s（共 ~48 秒）；期间一旦收到停止信号就立即退出。
// 新句柄先建好、再把旧句柄关掉（防止关完到重建成功这段空窗期里包没人接）。
func (e *Engine) recoverHandle(kind loopKind, stop chan struct{}, shard int) (*divert.Handle, error) {
	backoff := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}
	var lastErr error
	for i, wait := range backoff {
		select {
		case <-e.done:
			return nil, fmt.Errorf("引擎已停止")
		default:
		}
		if i > 0 {
			select {
			case <-e.done:
				return nil, fmt.Errorf("引擎已停止")
			case <-time.After(wait):
			}
		}
		filter, ferr := e.handleFilter(kind, shard)
		if ferr != nil {
			return nil, ferr // 过滤器都不在了（停止过程中）→ 不必再试
		}
		nh, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			lastErr = err
			continue
		}
		// 新句柄已经能收包了，才动旧的
		e.mu.Lock()
		var old *divert.Handle
		if kind == loopDyn {
			// 这期间可能有别的路径重建过：那就不用我们这只
			if e.dynHandle != nil {
				nh.Close()
				e.mu.Unlock()
				return nil, fmt.Errorf("动态句柄已被重建")
			}
			e.dynHandle, e.dynFilter = nh, filter
		} else {
			// 只换坏的那一片：其它分片的句柄不动（它们各自在自己的循环里跑）。
			// 下标越界 = 这中间热重载把分片换过了 → 直接放弃这只（外面会重新读 e.handles）。
			if shard < 0 || shard >= len(e.handles) {
				nh.Close()
				e.mu.Unlock()
				return nil, fmt.Errorf("分片 %d 已不在当前句柄表里（可能刚热重载过）", shard)
			}
			old = e.handles[shard]
			e.handles[shard] = nh
		}
		e.mu.Unlock()
		if old != nil {
			old.Close()
		}
		e.setFatal(nil)
		e.bus.Info("WinDivert: 句柄已重建（第 %d 次尝试）—— 拦截恢复", i+1)
		return nh, nil
	}
	return nil, lastErr
}

// handleFilter 重建句柄时用哪份过滤器：主句柄按当前规则集重算（取第 shard 片），
// 动态句柄用记着的那份。
func (e *Engine) handleFilter(kind loopKind, shard int) (string, error) {
	if kind == loopDyn {
		e.mu.RLock()
		f := e.dynFilter
		e.mu.RUnlock()
		if f == "" {
			return "", fmt.Errorf("动态过滤器没有记录")
		}
		return f, nil
	}
	_, shards, _ := e.buildMainFilters(e.ruleSet(), portOf(e.RelayAddr()), e.shards)
	if len(shards) == 0 {
		return "", fmt.Errorf("主过滤器为空（规则集为空？）")
	}
	if shard < 0 || shard >= len(shards) {
		return "", fmt.Errorf("分片索引 %d 超范围（共 %d 片）", shard, len(shards))
	}
	return shards[shard], nil
}

// loopKind 说明这只句柄是谁的 —— 决定 Recv 出错时怎么处理（这两类差别很大，
// 用 stop 是否为 nil 来区分已经不够了：热重载会让**主**句柄也带着 stop）。
type loopKind int

const (
	loopMain loopKind = iota // 主过滤器：出错＝整个引擎“拦截已中断”
	loopDyn                  // 动态过滤器（通配域名）：出错只是这部分不再接管
)

// shard 本循环负责的分片号（loopDyn 传 -1）：句柄出错重建时要按它只换自己那一片。
func (e *Engine) packetLoop(h *divert.Handle, stop chan struct{}, kind loopKind, shard int) {
	defer e.wg.Done()

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	relayIP := net.ParseIP(hostOf(e.RelayAddr())).To4()
	relayPort := portOf(e.RelayAddr())

	for {
		var pt perfTimes
		if e.perf.on {
			pt.enter = time.Now()
		}
		n, err := h.Recv(buf, addr)
		if e.perf.on {
			pt.recv = time.Now()
		}
		if err != nil {
			select {
			case <-e.done:
				return
			case <-closedCh(stop):
				return // 我们在换句柄（热重载 / 换动态过滤器），不是出错
			default:
			}
			if kind == loopDyn {
				// 动态句柄出错不能把整个引擎置成“已中断”：它只管通配域名那部分流量。
				// 但它也不能就此死掉 —— 先清掉句柄状态（让重建不再被“过滤器没变”挡回去），
				// 再退避重建；不行才放弃。
				e.bus.Warn("域名通配：动态过滤器已中断: %v（正在重建）", err)
				e.mu.Lock()
				e.dynHandle, e.dynStop, e.dynFilter = nil, nil, ""
				e.mu.Unlock()
				if nh, rerr := e.recoverHandle(kind, stop, shard); rerr == nil {
					h = nh
					continue
				}
				return
			}
			// 主句柄：**绝不能就此放弃**。
			//
			// 拦截一停，那些本该走隧道的内网目标就会被系统按原路发出去（直连内网 IP
			// = 全部不通），而进程还活着、界面还是绿的，只有人工重启才能恢复。
			// 实测触发过：驱动被卸、被安全软件拦、句柄失效。
			// 所以按退避重建；连续多次不行才判“已中断”。
			nh, rerr := e.recoverHandle(kind, stop, shard)
			if rerr == nil {
				h = nh
				continue
			}
			e.bus.Error("WinDivert Recv 失败，且重建句柄失败（最后一次: %v）：原错误 %v", rerr, err)
			e.setFatal(err) // 让界面变红「Error」—— 否则状态还说“运行中”，其实一个包都没拦
			if e.Notify != nil {
				e.Notify("拦截已中断", err.Error()+"（请重启服务）", true)
			}
			return
		}
		pkt := buf[:n]

		// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
		// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
		// 只取源端口、不取地址与载荷 —— 每个包都跑这段，udpPayload 会白白分配两块 slice。
		if sport, ok := udpSrcPort(pkt); ok && sport >= dnsProbePortLo && sport <= dnsProbePortHi {
			continue
		}

		src, dst, ihl, proto, ok := parseIPv4(pkt)
		if e.perf.on {
			pt.parsed = time.Now()
		}
		// QUIC（UDP 443）：这条包能到我们手上，说明它的目标落在“该走隧道”的网段里
		// （过滤器只装了那些范围的 UDP 443，直连目标的 QUIC 根本不经过我们）。
		// UDP 走不了隧道 —— 以前是静默直连漏出，现在丢掉并记一行（回 ICMP 是尽力而为）。
		if ok && proto == 17 {
			e.blockQUIC(h, pkt, addr, src, dst, ihl)
			e.perf.record(&pt, n, pkOther, shard)
			continue
		}
		if !ok || proto != 6 || len(pkt) < ihl+20 {
			_, _ = h.Send(pkt, addr)
			e.perf.record(&pt, n, pkOther, shard)
			continue
		}
		t := ihl
		sport := be16(pkt, t+offSrcPort)
		dport := be16(pkt, t+offDstPort)
		flags := pkt[t+offFlags]

		// 入方向：源端口 = relay 端口的包，只可能是本机 relay 回来的
		// （应用不可能正好用着 relay 占着的那个端口）。先判它，
		// 否则“只按进程”的规则会把回来的包也当出站命中。
		if sport == relayPort {
			if e.perf.on {
				pt.decided = time.Now() // 入方向没有判定面，这一段直接进改写+注入
			}
			e.rewriteInbound(h, pkt, addr, t, dport)
			if e.perf.on {
				pt.sent = time.Now()
			}
			e.perf.record(&pt, n, pkIn, shard)
			continue
		}

		// 出方向：这条连接属于哪个进程（只在规则里写了进程条件时才查表，其余情况零开销）。
		// 优先用连接上缓存的结论，避免每个包都查。
		procName, procPID := e.flowProc(sport)

		// 内置直连：Windows 更新传递优化走 TCP 7680，客户内网里不该进隧道。
		// 以前要在规则里写一条 direct 规则来实现；现在内置，规则列表干净。
		if dport == builtinDirectPort && e.cfg.BuiltinDirectEnabled() {
			// 内置直连（Windows 更新传递优化）：一个文件共享的 peer 一对一行，
			// 刷起来全是噪声且对现场结论无影响 → 归到“详细日志”。
			e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, rules.ActionDirect, 0, "", procName, procPID, true)
			continue
		}

		// 方向判定不依赖 addr.Flags 的位布局：目标落在规则内 = 应用发出的包。
		// 名字：通配域名只能靠“这个 IP 是哪个域名”匹配。两个来源：
		//  ① DNS 接管发的假 IP（池子反查）② 嗅探/解析学到的真 IP（名字表）
		// 没写通配规则时不做这次查找（每包一次查找，不该白付）。
		name := ""
		if e.ruleSet().HasWildcards() {
			if n, ok := e.nameOf(dst); ok {
				name = n
			}
		}
		chain, act, ruleNo, ruleName, hit := e.ruleSet().MatchNameRule(name, dst, dport, procName)
		if e.perf.on {
			pt.decided = time.Now()
		}
		if hit {
			switch act {
			case rules.ActionDirect, rules.ActionBlock:
				e.passThrough(h, pkt, addr, t, src, dst, sport, dport, flags, act, ruleNo, ruleName, procName, procPID, false)
				e.perf.record(&pt, n, pkOther, shard)
			default:
				e.rewriteOutbound(h, pkt, addr, t, src, dst, sport, dport, flags, chain, relayIP, relayPort, ruleNo, ruleName, procName, procPID)
				if e.perf.on {
					pt.sent = time.Now()
				}
				e.perf.record(&pt, n, pkOut, shard)
			}
			continue
		}
		// 没命中任何规则：要么是“带本机网段条件的规则”**当前不生效**（A16），
		// 要么是“只按进程”的规则拦下的其它程序的包（A20）。
		// 两种都必须原样放回内核，绝不能当入站包改写（会把用户的包改坏）。
		// 直连流量（仅当开了“统计直连流量”才会被拦到这里）：
		// 回来的包也要数上，否则界面上永远只有出方向（A15）。
		if isSyn(flags) {
			// verbose 档：说清“不拦”不是因为包没到我们手上，而是**没有规则命中**
			e.routeMatchLog(sport, dst, dport, procName, procPID, "没有规则命中 → 不拦（按系统路由直连）")
		}
		if st := e.flow(dport); st != nil && st.action == rules.ActionDirect {
			st.touch()
			st.packets.Add(1)
			st.down.Add(uint64(len(pkt)))
			e.dirDown.Add(uint64(len(pkt))) // 顶栏流量图的直连口径（开关关掉时不进表，也就不会到这里）
		}
		e.cap.note(pkt)
		if _, err := h.Send(pkt, addr); err != nil {
			e.bus.Throttle("inject.fail", time.Minute, "注入失败: %v（1 分钟内的重复不再逐条记）", err)
		}
		e.perf.record(&pt, n, pkOther, shard)
	}
}

// ───────────────────────── 域名通配：只读嗅探 DNS ─────────────────────────

// dnsSniffFilter 只读嗅探用的过滤器：只关心 DNS **应答**（源端口 53），UDP 与 TCP 都要。
//
// 用 sniff + recv-only：包照常交给系统与应用，我们只看一份拷贝 —— 这一步出
// 任何问题最多是“没看见”，绝不会把全机 DNS 弄坏（这是选这个方案的前提）。
const dnsSniffFilter = "(inbound and udp and udp.SrcPort == 53) or (inbound and tcp and tcp.SrcPort == 53)" +
	" or (outbound and udp and udp.DstPort == 53)"

// dnsLoop 读 DNS 应答 → 学“名字 ↔ IP” → 按需重建动态过滤器。
func (e *Engine) dnsLoop() {
	defer e.wg.Done()

	h, err := divert.Open(dnsSniffFilter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("域名通配：无法只读嗅探 DNS（%v）—— 通配域名只能匹配已经观察到的名字", err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止：直接退出（defer 会关 h）
	}
	e.bus.Debug("dns.sniff: started mode=read-only scope=answers+queries")

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	for {
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("域名通配：DNS 嗅探中断: %v（通配域名将不再学到新 IP）", err)
				return
			}
		}
		pkt := buf[:n]
		// 出方向的查询：DNS 接管（开了才有动作）—— 命中通配规则的名字塞一条假 IP 应答
		if e.fake != nil && e.takeoverQuery(pkt, addr) {
			continue
		}
		// 入方向的应答：学“名字 → IP”
		e.learnDNS(pkt)
	}
}

// takeoverQuery 处理一条**出方向** DNS 查询：命中通配规则就额外塞一条假 IP 应答。
//
// 返回 true 表示“这是查询，已处理”（不必再当应答解析）。
//
// 注意：这是**只读**句柄，我们从头到尾**不消费**这个包 —— 原查询照常发出去，
// 我们只是多塞一条应答。真应答先到的话，应用就用真 IP，而那条路我们能靠
// “名字→IP”嗅探照常接管（两条路都能到，不会因此失效）。
func (e *Engine) takeoverQuery(pkt []byte, addr *divert.Address) bool {
	info, payload, ok := udpPayload(pkt)
	if !ok {
		return false
	}
	// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
	// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
	if info.sport >= dnsProbePortLo && info.sport <= dnsProbePortHi {
		return true
	}
	q, okq := dnssniff.ParseQuery(payload)
	if !okq {
		return false
	}
	// verbose 档：DNS **请求**（Proxifier 把 DNS requests 归 Verbose）。
	// 只在这儿记：查询本来就是在这里被解析的（没开 DNS 接管时不解析，也就不记）。
	// 只看得到自己发出去的查询 —— 走 DoH 的应用不经这里（那类靠 sni.sniff 学名字）。
	e.bus.Detail("dns.query: name=%s type=%s from=%s:%d", q.Name, dnsTypeName(q.Type), info.src, info.sport)
	// 黑匣子：这是“到底谁弄坏的”唯一的原始事实
	if e.dnsBox != nil {
		e.dnsBox.Writef("查询  %s:%d → %s:%d  id=%#04x %s 类型 %d",
			info.src, info.sport, info.dst, info.dport, q.ID, q.Name, q.Type)
	}
	if !e.ruleSet().WildcardMatch(q.Name) {
		return true // 不命中：什么都不做（原查询照常）
	}
	var ansIP net.IP
	switch q.Type {
	case 1:
		ansIP = e.fake.Assign(q.Name, dnsFakeTTL)
		if ansIP == nil {
			e.bus.Throttle("dns.takeover.poolfull", time.Minute,
				"DNS 接管：假 IP 池已满，本次不接管（1 分钟内的重复不再逐条记）")
			return true
		}
	case 28:
		ansIP = nil // AAAA：答“没有这条记录”，否则应用可能走 IPv6 绕过我们
	default:
		// 其余类型（TXT / SRV / MX / **HTTPS-SVCB** …）也一律答“没有这条记录”，
		// **不放原查询出去**。
		//
		// 为什么（2026-09-28 复核发现的一个真泄漏面）：HTTPS/SVCB 记录里能带
		// `ipv4hint` / `ipv6hint`（RFC 9460）—— 应用拿到它就能直连真实 IP，绕过我们。
		// 原来这里 `return true` 让原查询照常发出去，等于把“本该走链”的名字的真实地址
		// 漏给了应用。Proxifier 对同一件事有个专门的开关「block non A/AAAA DNS queries」。
		//
		// 影响面只限**命中通配规则**的名字（不命中的在上面就 return 了），
		// 而这些名字本来就要接管，应用连它们靠的是 A/AAAA。
		ansIP = nil
		e.bus.Detail("dns.takeover: name=%s qtype=%s answer=NOERROR/empty（防空地址从 SVCB/HTTPS 的 ipv4hint 漏出去）",
			q.Name, dnsTypeName(q.Type))
	}
	resp := buildDNSResponse(pkt, info, q, ansIP)
	if resp == nil {
		return true
	}
	inj := e.injectorHandle()
	if inj == nil {
		return true
	}
	addr.Flags &^= 0x02 // 清掉 Outbound：回包是**入方向**的
	divert.CalcChecksums(resp, addr, divert.ChecksumDefault)
	if _, serr := inj.Send(resp, addr); serr != nil {
		e.bus.Throttle("dns.takeover.injectfail", time.Minute,
			"DNS 接管：注入假应答失败: %v（1 分钟内的重复不再逐条记）", serr)
		if e.dnsBox != nil {
			e.dnsBox.Writef("注入失败 %s: %v", q.Name, serr)
		}
		return true
	}
	e.tookOver.Add(1)
	if e.dnsBox != nil {
		e.dnsBox.Writef("已回答 %s → %v（已注入应答）", q.Name, ansIP)
	}
	e.noteTookOver(q.Name, q.Type)
	return true
}

// injectorHandle 取“只塞”那只句柄（过滤器是 false，什么也不匹配）。
func (e *Engine) injectorHandle() *divert.Handle {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.injector
}

// learnDNS 从一条 DNS 报文里学“名字 → IP”，写进名字表。
//
// 为什么全记（不只是能命中通配规则的名字）：同一个 IP 常被多个名字共用，
// 只记能命中的那些会漏掉“先用另一个名字访问过、然后才轮到通配规则”的情况；
// 表本身按 TTL 过期（见 dnsmap.Expired），不会无限长。
func (e *Engine) learnDNS(pkt []byte) {
	payload := dnsPayload(pkt)
	if len(payload) == 0 {
		return
	}
	res, err := dnssniff.Parse(payload)
	if err != nil || len(res.Pairs) == 0 {
		return
	}
	e.dnsSeen.Add(1)
	byName := map[string][]string{}
	ttl := map[string]time.Duration{}
	for _, p := range res.Pairs {
		byName[p.Name] = append(byName[p.Name], p.IP)
		if cur, ok := ttl[p.Name]; !ok || (p.TTL > 0 && p.TTL < cur) {
			ttl[p.Name] = p.TTL
		}
	}
	// 观测到的名字**封顶**存 10 分钟。
	//
	// 直接用报文里的 TTL（公网域名常见几千到 86400 秒）的后果：一天的观测全留着，
	// 而名字表每次写入都要整表重建索引（持写锁、全表 Snapshot），长跑后包处理会被
	// 这些写操作周期性地挡住（审计 P1-6）。
	// 10 分钟足够覆盖“应用刚解析完就要连”这个真正的用途。
	for name, d := range ttl {
		if d <= 0 || d > maxObservedTTL {
			ttl[name] = maxObservedTTL
		}
	}
	changed := false
	for name, ips := range byName {
		before := e.names.IPsFor(name)
		e.names.SetWithTTL(name, ips, dnsmap.PrioObserved, ttl[name])
		e.dnsLearn.Add(1)
		if !sameStrSet(before, e.names.IPsFor(name)) {
			changed = true
			// verbose 档：DNS **应答**里学到的“名字 → IP”（Proxifier 把 DNS requests 归 Verbose）。
			// 只在映射真的变了才写：同一个名字的重复应答不刷屏。
			e.bus.Detail("dns.answer: name=%s ips=%s ttl=%s", name, strings.Join(ips, ","), ttl[name])
		}
	}
	if changed {
		e.applyHostIPs()
		e.onWildcardsChanged()
	}
}

// tcpPayload 从 IP 包里取出 TCP 负载（不做端口判断，调用方自己判）。
func tcpPayload(pkt []byte) []byte {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok || proto != 6 {
		return nil
	}
	if len(pkt) < ihl+20 {
		return nil
	}
	hdr := int(pkt[ihl+12]>>4) * 4 // data offset
	if hdr < 20 || ihl+hdr > len(pkt) {
		return nil
	}
	return pkt[ihl+hdr:]
}

// dnsPayload 从 IP 包里取出 UDP/TCP 负载（DNS 报文）。取不到返回 nil。
//
// 只认**源端口 53**（应答）：嗅探过滤器只装了这一个条件，这里再守一道，
// 免得把别的 TCP 流量当成 DNS 报文去解析（解析器再怎么健壮也不该被白喂）。
func dnsPayload(pkt []byte) []byte {
	_, _, ihl, proto, ok := parseIPv4(pkt)
	if !ok {
		return nil
	}
	switch proto {
	case 17: // UDP
		if len(pkt) < ihl+8 {
			return nil
		}
		if be16(pkt, ihl) != 53 {
			return nil
		}
		l := int(be16(pkt, ihl+4)) // UDP 长度（含 8 字节头）
		end := ihl + l
		if l < 8 || end > len(pkt) {
			end = len(pkt)
		}
		return pkt[ihl+8 : end]
	case 6: // TCP
		if be16(pkt, ihl) != 53 {
			return nil
		}
		return tcpPayload(pkt)
	}
	return nil
}

// onWildcardsChanged 发现名字表变了：有必要时立刻重建动态过滤器。
//
// 为什么要“立刻”：应用解析完域名后会马上发起连接，而那个包还没进过滤器。
// 这一小段窗口就是能不能拦住首次连接的关键，所以不能等到下一次 tick。
// 但也不能每个 DNS 应答都重建（重建要开新句柄），所以节流 200 ms，
// 节流期间只置脏标记，由 dynFilterLoop 补上。
func (e *Engine) onWildcardsChanged() {
	if !e.ruleSet().HasWildcards() {
		return
	}
	now := time.Now().UnixMilli()
	last := e.dynLast.Load()
	if now-last >= 200 {
		e.dynLast.Store(now)
		e.rebuildDynFilter()
		return
	}
	select {
	case e.dynDirty <- struct{}{}:
	default: // 已经有人置脏了
	}
}

// dynFilterLoop 把节流期间攒下的“脏”补上（最多滞后 200 ms）。
func (e *Engine) dynFilterLoop() {
	defer e.wg.Done()
	tk := time.NewTicker(200 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			select {
			case <-e.dynDirty:
				e.dynLast.Store(time.Now().UnixMilli())
				e.rebuildDynFilter()
			default:
			}
		}
	}
}

// rebuildDynFilter 重建动态过滤器（第二只句柄，只装通配域名当前覆盖到的 IP）。
//
// 热替换的做法：**先开新句柄、再关旧句柄**，中间不丢包（两只都开着的那一瞬，
// 同一个包只会被其中一只收到，两边的处理逻辑完全一样）。
func (e *Engine) rebuildDynFilter() {
	rs := e.ruleSet().WildcardRanges(e.cfg.CountDirectEnabled())
	filter := ""
	if len(rs) > 0 {
		filter = buildFilter(rs, portOf(e.RelayAddr()))
	}

	e.mu.Lock()
	oldH, oldStop, oldFilter := e.dynHandle, e.dynStop, e.dynFilter
	if filter == oldFilter {
		e.mu.Unlock()
		return // 没变化，不要白白换句柄
	}
	if filter == "" {
		e.dynHandle, e.dynStop, e.dynFilter = nil, nil, ""
		e.mu.Unlock()
		if oldH != nil {
			if oldStop != nil {
				close(oldStop)
			}
			oldH.Close()
			e.bus.Debug("wildcard: filter.remove reason=no-matched-ip")
		}
		return
	}

	nh, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		// 把“记住的旧过滤器”清掉：否则下次观测到同一批 IP 时，
		// rebuildDynFilter 会以为“没变”直接返回，这只句柄就永久建立不起来了。
		e.dynFilter = ""
		e.mu.Unlock()
		e.bus.Warn("域名通配：动态过滤器打开失败: %v", err)
		return
	}
	if !e.run {
		// 已经停在停止过程中了：不要把协程加进 WaitGroup（Add 与 Wait 并发是错的）
		e.mu.Unlock()
		nh.Close()
		return
	}
	stop := make(chan struct{})
	e.dynHandle, e.dynStop, e.dynFilter, e.dynAt = nh, stop, filter, time.Now()
	e.wg.Add(1)
	e.mu.Unlock()

	go e.guard("dynPacketLoop", func() { e.packetLoop(nh, stop, loopDyn, -1) })
	if oldH != nil {
		if oldStop != nil {
			close(oldStop)
		}
		oldH.Close()
	}
	e.bus.Debug("wildcard: filter.update ranges=%d filter=%s", len(rs), filter)
}

// WildcardStat 一条通配规则当前的状态（界面/日志看“学到了几个 IP”）。
type WildcardStat struct {
	Pattern  string            `json:"pattern"`
	IPs      []string          `json:"ips"`
	Updated  string            `json:"updated"`
	Takeover bool              `json:"takeover"`
	Names    []string          `json:"names"`
	FakeIPs  map[string]string `json:"fakeIps"`
}

// WildcardStats 通配域名规则当前各覆盖到哪些 IP / 接管过哪些名字。
func (e *Engine) WildcardStats() []WildcardStat {
	var out []WildcardStat
	seen := map[string][]string{}
	for _, r := range e.ruleSet().List() {
		for _, w := range r.WildcardTargets() {
			if _, done := seen[w]; done {
				continue
			}
			var ips []string
			for h, list := range e.names.Snapshot() {
				if dnsmap.MatchWildcard(w, h) {
					ips = append(ips, list...)
				}
			}
			sort.Strings(ips)
			// 接管过哪些名字：假 IP 池里有记录（这是它**真的在干活**的证据）。
			var names []string
			fake := map[string]string{}
			if e.fake != nil {
				for _, n := range e.fake.Names() {
					if !dnsmap.MatchWildcard(w, n) {
						continue
					}
					names = append(names, n)
					if ip, ok := e.fake.IPFor(n); ok {
						fake[n] = ip.String()
					}
				}
			}
			sort.Strings(names)
			seen[w] = ips
			out = append(out, WildcardStat{Pattern: w, IPs: ips, Names: names, FakeIPs: fake,
				Takeover: e.cfg.DNSTakeoverEnabled()})
		}
	}
	if len(out) == 0 {
		return nil
	}
	e.mu.RLock()
	at := e.dynAt
	e.mu.RUnlock()
	age := "—"
	if !at.IsZero() {
		age = humanDur(time.Since(at))
	}
	for i := range out {
		out[i].Updated = age
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

// DNSStats 只读嗅探的统计（进/出）—— 诊断页用。
func (e *Engine) DNSStats() (seen, learned uint64) {
	return e.dnsSeen.Load(), e.dnsLearn.Load()
}

// closedCh 简单包装：nil 通道永远不关闭。
func closedCh(ch chan struct{}) <-chan struct{} {
	if ch == nil {
		return nil
	}
	return ch
}

// sameStrSet 两个集合是否相等（顺序无关，元素不重复）。
func sameStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}

// ───────────────────── 名字的第二个来源：TLS SNI / HTTP Host ─────────────────────

// sniSniffPorts 只读嗅探的端口：TLS 常见端口 + 明文 HTTP 常见端口。
//
// 为什么要端口白名单：嗅探的代价是“这些包的负载都拷一份到用户态”，
// 范围越小越好；而握手只发生在连接最开始，常见的就这几类端口。
// 内网服务端口不在表里的，可以用通配域名 + 明文 DNS 拿到（不依赖 SNI）。
var sniSniffPorts = []uint16{443, 8443, 9443, 6443, 4443, 10443, 80, 8080, 853} // 853=DoT

// sniSniffFilter 拼出方向 TCP 的嗅探过滤器（只读，不改任何包）。
//
// 加 `ip.Length < 1400` 是为了**开销**，不是为了省事：嗅探的代价在“每个匹配的包
// 都要拷一份到用户态”，而大包体量最大。实测 30MB 下载（全部经 Clash 的 443）
// 开销约 0.7s CPU；加上长度条件后大块数据包直接不进内核过滤，代价降到零头。
//
// 代价：极端大的 ClientHello（≥1400 字节，比如带 ECH 配置的）会被漏掉 ——
// 而 ECH 的名字本来我们也看不到（真名被加密），漏了不亏。
func sniSniffFilter() string {
	var c string
	for i, p := range sniSniffPorts {
		if i > 0 {
			c += " or "
		}
		c += fmt.Sprintf("tcp.DstPort == %d", p)
	}
	return "outbound and tcp and ip.Length < 1400 and (" + c + ")"
}

// sniBuf 一条连接攒起来的“开头几个字节”（连接只靠源端口区分，与拦截路径一致）。
type sniBuf struct {
	dst  net.IP
	data []byte
	at   time.Time
	done bool // 已经得出结论（学到了名字，或者判定不是我们要的）
}

// sniLoop 只读嗅探 TLS ClientHello / 明文 HTTP 请求，从中读出目标域名。
//
// 为什么要有它：名字原本靠“看明文 DNS 应答”学；一旦应用用了加密 DNS
// （DoH/DoT）或自带解析器，DNS 层就什么都看不见了。但握手是明文的 ——
// SNI 里还有名字。这就是“防患于未然”的那一半。
func (e *Engine) sniLoop() {
	defer e.wg.Done()

	filter := sniSniffFilter()
	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.bus.Warn("TLS 嗅探：无法启动（%v）—— 加密 DNS 环境下通配域名将学不到名字", err)
		return
	}
	defer h.Close()
	if !e.trackSniff(h) {
		return // 已经在停止：直接退出（defer 会关 h）
	}
	e.bus.Debug("sni.sniff: started mode=read-only ports=%d filter=%s", len(sniSniffPorts), filter)

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	flows := map[uint16]*sniBuf{}
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()

	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			// 定期把所有攒着的、没结论的连接丢掉（长连接 + 大流量不能无限攒）
			for k, f := range flows {
				if time.Since(f.at) > 20*time.Second || len(f.data) > 8192 {
					delete(flows, k)
				}
			}
			if len(flows) > 2048 { // 更硬的上限：宁可漏学，不能吃内存
				flows = map[uint16]*sniBuf{}
			}
		default:
		}

		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Warn("TLS 嗅探中断: %v（通配域名将只能靠明文 DNS）", err)
				return
			}
		}
		pkt := buf[:n]

		// 我们自己的解析（realResolver 从 53901-53910 发）不能被自己答成假 IP ——
		// 那就是自己骗自己。用源端口在代码里排掉（过滤器保持最简）。
		if info, _, ok := udpPayload(pkt); ok && info.sport >= dnsProbePortLo && info.sport <= dnsProbePortHi {
			continue
		}
		src, dst, _, proto, ok := parseIPv4(pkt)
		if !ok || proto != 6 {
			continue
		}
		t := 20
		if _, _, ihl, _, ok2 := parseIPv4(pkt); ok2 {
			t = ihl
		}
		sport := be16(pkt, t+offSrcPort)
		payload := tcpPayload(pkt)
		if len(payload) == 0 {
			continue
		}
		_ = src

		f := flows[sport]
		if f == nil {
			// 只关心“第一条数据”的样子：不像 TLS/HTTP 就不管它（后面也别攒）
			if !tlsname.LooksLikeTLS(payload) && !tlsname.LooksLikeHTTP(payload) {
				continue
			}
			f = &sniBuf{dst: dst, at: time.Now()}
			flows[sport] = f
		}
		if f.done || len(f.data) > 8192 {
			delete(flows, sport)
			continue
		}
		f.data = append(f.data, payload...)
		f.at = time.Now()

		// TLS 要看整条记录；HTTP 只要够一个请求头（通常第一段就够）
		if tlsname.LooksLikeTLS(f.data) && !tlsname.Complete(f.data) {
			continue
		}
		res, okr := tlsname.Name(f.data)
		if !okr {
			// 已经有结论了：不是 TLS 也不是 HTTP（或者没 SNI/Host）→ 别死等
			if len(f.data) > 512 {
				f.done = true
				delete(flows, sport)
			}
			continue
		}
		f.done = true
		delete(flows, sport)
		e.learnFromHandshake(res, dst)
	}
}

// learnFromHandshake 从握手里学到的名字 → 名字表（与 DNS 观察走同一条流水线）。
func (e *Engine) learnFromHandshake(res tlsname.Result, dst net.IP) {
	if res.Name == "" || dst == nil {
		return
	}
	if res.ECH {
		// ECH：SNI 里只是“公开名”，真名被加密了 —— 坦诚地说出来，别让人以为通了。
		// 但同一个域名每次握手都重复说一遍没意义（实测 22 分钟里刷了十几行）：
		// 它是个**稳定属性**，不是“刚发生的事故” —— 每个名字 10 分钟说一次、且降到 INFO。
		if e.noteOnce("ech:"+res.Name, 10*time.Minute) {
			e.bus.Detail("TLS 嗅探：%s 用了 ECH（加密的 ClientHello）—— 真实目标名看不见，"+
				"通配域名对它无效（具体域名规则不受影响）", res.Name)
		}
		e.names.Set(res.Name, []string{dst.String()}, dnsmap.PrioObserved)
		return
	}
	before := e.names.IPsFor(res.Name)
	_, wasKnown := e.names.NameFor(dst)
	e.names.Set(res.Name, []string{dst.String()}, dnsmap.PrioObserved)
	e.sniLearn.Add(1)
	if len(before) == 0 && !wasKnown {
		// 这个名字从未在明文 DNS 里出现过 → 基本可以确定这台机器上有人用了
		// 加密 DNS 或自带解析器的客户端。这条日志的价值：让“为什么通配能/不能生效”有据可查。
		e.bus.Detail("sni.learn: name=%s ip=%s dns_seen=false", res.Name, dst)
	}
	e.applyHostIPs()
	e.onWildcardsChanged()
}

// dohHosts 已知的加密 DNS（DoH/DoT）服务名。只用于**报信**，不参与任何匹配。
var dohHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	"doh.pub", "dns.pub", "doh.360.cn", "dns.alidns.com", "doh.alidns.com",
	"dns.quad9.net", "doh.opendns.com", "dns.nextdns.io", "doh.dns.sb",
	"doh.cleanbrowsing.org", "dns.adguard.com",
}

// isDoHEndpoint 这个域名是不是已知的加密 DNS 端点。
func isDoHEndpoint(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, h := range dohHosts {
		if name == h {
			return true
		}
	}
	return false
}

// noteDoH 第一次看到加密 DNS 端点时报一条（同一个端点只报一次，否则刷屏）。
func (e *Engine) noteDoH(name string, dst net.IP) {
	e.mu.Lock()
	if e.dohSeen == nil {
		e.dohSeen = map[string]bool{}
	}
	show := !e.dohSeen[name]
	if show {
		e.dohSeen[name] = true
	}
	e.mu.Unlock()
	if !show {
		return
	}
	e.bus.Warn("doh.detect: host=%s ip=%s impact=first-connect-may-miss", name, dst)
	e.bus.Warn("  影响：这些名字只能从 TLS 握手看到，**首次连接**可能来不及进过滤器（重试起生效）。" +
		"要首次就生效，需打开 DNS 接管或改用明文 DNS")
}

// ───────────────────────── DNS 接管（发假 IP） ─────────────────────────

// 我们自己的 DNS 解析专用源端口段（区间选在这种不常用的高位段）。
//
