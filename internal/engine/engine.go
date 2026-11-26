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
	"nethub/internal/fakeip"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imgk/divert-go"

	"nethub/internal/config"
	"nethub/internal/logbus"
	"nethub/internal/proc"
	"nethub/internal/rules"
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

// ───────────────────────── DNS 接管（发假 IP） ─────────────────────────

// 我们自己的 DNS 解析专用源端口段（区间选在这种不常用的高位段）。
//
