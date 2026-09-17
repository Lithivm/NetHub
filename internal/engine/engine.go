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
	"fmt"
	"netproxy/internal/winrun"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/imgk/divert-go"

	"netproxy/internal/config"
	"netproxy/internal/logbus"
	"netproxy/internal/rules"
	"netproxy/internal/socks"
)

const (
	offSrcIP   = 12
	offDstIP   = 16
	offProto   = 9
	offSrcPort = 0
	offDstPort = 2
	offFlags   = 13 // FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10
)

type connState struct {
	dst     net.IP
	dport   uint16
	app     net.IP
	appPort uint16
	chain   string
	last    time.Time
}

type Engine struct {
	bus   *logbus.Bus
	rules *rules.Set
	cfg   *config.Config

	mu     sync.Mutex
	handle *divert.Handle
	ln     net.Listener
	relay  string
	conns  map[uint16]*connState
	run    bool

	// 统计
	statTotal   uint64
	statActive  int
	statPerRule map[string]uint64

	stopOnce sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

func New(bus *logbus.Bus, rs *rules.Set, cfg *config.Config) *Engine {
	return &Engine{
		bus: bus, rules: rs, cfg: cfg,
		conns:       map[uint16]*connState{},
		statPerRule: map[string]uint64{},
		done:        make(chan struct{}),
	}
}

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

// Stats 返回 (累计连接数, 当前活跃数)。
func (e *Engine) Stats() (uint64, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statTotal, e.statActive
}

// Start 启动拦截。返回后即处于运行状态。
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.run {
		e.mu.Unlock()
		return fmt.Errorf("已在运行")
	}
	e.mu.Unlock()

	// 1) 先起 relay，拿到真实端口（端口可能配的是 0=自动分配，过滤器要用它）
	ln, err := net.Listen("tcp", e.cfg.Relay)
	if err != nil {
		return fmt.Errorf("relay 监听 %s 失败: %w", e.cfg.Relay, err)
	}
	relay := ln.Addr().String()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 2) 用规则区间拼内核过滤器
	rs := e.rules.Ranges()
	if len(rs) == 0 {
		ln.Close()
		return fmt.Errorf("没有生效的路由规则，无事可做")
	}
	filter := buildFilter(rs, port)
	e.bus.Info("内核过滤器: %s", filter)

	// 3) 打开 WinDivert（含首次安装驱动的重试）
	h, err := openDivert(e.bus, filter)
	if err != nil {
		ln.Close()
		return fmt.Errorf("WinDivert 打开失败: %w", err)
	}

	e.mu.Lock()
	e.ln, e.relay, e.handle, e.run = ln, relay, h, true
	e.mu.Unlock()

	e.bus.Info("✓ 拦截已启动：relay=%s，规则 %d 条", relay, len(e.rules.List()))
	for _, r := range e.rules.List() {
		e.bus.Info("    %s  →  链 %s", r.Target, r.Chain)
	}

	e.wg.Add(3)
	go e.acceptLoop()
	go e.packetLoop()
	go e.janitor()
	return nil
}

// Stop 停止拦截并回收资源。
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.done)

		e.mu.Lock()
		h, ln, run := e.handle, e.ln, e.run
		e.handle, e.ln, e.run = nil, nil, false
		e.mu.Unlock()

		if h != nil {
			h.Close() // 让 packetLoop 的 Recv 立刻返回错误
		}
		if ln != nil {
			ln.Close()
		}
		e.wg.Wait()
		if run {
			e.bus.Info("拦截已停止")
		}
	})
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
		go e.handleConn(c)
	}
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

	ch, ok := e.cfg.ChainByName(st.chain)
	if !ok {
		e.bus.Error("链 %s 不存在，丢弃 %s:%d", st.chain, st.dst, st.dport)
		return
	}

	up, err := socks.Dial(ch.Listen, st.dst, st.dport, 10*time.Second)
	if err != nil {
		e.bus.Error("[%s] 隧道建立失败 %s:%d — %v", st.chain, st.dst, st.dport, err)
		return
	}
	defer up.Close()

	e.bus.Info("[%s] 已接管 %s:%d  (来源端口 %d)", st.chain, st.dst, st.dport, sport)

	done := make(chan struct{}, 2)
	go func() { copyAndClose(up, c); done <- struct{}{} }()
	go func() { copyAndClose(c, up); done <- struct{}{} }()
	<-done

	e.mu.Lock()
	delete(e.conns, sport)
	if e.statActive > 0 {
		e.statActive--
	}
	e.mu.Unlock()
	e.bus.Info("[%s] 连接结束 %s:%d", st.chain, st.dst, st.dport)
}

// copyAndClose 单向拷贝并在结束后关闭写端（半关闭，双向都能正常收尾）。
func copyAndClose(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
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

func (e *Engine) packetLoop() {
	defer e.wg.Done()

	e.mu.Lock()
	h := e.handle
	e.mu.Unlock()

	buf := make([]byte, divert.MTUMax)
	addr := new(divert.Address)
	relayIP := net.ParseIP(hostOf(e.RelayAddr())).To4()
	relayPort := portOf(e.RelayAddr())

	for {
		n, err := h.Recv(buf, addr)
		if err != nil {
			select {
			case <-e.done:
				return
			default:
				e.bus.Error("WinDivert Recv 失败，拦截已中断: %v", err)
				return
			}
		}
		pkt := buf[:n]

		src, dst, ihl, proto, ok := parseIPv4(pkt)
		if !ok || proto != 6 || len(pkt) < ihl+20 {
			_, _ = h.Send(pkt, addr)
			continue
		}
		t := ihl
		sport := be16(pkt, t+offSrcPort)
		dport := be16(pkt, t+offDstPort)
		flags := pkt[t+offFlags]

		// 方向判定不依赖 addr.Flags 的位布局：目标落在规则内 = 应用发出的包。
		if chain, hit := e.rules.Match(dst); hit {
			e.rewriteOutbound(h, pkt, addr, t, src, dst, sport, dport, flags, chain, relayIP, relayPort)
			continue
		}
		e.rewriteInbound(h, pkt, addr, t, dport)
	}
}

// rewriteOutbound 把应用发往内网目标的包改成"发给本机 relay"。
func (e *Engine) rewriteOutbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int,
	src, dst net.IP, sport, dport uint16, flags byte, chain string, relayIP net.IP, relayPort uint16) {

	isSyn := flags&0x02 != 0 && flags&0x10 == 0
	if isSyn {
		e.mu.Lock()
		_, existed := e.conns[sport]
		e.conns[sport] = &connState{
			dst: dst, dport: dport,
			app: append(net.IP(nil), src...), appPort: sport,
			chain: chain, last: time.Now(),
		}
		if !existed {
			e.statTotal++
			e.statActive++
			e.statPerRule[chain]++
		}
		e.mu.Unlock()
		if !existed {
			e.bus.Info("[%s] 拦截 %s:%d  → relay", chain, dst, dport)
		}
	} else {
		e.mu.Lock()
		if st := e.conns[sport]; st != nil {
			st.last = time.Now()
		}
		e.mu.Unlock()
	}

	// 目标 → relay；源也改成 relay 的 IP（关键！否则环回口丢包）
	copy(pkt[offDstIP:offDstIP+4], relayIP)
	putBE16(pkt, t+offDstPort, relayPort)
	copy(pkt[offSrcIP:offSrcIP+4], relayIP)

	if flags&0x04 != 0 { // RST：连接结束，清映射
		e.mu.Lock()
		delete(e.conns, sport)
		e.mu.Unlock()
	}

	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Warn("注入失败: %v", err)
	}
}

// rewriteInbound 把 relay 回来的包改回"来自真正的内网目标"。
func (e *Engine) rewriteInbound(h *divert.Handle, pkt []byte, addr *divert.Address, t int, dport uint16) {
	e.mu.Lock()
	st := e.conns[dport] // dport = 应用的源端口
	e.mu.Unlock()
	if st == nil {
		_, _ = h.Send(pkt, addr)
		return
	}
	copy(pkt[offSrcIP:offSrcIP+4], st.dst.To4())
	putBE16(pkt, t+offSrcPort, st.dport)
	copy(pkt[offDstIP:offDstIP+4], st.app.To4())
	putBE16(pkt, t+offDstPort, st.appPort)
	divert.CalcChecksums(pkt, addr, divert.ChecksumDefault)
	if _, err := h.Send(pkt, addr); err != nil {
		e.bus.Warn("注入失败: %v", err)
	}
}

// janitor 定期清理"应用已经消失但没发 RST"的悬挂映射，避免内存无限增长。
func (e *Engine) janitor() {
	defer e.wg.Done()
	tk := time.NewTicker(60 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tk.C:
			cut := time.Now().Add(-10 * time.Minute)
			e.mu.Lock()
			for k, st := range e.conns {
				if st.last.Before(cut) {
					delete(e.conns, k)
					if e.statActive > 0 {
						e.statActive--
					}
				}
			}
			e.mu.Unlock()
		}
	}
}

// ───────────────────────── 过滤器与工具 ─────────────────────────

func buildFilter(rs []rules.Range, relayPort uint16) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("(ip.DstAddr >= %s and ip.DstAddr <= %s)",
			rules.U2IP(r.First), rules.U2IP(r.Last)))
	}
	return fmt.Sprintf("(outbound and tcp and (%s)) or (outbound and tcp and tcp.SrcPort == %d)",
		strings.Join(parts, " or "), relayPort)
}

// openDivert 打开 WinDivert；首次安装驱动会失败一次（服务被创建但启动失败，
// 报 ERROR_NO_SYSTEM_RESOURCES），所以这里带重试 + 主动拉起服务。
// ensureDriverPath：WinDivert 的驱动服务一旦注册，就固定指向某个目录下的 .sys。
// 整个文件夹被挪走/改名后，服务里的旧路径失效，Open 会一直失败且报错很难懂。
// 检测到路径和当前目录不符就先删掉服务，交给 WinDivert 按当前目录自己重装。
func ensureDriverPath(bus *logbus.Bus) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	want := filepath.Join(filepath.Dir(exe), "WinDivert64.sys")

	out, err := winrun.Command("sc", "qc", "WinDivert").CombinedOutput()
	if err != nil {
		return // 服务不存在，WinDivert 会自己装
	}
	i := strings.Index(string(out), "BINARY_PATH_NAME")
	if i < 0 {
		return
	}
	line := string(out)[i:]
	if j := strings.IndexAny(line, "\r\n"); j >= 0 {
		line = line[:j]
	}
	if !strings.Contains(line, ".sys") {
		return // 解析不出路径就别乱动
	}
	cur := strings.TrimSpace(line[strings.Index(line, ":")+1:])
	cur = strings.TrimSpace(strings.TrimPrefix(cur, `\??\`))
	if strings.EqualFold(cur, want) {
		return
	}

	bus.Warn("驱动服务指向旧路径（%s），按当前目录 %s 重建", cur, want)
	_ = winrun.Command("sc", "stop", "WinDivert").Run()
	time.Sleep(600 * time.Millisecond)
	_ = winrun.Command("sc", "delete", "WinDivert").Run()
	time.Sleep(600 * time.Millisecond)
}

func openDivert(bus *logbus.Bus, filter string) (*divert.Handle, error) {
	ensureDriverPath(bus)
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err == nil {
			if attempt > 1 {
				bus.Info("WinDivert 第 %d 次尝试成功", attempt)
			}
			return h, nil
		}
		lastErr = err
		bus.Warn("WinDivert 打开失败(第 %d/6 次): %v", attempt, err)
		out, serr := winrun.Command("sc", "start", "WinDivert").CombinedOutput()
		if serr != nil {
			bus.Info("  sc start WinDivert -> %s", strings.TrimSpace(string(out)))
		} else {
			bus.Info("  已尝试启动 WinDivert 驱动服务")
		}
		time.Sleep(time.Duration(attempt) * 700 * time.Millisecond)
	}
	return nil, fmt.Errorf("重试 6 次仍失败（驱动被安全软件拦截？或需要管理员权限）: %w", lastErr)
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
