package engine

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 抓包（A19）：把经过我们的每个包写成标准 .pcap，用 Wireshark 直接能开。
//
// 为什么要有它：疑难问题（"业务就是说某个操作不通"）里，日志只能说"我拦了、我转发了"，
// 但真正要证明的是"包长什么样、有没有发出去、对面回了什么"。抓一份原始流量比翻日志快得多。
//
// 两个刻意的设计决定：
//  1. **写原始形态**：出方向写"改写前"（目标还是内网地址）、入方向写"改写后"（源看起来像内网目标）
//     —— 这样 pcap 里就是一段干净的双向会话，拿去 Wireshark 不用自己脑补地址。
//     因此不会掺进我们自己的 127.0.0.1:relay 内部跳转（改写后的包不会再次进过滤器）。
//  2. **宁停不涨**：到上限直接停并写日志，而不是悄悄丢弃一部分包或无限写满磁盘 ——
//     缺一段的抓包包比没有更误导人。
const (
	capDefaultMaxMB = 64
	capFile         = "nethub-capture.pcap"
)

type capturer struct {
	mu         sync.Mutex
	f          *os.File
	path       string
	written    int64
	max        int64
	stopped    bool
	packets    uint64
	lastReason string
}

// pcap 文件头（链路类型 101 = LINKTYPE_RAW，也就是从 IP 头开始）。
var pcapMagic = []byte{0xd4, 0xc3, 0xb2, 0xa1}

func newCapturer() *capturer { return &capturer{} }

// start 开始抓包（dir 为空表示程序目录）。
func (c *capturer) start(dir string, maxMB int) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil {
		return c.path, fmt.Errorf("已经在抓了")
	}
	if dir == "" {
		dir = "."
	}
	if maxMB <= 0 {
		maxMB = capDefaultMaxMB
	}
	dir = filepath.Join(dir, "pcap")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, capFile)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	// 全局头：magic + ver 2.4 + thiszone 0 + sigfigs 0 + snaplen 65535 + network 101
	hdr := make([]byte, 0, 24)
	hdr = append(hdr, pcapMagic...)
	hdr = append(hdr, 0x02, 0x00, 0x04, 0x00) // ver 2.4
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 0)
	hdr = append(hdr, 0xff, 0xff, 0x00, 0x00) // snaplen 65535
	hdr = append(hdr, 101, 0, 0, 0)           // LINKTYPE_RAW = 101
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return "", err
	}
	c.f, c.path, c.written, c.stopped, c.packets = f, path, int64(len(hdr)), false, 0
	c.max = int64(maxMB) << 20
	return path, nil
}

// note 写一个包（未开始时什么都不做，所以调用点可以无条件调）。
func (c *capturer) note(pkt []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil || c.stopped || len(pkt) < 20 {
		return
	}
	if c.written+int64(len(pkt))+16 > c.max {
		// 到上限就停，并在文件里留个记号（别静默截断）
		msg := fmt.Sprintf("\n# 抓包已达上限 %d MB，于 %s 停止\n", c.max>>20, time.Now().Format("15:04:05"))
		_, _ = c.f.WriteString("#" + msg)
		c.stopLocked(fmt.Sprintf("抓包已达上限（%d MB），已停止", c.max>>20))
		return
	}
	now := time.Now()
	rec := make([]byte, 16, 16+len(pkt))
	binary.LittleEndian.PutUint32(rec[0:], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
	if _, err := c.f.Write(rec); err != nil {
		c.stopLocked("写抓包文件失败，已停止：" + err.Error())
		return
	}
	if _, err := c.f.Write(pkt); err != nil {
		c.stopLocked("写抓包文件失败，已停止：" + err.Error())
		return
	}
	c.written += int64(len(rec) + len(pkt))
	c.packets++
}

// stopLocked 关文件（调用方已持锁）。返回给调用方的日志文案由外面打。
func (c *capturer) stopLocked(reason string) {
	if c.f != nil {
		_ = c.f.Sync()
		_ = c.f.Close()
	}
	c.f = nil
	c.stopped = true
	if reason != "" {
		c.lastReason = reason
	}
}

// stop 手动停止。
func (c *capturer) stop() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return ""
	}
	reason := "已停止"
	c.stopLocked(reason)
	return reason
}

// status 当前状态（给界面）。
func (c *capturer) status() (on bool, path string, bytes int64, packets uint64, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.f != nil, c.path, c.written, c.packets, c.lastReason
}

// ───────── 引擎对外的抓包接口（webui 用）─────────

// StartCapture 开始抓包，返回文件路径。
func (e *Engine) StartCapture(dir string, maxMB int) error {
	if e.cap == nil {
		return fmt.Errorf("抓包组件未初始化")
	}
	_, err := e.cap.start(dir, maxMB)
	return err
}

// StopCapture 停止抓包，返回停止说明（没在抓就返回空串）。
func (e *Engine) StopCapture() string { return e.cap.stop() }

// CaptureStatus 抓包近况。
func (e *Engine) CaptureStatus() (on bool, path string, bytes int64, packets uint64, reason string) {
	if e.cap == nil {
		return false, "", 0, 0, ""
	}
	return e.cap.status()
}
