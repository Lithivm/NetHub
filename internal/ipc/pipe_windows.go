//go:build windows

package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

// 传输层用 go-winio，而不是自己包 CreateNamedPipe/ReadFile/WriteFile。
//
// 为什么：Windows 上**同步句柄（未带 FILE_FLAG_OVERLAPPED）同时只允许一个未完成的 I/O**。
// 我们自己那版在一个句柄上"挂着阻塞读 + 同时写"，写就会被排到读后面永远等下去 ——
// 死锁（已用裸 API 复现）。而且这种句柄上 CloseHandle 还会阻塞在未完成的 I/O 上。
// go-winio 内部走重叠 I/O：读写可以并发、Close 能取消挂起的 I/O、还能设超时。
//
// 管道安全：两类进程都是同一个用户（界面就是引擎拉起来的），用默认安全描述符即可。

const (
	pipeBufSize  = 64 * 1024
	writeTimeout = 30 * time.Second // 对端卡死时别把引擎一起拖住
)

// pipeConn 是一条已建立的连接（服务端/客户端同一套读写）。
type pipeConn struct {
	c    net.Conn
	done chan struct{}
	once sync.Once

	wmu sync.Mutex
	bw  *bufio.Writer
}

func newPipeConn(c net.Conn) *pipeConn {
	return &pipeConn{
		c:    c,
		done: make(chan struct{}),
		bw:   bufio.NewWriterSize(c, pipeBufSize),
	}
}

// pipeListener 是一个正在等连接的管道实例。Close 能让阻塞中的 Accept 立刻返回。
type pipeListener struct{ ln net.Listener }

// listenPipe 建一个管道实例（不阻塞，还没等客户端）。
func listenPipe(name string) (*pipeListener, error) {
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{
		MessageMode:      false, // 字节流：我们自己用换行分帧
		InputBufferSize:  pipeBufSize,
		OutputBufferSize: pipeBufSize,
	})
	if err != nil {
		return nil, err
	}
	tracef("listenPipe: listening %s", name)
	return &pipeListener{ln: ln}, nil
}

// Accept 等一个客户端连上（阻塞，可被 Close 取消）。
func (l *pipeListener) Accept() (*pipeConn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	tracef("listenPipe: accepted %s", c.RemoteAddr())
	return newPipeConn(c), nil
}

// Close 关掉监听（同时唤醒阻塞的 Accept）。
func (l *pipeListener) Close() error { return l.ln.Close() }

// dialPipe 连一条已经存在的管道。名字还没建出来时返回错误，由上层重试 ——
// 界面比引擎先起来是常态，必须能自愈。
func dialPipe(name string, timeout time.Duration) (*pipeConn, error) {
	c, err := winio.DialPipe(name, &timeout)
	if err != nil {
		tracef("dialPipe: 失败 %v", err)
		return nil, err
	}
	tracef("dialPipe: 连上 %s", c.LocalAddr())
	return newPipeConn(c), nil
}

// write 写一帧（一行 JSON）。多 goroutine 安全。
func (c *pipeConn) write(f frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.bw.Write(b); err != nil {
		return err
	}
	if err := c.bw.WriteByte('\n'); err != nil {
		return err
	}
	if traceOn {
		tracef("write: %d 字节 %s", len(b), string(b))
	}
	return c.bw.Flush()
}

// readLoop 一直读帧，直到连接断开。返回断开的原因。
func (c *pipeConn) readLoop(onFrame func(frame)) error {
	r := bufio.NewReaderSize(c.c, pipeBufSize)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
				var f frame
				// 坏帧只丢这一帧：每帧独立成行，丢一帧不会让后面的流错位
				if jErr := json.Unmarshal(trimmed, &f); jErr == nil {
					onFrame(f)
				} else {
					tracef("readLoop: 坏帧 %q (%v)", trimmed, jErr)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF // 对端正常关闭也是"断开"，别让上层以为是读完了
			}
			tracef("readLoop: 断开 %v", err)
			c.Close()
			return err
		}
	}
}

// Close 关掉连接（幂等）。挂起中的读写会当场收到错误，不会阻塞。
func (c *pipeConn) Close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.c.Close()
	})
}
