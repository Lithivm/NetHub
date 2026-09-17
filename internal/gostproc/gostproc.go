// Package gostproc 把 gost 当子进程托管：静默启动、日志回收、崩溃自动重启、退出清理。
//
// 为什么是"每条链一个进程"而不是"一个进程带多个 -L/-F"：
// 实测发现 gost 2.x 的命令行**不按位置配对 -L/-F**，而是把所有 -F 串成一条代理链——
// 结果是 1080 和 1081 都走"先 proxy-a 再 proxy-b"的两跳链，到 10.0.0.* 的请求会被
// 送进 proxy-b 服务器（它到不了那个内网）而超时。
// 所以一条链一个进程：命令行语义确定，且和原来两个 .bat 的行为完全一致。
package gostproc

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"netproxy/internal/config"
	"netproxy/internal/logbus"
	"netproxy/internal/winrun"
)

// proc 一个 gost 子进程（对应一条链）。
type proc struct {
	chain string
	args  []string

	mu    sync.Mutex
	cmd   *exec.Cmd
	fails int
}

type Manager struct {
	bus   *logbus.Bus
	exe   string
	procs []*proc

	mu      sync.Mutex
	wantRun bool
	job     *job
	done    chan struct{}
	wg      sync.WaitGroup
}

// New 创建管理器。forward 为空的链会被跳过。
func New(bus *logbus.Bus, gcfg config.GostCfg, chains []config.Chain) *Manager {
	m := &Manager{bus: bus, exe: gcfg.Exe, done: make(chan struct{})}
	for _, ch := range chains {
		fwd := strings.TrimSpace(ch.Forward)
		if fwd == "" {
			continue
		}
		m.procs = append(m.procs, &proc{
			chain: ch.Name,
			args:  []string{"-L", "socks5://" + ch.Listen, "-F", fwd},
		})
	}
	if j, err := newJob(); err == nil {
		m.job = j
	} else {
		bus.Warn("创建 Job Object 失败（子进程将不会随本程序被强杀而回收）: %v", err)
	}
	return m
}

// ChainCount 需要托管的链数。
func (m *Manager) ChainCount() int { return len(m.procs) }

// Start 启动全部子进程并开始守护。
func (m *Manager) Start() error {
	if len(m.procs) == 0 {
		return fmt.Errorf("没有可启动的链（所有 forward 都是空的）")
	}
	m.mu.Lock()
	if m.wantRun {
		m.mu.Unlock()
		return fmt.Errorf("gost 已在运行")
	}
	m.wantRun = true
	m.mu.Unlock()

	var failed []string
	for _, p := range m.procs {
		if err := m.spawn(p); err != nil {
			m.bus.Error("[%s] %v", p.chain, err)
			failed = append(failed, p.chain)
		}
	}
	if len(failed) == len(m.procs) {
		m.mu.Lock()
		m.wantRun = false
		m.mu.Unlock()
		return fmt.Errorf("全部 %d 条链都启动失败", len(failed))
	}
	if len(failed) > 0 {
		m.bus.Warn("以下链启动失败: %s", strings.Join(failed, ", "))
	}
	for _, p := range m.procs {
		m.wg.Add(1)
		go m.supervise(p)
	}
	return nil
}

// Stop 停止全部并等待退出。
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.wantRun {
		m.mu.Unlock()
		return
	}
	m.wantRun = false
	m.mu.Unlock()

	for _, p := range m.procs {
		p.mu.Lock()
		c := p.cmd
		p.mu.Unlock()
		if c != nil && c.Process != nil {
			_ = c.Process.Kill()
		}
	}
	waitTimeout(&m.wg, 5*time.Second)
	m.job.close()
	select {
	case <-m.done:
	default:
		close(m.done)
	}
}

// Running 是否有任意一条链在跑。
func (m *Manager) Running() bool {
	for _, p := range m.procs {
		p.mu.Lock()
		c := p.cmd
		p.mu.Unlock()
		if c != nil && c.Process != nil && c.ProcessState == nil {
			return true
		}
	}
	return false
}

// PIDs 返回所有子进程 PID。
func (m *Manager) PIDs() []int {
	var out []int
	for _, p := range m.procs {
		p.mu.Lock()
		c := p.cmd
		p.mu.Unlock()
		if c != nil && c.Process != nil {
			out = append(out, c.Process.Pid)
		}
	}
	return out
}

// PID 返回第一个子进程 PID（界面展示用；没有则 0）。
func (m *Manager) PID() int {
	if ps := m.PIDs(); len(ps) > 0 {
		return ps[0]
	}
	return 0
}

func (m *Manager) spawn(p *proc) error {
	// winrun 已经把 SysProcAttr 设成"隐藏控制台"了，这里不要再覆盖
	cmd := winrun.Command(m.exe, p.args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动失败（%s）: %w", m.exe, err)
	}
	p.mu.Lock()
	p.cmd = cmd
	p.mu.Unlock()

	if err := m.job.assign(cmd.Process.Pid); err != nil {
		m.bus.Warn("[%s] 加入 Job Object 失败: %v", p.chain, err)
	}
	m.bus.Info("[%s] gost 已启动 PID=%d（静默无窗口）", p.chain, cmd.Process.Pid)
	go m.pipe(stdout, p.chain)
	go m.pipe(stderr, p.chain+"!")
	return nil
}

func (m *Manager) pipe(r interface{ Read([]byte) (int, error) }, tag string) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\r\n"), "\n") {
				if strings.TrimSpace(line) != "" {
					m.bus.Info("[%s] %s", tag, strings.TrimRight(line, "\r"))
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// supervise 守护单个子进程：意外退出就重启，连续快速失败则放弃。
func (m *Manager) supervise(p *proc) {
	defer m.wg.Done()
	for {
		p.mu.Lock()
		cmd := p.cmd
		p.mu.Unlock()
		if cmd == nil {
			return
		}
		start := time.Now()
		err := cmd.Wait()

		m.mu.Lock()
		wantRun := m.wantRun
		m.mu.Unlock()
		if !wantRun {
			m.bus.Info("[%s] gost 已按要求停止", p.chain)
			return
		}

		p.mu.Lock()
		if time.Since(start) > 30*time.Second {
			p.fails = 0 // 稳定跑过一段，重置计数
		}
		p.fails++
		fails := p.fails
		p.mu.Unlock()

		m.bus.Warn("[%s] gost 意外退出（%v），第 %d 次重启", p.chain, err, fails)
		if fails > 5 {
			m.bus.Error("[%s] 连续启动失败，停止重启。请检查 exe 路径与 forward 参数", p.chain)
			return
		}
		time.Sleep(time.Duration(fails) * 2 * time.Second)
		m.mu.Lock()
		stillWant := m.wantRun
		m.mu.Unlock()
		if !stillWant {
			return
		}
		if err := m.spawn(p); err != nil {
			m.bus.Error("[%s] 重启失败: %v", p.chain, err)
		}
	}
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}
