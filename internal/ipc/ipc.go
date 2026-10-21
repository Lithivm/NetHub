// Package ipc 让"界面进程"和"引擎进程"说话。
//
// # 为什么要把界面和引擎拆到两个进程
//
// 界面是 Wails/WebView2 应用，它的 Chromium 子进程在系统里固定叫 msedgewebview2.exe。
// 现场机器上装着的 HIS/医保客户端启动器，在清理自己 WebView2 缓存时删不动文件，
// 它的兜底动作是**按进程名把全系统的 msedgewebview2 全部 Kill**（反编译
// Vendor.HIS.Launcher.exe 的 WebMainForm.DelectCache 实证：删除失败 → KillProcessByName
// ("msedgewebview2")；且启动器带管理员清单会静默提权，所以连提权进程也照杀）。
// 界面首当其冲，而 Wails 在浏览器进程消失后直接 os.Exit(-1)、跳过所有收尾。
// 引擎只要和界面同进程，就会被一起带走 —— 现场表现是"NetHub 整个静默消失，
// hosts 段留在系统里没人兑付"。拆进程之后被杀的只有界面：引擎和隧道毫发无损，
// 界面由引擎重新拉起（见 main.go 的 superviseFrontend）。
//
// # 传输与协议
//
// Windows 命名管道（一台机器只有一个界面，单客户端足够），帧格式是"一行一个 JSON"：
//
//	{"i":1,"m":"GetState","a":[]}          界面 → 引擎：调用方法
//	{"i":1,"r":{...}} / {"i":1,"e":"错误"}  引擎 → 界面：应答
//	{"i":-1,"u":"openFile","a":[...]}      引擎 → 界面：反向请求（弹文件框 / 显示窗口）
//	{"i":-1,"r":"C:\\x.yaml"}              界面 → 引擎：反向应答
//	{"v":"log","d":{...}}                  引擎 → 界面：单向事件推送
//
// id 正负分家：界面发起的用正数、引擎发起的用负数，两边各自自增，永不撞号。
//
// 方法派发用反射做（见 dispatch.go）：管道上传的是"方法名 + JSON 参数数组"，
// 引擎侧直接反射调用真正的 *webui.Backend —— 于是界面侧不需要把 80 多个方法
// 抄一遍，前端 JS 也只需要改一个 call() 入口。
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// traceOn 打开后把管道层的每一步打到 stderr（环境变量 NETHUB_IPC_TRACE=1）。
// 现场"界面连不上/调用不回来"这类问题，一眼能看出卡在哪一步。
var traceOn = os.Getenv("NETHUB_IPC_TRACE") != ""

func tracef(format string, a ...any) {
	if traceOn {
		// 带时间戳：排"界面多久才拿到 running=true"这类问题全靠它
		//（日志那边是另一个进程写的，两边只能靠时间对齐）。
		fmt.Fprintf(os.Stderr, "[ipc] %s "+format+"\n", append([]any{time.Now().Format("15:04:05.000")}, a...)...)
	}
}

// ErrNoUI 表示界面进程不在（没连上来或已经断开）。引擎侧遇到它不是致命错误：
// 界面死了引擎照跑，等界面回来继续。
var ErrNoUI = errors.New("界面进程不在")

// PipeName 返回本机上属于当前用户的管道名。
//
// 带上用户名是为了让"同一台机器多个用户各自跑一份 NetHub"互不干扰；
// 带上 tag 是为了让一条机器上并存的多份实例（比如服务版 + 界面版）各有自己的管子。
func PipeName(tag string) string {
	user := os.Getenv("USERNAME")
	if user == "" {
		user = "default"
	}
	return `\\.\pipe\nethub-` + user + `-` + tag
}

// DefaultTimeout 是反向请求（引擎问界面要东西）的兜底超时：界面进程被杀时
// 管道会立刻断开、等待者当场被唤醒，所以这个超时只防"界面活着但不理人"。
const DefaultTimeout = 30 * time.Second

// frame 是管道上的一帧。字段全部 omitempty，一帧只带它用得着的那几个。
type frame struct {
	ID     int64             `json:"i,omitempty"`
	Method string            `json:"m,omitempty"` // 界面 → 引擎：方法名
	Op     string            `json:"u,omitempty"` // 引擎 → 界面：反向操作名
	Args   []json.RawMessage `json:"a,omitempty"`
	Result json.RawMessage   `json:"r,omitempty"`
	Err    string            `json:"e,omitempty"`
	Event  string            `json:"v,omitempty"` // 引擎 → 界面：事件名
	Data   json.RawMessage   `json:"d,omitempty"`
}

// ───────────────────────────── 引擎侧：Server ─────────────────────────────

// Server 是引擎侧的管道服务端：接受界面连接、反射派发前端的方法调用、
// 推送事件、并支持"反向请求"（让界面弹文件对话框、显示窗口）。
type Server struct {
	name   string
	target any

	mu      sync.Mutex
	conn    *pipeConn
	ln      *pipeListener        // 正在等连接的那个实例（Close 时关它，唤醒阻塞的 Accept）
	pending map[int64]chan frame // 反向请求的等待者（id 为负）
	nextID  int64

	connHook func(connected bool) // 界面连上/断开时回调（看护/日志用）
	closed   chan struct{}
	started  bool
}

// NewServer 建服务端。target 是反射派发的目标（这里是 *webui.Backend）。
func NewServer(name string, target any) *Server {
	return &Server{
		name:    name,
		target:  target,
		pending: make(map[int64]chan frame),
		closed:  make(chan struct{}),
	}
}

// SetConnHook 设置"界面连上/断开"回调。
//
// 契约：**连上的那次回调不得依赖本连接上的读**（比如在里面发反向请求）——
// 连上时钩子先于 readLoop 启动，同步调用会把读循环堵住、把回执永远等不到
// （2026-10-14 实测：连上就推主题 → 恒定卡满 30 秒超时）。所以连上那次由服务端
// 另起 goroutine 调（见 acceptLoop），钩子里也尽可以慢慢做。
func (s *Server) SetConnHook(fn func(connected bool)) { s.connHook = fn }

// Start 起服务端：建好管道实例并开始等界面连上（不阻塞）。
func (s *Server) Start() error {
	ln, err := listenPipe(s.name)
	if err != nil {
		return fmt.Errorf("ipc: 建管道 %s 失败: %w", s.name, err)
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("ipc: 服务端已经启动")
	}
	s.started = true
	s.ln = ln
	s.mu.Unlock()
	go s.acceptLoop(ln)
	return nil
}

// Close 关掉服务端与当前连接。
func (s *Server) Close() {
	s.mu.Lock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	c := s.conn
	ln := s.ln
	s.mu.Unlock()
	// 先关监听：阻塞在 Accept 的循环当场被放走
	if ln != nil {
		_ = ln.Close()
	}
	if c != nil {
		c.Close()
	}
}

// Connected 界面现在连着吗。
func (s *Server) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil
}

// Emit 推一条事件给界面；界面不在就当没这回事（返回 ErrNoUI）。
func (s *Server) Emit(event string, data any) error {
	c := s.currentConn()
	if c == nil {
		return ErrNoUI
	}
	var raw json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("ipc: 事件 %s 序列化失败: %w", event, err)
		}
		raw = b
	}
	return c.write(frame{Event: event, Data: raw})
}

// Request 反向请求界面做一件事（弹框、显示窗口……），等它回答。
func (s *Server) Request(ctx context.Context, op string, args ...any) (json.RawMessage, error) {
	c := s.currentConn()
	if c == nil {
		return nil, ErrNoUI
	}
	rawArgs, err := marshalArgs(args)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
	}
	s.mu.Lock()
	s.nextID--
	id := s.nextID
	ch := make(chan frame, 1)
	s.pending[id] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	if err := c.write(frame{ID: id, Op: op, Args: rawArgs}); err != nil {
		return nil, err
	}
	select {
	case f := <-ch:
		if f.Err != "" {
			return nil, errors.New(f.Err)
		}
		return f.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, errors.New("ipc: 服务端已关闭")
	case <-c.done:
		return nil, ErrNoUI
	}
}

func (s *Server) currentConn() *pipeConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// acceptLoop 反复接界面：一个界面断开了，就回到这里等下一个。
// 监听实例建一次就够（go-winio 的 Accept 会自己补出下一个实例）。
func (s *Server) acceptLoop(ln *pipeListener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			// 关停时 Accept 必然报错；运行中报错多半是瞬时问题，等一下再来
			select {
			case <-s.closed:
				return
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}
		s.mu.Lock()
		s.conn = c
		s.mu.Unlock()
		tracef("acceptLoop: 界面已连上，开始读")
		// 钩子**必须**另起 goroutine：它可能做反向请求（比如连上就推主题），
		// 而反向请求的回执要等下面的 readLoop 去读 —— 同步调用 = 自己堵自己，
		// 恒定等满超时（实测 30 秒，期间界面所有方法调用都堆着、状态整整滞后 30 秒）。
		if s.connHook != nil {
			go s.connHook(true)
		}
		c.readLoop(func(f frame) {
			switch {
			case f.ID > 0 && f.Method != "":
				// 前端发来的方法调用
				go s.handleCall(c, f)
			case f.ID < 0:
				// 反向请求的应答
				s.mu.Lock()
				ch := s.pending[f.ID]
				s.mu.Unlock()
				if ch != nil {
					ch <- f
				}
			}
		})
		tracef("acceptLoop: 读到断开，收尾")
		c.Close()
		s.mu.Lock()
		if s.conn == c {
			s.conn = nil
		}
		s.mu.Unlock()
		s.failPending() // 界面没了：还等着它回答的反向请求当场作废，别把引擎吊死
		if s.connHook != nil {
			s.connHook(false)
		}
	}
}

func (s *Server) failPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ch := range s.pending {
		ch <- frame{ID: id, Err: ErrNoUI.Error()}
		delete(s.pending, id)
	}
}

func (s *Server) handleCall(c *pipeConn, f frame) {
	res, err := dispatch(s.target, f.Method, f.Args)
	if err != nil {
		_ = c.write(frame{ID: f.ID, Err: err.Error()})
		return
	}
	_ = c.write(frame{ID: f.ID, Result: res})
}

// ───────────────────────────── 界面侧：Client ─────────────────────────────

// Client 是界面侧的管道客户端：调引擎、接事件、并应答引擎的反向请求。
type Client struct {
	conn *pipeConn

	mu      sync.Mutex
	pending map[int64]chan frame
	nextID  int64

	onEvent   func(event string, data json.RawMessage)
	onRequest func(op string, args []json.RawMessage) (any, error)
	onDown    func(error)
}

// Dial 连引擎的管道。timeout 是"等引擎把管子建起来"的上限。
func Dial(name string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		c, err := dialPipe(name, 500*time.Millisecond)
		if err == nil {
			cl := &Client{conn: c, pending: make(map[int64]chan frame)}
			go cl.readLoop()
			return cl, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// SetEventHandler 事件回调（引擎推来的 log/notify/selftest…）。
func (c *Client) SetEventHandler(fn func(event string, data json.RawMessage)) { c.onEvent = fn }

// SetRequestHandler 反向请求处理（弹文件框、显示窗口、退出界面…）。
func (c *Client) SetRequestHandler(fn func(op string, args []json.RawMessage) (any, error)) {
	c.onRequest = fn
}

// SetDownHandler 连接断开时回调一次（界面拿它把状态标成"引擎不在了"）。
func (c *Client) SetDownHandler(fn func(error)) { c.onDown = fn }

// Call 调引擎上的一个方法，等结果。
//
// 刻意不设默认超时：有些方法天然慢（探测链路、体检），还有的要等用户在界面上选文件。
// 断开（引擎挂了/被杀了）会立刻唤醒所有等待者，所以不会永久吊住。
func (c *Client) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	rawArgs, err := marshalArgs(args)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan frame, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.conn.write(frame{ID: id, Method: method, Args: rawArgs}); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case f := <-ch:
		if f.Err != "" {
			return nil, errors.New(f.Err)
		}
		return f.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.conn.done:
		return nil, errors.New("ipc: 与引擎的连接已断开")
	}
}

// Close 断开。
func (c *Client) Close() { c.conn.Close() }

// Done 连接断开的信号（可用于 select）。
func (c *Client) Done() <-chan struct{} { return c.conn.done }

func (c *Client) readLoop() {
	err := c.conn.readLoop(func(f frame) {
		switch {
		case f.Event != "":
			if c.onEvent != nil {
				c.onEvent(f.Event, f.Data)
			}
		case f.ID < 0 && f.Op != "":
			go c.handleRequest(f)
		case f.ID > 0:
			c.mu.Lock()
			ch := c.pending[f.ID]
			c.mu.Unlock()
			if ch != nil {
				ch <- f
			}
		}
	})
	c.failPending()
	if c.onDown != nil {
		c.onDown(err)
	}
}

func (c *Client) handleRequest(f frame) {
	var (
		res any
		err error
	)
	if c.onRequest == nil {
		err = fmt.Errorf("界面不认识这个请求: %s", f.Op)
	} else {
		res, err = c.onRequest(f.Op, f.Args)
	}
	if err != nil {
		_ = c.conn.write(frame{ID: f.ID, Err: err.Error()})
		return
	}
	var raw json.RawMessage
	if res != nil {
		if b, mErr := json.Marshal(res); mErr == nil {
			raw = b
		} else {
			_ = c.conn.write(frame{ID: f.ID, Err: "结果序列化失败: " + mErr.Error()})
			return
		}
	}
	_ = c.conn.write(frame{ID: f.ID, Result: raw})
}

func (c *Client) failPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		ch <- frame{ID: id, Err: "ipc: 与引擎的连接已断开"}
		delete(c.pending, id)
	}
}

// marshalArgs 把可变参数编成 JSON 数组。
func marshalArgs(args []any) ([]json.RawMessage, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]json.RawMessage, 0, len(args))
	for i, a := range args {
		b, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("ipc: 第 %d 个参数无法序列化: %w", i+1, err)
		}
		out = append(out, b)
	}
	return out, nil
}
