package webui

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"nethub/internal/ipc"
)

// Bridge 是「界面进程」绑定给前端 JS 的那个对象。
//
// 前端只认这一个口子：app.js 里所有后端调用都走 call(fn, ...args) → Bridge.Call，
// 所以那 80 多个后端方法一个都不用在界面侧抄一遍 —— 引擎侧靠反射派发
// （见 internal/ipc/dispatch.go）。前端 JS 里 R().EventsOn(...) 那些监听器也不用改：
// 管道推来的事件在这里转成 Wails 事件再抛给 JS。
//
// 它同时代引擎做界面动作（弹文件框、显示/隐藏窗口、换主题、退出）—— 这些动作
// 只有界面进程有窗口和 Wails 上下文，引擎进程做不了（见 ui.go 的 UI 接口）。
type Bridge struct {
	pipeName string

	initialTheme string // 见 NewBridge

	mu      sync.RWMutex
	ctx     context.Context
	client  *ipc.Client
	lastErr string
	everUp  bool // 曾经连上过：用来区分"首连"和"断后重连"，免得启动就弹一句废话

	closed chan struct{}
	once   sync.Once
}

// NewBridge 造界面侧的桥。pipeName 要跟引擎进程建的一致（main.go 里同一个来源）。
// initialTheme 是启动参数里那个主题（dark/light）：界面**第一帧**就用它，避免
//
//	先浅色再等 GetState 回来才变暗 —— 那一闪会被当成"没记住我的深色设置"。
func NewBridge(pipeName, initialTheme string) *Bridge {
	return &Bridge{pipeName: pipeName, initialTheme: initialTheme, closed: make(chan struct{})}
}

// InitialTheme 启动时那个主题（同步取，不走管道）。
func (br *Bridge) InitialTheme() string { return br.initialTheme }

// OnStartup 由 Wails 调用：记住 ctx（反向操作要用），开始连引擎。
func (br *Bridge) OnStartup(ctx context.Context) {
	br.mu.Lock()
	br.ctx = ctx
	br.mu.Unlock()
	go br.connectLoop()
}

// Call 前端调用引擎方法的唯一入口。返回值/错误与 Wails bindings 的老语义一致：
// error 非空 → 前端 Promise reject，catch 到的是错误文本。
func (br *Bridge) Call(method string, args []any) (any, error) {
	if method == "" {
		return nil, errors.New("方法名为空")
	}
	c := br.currentClient()
	if c == nil {
		br.mu.RLock()
		why := br.lastErr
		br.mu.RUnlock()
		if why == "" {
			why = "引擎进程不在"
		}
		return nil, errors.New(why + "（界面会每隔一会儿自动重连；隧道若已就绪仍在跑）")
	}
	raw, err := c.Call(context.Background(), method, args...)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errors.New("引擎返回的内容看不懂: " + err.Error())
	}
	return v, nil
}

// EngineLinkView 给界面看一眼"引擎连上没有"（诊断页/标题栏用得上）。
type EngineLinkView struct {
	Connected bool   `json:"connected"`
	Pipe      string `json:"pipe"`
	LastError string `json:"lastError"`
}

// GetEngineLink 当前与引擎的连接状态。
func (br *Bridge) GetEngineLink() EngineLinkView {
	br.mu.RLock()
	defer br.mu.RUnlock()
	return EngineLinkView{Connected: br.client != nil, Pipe: br.pipeName, LastError: br.lastErr}
}

// connectLoop 反复连引擎：连上就干活，断了就等一会儿再连。
//
// 界面比引擎先起来（或引擎被重启）都是常态，所以这里绝不能"连不上就退出"。
func (br *Bridge) connectLoop() {
	for {
		select {
		case <-br.closed:
			return
		default:
		}
		c, err := ipc.Dial(br.pipeName, 2*time.Second)
		if err != nil {
			br.setDown(err.Error())
			select {
			case <-br.closed:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		c.SetEventHandler(br.onEngineEvent)
		c.SetRequestHandler(br.serve)
		br.setUp(c)
		<-c.Done() // 一直等到断开
		br.setDown("与引擎进程的连接已断开")
		select {
		case <-br.closed:
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (br *Bridge) onEngineEvent(name string, data json.RawMessage) {
	br.mu.RLock()
	ctx := br.ctx
	br.mu.RUnlock()
	if ctx == nil {
		return
	}
	var v any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &v); err != nil {
			return
		}
	}
	wruntime.EventsEmit(ctx, name, v)
}

func (br *Bridge) setDown(why string) {
	br.mu.Lock()
	was := br.client != nil
	br.client = nil
	br.lastErr = why
	br.mu.Unlock()
	if was {
		br.toast("与引擎断开", why+"（界面会自动重连，隧道不受影响）", "warn")
	}
}

func (br *Bridge) setUp(c *ipc.Client) {
	br.mu.Lock()
	first := !br.everUp
	br.everUp = true
	br.client = c
	br.lastErr = ""
	br.mu.Unlock()
	if !first {
		br.toast("已重新连上引擎", "界面恢复与引擎的通信", "info")
	}
}

func (br *Bridge) currentClient() *ipc.Client {
	br.mu.RLock()
	defer br.mu.RUnlock()
	return br.client
}

// toast 借前端的 notify 事件弹一条应用内提示（app.js 里已有这个监听器）。
func (br *Bridge) toast(title, text, kind string) {
	br.onEngineEvent("notify", mustJSON(NotifyView{Title: title, Text: text, Kind: kind}))
}

// ───────────────────── 代引擎做界面动作（反向请求）─────────────────────

// serve 处理引擎发来的界面动作请求。名字与 ui.go 里的常量一一对应。
func (br *Bridge) serve(op string, args []json.RawMessage) (any, error) {
	br.mu.RLock()
	ctx := br.ctx
	br.mu.RUnlock()
	if ctx == nil {
		return nil, errors.New("界面还没就绪")
	}
	switch op {
	case uiOpShowWindow:
		wruntime.WindowShow(ctx)
		wruntime.WindowUnminimise(ctx)
		return nil, nil
	case uiOpHideWindow:
		wruntime.WindowHide(ctx)
		return nil, nil
	case uiOpQuitApp:
		wruntime.Quit(ctx)
		return nil, nil
	case uiOpSetTheme:
		var dark bool
		if err := json.Unmarshal(first(args), &dark); err != nil {
			return nil, err
		}
		br.applyTheme(ctx, dark)
		return nil, nil
	case uiOpOpenFile:
		var opts wruntime.OpenDialogOptions
		if err := json.Unmarshal(first(args), &opts); err != nil {
			return nil, err
		}
		return wruntime.OpenFileDialog(ctx, opts)
	case uiOpOpenDir:
		var opts wruntime.OpenDialogOptions
		if err := json.Unmarshal(first(args), &opts); err != nil {
			return nil, err
		}
		return wruntime.OpenDirectoryDialog(ctx, opts)
	case uiOpSaveFile:
		var opts wruntime.SaveDialogOptions
		if err := json.Unmarshal(first(args), &opts); err != nil {
			return nil, err
		}
		return wruntime.SaveFileDialog(ctx, opts)
	}
	return nil, errors.New("界面不认识这个请求: " + op)
}

// applyTheme 换主题：标题栏/控件主题 + 窗口底色一起换，否则深色底配浅色自绘栏会花。
func (br *Bridge) applyTheme(ctx context.Context, dark bool) {
	if dark {
		wruntime.WindowSetDarkTheme(ctx)
		wruntime.WindowSetBackgroundColour(ctx, 0x14, 0x13, 0x12, 0xff)
		return
	}
	wruntime.WindowSetLightTheme(ctx)
	wruntime.WindowSetBackgroundColour(ctx, 0xff, 0xff, 0xff, 0xff)
}

// ShowWindowSelf 供第二实例的唤回路径用：把本进程的窗口叫到前面。
func (br *Bridge) ShowWindowSelf() {
	br.mu.RLock()
	ctx := br.ctx
	br.mu.RUnlock()
	if ctx != nil {
		wruntime.WindowShow(ctx)
		wruntime.WindowUnminimise(ctx)
	}
}

// HideToTrayNow 界面进程内部的"收进托盘"（自绘标题栏以外的系统关闭路径用它）。
//
// 两件事：① 告诉后端我现在是收着的（重启时按这个决定窗口要不要露出来）；
// ② 把窗口藏起来。上报是**尽力而为**的异步调用：后端万一不在，窗口照样得藏。
func (br *Bridge) HideToTrayNow(ctx context.Context) {
	go br.Call("NoteUIHidden", []any{true})
	wruntime.WindowHide(ctx)
}

// Close 断开与引擎的连接（界面退出时调）。
func (br *Bridge) Close() {
	br.once.Do(func() { close(br.closed) })
	if c := br.currentClient(); c != nil {
		c.Close()
	}
}

func first(args []json.RawMessage) json.RawMessage {
	if len(args) == 0 {
		return nil
	}
	return args[0]
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
