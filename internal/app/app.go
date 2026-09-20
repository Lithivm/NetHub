// Package app 把各部件装配成一个可启停的整体，并向上（GUI）暴露状态与通知。
package app

import (
	"fmt"
	"sync"

	"nethub/internal/config"
	"nethub/internal/engine"
	"nethub/internal/hostsmgr"
	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// NotifyKind 通知级别，对应托盘气泡图标。
type NotifyKind int

const (
	NotifyInfo NotifyKind = iota
	NotifyWarn
	NotifyError
)

// App 是应用的运行时容器。
type App struct {
	Bus    *logbus.Bus
	Cfg    *config.Config
	Rules  *rules.Set
	Engine *engine.Engine

	// Notify 由 GUI 注入：把状态变化变成系统托盘通知。
	Notify func(title, text string, kind NotifyKind)

	mu      sync.Mutex
	running bool
	lastErr string // 最近一次失败的原因（启动失败 / 拦截中断）；成功启动后清空
}

// LastError 最近一次异常：启动失败或拦截中断（空 = 没有）。
func (a *App) LastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// setLastError 记下（或清空）最近一次异常。
func (a *App) setLastError(s string) {
	a.mu.Lock()
	a.lastErr = s
	a.mu.Unlock()
}

// Status 给界面用的三态：运行中 / 已停止 / 出错。
// 出错优先：拦截中断后（驱动卸载、被别的程序抢了句柄）不能再显示绿点，
// 否则界面说"运行中"、实际一个包都没拦 —— 那种静默失败最坑人。
//
//	running = true 且无错 → Ready
//	running = false 但有错 → Error（红）
//	running = false 无错   → 已停止（灰，手动停的不算错）
func (a *App) Status() (running bool, errText string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.Engine.Fatal(); e != nil {
		return false, e.Error()
	}
	if a.lastErr != "" {
		return false, a.lastErr
	}
	return a.running, ""
}

func New(cfg *config.Config, bus *logbus.Bus) *App {
	rs := rules.New()
	a := &App{Bus: bus, Cfg: cfg, Rules: rs}
	a.Engine = engine.New(bus, rs, cfg)
	// 引擎里的"状态变化"（上游挂了、业务目标不通）走同一套应用内提示
	a.Engine.Notify = func(title, text string, bad bool) {
		kind := NotifyInfo
		if bad {
			kind = NotifyError
		}
		a.notify(title, text, kind)
	}
	a.Notify = func(string, string, NotifyKind) {} // 默认空实现，GUI 起来后替换
	return a
}

func (a *App) notify(t string, text string, k NotifyKind) {
	if a.Notify != nil {
		a.Notify(t, text, k)
	}
}

// String 给前端用的通知级别名。
func (k NotifyKind) String() string {
	switch k {
	case NotifyWarn:
		return "warn"
	case NotifyError:
		return "error"
	default:
		return "info"
	}
}

// Running 返回是否已启动。
func (a *App) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// Start 按顺序拉起：写 hosts → 起 gost → 等端口就绪 → 开拦截。
func (a *App) Start() error {
	a.setLastError("") // 重新启动就清掉上次的错
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("已在运行")
	}
	a.mu.Unlock()

	if err := a.Cfg.Validate(); err != nil {
		a.Bus.Error("配置不合法: %v", err)
		a.setLastError("配置不合法：" + err.Error())
		a.notify("启动失败", err.Error(), NotifyError)
		return err
	}
	if err := a.Rules.Load(toRules(a.Cfg.Routes)); err != nil {
		a.Bus.Error("规则载入失败: %v", err)
		a.setLastError("规则载入失败：" + err.Error())
		a.notify("启动失败", err.Error(), NotifyError)
		return err
	}

	// 1) hosts（可选）
	if a.Cfg.Hosts.Manage {
		if err := hostsmgr.Apply(a.Cfg.Hosts.Entries); err != nil {
			a.Bus.Warn("hosts 写入失败（不影响拦截）: %v", err)
			a.notify("hosts 未写入", err.Error(), NotifyWarn)
		} else {
			a.Bus.Info("hosts 已更新（%d 条）", len(a.Cfg.Hosts.Entries))
		}
	}

	a.Bus.Info("上游为原生实现（无需 gost 子进程）")

	// 2) 拦截
	if err := a.Engine.Start(); err != nil {
		a.Bus.Error("%v", err)
		a.setLastError("拦截启动失败：" + err.Error())
		a.notify("拦截启动失败", err.Error(), NotifyError)
		return err
	}

	a.mu.Lock()
	a.running = true
	a.mu.Unlock()

	total := len(a.Rules.List())
	text := fmt.Sprintf("已接管 %d 条规则，relay %s", total, a.Engine.RelayAddr())
	a.Bus.Info("✓ 服务已就绪：%s", text)
	a.notify("NetHub 已启动", text, NotifyInfo)
	return nil
}

// Stop 逆序收尾：停拦截 → 清 hosts（如果由我们托管）。
func (a *App) Stop() {
	a.mu.Lock()
	was := a.running
	a.running = false
	a.mu.Unlock()
	if !was {
		return
	}
	a.Bus.Info("正在停止…")
	a.Engine.Stop()
	a.Bus.Info("✓ 已停止")
	a.notify("NetHub 已停止", "拦截与隧道均已关闭", NotifyWarn)
}

// Restart 重启（改完配置后调用）。
func (a *App) Restart() error {
	a.Stop()
	// 允许再次启动：重置 bus 的一次性状态不存在，但 Engine 需要重建
	a.Engine = engine.New(a.Bus, a.Rules, a.Cfg)
	return a.Start()
}

// SaveConfig 保存配置并同步内存副本。
func (a *App) SaveConfig() error {
	if err := a.Cfg.Validate(); err != nil {
		return err
	}
	if err := a.Cfg.Save(); err != nil {
		return err
	}
	return a.Rules.Load(toRules(a.Cfg.Routes))
}

// toRules 把配置层的规则转成规则引擎的类型（两层各保持独立，避免互相依赖）。
//
// ⚠️ 加字段时记得同步这里：映射漏一个字段会被静默丢弃（端口维度就这么坑过一次）。
func toRules(rs []config.Route) []rules.Route {
	out := make([]rules.Route, 0, len(rs))
	for _, r := range rs {
		act := rules.ActionChain
		switch {
		case r.IsDirect():
			act = rules.ActionDirect
		case r.IsBlock():
			act = rules.ActionBlock
		}
		out = append(out, rules.Route{Name: r.Name, Targets: r.Targets, Ports: r.Ports, Chain: r.Chain, Action: act})
	}
	return out
}
