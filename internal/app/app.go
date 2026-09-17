// Package app 把各部件装配成一个可启停的整体，并向上（GUI）暴露状态与通知。
package app

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"netproxy/internal/config"
	"netproxy/internal/engine"
	"netproxy/internal/gostproc"
	"netproxy/internal/hostsmgr"
	"netproxy/internal/logbus"
	"netproxy/internal/rules"
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
	Gost   *gostproc.Manager

	// Notify 由 GUI 注入：把状态变化变成系统托盘通知。
	Notify func(title, text string, kind NotifyKind)

	mu      sync.Mutex
	running bool
}

func New(cfg *config.Config, bus *logbus.Bus) *App {
	rs := rules.New()
	a := &App{Bus: bus, Cfg: cfg, Rules: rs}
	a.Gost = gostproc.New(bus, cfg.Gost, cfg.Chains)
	a.Engine = engine.New(bus, rs, cfg)
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
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("已在运行")
	}
	a.mu.Unlock()

	if err := a.Cfg.Validate(); err != nil {
		a.Bus.Error("配置不合法: %v", err)
		a.notify("启动失败", err.Error(), NotifyError)
		return err
	}
	if err := a.Rules.Load(toRules(a.Cfg.Routes)); err != nil {
		a.Bus.Error("规则载入失败: %v", err)
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

	// 2) gost 子进程
	if a.Cfg.Gost.Enabled {
		if err := a.Gost.Start(); err != nil {
			a.Bus.Error("%v", err)
			a.notify("gost 启动失败", err.Error(), NotifyError)
			return err
		}
		// 等 gost 的 socks 端口就绪（最多 10 秒）
		if bad := a.waitChains(10 * time.Second); len(bad) > 0 {
			msg := "以下链的本地 socks 端口未就绪: " + strings.Join(bad, ", ")
			a.Bus.Error("%s", msg)
			a.notify("链路未就绪", msg, NotifyError)
			return fmt.Errorf("%s", msg)
		}
		a.Bus.Info("所有链的本地 socks 端口已就绪")
	} else {
		a.Bus.Info("gost 托管已关闭，假定外部的 socks 服务已就绪")
	}

	// 3) 拦截
	if err := a.Engine.Start(); err != nil {
		a.Bus.Error("%v", err)
		a.notify("拦截启动失败", err.Error(), NotifyError)
		if a.Cfg.Gost.Enabled {
			a.Gost.Stop()
		}
		return err
	}

	a.mu.Lock()
	a.running = true
	a.mu.Unlock()

	total := len(a.Rules.List())
	text := fmt.Sprintf("已接管 %d 条规则，relay %s", total, a.Engine.RelayAddr())
	a.Bus.Info("✓ 服务已就绪：%s", text)
	a.notify("netproxy 已启动", text, NotifyInfo)
	return nil
}

// Stop 逆序收尾：停拦截 → 停 gost → 清 hosts（如果由我们托管）。
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
	if a.Cfg.Gost.Enabled {
		a.Gost.Stop()
	}
	a.Bus.Info("✓ 已停止（所有子进程已回收）")
	a.notify("netproxy 已停止", "拦截与隧道均已关闭", NotifyWarn)
}

// Restart 重启（改完配置后调用）。
func (a *App) Restart() error {
	a.Stop()
	// 允许再次启动：重置 bus 的一次性状态不存在，但 Engine/Gost 需要重建
	a.Engine = engine.New(a.Bus, a.Rules, a.Cfg)
	a.Gost = gostproc.New(a.Bus, a.Cfg.Gost, a.Cfg.Chains)
	return a.Start()
}

// waitChains 轮询各链的本地 socks 端口，返回仍未就绪的链名。
func (a *App) waitChains(timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	var bad []string
	for _, ch := range a.Cfg.Chains {
		if strings.TrimSpace(ch.Forward) == "" {
			continue
		}
		ok := false
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", ch.Listen, 800*time.Millisecond)
			if err == nil {
				c.Close()
				ok = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("%s(%s)", ch.Name, ch.Listen))
		}
	}
	return bad
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
func toRules(rs []config.Route) []rules.Route {
	out := make([]rules.Route, 0, len(rs))
	for _, r := range rs {
		out = append(out, rules.Route{Target: r.Target, Chain: r.Chain})
	}
	return out
}
