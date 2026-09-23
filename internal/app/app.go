// Package app 把各部件装配成一个可启停的整体，并向上（GUI）暴露状态与通知。
package app

import (
	"fmt"
	"sync"
	"time"

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

	mu        sync.Mutex
	running   bool
	lastErr   string        // 最近一次失败的原因（启动失败 / 拦截中断）；成功启动后清空
	hostsStop chan struct{} // 停 hosts 定期自检

	// opMu 串行化 Start/Stop/Restart（托盘、界面、-quit 都会分别调）。
	// 不加锁时，“停止”与“启动”会同时动 Engine 与 hosts 自检，结果是半死状态。
	opMu sync.Mutex
}

// startHostsWatch 定期检查 hosts 是否还是我们要的样子。
//
// 现场实例：hosts 里有别的程序写的同名记录（它们写在我们块的上面），而 Windows 取**第一条**
// 匹配 —— 我们写的那些等于没用；又或者别的程序干脆把整个文件重写一遍。
// 这种“静默失效”没地方看，所以：不一致就改回来，并把原因和条数报出来。
func (a *App) startHostsWatch() {
	a.mu.Lock()
	if a.hostsStop != nil { // 已经有人在看了（重启时）
		a.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	a.hostsStop = stop
	a.mu.Unlock()

	go func() {
		tk := time.NewTicker(60 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			if !a.Running() || !a.Cfg.Hosts.Manage || len(a.Cfg.Hosts.Entries) == 0 {
				continue
			}
			ok, why := hostsmgr.Verify(a.Cfg.Hosts.Entries)
			if ok {
				continue
			}
			res, err := hostsmgr.Apply(a.Cfg.Hosts.Entries)
			if err != nil {
				a.Bus.Error("hosts 被改动了（%s），且自动恢复失败: %v", why, err)
				a.notify("hosts 被改动且恢复失败", err.Error(), NotifyError)
				continue
			}
			a.Bus.Warn("hosts 被其他程序改动了（%s）→ 已自动恢复 %d 条（已刷 DNS 缓存）", why, res.Written)
			for _, t := range res.TakenOver {
				a.Bus.Warn("  ├ 接管同名记录: %s", t)
			}
		}
	}()
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
	a.opMu.Lock()
	defer a.opMu.Unlock()
	return a.startLocked()
}

func (a *App) startLocked() error {
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
	// 旧版加过密的配置 + 保险箱丢了 → 这条链必然认证失败，先把话说清楚
	if legacy := a.Cfg.LegacySecretWarning(); len(legacy) > 0 {
		a.Bus.Error("⚠ 这些链还引用着旧版加密口令，但解不开（secrets.dat 丢了或换了机器）：%v", legacy)
		a.Bus.Error("   新版不再加密口令 —— 请把口令直接填回链路的 forward（形如 socks5+tls://用户名:口令@主机:端口）")
		a.notify("有链路的旧版口令解不开", "请把口令重新填进链路的上游地址（新版用明文）", NotifyError)
	}
	if err := a.Rules.Load(toRules(a.Cfg.Routes)); err != nil {
		a.Bus.Error("规则载入失败: %v", err)
		a.setLastError("规则载入失败：" + err.Error())
		a.notify("启动失败", err.Error(), NotifyError)
		return err
	}

	// 1) hosts（可选）
	if a.Cfg.Hosts.Manage {
		if res, err := hostsmgr.Apply(a.Cfg.Hosts.Entries); err != nil {
			a.Bus.Warn("hosts 写入失败（不影响拦截）: %v", err)
			a.notify("hosts 未写入", err.Error(), NotifyWarn)
		} else {
			a.Bus.Info("hosts 已更新（%d 条，已刷 DNS 缓存）", res.Written)
			// 块外原本有同名记录时，Windows 会先用那条（第一条匹配）→ 必须说一声
			for _, t := range res.TakenOver {
				a.Bus.Warn("hosts 里原有同名记录，已被 NetHub 接管（否则写进去也不生效）: %s", t)
			}
			if res.FlushError != nil {
				a.Bus.Warn("刷 DNS 缓存失败（解析可能要等缓存过期才生效）: %v", res.FlushError)
			}
		}
		a.startHostsWatch()
	}

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
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.stopLocked()
}

func (a *App) stopLocked() {
	a.mu.Lock()
	was := a.running
	a.running = false
	stop := a.hostsStop
	a.hostsStop = nil
	a.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if !was {
		return
	}
	a.Bus.Info("正在停止…")
	a.Engine.Stop()
	a.Bus.Info("✓ 已停止")
	a.notify("NetHub 已停止", "拦截与隧道均已关闭", NotifyWarn)
}

// Restart 重启（改完配置后调用）。
//
// 引擎本身可重复启停（见 engine.Start/Stop），所以这里不再重建 Engine ——
// 重建会把 a.Engine 指针换掉，而界面线程正无锁读它，那是一个数据竞争。
func (a *App) Restart() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.stopLocked()
	return a.startLocked()
}

// SaveConfig 保存配置并同步内存副本。
//
// 顺序有讲究：**先编译规则、再落盘**。rules.Load 比 Validate 多查一些东西
// （链名非空、local_nets 合法…），以前先写文件后编译，会出现“文件已经改了、
// 界面却显示保存失败”—— 下次启动引擎直接起不来。现在编译不过就一个字节也不写。
func (a *App) SaveConfig() error {
	if err := a.Cfg.Validate(); err != nil {
		return err
	}
	if err := a.Rules.Load(toRules(a.Cfg.Routes)); err != nil {
		return err
	}
	return a.Cfg.Save()
}

// toRules 把配置层的规则转成规则引擎的类型（两层各保持独立，避免互相依赖）。
//
// ⚠️ 加字段时记得同步这里：映射漏一个字段会被静默丢弃（端口维度就这么坑过一次）。
func toRules(rs []config.Route) []rules.Route {
	out := make([]rules.Route, 0, len(rs))
	for _, r := range rs {
		// 停用的规则**不进规则集**：既不参与匹配，也不进内核过滤器 ——
		// 所以停掉一条规则是真正的零开销（而不是“匹配到了再忽略”）。
		if !r.IsEnabled() {
			continue
		}
		act := rules.ActionChain
		switch {
		case r.IsDirect():
			act = rules.ActionDirect
		case r.IsBlock():
			act = rules.ActionBlock
		}
		out = append(out, rules.Route{Name: r.Name, Targets: r.Targets, Ports: r.Ports,
			LocalNets: r.LocalNets, Apps: r.Apps, Chain: r.Chain, Action: act})
	}
	return out
}

// BuildRules 供命令行（-check）复用“配置 → 规则集”这条唯一路径。
//
// 为什么单独导出：校验必须走**和启动时完全一样**的转换，否则会出现
// “-check 说没问题、启动却失败”这种最难查的情况。
func BuildRules(cfg *config.Config) (*rules.Set, error) {
	rs := rules.New()
	if err := rs.Load(toRules(cfg.Routes)); err != nil {
		return nil, err
	}
	return rs, nil
}
