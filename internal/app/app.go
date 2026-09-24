// Package app 把各部件装配成一个可启停的整体，并向上（GUI）暴露状态与通知。
package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	lock      *engineLock   // 引擎互斥（非 nil = 本进程在跑引擎）

	// opMu 串行化 Start/Stop/Restart（托盘、界面、-quit 都会分别调）。
	// 不加锁时，“停止”与“启动”会同时动 Engine 与 hosts 自检，结果是半死状态。
	opMu sync.Mutex

	// ── 配置热生效（细节见 hotconfig.go）──

	// Version 版本号（main 注入；写进 runtime.json，-status 直接读它）。
	Version string
	// watchStop 配置文件轮询的停止信号（非 nil = 在轮询）。
	watchStop chan struct{}
	// appliedHash/badHash 当前**生效**的 config.yaml 摘要 / 最近一个报过错的摘要。
	// badHash 是为了不每 2 秒重复报同一个坏文件。
	appliedHash string
	badHash     string
	// appliedAt/appliedRules 最近一次规则热生效的时间与条数（界面正据）。
	appliedAt    time.Time
	appliedRules int
	startedAt    time.Time
	// startupSnap 引擎**按哪份配置启动的**（热重载对比基线，见 RestartRequired）。
	startupSnap    config.ConfigSnapshot
	hasStartupSnap bool
	// lastApply 最近一次保存/热生效的结果（界面 toast 用）。
	lastApply ApplyResult
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
			hosts := a.Cfg.HostsCopy()
			// 拦截已经报错（句柄失效/驱动被拦）时**不能**再把内网域名指回内网 IP：
			// 那时没人兑付，应用会一直等到超时 —— 比没有这条记录还糟。
			if !a.RunningAndHealthy() || !hosts.Manage || len(hosts.Entries) == 0 {
				continue
			}
			ok, why := hostsmgr.Verify(hosts.Entries)
			if ok {
				continue
			}
			res, err := hostsmgr.Apply(hosts.Entries)
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
//
// 注意它**不包含**“拦截是否还活着”：引擎被报 Fatal（句柄失效、驱动被拦）时
// 这里仍返回 true（进程确实在跑，界面也不该显示成停止）。
// 需要“现在还能不能接住流量”的地方用 RunningAndHealthy。
func (a *App) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// RunningAndHealthy 引擎在跑、且拦截没被报错（“现在还能接住流量”）。
//
// 专用场景：hosts 那条守护 —— 拦截已死时它不能继续把内网域名指回内网 IP，
// 那几个名字会变成“没人兑付的地址”（应用一直等到超时）。
func (a *App) RunningAndHealthy() bool {
	if !a.Running() {
		return false
	}
	if a.Engine == nil {
		return true
	}
	return a.Engine.Fatal() == nil
}

// Start 按顺序拉起：写 hosts → 起 gost → 等端口就绪 → 开拦截。
func (a *App) Start() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	return a.startLocked()
}

func (a *App) startLocked() error {
	// 先抢引擎锁：服务版/另一个实例正在跑时，不要再装第二套过滤器去抢同一批包。
	// 抢不到就把话说清楚并回 ErrEngineBusy —— 界面版据此降级为只读，不是报错退出。
	lock, degraded, err := acquireEngineLock()
	if err != nil {
		// 引擎被别的进程（服务版/另一实例）拿着**不是故障**：界面版据此降级为只读，
		// 服务侧会先请对方退出再重试。所以用 WARN 而不是 ERROR，也不写 LastError ——
		// 否则界面上会冒出一个红色的 Error 状态，而其实一切正常（实测日志里就是这条先出现）。
		a.Bus.Warn("启动被拒：%v", err)
		if !errors.Is(err, ErrEngineBusy) {
			a.setLastError(err.Error())
		}
		return err
	}
	if degraded != "" {
		a.Bus.Warn("引擎互斥不可用（%s）—— 多个实例可能同时接管流量，请勿同时运行界面版与服务版", degraded)
	}
	a.mu.Lock()
	a.lock = lock
	a.mu.Unlock()

	if err := a.startLockedInner(); err != nil {
		// 启动没成功就把锁放开 —— 否则会变成"占着锁却没有引擎"，
		// 服务版也跟着起不来，等于两边都用不了。
		//
		// 同时把 hosts 收回来：启动失败（比如拦截打不开）时，已经写下去的
		// 内网域名映射没人兑付，留着只会让那几个名字一直超时。
		a.cleanupHosts()
		a.mu.Lock()
		a.lock = nil
		a.mu.Unlock()
		lock.release()
		return err
	}
	return nil
}

// startLockedInner 真正装配并启动引擎（调用方必须已持有引擎锁）。
func (a *App) startLockedInner() error {
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
	// “详细日志”是配置里的一项，启动时按它给总线定档（界面上的开关可直接改，见 SetLogVerbose）
	a.Bus.SetVerbose(a.Cfg.LogVerbose())
	// 旧版加过密的配置 + 保险箱丢了 → 这条链必然认证失败，先把话说清楚
	if legacy := a.Cfg.LegacySecretWarning(); len(legacy) > 0 {
		a.Bus.Error("⚠ 这些链还引用着旧版加密口令，但解不开（secrets.dat 丢了或换了机器）：%v", legacy)
		a.Bus.Error("   新版不再加密口令 —— 请把口令直接填回链路的 forward（形如 socks5+tls://用户名:口令@主机:端口）")
		a.notify("有链路的旧版口令解不开", "请把口令重新填进链路的上游地址（新版用明文）", NotifyError)
	}
	if err := a.Rules.Load(toRules(a.Cfg.RoutesSnapshot())); err != nil {
		a.Bus.Error("规则载入失败: %v", err)
		a.setLastError("规则载入失败：" + err.Error())
		a.notify("启动失败", err.Error(), NotifyError)
		return err
	}

	// 1) hosts（可选）
	if hosts := a.Cfg.HostsCopy(); hosts.Manage {
		if res, err := hostsmgr.Apply(hosts.Entries); err != nil {
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
	a.startedAt = time.Now()
	a.mu.Unlock()
	// 记下“启动基线”并开始盯 config.yaml：之后改规则/链不用重启，
	// 外部（脚本、手工、nethub.exe -apply）改了也自动吃进去。
	a.snapshotStartup()
	a.startConfigWatch()

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
	a.stopConfigWatch() // 先停轮询：别在收尾时又去应用配置
	a.mu.Lock()
	was := a.running
	a.running = false
	stop := a.hostsStop
	a.hostsStop = nil
	lock := a.lock
	a.lock = nil
	a.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if !was {
		// 没在跑也要把锁放掉（防御性：抢到锁之后到 running=true 之间失败时），
		// 并且把可能已经写下去的 hosts 段收回来 —— 启动失败就留在系统里的话，
		// 那几个内网域名会一直指着没人兑付的地址（一直等到超时）。
		a.cleanupHosts()
		lock.release()
		return
	}
	a.Bus.Info("正在停止…")
	a.Engine.Stop()
	// 引擎真的停完了才收尾：hosts 段与运行态文件都是“兑付不了的空头支票”。
	a.cleanupAfterStop()
	// 收尾完了才放锁：否则另一个进程可能在我们过滤器还在时就看到"空闲"
	lock.release()
	a.Bus.Info("✓ 已停止（痕迹已收尾）")
	a.notify("NetHub 已停止", "拦截与隧道均已关闭", NotifyWarn)
}

// cleanupAfterStop 引擎停之后的收尾：把我们在系统里留下的东西撒干净。
//
// 为什么要做：引擎一停，hosts 段里那些名字就没人兑付了 —— 它们还指着内网 IP，
// 而隧道已经不在，应用会一直等到超时（现场表现就是“服务一停，这几个系统打不开”）。
// 运行态文件同理：留着一份写着“运行中”的自报，下一个人（或下一个 agent）就会误判。
//
// 撒掉的东西下次启动会原样写回来（hosts.Apply 幂等），所以是“**停就撒、启再写**”。
func (a *App) cleanupAfterStop() {
	a.cleanupHosts()
	a.clearRuntime()
}

// cleanupHosts 撒掉我们维护的 hosts 段（只在 hosts.manage 开着时）。
func (a *App) cleanupHosts() {
	if !a.Cfg.HostsCopy().Manage {
		return
	}
	block, exists, _, err := hostsmgr.Read()
	if err != nil {
		a.Bus.Warn("hosts.cleanup: removed=0 err=%v", err)
		return
	}
	if !exists || len(block) == 0 {
		return // 没有我们的段（或空段）→ 本来就没痕迹
	}
	if err := hostsmgr.Remove(); err != nil {
		a.Bus.Warn("hosts.cleanup: removed=0 entries=%d err=%v", len(block), err)
		return
	}
	// Remove 自己会刷 DNS 缓存；不刷的话旧解析还会在缓存里生效。
	a.Bus.Info("hosts.cleanup: removed=%d flush=ok", len(block))
}

// clearRuntime 删掉运行态文件（runtime.json）：没有实例在跑，就不该留自报。
func (a *App) clearRuntime() {
	dir := exeDir()
	if dir == "" {
		return
	}
	err := os.Remove(filepath.Join(dir, RuntimeFile))
	if err == nil {
		a.Bus.Info("runtime.clear: file=%s", RuntimeFile)
	}
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

// ownsEngine 本进程是不是真拿着引擎（只读降级态＝没拿，不写运行态）。
func (a *App) ownsEngine() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lock != nil
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
			LocalNets: r.LocalNets, Apps: r.Apps, AllowQUIC: r.AllowQUIC, Chain: r.Chain, Action: act})
	}
	return out
}

// BuildRules 供命令行（-check）复用“配置 → 规则集”这条唯一路径。
//
// 为什么单独导出：校验必须走**和启动时完全一样**的转换，否则会出现
// “-check 说没问题、启动却失败”这种最难查的情况。
func BuildRules(cfg *config.Config) (*rules.Set, error) {
	rs := rules.New()
	if err := rs.Load(toRules(cfg.RoutesSnapshot())); err != nil {
		return nil, err
	}
	return rs, nil
}
