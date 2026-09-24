package app

// 配置热生效（“改完不用重启”）：
//
//   - 界面里保存 → App.SaveConfig → ApplyFromMemory：内存里的配置编译成新规则集，
//     交给引擎热替换（见 engine.ReloadRules），不重启进程、不断已有连接。
//   - 外部改了 config.yaml（脚本、手工编辑、`nethub.exe -apply`）→ watchConfig 每 2 秒
//     看一次文件摘要，变了就校验并应用；校验不过**什么都不动**（继续用旧配置），
//     把原始错误写进日志。
//   - 每个真正拿着引擎的进程往 exe 同目录写 runtime.json（运行态自报），
//     供 `-status` 看“到底在不在跑、吃的是哪份配置”和 `-apply` 核验“到底生效没有”。
//
// 哪些改动热不了（必须重启，界面/日志都会明说）：中转端口、DNS 接管（假 IP）、
// 系统 hosts 条目。其余（规则、链、上游、巡检、拨号参数）都是热生效或本来就实时读。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nethub/internal/config"
	"nethub/internal/engine"
	"nethub/internal/rules"
)

const (
	// configPollEvery 外部改动了 config.yaml 多久能被发现（也是 -apply 的最坏生效延迟）。
	configPollEvery = 2 * time.Second
	// configRetryEvery / configRetryTries 读到“写了一半”的文件时重试的节奏与次数。
	//
	// 为什么要重试：外部编辑器（包括 agent 的工具）是**原地写**文件的，2 秒一次的轮询
	// 很容易正好读到半截 YAML —— 实测：先记一行 ERROR“改动没有生效”，两秒后又自己好了。
	// 这种噪声会让人以为配置坏了，白查一圈。连续几次都载入不进去，才真是配置有问题。
	configRetryEvery = 400 * time.Millisecond
	configRetryTries = 4
	// stateEvery 运行态自报的间隔（内容没变也写，供外部判断“进程还活着”）。
	stateEvery = 10 * time.Second
	// RuntimeFile 运行态文件名（放在 exe 同目录，和 config.yaml 一起）。
	RuntimeFile = "runtime.json"
)

// ApplyResult 一次“配置热生效”的结果（界面提示与 CLI 核验都用它）。
type ApplyResult struct {
	// Applied 规则集真的被换了（false 也可能是“没什么可换”或“引擎没在跑”，看 Note）。
	Applied bool `json:"applied"`
	// Rules 生效后的规则条数。
	Rules int `json:"rules"`
	// RestartNeeded 这次配置里有、但热重载管不了的项（给人看的中文短句）。
	RestartNeeded []string `json:"restartNeeded,omitempty"`
	// Note 补充说明（如“引擎没在跑，下次启动生效”）。
	Note string `json:"note,omitempty"`
}

// Hint 给人看的一句话：有“热不了的东西”或异常就说，一切正常返回空串。
func (r ApplyResult) Hint() string {
	if len(r.RestartNeeded) > 0 {
		return "需要重启才生效：" + strings.Join(r.RestartNeeded, "、")
	}
	return r.Note
}

// LastApply 最近一次保存/热生效的结果（界面据此提示“哪些改动要重启”）。
func (a *App) LastApply() ApplyResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastApply
}

// ApplyFromMemory 把内存里的配置编译成新规则集，让运行中的引擎立刻按它干活。
//
// 用在“界面保存”这条路径：配置已经改在内存里、也落了盘，这里只负责让引擎跟上。
// 校验不过直接返回错误，**不落盘、不动运行中的规则**（调用方原样报给用户）。
func (a *App) ApplyFromMemory() (ApplyResult, error) {
	ns, err := BuildRules(a.Cfg)
	if err != nil {
		return ApplyResult{}, err
	}
	// 界面/模拟用的那份规则视图也要跟上（规则页的“命中哪条”用它算）。
	if err := a.Rules.Load(toRules(a.Cfg.RoutesSnapshot())); err != nil {
		return ApplyResult{}, err
	}
	return a.applyRuleSet(ns), nil
}

// ApplyFromDisk 读磁盘上的配置并让运行实例切过去（校验 → 换内存 → 热重载）。
//
// 校验不过则**完全不改动**（内存与运行中的规则都保持原样），错误原样交给调用方。
func (a *App) ApplyFromDisk() (ApplyResult, error) {
	path := a.Cfg.Path()
	if path == "" {
		return ApplyResult{}, fmt.Errorf("配置路径未设置")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return ApplyResult{}, err
	}
	ns, err := BuildRules(cfg)
	if err != nil {
		return ApplyResult{}, err
	}
	a.Cfg.ReplaceFrom(cfg) // 内存也换成新的一份（链/上游是实时读内存的，热重载只管规则）
	// “详细日志”也得跟着走：它是配置里的一项，外部改文件（或 -apply）改到它时必须生效，
	// 否则改了开关却什么都没发生（只能重启才能看到区别）。
	a.Bus.SetVerbose(a.Cfg.LogVerbose())
	if err := a.Rules.Load(toRules(cfg.RoutesSnapshot())); err != nil {
		return ApplyResult{}, err
	}
	return a.applyRuleSet(ns), nil
}

// applyRuleSet 把编译好的规则集交给引擎，并记下“什么时候生效的”。
func (a *App) applyRuleSet(ns *rules.Set) ApplyResult {
	res := ApplyResult{Rules: len(ns.List()), RestartNeeded: a.RestartRequired()}
	if ns == nil {
		res.Note = "规则集为空"
		return res
	}
	if !a.Running() {
		// 引擎没在跑：磁盘上的配置已经是新的，下次启动自然生效。
		res.Note = "引擎未在运行，新配置在下次启动时生效"
		a.mu.Lock()
		a.lastApply = res
		a.mu.Unlock()
		return res
	}
	if err := a.Engine.ReloadRules(ns); err != nil {
		if errors.Is(err, engine.ErrNotRunning) {
			res.Note = "引擎未在运行，新配置在下次启动时生效"
			return res
		}
		a.Bus.Error("规则热生效失败: %v", err)
		res.Note = "规则热生效失败，仍在用旧规则：" + err.Error()
		return res
	}
	res.Applied = true
	a.mu.Lock()
	a.appliedAt = time.Now()
	a.appliedRules = res.Rules
	a.lastApply = res
	a.mu.Unlock()
	a.writeRuntime()
	return res
}

// RestartRequired 这次配置里“热重载管不了”的项（改了就得重启才生效）。
//
// 判据是“与**启动那一刻**的配置比”。不比较就没法说实话：中转端口是启动时绑定的、
// 假 IP 池是启动时建的、hosts 是启动时写的一次 —— 它们改了但没重启，界面必须说清楚，
// 否则用户以为“保存了就该生效”，然后拿着没生效的配置去排障。
func (a *App) RestartRequired() []string {
	a.mu.Lock()
	base, ok := a.startupSnap, a.hasStartupSnap
	a.mu.Unlock()
	if !ok {
		return nil
	}
	cur := a.Cfg.Snapshot()
	var out []string
	if cur.Relay != base.Relay {
		out = append(out, "本机中转端口（relay）")
	}
	if cur.Tuning.DNSTakeoverDisabled != base.Tuning.DNSTakeoverDisabled ||
		strings.TrimSpace(cur.Tuning.FakeIPRange) != strings.TrimSpace(base.Tuning.FakeIPRange) {
		out = append(out, "DNS 接管（假 IP 段）")
	}
	if !sameHostsBlock(cur, base) {
		out = append(out, "系统 hosts 条目")
	}
	return out
}

// sameHostsBlock 两份配置的 hosts 托管段是否一致（开关 + 条目）。
func sameHostsBlock(a, b config.ConfigSnapshot) bool {
	if a.Hosts.Manage != b.Hosts.Manage {
		return false
	}
	return strings.Join(a.Hosts.Entries, "\n") == strings.Join(b.Hosts.Entries, "\n")
}

// snapshotStartup 记下“引擎是按哪份配置启动的”（热重载的对比基线）。
func (a *App) snapshotStartup() {
	snap := a.Cfg.Snapshot()
	a.mu.Lock()
	a.startupSnap, a.hasStartupSnap = snap, true
	a.mu.Unlock()
}

// SaveConfig 校验 → 编译规则集 → 落盘 → 让运行中的引擎**立刻**生效。
//
// “保存即生效”是刻意的：现场最烦“改完还要记得点一下重启”。不重启进程、不断已有连接。
// 热重载管不了的改动由返回值的 RestartNeeded 说清楚（界面据此提示）。
func (a *App) SaveConfig() (ApplyResult, error) {
	if err := a.Cfg.Validate(); err != nil {
		return ApplyResult{}, err
	}
	// 先编译再落盘：编译不过就连文件都不动（避免落下一份启动不起来的配置）。
	if _, err := BuildRules(a.Cfg); err != nil {
		return ApplyResult{}, err
	}
	if err := a.Cfg.Save(); err != nil {
		return ApplyResult{}, err
	}
	res, err := a.ApplyFromMemory()
	if err != nil {
		return res, err
	}
	// 记下“这份文件已经吃进去了”，免得 watchConfig 把我们自己刚写的再处理一遍。
	a.rememberFile()
	return res, nil
}

// rememberFile 把当前配置文件的摘要记成“已生效”，让文件轮询跳过自己的写入。
func (a *App) rememberFile() {
	sum, err := hashFile(a.Cfg.Path())
	if err != nil {
		return
	}
	a.mu.Lock()
	a.appliedHash, a.badHash = sum, ""
	a.mu.Unlock()
}

// ── 文件轮询（外部改了 config.yaml 也能热生效）──

// startConfigWatch 起文件轮询（幂等；引擎起来时调一次）。
func (a *App) startConfigWatch() {
	a.mu.Lock()
	if a.watchStop != nil {
		a.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	a.watchStop = stop
	a.mu.Unlock()

	a.rememberFile()
	a.writeRuntime()
	go func() {
		tk := time.NewTicker(configPollEvery)
		defer tk.Stop()
		lastState := time.Now()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			a.pollConfigFile()
			if time.Since(lastState) >= stateEvery {
				lastState = time.Now()
				a.writeRuntime()
			}
		}
	}()
}

// stopConfigWatch 停掉文件轮询，并补一份“已停止”的运行态。
func (a *App) stopConfigWatch() {
	a.mu.Lock()
	stop := a.watchStop
	a.watchStop = nil
	a.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	a.writeRuntime()
}

// pollConfigFile 看配置文件是不是被外部改过；改过且校验通过就热生效。
func (a *App) pollConfigFile() {
	path := a.Cfg.Path()
	if path == "" {
		return
	}
	sum, err := hashFile(path)
	if err != nil || sum == "" {
		return
	}
	a.mu.Lock()
	seen, bad := a.appliedHash, a.badHash
	a.mu.Unlock()
	if sum == seen || sum == bad {
		return // 没变，或这个坏版本已经报过了（别每 2 秒刷屏）
	}

	res, err := a.applyFromDiskWithRetry()
	if err != nil {
		a.mu.Lock()
		a.badHash = sum
		a.mu.Unlock()
		// 原始且完整：一行上下文 + 错误原文逐行照抄（现场拿日志当第一手材料）。
		a.Bus.Error("config.reload: source=file 配置文件被改动，但这次改动没有生效（仍在用旧配置）")
		for _, line := range strings.Split(err.Error(), "\n") {
			a.Bus.Error("    %s", line)
		}
		a.notify("配置改动没有生效", err.Error(), NotifyError)
		return
	}
	a.mu.Lock()
	a.appliedHash, a.badHash = sum, ""
	a.mu.Unlock()
	a.Bus.Info("config.reload: source=file rules=%d applied=%v", res.Rules, res.Applied)
	if res.Note != "" {
		a.Bus.Warn("config.reload: %s", res.Note)
	}
	for _, f := range res.RestartNeeded {
		a.Bus.Warn("config.reload: %s 改了，需要重启才生效", f)
	}
	a.writeRuntime()
}

// applyFromDiskWithRetry 载入磁盘配置；載入失败时重试几次。
//
// 失败区分两种：① 文件正被外部程序写（读到半截）—— 重试就能成功；
// ② 配置真有问题 —— 重试几遍仍失败，调用方报 ERROR。
// 只有① 被重试掉，才不让现场看到一条虚警。
func (a *App) applyFromDiskWithRetry() (ApplyResult, error) {
	res, err := a.ApplyFromDisk()
	if err == nil {
		return res, nil
	}
	for i := 1; i < configRetryTries; i++ {
		time.Sleep(configRetryEvery)
		res, err = a.ApplyFromDisk()
		if err == nil {
			a.Bus.Info("config.reload: source=file 第 %d 次读到完整文件（前 %d 次读到的是写了一半的）", i+1, i)
			return res, nil
		}
	}
	return res, err
}

// ── 运行态自报（runtime.json）──

// RuntimeDoc 运行态快照。字段名给机器用（-status 与 -apply 读它），改名前先想清楚。
type RuntimeDoc struct {
	PID           int      `json:"pid"`
	Version       string   `json:"version"`
	Running       bool     `json:"running"`
	ConfigPath    string   `json:"configPath,omitempty"`
	ConfigHash    string   `json:"configHash,omitempty"` // 当前**生效**的 config.yaml 内容 sha256
	Rules         int      `json:"rules"`
	ChainCount    int      `json:"chains"`
	Relay         string   `json:"relay,omitempty"`
	AppliedAt     string   `json:"appliedAt,omitempty"`
	StartedAt     string   `json:"startedAt,omitempty"`
	LastError     string   `json:"lastError,omitempty"`
	RestartNeeded []string `json:"restartNeeded,omitempty"`
	UpdatedAt     string   `json:"updatedAt"`
}

// Runtime 当前运行态（也供界面显示“配置生效于 …”）。
func (a *App) Runtime() RuntimeDoc {
	running, errText := a.Status()
	a.mu.Lock()
	hash, appliedAt, startedAt := a.appliedHash, a.appliedAt, a.startedAt
	a.mu.Unlock()
	doc := RuntimeDoc{
		PID:        os.Getpid(),
		Version:    a.Version,
		Running:    running,
		Relay:      a.Engine.RelayAddr(),
		Rules:      a.Engine.RuleCount(),
		ChainCount: len(a.Cfg.ChainsSnapshot()),
		LastError:  errText,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	if p := a.Cfg.Path(); p != "" {
		doc.ConfigPath = p
		doc.ConfigHash = hash
	}
	if !appliedAt.IsZero() {
		doc.AppliedAt = appliedAt.Format(time.RFC3339)
	}
	if !startedAt.IsZero() {
		doc.StartedAt = startedAt.Format(time.RFC3339)
	}
	doc.RestartNeeded = a.RestartRequired()
	return doc
}

// writeRuntime 原子写运行态（先写 .tmp 再改名，读的人不会读到半截 JSON）。
//
// 只有真拿着引擎的进程写：界面版在“服务版在跑”的只读降级态下**不能**写，
// 否则会把服务版的运行态覆盖成假的。
func (a *App) writeRuntime() {
	if a.Version == "" && !a.Running() {
		return // 纯只读进程（-check / -status 那种）不写
	}
	if !a.ownsEngine() {
		return
	}
	dir := exeDir()
	if dir == "" {
		return
	}
	b, err := json.MarshalIndent(a.Runtime(), "", "  ")
	if err != nil {
		return
	}
	b = append(b, '\n')
	target := filepath.Join(dir, RuntimeFile)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, target)
}

// ReadRuntime 读运行态（-status / -apply 用）。
//
// 返回 (doc, ok)：ok=false 表示没有运行态文件（从没起来过 / 已被清理）。
// running 字段还会核对进程是否真的活着 —— 进程被强杀时文件会停在“运行中”。
func ReadRuntime() (RuntimeDoc, bool) {
	dir := exeDir()
	if dir == "" {
		return RuntimeDoc{}, false
	}
	b, err := os.ReadFile(filepath.Join(dir, RuntimeFile))
	if err != nil {
		return RuntimeDoc{}, false
	}
	var doc RuntimeDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return RuntimeDoc{}, false
	}
	if doc.Running && !processAlive(doc.PID) {
		// 文件停在“运行中”但进程没了（强杀/崩溃）：别让外部以为还在跑
		doc.Running = false
		if doc.LastError == "" {
			doc.LastError = "进程已退出（运行态文件是上一次留下的）"
		}
	}
	return doc, true
}

// FileHash 文件内容的 sha256（十六进制小写）；读不到返回空串。
func FileHash(path string) string {
	sum, err := hashFile(path)
	if err != nil {
		return ""
	}
	return sum
}

func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}
