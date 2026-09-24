// 命令行控制面：给脚本与 agent 用的开关。
//
// 为什么要它们（而不是让 agent 直接改 YAML 就完事）：
//
//	-check  改完配置得能**验**：以前 YAML 写坏（比如重复键）程序会静默起不来，
//	        连日志都没有 —— 这是实测踩过的坑。
//	-status 得能**看**：agent 需要机器可读的现状（版本/服务状态/链路/规则/开关/
//	        **运行实例到底在不在跑、吃的是哪份配置**），而不是去翻日志猜。
//	-apply  改完得能**切**：校验 → 落盘 → 运行中的实例自己热生效（不用重启进程，
//	        也不用去点界面）—— 改配置这件事从“重启一次”变成“等一下”，
//	        并且 -apply 会等到实例真的吃进去才返回（否则报清楚为什么没生效）。
//
// -check / -status 只读、不写文件、不启服务、不需管理员；-apply 只写配置文件本身。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/rules"
	"nethub/internal/upstream"
	"nethub/internal/webui"
	"nethub/internal/winsvc"

	"golang.org/x/sys/windows"
)

// cmdCheck 校验配置：能载入 + 规则能编译 + 关键项合法。零副作用。
//
// 退出码：0 = 通过；1 = 有问题（逐条打印，供机器解析）。
func cmdCheck(cfgPath string) int {
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}
	fmt.Printf("config: %s\n", cfgPath)

	problems := []string{}
	if _, err := os.Stat(cfgPath); err != nil {
		fmt.Printf("check: FAIL\n")
		fmt.Printf("  - 配置文件不存在（第一次运行会自动生成默认配置）：%v\n", err)
		return 1
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		// YAML 语法错/重复键/类型不对都走这里 —— 以前这种情况启动时是静默的，
		// 所以这里必须把原始错误整段打出来。
		fmt.Printf("check: FAIL\n")
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Printf("  - %s\n", line)
		}
		return 1
	}
	fmt.Printf("loaded: chains=%d routes=%d hosts=%d\n", len(cfg.Chains), len(cfg.Routes), len(cfg.Hosts.Entries))

	// 规则能不能编译（这条路径与启动时完全一致）
	rs, rerr := app.BuildRules(cfg)
	if rerr != nil {
		problems = append(problems, rerr.Error())
	} else {
		list := rs.List()
		fmt.Printf("rules: ok total=%d enabled=%d wildcard=%d\n",
			len(cfg.Routes), len(list), countWildcard(list))
	}

	// 链与上游
	for i, ch := range cfg.Chains {
		name := strings.TrimSpace(ch.Name)
		if name == "" {
			problems = append(problems, fmt.Sprintf("第 %d 条链没有名字", i+1))
		}
		if len(ch.Upstreams()) == 0 {
			problems = append(problems, fmt.Sprintf("链 %s 没有上游", name))
		}
		for _, up := range ch.Upstreams() {
			if _, perr := upstream.Parse(up); perr != nil {
				problems = append(problems, fmt.Sprintf("链 %s 的上游解析失败: %v", name, perr))
			}
		}
	}
	fmt.Printf("chains: %d\n", len(cfg.Chains))

	// 规则引用的链必须存在
	names := map[string]bool{}
	for _, ch := range cfg.Chains {
		names[strings.TrimSpace(ch.Name)] = true
	}
	for i, r := range cfg.Routes {
		c := strings.TrimSpace(r.Chain)
		if c == "" {
			problems = append(problems, fmt.Sprintf("第 %d 条规则没有 chain", i+1))
			continue
		}
		if c == config.DirectChain || c == config.BlockChain {
			continue
		}
		if !names[c] {
			problems = append(problems, fmt.Sprintf("第 %d 条规则引用了不存在的链 %q", i+1, c))
		}
	}

	// hosts 条目格式
	for i, e := range cfg.Hosts.Entries {
		s := strings.TrimSpace(e)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		f := strings.Fields(s)
		if len(f) < 2 || net.ParseIP(f[0]).To4() == nil {
			problems = append(problems, fmt.Sprintf("hosts 第 %d 行不是「IP 域名」：%q", i+1, s))
		}
	}

	if len(problems) > 0 {
		fmt.Printf("check: FAIL\n")
		for _, p := range problems {
			fmt.Printf("  - %s\n", p)
		}
		return 1
	}
	fmt.Printf("check: OK\n")
	return 0
}

// statusDoc -status 输出的 JSON（字段名给机器用，稳定）。
type statusDoc struct {
	Version     string         `json:"version"`
	ConfigPath  string         `json:"configPath"`
	ConfigOK    bool           `json:"configOk"`
	ConfigError string         `json:"configError,omitempty"`
	Service     serviceDoc     `json:"service"`
	Chains      []chainDoc     `json:"chains"`
	Rules       []ruleDoc      `json:"rules"`
	Hosts       hostsDoc       `json:"hosts"`
	Tuning      map[string]any `json:"tuning"`
	Wildcards   []string       `json:"wildcardTargets"`
	// Runtime 运行实例的自报（runtime.json）：不在跑就没有这个字段。
	Runtime *runtimeDoc `json:"runtime,omitempty"`
	Notes   []string    `json:"notes,omitempty"`
}

// runtimeDoc 运行实例自报 + 读文件时现算的判断。
type runtimeDoc struct {
	app.RuntimeDoc
	// ConfigMatchesFile 运行实例吃进去的配置就是磁盘上这一份（false = 改了但没生效）。
	ConfigMatchesFile bool `json:"configMatchesFile"`
}

type serviceDoc struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	State     string `json:"state,omitempty"`
}

type chainDoc struct {
	Name      string   `json:"name"`
	Upstreams []string `json:"upstreams"` // 已脱敏（userinfo/auth 去掉）
	HasCred   bool     `json:"hasCred"`
}

type ruleDoc struct {
	Index     int      `json:"index"`
	Name      string   `json:"name,omitempty"`
	Enabled   bool     `json:"enabled"`
	Action    string   `json:"action"` // chain / direct / block
	Chain     string   `json:"chain,omitempty"`
	Targets   []string `json:"targets,omitempty"`
	Ports     []string `json:"ports,omitempty"`
	Apps      []string `json:"apps,omitempty"`
	LocalNets []string `json:"localNets,omitempty"`
}

type hostsDoc struct {
	Manage  bool     `json:"manage"`
	Entries []string `json:"entries"`
}

// cmdStatus 打印机器可读的现状。退出码：0 = 配置能载入（服务在不在跑都算 OK）；
// 1 = 配置有问题（此时 ConfigError 有值）。
func cmdStatus(cfgPath string) int {
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}
	doc := statusDoc{Version: webui.Version, ConfigPath: cfgPath}
	doc.Service = serviceState()
	doc.Tuning = map[string]any{}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		doc.ConfigError = err.Error()
		doc.Notes = append(doc.Notes, "配置无法载入：先用 nethub.exe -check 看逐条错误")
		return emitStatus(doc, 1)
	}
	doc.ConfigOK = true

	for _, ch := range cfg.Chains {
		d := chainDoc{Name: ch.Name, HasCred: false}
		for _, raw := range ch.Upstreams() {
			short := "（无法解析的上游）"
			if u, perr := upstream.Parse(raw); perr == nil {
				short = u.String()
				if u.Creds.User != "" || u.Creds.Pass != "" {
					d.HasCred = true
				}
			}
			d.Upstreams = append(d.Upstreams, short)
		}
		doc.Chains = append(doc.Chains, d)
	}
	for i, r := range cfg.Routes {
		d := ruleDoc{Index: i, Name: r.Name, Enabled: r.IsEnabled(), Targets: r.Targets,
			Ports: r.Ports, Apps: r.Apps, LocalNets: r.LocalNets}
		switch {
		case r.IsDirect():
			d.Action = "direct"
		case r.IsBlock():
			d.Action = "block"
		default:
			d.Action = "chain"
			d.Chain = r.Chain
		}
		for _, t := range r.Targets {
			if strings.Contains(t, "*") && !strings.Contains(t, "/") {
				doc.Wildcards = append(doc.Wildcards, t)
			}
		}
		doc.Rules = append(doc.Rules, d)
	}
	doc.Hosts = hostsDoc{Manage: cfg.Hosts.Manage, Entries: cfg.Hosts.Entries}

	// 运行实例自报（谁在跑、吃的是哪份配置）：文件不在（或进程已退出）就说明没实例在跑。
	if rd, ok := app.ReadRuntime(); ok {
		rdoc := runtimeDoc{RuntimeDoc: rd}
		fileSum := app.FileHash(cfgPath)
		rdoc.ConfigMatchesFile = rd.Running && fileSum != "" && rd.ConfigHash == fileSum
		doc.Runtime = &rdoc
	}

	doc.Tuning = map[string]any{
		"domainResolve":    cfg.DomainResolveMode(),
		"dialTimeout":      cfg.DialTimeoutDur().String(),
		"dialBudget":       cfg.DialBudgetDur().String(),
		"raceAfter":        cfg.RaceAfterDur().String(),
		"countDirect":      cfg.CountDirectEnabled(),
		"tlsSniff":         cfg.TLSSniffEnabled(),
		"dnsTakeover":      cfg.DNSTakeoverEnabled(),
		"dnsTakeoverRange": cfg.FakeIPRangeOr(),
		"patrolInterval":   cfg.PatrolInterval().String(),
	}
	doc.Notes = append(doc.Notes,
		"-status 只读，不改任何状态；配置改动用 -check 验、用 -apply 落到运行实例（热生效），需要重启的项见 runtime.restartNeeded",
		"人类可读的实时状态在界面里（托盘 → 显示主界面）；日志在 exe 同目录 logs\\nethub.log")
	return emitStatus(doc, 0)
}

// cmdApply 把一份配置应用到正在运行的实例：校验 → 落盘 → 等它热生效。
//
// 退出码：0 = 已生效（或当前没有实例在跑，下次启动生效）；1 = 校验/写入失败；
// 3 = 已写入但运行实例始终没吃进去（详见 logs\\nethub.log）。
//
// 为什么不是“直接 cp 覆盖”：覆盖完你不知道实例到底吃进去没有（热生效是轮询发现的）。
// 这里写完会盯着运行实例自报的 configHash 等它变过来 —— 脚本与 agent 需要这个确定结论。
func cmdApply(srcPath, cfgPath string, force bool) int {
	if srcPath == "" || cfgPath == "" {
		fmt.Println("apply: FAIL 用法：nethub.exe -apply <新配置.yaml> [-config <目标配置>] [-apply-force]")
		return 1
	}
	cfg, err := config.Load(srcPath)
	if err != nil {
		fmt.Println("apply: FAIL 源配置无法载入")
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Printf("  - %s\n", line)
		}
		return 1
	}
	if _, err := app.BuildRules(cfg); err != nil {
		fmt.Println("apply: FAIL 规则编译失败（一个字节都没写）")
		fmt.Printf("  - %s\n", err)
		return 1
	}

	// 防并发覆盖：如果目标配置比源文件还新，说明有人在我们准备这份文件之后又改了它。
	// 这时直接覆盖会把别人的改动吞掉 —— 除非显式 -apply-force。
	if !force {
		sSrc, e1 := os.Stat(srcPath)
		sDst, e2 := os.Stat(cfgPath)
		if e1 == nil && e2 == nil && sDst.ModTime().After(sSrc.ModTime()) {
			fmt.Println("apply: FAIL 目标配置比源文件新（可能有人刚改过它），已拒绝覆盖")
			fmt.Printf("  - 目标: %s  %s\n", cfgPath, sDst.ModTime().Format("2006-01-02 15:04:05"))
			fmt.Printf("  - 源:   %s  %s\n", srcPath, sSrc.ModTime().Format("2006-01-02 15:04:05"))
			fmt.Println("  - 确认要以源文件为准就用 -apply-force")
			return 1
		}
	}

	if err := cfg.SaveFile(cfgPath); err != nil {
		fmt.Println("apply: FAIL 写入失败")
		fmt.Printf("  - %s\n", err)
		return 1
	}
	sum := app.FileHash(cfgPath)
	fmt.Printf("apply: 已写入 %s（%d 条链 %d 条规则，旧配置已备份到 backups\\）\n",
		cfgPath, len(cfg.Chains), len(cfg.Routes))

	// 等运行实例吃进去（最坏 6 秒：轮询 2 秒 + 应用 + 自报）
	deadline := time.Now().Add(6 * time.Second)
	for {
		rd, ok := app.ReadRuntime()
		if !ok || !rd.Running {
			fmt.Println("apply: 当前没有运行中的实例 —— 新配置在下次启动时生效")
			return 0
		}
		if sum != "" && rd.ConfigHash == sum {
			fmt.Printf("apply: OK 运行实例已生效（pid=%d 版本=%s 规则=%d 链=%d relay=%s）\n",
				rd.PID, rd.Version, rd.Rules, rd.ChainCount, rd.Relay)
			if len(rd.RestartNeeded) > 0 {
				fmt.Printf("apply: 注意 这些改动要重启才生效：%s\n", strings.Join(rd.RestartNeeded, "、"))
			}
			return 0
		}
		if time.Now().After(deadline) {
			fmt.Println("apply: FAIL 已写入，但运行实例没有应用（仍在用旧配置）")
			fmt.Printf("  - 实例 pid=%d 生效于 %s 摘要=%s\n", rd.PID, rd.AppliedAt, shortHash(rd.ConfigHash))
			if rd.LastError != "" {
				fmt.Printf("  - 实例当前状态：%s\n", rd.LastError)
			}
			fmt.Println("  - 原因见 exe 同目录 logs\\nethub.log（校验不通过 / 规则热生效失败）")
			return 3
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// shortHash 摘要前 12 位（给人看，不用看全）。
func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func emitStatus(doc statusDoc, code int) int {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Printf("{\"error\":%q}\n", err.Error())
		return 1
	}
	fmt.Println(string(b))
	return code
}

// serviceState 读 Windows 服务的安装/运行状态（不启动任何东西）。
func serviceState() serviceDoc {
	d := serviceDoc{Name: winsvc.Name}
	d.Installed = winsvc.Installed()
	d.State = winsvc.State()
	d.Running = d.State == "running"
	return d
}

func countWildcard(list []rules.Route) int {
	n := 0
	for _, r := range list {
		if len(r.WildcardTargets()) > 0 {
			n++
		}
	}
	return n
}

// configPathFor 供 main 里两个开关共用：优先 -config，其次 exe 同目录。
func configPathFor(p string) string {
	if p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(exePath()), "config.yaml")
}

// msgBox 弹一个阻塞式的 Windows 消息框（启动失败时要让用户**看见**，
// 而不是只写进日志 —— 双击启动的人不会去看日志）。
//
// 用 MessageBoxW：不需要窗口句柄，MB_OK|MB_ICONERROR = 0x10。
func msgBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	procMessageBox.Call(0,
		uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), uintptr(0x10))
}

var procMessageBox = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")
