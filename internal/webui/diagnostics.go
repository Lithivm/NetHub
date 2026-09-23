package webui

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"nethub/internal/gostbat"
	"nethub/internal/hostsmgr"
)

// ExportDiagnostics 打一个"一键诊断包"：脱敏配置 + 日志 + 环境与运行态报告。
//
// 给"同事机器出问题、把包发回来"用 —— 所以凭据一律遮蔽（auth=、user:pass 都抹掉），
// 出问题的机器不需要自己判断哪些字段敏感。
func (b *Backend) ExportDiagnostics() (string, error) {
	dir := filepath.Dir(b.a.Cfg.Path())
	if dir == "" || dir == "." {
		dir, _ = os.Getwd()
	}
	name := filepath.Join(dir, "诊断包-"+time.Now().Format("20060102-150405")+".zip")
	f, err := os.Create(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	// 1) 报告
	if err := addZip(zw, "报告.txt", []byte(b.diagReport())); err != nil {
		return "", err
	}
	// 2) 脱敏配置
	if raw, err := os.ReadFile(b.a.Cfg.Path()); err == nil {
		_ = addZip(zw, "config.脱敏.yaml", []byte(redactConfig(string(raw))))
	}
	// 3) 日志（连轮转出去的历史一起带，否则“出问题之前发生了什么”就断了）
	if lp := b.a.Bus.FilePath(); lp != "" {
		if raw, err := os.ReadFile(lp); err == nil {
			// 只带最后 2000 行，避免几个月的日志把包撑爆
			_ = addZip(zw, "nethub.log", []byte(tailLines(string(raw), 2000)))
		}
		for i := 1; i <= 3; i++ {
			name := fmt.Sprintf("%s.%d", lp, i)
			raw, err := os.ReadFile(name)
			if err != nil {
				break
			}
			_ = addZip(zw, fmt.Sprintf("nethub.log.%d", i), []byte(tailLines(string(raw), 2000)))
		}
	}
	// 4) 说明
	_ = addZip(zw, "说明.txt", []byte(`诊断包里有什么：
  报告.txt          —— 版本、系统、规则、链路上游、健康与巡检结果、hosts 与 Clash 共存状态
  config.脱敏.yaml  —— 你的配置，上游凭据已抹掉（auth= 与 user:pass 都替换成 ***）
  nethub.log        —— 最近的日志（最后 2000 行）
  nethub.log.1/.2   —— 轮转出去的历史（日志单文件 8 MB 上限，最多 3 个文件）

可以直接发给维护者。里面不含任何上游口令。
`))
	return name, nil
}

func addZip(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// diagReport 组一份人话报告。
func (b *Backend) diagReport() string {
	var s strings.Builder
	total, active := b.a.Engine.Stats()
	fmt.Fprintf(&s, "NetHub 诊断报告  生成于 %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&s, "系统：%s/%s   Go %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Fprintf(&s, "配置：%s\n", b.a.Cfg.Path())
	fmt.Fprintf(&s, "日志：%s\n", b.a.Bus.FilePath())
	fmt.Fprintf(&s, "服务：%v   累计连接 %d   活跃 %d\n\n", b.a.Running(), total, active)

	s.WriteString("── 配置体检 ──\n")
	for _, line := range b.a.Cfg.Precheck() {
		s.WriteString("  " + line + "\n")
	}

	s.WriteString("\n── 规则（自上而下，命中即停）──\n")
	for i, r := range b.a.Cfg.RoutesSnapshot() {
		ports := ""
		if len(r.Ports) > 0 {
			ports = "  端口 " + strings.Join(r.Ports, ",")
		}
		fmt.Fprintf(&s, "  %d) %s%s  →  %s\n", i+1, r.Label(), ports, r.ActionText())
	}

	s.WriteString("\n── 链路上游健康 ──\n")
	for _, ch := range b.a.Engine.ChainHealth() {
		fmt.Fprintf(&s, "  %s（策略 %s，探测 %s）\n", ch.Name, ch.Strategy, ch.Probe)
		for _, u := range ch.Upstreams {
			st := "待探测"
			switch {
			case !u.Known:
			case u.OK:
				st = "可用 " + u.Latency
			default:
				st = "不可用：" + u.Error
			}
			fmt.Fprintf(&s, "      %s  %s（%s）\n", u.URL, st, u.Checked)
		}
	}

	s.WriteString("\n── 业务目标巡检（最近用过的）──\n")
	for _, th := range b.a.Engine.TargetHealth() {
		st := "可达 " + th.Latency
		if !th.OK {
			st = "不可达：" + th.Error
		}
		fmt.Fprintf(&s, "  %s  经 %s  %s（%s）\n", th.Target, th.Chain, st, th.Checked)
	}

	s.WriteString("\n── 最近连接（最多 30 条）──\n")
	for _, c := range b.a.Engine.Conns(30, false) {
		fmt.Fprintf(&s, "  %-22s %-4s %-8s %-8s ↑%d ↓%d  %s %s\n",
			c.Target, c.Action, c.Chain, c.Dur, c.Up, c.Down, c.State, c.Error)
	}

	s.WriteString("\n── 与 Clash 共存 / hosts ──\n")
	if cc := b.clashCoverage(); true {
		fmt.Fprintf(&s, "  系统代理：%s   绕过覆盖 OK=%v\n", readProxyMode().Mode, cc.OK)
		if len(cc.Missed) > 0 {
			fmt.Fprintf(&s, "  ⚠ 未覆盖的内网目标：%s\n", strings.Join(cc.Missed, ", "))
		}
	}
	hostsPath := hostsmgr.Path()
	_, hostsInFile, _, _ := hostsmgr.Read()
	fmt.Fprintf(&s, "  hosts：%s（已托管标记：%v）\n", hostsPath, hostsInFile)
	fmt.Fprintf(&s, "  hosts 托管开关：%v\n", b.a.Cfg.HostsCopy().Manage)
	return s.String()
}

// redactConfig 把配置里的凭据抹掉：auth=xxx 与 scheme://user:pass@host 都处理。
func redactConfig(s string) string {
	out := make([]string, 0, 64)
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "forward:") || strings.HasPrefix(t, "- socks") || strings.HasPrefix(t, "- http") {
			line = gostbat.Redact(line)
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// tailLines 取文本的最后 n 行。
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n") + "\n"
	}
	return strings.Join(lines[len(lines)-n:], "\n") + "\n"
}
