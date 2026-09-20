package webui

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nethub/internal/app"
	"nethub/internal/config"
	"nethub/internal/logbus"
	"nethub/internal/rules"
)

// 批量模拟：三类结论要分得清（走隧道 / 直连 / 未命中），网段要抽样，
// 端口没填时要说清楚“这只看了目标”。
func TestSimulateTargets(t *testing.T) {
	b, cfg := newRoutesBackend(t)
	cfg.Routes = []config.Route{
		{Name: "业务A", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a", Ports: []string{"443", "80"}},
		{Name: "本机直连", Targets: []string{"172.22.224.0/20"}, Chain: config.DirectChain},
		{Name: "禁访问", Targets: []string{"10.9.9.0/24"}, Chain: config.BlockChain},
	}
	rs := rules.New()
	if err := rs.Load([]rules.Route{
		{Name: "业务A", Targets: []string{"10.0.0.0/24"}, Chain: "proxy-a", Ports: []string{"443", "80"}},
		{Name: "本机直连", Targets: []string{"172.22.224.0/20"}, Chain: config.DirectChain, Action: rules.ActionDirect},
		{Name: "禁访问", Targets: []string{"10.9.9.0/24"}, Chain: config.BlockChain, Action: rules.ActionBlock},
	}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs

	v := b.SimulateTargets(`
		10.0.0.5:443          # 走隧道
		172.22.224.10         # 直连
		10.9.9.9:22           # 阻断
		192.168.1.1           # 没规则命中
		10.0.0.0/24:443       # 网段 + 端口
		乱写的东西
	`)
	byInput := map[string]SimRow{}
	for _, r := range v.Rows {
		byInput[r.Input] = r
	}
	check := func(in, wantAction, wantChain string) {
		t.Helper()
		r, ok := byInput[in]
		if !ok {
			t.Fatalf("没模拟 %s：%+v", in, v.Rows)
		}
		if !r.OK || !strings.Contains(r.Action, wantAction) || r.Chain != wantChain {
			t.Errorf("%s 期望 %s/%s，得到 ok=%v action=%q chain=%q err=%q", in, wantAction, wantChain, r.OK, r.Action, r.Chain, r.Err)
		}
	}
	check("10.0.0.5:443", "链 proxy-a", "proxy-a")
	check("172.22.224.10", "直连", config.DirectChain)
	check("10.9.9.9:22", "阻断", config.BlockChain)
	check("192.168.1.1", "未命中", "")
	if r := byInput["10.0.0.0/24:443"]; !r.OK || !strings.Contains(r.Action, "proxy-a") || !strings.Contains(r.Note, "抽样") {
		t.Errorf("带端口的网段应抽样后给结论：%+v", r)
	}
	if r := byInput["乱写的东西"]; r.OK || r.Err == "" {
		t.Errorf("非法输入应报错：%+v", r)
	}

	// 没填端口 + 规则限定端口 → 必须提示“只看目标”
	if r := byInput["172.22.224.10"]; r.OK && r.Note != "" && strings.Contains(r.Note, "端口") {
		// 直连规则没端口条件，这里不该有提示
		t.Errorf("无端口条件的规则不该给端口提示：%+v", r)
	}
	rs2 := rules.New()
	if err := rs2.Load([]rules.Route{{Name: "只走443", Targets: []string{"10.1.0.0/16"}, Chain: "proxy-a", Ports: []string{"443"}}}); err != nil {
		t.Fatal(err)
	}
	b.a.Rules = rs2
	cfg.Routes = []config.Route{{Name: "只走443", Targets: []string{"10.1.0.0/16"}, Chain: "proxy-a", Ports: []string{"443"}}}
	v2 := b.SimulateTargets("10.1.2.3")
	if len(v2.Rows) != 1 || !strings.Contains(v2.Rows[0].Note, "只看目标") {
		t.Errorf("未填端口应提示端口条件没算进来：%+v", v2.Rows)
	}

	// 汇总要能一眼看懂
	if !strings.Contains(v.Summary, "共 6 项") {
		t.Errorf("汇总缺项数：%q", v.Summary)
	}
}

// 装机包：内容必须齐（程序/驱动/配置/说明/校验），且**绝不能**带日志或备份。
func TestBuildPackage(t *testing.T) {
	dir := t.TempDir()
	// 造一个“程序目录”：exe + 驱动 + 图标
	for _, n := range []string{"nethub.exe", "WinDivert.dll", "WinDivert64.sys", "nethub.ico"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x-"+n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 配置 + 日志 + 备份（后两个不该被打进包）
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("relay: 127.0.0.1:0\n"+
		"chains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n"+
		"routes:\n  - name: 业务A\n    targets: [10.0.0.0/24]\n    chain: proxy-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "nethub.log"), []byte("secret log"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "backups"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "backups", "20260101.yaml"), []byte("old"), 0o644)

	b := &Backend{a: app.New(cfg, logbus.New(50)), exeDir: dir}
	var buf bytes.Buffer
	res, err := b.buildPackage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(rc)
		rc.Close()
		names[f.Name] = raw
	}
	for _, want := range []string{"nethub.exe", "WinDivert.dll", "WinDivert64.sys", "nethub.ico",
		"config.yaml", "启动NetHub.cmd", "装机说明.txt", "SHA256SUMS.txt"} {
		if _, ok := names[want]; !ok {
			t.Errorf("装机包缺 %s（现有：%v）", want, keys(names))
		}
	}
	for _, bad := range []string{"nethub.log", "backups/20260101.yaml", "诊断包.zip"} {
		if _, ok := names[bad]; ok {
			t.Errorf("装机包不该带运行期数据：%s", bad)
		}
	}
	// 说明书要是 UTF-8 BOM 开头（记事本不乱码），启动脚本要纯 ASCII（.cmd 不要中文）
	if !bytes.HasPrefix(names["装机说明.txt"], []byte{0xEF, 0xBB, 0xBF}) {
		t.Error("装机说明.txt 应以 UTF-8 BOM 开头")
	}
	for i, c := range names["启动NetHub.cmd"] {
		if c > 127 {
			t.Errorf("启动NetHub.cmd 第 %d 字节不是 ASCII（.cmd 里中文会变乱码）", i)
			break
		}
	}
	// 校验值要对得上文件内容
	sums := string(names["SHA256SUMS.txt"])
	if !strings.Contains(sums, sha256Hex(names["config.yaml"])) {
		t.Error("SHA256SUMS 里的 config.yaml 摘要对不上")
	}
	if len(res.Files) < 8 || res.Warning != "" {
		t.Errorf("结果不对：%d 个文件，警告=%q", len(res.Files), res.Warning)
	}
}

// 缺文件时要给出警告（别让客户拿到一个起不来的包）。
func TestBuildPackageWarnsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("relay: 127.0.0.1:0\nchains:\n  - name: proxy-a\n    forward: socks5://127.0.0.1:1080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b := &Backend{a: app.New(cfg, logbus.New(50)), exeDir: dir}
	var buf bytes.Buffer
	res, err := b.buildPackage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Warning == "" || !strings.Contains(res.Warning, "nethub.exe") {
		t.Errorf("缺文件应警告，实际：%q", res.Warning)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
