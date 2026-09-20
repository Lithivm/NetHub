package webui

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// 「客户装机包」：上门装机时直接把这个 zip 拷过去，解压、双击、完事。
//
// 包里**只放运行必需的东西 + 一份说明**：程序、两个 WinDivert 文件、图标、
// 当前配置（含上游凭据）、启动脚本、校验值。
// 刻意**不带**任何运行期数据（日志、配置备份、连接历史）—— 分发包不带数据是硬规矩：
// 既避免把上一台机器的信息带到客户这儿，也避免客户看到别人的东西。
//
// 文件名与说明里都不出现客户环境标识（链名、网段等由 config.yaml 自己带）。

// PackageResult 装机包导出结果。
type PackageResult struct {
	Path    string   `json:"path"`
	Files   []string `json:"files"`   // 包里都有什么（给界面显示）
	Warning string   `json:"warning"` // 缺了什么（比如开发环境下没有 WinDivert 文件）
}

// pkgFile 一个待打包的文件。
type pkgFile struct {
	name string
	data []byte
	note string // 界面里显示在人话后面（如「含上游凭据」）
}

// ExportPackage 让用户选保存位置，然后生成装机包。
func (b *Backend) ExportPackage() (PackageResult, error) {
	def := "nethub-装机包-" + time.Now().Format("20060102") + ".zip"
	path, err := wruntime.SaveFileDialog(b.ctx, wruntime.SaveDialogOptions{
		Title:           "导出客户装机包（含上游凭据，只发给客户本人）",
		DefaultFilename: def,
		Filters: []wruntime.FileFilter{
			{DisplayName: "压缩包 (*.zip)", Pattern: "*.zip"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return PackageResult{}, err
	}
	if path == "" {
		return PackageResult{}, nil // 用户取消
	}
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		path += ".zip"
	}

	f, err := os.Create(path)
	if err != nil {
		return PackageResult{}, err
	}
	defer f.Close()
	res, err := b.buildPackage(f)
	if err != nil {
		return PackageResult{}, err
	}
	res.Path = path
	b.a.Bus.Info("已导出客户装机包：%s（%d 个文件）", filepath.Base(path), len(res.Files))
	if res.Warning != "" {
		b.a.Bus.Warn("装机包%s", res.Warning)
	}
	return res, nil
}

// buildPackage 生成装机包内容（拆出来是为了能测：SaveFileDialog 在测试里起不来）。
func (b *Backend) buildPackage(w io.Writer) (PackageResult, error) {
	res := PackageResult{}
	exeDir := b.packageExeDir()

	var files []pkgFile
	var missing []string

	// ① 运行必需：主程序 + WinDivert（驱动）+ 图标
	for _, name := range []string{"nethub.exe", "WinDivert.dll", "WinDivert64.sys", "nethub.ico"} {
		raw, err := os.ReadFile(filepath.Join(exeDir, name))
		if err != nil {
			missing = append(missing, name)
			continue
		}
		files = append(files, pkgFile{name, raw, ""})
	}

	// ② 当前配置（含凭据 —— 这个包就是给客户用的那一份）
	cfgNote := ""
	if p := b.a.Cfg.Path(); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			cfgNote = "含上游凭据"
			files = append(files, pkgFile{"config.yaml", raw, cfgNote})
		} else {
			missing = append(missing, "config.yaml")
		}
	}

	// ③ 启动脚本（纯 ASCII，避免 .cmd 里中文乱码的坑）
	files = append(files, pkgFile{"启动NetHub.cmd", []byte(launcherCmd), ""})

	// ④ 说明书（UTF-8 带 BOM，记事本打开不出乱码）
	files = append(files, pkgFile{"装机说明.txt", []byte(installDoc(b, missing)), ""})

	// ⑤ 使用说明（程序目录旁边有 docs/ 就一起带上；没有就不带）
	for _, rel := range []string{"docs/使用说明.md", "../docs/使用说明.md"} {
		if raw, err := os.ReadFile(filepath.Join(exeDir, filepath.FromSlash(rel))); err == nil {
			files = append(files, pkgFile{"使用说明.md", raw, ""})
			break
		}
	}

	// ⑥ 校验值：传输有没有损坏，一比对就知道
	var sums strings.Builder
	sums.WriteString("SHA256 校验值\r\n")
	sums.WriteString("（校验：certutil -hashfile <文件名> SHA256，或 Get-FileHash）\r\n\r\n")
	for _, f := range files {
		fmt.Fprintf(&sums, "%s  %s\r\n", sha256Hex(f.data), f.name)
	}
	files = append(files, pkgFile{"SHA256SUMS.txt", []byte(sums.String()), ""})

	zw := zip.NewWriter(w)
	for _, f := range files {
		if err := addZip(zw, f.name, f.data); err != nil {
			return res, err
		}
		line := f.name + "   " + bytesText(len(f.data))
		if f.note != "" {
			line += "（" + f.note + "）"
		}
		res.Files = append(res.Files, line)
	}
	if err := zw.Close(); err != nil {
		return res, err
	}
	if len(missing) > 0 {
		res.Warning = "里缺少：" + strings.Join(missing, "、") + "（当前程序目录找不到这些文件，客户那边可能起不来）"
	}
	return res, nil
}

// launcherCmd 启动脚本：一律以管理员身份启动（首次要装 WinDivert 驱动）。
// 纯 ASCII，避免代码页问题把中文注释搞成乱码。
const launcherCmd = `@echo off
rem NetHub launcher - starts the app elevated (needs admin to load the WinDivert driver).
setlocal
set "EXE=%~dp0nethub.exe"
if not exist "%EXE%" (
  echo nethub.exe not found next to this script.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -FilePath '%EXE%'"
`

// installDoc 装机说明（UTF-8 BOM，记事本打开不乱码）。
func installDoc(b *Backend, missing []string) string {
	var sb strings.Builder
	sb.WriteString("\ufeffNetHub 装机说明\r\n")
	sb.WriteString(strings.Repeat("=", 46) + "\r\n\r\n")

	sb.WriteString("【这是什么】\r\n")
	sb.WriteString("  一个内网隧道代理：只有配置里列出的目标会经过隧道，其余流量原样直连。\r\n")
	sb.WriteString("  不需要装 Proxifier、不需要 gost、没有常驻后台的第三方组件。\r\n\r\n")

	sb.WriteString("【怎么用】\r\n")
	sb.WriteString("  1. 整个文件夹解压到固定位置，建议 D:\\NetHub\r\n")
	sb.WriteString("     （路径里别带空格，省得以后写脚本被引号坑）\r\n")
	sb.WriteString("  2. 双击「启动NetHub.cmd」，UAC 弹窗点「是」\r\n")
	sb.WriteString("     （要管理员权限才能装载网络驱动，这是 Windows 的要求）\r\n")
	sb.WriteString("  3. 界面显示「运行中」就可以了；关窗口只是缩到托盘，不算退出\r\n")
	sb.WriteString("  4. 想开机自动跑：设置页 → headless 模式 → 安装服务 → 启动\r\n\r\n")

	sb.WriteString("【包里有什么】\r\n")
	for _, l := range []string{
		"nethub.exe        主程序",
		"WinDivert.dll     流量拦截驱动（第三方签名库）",
		"WinDivert64.sys   驱动本体，程序会自动装载",
		"nethub.ico        图标",
		"config.yaml       这台机器的配置：上游代理、要走隧道的目标",
		"启动NetHub.cmd    以管理员身份启动",
		"装机说明.txt      本文件",
		"SHA256SUMS.txt    校验值",
	} {
		sb.WriteString("  " + l + "\r\n")
	}
	sb.WriteString("\r\n")

	sb.WriteString("【这台机器的配置要点】\r\n")
	var chains []string
	for _, ch := range b.a.Cfg.Chains {
		chains = append(chains, fmt.Sprintf("%s（%d 个上游，策略 %s）", ch.Name, len(ch.Upstreams()), ch.StrategyName()))
	}
	if len(chains) > 0 {
		sb.WriteString("  上游链路：" + strings.Join(chains, "；") + "\r\n")
	}
	tunnel := 0
	for _, r := range b.a.Cfg.Routes {
		if r.NeedsChain() {
			tunnel++
		}
	}
	sb.WriteString(fmt.Sprintf("  规则：%d 条，其中 %d 条走隧道，其余是直连或阻断\r\n", len(b.a.Cfg.Routes), tunnel))
	sb.WriteString("  具体网段以 config.yaml 为准（界面「路由规则」里也能看）\r\n\r\n")

	sb.WriteString("【出问题怎么办】\r\n")
	sb.WriteString("  诊断页 → 一键诊断：先跑一遍，多数问题会直接指出是哪一环\r\n")
	sb.WriteString("  诊断页 → 导出诊断包：脱敏配置 + 日志 + 报告，发给技术支持\r\n")
	sb.WriteString("  注意：诊断包里的配置是脱敏的，而这个装机包不是 ——\r\n")
	sb.WriteString("        装机包含明文上游凭据，别往群里/邮件列表里发\r\n\r\n")

	if len(missing) > 0 {
		sb.WriteString("【警告】打包时缺了这些文件：" + strings.Join(missing, "、") + "\r\n")
		sb.WriteString("  这份包可能不完整，请从正式分发包补齐后再给客户。\r\n\r\n")
	}
	sb.WriteString("生成时间：" + time.Now().Format("2006-01-02 15:04:05") + "\r\n")
	return sb.String()
}

// packageExeDir 程序目录：测试可以注入，运行时用 exe 自己所在目录。
func (b *Backend) packageExeDir() string {
	if b.exeDir != "" {
		return b.exeDir
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Dir(exe)
	}
	return dirOf(b.a.Cfg.Path())
}

// bytesText 人类可读的文件大小（webui 自己一份，不去引用 engine 的实现）。
func bytesText(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// sha256Hex 内容摘要（十六进制）。
func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
