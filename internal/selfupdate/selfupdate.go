// Package selfupdate 做"一键更新"里最脏的那部分：在 Windows 上把自己换掉。
//
// Windows 的三条硬约束，以及本包的对策：
//
//  1. **运行中的 exe 不能覆盖，但可以改名**。
//     → 先把正在跑的 nethub.exe 改名成 nethub.exe.old，再把新文件写成 nethub.exe。
//
//  2. **已加载的 DLL（WinDivert.dll）改名/删除都可能失败**。
//     → 不在运行时碰它，而是留一个 pending.json：**重启后、装载驱动之前**再替换。
//
//  3. **新旧两个进程不能同时跑**（会抢 WinDivert 驱动）。
//     → pending.json 里记下旧进程 PID，新进程启动时先等它消失（最多 15 秒）再动手。
//
// 安全边界（很重要）：只替换**白名单里的文件**（程序本体与驱动），
// 绝不碰 config.yaml / logs / backups / secrets.dat —— 更新不该动用户数据。
package selfupdate

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 允许被更新覆盖的文件。多一个都不行 —— 更新是"替换程序"，不是"同步目录"。
var Allowed = map[string]bool{
	"nethub.exe":      true,
	"WinDivert.dll":   true,
	"WinDivert64.sys": true,
	"nethub.ico":      true,
}

const (
	StageDirName = "update"       // 暂存目录（程序目录下）
	PendingName  = "pending.json" // 待完成标记
	OldSuffix    = ".old"         // 旧文件改名后缀
)

// Pending 待完成的更新。写入后即使进程被杀，下次启动也能接着做完。
type Pending struct {
	Version    string   `json:"version"`     // 目标版本（日志用）
	Files      []string `json:"files"`       // 需要替换的文件（相对程序目录）
	StartedAt  string   `json:"started_at"`  // 什么时候开始的（人看）
	OldPID     int      `json:"old_pid"`     // 旧进程 PID：新进程要等它退出
	ExeSwapped bool     `json:"exe_swapped"` // nethub.exe 是否已经换过了
}

// Stage 把 zip 里白名单内的文件解到 <progDir>/update/，并写下 pending.json。
// 校验：nethub.exe 必须是 PE 文件（MZ 开头），否则说明包不对，直接拒绝。
func Stage(zipPath, progDir, version string, oldPID int) (Pending, error) {
	var p Pending
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return p, fmt.Errorf("打开更新包失败: %w", err)
	}
	defer zr.Close()

	dir := filepath.Join(progDir, StageDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return p, err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		if !Allowed[name] {
			continue // 白名单之外一律不取（配置、日志、脚本都不该来自更新包）
		}
		rc, err := f.Open()
		if err != nil {
			return p, fmt.Errorf("读取 %s 失败: %w", name, err)
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			return p, fmt.Errorf("读取 %s 失败: %w", name, err)
		}
		if name == "nethub.exe" && !looksLikePE(raw) {
			return p, fmt.Errorf("更新包里的 nethub.exe 不是可执行文件（包不对？）")
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o755); err != nil {
			return p, err
		}
		p.Files = append(p.Files, name)
	}
	if len(p.Files) == 0 {
		return p, fmt.Errorf("更新包里没有需要的文件（期望至少有 nethub.exe）")
	}
	hasExe := false
	for _, f := range p.Files {
		if f == "nethub.exe" {
			hasExe = true
		}
	}
	if !hasExe {
		return p, fmt.Errorf("更新包里没有 nethub.exe")
	}

	p.Version = version
	p.OldPID = oldPID
	p.StartedAt = time.Now().Format("2006-01-02 15:04:05")
	return p, writePending(progDir, p)
}

// looksLikePE 粗略校验 PE 头（MZ + PE\0\0）。
func looksLikePE(b []byte) bool {
	if len(b) < 64 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	off := int(b[0x3c]) | int(b[0x3d])<<8 // e_lfanew 低 16 位够用（实际是 4 字节）
	if off+4 > len(b) {
		return false
	}
	return b[off] == 'P' && b[off+1] == 'E' && b[off+2] == 0 && b[off+3] == 0
}

// SwapRunningExe 把正在运行的 exe 换成新的（改名旧文件 → 写新文件）。
// 这一步可以现在做：改名运行中的 exe 是允许的；新文件直接写成 nethub.exe。
func SwapRunningExe(progDir string) error {
	newExe := filepath.Join(progDir, StageDirName, "nethub.exe")
	curExe := filepath.Join(progDir, "nethub.exe")
	if _, err := os.Stat(newExe); err != nil {
		return fmt.Errorf("暂存的新版本不存在: %w", err)
	}
	_ = os.Remove(curExe + OldSuffix) // 上一轮留下的
	if err := os.Rename(curExe, curExe+OldSuffix); err != nil {
		return fmt.Errorf("旧版本改名失败（可能被别的程序占用）: %w", err)
	}
	raw, err := os.ReadFile(newExe)
	if err != nil {
		// 改名成功但读不到新的：把旧的换回来，别让程序消失
		_ = os.Rename(curExe+OldSuffix, curExe)
		return err
	}
	if err := os.WriteFile(curExe, raw, 0o755); err != nil {
		_ = os.Rename(curExe+OldSuffix, curExe)
		return fmt.Errorf("写入新版本失败: %w", err)
	}
	// 标记 exe 已换（重启后收尾时不用再动它）
	if p, ok := HasPending(progDir); ok {
		p.ExeSwapped = true
		_ = writePending(progDir, p)
	}
	return nil
}

// HasPending 有没有没做完的更新。
func HasPending(progDir string) (Pending, bool) {
	var p Pending
	raw, err := os.ReadFile(filepath.Join(progDir, StageDirName, PendingName))
	if err != nil {
		return p, false
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, false
	}
	return p, true
}

func writePending(progDir string, p Pending) error {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(progDir, StageDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, PendingName), raw, 0o644)
}

// ApplyPending 收尾：等在跑的旧进程退出，然后把剩下被占用过的文件（DLL/驱动）换掉。
// **必须在装载 WinDivert 之前调用**（那时候 DLL 还没被加载，可以随便换）。
// 返回被替换的文件名；没有待办时返回 nil。
func ApplyPending(progDir string, waitFor func(pid int, max time.Duration) bool) ([]string, error) {
	p, ok := HasPending(progDir)
	if !ok {
		return nil, nil
	}
	if p.OldPID > 0 && waitFor != nil {
		// 旧进程可能还在退出中；它不走开，我们就换不了 DLL（文件被占用）
		waitFor(p.OldPID, 15*time.Second)
	}
	stageDir := filepath.Join(progDir, StageDirName)
	var done []string
	var firstErr error
	for _, name := range p.Files {
		if name == "nethub.exe" && p.ExeSwapped {
			continue // 运行前就换过了，这里的还是旧进程的副本
		}
		src := filepath.Join(stageDir, name)
		dst := filepath.Join(progDir, name)
		raw, err := os.ReadFile(src)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("读暂存文件 %s 失败: %w", name, err)
			}
			continue
		}
		// 旧文件改名让路（加载中的文件通常删不掉、但改名一般可以；失败就重试几次）
		if _, err := os.Stat(dst); err == nil {
			_ = os.Remove(dst + OldSuffix)
			if err := retry(5, 300*time.Millisecond, func() error {
				return os.Rename(dst, dst+OldSuffix)
			}); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s 占用中，这次没能替换（下次启动再试）: %w", name, err)
				}
				continue
			}
		}
		if err := os.WriteFile(dst, raw, 0o755); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("写 %s 失败: %w", name, err)
			}
			continue
		}
		done = append(done, name)
	}
	// 全部换完了才清标记；有失败就留着，下次启动继续
	if len(done) == len(p.Files) || (firstErr == nil && len(done) > 0) {
		_ = os.Remove(filepath.Join(stageDir, PendingName))
		cleanupOld(progDir, p.Files)
	}
	return done, firstErr
}

// cleanupOld 删掉 .old 残留 —— 但保留 nethub.exe.old，它是一键回滚的底牌。
func cleanupOld(progDir string, files []string) {
	for _, name := range files {
		if name == "nethub.exe" {
			continue
		}
		_ = os.Remove(filepath.Join(progDir, name) + OldSuffix)
	}
}

// Rollback 回滚到上一版本（把 .old 换回来）。只在 exe.old 还在时可用。
func Rollback(progDir string) error {
	cur := filepath.Join(progDir, "nethub.exe")
	old := cur + OldSuffix
	if _, err := os.Stat(old); err != nil {
		return fmt.Errorf("没有可回滚的上一版本（%s 不存在）", filepath.Base(old))
	}
	bad := cur + ".bad"
	_ = os.Remove(bad)
	if err := os.Rename(cur, bad); err != nil {
		return fmt.Errorf("当前版本改名失败: %w", err)
	}
	if err := os.Rename(old, cur); err != nil {
		_ = os.Rename(bad, cur)
		return fmt.Errorf("回滚失败: %w", err)
	}
	return nil
}

// HasRollback 有没有可以回滚的上一版本。
func HasRollback(progDir string) bool {
	_, err := os.Stat(filepath.Join(progDir, "nethub.exe"+OldSuffix))
	return err == nil
}

// CleanupStale 清掉上次没做完、这次也不该再做的残留（无 pending 时的 update/ 目录）。
func CleanupStale(progDir string) {
	if _, ok := HasPending(progDir); ok {
		return
	}
	dir := filepath.Join(progDir, StageDirName)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}

func retry(n int, gap time.Duration, fn func() error) error {
	var err error
	for i := 0; i < n; i++ {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(gap)
	}
	return err
}

// 供 webui 显示用：把文件名列表拼成一句话。
func Describe(files []string) string {
	if len(files) == 0 {
		return "无"
	}
	return strings.Join(files, "、")
}
