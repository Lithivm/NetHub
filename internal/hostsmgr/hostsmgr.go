// Package hostsmgr 管理系统 hosts 文件里"我们自己那一段"。
//
// 只动标记块之间的内容，块外原则上一个字都不碰（Docker 的条目、微信的 pin 都在块外）。
// 唯一的例外见 Apply 里的"同名接管"：块外如果已经有一条同名记录，Windows 会**先**用
// 那条（hosts 自上而下第一条生效），我们写的就没用了 —— 所以必须把它挪进我们的块。
//
// 写入用"唯一临时文件 + 原子替换"（失败重试，绝不原地截断写），写后回读校验，并刷一次 DNS 缓存
// （否则系统缓存的旧解析会继续生效，表现成"改了没反应"）。
package hostsmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// mu 串行化对 hosts 的读-改-写。
//
// 并发来源：后台 60s 自愈协程 + 界面保存/启停都在调 Apply/Remove/Verify。
// 不加锁的后果很脏：① 自愈拿着旧条目把用户刚存的覆盖回去；
// ② 两个写各写同一个临时文件、互相踩；③ 读到别人写到一半的内容。
var mu sync.Mutex

const (
	beginMark = "# >>> NetHub 自动维护开始（勿手改本段内的内容）"
	endMark   = "# <<< NetHub 自动维护结束"
)

// FlushFunc 刷 DNS 缓存（测试里替换掉，别真去刷系统缓存）。
var FlushFunc = flushDNS

// isBegin 判定是否是"我们的区块开始"。
func isBegin(line string) bool {
	return strings.HasPrefix(line, beginMark)
}

// isEnd 判定是否是"我们的区块结束"。
func isEnd(line string) bool {
	return strings.HasPrefix(line, endMark)
}

// Path 返回系统 hosts 路径。
func Path() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// hostOf 取一行 hosts 记录里的主机名（第一个字段），注释/空行返回空串。
func hostOf(line string) string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	if i := strings.IndexByte(s, '#'); i >= 0 { // 行尾注释
		s = strings.TrimSpace(s[:i])
	}
	f := strings.Fields(s)
	if len(f) < 2 {
		return ""
	}
	return strings.ToLower(f[1])
}

// splitLines 拆行（统一成不带 \r 的行）。
func splitLines(full string) []string {
	lines := strings.Split(strings.TrimPrefix(full, "\ufeff"), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

// Read 返回 (块内的行, 块是否存在, 整个文件内容, 错误)。
func Read() (block []string, exists bool, full string, err error) {
	b, err := os.ReadFile(Path())
	if err != nil {
		return nil, false, "", err
	}
	full = string(b)
	in := false
	for _, t := range splitLines(full) {
		switch {
		case isBegin(t):
			in, exists = true, true
		case isEnd(t):
			in = false
		case in:
			if s := strings.TrimSpace(t); s != "" && !strings.HasPrefix(s, "#") {
				block = append(block, s)
			}
		}
	}
	return block, exists, full, nil
}

// ApplyResult 描述这次写入干了什么（用来给界面/日志一个能看见的结果）。
type ApplyResult struct {
	Written    int      // 写进我们块里的条数
	TakenOver  []string // 块外的同名记录（会被我们接管，格式：旧行 → 新行）
	FlushError error    // 刷 DNS 缓存的结果（失败不影响写入本身）
}

// Apply 把 entries 写进标记块（替换旧的块；没有块就追加到文件末尾）。
//
// 会做三件以前漏掉的事：
//  1. 块外的**同名记录**挪走 —— Windows 用第一条匹配，否则我们写的永远不生效；
//  2. 写后回读校验（替换失败会被发现，而不是"以为写好了"）；
//  3. 刷一次 DNS 缓存，让改动立刻可见。
//
// 首次会备份到 hosts.nethub.bak（只在备份不存在时创建，避免覆盖最初的原件）。
func Apply(entries []string) (ApplyResult, error) {
	mu.Lock()
	defer mu.Unlock()

	var res ApplyResult
	p := Path()
	_, _, full, err := Read()
	if err != nil {
		return res, err
	}

	// 备份（仅首次）
	bak := p + ".nethub.bak"
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		if err := os.WriteFile(bak, []byte(full), 0o644); err != nil {
			return res, fmt.Errorf("备份 hosts 失败: %w", err)
		}
	}

	// 规范化要写入的条目：去掉空行/注释，同时收集"我们管的名字"
	clean := make([]string, 0, len(entries))
	ours := map[string]bool{}
	for _, e := range entries {
		s := strings.TrimSpace(e)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		clean = append(clean, s)
		if h := hostOf(s); h != "" {
			ours[h] = true
		}
	}
	res.Written = len(clean)

	bom := strings.HasPrefix(full, "\ufeff")

	// 去掉旧块；同时把块外的**同名**记录摘出来（它们会抢在我们的记录前面生效）
	var kept []string
	skip := false
	for _, t := range splitLines(full) {
		switch {
		case isBegin(t):
			skip = true
			continue
		case isEnd(t):
			skip = false
			continue
		}
		if skip {
			continue
		}
		if h := hostOf(t); h != "" && ours[h] {
			// 块外已有同名记录 → 我们接管它（值相同的就不必惊动用户）
			if want := firstIPOf(clean, h); want != "" && firstIPOf([]string{t}, h) != want {
				res.TakenOver = append(res.TakenOver, fmt.Sprintf("%s → %s", strings.TrimSpace(t), want+" "+h))
			}
			continue
		}
		kept = append(kept, t)
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}

	var out strings.Builder
	if bom {
		out.WriteString("\ufeff")
	}
	out.WriteString(strings.Join(kept, "\n"))
	out.WriteString("\n\n")
	out.WriteString(beginMark + "\n")
	for _, e := range clean {
		out.WriteString(e + "\n")
	}
	out.WriteString(endMark + "\n")
	content := out.String()

	if err := writeFile(p, content); err != nil {
		return res, err
	}

	// 回读校验：写没写进去、块外还有没有同名记录
	block, exists, full2, err := Read()
	if err != nil {
		return res, fmt.Errorf("写入后回读失败: %w", err)
	}
	if !exists {
		return res, fmt.Errorf("写入后没找到 NetHub 标记段（%s 可能被其他程序覆盖了）", filepath.Base(p))
	}
	if want, got := strings.Join(clean, "\n"), strings.Join(block, "\n"); want != got {
		return res, fmt.Errorf("写入后内容对不上（期望 %d 条，实际 %d 条）", len(clean), len(block))
	}
	if extra := outsideConflict(full2, ours); len(extra) > 0 {
		return res, fmt.Errorf("块外仍有同名记录会在我们前面生效: %s", strings.Join(extra, "; "))
	}

	res.FlushError = FlushFunc()
	return res, nil
}

// firstIPOf 取某组行里某个主机名对应的 IP（第一条）。
func firstIPOf(lines []string, host string) string {
	for _, l := range lines {
		if hostOf(l) != host {
			continue
		}
		if f := strings.Fields(strings.TrimSpace(l)); len(f) >= 2 {
			return f[0]
		}
	}
	return ""
}

// outsideConflict 找出块外仍然存在的同名记录（理论上 Apply 之后不该有）。
func outsideConflict(full string, ours map[string]bool) []string {
	var out []string
	in := false
	for _, t := range splitLines(full) {
		switch {
		case isBegin(t):
			in = true
			continue
		case isEnd(t):
			in = false
			continue
		}
		if in {
			continue
		}
		if h := hostOf(t); h != "" && ours[h] {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

// writeFile 先写唯一临时文件 + 原子替换。
//
// 两个必须：
//   - 临时文件用 CreateTemp 的**唯一名**（以前固定叫 hosts.nethub.tmp，两个写并发时互相踩）；
//   - 替换失败时**绝不原地截断写** —— os.WriteFile 是 O_TRUNC，写到一半被杀软/断电打断
//     会把客户的 hosts 弄成半截，那台机器解析全乱。宁可报错让人/自愈重试。
func writeFile(p, content string) error {
	dir := filepath.Dir(p)
	f, err := os.CreateTemp(dir, "nethub-hosts-*.tmp")
	if err != nil {
		return fmt.Errorf("建临时文件失败: %w", err)
	}
	tmp := f.Name()
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return fmt.Errorf("写临时文件失败: %w", werr)
		}
		return fmt.Errorf("关闭临时文件失败: %w", cerr)
	}
	_ = os.Chmod(tmp, 0o644)

	// 替换可能被其他程序/杀软短暂占用 → 退避重试几次
	var lastErr error
	for i := 0; i < 5; i++ {
		if err := os.Rename(tmp, p); err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(50*(i+1)) * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return fmt.Errorf("替换 hosts 失败（可能被其他程序/杀软占用，已重试 5 次）: %w", lastErr)
}

// Remove 删掉我们的标记块（卸载/停用时调用）。
func Remove() error {
	mu.Lock()
	defer mu.Unlock()

	p := Path()
	_, exists, full, err := Read()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	bom := strings.HasPrefix(full, "\ufeff")
	var kept []string
	skip := false
	for _, t := range splitLines(full) {
		switch {
		case isBegin(t):
			skip = true
			continue
		case isEnd(t):
			skip = false
			continue
		}
		if !skip {
			kept = append(kept, t)
		}
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	s := strings.Join(kept, "\n") + "\n"
	if bom {
		s = "\ufeff" + s
	}
	if err := writeFile(p, s); err != nil {
		return err
	}
	_ = FlushFunc()
	return nil
}

// Same 判断"块里的内容"与期望是否一致（给定期自检用：不一致就说明被别的程序动了）。
func Same(block []string, want []string) bool {
	if len(block) != len(want) {
		return false
	}
	for i := range block {
		if strings.TrimSpace(block[i]) != strings.TrimSpace(want[i]) {
			return false
		}
	}
	return true
}

// Verify 检查当前 hosts 是否还是我们要的样子，返回（是否一致, 不一致的原因）。
//
// 为什么要定期查：改 hosts 的程序不止我们（杀软、微信 pin、Clash、VPN 都会写这个文件），
// 而它一旦被改，表现就是"域名解析莫名其妙不对/时好时坏"—— 必须能改回来并说出来。
func Verify(entries []string) (bool, string) {
	mu.Lock()
	defer mu.Unlock()

	want := make([]string, 0, len(entries))
	ours := map[string]bool{}
	for _, e := range entries {
		s := strings.TrimSpace(e)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		want = append(want, s)
		if h := hostOf(s); h != "" {
			ours[h] = true
		}
	}
	block, exists, full, err := Read()
	if err != nil {
		return false, fmt.Sprintf("读 hosts 失败: %v", err)
	}
	if !exists {
		return false, "NetHub 标记段不见了"
	}
	if !Same(block, want) {
		return false, fmt.Sprintf("标记段内容被改动（期望 %d 条，实际 %d 条）", len(want), len(block))
	}
	if extra := outsideConflict(full, ours); len(extra) > 0 {
		return false, "块外出现同名记录（会抢在我们前面生效）: " + strings.Join(extra, "; ")
	}
	return true, ""
}
