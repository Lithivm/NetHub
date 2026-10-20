package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 日志档位是本机偏好：必须**持久化**，而且不能被“整份配置替换”的几条路径洗回 normal。
//
// 为什么要一整组用例：这几条路径（保存/回滚/-apply/导入/热重载）分别在不同包里，
// 谁都不会顺手想起“还有档位这回事”。2026-10-20 现场就是部署一份配置之后
// 日志从 verbose 变回 normal，事后回去查故障时判定面没了。
// 分档是**靠人自觉**的东西，只有测试能钉住。

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const seedChain = "relay: 127.0.0.1:0\nchains:\n  - name: a\n    forward: socks5://127.0.0.1:1080\nroutes: []\n"

// ① 存下去再读回来，还是 verbose —— 这是“重启不丢档”的最小事实。
func TestLogLevelSurvivesSaveAndLoad(t *testing.T) {
	p := writeCfg(t, seedChain)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.LogLevel() != "normal" {
		t.Fatalf("没写档位时应当是 normal，得到 %q", c.LogLevel())
	}
	if c.LogLevelExplicit() {
		t.Error("没写档位时不该算“明确写了”")
	}
	c.SetLogLevel("verbose")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c2.LogLevel() != "verbose" {
		t.Fatalf("存过 verbose，读回来是 %q", c2.LogLevel())
	}
	if !c2.LogLevelExplicit() {
		t.Error("文件里写了 log_level，应当算“明确写了”")
	}
}

// ② 默认配置落盘时必须把 log_level 写出来（不带 omitempty）。
//
// 少了这一行，现场打开 config.yaml 根本看不到有这个开关；也分不清
// “用户选了 normal”与“这份配置没提到档位”。
func TestDefaultConfigWritesLogLevel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	c := Default()
	c.path = p
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "log_level: normal") {
		t.Errorf("默认配置里应当显式写出 log_level: normal，实际：\n%s", string(b))
	}
}

// ③ 认不出的值：回落 normal，但**原始值要留得下**（启动时 WARN 用），
// 否则“我明明存了 verbose，一重启就没了”只能靠猜。
func TestLogLevelDirtyValueIsRecorded(t *testing.T) {
	p := writeCfg(t, seedChain+"ui:\n    log_level: verbos\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.LogLevel() != "normal" {
		t.Errorf("认不出的值应回落 normal，得到 %q", c.LogLevel())
	}
	if got := c.LogLevelDirty(); got != "verbos" {
		t.Errorf("原始脏值没留住：%q", got)
	}
}

// ④ 整份配置替换（导入/部署）拿到的是一份“别人机器上的 normal”，本机偏好要搬回来。
func TestKeepLocalPrefsFrom(t *testing.T) {
	old := Default()
	old.SetLogLevel("debug")
	incoming := Default() // 别人那份是 normal
	if incoming.LogLevel() != "normal" {
		t.Fatal("前提：incoming 是 normal")
	}
	if !incoming.KeepLocalPrefsFrom(old) {
		t.Error("档位不同，应当报告“改了”")
	}
	if incoming.LogLevel() != "debug" {
		t.Errorf("本机偏好没搬过来：%q", incoming.LogLevel())
	}
	// 相同的档位不算改动（调用方据此决定要不要重写文件、打日志）
	if incoming.KeepLocalPrefsFrom(old) {
		t.Error("档位相同不该报改动")
	}
}

// ⑤ 回滚备份：回滚的是配置内容，不是“这台机器看日志的习惯”。
func TestRestoreBackupKeepsLocalLogLevel(t *testing.T) {
	p := writeCfg(t, seedChain)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c.SetLogLevel("verbose")
	if err := c.Save(); err != nil { // 这一份会进 backups
		t.Fatal(err)
	}
	c.SetLogLevel("normal")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	list := c.Backups()
	if len(list) == 0 {
		t.Fatal("应当有备份")
	}
	// 回滚到那份 verbose 的备份：内容回来了，档位本来就该是 verbose
	nc, err := c.RestoreBackup(list[0])
	if err != nil {
		t.Fatal(err)
	}
	if nc.LogLevel() != "normal" {
		t.Errorf("回滚到 normal 的备份后档位应是 normal，得到 %q", nc.LogLevel())
	}

	// 关键一环：备份里是 normal，本机现在是 debug → 回滚不能把 debug 拖回 normal
	c.SetLogLevel("debug")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	list = c.Backups()
	if len(list) == 0 {
		t.Fatal("应当有备份")
	}
	nc2, err := c.RestoreBackup(list[len(list)-1])
	if err != nil {
		t.Fatal(err)
	}
	if nc2.LogLevel() != "debug" {
		t.Errorf("回滚不该改本机日志档位，期望 debug，得到 %q", nc2.LogLevel())
	}
	// 而且写回了文件（否则重启后又变回备份那份的档位）
	reloaded, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.LogLevel() != "debug" {
		t.Errorf("保住的档位要落盘（否则重启就丢），文件里是 %q", reloaded.LogLevel())
	}
}

// 文件档（`ui.log_level_file`）：空 = 跟随屏幕档；单独设了就各走各的。
//
// 为什么要有这一项：屏幕与文件是两个受众 —— 现场看着要清爽（normal），
// 事后把 logs/nethub.log 发出去时要能看到“为什么”（verbose）。
func TestLogLevelFileFollowsScreenWhenUnset(t *testing.T) {
	p := writeCfg(t, seedChain)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c.SetLogLevel("verbose")
	if got := c.LogLevelFile(); got != "verbose" {
		t.Errorf("没单独设文件档时应跟随屏幕档，得到 %q", got)
	}
	if c.LogLevelFileSet() {
		t.Error("没单独设过就不该报告“已设”")
	}

	// 单独设一个更细的文件档：屏幕不动
	c.SetLogLevelFile("debug")
	if got := c.LogLevelFile(); got != "debug" {
		t.Errorf("文件档 = %q", got)
	}
	c.SetLogLevel("normal")
	if got := c.LogLevelFile(); got != "debug" {
		t.Errorf("改屏幕档不该把单独设过的文件档改掉，得到 %q", got)
	}

	// 两个都持久化（重启不丢）
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c2.LogLevel() != "normal" || c2.LogLevelFile() != "debug" {
		t.Errorf("存读后应为 屏幕 normal / 文件 debug，实际 %q / %q", c2.LogLevel(), c2.LogLevelFile())
	}

	// 传空串 = 回到“跟随”（配置里那一项不再写出来）
	c2.SetLogLevelFile("")
	if c2.LogLevelFileSet() || c2.LogLevelFile() != "normal" {
		t.Errorf("清空文件档后应跟随屏幕 normal，实际 set=%v lv=%q", c2.LogLevelFileSet(), c2.LogLevelFile())
	}
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "log_level_file") {
		t.Errorf("跟随屏幕时不该把 log_level_file 写进文件：\n%s", string(b))
	}
}

// 本机偏好要把两个档位都带上（-apply / 导入 / 回滚 都不许把它们洗掉）。
func TestLocalPrefsCarryFileLevel(t *testing.T) {
	old := Default()
	old.SetLogLevel("normal")
	old.SetLogLevelFile("debug")
	incoming := Default()
	if !incoming.KeepLocalPrefsFrom(old) {
		t.Fatal("档位不同，应当报告改动")
	}
	if incoming.LogLevel() != "normal" || incoming.LogLevelFile() != "debug" {
		t.Errorf("文件档没跟着搬：屏幕 %q / 文件 %q", incoming.LogLevel(), incoming.LogLevelFile())
	}
}

// 托盘流量图（开关 + 显示内容）与主题也是“本机偏好”：
// 换一份别人的配置（-apply / 导入 / 回滚 / 部署）不该把它们换掉。
//
// 这条是 2026-10-20 补的：原先 LocalPrefs 只管日志档位，而“显示内容”这种
// 改一次就一直有效的偏好被配置替换洗掉，用户看到的是“明明设过，换完配置就没了”。
func TestLocalPrefsCarryTrayAndTheme(t *testing.T) {
	old := Default()
	old.SetTheme("dark")
	old.SetTrayTraffic(true)
	old.SetTrayTrafficMode("up")

	incoming := Default() // 别人那份：浅色主题、托盘图关着、total
	if !incoming.KeepLocalPrefsFrom(old) {
		t.Fatal("偏好不同，应当报告改动")
	}
	if incoming.Theme() != "dark" {
		t.Errorf("主题没保住：%q", incoming.Theme())
	}
	if !incoming.TrayTraffic() {
		t.Error("托盘流量图开关没保住")
	}
	if got := incoming.TrayTrafficMode(); got != "up" {
		t.Errorf("托盘显示内容没保住：%q", got)
	}
}

// 认不出的值都要回落成安全的默认，而不是原样写回。
func TestTrayTrafficModeNormalize(t *testing.T) {
	c := Default()
	c.SetTrayTrafficMode("outgoing")
	if got := c.TrayTrafficMode(); got != "up" {
		t.Errorf("outgoing 应当认成 up，得到 %q", got)
	}
	c.SetTrayTrafficMode("verbos")
	if got := c.TrayTrafficMode(); got != "total" {
		t.Errorf("认不出的值应当回落 total，得到 %q", got)
	}
	c.SetTheme("VERBOS")
	if got := c.Theme(); got != "system" {
		t.Errorf("主题认不出应当回落 system，得到 %q", got)
	}
}
