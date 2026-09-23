package config

import (
	"os"
	"path/filepath"
	"testing"
)

// 回归：overlap 的“完全包住”必须比前缀长度，不能只比网络地址。
// a=10.0.0.0/16（在前）、b=10.0.0.0/8（在后）：是 b 包住 a，不是 a 包住 b。
// 旧实现用 an.Contains(bn.IP) 会把 b 判成 dead（“永远不会生效”，与事实相反）。
func TestOverlapContainmentChecksPrefixLength(t *testing.T) {
	c := &Config{Routes: []Route{
		{Name: "窄", Chain: "a", Targets: []string{"10.0.0.0/16"}},
		{Name: "宽", Chain: "b", Targets: []string{"10.0.0.0/8"}},
	}}
	got := c.CheckOverlaps()
	if len(got) != 1 {
		t.Fatalf("期望 1 条重叠结论，得到 %+v", got)
	}
	if got[0].Kind == "dead" {
		t.Fatalf("误判为 dead（“第 2 条整个被第 1 条包住”），实际是第 2 条更宽: %+v", got[0])
	}
	if got[0].Kind != "fine" {
		t.Fatalf("期望 fine（窄在前、宽在后是正常写法），得到 %+v", got[0])
	}
}

// 回归：occupiedHint 只看“排在前面”的规则。被编辑的规则后面还有一条同目标规则，
// 不能提示成“它在前面，会先命中”（方向说反了）。
func TestOccupiedHintOnlyLooksAtEarlierRules(t *testing.T) {
	c := &Config{Routes: []Route{
		{Name: "当前", Chain: "a", Targets: []string{"10.0.0.0/24"}},
		{Name: "后面重复", Chain: "b", Targets: []string{"10.0.0.0/24"}},
	}}
	if hint := c.occupiedHint(c.Routes[0], 0); len(hint) != 0 {
		t.Fatalf("后面的规则不该被提示为“在前面”: %v", hint)
	}
	// 反过来：编辑后面那条时，前面的同名目标要提示
	if hint := c.occupiedHint(c.Routes[1], 1); len(hint) != 1 {
		t.Fatalf("前面的规则应被提示: %v", hint)
	}
}

// 回归：UpdateChain 改名后校验失败，必须把链名与规则引用一起回滚，
// 不能留下“规则指向一个不存在的链”。
func TestUpdateChainRollbackRestoresRouteReferences(t *testing.T) {
	c := &Config{
		Relay:  "127.0.0.1:0",
		Chains: []Chain{{Name: "a", Forward: "socks5://1.2.3.4:1080"}},
		Routes: []Route{{Name: "r", Targets: []string{"10.0.0.0/24"}, Chain: "a"}},
	}
	// 改名成 b 且不带任何上游 → Validate 必失败
	if err := c.UpdateChain("a", Chain{Name: "b"}); err == nil {
		t.Fatal("缺上游的链应当校验失败")
	}
	if c.Chains[0].Name != "a" {
		t.Fatalf("链名没回滚: %q", c.Chains[0].Name)
	}
	if c.Routes[0].Chain != "a" {
		t.Fatalf("规则引用没回滚（悬空链）: %q", c.Routes[0].Chain)
	}
}

// 回归：保险箱缓存加载失败时必须清空，不能把上一个目录的口令串给下一个目录。
func TestSecretsCacheNotLeakedAcrossDirs(t *testing.T) {
	reset := func() {
		secretMu.Lock()
		secretStore, secretDir = nil, ""
		secretMu.Unlock()
	}
	reset()
	t.Cleanup(reset)

	dirA, dirB := t.TempDir(), t.TempDir()
	// B 目录一个损坏的 secrets.dat，让 Load 失败
	if err := os.WriteFile(filepath.Join(dirB, "secrets.dat"), []byte("!!!not-base64!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Config{path: filepath.Join(dirA, "config.yaml")}
	b := &Config{path: filepath.Join(dirB, "config.yaml")}

	if a.Secrets() == nil {
		t.Fatal("A（无 secrets.dat）应当拿到空箱子")
	}
	if b.Secrets() != nil {
		t.Fatal("B（secrets.dat 损坏）应当返回 nil")
	}
	if got := b.Secrets(); got != nil {
		t.Fatal("B 第二次访问拿到了缓存 —— 串用了 A 目录的口令")
	}
}

// 回归：Validate 必须拦住 rules.Load 会拦的写法（否则界面能把起不来的配置写进文件）。
func TestValidateRejectsEmptyChainAndBadLocalNets(t *testing.T) {
	base := func() *Config {
		return &Config{
			Relay:  "127.0.0.1:0",
			Chains: []Chain{{Name: "a", Forward: "socks5://1.2.3.4:1080"}},
		}
	}
	c := base()
	c.Routes = []Route{{Name: "空链", Targets: []string{"10.0.0.0/24"}, Chain: ""}}
	if err := c.Validate(); err == nil {
		t.Fatal("chain 为空的启用规则应当校验失败")
	}

	c2 := base()
	c2.Routes = []Route{{Name: "坏本机网段", Targets: []string{"10.0.0.0/24"}, Chain: "a",
		LocalNets: []string{"不是网段"}}}
	if err := c2.Validate(); err == nil {
		t.Fatal("非法 local_nets 应当校验失败")
	}
}
