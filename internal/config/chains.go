package config

import (
	"fmt"

	"strings"

	"nethub/internal/upstream"
)

func (c *Config) FindChain(name string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.findChainLocked(name)
}

func (c *Config) findChainLocked(name string) int {
	for i := range c.Chains {
		if c.Chains[i].Name == name {
			return i
		}
	}
	return -1
}

// AddChain 追加一条链。
func (c *Config) AddChain(ch Chain) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(ch.Name) == "" {
		return fmt.Errorf("链名不能为空")
	}
	if c.findChainLocked(ch.Name) >= 0 {
		return fmt.Errorf("链名 %q 已存在", ch.Name)
	}
	old := c.Chains
	// copy-on-write：读方（引擎）可能正持着旧切片遍历，绝不原地改它
	c.Chains = append(append([]Chain(nil), c.Chains...), ch)
	if err := c.validateLocked(); err != nil {
		c.Chains = old // 回滚，不留非法状态
		return err
	}
	return nil
}

// chainHasCreds 这条链的上游 URL 里有没有明文凭据（user:pass@ 或 ?auth=）。
func chainHasCreds(ch Chain) bool {
	for _, raw := range ch.Upstreams() {
		up, err := upstream.Parse(raw)
		if err != nil {
			continue
		}
		if up.Creds.User != "" || up.Creds.Pass != "" {
			return true
		}
	}
	return false
}

// ChainCredUser 已封存口令的账号名（只给界面显示"账号还是那个"，不暴露口令）。
func (c *Config) ChainCredUser(ch Chain) string {
	if ch.Secret == "" {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	store := c.Secrets()
	if store == nil {
		return ""
	}
	cred := store.Get(ch.Secret)
	if i := strings.Index(cred, ":"); i >= 0 {
		return cred[:i]
	}
	return cred
}

// UpdateChain 把 oldName 这条链替换成 ch（允许改名）。
func (c *Config) UpdateChain(oldName string, ch Chain) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.findChainLocked(oldName)
	if i < 0 {
		return fmt.Errorf("找不到链 %q", oldName)
	}
	if ch.Name != oldName && c.findChainLocked(ch.Name) >= 0 {
		return fmt.Errorf("链名 %q 已存在", ch.Name)
	}
	// copy-on-write：先拿旧切片做快照（引擎可能正在遍历），改的是一份新切片
	oldChains, oldRoutes := c.Chains, c.Routes
	chains := append([]Chain(nil), c.Chains...)
	routes := append([]Route(nil), c.Routes...)
	old := chains[i]
	// ⚠ 关键：界面上编辑链路时，表单里看不到已封存的口令（forward 只剩 host:port），
	// 如果直接整体替换，就会把 secret: 引用一并抹掉 —— 那才是真丢口令。
	// 所以：新写法里没有凭据时，继承旧的 secret 引用；
	// 若用户确实填了新凭据（URL 里带 user:pass@），则丢掉旧引用，交给保存时重新封存。
	if ch.Secret == "" && old.Secret != "" && !chainHasCreds(ch) {
		ch.Secret = old.Secret
	}
	if chainHasCreds(ch) {
		ch.Secret = ""
	}
	chains[i] = ch
	if ch.Name != oldName {
		// 改名同步改所有引用
		for j := range routes {
			if routes[j].Chain == oldName {
				routes[j].Chain = ch.Name
			}
		}
	}
	c.Chains, c.Routes = chains, routes
	if err := c.validateLocked(); err != nil {
		// 回滚：链本体 + 改名连带改过的规则引用（只还原链会留下“规则指向不存在的链”）
		c.Chains, c.Routes = oldChains, oldRoutes
		return err
	}
	return nil
}

// ChainUsage 返回引用了该链的规则条数。
func (c *Config) ChainUsage(name string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.chainUsageLocked(name)
}

func (c *Config) chainUsageLocked(name string) int {
	n := 0
	for _, r := range c.Routes {
		if r.Chain == name {
			n++
		}
	}
	return n
}

// RemoveChain 删除链；还被规则引用时拒绝，避免静默产生悬空规则。
func (c *Config) RemoveChain(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.findChainLocked(name)
	if i < 0 {
		return fmt.Errorf("找不到链 %q", name)
	}
	if n := c.chainUsageLocked(name); n > 0 {
		return fmt.Errorf("链 %q 还被 %d 条规则引用，请先改掉那些规则", name, n)
	}
	if len(c.Chains) <= 1 {
		return fmt.Errorf("至少要保留一条链")
	}
	out := make([]Chain, 0, len(c.Chains)-1)
	out = append(out, c.Chains[:i]...)
	out = append(out, c.Chains[i+1:]...)
	c.Chains = out
	return nil
}

// MoveChain 把第 from 条链移到第 to 条位置。
func (c *Config) MoveChain(from, to int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.Chains)
	if from < 0 || from >= n || to < 0 || to >= n || from == to {
		return fmt.Errorf("位置越界")
	}
	ch := c.Chains[from]
	rest := append(append([]Chain{}, c.Chains[:from]...), c.Chains[from+1:]...)
	out := append([]Chain{}, rest[:to]...)
	out = append(out, ch)
	out = append(out, rest[to:]...)
	c.Chains = out
	return nil
}

// normalize 就地规范一条规则：清掉名字/链两侧空白、旧 target 并进 targets、
// 目标归一化成 CIDR 并组内去重。返回是否改动过、被丢掉的重复项。
