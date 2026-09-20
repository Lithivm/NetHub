package dnsmap

import (
	"net"
	"testing"
	"time"
)

func newFake() *Map {
	m := New()
	m.lookup = func(host string) ([]string, error) {
		switch host {
		case "main.his.com":
			return []string{"172.30.4.217"}, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
	}
	return m
}

// 域名→IP、IP→域名 双向都要对；优先级高（规则）的名字要盖住观察来的。
func TestSetAndLookup(t *testing.T) {
	m := newFake()
	if _, err := m.Resolve("main.his.com", PrioRule); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ips := m.IPsFor("MAIN.HIS.COM"); len(ips) != 1 || ips[0] != "172.30.4.217" {
		t.Errorf("域名大小写应不敏感，得到 %v", ips)
	}
	if name, ok := m.NameFor(net.ParseIP("172.30.4.217")); !ok || name != "main.his.com" {
		t.Errorf("IP→域名 = %q ok=%v", name, ok)
	}
	// 低优先级的观察结果不该盖住规则里的名字
	m.Set("other.example", []string{"172.30.4.217"}, PrioObserved)
	if name, _ := m.NameFor(net.ParseIP("172.30.4.217")); name != "main.his.com" {
		t.Errorf("规则里的名字应优先，得到 %q", name)
	}
	// 反过来：后写的规则优先级更高（规则之间后写覆盖，符合“改配置”的直觉）
	m.Set("newer.example", []string{"172.30.4.217"}, PrioRule)
	if name, _ := m.NameFor(net.ParseIP("172.30.4.217")); name != "newer.example" {
		t.Errorf("同优先级后写应覆盖，得到 %q", name)
	}
}

// 解析失败要能记住原因（界面上要说得出“这个域名现在解析不到”）。
func TestResolveFailure(t *testing.T) {
	m := newFake()
	if _, err := m.Resolve("nope.example", PrioRule); err == nil {
		t.Fatal("应该报解析失败")
	}
	st := m.Status()
	if len(st) != 1 || !st[0].Failed || st[0].LastErr == "" {
		t.Fatalf("失败状态没记住: %+v", st)
	}
	if st[0].Stale {
		t.Error("刚写进去的不该算过期")
	}
}

func TestIsHostname(t *testing.T) {
	yes := []string{"main.his.com", "a-b.c", "main.*.com", "*.his.com"}
	no := []string{"", "10.0.0.5", "172.30.4.0/24", "127.0.0.1"}
	for _, s := range yes {
		if !IsHostname(s) {
			t.Errorf("IsHostname(%q) 应为真", s)
		}
	}
	for _, s := range no {
		if IsHostname(s) {
			t.Errorf("IsHostname(%q) 应为假", s)
		}
	}
	if !IsWildcard("main.*.com") || IsWildcard("main.his.com") {
		t.Error("IsWildcard 判断不对")
	}
}

// 过期判断按 TTL。
func TestStale(t *testing.T) {
	m := newFake()
	base := time.Now()
	m.nowFunc = func() time.Time { return base }
	m.Set("main.his.com", []string{"172.30.4.217"}, PrioRule)
	m.nowFunc = func() time.Time { return base.Add(TTL + time.Second) }
	if st := m.Status(); !st[0].Stale {
		t.Error("超过 TTL 应算过期")
	}
}
