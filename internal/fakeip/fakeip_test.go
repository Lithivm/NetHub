package fakeip

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func newTestPool(t *testing.T, cidr string) *Pool {
	t.Helper()
	p, err := NewPool(cidr)
	if err != nil {
		t.Fatalf("建池失败(%s): %v", cidr, err)
	}
	now := time.Now()
	p.nowFn = func() time.Time { return now }
	return p
}

// 同一个名字必须**稳定**拿到同一个假 IP —— 否则连接回来时对不上名字。
func TestAssignIsStable(t *testing.T) {
	p := newTestPool(t, "198.19.0.0/24")
	a1 := p.Assign("main.his.com", time.Minute)
	a2 := p.Assign("main.his.com", time.Minute)
	if a1 == nil || a2 == nil {
		t.Fatal("分配失败")
	}
	if !a1.Equal(a2) {
		t.Fatalf("同一个名字拿到了不同假 IP: %v vs %v", a1, a2)
	}
	if n, ok := p.NameFor(a1); !ok || n != "main.his.com" {
		t.Fatalf("反查 = %q, %v（期望 main.his.com）", n, ok)
	}
	if ip, ok := p.IPFor("main.his.com"); !ok || !ip.Equal(a1) {
		t.Fatalf("正查 = %v, %v", ip, ok)
	}
	// 不同名字必须拿到不同 IP
	b := p.Assign("opm.his.com", time.Minute)
	if b == nil || b.Equal(a1) {
		t.Fatalf("不同名字撞到同一个假 IP: %v", b)
	}
	// 都在池子网段里，且不是网络地址/广播地址
	r := p.Range()
	for _, ip := range []net.IP{a1, b} {
		if !r.Contains(ip) {
			t.Errorf("%v 不在池子网段 %v 里", ip, r)
		}
	}
	if a1[3] == 0 || b[3] == 0 {
		t.Error("不该分配网络地址")
	}
}

// 过期后要能回收：TTL 到 → Sweep 归还 → 池子不涨。
func TestSweepReclaims(t *testing.T) {
	p := newTestPool(t, "198.19.0.0/24")
	cur := p.nowFn()
	a := p.Assign("a.his.com", 30*time.Second)
	b := p.Assign("b.his.com", 10*time.Minute)
	if a == nil || b == nil {
		t.Fatal("分配失败")
	}
	if used, _ := p.Stats(); used != 2 {
		t.Fatalf("用量 = %d，期望 2", used)
	}
	p.nowFn = func() time.Time { return cur.Add(31 * time.Second) }
	gone := p.Sweep()
	if len(gone) != 1 || gone[0] != "a.his.com" {
		t.Fatalf("应该只回收 a.his.com，得到 %v", gone)
	}
	if _, ok := p.NameFor(a); ok {
		t.Error("过期后不该还能反查出名字")
	}
	if _, ok := p.NameFor(b); !ok {
		t.Error("没过期的不该被回收")
	}
	// 被回收的地址应当优先复用（减少假 IP 漂移）
	c := p.Assign("c.his.com", time.Minute)
	if c == nil || !c.Equal(a) {
		t.Errorf("回收的地址应优先复用：得到 %v，期望 %v", c, a)
	}
}

// 续期：同一个名字在 TTL 内再被问到，过期时间往后推。
func TestAssignRenews(t *testing.T) {
	p := newTestPool(t, "198.19.0.0/24")
	cur := p.nowFn()
	ip := p.Assign("x.his.com", 30*time.Second)
	p.nowFn = func() time.Time { return cur.Add(20 * time.Second) }
	again := p.Assign("x.his.com", 30*time.Second)
	if !again.Equal(ip) {
		t.Fatalf("续期不该换 IP: %v vs %v", again, ip)
	}
	p.nowFn = func() time.Time { return cur.Add(45 * time.Second) } // 21 秒后（< 20+30）
	if _, ok := p.NameFor(ip); !ok {
		t.Error("续期后不该过期")
	}
}

// 池子满了必须返回 nil —— 调用方要据此**放行原查询**，不能乱答。
func TestPoolExhaustion(t *testing.T) {
	p := newTestPool(t, "198.19.0.0/28") // 16 个地址，去掉网络/广播 → 14 个可用
	var got []net.IP
	for i := 0; i < 14; i++ {
		ip := p.Assign(fmt.Sprintf("n%d.his.com", i), time.Minute)
		if ip == nil {
			t.Fatalf("第 %d 个就分配失败了（容量应该够）", i)
		}
		got = append(got, ip)
	}
	if c := p.Assign("overflow.his.com", time.Minute); c != nil {
		t.Errorf("池子满了应该返回 nil，得到 %v", c)
	}
	// 过期回收后又能分配
	p.nowFn = func() time.Time { return time.Now().Add(2 * time.Minute) }
	p.Sweep()
	if d := p.Assign("d", time.Minute); d == nil {
		t.Error("回收后应该又能分配")
	}
}

// 空名字不分配；nil IP 不反查。
func TestEdgeCases(t *testing.T) {
	p := newTestPool(t, "198.19.0.0/24")
	if ip := p.Assign("", time.Minute); ip != nil {
		t.Errorf("空名字不该分配: %v", ip)
	}
	if _, ok := p.NameFor(nil); ok {
		t.Error("nil IP 不该反查成功")
	}
	if _, ok := p.NameFor(net.ParseIP("2001:db8::1")); ok {
		t.Error("IPv6 不该反查成功")
	}
	if _, ok := p.NameFor(net.ParseIP("10.0.0.1")); ok {
		t.Error("池子外的地址不该反查成功")
	}
	if _, ok := p.IPFor("从没分配过"); ok {
		t.Error("没分配过的名字不该正查成功")
	}
}

// 段的选择：撞上 Clash 的 fake-ip 段必须**直接拒绝**（不然两个程序互相误判）。
func TestRangeGuards(t *testing.T) {
	bad := []string{
		"198.18.0.0/16",  // Clash/mihomo 默认 fake-ip 段
		"198.18.5.0/24",  // 落在它里面
		"10.0.0.0/8",     // 真实网络段（客户内网就是它）
		"172.30.0.0/16",  // 真实网络段（客户内网）
		"192.168.1.0/24", // 真实网络段（本机局域网）
		"127.0.0.0/24",   // 环回
		"169.254.0.0/24", // 链路本地（本机就有）
		"2001:db8::/64",  // IPv6
		"198.19.0.0/29",  // 太小（可用地址太少）
		"不是 CIDR",
	}
	for _, c := range bad {
		if _, err := NewPool(c); err == nil {
			t.Errorf("应该拒绝假 IP 段 %q", c)
		}
	}
	good := []string{"", "198.19.0.0/16", "198.19.7.0/24", "198.19.0.0/25", "240.0.0.0/24", "198.20.0.0/16"}
	for _, c := range good {
		if _, err := NewPool(c); err != nil {
			t.Errorf("%q 应该接受: %v", c, err)
		}
	}
	if _, err := NewPool(clashRange); err == nil {
		t.Error("Clash 的段必须被明确拒绝（错误信息要能指向改法）")
	} else if !contains(err.Error(), "Clash") {
		t.Errorf("拒绝理由要说清是 Clash 的段: %v", err)
	}
}

// 池子会在多个 goroutine 里被用（DNS 拦截协程 + 包处理协程），不能崩。
func TestConcurrent(t *testing.T) {
	p := newTestPool(t, "198.19.0.0/24")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				name := fmt.Sprintf("h%d-%d.his.com", i, j%10)
				ip := p.Assign(name, time.Minute)
				if ip == nil {
					continue
				}
				p.NameFor(ip)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if used, capa := p.Stats(); used > capa {
		t.Errorf("用量 %d 超过容量 %d", used, capa)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
