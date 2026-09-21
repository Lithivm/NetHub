package dnsmap

import (
	"net"
	"testing"
	"time"
)

// 通配域名的写法校验：只认 `*.域名`，其余要报错（错误信息要说清收到了什么）。
func TestWildcardSuffixValidation(t *testing.T) {
	ok := map[string]string{
		"*.his.com":      ".his.com",
		"*.HIS.com":      ".his.com",
		"*.his.com.":     ".his.com",
		"  *.his.com  ":  ".his.com",
		"*.corp":         ".corp",
		"*.a.b.c.d.com":  ".a.b.c.d.com",
		"*.his-internal": ".his-internal",
	}
	for in, want := range ok {
		got, err := WildcardSuffix(in)
		if err != nil {
			t.Errorf("%q 应该接受: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q → %q，期望 %q", in, got, want)
		}
	}

	bad := []string{
		"*",           // 只有星号
		"*.",          // 星号后面没东西
		"his.*.com",   // 星号写在中间
		"his.com*",    // 星号写在结尾
		"*his.com",    // 少了点
		"*.a..com",    // 空标签
		"*.a/b.com",   // 斜杠
		"*.a b.com",   // 空格
		"10.100.*.13", // 想拿它当 IP 通配用（那是另一条路，见 netx）
	}
	for _, in := range bad {
		if _, err := WildcardSuffix(in); err == nil {
			t.Errorf("%q 应该被拒绝", in)
		}
	}
}

// 匹配语义：不含裸域名自身、不匹配"尾巴长得像"的域名、多层也认、大小写不敏感。
func TestMatchWildcard(t *testing.T) {
	suffix, err := WildcardSuffix("*.his.com")
	if err != nil {
		t.Fatal(err)
	}
	yes := []string{"a.his.com", "a.b.his.com", "main.his.com", "MAIN.HIS.COM", "a.his.com.",
		// 去掉尾点后就是 his.com 的子域，命中是对的（别被“看起来像父域名”骗了）
		"his.com.his.com."}
	for _, h := range yes {
		if !MatchWildcard(suffix, h) {
			t.Errorf("%q 应该命中 *.his.com", h)
		}
	}
	no := []string{
		"his.com",        // 裸域名自身
		"xhis.com",       // 前缀不是点
		"a.his.com.evil", // 尾巴对不上
		"b.a.hisXcom",    // 相似但不同
		"evil.com",       // 完全无关
		"",               // 空
		"a.his.com.cn",   // 更长的后缀
	}
	for _, h := range no {
		if MatchWildcard(suffix, h) {
			t.Errorf("%q 不该命中 *.his.com", h)
		}
	}
	if MatchWildcard("", "a.his.com") {
		t.Error("空后缀不该命中任何东西")
	}
}

// 观测到的 DNS 带真实 TTL：TTL 到了要能被 Expired 列出来（过滤器要能摘掉）。
func TestExpiredUsesRealTTL(t *testing.T) {
	m := New()
	now := time.Now()
	m.nowFunc = func() time.Time { return now }

	m.SetWithTTL("a.his.com", []string{"10.0.0.1"}, PrioObserved, 30*time.Second)
	m.SetWithTTL("b.his.com", []string{"10.0.0.2"}, PrioObserved, 10*time.Minute)

	if got := m.Expired(); len(got) != 0 {
		t.Fatalf("刚写进去的不该过期，得到 %v", got)
	}
	now = now.Add(31 * time.Second)
	got := m.Expired()
	if len(got) != 1 || got[0] != "a.his.com" {
		t.Fatalf("TTL 30 秒的应该过期，得到 %v", got)
	}
	m.Remove("a.his.com")
	if names := m.NamesFor(net.ParseIP("10.0.0.1")); len(names) != 0 {
		t.Errorf("移除后反查索引要一起清干净，得到 %v", names)
	}
	if st := m.Status(); len(st) != 1 || st[0].Host != "b.his.com" {
		t.Errorf("移除后只剩 b.his.com，得到 %+v", st)
	}

	// 没带 TTL 的（规则解析）用默认 TTL，不该被 TTL 30 秒那条带崩
	m.Set("c.his.com", []string{"10.0.0.3"}, PrioRule)
	now = now.Add(time.Minute)
	if got := m.Expired(); len(got) != 0 {
		t.Errorf("规则来源的不该出现在 Expired 里（由引擎定期重解析），得到 %v", got)
	}
}

// 优先级只升不降：观察到的 DNS 不能把规则里的名字/结果冲掉。
func TestPrioNeverDowngrades(t *testing.T) {
	m := New()
	m.Set("main.his.com", []string{"172.30.4.217"}, PrioRule)
	m.SetWithTTL("main.his.com", []string{"6.6.6.6"}, PrioObserved, time.Minute)

	if ips := m.IPsFor("main.his.com"); len(ips) != 1 || ips[0] != "172.30.4.217" {
		t.Errorf("低优先级来源覆盖了高优先级的解析结果: %v", ips)
	}
	m.MarkFailedPrio("main.his.com", "no such host", PrioObserved)
	if st := m.Status(); len(st) != 1 || st[0].Failed {
		t.Errorf("低优先级来源把成功的解析结果标成失败: %+v", st)
	}

	// 反过来：规则重新解析成功后允许覆盖
	m.Set("main.his.com", []string{"172.30.4.217", "172.30.4.218"}, PrioRule)
	if ips := m.IPsFor("main.his.com"); len(ips) != 2 {
		t.Errorf("同级应该覆盖（规则刷新），得到 %v", ips)
	}
}

// 一个 IP 多个名字时，NameFor 要给优先级最高的那个；观察来的同名 IP 不该顶掉规则名字。
func TestNamesForOneIP(t *testing.T) {
	m := New()
	m.Set("main.his.com", []string{"10.1.1.1"}, PrioRule)
	m.SetWithTTL("cdn.his.com", []string{"10.1.1.1"}, PrioObserved, time.Minute)
	m.SetWithTTL("www.his.com", []string{"10.1.1.1"}, PrioObserved, time.Minute)

	names := m.NamesFor(net.ParseIP("10.1.1.1"))
	if len(names) != 3 {
		t.Fatalf("三个名字都要能看到（通配匹配靠它），得到 %v", names)
	}
	if name, _ := m.NameFor(net.ParseIP("10.1.1.1")); name != "main.his.com" {
		t.Errorf("NameFor 应返回优先级最高的 main.his.com，得到 %q", name)
	}
	if got := m.NamesFor(net.ParseIP("10.9.9.9")); got != nil {
		t.Errorf("没关联的 IP 应该返回空，得到 %v", got)
	}
	if got := m.NamesFor(nil); got != nil {
		t.Errorf("nil IP 应该返回空，得到 %v", got)
	}
}
