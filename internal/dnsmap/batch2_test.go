package dnsmap

import (
	"fmt"
	"testing"
	"time"
)

// 回归：Resolve 解析失败时记的失败项要用**传进来的来源优先级**，
// 不能硬编码 PrioRule —— 否则观测来源（PrioObserved）之后写不进来，规则永远“解析不到”。
func TestResolveFailureKeepsSourcePriority(t *testing.T) {
	m := NewWithLookup(func(string) ([]string, error) {
		return nil, fmt.Errorf("boom")
	})
	if _, err := m.Resolve("x.his.com", PrioObserved); err == nil {
		t.Fatal("解析器报错时 Resolve 应返回错误")
	}
	// 观测来源应当能覆盖这条失败记录
	m.SetWithTTL("x.his.com", []string{"1.2.3.4"}, PrioObserved, time.Minute)
	if ips := m.IPsFor("x.his.com"); len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("观测写入被失败记录挡死了: %v", ips)
	}
}
