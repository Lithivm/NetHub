package engine

import (
	"net"
	"testing"
)

// 回归：假 IP 连接上，st.dst 必须始终是“应用连的那个假 IP”：
//   - rewriteInbound 用它做回包源地址，应用内核才认（否则连接会被 RST）；
//   - 它还被 Conns/recentTargets 在锁下读，改了就是数据竞争。
//
// 真实 IP 只存在 realDst，供拨号与展示。
func TestFakeIPConnKeepsAppAddressedDst(t *testing.T) {
	fake := net.ParseIP("198.19.0.7")
	real := net.ParseIP("10.20.30.40")

	st := &connState{dst: fake, dport: 443}
	st.realDst.Store(real)

	if !st.dst.Equal(fake) {
		t.Fatalf("st.dst 必须保持应用连的假 IP，得到 %v", st.dst)
	}
	if got := st.displayTarget(); !got.Equal(real) {
		t.Fatalf("展示/巡检应使用真实 IP，得到 %v", got)
	}

	// 未解析到真实 IP 时，展示回落到应用连的地址
	st2 := &connState{dst: net.ParseIP("10.0.0.9"), dport: 80}
	if got := st2.displayTarget(); !got.Equal(net.ParseIP("10.0.0.9")) {
		t.Fatalf("未解析时应回落 st.dst，得到 %v", got)
	}
}
