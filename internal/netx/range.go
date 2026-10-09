package netx

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// IP 区间（Proxifier 的写法：10.1.1.1-10.1.1.255）展开成一批 CIDR。
//
// 为什么放在这儿：和 IP 通配（10.100.100.*）是同一类东西 —— 都是"用户从别处搬过来的
// 写法，我们折成 CIDR"。折成 CIDR 之后，配置、规则、内核过滤器都只需要认识一种东西，
// 不必让下游每个消费方都学会区间。
//
// 为什么不让下游认区间：区间在 rules 里本来就是 Range{First,Last}，看着更省，但配置层的
// **不变量是"目标是 CIDR"** —— 重叠检测、界面上的"已覆盖 N 个 IP"、过滤器原文全是按这个
// 不变量写的。为了一种写法去动那个不变量，代价远大于展开。
//
// 展开条数不失控：**一个连续区间最多 64 条 CIDR**（首尾各自最多 32 条），和用户手工粘
// 64 行 CIDR 是一回事，所以这里不设上限。
//
// 展开是**精确覆盖**，不做"凑整段"：10.1.1.1-10.1.1.255 会展开成 8 条，而不是
// 顺手并成 10.1.1.0/24。凑整会把用户**没写**的地址（10.1.1.0）也吞进来 ——
// 那不是写成 /24 那种"整段"的意图，而是把别人的流量抢过来接管，方向错了。

// rangeDashes 认这三种横线：ASCII、en dash、em dash。
//
// 为什么不止 ASCII：区间是从工单、Word 文档、Proxifier 自己的文档里粘过来的，
// 那些地方常被自动排版成 en dash（–）。只认 ASCII 的话，用户看着"一模一样"的写法就是不生效。
var rangeDashes = []rune{'-', '–', '—'}

// IsRangeDash 这个 token 是不是单独一根横线（"10.1.1.1 - 10.1.1.255" 粘进来会被
// 空白拆成三段，中间那段的形状就是它）。
func IsRangeDash(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isRangeDash(r) {
			return false
		}
	}
	return true
}

// IsIPv4Literal 是不是不带掩码的 IPv4 字面量（10.1.1.1）。
func IsIPv4Literal(s string) bool { return parseIPv4(strings.TrimSpace(s)).IsValid() }

// IsIPRange 判断是不是 "10.1.1.1-10.1.1.255" 这种 IP 区间写法（横线两侧容许空白）。
//
// 只认**两侧都是 IPv4 字面量**的形式。域名里本来就允许横线（main-1.his.com），
// 光看有没有横线就当区间，会把域名判成非法目标 —— 那是个很阴的错误。
func IsIPRange(s string) bool {
	lo, hi, ok := splitRange(s)
	if !ok {
		return false
	}
	return parseIPv4(lo).IsValid() && parseIPv4(hi).IsValid()
}

// RangeToCIDRs 把 IP 区间展开成一组 CIDR（最少条数），如
// 10.1.1.1-10.1.1.255 → 8 条，恰好覆盖 1~255（不含 .0）。
//
// 两端写反了自动换过来（和端口区间 8000-9000 / 9000-8000 的处理一致）。
func RangeToCIDRs(s string) ([]string, error) {
	lo, hi, ok := splitRange(s)
	if !ok {
		return nil, fmt.Errorf("%q 不是 IP 区间（要写成 起始IP-结束IP，如 10.1.1.1-10.1.1.255）", s)
	}
	a, b := parseIPv4(lo), parseIPv4(hi)
	if !a.IsValid() || !b.IsValid() {
		// 单独说清是哪一侧坏了：一侧是域名的写法（main-1.his.com）最容易被误当成区间
		bad := lo
		if a.IsValid() {
			bad = hi
		}
		return nil, fmt.Errorf("%q 不是合法的 IPv4 地址（区间两端都必须是 IPv4 地址）", bad)
	}

	first, last := beUint32(a.As4()), beUint32(b.As4())
	if first > last {
		first, last = last, first
	}

	out := make([]string, 0, 4)
	for {
		// 这一块的宽度受两个约束：起点对齐（低位零越多块越大）、不超过剩余量。
		size := uint64(1) << uint(alignBits(first))
		span := uint64(last) - uint64(first) + 1
		for size > span {
			size >>= 1
		}
		out = append(out, fmt.Sprintf("%s/%d", u32ToIPv4(first), 32-bits.TrailingZeros64(size)))
		if size >= span {
			break
		}
		first += uint32(size)
	}
	return out, nil
}

// splitRange 拆出区间两端；形状不对（缺一侧、多余横线）就返回 false。
//
// IPv4 字面量里不会有横线，所以正常形状只有一根；多出来的（1-2-3）一律不当区间，
// 让它落到后面的常规校验去报错。
func splitRange(s string) (lo, hi string, ok bool) {
	i := strings.IndexFunc(s, isRangeDash)
	if i < 0 {
		return "", "", false
	}
	_, w := utf8.DecodeRuneInString(s[i:]) // 横线本身占几个字节（en/em dash 是三字节）
	lo, hi = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+w:])
	if lo == "" || hi == "" || strings.ContainsFunc(lo+hi, isRangeDash) {
		return "", "", false
	}
	return lo, hi, true
}

func isRangeDash(r rune) bool {
	for _, d := range rangeDashes {
		if r == d {
			return true
		}
	}
	return false
}

// parseIPv4 解析成 IPv4；带掩码的（10.0.0.0/24）与 IPv6 都不算。
func parseIPv4(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}
	}
	return a
}

// alignBits 起点低位连零的个数（0.0.0.0 视作 32 —— 整段对齐，可以是一整个 /0）。
func alignBits(v uint32) int {
	if v == 0 {
		return 32
	}
	return bits.TrailingZeros32(v)
}

func beUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
