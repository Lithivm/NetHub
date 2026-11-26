package config

import (
	"fmt"
	"net"

	"nethub/internal/dnsmap"
	"nethub/internal/netx"
	"strconv"
	"strings"
	"unicode"
)

func NormalizeTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("不能为空")
	}
	// IP 区间（10.1.1.1-10.1.1.255）会展开成**多条** CIDR —— 那是列表级的写法，
	// 这个入口只对应"一个写法一个目标"（见 NormalizeTargetExpr）。
	// 报一句能照着改的提示，别甩一句没有信息量的"解析失败"。
	if netx.IsIPRange(s) {
		return "", fmt.Errorf("%q 是 IP 区间 —— 区间展开后是多条网段，请填在规则的目标框里"+
			"（那里支持一次填多个目标）；单个目标请写 CIDR（如 10.1.1.0/24）", s)
	}
	// IP 通配（Proxifier 的写法：198.51.100.* = 一整段）→ 展开成 CIDR
	if strings.HasSuffix(s, ".*") {
		cidr, err := ipWildcardToCIDR(s)
		if err != nil {
			return "", err
		}
		s = cidr
	}
	// 带 * 的都先当通配域名校验（报错最具体：哪个字符不行、为什么不给过），
	// 比后面的 IP 提示更贴切。
	if strings.Contains(s, "*") && isHostname(s) {
		pattern, err := dnsmap.WildcardPattern(s)
		if err != nil {
			return "", err
		}
		// 纯数字+点的写法（如 198.51.100.*）其实是 IP 通配，更推荐用那个：
		// 它会被折成 CIDR、在 IP 层匹配，不依赖任何解析。
		if isAllDigits(strings.ReplaceAll(pattern, "*", "")) {
			return "", fmt.Errorf("%q 看起来是 IP 通配 —— IP 请写 198.51.100.*（整段）或 CIDR；"+
				"域名通配用于主机名（如 *.example.com、db-*.example.com）", s)
		}
		return pattern, nil
	}
	// 剩下 * 且不是域名（如 10.*.100.5）→ 直接说清改写方式，
	// 别拖到最后报一句没有信息量的“解析失败”。
	if strings.Contains(s, "*") && !isHostname(s) {
		return "", fmt.Errorf("这种写法猜不出范围 —— 末尾一段才能用 *（如 198.51.100.*）；" +
			"其他情况请写 CIDR（如 10.100.0.0/16）")
	}
	if !strings.Contains(s, "/") && !isHostname(s) {
		s += "/32"
	} else if isHostname(s) {
		// 统一去掉尾点：名字表（dnsmap）的 key 都是不带尾点的，
		// 否则 "main.example.com." 这条规则会静默地永不匹配（也查不出原因）。
		s = strings.TrimSuffix(strings.ToLower(s), ".")
		if !validHostname(s) {
			return "", fmt.Errorf("不是合法的域名")
		}
		return s, nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("解析失败")
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("只支持 IPv4")
	}
	// 归一化：让 10.0.1.5/24 这类写法变成 10.0.1.0/24
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return "", fmt.Errorf("只支持 IPv4")
	}
	return fmt.Sprintf("%s/%d", n.IP.String(), ones), nil
}

// NormalizeTargetExpr 归一化一个目标写法 —— 它可能对应**多个**目标：IP 区间会展开成一批 CIDR。
//
// 为什么要多这一层：区间是列表级的写法（一条规则的目标框能一次填多条），而配置层的不变量是
// "目标是 CIDR"，所以展开必须发生在**写进配置之前**。其余入口（Validate / 规则归一化 /
// 界面里的多目标输入）统一走这里，就不必各自记得"还有区间这回事"。
func NormalizeTargetExpr(s string) ([]string, error) {
	if netx.IsIPRange(s) {
		return netx.RangeToCIDRs(s)
	}
	n, err := NormalizeTarget(s)
	if err != nil {
		// 形状像区间但写坏了（10.1.1.0-10.1.1.300）：用区间的报错——它会指明是**哪一侧**
		// 不对，比甩一句"解析失败"有用得多。
		// 只在不含字母时走这条：带字母的 main-1.example.com 是**域名**，不能拿区间去报错。
		if hasRangeDash(s) && !strings.ContainsFunc(s, unicode.IsLetter) {
			if _, rerr := netx.RangeToCIDRs(s); rerr != nil {
				return nil, rerr
			}
		}
		return nil, err
	}
	return []string{n}, nil
}

// hasRangeDash 字符串里有横线（三种写法任一）。
func hasRangeDash(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return netx.IsRangeDash(string(r)) })
}

// isHostname 目标写法是不是域名（而不是 IP/CIDR）。
func isHostname(s string) bool {
	if s == "" || strings.Contains(s, "/") || net.ParseIP(s) != nil {
		return false
	}
	return strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// isAllDigits 字符串是否只由数字和点组成（用来看“通配域名后面跟的其实是 IP”）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

// validHostname 粗校域名（不追求 RFC 完备：拦下空格/下划线以外明显不对的写法）。
func validHostname(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
			if r == '-' && (i == 0 || s[i-1] == '.') {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ipWildcardToCIDR 把 198.51.100.* 这种写法展开成整段 CIDR。
//
// 为什么单独支持它：这是 Proxifier 的写法（从它那儿搬过来的规则与工单里到处都是），
// 语义就是“最后一段随便填”= 一整段网段。不展开的话用户会以为我们连“通配”都不支持。
// 只允许**末尾一段**是 *（198.51.100.* ✓）；中间带 * 的（10.*.100.5）猜不出范围，不要猜。
// ipWildcardToCIDR 已挪到 internal/netx（规则包也要用，避免两份实现）。
func ipWildcardToCIDR(s string) (string, error) { return netx.WildcardToCIDR(s) }

// targetSep 判断多目标输入里的分隔符：换行、Tab、空格等所有空白，
// 外加中英文逗号、分号、顿号。用户从工单/表格里粘一串 IP 是最常见的用法。
func targetSep(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case ',', '，', ';', '；', '、':
		return true
	}
	return false
}

// NormalizeTargets 把一次手输/粘贴的多目标文本解析成目标列表，
// 供"一条规则填多个目标"用。分隔符：所有空白 + 中英文逗号/分号/顿号。
//
//	out  归一化后的 CIDR，保持输入顺序，组内去重（IP 区间会展开成多条）
//	dup  被去掉的重复项（归一化形式，供界面如实告知）
//	err  第一个非法目标 —— 整条规则都不落地，不留半生效状态
func NormalizeTargets(raw string) (out, dup []string, err error) {
	seen := map[string]bool{}
	for _, f := range mergeSpacedRanges(strings.FieldsFunc(raw, targetSep)) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if netx.IsRangeDash(f) {
			return nil, nil, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（这是一根单独的横线："+
				"区间要写成 10.1.1.1-10.1.1.255，两端都必须是 IP）", f)
		}
		ns, nerr := NormalizeTargetExpr(f)
		if nerr != nil {
			return nil, nil, fmt.Errorf("目标 %q 不是合法 IP 或 CIDR（%v）", f, nerr)
		}
		for _, n := range ns {
			key := strings.ToLower(n)
			if seen[key] {
				dup = append(dup, n)
				continue
			}
			seen[key] = true
			out = append(out, n)
		}
	}
	return out, dup, nil
}

// mergeSpacedRanges 把"被空白拆散的区间"拼回去：
// ["10.1.1.1", "-", "10.1.1.255"] → ["10.1.1.1-10.1.1.255"]。
//
// 为什么要做：区间是从工单/文档里粘过来的，写的人常在横线两边留空格（文档还会把它排成
// en dash）。而多目标输入的**分隔符就是空白** —— 不拼回去，一个区间会被拆成三个目标，
// 报一句让人摸不着头脑的错（"目标 - 不是合法 IP"）。
//
// 只在**两侧都是 IPv4 字面量**时才拼：否则 "a.com - b.com" 这种会被拼成一个怪域名。
func mergeSpacedRanges(fields []string) []string {
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		if netx.IsRangeDash(fields[i]) && len(out) > 0 && i+1 < len(fields) &&
			netx.IsIPv4Literal(out[len(out)-1]) && netx.IsIPv4Literal(fields[i+1]) {
			out[len(out)-1] += "-" + fields[i+1]
			i++
			continue
		}
		out = append(out, fields[i])
	}
	return out
}

// PortText 端口集合的人话描述：空 = 全部端口。
func PortText(ports []string) string {
	if len(ports) == 0 {
		return "全部端口"
	}
	return strings.Join(ports, ",")
}

// NormalizePort 归一化单个端口或端口区间：443 / 8000-9000（也接受 8000~9000）。
// 区间写反了自动换过来；只支持 1-65535。
func NormalizePort(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("不能为空")
	}
	lo, hi, hasSep := s, "", false
	if i := strings.IndexAny(s, "-~"); i >= 0 {
		lo, hi, hasSep = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
	}
	a, err := parsePortNum(lo)
	if err != nil {
		return "", err
	}
	if !hasSep {
		return strconv.Itoa(a), nil
	}
	b, err := parsePortNum(hi)
	if err != nil {
		return "", err
	}
	if a > b {
		a, b = b, a
	}
	if a == b {
		return strconv.Itoa(a), nil
	}
	return fmt.Sprintf("%d-%d", a, b), nil
}

func parsePortNum(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("不是数字")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("端口要在 1-65535")
	}
	return n, nil
}

// NormalizePorts 把一次手输/粘贴的多端口文本解析成端口列表（留空 = nil = 任意端口）。
// 分隔符与目标一致：所有空白 + 中英文逗号/分号/顿号。
func NormalizePorts(raw string) (out, dup []string, err error) {
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, targetSep) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, nerr := NormalizePort(f)
		if nerr != nil {
			return nil, nil, fmt.Errorf("端口 %q 不合法（%v）", f, nerr)
		}
		if seen[n] {
			dup = append(dup, n)
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, dup, nil
}

// portSpan 归一化后的端口区间（供“是否被覆盖”判断用）。
type portSpan struct{ lo, hi int }

func portSpans(ports []string) []portSpan {
	out := make([]portSpan, 0, len(ports))
	for _, p := range ports {
		lo, hi := p, ""
		if i := strings.IndexByte(p, '-'); i >= 0 {
			lo, hi = p[:i], p[i+1:]
		}
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if hi != "" {
			if v, err := strconv.Atoi(hi); err == nil {
				b = v
			}
		}
		out = append(out, portSpan{a, b})
	}
	return out
}

// PortsCover 判断端口集合 a 是否覆盖 b（a 留空 = 任意端口，覆盖一切）。
// 用来判断“这条规则是不是永远不会生效”：目标相同、端口又被上面全覆盖。
func PortsCover(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	as := portSpans(a)
	for _, br := range portSpans(b) {
		covered := false
		for _, ar := range as {
			if ar.lo <= br.lo && br.hi <= ar.hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Patrol 业务目标巡检：只探“最近真的被访问过”的内网目标（经隧道连一次、不发数据）。
