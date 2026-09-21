// Package dnssniff 从 DNS 报文里抠出「域名 → IP」。
//
// 为什么需要它：规则里写具体域名时，我们能在启动/刷新时主动解析；但写成通配
// （*.his.com）就不知道会解析出哪些 IP，而那些 IP 不在我们的内核过滤器里 ——
// 包根本到不了我们手上。所以只能"顺着应用自己的 DNS 应答"把名字学回来，
// 再把学到的 IP 塞进过滤器（见 engine 的 dnsWatch）。
//
// 这里只关心 IPv4：过滤器和整个引擎都是 IPv4 的（buildFilter 用的是
// ip.DstAddr），AAAA 学了也没用，直接忽略。
//
// 解析一律按"不可信字节"对待：越界、指针成环、超长名字都要能被挡住，
// 不能 panic，也不能卡住（跳转次数有上限）。
package dnssniff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Pair 一条「域名 → IP」。Name 已归一化（小写、无尾点）。
type Pair struct {
	Name string
	IP   string
	TTL  time.Duration // 应答里带的 TTL（0 表示没写）
}

// Result 一个报文解析出来的东西。查询报文也算"解析成功"，只是 IsResponse 为 false。
type Result struct {
	ID         uint16
	IsResponse bool
	RCode      int
	Truncated  bool
	Question   string // 问题段第一个名字（小写、无尾点）
	Pairs      []Pair
	// Answers 应答段里所有 A 记录（不做 CNAME 串联，调试用）
	Answers []Pair
	// Names 该 IP 关联到的所有名字：问题名 + CNAME 链上的每个名字
}

var (
	ErrShort   = errors.New("DNS 报文太短")
	ErrNotDNS  = errors.New("不是 DNS 报文")
	ErrBadName = errors.New("域名编码有问题")
)

const (
	maxJumps = 64  // 压缩指针最多跳这么多次（防成环）
	maxRR    = 512 // 最多处理这么多条记录（防构造报文放大）
	maxName  = 255 // 单条名字的字节上限
)

// Parse 解析一个 DNS 报文。畸形报文返回 error；正常报文（含 NXDOMAIN）返回 Result。
func Parse(msg []byte) (Result, error) {
	var r Result
	if len(msg) < 12 {
		return r, ErrShort
	}
	r.ID = binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	r.IsResponse = flags&0x8000 != 0
	r.RCode = int(flags & 0x000f)
	r.Truncated = flags&0x0200 != 0

	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	// 问题段：可能不止一个，但我们只认第一个（真实世界的查询只有一个）
	for i := 0; i < qd; i++ {
		name, next, err := parseName(msg, off)
		if err != nil {
			return r, err
		}
		if i == 0 {
			r.Question = name
		}
		if next+4 > len(msg) {
			return r, ErrShort
		}
		off = next + 4 // 跳过 QTYPE + QCLASS
	}
	if !r.IsResponse {
		return r, nil // 查询报文：名字拿到就够了
	}

	cname := map[string]string{} // 别名 → 真名
	ips := map[string][]string{} // 真名 → IP
	ttl := map[string]time.Duration{}

	n := an
	if n > maxRR {
		n = maxRR
	}
	for i := 0; i < n; i++ {
		name, next, err := parseName(msg, off)
		if err != nil {
			return r, err
		}
		if next+10 > len(msg) {
			return r, ErrShort
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		// class 在 next+2..next+4（IN=1）
		ttlSec := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rd := next + 10
		if rd+rdlen > len(msg) {
			return r, ErrShort
		}
		switch typ {
		case 1: // A
			if rdlen == 4 {
				ip := fmt.Sprintf("%d.%d.%d.%d", msg[rd], msg[rd+1], msg[rd+2], msg[rd+3])
				ips[name] = append(ips[name], ip)
				if _, ok := ttl[name]; !ok || time.Duration(ttlSec)*time.Second < ttl[name] {
					ttl[name] = time.Duration(ttlSec) * time.Second
				}
				r.Answers = append(r.Answers, Pair{Name: name, IP: ip, TTL: time.Duration(ttlSec) * time.Second})
			}
		case 5: // CNAME
			target, _, err := parseName(msg, rd)
			if err != nil {
				return r, err
			}
			cname[name] = target
		}
		off = rd + rdlen
	}

	// 把问题名沿 CNAME 链走到有 A 记录的名字，再把这几个名字**都**记成同一个 IP：
	// 应用可能用问题名，也可能用链上的别名，而匹配是按 IP 反查名字做的。
	if r.Question != "" {
		seen := map[string]bool{}
		cur := r.Question
		for hops := 0; hops < maxJumps; hops++ {
			if seen[cur] {
				break // 链成环
			}
			seen[cur] = true
			if list := ips[cur]; len(list) > 0 {
				for _, ip := range list {
					r.Pairs = append(r.Pairs, Pair{Name: cur, IP: ip, TTL: ttl[cur]})
					if cur != r.Question {
						r.Pairs = append(r.Pairs, Pair{Name: r.Question, IP: ip, TTL: ttl[cur]})
					}
				}
			}
			next, ok := cname[cur]
			if !ok {
				break
			}
			cur = next
		}
	}
	return r, nil
}

// Question 只取问题段的名字（看到出方向的查询时想知道"在解析谁"）。
func Question(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	name, _, err := parseName(msg, 12)
	if err != nil {
		return "", false
	}
	return name, true
}

// Query 一条查询的关键信息（DNS 接管要原样搬问题段，所以需要 QEnd）。
type Query struct {
	ID    uint16
	Name  string // 小写、无尾点
	Type  uint16 // 1=A、28=AAAA、12=PTR …
	Class uint16
	QEnd  int // 问题段结束位置（相对 DNS 报文头部），用于原样搬运
}

// ParseQuery 解析一条查询报文的头部与第一个问题。
//
// 只从**查询**报文取（QR=0）；应答或畸形报文返回 false —— 接管那边只关心
// “应用要解析什么”，拿应答当查询处理会回路。
func ParseQuery(msg []byte) (Query, bool) {
	var q Query
	if len(msg) < 12 {
		return q, false
	}
	if binary.BigEndian.Uint16(msg[2:4])&0x8000 != 0 {
		return q, false // 应答，不是查询
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return q, false // 只处理单问题查询（真实世界就是这样）
	}
	q.ID = binary.BigEndian.Uint16(msg[0:2])
	name, next, err := parseName(msg, 12)
	if err != nil || next+4 > len(msg) {
		return q, false
	}
	q.Name = name
	q.Type = binary.BigEndian.Uint16(msg[next : next+2])
	q.Class = binary.BigEndian.Uint16(msg[next+2 : next+4])
	q.QEnd = next + 4
	return q, true
}

// parseName 解析一个（可能带压缩指针的）域名，返回名字和"下一个字段的偏移"。
func parseName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	jumps := 0
	next := -1 // 第一次跳转前的偏移，就是调用方该继续读的位置
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, ErrShort
		}
		b := msg[off]
		switch {
		case b == 0:
			off++
			if next < 0 {
				next = off
			}
			name := strings.ToLower(strings.TrimSuffix(sb.String(), "."))
			if name == "" {
				return "", next, nil
			}
			return name, next, nil
		case b&0xc0 == 0xc0: // 压缩指针
			if off+2 > len(msg) {
				return "", 0, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > maxJumps {
				return "", 0, ErrBadName
			}
			off = ptr
		case b&0xc0 != 0:
			return "", 0, ErrBadName
		default:
			l := int(b)
			if off+1+l > len(msg) {
				return "", 0, ErrShort
			}
			sb.Write(msg[off+1 : off+1+l])
			sb.WriteByte('.')
			if sb.Len() > maxName {
				return "", 0, ErrBadName
			}
			off += 1 + l
		}
	}
}
