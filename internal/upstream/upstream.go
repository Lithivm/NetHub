// Package upstream 直接实现"到上游代理"的连接 —— 不再依赖外部 gost 进程。
//
// 背景：原来每条链是这样跑的
//
//	应用 → 我们的 relay → 本地 gost(SOCKS5, 127.0.0.1:1080) → TLS → 上游 SOCKS5 → 目标
//
// 其中 gost 只做了一件事：在 TLS 隧道里做一次 SOCKS5 认证 + CONNECT。
// 这件事 Go 标准库 + 一个带认证的 SOCKS5 客户端就能做，于是变成
//
//	应用 → 我们的 relay → TLS → 上游 SOCKS5 → 目标
//
// 好处：少一个外部依赖（不用配 gost.exe 路径、不会版本漂移）、少一个本地 SOCKS5 握手跳、
// 没有子进程要托管（不需要 Job Object 回收）、日志与超时都归我们控制。
//
// 支持的 URL 形式（与 gost 的写法兼容，好让旧配置直接能用）：
//
//	socks5+tls://host:port?auth=<base64(user:pass)>   ← 现网两个上游都是这种
//	socks5+tls://user:pass@host:port
//	socks5://[user:pass@]host:port
//	可加参数：secure=true 校验证书（默认不校，与 gost 默认行为一致）
package upstream

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"netproxy/internal/socks"
)

// Upstream 一条上游链路。
type Upstream struct {
	Raw   string // 原始 URL（含凭据，不要往日志里打）
	Addr  string // host:port
	TLS   bool
	Creds socks.Creds
	// Verify 是否校验上游证书。
	// 默认 false —— 与 gost 的 socks5+tls 默认行为一致（它不配 CA 时不校验）。
	// 想开启就在 URL 上加 ?secure=true。
	Verify bool
	// tlsServerName 校验用（Verify=false 时仅作 SNI）
	ServerName string
}

// Parse 解析上游 URL。
func Parse(raw string) (*Upstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("上游 URL 为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("解析上游 URL 失败: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if !strings.HasPrefix(scheme, "socks5") && !strings.HasPrefix(scheme, "socks") {
		return nil, fmt.Errorf("不支持的上游协议 %q（目前支持 socks5 / socks5+tls）", u.Scheme)
	}

	up := &Upstream{Raw: raw, TLS: strings.HasSuffix(scheme, "+tls")}

	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("上游地址必须是 host:port，当前 %q", u.Host)
	}
	up.Addr = net.JoinHostPort(host, port)
	up.ServerName = host

	// 凭据可以写在 userinfo，也可以写在 ?auth=<base64(user:pass)>（gost 的写法）
	if u.User != nil {
		up.Creds.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			up.Creds.Pass = p
		}
	}
	if a := u.Query().Get("auth"); a != "" {
		dec, err := base64.StdEncoding.DecodeString(a)
		if err != nil {
			// 有些写法不做 padding 补齐
			dec, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(a, "="))
		}
		if err != nil {
			return nil, fmt.Errorf("auth 参数不是合法的 base64(user:pass)")
		}
		s := string(dec)
		i := strings.Index(s, ":")
		if i < 0 {
			return nil, fmt.Errorf("auth 解出来后没有冒号，期望 user:pass")
		}
		up.Creds.User, up.Creds.Pass = s[:i], s[i+1:]
	}
	if q := u.Query(); q.Get("secure") == "true" {
		up.Verify = true
	}
	return up, nil
}

// String 只用来打日志：把凭据遮蔽掉。
func (u *Upstream) String() string {
	scheme := "socks5"
	if u.TLS {
		scheme = "socks5+tls"
	}
	auth := ""
	if u.Creds.User != "" || u.Creds.Pass != "" {
		auth = "（带凭据）"
	}
	return scheme + "://" + u.Addr + auth
}

// Dial 连到 targetIP:port（目标从我们内核拦截拿到的是 IP，不需要域名解析）。
func (u *Upstream) Dial(targetIP net.IP, targetPort uint16, timeout time.Duration) (net.Conn, error) {
	var conf *tls.Config
	if u.TLS {
		conf = &tls.Config{
			ServerName:         u.ServerName,
			InsecureSkipVerify: !u.Verify, //nolint:gosec // 默认与 gost 行为一致；要校验就加 ?secure=true
		}
	}
	return socks.DialTLS(u.Addr, u.Creds, conf, targetIP, targetPort, timeout)
}
