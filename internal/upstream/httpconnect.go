// HTTP / HTTPS 代理（CONNECT 隧道）。
//
// 为什么值得支持：这是现实里最常见的一类企业代理 —— 一个标准的 HTTP 代理，
// 用 CONNECT 建立任意目标 TCP 隧道。gost 的默认 `-F` 协议就是 http。
//
// 认证用 Basic（Proxy-Authorization），凭据同样可以写 userinfo 或 ?auth=<b64>。
package upstream

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// dialHTTPConnect 经 HTTP 代理连到 targetIP:port。
func dialHTTPConnect(u *Upstream, targetIP net.IP, targetPort uint16, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	raw, err := net.DialTimeout("tcp", u.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("连代理失败: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	var conn net.Conn = raw
	if u.TLS {
		tc := tls.Client(raw, u.tlsConfig())
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("代理的 TLS 握手失败: %w", err)
		}
		conn = tc
	}

	// CONNECT 的目标一律用 IP：我们的引擎拿到的就是内网 IP，不需要代理解析域名
	target := net.JoinHostPort(targetIP.String(), fmt.Sprint(targetPort))
	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&sb, "Host: %s\r\n", target)
	fmt.Fprintf(&sb, "Proxy-Connection: Keep-Alive\r\n")
	if u.Creds.User != "" || u.Creds.Pass != "" {
		token := base64.StdEncoding.EncodeToString([]byte(u.Creds.User + ":" + u.Creds.Pass))
		fmt.Fprintf(&sb, "Proxy-Authorization: Basic %s\r\n", token)
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT 请求写入失败: %w", err)
	}

	// 只读状态行；2xx 表示隧道已建立
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读 CONNECT 响应失败: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "HTTP/") {
		conn.Close()
		return nil, fmt.Errorf("代理返回的不是 HTTP 响应: %q", truncate(line, 60))
	}
	fields := strings.SplitN(line, " ", 3)
	if len(fields) < 2 {
		conn.Close()
		return nil, fmt.Errorf("CONNECT 响应格式异常: %q", line)
	}
	code := fields[1]
	if !strings.HasPrefix(code, "2") {
		// 把状态码带回去；常见的 407 = 需要认证
		hint := ""
		if code == "407" {
			hint = "（代理要求认证，检查上游 URL 里的用户名/口令）"
		} else if code == "403" {
			hint = "（代理拒绝该目标）"
		}
		conn.Close()
		return nil, fmt.Errorf("CONNECT 被代理拒绝: %s%s", line, hint)
	}
	// 读完响应头（到空行），否则残留的头部字节会被当成隧道数据
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("读 CONNECT 响应头失败: %w", err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// tlsConfig 统一构造 TLS 配置（socks5+tls 与 https 共用）。
func (u *Upstream) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         u.ServerName,
		InsecureSkipVerify: !u.Verify, //nolint:gosec // 默认与 gost 行为一致；要校验就加 ?secure=true
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
