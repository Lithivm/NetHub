// HTTP / HTTPS 代理（CONNECT 隧道）。
//
// 为什么值得支持：这是现实里最常见的一类企业代理 —— 一个标准的 HTTP 代理，
// 用 CONNECT 建立任意目标 TCP 隧道。gost 的默认 `-F` 协议就是 http。
//
// 认证用 Basic（Proxy-Authorization），凭据同样可以写 userinfo 或 ?auth=<b64>。
package upstream

import (
	"bytes"
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
	conn, err := prepareHTTPConnect(u, timeout)
	if err != nil {
		return nil, err
	}
	if err := connectHTTPConnect(u, conn, targetIP, targetPort, timeout); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// prepareHTTPConnect 连上代理（+可选 TLS）；HTTP 代理的认证在 CONNECT 里发，
// 所以预备阶段就是 TCP+TLS。
func prepareHTTPConnect(u *Upstream, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	raw, err := net.DialTimeout("tcp", u.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("连代理失败: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	if !u.TLS {
		return raw, nil
	}
	tc := tls.Client(raw, u.tlsConfig())
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("代理的 TLS 握手失败: %w", err)
	}
	return tc, nil
}

// connectHTTPConnect 在已预备好的连接上发 CONNECT 并读应答（2xx = 隧道建立）。
// 目标用 IP（引擎拿到的是内网 IP）。要把域名交给代理解析时用 sendConnectRequest。
func connectHTTPConnect(u *Upstream, conn net.Conn, targetIP net.IP, targetPort uint16, timeout time.Duration) error {
	target := net.JoinHostPort(targetIP.String(), fmt.Sprint(targetPort))
	return sendConnectRequest(u, conn, target, timeout)
}

// sendConnectRequest 发一个 CONNECT target（可以是 IP:port，也可以是域名:port）。
func sendConnectRequest(u *Upstream, conn net.Conn, target string, timeout time.Duration) error {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
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
		return fmt.Errorf("CONNECT 请求写入失败: %w", err)
	}

	// 只读状态行；2xx 表示隧道已建立。
	//
	// 必须**只读到头部结束、不多读一个字节**：代理完全可能把 `200 ...\r\n\r\n`
	// 与目标先发来的数据放在同一段里；用 bufio.Reader 会把这些数据一并吞进它自己的
	// 缓冲区然后随缓冲丢弃，表现为“CONNECT 成功，但业务首包永远收不到”。
	head, err := readResponseHeader(conn, 8192)
	if err != nil {
		return fmt.Errorf("读 CONNECT 响应失败: %w", err)
	}
	line := string(head)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "HTTP/") {
		return fmt.Errorf("代理返回的不是 HTTP 响应: %q", truncate(line, 60))
	}
	fields := strings.SplitN(line, " ", 3)
	if len(fields) < 2 {
		return fmt.Errorf("CONNECT 响应格式异常: %q", line)
	}
	code := fields[1]
	if code == "407" {
		return &ProxyAuthError{Line: line}
	}
	if !strings.HasPrefix(code, "2") {
		// 把状态码带回去
		hint := ""
		if code == "403" {
			hint = "（代理拒绝该目标）"
		}
		return fmt.Errorf("CONNECT 被代理拒绝: %s%s", line, hint)
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

// readResponseHeader 逐字节读到 HTTP 响应头结束（\r\n\r\n）。
//
// 为什么逐字节：net.Conn 没有 peek，任何带缓冲的读都可能把“隧道里的第一个数据字节”
// 提前吃掉。响应头只有几百字节，代价可以忽略（TLS 连接内部有 record 缓冲，不会增加系统调用）。
func readResponseHeader(conn net.Conn, max int) ([]byte, error) {
	if max <= 0 {
		max = 8192
	}
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	end := []byte("\r\n\r\n")
	for len(buf) < max {
		n, err := conn.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if len(buf) >= 4 && bytes.Equal(buf[len(buf)-4:], end) {
				return buf, nil
			}
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, fmt.Errorf("响应头超过 %d 字节仍未结束", max)
}

// ProxyAuthError 代理明确拒绝了认证（HTTP 407）。
//
// 单独一个类型是为了让探活能区分两种“CONNECT 失败”：
//   - 认证失败（407）→ 链路真的不可用，AuthOK 必须为 false；
//   - 出口出不了公网（其他错误）→ 很多客户就是这样，不能因此报“链路坏”。
// 旧版 ProbeAuth 把两者混为一谈，HTTP 代理口令错了也报“可用”。
type ProxyAuthError struct{ Line string }

func (e *ProxyAuthError) Error() string {
	return "CONNECT 认证失败（407）: " + e.Line
}

// sessionCache TLS 会话复用（A13）：同一上游的下一条连接可以跳过完整握手
// （TLS 1.3 会话恢复 = 1 RTT、跳过证书与密钥交换），实测能省一个 RTT（~56ms）。
//
// 进程内共享一份即可：缓存是按 ServerName 建索引的，不同上游互不影响。
// 注意上游默认不校验证书（Verify=false）时，会话恢复依然有效、且不像
// 重新握手那样每次做一次非对称运算。
var sessionCache = tls.NewLRUClientSessionCache(64)

// tlsConfig 统一构造 TLS 配置（socks5+tls 与 https 共用）。
func (u *Upstream) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         u.ServerName,
		InsecureSkipVerify: !u.Verify,    //nolint:gosec // 默认与 gost 行为一致；要校验就加 ?secure=true
		ClientSessionCache: sessionCache, // 会话复用：重建连接少一个 RTT（见上）
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// dialHTTPConnectHost 与 dialHTTPConnect 相同，但 CONNECT 的目标写成**域名**，
// 由 HTTP 代理自己去解析（= "域名交给上游"）。
func dialHTTPConnectHost(u *Upstream, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	conn, err := prepareHTTPConnect(u, timeout)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(host, fmt.Sprint(port))
	if err := sendConnectRequest(u, conn, target, timeout); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
