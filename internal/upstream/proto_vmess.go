package upstream

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nethub/internal/vmess"
)

// VMess 上游（AEAD 头，alterId 必须 0 / 不支持 legacy）。
//
// URL 两种写法：
//
//	vmess://<base64(json)>                     ← 分享链接（"添加节点"粘的就是这个）
//	vmess://<uuid>@host:port?type=ws&path=/    ← 我们自己的写法（与 vless 形似）
//
// 分享链接的 json 字段：
//
//	{"v":"2","ps":"名字","add":"host","port":"443","id":"uuid","aid":"0","scy":"auto",
//	 "net":"ws","host":"","path":"/","tls":"tls","sni":""}
//
// **aid 非 0 直接拒**：xray 已经删掉了 LEGACY 类型，AEAD 下 alterId 没有意义（必须 0）。
// 拒掉比"看起来连上了但会被服务端按 legacy 解"强。
//
// 加解密细节在 internal/vmess（对着 xray 源码核过），这里只做 URL 与注册。

func init() {
	register("vmess", func(u *Upstream) Proxy { return &vmessProxy{u} })
	registerURLSetup("vmess", vmessSetup)
}

// vmessShare 分享链接里的字段（只取我们用的那几个）。
type vmessShare struct {
	PS   string `json:"ps"`   // 名字（不用）
	Add  string `json:"add"`  // 主机
	Port any    `json:"port"` // 端口：**有的客户端写字符串有的写数字**
	ID   string `json:"id"`   // UUID
	Aid  any    `json:"aid"`  // alterId
	Net  string `json:"net"`  // tcp / ws / grpc / kcp…
	Host string `json:"host"` // ws 的 Host 头
	Path string `json:"path"` // ws 的 path
	TLS  string `json:"tls"`  // tls / 空
	SNI  string `json:"sni"`
	Scy  string `json:"scy"` // auto / aes-128-gcm / chacha20-poly1305 / none
}

// vmessSetup 解析期把分享链接的 json 展开成我们的字段，并校验。
func vmessSetup(u *Upstream, q url.Values) error {
	scy := q.Get("scy")
	// ① base64(json) 那一支：Raw 里 `vmess://` 后面那一大坨（url.Parse 会把整段当 Host，
	//    所以只能自己从原串里取 —— 这是分享链接最容易解析错的地方）。
	if payload := vmessSharePayload(u.Raw); payload != "" {
		got, err := applyVmessShare(u, payload)
		if err != nil {
			return err
		}
		if scy == "" {
			scy = got
		}
	}
	// ② 查询参数那一支（和我们别的协议一致）
	if err := applyXrayParams(u, q); err != nil {
		return err
	}

	id := firstNonEmpty(u.Creds.User, u.Creds.Pass)
	uid, err := parseUUID(id)
	if err != nil {
		return fmt.Errorf("vmess 的 id 应该是 UUID：%w", err)
	}
	u.UserID = uid

	// scy：我们只发 AES-128-GCM（0x03）。服务端按请求头里写的来解，所以不必与服务端配置一致；
	// 但用户写了个我们不实现的加密方式时要说清楚，别让他以为生效了。
	switch strings.ToLower(strings.TrimSpace(scy)) {
	case "", "auto", "aes-128-gcm", "aes128gcm":
	default:
		return fmt.Errorf("vmess 的加密方式 %q 我们不发（只发 aes-128-gcm）—— "+
			"分享链接里通常写 auto，保持 auto 即可", scy)
	}
	return nil
}

// vmessSharePayload 从 `vmess://xxx` 里取出 xxx（去掉可能的 #备注 与 ?查询）。
func vmessSharePayload(raw string) string {
	s := strings.TrimSpace(raw)
	i := strings.Index(s, "://")
	if i < 0 {
		return ""
	}
	s = s[i+3:]
	if j := strings.IndexAny(s, "#?"); j >= 0 {
		s = s[:j]
	}
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	// 分享链接里的 payload 基本都带 base64（可能缺失 padding、也可能用 URL-safe 字母表）
	if strings.ContainsAny(s, "@:") { // 这是 vmess://uuid@host:port 那种写法，不是 json
		return ""
	}
	return s
}

func applyVmessShare(u *Upstream, payload string) (scy string, err error) {
	dec, err := decodeB64Any(payload)
	if err != nil {
		return "", fmt.Errorf("vmess 分享链接解析失败（应该是 base64 的 JSON）: %w", err)
	}
	var sh vmessShare
	if err := json.Unmarshal(dec, &sh); err != nil {
		return "", fmt.Errorf("vmess 分享链接的 JSON 不合法: %w（内容：%s）", err, truncate(string(dec), 120))
	}
	if sh.Add == "" || sh.Port == nil || sh.ID == "" {
		return "", fmt.Errorf("vmess 分享链接缺少 add / port / id（内容：%s）", truncate(string(dec), 120))
	}
	port := fmt.Sprint(sh.Port)
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("vmess 分享链接的端口不是数字: %q", port)
	}
	// alterId：xray 已删 LEGACY，AEAD 下 aid 无意义且必须为 0
	if sh.Aid != nil && fmt.Sprint(sh.Aid) != "0" && fmt.Sprint(sh.Aid) != "" {
		return "", fmt.Errorf("vmess 的 alterId=%v 是旧版（LEGACY）写法，本版不支持 —— "+
			"xray 已经删掉了 LEGACY，请让上游把这个节点的 aid 改成 0（或用 VLESS）", sh.Aid)
	}

	u.Addr = net.JoinHostPort(sh.Add, port)
	u.ServerName = sh.Add
	u.Creds.User, u.Creds.Pass = sh.ID, ""

	// 传输：net=ws → ws；tls=tls → 再套 TLS（= wss）；grpc/kcp 等本版不支持
	switch strings.ToLower(sh.Net) {
	case "", "tcp", "raw":
		u.Transport = transportTCP
		if u.TLS {
			u.Transport = transportTLS
		}
	case "ws", "websocket":
		u.Transport = transportWS
		if u.TLS {
			u.Transport = transportWSS
		}
	case "grpc", "kcp", "quic", "http", "h2", "httpupgrade", "xhttp", "splithttp":
		return "", fmt.Errorf("vmess 分享链接用的是 %q 传输，本版不支持（支持 tcp / ws + tls）—— "+
			"请让上游换个传输或换个协议", sh.Net)
	default:
		return "", fmt.Errorf("不认识的 vmess 传输方式 %q", sh.Net)
	}
	switch strings.ToLower(sh.TLS) {
	case "":
	case "tls":
		u.TLS = true
		if u.Transport == transportTCP {
			u.Transport = transportTLS
		} else if u.Transport == transportWS {
			u.Transport = transportWSS
		}
	case "reality":
		return "", fmt.Errorf("vmess 分享链接写的是 reality，本版不支持（要 uTLS 指纹伪装）")
	default:
		return "", fmt.Errorf("不认识的 vmess TLS 方式 %q", sh.TLS)
	}
	if sh.Path != "" {
		u.WSPath = sh.Path
	}
	if sh.Host != "" {
		u.WSHost = sh.Host
	}
	if sh.SNI != "" {
		u.ServerName = sh.SNI
	}
	return sh.Scy, nil
}

// decodeB64Any base64 解（标准/URL-safe、带不带 padding 都试）。
func decodeB64Any(s string) ([]byte, error) {
	trimmed := strings.TrimRight(s, "=")
	var err error
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding,
	} {
		var dec []byte
		if dec, err = enc.DecodeString(trimmed); err == nil {
			return dec, nil
		}
	}
	return nil, err
}

type vmessProxy struct{ u *Upstream }

func (p *vmessProxy) Dial(ip net.IP, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddrXray(nil, ip, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *vmessProxy) DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error) {
	target, err := appendAddrHostXray(nil, host, port)
	if err != nil {
		return nil, err
	}
	return p.dial(target, timeout)
}

func (p *vmessProxy) dial(target []byte, timeout time.Duration) (net.Conn, error) {
	raw, err := p.u.dialTransport(timeout)
	if err != nil {
		return nil, err
	}
	conn, err := vmess.NewClientConn(raw, p.u.UserID, target, timeout)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Prepare 预热：**本版对 vmess 不支持预热**，返回 ErrNoPrepare（契约⑤ 要求）。
//
// 为什么：请求头里带目标地址、而且每个连接都必须重新随机 IV/Key/RespV
// （服务端有会话去重，复用会被判重放），所以"先预备好只差 CONNECT"这一段对 vmess
// 只剩传输层握手；而响应头要在读路径上惰性剥（得包一层自己的连接）。
// 与其做一个"只省一半"的假预热，不如老实说不支持 —— 预热池会直接走 Dial。
func (p *vmessProxy) Prepare(timeout time.Duration) (net.Conn, error) { return nil, ErrNoPrepare }

// ConnectOn 与 Prepare 成对：不支持预热时不该被调用到。
func (p *vmessProxy) ConnectOn(conn net.Conn, ip net.IP, port uint16, timeout time.Duration) error {
	return ErrNoPrepare
}

func (p *vmessProxy) SupportsPrepare() bool { return false }
