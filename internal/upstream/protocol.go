package upstream

// 「上游协议」的适配器边界。
//
// 为什么要这一层（KB 把它列为结构性风险第 1 条）：`socks5+tls` 是 **gost 的私有组合**、
// 不是业界标准 —— 上游一旦换成 v2ray/xray/sing-box 或私有实现，这种形态直接失效。
// 所以协议实现必须是**可插拔的**：
//
//	加协议 = 新写一个文件 + 在 init() 里 register，**别往 engine / config 里塞私有分支**。
//
// 对外接口（Upstream 的 Dial/Prepare/ConnectOn/DialHost）**一个字都没变**，
// 变的只是内部分发方式（原来是 switch，现在是注册表）。这样上层不用跟着改。
//
// 新协议必须过的契约（断言都在 contract_test.go，写完 register 就会被它自动带上）：
//  1. 正常连：Dial 成功后数据能双向走（不是"连上了但写不出去"）
//  2. 认证失败：要报**明确的错**，不能静默降级成"连上了却没鉴权"
//  3. 超时：上游不回话时必须在 timeout 内返回错误（不能挂死）
//  4. 域名：DialHost 要真的把域名交给上游（而不是本机解析完再发 IP）
//  5. 预热：SupportsPrepare 为真时，Prepare+ConnectOn 必须等价于 Dial；为假时必须返回 ErrNoPrepare
//  6. 并发：N 路并发 Dial 都成功（协议实现里不能有共享可变状态）

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Proxy 一种上游协议的客户端 —— 回答"帮我连到 target 这个目标"。
//
// 注意这个接口的语义边界：**只做 CONNECT 语义的代理**。VPN（L3 隧道）那类东西
// 没有"帮我连某个目标"这个操作，所以它不适合、也不该被塞进这个接口 ——
// 那种需求走"让它自己的客户端跑、把本地 socks 端口填进 forward"（见 AGENTS.md 的系统配置红线）。
type Proxy interface {
	// Dial 连到 targetIP:targetPort。
	Dial(targetIP net.IP, targetPort uint16, timeout time.Duration) (net.Conn, error)
	// DialHost 把**域名**交给上游去解析并连接（不是本机先解析成 IP 再发过去）。
	DialHost(host string, port uint16, timeout time.Duration) (net.Conn, error)
	// Prepare 预热：把 TCP(+TLS)+握手做到"只差 CONNECT"这一步。
	// 不支持"先预备后打通"的协议返回 ErrNoPrepare。
	Prepare(timeout time.Duration) (net.Conn, error)
	// ConnectOn 在 Prepare 预备好的连接上打通到目标。与 Prepare 成对使用。
	ConnectOn(conn net.Conn, targetIP net.IP, targetPort uint16, timeout time.Duration) error
	// SupportsPrepare 是否支持"先预备后打通"（预热连接池据此决定要不要养它）。
	SupportsPrepare() bool
}

type factory func(u *Upstream) Proxy

// registry 协议名 → 构造器。协议名与 scheme.go 里 classify() 归一化后的 base 名一致。
var registry = map[string]factory{}

func register(name string, f factory) { registry[name] = f }

// RegisteredSchemes 已注册的协议名（排序）。给错误提示与"两边是否同步"的测试用。
func RegisteredSchemes() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// proxy 取这条上游对应的协议实现。
// 解析期（Parse）已经挡掉未知协议，所以这里正常不会失败 —— 留着是为了兜底与可诊断。
func (u *Upstream) proxy() (Proxy, error) {
	f, ok := registry[u.Protocol]
	if !ok {
		return nil, fmt.Errorf("未实现的上游协议 %q（已注册：%s）",
			u.Protocol, strings.Join(RegisteredSchemes(), " / "))
	}
	return f(u), nil
}
