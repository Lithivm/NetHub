# 上游协议（可插拔 + 真实现对测）

> 上位：[AGENTS.md](../AGENTS.md)。这页只展开「加/改上游协议」这一块。

- **加协议 = 新写一个文件 + `init()` 里 register**（`internal/upstream/protocol.go`），engine / config **一个字不用改**；`contract_test.go` 的 6 条契约自动覆盖新协议。
- **同 scheme 的分支**（`ss` 传统 vs 2022 线格式）在协议自己文件里按加密方式名分发（`proto_ss.go` + `internal/ss/{conn.go,ss2022.go}`，公共 chunk 流在 `stream.go`）。
- **两处公共东西单独成文件，别在各协议里重写**：`transport.go`（TCP → [TLS] → [ws]；`+tls/+ws/+wss` 只认两段，≥3 段直接拒）；`addr.go`（A 族 SOCKS5 风格 `ATYP|ADDR|PORT` 域名 `0x03`；B 族 xray 风格 **`PORT|AT|ADDR`** 域名 **`0x02`** —— 两族的端口位置与域名码都不同）。
- **必须与真实现对测**（`interop_test.go`）：ws/tls/ss 用 `local/bin/gost.exe`，trojan/vless/vmess/ss2022 用 `local/bin/xray.exe`（gost 没有这几样的服务端，**也不支持 ss2022**）；文件不在就 skip（clone 下来 `go test` 不红）。**别自己写"照规范的"假服务端来测** —— 那只会把理解错误照抄一遍（两边一起错、全绿、上线连不上）；假服务端只用来构造真服务端不会给的坏输入（`internal/ss/ss2022_test.go`）。
