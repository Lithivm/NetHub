# AGENTS.md —— 给 AI agent 的项目说明

> 人看的文档在 [`README.md`](README.md)（怎么用）与 [`DESIGN.md`](DESIGN.md)（界面规范）。

## 这是什么

**NetHub**：Windows 内网透明代理。目标 IP 落在配置网段里的 **TCP** 连接，
由内核层（WinDivert）拦下、改写到本机 relay，再经**我们自带的** SOCKS5/HTTP 客户端
从上游代理转发出去。用途是替代「Proxifier + 两个 gost `.bat`」——
客户机装一个 exe 就能访问内网业务系统，应用零改动、不抢系统代理、不动路由表。

- 语言/栈：**Go** + Wails v2（WebView2 界面）+ WinDivert（内核驱动）。仅 Windows x64。
- 界面是**中文**的，用户是运维/实施人员（不是开发者），文案要写人话、别堆术语。

## 关键设计决定（改代码前先读懂，别绕过）

| 决定 | 为什么 |
|---|---|
| 判定维度 = **目标 IP/CIDR + 端口**，进程只是可选**例外**条件 | 主用法按目标（按进程要"每个新程序配一次"，现场成本大于收益）；进程条件只用于"某程序必须走/绝不许走隧道"这种目标不固定的情况 |
| 规则**自上而下、命中即止**；排序与重叠检查都是**用户主动点的按钮**，不自动干预 | 用户可能就想"宽规则兜底、窄规则例外"，我们不强迫 |
| 直连/阻断用**保留链名** `direct` / `block`（不是真实链） | 一个动作就是一个字段，少一套分支 |
| 过滤器只装"走链 + 阻断"的网段 | 直连零开销（可选开"直连统计"才纳入） |
| 阻断尽力回 **RST** | 让应用立刻被拒，而不是等 21s 超时 |
| 上游多路复用（mux）**不做**（评估见 git log） | 收益与"预热连接池"相同但成本高 3～4 倍，且要上游改成 `socks5+mtls` |
| 分发包**不带任何数据**（无日志/配置/备份）；脚本**不进仓库** | 避免把上一台机器的信息带到客户那儿 |
| 上游口令用 **DPAPI 封存**（`secrets.dat`），配置里只留 `secret:` 引用 | 配置被拷走 ≠ 口令泄露；**导出时还原成明文**（新机器解不开密文） |

“明确不做”清单：UDP 中继、多跳串联、TUN/TAP、Prometheus、域名/正则匹配、限速配额、反向端口转发。

## 目录

```
main.go                  入口：-headless / -service* / -quit / -import-bats / -clash-check …
internal/app/            应用编排（Start/Stop/Restart、状态与 LastError）
internal/config/         配置读写、校验、体检、备份、凭据封存、重叠检查
internal/rules/          规则集：匹配、过滤器网段、影子/具体度
internal/engine/         引擎：relay、包循环、连接表、健康探测、预热池、环路检测、抓包
internal/upstream/       上游协议客户端（socks4/5、+tls、http(s)）+ 探测
internal/socks/          最小 SOCKS 客户端（Prepare/ConnectOn 两段式，供预热池用）
internal/webui/          Wails 后端（界面的全部 API）+ 托盘 + 诊断包 + 配置导入导出
internal/secret/         DPAPI 凭据保险箱
internal/winsvc/         Windows 服务安装/启停
frontend/                界面（index.html / app.js / style.css，无框架、无构建步骤）
local/                   **本机开发脚本（gitignore，不进仓库）**：restart.ps1、shot/、dialprobe/
docs/                    截图等
```

## 构建与运行

```bash
export PATH="/c/Program Files/Go/bin:$PATH"                 # git-bash
go build -tags production -ldflags "-H=windowsgui -s -w" -o run/nethub.exe .
go test ./internal/...                                      # 全量测试
pwsh -NoProfile -File ./local/check-ui.ps1                   # 前端自检：跑一遍 + 查“调用了但没定义的函数”（改完前端必须跑）
pwsh -NoProfile -File ./local/restart.ps1                   # 优雅重启 + 复测 6 个内网目标
```

`run/` 是运行目录（exe + WinDivert + config.yaml + logs/），**已被 gitignore**。
`local/restart.ps1` 先用 `nethub.exe -quit` **优雅退出**再启动 —— 直接 `Stop-Process` 会留下
"僵尸托盘图标"（进程没了、图标还在，鼠标扫过才消失）。

## 本机踩过的坑（别重犯）

- **中文 `.ps1` 必须带 UTF-8 BOM**（`powershell 5.1` 会把无 BOM 的 UTF-8 当 ANSI 解码并吞行）。
  改完跑 `pwsh -File local/fix-ps1-encoding.ps1 -Check`；用 `pwsh` 7，别用 `powershell` 5.1。
- **`python - <<'PY'`（stdin heredoc）在这台机器上会静默失败** —— 批量改文件用 `sed`/`edit` 工具，别用 python 管道。
- **`select`/`Select-Object -First N` 会中断上游管道脚本**；`sed -i` 对某些文件要加 `.bak`。
- **提权进程收不到普通权限进程的窗口消息**（UIPI，报 `Access is denied`）→ 进程间通知走**命名事件**。
- 装了安全软件（火绒/360）时 `WinDivert64.sys` 会被拦 → 报 **1450**，要在安全软件里信任后**重启它**。
- 规则加字段时**别忘了 `toRules()`**（`internal/app/app.go`）—— 端口维度那次就是漏在这里，界面配了不生效。
  同样地，加字段时检查 `Route.normalize()`（`internal/config/config.go`）：漏一趟 → 保存后字段静默消失。
- **进程维度（A20）三个反直觉点**：① 包的来源端口 → TCP 表（`GetExtendedTcpTable`，DLL 自己调，`x/sys` 没封装）
  → PID → 进程名，所以是**每连接查一次，不是每包**；② 查不到进程（系统服务/受保护进程）时带进程条件的规则**不命中**（fail-open，
  “不因为认不出进程就改变流量走向”）；③ "只填进程不填目标"的规则目标不可知 → 过滤器只能拦 `0.0.0.0/0`（性能略降，用户显式这么写才发生）。

## 文档纪律

- 只有三份 md：`README.md`（人）、`DESIGN.md`（界面规范）、`AGENTS.md`（本文件）。
  其他内容一律**别新建文档** —— 该进代码注释就进注释，该进 `git log` 就进 commit message。
- 跨项目、下次干活会用到的知识写进**本机知识库**（Obsidian vault，见全局 `AGENTS.md` 的 KB 约定），
  项目里引用写作 `KB:相对路径`。

## 下一步（待办，按性价比）

1. **规则顺序无关**（可选设计，未采纳）：把"命中即止"改成"最具体优先"，顺序就不影响结果。
   用户明确要求**不自动排序**，所以现状是"用户自己点按钮"——需求变了再评估。
2. **抓包升级**：现在导出 pcap（`pcap/nethub-capture.pcap`，上限 64MB 停写）；可按连接过滤/分文件。
3. **候选竞速再进一层**：现在只对"第一条超过 150ms"起跑，可扩到"按历史延迟排序后竞速"。
4. **服务模式与界面共存**（需 IPC，较大）；**DNS 走代理**（需确认客户是否真有内网域名解析需求）。
5. 上游协议扩展（ws/gRPC/QUIC/ss）——**取决于上游会不会换实现**，换之前不做。
