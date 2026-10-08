# AGENTS.md —— NetHub

## 技术栈

Go + **Wails v2**（WebView2 界面）+ **WinDivert**（内核驱动），**仅 Windows x64**。
界面 `frontend/`：无框架、无构建步骤（`index.html` / `app.js` / `style.css`）；界面文案是**中文**，
用户是运维/实施人员（不是开发者），写人话、别堆术语。
后端 `internal/`：`app`（编排 Start/Stop/Restart）· `config`（读写/校验/体检/重叠）· `rules`（匹配）·
`engine`（relay / 包循环 / 连接表 / 探测 / 预热池 / 抓包）· `upstream` + `socks`（上游客户端）·
`webui`（界面 API / 托盘）· `secret`（DPAPI 保险箱）· `winsvc`（Windows 服务）。

## 设计初衷：替代现场的「Proxifier + 两个 gost .bat」

- **按目标 IP/CIDR + 端口判定**，不按进程 —— 现场不用"每来一个新程序就配一次"；进程只作可选**例外**条件。
- **应用零改动**：内核层拦包改写，不抢系统代理、不动路由表 —— 客户机装一个 exe 就能访问内网业务。
- **上游转发自带**（SOCKS5 / SOCKS4 / HTTP(S)，可 +TLS），不再依赖外部 gost 进程与 `.bat` 脚本。
- 规则**自上而下、命中即止**（顺序即语义，排序只由用户按钮触发）；`direct` / `block` 是保留链名，不是真实链。
- **改配置不用重启**：规则 / 链 / 上游 / 拨号参数即时生效（界面保存即生效，外部改文件 ≤ 2 秒热重载；
  换过滤器句柄“先开新再关旧”，不断已有连接）。只有**三项**要重启：中转端口、DNS 接管（假 IP）、hosts 条目。
- **QUIC（UDP 443）不中继，只拦下**：本该走链的目标上的 HTTP/3 以前是默默直连漏出的；
  现在拦下 + 记一行 `quic.block`，让应用回落到 TCP（TCP 那条路仍归我们管）；单条规则可勾「不拦 QUIC」放行。
- **停就撤、启再写**：停引擎/退出时把 hosts 段与 `runtime.json` 一起收走（引擎一停，hosts 段里
  那些名字就没人兑付）。被强杀撤不掉 → `-status` 报 `hosts.stale` 与一条 note，下次启动盖回去。
- **日志三档（照抄 Proxifier 的 Normal / Verbose / Debug）**：运行日志页的三段滑块
  `normal | verbose | debug`（配置 `ui.log_level`，默认 normal）。normal 只写连接开/关、启停、
  状态翻转、错误；verbose 加**判定面**（每条连接的 `route.match`、DNS 请求与应答）；
  debug 加**内部面**（名字表/假 IP 池维护、内核层、规则表编译、过滤器原文）；
  **切到 debug 时立刻转储一份当前内部状态**（`Engine.DumpState`）—— 那些内容本来只在启动时写，
  不转储就等于“只有重启才看得到”。诊断包那个功能已删（2026-10-08）：要交现场材料就发 nethub.log。
  分档是**靠人自觉**的：新增日志行时必须先问“这一行回答的是‘发生了什么’还是‘为什么’”，
  并有测试钉住（`internal/engine/loglevel_test.go`）。被去重的重复项必须补 `suppressed: count=N`。
- **明确不做**：IPv6 · UDP 中继 · 多跳串联 · TUN/TAP · 域名/正则匹配 · 限速配额 · 反向端口转发 · 上游 mux。
  IPv6 是**我们主动不收**（引擎只做 IPv4，且 DNS 层把 AAAA 答空防应用绕过）—— **不是 WinDivert 的限制**，
  它的网络层同时管 v4/v6；哪天真要做就是重写拦截层，不是“打开一个开关”。
- **系统配置红线（新增功能前先过一遍）**：**不得**要求“改路由表 / 抢系统代理 / 写注册表新键”。
  现在碰系统的只有三处，别再添：WinDivert 驱动服务条目（内核驱动的唯一注册方式）·
  hosts 文件（可选、可关、停就撤）· 计划任务（开机自启，用户自己开）。

## 构建与运行

```bash
export PATH="/c/Program Files/Go/bin:$PATH"                 # git-bash
go build -tags production -ldflags "-H=windowsgui -s -w" -o run/nethub.exe .
go test ./internal/...
pwsh -NoProfile -File ./local/check-ui.ps1                  # 改完前端必须跑（boot 不报错 + 无未定义函数 + **结构断言**：标签成对 / tab↔页面一一对应 / main 下无孤儿）
pwsh -NoProfile -File ./local/ui-controls-test.ps1          # 勾选/下拉真的调到了后端 + 卡片标题不被挤成两行
pwsh -NoProfile -File ./local/restart.ps1                   # 快速优雅重启 + 复测内网目标
pwsh -NoProfile -File ./local/accept.ps1                    # 验收门禁（重启→驱动→连通→热生效→还原）；**退出码 0/非0 可判，发版前必须跑**
pwsh -NoProfile -File ./local/accept.ps1 -InjectFault        # 门禁自检：故意注入故障，证明它真会失败（防“永远绿灯的假门禁”）
./run/nethub.exe -check | -status | -apply <新配置> | -quit   # 控制面：验 / 看 / 切 / 停（不需管理员）
pwsh -NoProfile -File ./local/deploy.ps1 -Zip <zip> -Autostart -Start -Accept   # 无人值守部署（解压→配置→自启→启动→验收；并把该加的白名单打出来）
pwsh -NoProfile -File ./local/memwatch.ps1                  # 长跑采样（内存/句柄/名字表/假IP池）→ run/memwatch.csv
```

`-status` 里的 `runtime` 块是**运行实例自己写的**（exe 同目录 `runtime.json`）：在不在跑、吃的
是哪份配置（`configHash` / `configMatchesFile`）、有哪些改动还没生效（`restartNeeded`）。
`-apply` 会校验 → 落盘 → 等实例真的吃进去才返回（0 = 已生效，3 = 写了但没应用）。

---

其余一律不写在这里（避免每个会话重复注入）：做法与判据 `KB:规则/代理/` · 坑 `KB:教训/` ·
为什么这样定 `KB:决策/` · 存证 `KB:产物/nethub/` · 用户文档 `README.md`（怎么用）与 `DESIGN.md`（界面规范）。
只有三份 md：`README.md` · `DESIGN.md` · 本文件 —— 别的**不要新建**，该进代码注释就进注释，该进 `git log` 就进 commit message。
