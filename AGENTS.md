# AGENTS.md —— NetHub

> **常驻只放红线与判据**，按块展开的细则在 `docs/`：
> 进程模型 [`docs/process-model.md`](docs/process-model.md) · 日志三档 [`docs/logging.md`](docs/logging.md) · 探针与统计 [`docs/stats.md`](docs/stats.md) · 上游协议 [`docs/upstream.md`](docs/upstream.md)
> 其余：做法与判据 `KB:规则/代理/` · 坑 `KB:教训/` · 为什么这样定 `KB:决策/` · 存证 `KB:产物/nethub/` · 用户文档 `README.md` · 界面规范 `DESIGN.md`。
> **新知识先进 `docs/` 或代码注释，别再往本文件堆** —— 本文件只留「不知道就会做错」的那一层。

## 1. 技术栈

Go + **Wails v2**（WebView2 界面）+ **WinDivert**（内核驱动），**仅 Windows x64**。

**一条 exe 两种形态，同机只开一种自启**：GUI（有人在用）= 双击起界面+托盘，`-autostart` 装**计划任务**（**登录**事件后延迟 20 秒），有托盘有通知；headless/服务（服务器、无人登录）= `-service-install` + `-service-autostart on`（或界面「服务模式」开关）随**开机**由 SCM 拉起，**本来没有界面/托盘/通知，那是定义不是缺陷**。

**安装 ≠ 启用**（同 Clash：装虚拟网卡 ≠ 开 TUN）：`-service-install` 只注册成**手动启动**，装好留着备用；拨开关才改 `StartType` 并当场交棒。两种形态都装着无害，**冲突的是两条自启**（服务开机先拿到引擎，登录后起的界面版只能当只读失败者）。开关打开会自动关掉计划任务那条（`SetServiceAutoStart`），关掉会停服务并把引擎接回界面版。**别当成同一个设置的两个落法**：GUI 是"登录后延迟启动"，headless 是"开机即启然后一直跑"。**跨形态的互斥统一走 `autostart.Plan`**（先设目标、再清对方；目标那步失败立即停手，绝不留下"两边都没自启"）—— 界面（`SetServiceAutoStart`）和 CLI（`-service-autostart on` / `-autostart`）两条路都调它，**别再各写一套**；`HKCU\Run` 是第三份历史来源，启用服务自启时由 `ClearLegacyRunValue` 清掉。

界面 `frontend/`：无框架、无构建（`index.html`/`app.js`/`style.css`）；文案**中文**，用户是运维/实施人员 —— 写人话、别堆术语。
后端 `internal/`：`app`（编排 Start/Stop/Restart）· `config`（读写/校验/体检/重叠）· `rules`（匹配）· `engine`（relay / 包循环 / 连接表 / 探测 / 预热池 / 抓包）· `upstream` + `socks`（上游客户端）· `webui`（界面 API / 托盘）· `secret`（DPAPI 保险箱）· `winsvc`（Windows 服务）。

## 2. 产品契约（违反即 bug）

- **按目标 IP/CIDR + 端口判定，不按进程** —— 现场不用"每来一个新程序就配一次"；进程只作可选**例外**条件。
- **应用零改动**：内核层拦包改写，**不抢系统代理、不动路由表** —— 客户机装一个 exe 就能访问内网业务。
- **上游转发自带**：SOCKS5 / SOCKS4 / HTTP(S)（可 +TLS），**不依赖外部 gost 进程与 `.bat`**。
- **规则顺序即语义**：自上而下、命中即止；排序只由用户按钮触发；`direct`/`block` 是**保留链名**，不是真实链。
- **改配置不用重启**：规则/链/上游/拨号参数即时生效（界面保存即生效；外部改文件 ≤ 2 秒热重载；换过滤器句柄"先开新再关旧"，不断已有连接）。**只有三项要重启**：中转端口、DNS 接管（假 IP）、hosts 条目。
- **QUIC 只拦不中继**：UDP 443 拦下 + 记一行 `quic.block`，让应用回落 TCP（TCP 仍归我们管）；单条规则可勾「不拦 QUIC」放行。以前是默默直连漏出。
- **停就撤、启再写**：停引擎/退出时把 hosts 段与 `runtime.json` 一起收走（引擎一停，hosts 段里那些名字就没人兑付）；被强杀撤不掉 → `-status` 报 `hosts.stale` 与 note，下次启动盖回去。

## 3. 四块细则：一句话红线 + 展开在哪

- **两个进程**：界面与引擎**必须分开跑** —— 清 WebView2 缓存时客户端启动器会按进程名杀掉全系统 `msedgewebview2.exe`，同进程就是引擎被连坐（现场"静默消失 + hosts 无人兑付"）。孤儿界面、`-parent`、`waitNudge`、`ShowMainWindow` 的判据 → [`docs/process-model.md`](docs/process-model.md)
- **日志三档**：`normal | verbose | debug`，**档位算本机偏好** —— `-apply`/导入/回滚/`deploy.ps1` 都不许打回 normal（新加的"整份配置替换"路径要调 `KeepLocalPrefsFrom`）。屏幕档与文件档是两个档 → [`docs/logging.md`](docs/logging.md)
- **探针与统计**：自检/共存检测一律 `Engine.DialSelf`，用 `net.DialTimeout` 直连就是错的（会被自己接住当成应用流量）；「累计」全界面只有一个口径 → [`docs/stats.md`](docs/stats.md)
- **上游协议**：加协议 = 新文件 + `init()` 里 register（engine/config 不改）；**只与真实现对测**（gost/xray），别自写"照规范的"假服务端 → [`docs/upstream.md`](docs/upstream.md)

## 4. 明确不做

IPv6 · UDP 中继 · 多跳串联 · TUN/TAP · 域名/正则匹配 · 限速配额 · 反向端口转发 · 上游 mux。
IPv6 是**主动不收**（引擎只做 IPv4，DNS 层把 AAAA 答空防应用绕过）—— **不是 WinDivert 的限制**；要做就是重写拦截层，不是"打开一个开关"。

## 5. 系统配置红线

**不得**要求"改路由表 / 抢系统代理 / 写注册表新键"。现在碰系统的只有三处，别再添：WinDivert 驱动服务条目（内核驱动唯一注册方式）· hosts 文件（可选、可关、停就撤）· 计划任务（GUI 形态自启，用户自己开）。

## 6. 构建与运行

```bash
export PATH="/c/Program Files/Go/bin:$PATH"                 # git-bash

gofmt -l . | grep -v '^local/'                              # 空即合规；别只扫 internal/（仓库根 main.go 也改）
go vet ./... && go test ./internal/...
go build -tags production -ldflags "-H=windowsgui -s -w" -o run/nethub.exe .
pwsh -NoProfile -File ./tools/check-ui.ps1                  # 改完前端必须跑（boot 不报错 + 无未定义函数 + 结构断言：标签成对 / tab↔页面一一对应 / main 下无孤儿）
pwsh -NoProfile -File ./tools/ui-controls-test.ps1          # 勾选/下拉真的调到了后端 + 卡片标题不被挤成两行
pwsh -NoProfile -File ./tools/tray-fix.ps1                  # 托盘回归（需管理员）：验「X 收进托盘→托盘能叫回」+「强杀引擎不留孤儿界面」
pwsh -NoProfile -File ./tools/restart.ps1                   # 快速优雅重启 + 复测目标（-Targets 传）
pwsh -NoProfile -File ./tools/accept.ps1                    # 验收门禁（重启→驱动→连通→热生效→还原）；退出码可判，发版前必须跑
pwsh -NoProfile -File ./tools/accept.ps1 -InjectFault        # 门禁自检：故意注入故障，证明它真会失败（防"永远绿灯的假门禁"）
./run/nethub.exe -check | -status | -apply <新配置> | -quit   # 控制面：验 / 看 / 切 / 停（不需管理员）
pwsh -NoProfile -File ./tools/deploy.ps1 -Zip <zip> -Autostart -Start -Accept   # 无人值守部署（解压→配置→自启→启动→验收；并把该加的白名单打出来）
pwsh -NoProfile -File ./tools/memwatch.ps1                  # 长跑采样（内存/句柄/名字表/假IP池）→ run/memwatch.csv
pwsh -NoProfile -File ./tools/install-hooks.ps1             # 每台机器跑一次：接上 pre-commit（脱敏扫描 + .ps1 的 BOM 检查）
```

**`tools/` 与 `local/`**：`tools/` 里通用工具（自检/截图/打包/装机/采样/验收）**入库**，任何人 clone 都能跑（路径基于 `$PSScriptRoot`，**不写死本机目录、不写任何客户地址**）；`local/` 只放本机专属（现场地址、凭据、二进制、一次性实验），不入库也不入包。

**目标不写死在脚本里**：`accept`/`restart`/`verify-after-reboot`/`porttest` 都接 `-Targets 'IP:端口[:名字]',...`（仓库默认空，空则跳过连通性检查，不会造成"永远红灯的假门禁"）；`test-upstream -Upstream 'IP:端口',...` 同理。

`-status` 的 `runtime` 块是**运行实例自己写的**（exe 同目录 `runtime.json`）：在不在跑、吃的哪份配置（`configHash`/`configMatchesFile`）、哪些改动还没生效（`restartNeeded`）。`-apply` 会校验 → 落盘 → 等实例真的吃进去才返回（0 = 已生效，3 = 写了但没应用）。
