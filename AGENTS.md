# AGENTS.md —— NetHub

> **分支索引**（按你要动的东西跳节，别整份读）：
> 改配置/热更/规则 → §2 · 动界面/进程模型 → §3 · 动日志 → §4 · 动统计/连接列表 → §5 · 加/改上游协议 → §7 · 搭测试/发版 → §9
> 其余一律不写在这里：做法与判据 `KB:规则/代理/` · 坑 `KB:教训/` · 为什么这样定 `KB:决策/` · 存证 `KB:产物/nethub/` · 用户文档 `README.md` · 界面规范 `DESIGN.md`。
> **只有三份 md**：`README.md` · `DESIGN.md` · 本文件 —— 别的**不要新建**，该进代码注释就进注释，该进 `git log` 就进 commit message。

## 1. 技术栈

Go + **Wails v2**（WebView2 界面）+ **WinDivert**（内核驱动），**仅 Windows x64**。

**一条 exe 两种形态，同机只开一种自启**：GUI（有人在用）= 双击起界面+托盘，`-autostart` 装**计划任务**（**登录**事件后延迟 20 秒），有托盘有通知；headless/服务（服务器、无人登录）= `-service-install` + `-service-autostart on`（或界面「服务模式」开关）随**开机**由 SCM 拉起，**本来没有界面/托盘/通知，那是定义不是缺陷**。

**安装 ≠ 启用**（同 Clash：装虚拟网卡 ≠ 开 TUN）：`-service-install` 只注册成**手动启动**，装好留着备用；拨开关才改 `StartType` 并当场交棒。两种形态都装着无害，**冲突的是两条自启**（服务开机先拿到引擎，登录后起的界面版只能当只读失败者）。开关打开会自动关掉计划任务那条（`SetServiceAutoStart`），关掉会停服务并把引擎接回界面版。**别当成同一个设置的两个落法**：GUI 是"登录后延迟启动"，headless 是"开机即启然后一直跑"。

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

## 3. 界面和引擎是两个进程

`nethub.exe` 后端 + `nethub.exe -frontend` 前端，通信见 `internal/ipc`。

- **为什么必须拆**：现场 HIS/医保客户端启动器清 WebView2 缓存时会**按进程名杀掉全系统所有 `msedgewebview2.exe`**，而 Wails 在浏览器进程消失后 `os.Exit(-1)` 且跳过收尾 —— 同进程就是引擎被连坐（现场："整个 NetHub 静默消失、hosts 段留在系统里没人兑付"）。拆开后被杀只影响界面，引擎/隧道/hosts 毫发无损，看护约 2 秒把界面拉回并记一条"界面进程被外部程序结束（退出码 N）"。
- **前端不读也不写配置**（配置里有上游凭据）：只给它 `-logdir`，结构上碰不到 config.yaml。
- **已知边界**：点名杀 `nethub.exe` 时后端一样会死 → 靠 SCM 失败恢复（服务形态有；**GUI/计划任务形态没有**，Task Scheduler 的 `RestartOnFailure` 对"进程被外部结束"实测不生效）→ 无人值守装服务形态。对外只承诺"杀界面不影响业务"。
- **卡死判据**：两边都用"自己名下还有几个 `msedgewebview2`"（`internal/proc.ChildrenByName`）—— `os.Process.Wait()` 的退出码不在 error 里，Wails 的报错框会等人点。
- **孤儿界面是"双击托盘没反应"的根**：引擎被强杀时界面不死（带管道 + Wails 单实例锁），之后新界面 30ms 内让位给孤儿（`single_instance.go` 走 `SendMessage` 后 `os.Exit(0)`）→ 退出码 0 被当成"用户主动退出"。所以：界面带 `-parent <引擎pid>` 起来（`watchParent`，宿主没了自己退）；看护遇退出码 0 进**待命**（`waitNudge`）而不是收工；`Show` 先试已接上的界面（`ShowMainWindow` 报错才算叫不动）再唤醒看护 —— **别用"我拉起过进程没有"当界面在不在的判据**。

## 4. 日志三档（照抄 Proxifier 的 Normal / Verbose / Debug）

运行日志页三段滑块 `normal | verbose | debug`（`ui.log_level`，默认 normal）。

- **分档内容**：normal 只写连接 open/close、直连/阻断、启停、配置变更、上游状态翻转与错误（连接行形如 `open: chrome.exe (8804) → main.example.com(192.0.2.217):80 via site-a`，**命中哪条规则不进这行**）；verbose 加判定面（`route.match`、DNS 请求与应答、`upstream.pick`、`conn.stage` 分段耗时、`direct.done`、`stats` 周期快照）；debug 加内部面（名字表/假 IP 池、内核层、规则表编译、过滤器原文、装配细节），且**切到 debug 时立刻 `Engine.DumpState`**（那些内容本来只在启动写，不转储就等于"只有重启才看得到"）。诊断包功能已删：要交现场材料就发 `nethub.log`。
- **分档靠自觉 + 测试钉住**（`internal/engine/loglevel_test.go`）：新增日志行先问"这一行回答'发生了什么'还是'为什么'"；被去重的重复项补 `suppressed: count=N`。
- **排查入口在用到它的那一页**：连接页右上角「详细日志」开关（点一下就是 verbose，不用跳去日志页）；两个控件管同一档，改完互相同步（`updateVerboseToggle`）。
- **档位持久化，算"本机偏好"**（`config.LocalPrefs`）：重启保持；`-apply`/导入/回滚/`deploy.ps1` 都不许打回 normal —— 任何新加的"整份配置替换"路径都要调 `KeepLocalPrefsFrom`；启动打一行档位、`-status` 报 `logLevel`。
- **屏幕与文件是两个档**（`Bus.SetLevels`）：`ui.log_level` 管界面（环形缓冲/订阅者）、`ui.log_level_file` 管 `logs/nethub.log`（空 = 跟随）。`Detail`/`Debug` 的门槛是"**任一 sink 达档**" → "屏幕 normal + 文件 verbose"合法（现场最常用）。`tools/memwatch.ps1` 采 `stats` 行，切的是**文件档**。
- **我们自己的探针在 normal 档一行都不写**（自检、共存检测走 `DialSelf`）：仪器不是业务 —— 与"不进连接列表、不计累计、不进顶栏流量图"同一条原则。开机一串 `proc=nethub.exe` 的 `intercept`/`relay.done` 会被当成"应用在连"（用户报过）。

## 5. 探针与统计口径

- **自己发的探针不当应用流量**：自检/共存检测直连内网目标会被自己的过滤器接住 → 一律 `Engine.DialSelf`（connect 前先登记本地端口）；用 `net.DialTimeout` 直连就是错的。
- **诊断页「接管状态」卡是仪表盘，不是日志**（用户要求"不能看起来像另类的日志"）：只放当前值（在不在/几个/几百）+ 状态点，**无时间戳、不追加行、原地更新**；原文进折叠区且展开才取。异常判据是纯函数 `engine.statusWarnings`，`runtime_test.go` 逐条钉住。
- **「活跃」含直连与阻断**（`Engine.ConnsActive`，与列表一致）；"累计/各链累计"只算走隧道的（`statTotal`/`statPerRule`）。两口径不同是故意的，界面必须标清楚（连接页「i」）。
- **开关改完立刻重画受影响视图**（`refreshAfterToggle`）；关掉直连统计时，只剩 `connState.statsOnly` 才可见的直连条目要**立即**从列表消失。
- **「统计」卡与连接列表是两个问题**：列表 = "现在有哪些连接"（15 秒就消失）；统计 = "这段时间谁在占通道"（累计、可清零）。它是**卡片不是页签**（2026-10-16 拍板）。
- **口径只有一个：累计**（进程启动以来）。引擎 Start 时清的那一档是**全界面唯一**不同起点的数字（链页累计、顶栏流量图都进程起算），留着就是"同一件事两个数"。卡上「时长」= 这组数字覆盖了多久，不是程序跑了多久。后端 `StatsPage(scope)` 仍认两档（有用例），界面只问 all。
- **数据两条腿**：连接**收尾时**落累计桶（`finish` 与 janitor 两条路，幂等靠 `st.ended` 的 CAS，否则同一连接的字节算两次）；**还开着的**在读取时实时算（否则 8 小时长会话永远是 0）。
- **目标按名字归并**（`nameOf`，同时认假 IP 与"应用拿真实 IP 连过来"）—— **不要用 `connState.fakeName`**（包路径上无锁写，读它就是 data race）。
- 桶上限 **512**，合计单独存（不随淘汰丢）；**不落盘**。

## 6. 明确不做

IPv6 · UDP 中继 · 多跳串联 · TUN/TAP · 域名/正则匹配 · 限速配额 · 反向端口转发 · 上游 mux。
IPv6 是**主动不收**（引擎只做 IPv4，DNS 层把 AAAA 答空防应用绕过）—— **不是 WinDivert 的限制**；要做就是重写拦截层，不是"打开一个开关"。

## 7. 上游协议可插拔

- **加协议 = 新写一个文件 + `init()` 里 register**（`internal/upstream/protocol.go`），engine / config **一个字不用改**；`contract_test.go` 的 6 条契约自动覆盖新协议。
- **同 scheme 的分支**（`ss` 传统 vs 2022 线格式）在协议自己文件里按加密方式名分发（`proto_ss.go` + `internal/ss/{conn.go,ss2022.go}`，公共 chunk 流在 `stream.go`）。
- **两处公共东西单独成文件，别在各协议里重写**：`transport.go`（TCP → [TLS] → [ws]；`+tls/+ws/+wss` 只认两段，≥3 段直接拒）；`addr.go`（A 族 SOCKS5 风格 `ATYP|ADDR|PORT` 域名 `0x03`；B 族 xray 风格 **`PORT|AT|ADDR`** 域名 **`0x02`** —— 两族的端口位置与域名码都不同）。
- **必须与真实现对测**（`interop_test.go`）：ws/tls/ss 用 `local/bin/gost.exe`，trojan/vless/vmess/ss2022 用 `local/bin/xray.exe`（gost 没有这几样的服务端，**也不支持 ss2022**）；文件不在就 skip（clone 下来 `go test` 不红）。**别自己写"照规范的"假服务端来测** —— 那只会把理解错误照抄一遍（两边一起错、全绿、上线连不上）；假服务端只用来构造真服务端不会给的坏输入（`internal/ss/ss2022_test.go`）。

## 8. 系统配置红线

**不得**要求"改路由表 / 抢系统代理 / 写注册表新键"。现在碰系统的只有三处，别再添：WinDivert 驱动服务条目（内核驱动唯一注册方式）· hosts 文件（可选、可关、停就撤）· 计划任务（GUI 形态自启，用户自己开）。

## 9. 构建与运行

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
