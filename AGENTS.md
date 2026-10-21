# AGENTS.md —— NetHub

## 技术栈

Go + **Wails v2**（WebView2 界面）+ **WinDivert**（内核驱动），**仅 Windows x64**。

**一条 exe 两种形态，同一台机器只开一种自启**（2026-10-15 现场踩到）：

- **GUI**（有人在用的机器）—— 双击 `nethub.exe` 起界面+托盘，用 `-autostart` 装**计划任务**
  （挂在**登录**事件上，登录后延迟 20 秒）。有托盘、有系统通知。
- **headless / 服务**（服务器、无人登录）—— `-service-install` 装**Windows 服务** +
  `-service-autostart on`（或界面「服务模式」卡片的开关）让它随**开机**启动（SCM 拉起）。
  **本来就没有界面/托盘/系统通知**，那是它的定义不是缺陷。

**安装 ≠ 启用**（用户 2026-10-19 拍板，同 Clash：装虚拟网卡 ≠ 开 TUN）：`-service-install` 只注册成
**手动启动**（不随开机、不起进程），装好留着备用；拨开关才改 `StartType` 并当场交棒。
所以"两种形态都装着"是无害的，**冲突的是两条自启**：服务在**开机**时先拿到引擎，登录后才起来的
计划任务界面版只能当「只读失败者」（没托盘、没通知、刷权限报错）。
开关打开时会**自动关掉计划任务那条自启**（`SetServiceAutoStart`），关掉时会把服务停掉并把引擎接回界面版。
**别把它们当成"同一个设置的两个落法"**：GUI 的自启是"登录后延迟启动"，headless 的自启是"开机即启然后一直跑"。

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
- **界面和引擎是两个进程**（`nethub.exe` 后端 + `nethub.exe -frontend` 前端；编排见 `frontend.go`，
  通信见 `internal/ipc`）：现场机器上的 HIS/医保客户端启动器清自己 WebView2 缓存时，
  **按进程名杀掉全系统所有 `msedgewebview2.exe`**（反编译 Vendor.HIS.Launcher.exe 的
  `WebMainForm.DelectCache` 实证），界面首当其冲；而 Wails 在浏览器进程消失后会 `os.Exit(-1)`
  且跳过所有收尾。同进程就意味着引擎被连坐 —— 现场表现是“整个 NetHub 静默消失、hosts 段留在
  系统里没人兑付”。拆开之后：被杀只影响界面，引擎/隧道/hosts 毫发无损，后端看护循环约 2 秒
  把界面拉回来并在日志里写一条“界面进程被外部程序结束（退出码 N）”。
  - **前端不读也不写配置**（配置里有上游凭据）：只给它 `-logdir`，结构上碰不到 config.yaml。
  - **已知边界**：有人**点名杀 `nethub.exe`** 时后端一样会死 —— 靠 SCM 的失败恢复
    把服务形态拉回来（已做，见下）；**GUI/计划任务形态没有这个能力**（Task Scheduler 的
    RestartOnFailure 对“进程被外部结束”实测不生效）—— 无人值守就该装服务形态。
    对外只承诺“杀界面不影响业务”。
  - 前端**卡死**也要能被处理：`os.Process.Wait()` 的退出码不在 error 里、Wails 的报错框会等人点，
    所以两边都用“自己名下的 msedgewebview2 还剩几个”当存活判据（`internal/proc.ChildrenByName`）。
  - **孤儿界面是“双击托盘没反应”的根**（2026-10-19 现场：孤儿活了三天，期间每次重启都白重启）：
    引擎被强杀时界面不会跟着死，它带着管道和 Wails 的单实例锁活下来；之后引擎拉起的每个界面都
    在 30ms 内“让位”给孤儿（wails `single_instance.go` 是 `SendMessage` 后 `os.Exit(0)`）→ 退出码 0
    被当成“用户主动退出”。所以：**界面带 `-parent <引擎pid>` 起来，宿主没了就自己退**（`watchParent`）；
    看护遇到退出码 0 进**待命**而不是收工（`waitNudge`）；`Show` 先试“已经接上的界面”
    （`ShowMainWindow` 返回错误才算叫不动），再唤醒看护 —— **别用“我拉起过进程没有”当界面在不在的判据**。
- **日志三档（照抄 Proxifier 的 Normal / Verbose / Debug）**：运行日志页的三段滑块
  `normal | verbose | debug`（配置 `ui.log_level`，默认 normal）。normal **只**写连接 open/close、
  直连/阻断、启停、配置变更、上游状态翻转与错误 —— 连接行是 Proxifier 那种
  `open: chrome.exe (8804) → main.example.com(192.0.2.217):80 via etyy`（命中哪条规则不进这行）；
  verbose 加**判定面**（`route.match`、DNS 请求与应答、`upstream.pick` 实际走了哪个上游、
  `conn.stage` 分段耗时、`direct.done` 直连收尾、`stats` 周期快照）；
  debug 加**内部面**（名字表/假 IP 池维护、内核层、规则表编译、过滤器原文、装配细节）；
  **切到 debug 时立刻转储一份当前内部状态**（`Engine.DumpState`）—— 那些内容本来只在启动时写，
  不转储就等于“只有重启才看得到”。诊断包那个功能已删（2026-10-08）：要交现场材料就发 nethub.log。
  分档是**靠人自觉**的：新增日志行时必须先问“这一行回答的是‘发生了什么’还是‘为什么’”，
  并有测试钉住（`internal/engine/loglevel_test.go`）。被去重的重复项必须补 `suppressed: count=N`。
  排查入口在**用到它的那一页**：连接页右上角有「详细日志」开关（点一下就是 verbose，
  不用跳去日志页——对齐 Proxifier 连接面板上的 enable verbose output）。两个控件管同一个屏幕档，
  改完必须互相同步（`updateVerboseToggle`）。
  **档位必须持久化，且算“本机偏好”**（`config.LocalPrefs`）：重启保持；`-apply` / 导入 / 回滚 /
  `deploy.ps1` 都不许把它打回 normal（换配置不该换掉这台机器看日志的习惯）——
  任何新加的“整份配置替换”路径都要调 `KeepLocalPrefsFrom`；启动打一行档位、`-status` 报 `logLevel`。
  **屏幕与文件是两个档**（Proxifier 的 Screen Log / File Log，`Bus.SetLevels`）：
  `ui.log_level` 管界面（环形缓冲/订阅者）、`ui.log_level_file` 管 `logs/nethub.log`（空 = 跟随屏幕）。
  `Detail`/`Debug` 的写入门槛是“**任一 sink 达档**”，分流在 `log()` 里按 sink 各判 ——
  所以屏幕 normal + 文件 verbose 是允许的（现场最常用的就是这个组合）。
  `local/memwatch.ps1` 采的是 `stats` 行，所以它切的是**文件档**，不动屏幕。
  **我们自己的探针在 normal 档一行都不写**（自检、共存检测走 `DialSelf` 的连接）：它们是仪器不是
  业务 —— 与“不进连接列表、不计累计、不进顶栏流量图”同一条原则；开机一串 `proc=nethub.exe`
  的 `intercept`/`relay.done` 会被当成“应用在连”（2026-10-14 用户报的），要看就切 verbose。
- **诊断页的「接管状态」卡是仪表盘，不是日志**（用户明确要求：“不能看起来像是另类的日志”）：
  只放当前值（在不在 / 几个 / 几百）+ 胶囊/状态点，没有时间戳、不追加行、原地更新；
  唯一的原文进折叠区且展开时才取。异常判据是纯函数 `engine.statusWarnings`，
  `runtime_test.go` 逐条钉住 —— 它定义的是“打开诊断页看到红色意味着什么”，不能靠记。
- **自己发的探针不当应用流量**：自检 / 与其它代理共存检测会**直接 dial** 内网目标（那些地址本来就在
  我们的接管网段里）→ 会被自己的过滤器接住，变成一条 `nethub.exe` 的连接。凡是这种探针
  一律用 `Engine.DialSelf`（connect 之前就把本地端口登记好）→ 不进连接列表、不计累计。
  用 `net.DialTimeout` 直连就是错的（用户报过“纯误导”）。
- **界面上的“活跃”含直连与阻断**（`Engine.ConnsActive`，与列表一致）；而“累计/各链累计”只算走隧道的
  （`statTotal/statPerRule`）。两个口径不同是故意的，但必须在界面上标清楚（连接页的「i」里写了）。
- **开关类设置改完要立刻重画受影响的视图**：`直连流量统计` / `QUIC 阻断` 直接决定列表里有没有
  这一类连接，等轮询会让界面短暂自相矛盾（`refreshAfterToggle`）。关掉直连统计时，
  靠它才可见的直连条目要**立即**从列表消失（`connState.statsOnly`）。
- **「统计」卡（在连接页里，按应用/按目标）与连接列表是两个问题，别让两边长成对方**：
  列表 = “现在有哪些连接”（实时、15 秒就消失）；统计 = “这段时间谁在占通道”（累计、可清零）。
  它是**卡片不是页签**（用户 2026-10-16 拍板：页签带不该长）。
  口径**只有一个：累计**（本程序启动以来）—— 2026-10-16 去掉了「本次运行/累计」那个切换：
  引擎 Start 时清的那一档是**全界面唯一**不同起点的数字（链页累计、顶栏流量图都是进程起算），
  留着就是“同一件事两个数”。同理卡上的**「时长」= 这组数字覆盖了多久**，不是程序跑了多久。
  后端 `StatsPage(scope)` 仍认两档（有用例钉住），界面只问 all。
  数据靠两条腿：连接**收尾时**落累计桶（`finish` 与 janitor 回收两条路，幂等靠 `st.ended` 的 CAS
  —— 否则同一条连接的字节被算两次），**还开着的**在读取时实时算进去（否则 8 小时的长会话永远是 0）。
  目标按**名字**归并（`nameOf`，它同时认假 IP 与“应用拿真实 IP 连过来”那种）——
  **不要用 `connState.fakeName`**：那个字段在包路径上无锁写，读它就是数据竞争。
  桶上限 512 但合计单独存（不随淘汰丢）；不落盘（重启前的数混进来谁也说不清是哪一段的）。
- **明确不做**：IPv6 · UDP 中继 · 多跳串联 · TUN/TAP · 域名/正则匹配 · 限速配额 · 反向端口转发 · 上游 mux。
  IPv6 是**我们主动不收**（引擎只做 IPv4，且 DNS 层把 AAAA 答空防应用绕过）—— **不是 WinDivert 的限制**，
  它的网络层同时管 v4/v6；哪天真要做就是重写拦截层，不是“打开一个开关”。
- **上游协议是可插拔的**（本批扩到 ws/wss 传输 + ss 传统/2022 + trojan + vless + vmess）：
  加协议 = **新写一个文件 + `init()` 里 register**（`internal/upstream/protocol.go` 的注册表），
  engine / config **一个字不用改**；`contract_test.go` 那 6 条契约会自动覆到新协议头上。
  同一个 scheme 下的分支（如 `ss` 的**传统与 2022 两套线格式**）在协议自己的文件里按加密方式名
  分发（`proto_ss.go` + `internal/ss/{conn.go,ss2022.go}`，公共的 chunk 流在 `stream.go`）。
  两处容易写错的公共东西单独成文件，别在各协议里重写：
  **传输层** `transport.go`（TCP → [TLS] → [ws]；`+tls/+ws/+wss` 只认两段，≥3 段直接拒）、
  **地址编码** `addr.go`（A 族 SOCKS5 风格：ATYP|ADDR|PORT，域名 0x03；
  B 族 xray 风格：**PORT|AT|ADDR**，域名 **0x02** —— 两族的端口位置与域名码都不同）。
- **上游协议必须与真实现对测**（`interop_test.go`）：ws/tls/ss 用 `local/bin/gost.exe`，
  trojan/vless/vmess/**ss2022** 用 `local/bin/xray.exe`（gost 没有 trojan/vless/vmess 服务端，
  **也不支持 ss2022** —— 实测 `cipher not supported`；这条 KB 里曾记错）；文件不在就 skip，
  所以别人 clone 下来 `go test` 不会红。**别自己写个“照规范的”假服务端来测** ——
  那只会把“我读规范理解错了”照抄一遍（两边一起错、测试全绿、上线连不上）。
  自己的假服务端只能用来构造**真服务端不会给的坏输入**（钉报错文案），见 `internal/ss/ss2022_test.go`。
- **系统配置红线（新增功能前先过一遍）**：**不得**要求“改路由表 / 抢系统代理 / 写注册表新键”。
  现在碰系统的只有三处，别再添：WinDivert 驱动服务条目（内核驱动的唯一注册方式）·
  hosts 文件（可选、可关、停就撤）· 计划任务（**GUI 形态的自启方式**，用户自己开）。

## 构建与运行

```bash
export PATH="/c/Program Files/Go/bin:$PATH"                 # git-bash
gofmt -l . | grep -v '^local/'                              # 空即合规；**别只扫 internal/**（仓库根 main.go 也改）
go vet ./... && go test ./internal/...
go build -tags production -ldflags "-H=windowsgui -s -w" -o run/nethub.exe .
pwsh -NoProfile -File ./local/check-ui.ps1                  # 改完前端必须跑（boot 不报错 + 无未定义函数 + **结构断言**：标签成对 / tab↔页面一一对应 / main 下无孤儿）
pwsh -NoProfile -File ./local/ui-controls-test.ps1          # 勾选/下拉真的调到了后端 + 卡片标题不被挤成两行
pwsh -NoProfile -File ./local/tray-fix.ps1                   # 托盘回归（**需管理员**）：换 exe+重启，验「X 收进托盘→托盘能叫回」+「强杀引擎不留孤儿界面」
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
