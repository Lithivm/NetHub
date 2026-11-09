# 日志三档（Normal / Verbose / Debug）

> 上位：[AGENTS.md](../AGENTS.md)。这页只展开日志这一块。三档照抄 Proxifier。

运行日志页三段滑块 `normal | verbose | debug`（`ui.log_level`，默认 normal）。

- **分档内容**：normal 只写连接 open/close、直连/阻断、启停、配置变更、上游状态翻转与错误（连接行形如 `open: chrome.exe (8804) → main.example.com(192.0.2.217):80 via site-a`，**命中哪条规则不进这行**）；verbose 加判定面（`route.match`、DNS 请求与应答、`upstream.pick`、`conn.stage` 分段耗时、`direct.done`、`stats` 周期快照）；debug 加内部面（名字表/假 IP 池、内核层、规则表编译、过滤器原文、装配细节），且**切到 debug 时立刻 `Engine.DumpState`**（那些内容本来只在启动写，不转储就等于"只有重启才看得到"）。诊断包功能已删：要交现场材料就发 `nethub.log`。
- **分档靠自觉 + 测试钉住**（`internal/engine/loglevel_test.go`）：新增日志行先问"这一行回答'发生了什么'还是'为什么'"；被去重的重复项补 `suppressed: count=N`。
- **排查入口在用到它的那一页**：连接页右上角「详细日志」开关（点一下就是 verbose，不用跳去日志页）；两个控件管同一档，改完互相同步（`updateVerboseToggle`）。
- **档位持久化，算"本机偏好"**（`config.LocalPrefs`）：重启保持；`-apply`/导入/回滚/`deploy.ps1` 都不许打回 normal —— 任何新加的"整份配置替换"路径都要调 `KeepLocalPrefsFrom`；启动打一行档位、`-status` 报 `logLevel`。
- **屏幕与文件是两个档**（`Bus.SetLevels`）：`ui.log_level` 管界面（环形缓冲/订阅者）、`ui.log_level_file` 管 `logs/nethub.log`（空 = 跟随）。`Detail`/`Debug` 的门槛是"**任一 sink 达档**" → "屏幕 normal + 文件 verbose"合法（现场最常用）。`tools/memwatch.ps1` 采 `stats` 行，切的是**文件档**。
- **我们自己的探针在 normal 档一行都不写**（自检、共存检测走 `DialSelf`）：仪器不是业务 —— 与"不进连接列表、不计累计、不进顶栏流量图"同一条原则。开机一串 `proc=nethub.exe` 的 `intercept`/`relay.done` 会被当成"应用在连"（用户报过）。
