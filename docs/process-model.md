# 进程模型：界面与引擎为什么必须分开

> 上位：[AGENTS.md](../AGENTS.md)（红线、构建命令、其他块都在那里）。这页只展开「两进程」这一块。

`nethub.exe` 后端 + `nethub.exe -frontend` 前端，通信见 `internal/ipc`。

- **为什么必须拆**：现场 HIS/医保客户端启动器清 WebView2 缓存时会**按进程名杀掉全系统所有 `msedgewebview2.exe`**，而 Wails 在浏览器进程消失后 `os.Exit(-1)` 且跳过收尾 —— 同进程就是引擎被连坐（现场："整个 NetHub 静默消失、hosts 段留在系统里没人兑付"）。拆开后被杀只影响界面，引擎/隧道/hosts 毫发无损，看护约 2 秒把界面拉回并记一条"界面进程被外部程序结束（退出码 N）"。
- **前端不读也不写配置**（配置里有上游凭据）：只给它 `-logdir`，结构上碰不到 config.yaml。
- **已知边界**：点名杀 `nethub.exe` 时后端一样会死 → 靠 SCM 失败恢复（服务形态有；**GUI/计划任务形态没有**，Task Scheduler 的 `RestartOnFailure` 对"进程被外部结束"实测不生效）→ 无人值守装服务形态。对外只承诺"杀界面不影响业务"。
- **卡死判据**：两边都用"自己名下还有几个 `msedgewebview2`"（`internal/proc.ChildrenByName`）—— `os.Process.Wait()` 的退出码不在 error 里，Wails 的报错框会等人点。
- **孤儿界面是"双击托盘没反应"的根**：引擎被强杀时界面不死（带管道 + Wails 单实例锁），之后新界面 30ms 内让位给孤儿（`single_instance.go` 走 `SendMessage` 后 `os.Exit(0)`）→ 退出码 0 被当成"用户主动退出"。所以：界面带 `-parent <引擎pid>` 起来（`watchParent`，宿主没了自己退）；看护遇退出码 0 进**待命**（`waitNudge`）而不是收工；`Show` 先试已接上的界面（`ShowMainWindow` 报错才算叫不动）再唤醒看护 —— **别用"我拉起过进程没有"当界面在不在的判据**。
