# AGENTS.md —— NetHub

## 技术栈

Go + **Wails v2**（WebView2 界面）+ **WinDivert**（内核驱动），**仅 Windows x64**。
界面 `frontend/`：无框架、无构建步骤（`index.html` / `app.js` / `style.css`）；界面文案是**中文**，
用户是运维/实施人员（不是开发者），写人话、别堆术语。
后端 `internal/`：`app`（编排 Start/Stop/Restart）· `config`（读写/校验/体检/重叠）· `rules`（匹配）·
`engine`（relay / 包循环 / 连接表 / 探测 / 预热池 / 抓包）· `upstream` + `socks`（上游客户端）·
`webui`（界面 API / 托盘 / 诊断包）· `secret`（DPAPI 保险箱）· `winsvc`（Windows 服务）。

## 设计初衷：替代现场的「Proxifier + 两个 gost .bat」

- **按目标 IP/CIDR + 端口判定**，不按进程 —— 现场不用"每来一个新程序就配一次"；进程只作可选**例外**条件。
- **应用零改动**：内核层拦包改写，不抢系统代理、不动路由表 —— 客户机装一个 exe 就能访问内网业务。
- **上游转发自带**（SOCKS5 / SOCKS4 / HTTP(S)，可 +TLS），不再依赖外部 gost 进程与 `.bat` 脚本。
- 规则**自上而下、命中即止**（顺序即语义，排序只由用户按钮触发）；`direct` / `block` 是保留链名，不是真实链。
- **明确不做**：UDP 中继 · 多跳串联 · TUN/TAP · 域名/正则匹配 · 限速配额 · 反向端口转发 · 上游 mux。

## 构建与运行

```bash
export PATH="/c/Program Files/Go/bin:$PATH"                 # git-bash
go build -tags production -ldflags "-H=windowsgui -s -w" -o run/nethub.exe .
go test ./internal/...
pwsh -NoProfile -File ./local/check-ui.ps1                  # 改完前端必须跑
pwsh -NoProfile -File ./local/restart.ps1                   # 优雅重启 + 复测内网目标
./run/nethub.exe -check | -status | -headless | -quit      # 只读控制面，给脚本与 agent 用
```

---

其余一律不写在这里（避免每个会话重复注入）：做法与判据 `KB:规则/代理/` · 坑 `KB:教训/` ·
为什么这样定 `KB:决策/` · 存证 `KB:产物/nethub/` · 用户文档 `README.md`（怎么用）与 `DESIGN.md`（界面规范）。
只有三份 md：`README.md` · `DESIGN.md` · 本文件 —— 别的**不要新建**，该进代码注释就进注释，该进 `git log` 就进 commit message。
