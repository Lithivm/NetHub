# netproxy —— 内网隧道透明代理

替代 **Proxifier + 两个 gost .bat**：一个进程管链路（gost 子进程）、一个驱动管拦截（WinDivert）、
一个界面管规则。

**核心特点：应用零改动。** 不管是浏览器、Navicat、DBHub(node)、PostgreSQL/MySQL 客户端还是
业务客户端，都不需要配代理 —— 拦截发生在内核层，只有目标落在内网网段的 TCP 连接会被劫持。

界面是 **Wails + WebView2**（手写 HTML/CSS/JS，不需要 npm），设计规范见 [`DESIGN.md`](DESIGN.md)。

---

## 1. 目录里哪些文件是必须的

| 文件 | 必须 | 说明 |
|---|---|---|
| `netproxy.exe` | ✅ | 主程序（约 12.5 MB，前端已内嵌） |
| `config.yaml` | ✅ | 配置（**含上游凭据，不要外传/入库**） |
| `WinDivert.dll` | ✅ | WinDivert 运行库 |
| `WinDivert64.sys` | ✅ | WinDivert 内核驱动 |
| `netproxy.ico` | ⚠️ | 托盘图标；缺了就用系统默认图标 |
| `netproxy.log` | ❌ | 运行日志，自动生成，可随时删 |
| `*.ps1` / `*.log` | ❌ | 测试脚本和历史输出，可删 |

> **整个文件夹可以随便挪位置、改名。** 程序启动时会检查驱动服务里登记的 `.sys` 路径，
> 发现是旧路径会自动重建服务。

---

## 2. 日常使用

### 启动
- **开机自动启动**：已注册计划任务 `netproxy`（登录后延迟 20 秒启动）。
  用「计划任务 + 最高权限」而不是注册表 Run 键，是为了**静默拿到管理员权限、不弹 UAC**。
- **手动启动**：双击 `netproxy.exe`（会弹一次 UAC，因为要装/加载内核驱动）。
- 程序起来后会**自动拉起服务**，不需要再点一次。

### 界面
四个标签页：

| 页 | 内容 |
|---|---|
| **运行日志** | 实时日志（含 gost 自己的连接日志）+ 链路自检 + 打开日志目录 |
| **隧道链路** | ≈ Proxifier 的 **Proxy Servers**。增删改排序；可从旧 `.bat` 导入 |
| **路由规则** | ≈ Proxifier 的 **Rules**。目标网段 → 走哪条链，可增删改排序 |
| **设置** | gost 托管 / hosts 接管 / 开机自启 / 文件位置 |

右上角可切 **深色 / 浅色**（会记住，写进 `config.yaml` 的 `ui.theme`）。

**点右上角 × = 最小化到托盘，服务继续跑。** 真退出用托盘右键 → 退出。

### 托盘
双击托盘图标唤回窗口；右键菜单有 显示主界面 / 启动服务 / 停止服务 / 退出。
服务级事件（启动完成、链路异常）会弹**系统通知**（Win10/11 的标准通知，会进操作中心）。

---

## 3. 配置文件 `config.yaml`

```yaml
relay: 127.0.0.1:0        # relay 监听地址；端口写 0 = 自动分配（推荐）

chains:                   # 每条链 = 一个 gost 子进程
  - name: proxy-a             # 链名（下面 routes 里引用）
    listen: 127.0.0.1:1080 # gost -L 监听地址（也是 relay 的出口）
    forward: socks5+tls://IP:PORT?auth=XXXX   # gost -F 上游（凭据在这里）
    note: 内网主体链路        # 备注，随便写
  - name: proxy-b
    listen: 127.0.0.1:1081
    forward: socks5+tls://IP:PORT?auth=XXXX
    note: 192.168.100.*

routes:                   # 目标网段 → 走哪条链（按顺序匹配，命中即止）
  - target: 10.0.0.0/24    # CIDR 或单个 IP（单 IP 会自动存成 /32）
    chain: proxy-a
  - target: 10.0.1.0/24
    chain: proxy-a
  - target: 192.168.100.0/24
    chain: proxy-b

gost:
  enabled: true           # false = 假定 gost 已经在外面跑着，我们不起子进程
  exe: C:\Users\Administrator\Desktop\gost\gost.exe

hosts:
  manage: false           # true = 由我们维护 hosts 里的标记区块（默认关）
  entries:
    - 10.0.0.10 app.example.com
    - 10.0.0.10 opm.example.com
    - 192.168.100.10 site-b.example.com
    - 192.168.100.10 site-c.example.com

ui:
  theme: light            # light | dark
```

改配置**界面里改就行**（编辑即时保存），或手改 yaml 再重启程序。
注意 `hosts.manage` / `gost.enabled` / `relay` 这几项要**重启服务**才生效。

---

## 4. 排障

| 症状 | 先看什么 |
|---|---|
| 内网连不上 | 界面「运行日志」。正常应看到 `内核过滤器: (...)` 和 `引擎已接管` |
| gost 起不来 | `gost.exe` 路径对不对、1080/1081 是否被别的进程占着 |
| 程序起来了但没拦到 | 是不是没管理员权限（日志会有 `当前不是管理员权限` 警告） |
| 驱动加载失败 | 日志会有 `打开失败(第 N/6 次)`。自动重试 + `sc start WinDivert` 兜底 |
| 想单独验证链路 | 界面「链路自检」：它绕过内核拦截，直接从 gost 的 socks5 口往外连 |
| 有一堆窗口在闪 | 不该发生。若出现，说明某处 `exec` 漏了 `internal/winrun`（见 DESIGN.md） |

命令行自检：
```powershell
powershell -ExecutionPolicy Bypass -File porttest.ps1            # 内网 6 个目标
powershell -ExecutionPolicy Bypass -File porttest-internet.ps1   # 公网对照（必须全通）
powershell -ExecutionPolicy Bypass -File clash-check.ps1         # 与 Clash 的共存判定（只读）
powershell -ExecutionPolicy Bypass -File final-accept.ps1        # 端到端全量验收（需管理员）
```

---

## 5. 卸载 / 回退

```powershell
netproxy.exe -no-autostart   # 移除开机自启
# 退出程序后整个文件夹删掉即可
# 驱动残留（可选，需要管理员）：
sc stop WinDivert
sc delete WinDivert
```

**退回 Proxifier**：安装包在 `C:\Users\Administrator\Desktop\gost\新建文件夹\ProxifierSetup.exe`。
旧脚本改名保留了：`gost-proxy-a.bat.disabled` / `gost-proxy-b.bat.disabled`（改回 `.bat` 即可用）。
退回前记得先 `netproxy.exe -no-autostart` 并退出，否则两边会抢 1080/1081 端口和驱动层拦截。

**退回 govcl 界面**：旧的原生界面代码保留在 `cmd/govcl-gui/`（配合 `internal/gui/`）。
把它的 `main.go` 放回根目录、换掉 `internal/webui` 的调用即可，引擎部分完全不用动。

---

## 6. 与 Clash 共存（实测结论）

netproxy 不改变系统代理设置，也不动路由表，所以**在“谁写什么”这个层面上不会和 Clash 打架**。
真正的冲突点只有一个：**谁负责把内网域名解析成内网 IP**。

### 先把分层说清楚

我们的拦截在**最后一跳**：不管哪个进程最终发起对内网 IP 的 TCP 连接，只要目标落在拦截网段里就会被接管。
所以下面两类东西**天然不受 Clash 影响**：

- 业务客户端、Navicat、DBHub(node)、任何直接读 hosts 的程序 → 自己解析成 `10.0.0.10` → 被我们接管
- Clash 自己（例如你让它去访问一个内网 IP）→ 它发出的连接也会被我们接管

**唯一会坏的是浏览器跟随系统代理（PAC）的情况**：浏览器把**域名**（不是 IP）交给 Clash，
而 **Clash 用自己的 DNS 解析、看不到系统的 hosts 文件**，于是它永远到不了内网。
此时我们的内核拦截救不了 —— 那时候命中过滤器的只是“Clash → 某个公网地址”这条连接。

### 实测证据（本机 2026-09-17，Clash 开着 PAC）

```
系统代理状态: ProxyEnable=0  AutoConfigURL=http://127.0.0.1:33331/commands/pac   ← PAC 模式

浏览器那条路的判定（.NET 的 GetSystemWebProxy，与浏览器同一套逻辑）:
  http://app.example.com/    -> 走代理 127.0.0.1:7897      ← 内网域名没被排除

同一目标两种解析方式:
  Clash 解析域名  (--socks5-hostname) -> TLS/连接失败     ← 它解析不到内网 IP
  直连（= 我们接管）                    -> HTTP 200，连接 IP=10.0.0.10  ✓

内网 6 个目标: 6/6 REACHABLE ✓
```

**结论**："内网和 ChatGPT 都通"是错觉 —— 你的 业务系统 走的是不走代理的那条路（应用直读 hosts）；
一旦用浏览器跟随 PAC 访问 `app.example.com`，就会失败。

### 关于 `ProxyOverride` 绕过列表

注册表里那份绕过列表（含 `10.*`、`10.0.*`）**只在普通系统代理模式下生效**（`ProxyEnable=1` + `ProxyServer`）。
**PAC 模式下 WinINET 不看它**，去向完全由 PAC 脚本决定——这就是上面内网域名被交给代理的原因。

### 该怎么配

| 模式 | 能开吗 | 说明 |
|---|---|---|
| **TUN** | ❌ **绝对不要** | `auto-route` 会写 `0.0.0.0/1` + `128.0.0.0/1` 默认路由，把 `10.x`/`172.30.x` 一起吞掉，还有 DNS 劫持 |
| **PAC** | ❌ 对内网必坏 | 绕过列表在此模式下**完全不生效**，内网域名被交给 Clash 解析 → 必坏 |
| **普通系统代理** | ⚠️ 可用，但有条件 | 绕过列表生效，但见下面的"IP 与域名的区别" |
| **浏览器不走代理** | ✅ 最稳 | 用扩展/独立浏览器配置只给需要的站点走 Clash，完全不碰系统代理 |

**不管选哪种，判据只有一条：内网请求不能经过 Clash 的 DNS。**

### IP 与域名的区别（重要）

`ProxyOverride` 的绕过条目**匹配的是主机名字符串，不是 IP 网段**：

```
绕过列表含 10.* / 10.0.* 时：
  http://10.0.1.10/   -> DIRECT 直连   ✓
  http://10.0.0.10/   -> DIRECT 直连   ✓
  http://app.example.com/   -> 走代理        ✗  ← 域名匹配不到 10.0.*
```

所以**内网用 IP 访问在系统代理模式下是通的，用域名访问仍然坏**，除非绕过列表里补上域名条目。

> ⚠️ **域名通配符的匹配语义尚未实测确认。**
> 用 .NET 的 `System.Net.WebProxy` 模拟时，`*.example.com` 这种写法直接抛异常
> （`限定符 {x,y} 前没有任何内容`），说明 .NET 与 WinINET 是两套不同实现，
> **不能拿它给 WinINET 的行为下结论**。要确认必须切到系统代理模式后跑 `clash-check.ps1`。

### 更稳的思路

**别依赖绕过列表的细节。** 把内网请求完全排除在 Clash 之外（或浏览器不走系统代理），
而不是指望 WinINET 去正确区分内外网。理由：我们的拦截在**最后一跳**，
只要"应用自己按 hosts 解析并直连"就一定能工作，绕过列表的任何匹配差异都不会再影响它。

### 一键判定

```powershell
powershell -ExecutionPolicy Bypass -File clash-check.ps1
```

它会（只读，不改任何设置）报出系统代理模式、浏览器对几个域名的判定、
"Clash 解析域名"与"直连"的对比结果，以及内网 6 个目标的可达性。
**第 3 节 (a) 失败而 (b) 成功 = 问题在 Clash 的 DNS，不在路由。**

### 其他两条约束

- **不要同时用 Proxifier**：两套驱动层拦截会互相干扰。
- **`config.yaml` 含上游凭据**（`auth=` 是 `用户:口令` 的 base64），已加入 `.gitignore`，不要贴到聊天/文档/仓库里。

---

## 7. 从源码构建

需要 Go 1.21+（本项目用 `C:\Users\Administrator\go-sdk\go`）。

```bash
export PATH="/c/Users/Administrator/go-sdk/go/bin:$PATH"
export GOPROXY="https://goproxy.cn,direct"
export GOSUMDB=off
cd /c/Users/Administrator/Desktop/netproxy
go mod tidy
go build -tags production -ldflags "-H=windowsgui -s -w" -o netproxy.exe .
```

**`-tags production` 是必需的** —— 不带它 Wails 会在启动时弹
`Wails applications will not build without the correct build tags`。

不需要 wails CLI，也不需要 npm：前端是手写的 `frontend/`，用 `//go:embed` 嵌进 exe，
bindings 由 Wails 在运行时从 `options.Bind` 自动生成。
加 `-H=windowsgui` 是不要黑框；调试时去掉它，日志才会打到控制台。

命令行参数：
```
netproxy.exe                     # 正常：带界面
netproxy.exe -headless           # 无界面，只跑引擎（自动化测试用）
netproxy.exe -config D:\x.yaml   # 指定配置文件
netproxy.exe -import-bats "C:\Users\Administrator\Desktop\gost"  # 从旧 bat 导入链路，然后退出
netproxy.exe -autostart          # 装开机自启（计划任务），然后退出
netproxy.exe -no-autostart       # 移除开机自启，然后退出
netproxy.exe -no-elevate         # 不自动提权（调试）
```

重新生成托盘图标：`go run tools_mkicon.go netproxy.ico`

---

## 8. 实现要点（改代码前必读）

**为什么是驱动级拦截而不是 PAC**：PostgreSQL/MySQL 协议、Navicat、DBHub(node) 都不认
系统代理/环境变量/SOCKS。只有内核层透明接管才能一次覆盖全部且应用零改动。

**WinDivert 两个不能改的地方（实测踩出来的）**：
1. 改写目标地址时**必须把源 IP 也改成 relay 的 IP**（`127.0.0.1`）。
   否则 Windows 在环回口丢弃"非环回源地址"的包，劫持会静默失败。
2. 注入时**必须保留** `addr.Flags` 的 Outbound 位，翻转它就失效。

**首次加载驱动会失败一次**：报 `Insufficient system resources ... (1450)`，
紧接着 `sc start WinDivert` 就成功。所以 `openDivert` 里是重试 6 次 + 兜底启动。

**驱动路径会自愈**：`ensureDriverPath` 检查服务里登记的 `.sys` 是否在当前目录，不符就重建服务。

**gost 是"每条链一个进程"**：gost 2.x 的命令行**不按位置配对** `-L`/`-F`，
多个 `-F` 会被拼成一条链（`1080 → proxy-a → proxy-b → 目标`），内网直接超时。所以一条链一个进程。

**子进程回收靠 Job Object**（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）：
主程序被强杀时 gost 子进程也跟着死，不会留下孤儿占着端口。

**所有外部命令必须走 `internal/winrun`**：本程序是 GUI 子系统、没有自己的控制台，
直接 `exec.Command` 调 `schtasks`/`sc` 会**每次弹一个控制台窗口**。
落在轮询路径上就会变成"窗口一直闪还抢焦点，打不了字"（实际踩过）。
同理 `GetState()` 里不许跑外部进程，`schtasks` 结果要缓存。

**托盘是手写 Win32**：`Shell_NotifyIconW` + 自己一条锁定的 OS 线程跑消息循环
（不用 systray 库，它自己的消息泵会跟 Wails 抢）。

**代码结构**：
```
main.go                          组装、单实例、自动提权、计划任务自启、headless
frontend/                        界面（index.html / style.css / app.js，手写，无构建链）
internal/webui/backend.go        暴露给前端的 API（window.go.webui.Backend.*）
internal/webui/tray_windows.go   原生托盘 + 系统通知气泡
internal/app/app.go              启停编排（hosts → gost → 等端口 → 引擎）
internal/engine/engine.go        WinDivert 拦截、地址改写、relay、连接映射
internal/rules/rules.go          网段规则表（合并 CIDR 成区间）
internal/socks/socks.go          最小 SOCKS5 客户端（链路自检用）
internal/gostproc/               gost 子进程托管 + .bat 解析
internal/hostsmgr/               hosts 标记区块管理
internal/config/                 配置读写校验
internal/autostart/              计划任务自启
internal/winrun/                 起外部进程时隐藏控制台窗口
internal/logbus/                 日志总线（环形缓冲 + 订阅 + 落盘）
internal/gui/                    旧的 govcl 原生界面（保留未用，见 cmd/govcl-gui）
```
