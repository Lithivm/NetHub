# 开发说明 —— 构建、打包、实现要点与踩坑记录

> 这是给改代码的人看的文档。用户请读 [使用说明](使用说明.md)。

---

## 分发目录里有哪些文件

| 文件 | 必须 | 说明 |
|---|---|---|
| `nethub.exe` | ✅ | 主程序（约 12.6 MB，前端已内嵌） |
| `config.yaml` | ✅ | 配置（**含上游凭据，不要外传/入库**） |
| `WinDivert.dll` | ✅ | WinDivert 运行库 |
| `WinDivert64.sys` | ✅ | WinDivert 内核驱动 |
| `nethub.ico` | ⚠️ | 托盘图标；缺了就用系统默认图标 |
| `assets/logo.png` | ─ | **logo 源图**（仅构建时用；`tools_mkicon.go` 从它生成 ico） |
| `nethub.syso` | ─ | **exe 图标资源**（构建时必需，否则 exe 没图标；已入库） |
| `config.yaml.example` | ─ | 配置模板（占位符、无凭据）；复制成 `config.yaml` 再改 |
| `nethub.log` | ❌ | 运行日志，自动生成，可随时删 |
| `nethub-256.png` | ❌ | 图标预览图，由 `tools_mkicon.go` 顺带生成 |
| `gost.exe` / `gost-*.bat` | ❌ | **不再需要**（导入完配置就可以删） |
| `dist/` | ❌ | 打包产物（分发用），不进 git |
| `*.ps1` / `*.log` | ❌ | 本机的运维/打包脚本与历史输出：`.ps1` 一律不入库（都放在 `local/`，已 gitignore） |

> **整个文件夹可以随便挪位置、改名。** 程序启动时会检查驱动服务里登记的 `.sys` 路径，
> 发现是旧路径会自动重建服务。

---


## 从源码构建

需要 Go 1.21+（官方 zip 解压或 MSI 安装均可；Windows 下标准位置是 `C:\Program Files\Go`）。

```bash
（把 Go 的 bin 目录加进 PATH 即可）
export GOPROXY="https://goproxy.cn,direct"
export GOSUMDB=off
cd <仓库目录>
go mod tidy
go build -tags production -ldflags "-H=windowsgui -s -w" -o nethub.exe .
```

**`-tags production` 是必需的** —— 不带它 Wails 会在启动时弹
`Wails applications will not build without the correct build tags`。

不需要 wails CLI，也不需要 npm：前端是手写的 `frontend/`，用 `//go:embed` 嵌进 exe，
bindings 由 Wails 在运行时从 `options.Bind` 自动生成。
加 `-H=windowsgui` 是不要黑框；调试时去掉它，日志才会打到控制台。

命令行参数：
```
nethub.exe                     # 正常：带界面
nethub.exe -headless           # 无界面，只跑引擎（自动化测试用）
nethub.exe -config D:\x.yaml   # 指定配置文件
nethub.exe -import-bats "D:\旧脚本目录"  # 从旧 gost .bat 导入链路（只取 -F），然后退出
nethub.exe -test-upstream      # 实测原生上游链路（真发 HTTP 请求），不需管理员
nethub.exe -clash-check        # 与 Clash 的共存检测，不需管理员
nethub.exe -autostart          # 装开机自启（计划任务），然后退出
nethub.exe -no-autostart       # 移除开机自启，然后退出
nethub.exe -no-elevate         # 不自动提权（调试）
```

重新生成图标（改了 logo 就重跑这两条）：

```bash
# 1) 从 logo 源图生成多尺寸 ico（Lanczos3 缩放 + 自动裁剪）
go run tools_mkicon.go assets/logo.png nethub.ico
# 2) 生成 exe 资源文件，把图标嵌进 exe（任务栏/Alt-Tab 用的是它）
rsrc -ico nethub.ico -arch amd64 -o nethub.syso
```

`nethub.syso` 是 Go 链接器会自动拾取的资源文件（同目录下任何 `*.syso`），
**生成一次后要留着** —— 没有它 exe 就没有图标资源，任务栏显示系统默认图标。
`rsrc` 的安装：`go install github.com/akavel/rsrc@latest`。

> 图标里 16/20/24/32/40/48/64 是 **DIB** 条目、128/256 是 **PNG** 条目。
> 不能全用 PNG：Windows Shell 认 PNG 条目，但 **GDI+（`System.Drawing.Icon`）、
> 部分老工具和安装程序读不了**，会渲染成彩色噪点。这是 Windows SDK 自己的做法。

---


## 打包

```powershell
nethub.exe -autostart          # 注册开机自启（计划任务，静默提权、不弹 UAC）
nethub.exe -no-autostart       # 取消开机自启
```

仓库里**只放 NetHub 本体**：打包、快捷方式、各类验收脚本都是本机用的，
放在 `local/`（已 gitignore，不入库）。

`dist/` 是“拿到就能跑”的集合（exe + ico + WinDivert + 许可证 + 配置模板 + 使用说明 + README），
**不含任何配置与日志**；它不进 git（里面是二进制产物）。

同目录会额外生成 **`dist/NetHub.zip`**（约 5 MB）—— 归档里带一层 `NetHub/` 目录，
对方解压不会把文件撒一地，可直接发出去。

> 打 zip 时手动修正了 .NET 的两个不合规（本机打包脚本里的 `Fix-ZipEntryNames`）：
> 1. **没设 UTF-8 文件名标志**（通用位 11 = 0x0800）。`ZipFile.CreateFromDirectory`
>    即使传了 `UTF8Encoding`，名字字节按 UTF-8 写但不设标志位 —— 读的一方按旧代码页
>    （中文机器上是 GBK）解释，`使用说明.txt` 会显示成乱码。
>    ⚠️ flags 是 2 字节小端：低字节在偏移 8，高字节在 9；bit11 要改的是**偏移 9 的 0x08**。
> 2. **用反斜杠做路径分隔符**（`NetHub\file`）。zip 规范要求正斜杠，
>    部分工具（Info-ZIP `unzip`）会警告甚至解压失败。
>
> （注：Info-ZIP `unzip 6.00` 不支持 UTF-8 标志位，在它下面看中文名仍是乱码 ——
> 那是它的限制，Windows 资源管理器 / 7-Zip / .NET 解压都正常。）

三个脚本的路径都从**自身所在目录**推导，所以整个文件夹拷到任何地方都能用。

---


## 实现要点

**为什么是驱动级拦截而不是 PAC**：PostgreSQL/MySQL 协议、Navicat、DBHub(node) 都不认
系统代理/环境变量/SOCKS。只有内核层透明接管才能一次覆盖全部且应用零改动。

**WinDivert 两个不能改的地方（实测踩出来的）**：
1. 改写目标地址时**必须把源 IP 也改成 relay 的 IP**（`127.0.0.1`）。
   否则 Windows 在环回口丢弃"非环回源地址"的包，劫持会静默失败。
2. 注入时**必须保留** `addr.Flags` 的 Outbound 位，翻转它就失效。

**1450 不是“首次加载的正常现象”（早期本文档写错过）**：它写着“资源不足”，但内存池是健康的。
真实原因只有两个：① 安全软件拦了驱动加载（见开头的「首次使用前必做」）② 反复加载/卸载留下的驱动残留状态（重启系统恢复）。

因此 `openDivert` 的顺序是：**先直接 Open，成功了就绝不碰驱动服务**；
失败才在路径确实不符时重建服务（`sc stop` → **轮询等它真的 STOPPED** → `sc delete` → **再等它真的消失**）。
早期版本用固定 `Sleep(600ms)` 赌，会在驱动还挂在内核里时就删服务，留下残留状态，之后一律 1450 —— 这个 bug 已修。

**驱动路径会自愈**：`driverPathMatches` 只在 **Open 失败之后**才去比对服务里登记的 `.sys` 是否在当前目录，
不符才重建服务；不在启动路径上无脑动驱动服务。

**上游是原生实现，不跑 gost**：`internal/upstream` 在 Go 里完成 TLS + RFC1929 SOCKS5 认证 + CONNECT。
原来那条链是 `relay → 本地 gost(SOCKS5) → TLS → 上游`，现在直接 `relay → TLS → 上游`：
少一个外部依赖、少一跳本地握手、没有子进程要托管。旧的 gost `.bat` 可导入（脚本里的 `-F` 就是上游 URL），
`internal/gostbat` 只负责解析它，**不启动 gost**。

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
internal/app/app.go              启停编排（hosts → 引擎）
internal/engine/engine.go        WinDivert 拦截、地址改写、relay、连接映射
internal/rules/rules.go          网段规则表（合并 CIDR 成区间）
internal/socks/socks.go          最小 SOCKS5 客户端（支持 RFC1929 认证与 TLS）
internal/upstream/                上游连接原生实现（socks5 / socks4 / http CONNECT + TLS）
internal/gostbat/                 只解析旧 gost .bat（导入用，不启动 gost）
internal/hostsmgr/               hosts 标记区块管理
internal/config/                 配置读写校验
internal/autostart/              计划任务自启
internal/winrun/                 起外部进程时隐藏控制台窗口
internal/logbus/                 日志总线（环形缓冲 + 订阅 + 落盘）
```

---


## 与 Clash 共存：实测证据

NetHub 不改变系统代理设置，也不动路由表，所以**在“谁写什么”这个层面上不会和 Clash 打架**。
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
> **不能拿它给 WinINET 的行为下结论**。要确认必须切到系统代理模式后跑 `nethub.exe -clash-check`。

### 更稳的思路

**别依赖绕过列表的细节。** 把内网请求完全排除在 Clash 之外（或浏览器不走系统代理），
而不是指望 WinINET 去正确区分内外网。理由：我们的拦截在**最后一跳**，
只要"应用自己按 hosts 解析并直连"就一定能工作，绕过列表的任何匹配差异都不会再影响它。

### 一键判定

```powershell
nethub.exe -clash-check
```

它会（只读，不改任何设置）报出系统代理模式、以及每个内网目标会不会被交给代理，
并在界面的「与 Clash 共存」卡片里给出结论。
**第 3 节 (a) 失败而 (b) 成功 = 问题在 Clash 的 DNS，不在路由。**

### 其他两条约束

- **不要同时用 Proxifier**：两套驱动层拦截会互相干扰。
- **`config.yaml` 含上游凭据**（`auth=` 是 `用户:口令` 的 base64），已加入 `.gitignore`，不要贴到聊天/文档/仓库里。

---

