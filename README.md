# netproxy —— 内网隧道透明代理

替代 **Proxifier + 两个 gost .bat**：一个进程管链路（gost 子进程）、一个驱动管拦截（WinDivert）、
一个原生界面管规则和日志。

**核心特点：应用零改动。** 不管是浏览器、Navicat、DBHub(node)、PostgreSQL/MySQL 客户端还是
业务客户端，都不需要配代理 —— 拦截发生在内核层，只有目标落在内网网段的 TCP 连接会被劫持。

---

## 1. 目录里哪些文件是必须的

| 文件 | 必须 | 说明 |
|---|---|---|
| `netproxy.exe` | ✅ | 主程序（约 9.5 MB） |
| `config.yaml` | ✅ | 配置（**含上游凭据，不要外传/入库**） |
| `WinDivert.dll` | ✅ | WinDivert 运行库 |
| `WinDivert64.sys` | ✅ | WinDivert 内核驱动 |
| `netproxy.log` | ❌ | 运行日志，自动生成，可随时删 |
| `*.ps1` / `*.log` | ❌ | 测试脚本和历史输出，可删 |

> **整个文件夹可以随便挪位置、改名。** 程序启动时会检查驱动服务里登记的 `.sys` 路径，
> 发现是旧路径会自动重建服务（实测：故意指到一个不存在的路径，启动后自动修回当前目录）。

---

## 2. 日常使用

### 启动
- **开机自动启动**：已注册计划任务 `netproxy`（登录后延迟 20 秒启动）。
  用「计划任务 + 最高权限」而不是注册表 Run 键，是为了**静默拿到管理员权限、不弹 UAC**。
- **手动启动**：双击 `netproxy.exe`（会弹一次 UAC，因为要装/加载内核驱动）。

### 界面
顶部三个按钮 + 三个标签页：
- **启动 / 停止**：拉起或停掉 gost 子进程和内核拦截。启动/停止/重启的结果会以**系统托盘气泡通知**弹出来。
- **运行日志**：实时日志（含 gost 自己的连接日志）。排障先看这里。
- **路由规则**：哪个网段走哪条链。
- **隧道链路**：每条链的本地监听地址和上游。

**关窗口 = 最小化到托盘**（不退出）。真正退出用托盘右键 → 退出，或托盘双击唤回窗口。

### 托盘
托盘图标双击唤回窗口；右键菜单有 显示窗口 / 启动 / 停止 / 重启 / 退出。
拉起服务和出现异常时会弹**系统通知（气球）**，不是自绘弹窗。

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
  - target: 10.0.0.0/24    # CIDR 或单个 IP
    chain: proxy-a
  - target: 10.0.1.0/24
    chain: proxy-a
  - target: 192.168.100.0/24
    chain: proxy-b

gost:
  enabled: true           # false = 假定 gost 已经在外面跑着，我们不起子进程
  exe: C:\Users\Administrator\Desktop\gost\gost.exe
  # extraArgs: []         # 追加到 gost 命令行的参数，一般留空

hosts:
  manage: false           # true = 由我们维护 hosts 里的标记区块（默认关）
  entries:
    - 10.0.0.10 app.example.com
    - 10.0.0.10 opm.example.com
    - 192.168.100.10 site-b.example.com
    - 192.168.100.10 site-c.example.com
```

**规则按目标 IP/网段匹配，不看域名。** 因为 业务系统 域名已经在系统 hosts 里解析成内网 IP 了，
所以不需要解析 SNI、也不需要嗅探 DNS —— 问题因此小很多。

改完 config.yaml 后点界面上的「重启」生效（或重启程序）。

### hosts 由谁维护
`manage: false` 时**完全不动你的 hosts**，你自己手改（现状就是这样，一直能用）。
想让我们管，改成 `true`：会在 hosts 里插入一对标记注释围起来的区块，
重复的条目无害（hosts 允许重复），原来的手写行不受影响。首次修改会备份成 `hosts.netproxy.bak`。

---

## 4. 排障

| 症状 | 先看什么 |
|---|---|
| 内网连不上 | 界面「运行日志」。正常应看到 `内核过滤器: (...)` 和 `引擎已接管` |
| 日志里 gost 起不来 | `gost.exe` 路径对不对、1080/1081 是否被别的进程占着 |
| 程序起来了但没拦到 | 是不是没管理员权限（日志会有 `当前不是管理员权限` 警告） |
| 驱动加载失败 | 日志会有 `打开失败(第 N/6 次)`。自动重试 + `sc start WinDivert` 兜底 |
| 想确认网段是否被拦 | `netstat -ano \| findstr :1080`，有连到 127.0.0.1:1080 的就说明在走隧道 |

命令行自检：
```powershell
# 内网目标可达性（6 个目标）
powershell -ExecutionPolicy Bypass -File porttest.ps1
# 公网对照（必须全通，说明没误伤）
powershell -ExecutionPolicy Bypass -File porttest-internet.ps1
```

---

## 5. 卸载 / 回退

```powershell
# 移除开机自启
netproxy.exe -no-autostart

# 退出程序后，整个文件夹删掉即可。
# 驱动残留（可选清理，需要管理员）：
sc stop WinDivert
sc delete WinDivert
```

**退回 Proxifier**：安装包还在 `C:\Users\Administrator\Desktop\gost\新建文件夹\ProxifierSetup.exe`。
旧的两个 gost 脚本改名保留了：`gost-proxy-a.bat.disabled` / `gost-proxy-b.bat.disabled`
（改回 `.bat` 即可用）。退回前记得先 `netproxy.exe -no-autostart` 并退出，
否则两边会抢 1080/1081 端口和驱动层拦截。

---

## 6. 必须遵守的外部约束

- **Clash Verge 不要开 TUN，也不要开"系统代理"开关。**
  开 TUN 的 `auto-route` 会写 `0.0.0.0/1` + `128.0.0.0/1` 默认路由，把 `10.x`/`172.30.x`
  的内网流量也一起吞掉；"系统代理"会占用唯一的 WinINET `AutoConfigURL`。
- **不要同时用 Proxifier**：两套驱动层拦截会互相干扰（实测 WinDivert 加载后 Proxifier 就失效）。
- **`config.yaml` 含上游凭据**（`auth=` 是 `用户:口令` 的 base64）：不要贴到聊天/文档/仓库里。
  已加入 `.gitignore`。

---

## 7. 从源码构建

需要 Go 1.21+（本项目用 `C:\Users\Administrator\go-sdk\go`）。

```bash
export PATH="/c/Users/Administrator/go-sdk/go/bin:$PATH"
export GOPROXY="https://goproxy.cn,direct"
export GOSUMDB=off
cd /c/Users/Administrator/Desktop/netproxy
go mod tidy
go build -tags "tempdll hideversion" -ldflags "-H=windowsgui -s -w" -o netproxy.exe .
```

- `tempdll`：govcl 的 liblcl 运行时从 `%TEMP%\liblcl\<crc32>` 释放，不落一堆 DLL 在程序目录。
- `hideversion`：不打印 govcl 的版本横幅（**不叫** `initdonnotprintversion`）。
- 加 `-H=windowsgui` 是不要黑框；调试时去掉它，panic 才会打到控制台。

有界面/无界面两种跑法：
```bash
netproxy.exe                    # 正常：带界面
netproxy.exe -headless          # 无界面，只跑引擎（自动化测试用）
netproxy.exe -config D:\x.yaml  # 指定配置文件
netproxy.exe -import-bats "C:\Users\Administrator\Desktop\gost"   # 从旧 bat 导入链路，然后退出
netproxy.exe -no-elevate        # 不自动提权（调试）
```

---

## 8. 实现要点（改代码前必读）

**为什么是驱动级拦截而不是 PAC**：PostgreSQL/MySQL 协议、Navicat、DBHub(node) 都不认
系统代理/环境变量/SOCKS。PAC 方案当初以为"只有浏览器需要"是错的，只有内核层透明接管
才能一次覆盖全部且应用零改动。

**WinDivert 两个不能改的地方（实测踩出来的）**：
1. 改写目标地址时**必须把源 IP 也改成 relay 的 IP**（`127.0.0.1`）。
   否则 Windows 在环回口丢弃"非环回源地址"的包，劫持会静默失败。
2. 注入时**必须保留** `addr.Flags` 的 Outbound 位，翻转它就失效。

**首次加载驱动会失败一次**：报 `Insufficient system resources exist to complete the requested
service (1450)`，紧接着 `sc start WinDivert` 就成功。所以 `openDivert` 里是重试 6 次 + 兜底启动。

**gost 是"每条链一个进程"**：gost 2.x 的命令行**不会**按位置配对 `-L`/`-F`，
多个 `-F` 会被拼成一条链（`1080 → proxy-a → proxy-b → 目标`），内网直接超时。
所以每条链单独起一个进程，各自 `-L socks5://… -F …`。

**子进程回收靠 Job Object**（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）：
主程序被强杀（任务管理器结束进程）时，gost 子进程也会跟着死，不会留下孤儿进程占着端口。

**govcl 的坑**：`Application.CreateForm` 会用反射**新建一个 form 实例**并改写你的指针
（见 `vcl/resform.go` 的 `newGoFormInstance`），你塞进结构体的字段会被丢掉。
所以构造期共享状态一律走包级变量（见 `internal/gui/gui.go` 的 `theApp`）。

**代码结构**：
```
main.go                      组装、单实例、自动提权、计划任务自启、headless
internal/gui/gui.go          govcl 界面 + 托盘 + 气泡通知
internal/app/app.go          启停编排（hosts → gost → 等端口 → 引擎）
internal/engine/engine.go    WinDivert 拦截、地址改写、relay、连接映射
internal/rules/rules.go      网段规则表（合并 CIDR 成区间）
internal/socks/socks.go      最小 SOCKS5 客户端
internal/gostproc/           gost 子进程托管（一链一进程、守护、Job Object）
internal/hostsmgr/           hosts 标记区块管理
internal/config/             配置读写校验
internal/logbus/             日志总线（环形缓冲 + 订阅 + 落盘）
```
