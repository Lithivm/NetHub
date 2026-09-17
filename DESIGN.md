---
version: 2.0
name: NetHub-design
description: NetHub 内网隧道代理的设计系统。明暗两套:浅色=中性(白底+深蓝主色#1e3a8a,产品感高对比),深色=暖黑画布+提亮蓝主色。载体是 Wails v2 + WebView2 + 手写 HTML/CSS/JS,故圆角/阴影/字体栈/动画全部原生支持。token 与 frontend/style.css 保持同步,style.css 是唯一事实来源,本文件为阅读型规范。
source: v1.1 移植自 另一个内部项目的 DESIGN.md；v2.0 随界面栈换成 Web 而重写载体章节
---

# NetHub — 设计系统

工具型桌面应用（替代 Proxifier + 两个 gost .bat），面向开发者/运维。设计目标：**信息密度优先、状态一眼可辨、长时间盯着不累**。不是营销页，不模仿任何外部品牌。

## 与原设计系统的关系

移植自 `另一个内部项目的 DESIGN.md` v1.1。**颜色 token 与间距节奏原样保留**，只改了一处颜色和承载方式：

1. **深色主色：旧主色 `#d99c96` → 提亮蓝 `#3b82f6`**（用户明确要求）。
   理由：本项目界面主体是日志与表格，色相要克制；而且"旧主色"的暖色气质属于医疗行业语境，与本工具无关。
   `#3b82f6` 与浅色主色 `#1e3a8a` **同色相（蓝）**，白字对比度 3.1:1，与原旧主色的 3.0:1 同级。
2. **深色画布从设计系统的 `#181715` 微调为 `#141312`**：让卡片（`#23211f`）与画布拉开更明显的层次，
   因为本界面大量使用嵌套卡片，层次不靠阴影（深色下几乎看不见）而靠明度差。

## 设计语言一句话

**中性画布 + 单一蓝色强调 + 字重建立层级。** 界面上任何一个蓝色像素都意味着"这是主路径 / 这是选中态"，除此以外全用中性灰阶表达。

---

## 双语言定义

### 浅色（中性语言）

白底 + **中性纯灰阶** + 深蓝主色。产品感、高对比、可长时间阅读。
灰阶**必须中性**（R=G=B），不允许掺蓝灰——一旦掺蓝，会与主色打架。

### 深色（暖黑语言）

暖黑画布（`#141312`）+ 提亮蓝主色。层次靠"**卡片比画布亮**"表达，不靠阴影。
不用纯黑（`#000`）+ 纯白（`#fff`）的极端对比，长时间看会累。

---

## 颜色 Token

> `frontend/style.css` 里的 `:root` / `[data-theme="dark"]` 是唯一事实来源，改色只改那里。

### 浅色

| token | 值 | 用途 |
|---|---|---|
| `--canvas` | `#ffffff` | 页面底色、输入框底、表格底 |
| `--canvas-soft` | `#f4f4f5` | 标题栏、 hover 底 |
| `--card` | `#ffffff` | 卡片底 |
| `--card-strong` | `#ececee` | 表头、hover 态、次级色块 |
| `--hairline` | `#dcdde1` | 1px 边框、卡片描边 |
| `--hairline-soft` | `#eeeef1` | 卡片内部分隔线 |
| `--ink` | `#0a0a0a` | 标题、卡片标题、强调文字 |
| `--body` | `#2a2a2a` | 正文 |
| `--muted` | `#707073` | 次级说明（状态栏、提示） |
| `--muted-soft` | `#a1a1a5` | 占位符、时间戳 |
| **`--primary`** | **`#1e3a8a`** | 主按钮、选中标签、当前项 |
| `--primary-hover` | `#172554` | 悬停 / 按下 |
| `--primary-soft` | `#eef2fb` | 主色的极浅底（标签、命中行） |
| `--primary-ring` | `rgba(30,58,138,.25)` | 焦点环 |
| `--on-primary` | `#ffffff` | 主色块上的文字 |
| `--success` / `--success-soft` | `#2f7d44` / `#eaf6ee` | 运行中、连通、自检通过 |
| `--warning` / `--warning-soft` | `#8a6208` / `#fbf3e2` | 需重启、配置有风险 |
| `--error` / `--error-soft` | `#b83838` / `#fbeded` | 失败、不可达 |

### 深色

| token | 值 | 用途 |
|---|---|---|
| `--canvas` | `#141312` | 页面底色 |
| `--canvas-soft` | `#1c1b19` | 标题栏底 |
| `--card` | `#23211f` | 卡片底（比画布亮 = 层次） |
| `--card-strong` | `#2c2a27` | 表头、hover 态 |
| `--hairline` | `#3a3733` | 边框 |
| `--hairline-soft` | `#2a2824` | 卡片内分隔线 |
| `--ink` | `#faf9f6` | 标题 |
| `--body` | `#ece9e4` | 正文（**保证在暖黑上高对比，这是可读性的关键**） |
| `--muted` | `#b4aea4` | 次级说明 |
| `--muted-soft` | `#8a847b` | 占位符、时间戳 |
| **`--primary`** | **`#3b82f6`** | 主按钮、选中标签（原设计是 `#d99c96` 旧主色，已改） |
| `--primary-hover` | `#60a5fa` | 悬停 / 按下 |
| `--primary-soft` | `#1c2a41` | 主色的深色底 |
| `--on-primary` | `#ffffff` | 主色块上的文字 |
| `--success` / `--warning` / `--error` | `#5abe74` / `#d4a42a` / `#e86b6b` | 语义与浅色一致，按深色画布提亮 |

**状态色两套模式语义一致**，不因模式改变含义。

---

## 字体

**浏览器原生支持字体栈回退**，所以可以直接用设计系统的完整字体栈（这是 Web 载体相对原生控件的核心优势之一）：

```css
--font-ui:   "HarmonyOS Sans SC", "Noto Sans SC", "PingFang SC",
             "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", system-ui, sans-serif;
--font-mono: "Cascadia Code", "JetBrains Mono", "Cascadia Mono", Consolas, monospace;
```

本机实际命中的是 **Noto Sans SC**（已安装）与 **Cascadia Code**。

| 用途 | 字号 | 字重 |
|---|---|---|
| 正文、按钮、状态栏 | `13px` | 400 / 600 |
| 卡片标题 | `15px` | 700 |
| 次级说明、表格单元 | `12px` | 400 / 600 |
| 日志、IP、路径、上游 URL | `11px` | 400（等宽） |

**层级靠字重不靠字号**：卡片标题与正文只差 2px，主要靠 700 字重拉开。
**数字与地址一律等宽**（`--font-mono`）—— IP、端口、PID 对齐后才扫得快。

---

## 间距与布局

**4px 网格**，token 为 `--s1`–`--s6` = `4 / 8 / 12 / 16 / 24 / 32`。

| 场景 | 值 |
|---|---|
| 窗体左右留白 | `--s4` = 16 |
| 卡片之间 | `--s3` = 12 |
| 卡片内边距 | `--s3` `--s4` |
| 卡片标题与内容之间 | `--s3` |
| 按钮之间 | `--s2` = 8 |
| 标签与输入框之间 | `--s1` = 4 |

**布局用 flex/grid，不写死像素坐标**（`height: 100%` + `flex: 1` + `min-height: 0` 是滚动容器能正常收缩的关键）。
窗口可缩放，最小 `880×560`。

圆角：`--r-card: 12px`、`--r-btn: 8px`、`--r-chip: 8px`、`--r-input: 8px`、`--r-pill: 999px`。

---

## 组件规范

### 自绘标题栏（窗口是 Frameless）

Win10 的原生标题栏本身就很"工程软件"，所以窗口设为 `Frameless`，标题栏自己画：

- 高 `36px`，底 `--canvas-soft`，下边框 `--hairline`
- 左侧：蓝渐变方块 logo（14px，圆角 4）+ `NetHub`（700）+ 灰色副标题 + 可选的「管理员」pill
- 右侧：最小化 / 最大化 / 关闭 三个方形按钮，宽 `44px`，hover 变 `--card-strong`
- 关闭按钮 hover 变 `--error` 底 + 白字；**它的行为是最小化到托盘，不是退出**（提示文案写明）
- 拖动靠 Wails 的 `-webkit-app-region: drag`

### 状态条

左侧是运行状态与实时指标，右侧是主操作。指标里的值一律等宽字体。

运行状态点：未启动 `--muted-soft`；运行中 `--success` + 一圈 22% 透明度的同色光晕；操作中 `--warning`。

### 标签条

**不是** `TabControl`，是 flex 排列的按钮：

| 状态 | 底 | 字 |
|---|---|---|
| 选中 | `--primary` | `--on-primary` |
| 未选中 | 透明 | `--muted` |
| hover | `--canvas-soft` | `--ink` |

选中的标签圆角为「上方 8px、下方 0」——与下面的内容区连成一体。
标签上可带一个计数 badge，选中时底色为 22% 白。

### 卡片

`--card` 底 + `1px --hairline` + `--r-card` + `--shadow-card`。
卡片头（标题 + 说明 + 右侧操作）与内容之间用 `--hairline-soft` 分隔。
主内容卡片用 `card-fill`（`flex: 1`）撑满剩余高度，内部滚动。

### 表格

**不是 `<table>`，是 `display: grid` 的行列表**——因为要整行对齐 + 行内放操作按钮：

- 表头行 `sticky`，底 `--card-strong`，`--fs-xs` + 700 + 大写间距
- 数据行 `min-height: 46px`，下边框 `--hairline-soft`，hover 变 `--canvas-soft`
- 序号用小圆形徽标（20px，`--card-strong` 底）
- 操作按钮放行末右对齐

列宽用 `grid-template-columns` 按内容权重分配，地址列给 `minmax(..., 1fr)` 保证长 URL 可压缩。

### 日志

等宽、`--fs-xs`、行高 1.65、`user-select: text`（唯一允许选中的区域之一）。
每行 = 时间（`--muted-soft`）+ 级别（固定宽 44px）+ 正文。
**级别用整行底色表达**：`WARN` 用 `--warning-soft`，`ERROR` 用 `--error-soft`——比只染一个词更容易扫。

### 按钮

| 变体 | 底 | 字 | 边框 |
|---|---|---|---|
| `btn-primary` | `--primary` | `--on-primary` | 无 |
| 默认（次要） | `--card` | `--body` | `--hairline` |
| `btn-ghost` | 透明 | `--muted` | 无 |
| `btn-danger` | 透明 | `--error` | 无 |

尺寸 `btn` / `btn-sm` / `btn-xs`。`:active` 下移 1px，`:focus-visible` 出 `--primary-ring` 焦点环。
禁用态 `opacity: .45`。

> **v1.1 里"按钮无法主题化"的 Known Gap 在 v2.0 已消除**——Web 载体下按钮完全可控。

### 输入框

`--canvas` 底 + `1px --hairline` + `--r-input`；聚焦时边框转 `--primary` 并出 3px `--primary-ring`。
等宽输入（IP、URL、hosts）加 `.mono`。多行（hosts 条目）用等宽 + `resize: vertical`。

### 模态框

半透明黑底 + `backdrop-filter: blur(2px)`，弹窗 `--shadow-pop` + 160ms 缩放淡入。
错误信息显示在**底部按钮左侧**（不是弹 toast），因为它属于当前表单的上下文。
`Esc` 关闭，点击遮罩不关闭（防误关丢输入）。

### 应用内提示（toast）

右下角堆叠，左边框 3px 用语义色。180ms 从右侧滑入，4.2s 后淡出。
**与系统托盘气泡并存但有分工**：toast 用于"你刚做的操作的结果"，托盘气泡用于"服务级事件"（启动完成、链路异常）。

---

## 硬规则

1. **改样式只改 `frontend/style.css`**，禁止在 HTML/JS 里写死色值。
2. **界面文字里不用 emoji**。分段用 `──`，结果用 `✓`/`✗`。
3. **间距必须落在 4px 网格上。**
4. **任何蓝色像素都必须是主色**：表示选中、激活、主路径。不允许用蓝色做装饰。
5. **IP / 端口 / PID / 路径一律等宽字体**，且可选中复制。
6. **深色模式的正文对比度必须够**：`--body` 在 `--canvas` 上要能轻松阅读，
   `--muted` 只能用于真正次要的信息，不能拿它当正文色。
7. 改完界面必须冒烟：程序能起 + 四个标签页都能切 + 日志无错误 + **两种主题都看一遍**。

---

## 实现要点（改代码前必读）

**界面栈 = Wails v2 当库用 + 手写前端。**
不需要 wails CLI，也不需要 npm：bindings 由 Wails 在运行时从 `options.Bind` 自动生成，
调用路径是 `window.go.<Go包名>.<结构体名>.<方法名>(...)`，返回 Promise。
前端资源用 `//go:embed all:frontend` 嵌进 exe。

**构建必须带 `production` 标签**：
```bash
go build -tags production -ldflags "-H=windowsgui -s -w" -o nethub.exe .
```
不带标签时 Wails 会在启动时弹一个 "Wails applications will not build without the correct build tags" 的错误框。

**所有外部命令必须走 `internal/winrun`**：
本程序是 GUI 子系统，没有自己的控制台，直接 `exec.Command` 调 `schtasks`/`sc` 会**每次弹一个控制台窗口**。
如果这个调用落在轮询路径上（界面每 1.5 秒查一次状态），就会变成"窗口一直闪还抢焦点，用户打不了字"——
这是实际踩过的 bug。`winrun.Command` 统一加了 `CREATE_NO_WINDOW`。

**同理，轮询路径里不许跑外部进程**：`GetState()` 被前端每 1.5 秒调一次，
所以 `schtasks` 查询结果必须在启动和切换时缓存（见 `Backend.refreshAutostart`）。

**托盘是手写 Win32**：`Shell_NotifyIconW` + 自己一条锁定的 OS 线程跑消息循环。
不用 systray 那类库——它们会起自己的消息泵，与 Wails 的 UI 线程互相干扰。
通知走 `NIF_INFO` 气泡，Win10/11 会渲染成标准通知并进操作中心。

**必须处理 `TaskbarCreated`**：Explorer（任务栏）重启时，**所有托盘图标都会被系统清空**，
应用必须收到这条广播消息后重新 `NIM_ADD`，否则图标永久消失（直到进程重启）。
消息号由 `RegisterWindowMessageW("TaskbarCreated")` 动态分配，**不能写死**。

**退出时必须 `NIM_DELETE`**：`Backend.Quit` 走 `tray.Remove()`，另加 `OnShutdown` 兜底。
否则图标变成孤儿 —— 会堆积在托盘的**折叠飞出面板**里，打开折叠面板看到一堆重复图标，
鼠标划过去才被系统清理掉。
（注意：进程被强杀 —— 任务管理器 / `Stop-Process -Force` —— 时来不及注销，**任何程序都会留孤儿**，
这不是产品 bug。清掉历史孤儿的办法是重启 `explorer.exe`。）

**点 X = 最小化到托盘**：靠 Wails 的 `OnBeforeClose` 返回 `true` 拦下关闭，然后 `WindowHide`。
真退出走托盘菜单的「退出」（或 `Backend.Quit`）。

**前端初始化不能一荣俱荣一损俱损**（踩过的坑）：`boot()` 里曾经是
`await Promise.all([logs, chains, routes, settings])`，而某个面板抛异常（例如引用了已被删除的 DOM 元素）
会让整个 `Promise.all` reject，后面的 `setInterval(refreshState, 1500)` **根本没注册上** ——
结果就是状态条永久冻在启动前那一帧（显示“未启动”、relay 显示 `-`），
而日志还在实时滚，看上去像“后端没上报状态”。现在改成：

- **状态轮询先注册**，再跑各面板
- 面板用 `Promise.allSettled`，失败只 toast 不阻断
- `refreshState` 不再静默 `catch(_) { return }`，失败会提示一次（否则坏掉完全看不出来）
- 取 DOM 一律走 `setChecked/setValue`（元素不存在就跳过）

---

## Known Gaps

- **无 Mica/Acrylic 背景**：需要 Win11 22621+，本机是 Win10 19045，只能 `BackdropType: None`
- **窗口外框圆角**：Win10 上无解（系统级圆角是 Win11 特性）；窗口内部的圆角全部正常
- **无视觉回归测试**：改样式后的验收靠人工，没有截图对比自动化
- **`dpr` 报告 1.25 但布局按 1:1 走**：WebView2 在 125% 缩放下报告 devicePixelRatio=1.25，
  实际 CSS 像素与物理像素近似 1:1，所以 1px 边框在物理上可能落在半个像素上（轻微发虚），不影响可用性
- **前端无构建链**：手写 HTML/CSS/JS，没有 lint/类型检查；复杂度上来后考虑加一个极简构建步骤
- **`nethub.ico` 由 `tools_mkicon.go` 生成**，不是设计稿导出；要换正式图标改那个脚本
