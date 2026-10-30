# 托盘「打不开界面」的端到端验证（**必须管理员**：要起提权引擎、要动窗口）。
#
# 验的是用户在 2026-10-19 报的那条路：
#   点 X 收进托盘  →  双击托盘图标  →  窗口必须回来
# 走的是产线上的真路径：第二次启动 nethub.exe = RequestShowWindow 信号 → 引擎的
# WatchShowSignal → frontendSupervisor.Show() → ShowMainWindow（走管道请界面把窗口露出来）。
# 所以这里不直接调 Win32 的 ShowWindow —— 那样验证不到我们自己的代码。
$ErrorActionPreference = 'Continue'
$root = Join-Path (Split-Path -Parent $PSScriptRoot) 'run'
$log  = Join-Path $root 'tray-fix.log'
Remove-Item $log -EA SilentlyContinue
function Say($m) { $line = "$(Get-Date -Format 'HH:mm:ss') $m"; $line | Out-File $log -Append -Encoding utf8; Write-Host $line }

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class TW {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  public static IntPtr FindWails(uint target) {
    IntPtr found = IntPtr.Zero;
    EnumWindows(delegate(IntPtr h, IntPtr l) {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != target) return true;
      var cn = new StringBuilder(64); GetClassName(h, cn, 64);
      if (cn.ToString() == "wailsWindow") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$exe = Join-Path $root 'nethub.exe'
$nlog = Join-Path $root 'logs\nethub.log'
$new  = Join-Path $root 'nethub.exe.new'

# ── 停：先优雅让旧引擎收尾（撑 hosts / 清 runtime.json），剩下的（孤儿界面）强杀
if (Get-Process nethub -EA SilentlyContinue) {
  Say "已经有 nethub 在跑，先停掉"
  try { & $exe -quit | Out-Null } catch {}
  Start-Sleep 3
  Get-Process nethub -EA SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
}

# ── 有新 exe 就换上（运行中的 exe 不能覆盖，所以必须先停）
if (Test-Path $new) {
  Copy-Item $exe (Join-Path $root 'nethub.exe.bak-prev') -Force
  Move-Item $new $exe -Force
  Say "已换成新 exe（$((Get-Item $exe).Length) 字节）"
}

Remove-Item $nlog -EA SilentlyContinue
$p = Start-Process $exe -PassThru
Say "已启动 PID=$($p.Id)"

# ── 等界面接入
$ok = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  if ((Get-Content $nlog -Encoding UTF8 -EA SilentlyContinue) -match '界面已接入') { $ok = $true; break }
}
if (-not $ok) { Say '!! 20 秒内界面没接上引擎'; (Get-Content $nlog -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 20 | ForEach-Object { Say "  LOG $_" }; exit 1 }

# 界面窗口 = 有 wailsWindow 的那个 nethub 进程
$frontend = $null; $hwnd = [IntPtr]::Zero
foreach ($q in (Get-Process nethub)) {
  $h = [TW]::FindWails([uint32]$q.Id)
  if ($h -ne [IntPtr]::Zero) { $frontend = $q; $hwnd = $h }
}
if (-not $frontend) { Say '!! 界面进程起来了，但找不到它的窗口'; exit 1 }
Say "界面进程=$($frontend.Id) hwnd=$hwnd"
(Get-Content $nlog -Encoding UTF8 -EA SilentlyContinue) | Where-Object { $_ -match '界面|托盘' } | ForEach-Object { Say "  LOG $_" }
# 窗口是管道接上之后才露出来的（差 0.5～2 秒），要等，不能马上判
$shownAtStart = $false
for ($i = 0; $i -lt 30; $i++) {
  if ([TW]::IsWindowVisible($hwnd)) { $shownAtStart = $true; break }
  Start-Sleep -Milliseconds 500
}
Say "界面起来就露窗口=$shownAtStart（应为 True）"

# ── ① 点 X = 收进托盘
[void][TW]::SendMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) # WM_CLOSE
Start-Sleep -Milliseconds 1500
$hiddenOk = -not [TW]::IsWindowVisible($hwnd)
Say "① 点 X 之后：可见=$([TW]::IsWindowVisible($hwnd))（应为 False）"

# ── ② 点托盘 = 再双击一次 exe
& $exe | Out-Null
Start-Sleep -Milliseconds 3000
$vis = [TW]::IsWindowVisible($hwnd)
Say "② 点托盘之后：可见=$vis（应为 True）"
(Get-Content $nlog -Encoding UTF8 -EA SilentlyContinue) | Where-Object { $_ -match '显示界面|界面已显示|待命|让位|不再拉起' } | ForEach-Object { Say "  LOG $_" }

if (-not ($shownAtStart -and $hiddenOk -and $vis)) {
  Say "== 失败：起来可见=$shownAtStart 收起=$hiddenOk 叫回=$vis =="
  exit 1
}

# ── ③ 孤儿验证：把引擎**强杀**（模拟任务管理器 / 崩溃），界面必须自己走 ——
# 它就是 2026-10-19 那次“托盘永久点不开”的源头：孤儿占着 Wails 单实例锁，
# 之后每次拉起的界面都立刉让位并 exit 0，看护当成“用户主动退出”就此收工。
$eng = Get-Process nethub | Where-Object { $_.Id -ne $frontend.Id } | Sort-Object StartTime | Select-Object -First 1
if (-not $eng) { Say '!! 找不到引擎进程'; exit 1 }
Stop-Process -Id $eng.Id -Force
Start-Sleep 4
$orphanGone = -not (Get-Process -Id $frontend.Id -EA SilentlyContinue)
Say "③ 强杀引擎 $($eng.Id) 后 4 秒：界面已经自己退=$orphanGone（应为 True）"
(Get-Content (Join-Path $root 'logs\stderr.log') -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 3 | ForEach-Object { Say "  ERR $_" }

# ── ④ 再起一次：界面必须干净地露出来（没有被孤儿占着单实例锁）
Remove-Item $nlog -EA SilentlyContinue
$p2 = Start-Process $exe -PassThru
Say "④ 再起一次 PID=$($p2.Id)"
$again = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  if ((Get-Content $nlog -Encoding UTF8 -EA SilentlyContinue) -match '界面已接入') { $again = $true; break }
}
$h2 = [IntPtr]::Zero; $f2 = $null
foreach ($q in (Get-Process nethub -EA SilentlyContinue)) {
  $h = [TW]::FindWails([uint32]$q.Id)
  if ($h -ne [IntPtr]::Zero) { $f2 = $q; $h2 = $h }
}
$vis2 = $false
for ($i = 0; $i -lt 30; $i++) {
  if ($h2 -ne [IntPtr]::Zero -and [TW]::IsWindowVisible($h2)) { $vis2 = $true; break }
  Start-Sleep -Milliseconds 500
}
Say "④ 接入=$again 界面起来就露窗口=$vis2（都应为 True）"
(Get-Content $nlog -Encoding UTF8 -EA SilentlyContinue) | Where-Object { $_ -match '退出码 0|待命|不再拉起|让位' } | ForEach-Object { Say "  LOG $_" }

if ($orphanGone -and $again -and $vis2) { Say '== 全过：X→托盘能叫回；强杀引擎不留孤儿；再起界面正常 =='; exit 0 }
Say "== 失败：孤儿已清=$orphanGone 重启接入=$again 重启露窗=$vis2 =="
exit 1
