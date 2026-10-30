# 截某个进程的主窗口（按进程名）—— 现场排查用：要看的是"那个窗口现在长什么样"。
# 用法: pwsh -NoProfile -File local/tmp-shotwindow.ps1 -Proc DF.HIS.Launcher -Out C:\tmp\dfhis.png
param(
  [Parameter(Mandatory = $true)][string]$Proc,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinShot {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
"@
$p = Get-Process -Name $Proc -ErrorAction SilentlyContinue |
  Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $p) { Write-Output "找不到带窗口的进程 $Proc"; exit 1 }
[void][WinShot]::ShowWindow($p.MainWindowHandle, 9)     # SW_RESTORE
[void][WinShot]::SetForegroundWindow($p.MainWindowHandle)
Start-Sleep -Milliseconds 900
$r = New-Object WinShot+RECT
[void][WinShot]::GetWindowRect($p.MainWindowHandle, [ref]$r)
$w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
if ($w -le 0 -or $h -le 0) { Write-Output "窗口尺寸异常: ${w}x${h}"; exit 1 }
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output ("已截图 {0}（{1}x{2}）→ {3}" -f $p.ProcessName, $w, $h, $Out)
