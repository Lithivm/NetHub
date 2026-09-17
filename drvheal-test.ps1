# 验证驱动路径自愈：故意破坏 binPath，看程序是否自动重建（提权运行）
$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\netproxy'
$exe  = Join-Path $root 'netproxy.exe'
$log  = Join-Path $root 'drvheal-test.log'
Remove-Item $log -ErrorAction SilentlyContinue
function Say($m) { $m | Out-File -FilePath $log -Append -Encoding utf8 }
function DrvPath { $l = (& sc.exe qc WinDivert 2>$null | Select-String 'BINARY_PATH_NAME'); if ($l) { ($l.Line -split ':',2)[1].Trim() } else { '(服务不存在)' } }

Say "=== 驱动路径自愈验证 $(Get-Date -Format 'HH:mm:ss') ==="

Say "`n[1] 停程序，破坏驱动服务路径"
Get-Process netproxy -EA SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
Start-Sleep -Seconds 3
& sc.exe stop WinDivert 2>$null | Out-Null
Start-Sleep -Seconds 2
& sc.exe config WinDivert binPath= '\??\C:\BOGUS-PATH-DOES-NOT-EXIST\WinDivert64.sys' | Out-Null
Say "  破坏后 binPath = $(DrvPath)"

Say "`n[2] 由计划任务拉起程序（模拟用户挪了文件夹后的开机启动）"
Remove-Item (Join-Path $root 'netproxy.log') -ErrorAction SilentlyContinue
& schtasks.exe /run /tn 'netproxy' | Out-Null
for ($i = 1; $i -le 15; $i++) { Start-Sleep -Seconds 2; if (Get-Process netproxy -EA SilentlyContinue) { Say "  +$($i*2)s 程序已启动"; break } }
Start-Sleep -Seconds 8

Say "`n[3] 自愈结果"
Say "  binPath = $(DrvPath)"
$s = Get-Service WinDivert -EA SilentlyContinue
Say "  服务状态 = $(if ($s) { $s.Status } else { '不存在' })"

Say "`n[4] 连通性"
foreach ($tp in @(@('10.0.1.10',5432),@('10.0.0.10',443),@('192.168.100.10',80))) {
    $c = New-Object Net.Sockets.TcpClient
    try { $iar = $c.BeginConnect($tp[0], $tp[1], $null, $null)
          if ($iar.AsyncWaitHandle.WaitOne(6000, $false)) { $c.EndConnect($iar); Say "  $($tp[0]):$($tp[1])  REACHABLE" }
          else { Say "  $($tp[0]):$($tp[1])  unreachable(timeout)" }
    } catch { Say "  $($tp[0]):$($tp[1])  unreachable($($_.Exception.Message))" } finally { $c.Close() }
}

Say "`n[5] 日志里的自愈痕迹"
$f = Join-Path $root 'netproxy.log'
if (Test-Path $f) {
    $hits = Get-Content $f -Encoding UTF8 | Select-String '旧路径|重建|WinDivert|内核过滤器|已接管'
    if ($hits) { $hits | ForEach-Object { Say "  " + $_.Line } } else { Say "  (无相关日志)" }
} else { Say "  (无日志)" }
Say "=== done ==="
