$ErrorActionPreference='Continue'
$log='C:\Users\Administrator\Desktop\NetHub\verify-after-reboot.log'
Remove-Item $log -EA SilentlyContinue
function W($m){ $m|Out-File $log -Append -Encoding utf8; }

W "########## 重启后验证 ##########"
$os = Get-CimInstance Win32_OperatingSystem
W ("系统启动时间: " + $os.LastBootUpTime + "  （已运行 " + [math]::Round(((Get-Date)-$os.LastBootUpTime).TotalMinutes,1) + " 分钟）")

W "`n== 1) 驱动服务状态 =="
$o = & sc.exe query WinDivert 2>&1 | Out-String
W (($o.Trim()))

W "`n== 2) 尝试启动驱动服务 =="
$s = & sc.exe start WinDivert 2>&1 | Out-String
W ("  " + ($s.Trim() -replace "`r?`n"," / "))
Start-Sleep -Seconds 2
$q = & sc.exe query WinDivert 2>&1 | Out-String
W (($q -split "`n" | Where-Object { $_ -match 'STATE' }) | ForEach-Object { "  " + $_.Trim() })

W "`n== 3) 清掉旧进程，启动 nethub.exe =="
Get-Process nethub -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 2
Remove-Item 'C:\Users\Administrator\Desktop\NetHub\nethub.log' -EA SilentlyContinue
Start-Process 'C:\Users\Administrator\Desktop\NetHub\nethub.exe' -EA SilentlyContinue
Start-Sleep -Seconds 8

W "`n== 4) nethub 进程 =="
$p = Get-Process nethub -EA SilentlyContinue
if ($p) { $p | ForEach-Object { W ("  PID=" + $_.Id) } } else { W "  !! nethub 没起来" }

W "`n== 5) nethub.log =="
if (Test-Path 'C:\Users\Administrator\Desktop\NetHub\nethub.log') {
    Get-Content 'C:\Users\Administrator\Desktop\NetHub\nethub.log' -Encoding UTF8 | ForEach-Object { W ("  " + $_) }
} else { W "  没有日志" }

W "`n== 6) 内网目标连通性 =="
$targets = @(
  @{h='10.0.1.10'; p=5432;  n='PostgreSQL (DBHub)'},
  @{h='10.0.1.11'; p=6446;  n='MySQL (DBHub)'},
  @{h='10.0.0.11'; p=5000;  n='Navicat'},
  @{h='10.0.0.10'; p=443;   n='业务系统'},
  @{h='10.0.0.12'; p=9056;  n='内部 API'},
  @{h='192.168.100.10'; p=80;   n='公卫'}
)
foreach ($t in $targets) {
    $c = New-Object Net.Sockets.TcpClient
    $ok = $false
    try { $iar=$c.BeginConnect($t.h,$t.p,$null,$null); $ok=$iar.AsyncWaitHandle.WaitOne(5000,$false) -and $c.Connected } catch {}
    $c.Close()
    W ("  " + $t.h.PadRight(16) + ":" + $t.p.ToString().PadRight(6) + $t.n.PadRight(20) + $(if($ok){'REACHABLE'}else{'unreachable'}))
}
W "`n########## 完 ##########"
