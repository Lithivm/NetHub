$ErrorActionPreference='Continue'
$log='C:\Users\Administrator\Desktop\NetHub\reload.log'
Remove-Item $log -EA SilentlyContinue
function W($m){ $m|Out-File $log -Append -Encoding utf8 }

W "== 停掉旧进程 =="
Get-Process nethub -EA SilentlyContinue | ForEach-Object { W ("  停 PID=" + $_.Id); $_ | Stop-Process -Force -EA SilentlyContinue }
Start-Sleep -Seconds 3

W "`n== 启动新构建的 nethub.exe =="
Remove-Item 'C:\Users\Administrator\Desktop\NetHub\nethub.log' -EA SilentlyContinue
Start-Process 'C:\Users\Administrator\Desktop\NetHub\nethub.exe'
Start-Sleep -Seconds 10

$p = Get-Process nethub -EA SilentlyContinue
W ("  进程: " + $(if($p){"PID=" + $p.Id}else{"!! 没起来"}))

W "`n== nethub.log =="
if (Test-Path 'C:\Users\Administrator\Desktop\NetHub\nethub.log') {
    Get-Content 'C:\Users\Administrator\Desktop\NetHub\nethub.log' -Encoding UTF8 | ForEach-Object { W ("  " + $_) }
} else { W "  没有日志" }

W "`n== 驱动服务 =="
$q = & sc.exe query WinDivert 2>&1 | Out-String
W (($q -split "`n" | Where-Object { $_ -match 'STATE' }) | ForEach-Object { "  " + $_.Trim() })

W "`n== 内网目标 =="
foreach ($t in @(@{h='10.0.1.10';p=5432},@{h='10.0.1.11';p=6446},@{h='10.0.0.11';p=5000},
                @{h='10.0.0.10';p=443},@{h='10.0.0.12';p=9056},@{h='192.168.100.10';p=80})) {
    $c = New-Object Net.Sockets.TcpClient
    $ok=$false
    try { $iar=$c.BeginConnect($t.h,$t.p,$null,$null); $ok=$iar.AsyncWaitHandle.WaitOne(5000,$false) -and $c.Connected } catch {}
    $c.Close()
    W ("  " + $t.h.PadRight(16) + ":" + $t.p.ToString().PadRight(6) + $(if($ok){'REACHABLE'}else{'unreachable'}))
}
