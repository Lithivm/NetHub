param(
    # 连通性检查目标，host:port[:名字]。仓库默认空 —— 不把客户地址写进代码。
    [string[]]$Targets = @()
)
$ErrorActionPreference='Continue'
$repo = Split-Path -Parent $PSScriptRoot
$log = Join-Path $repo 'verify-after-reboot.log'
$logpath = Join-Path (Join-Path $repo 'run') 'logs\nethub.log'
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
Remove-Item $logpath -EA SilentlyContinue
Start-Process (Join-Path (Join-Path $repo 'run') 'nethub.exe') -EA SilentlyContinue
Start-Sleep -Seconds 8

W "`n== 4) nethub 进程 =="
$p = Get-Process nethub -EA SilentlyContinue
if ($p) { $p | ForEach-Object { W ("  PID=" + $_.Id) } } else { W "  !! nethub 没起来" }

W "`n== 5) nethub.log =="
if (Test-Path $logpath) {
    Get-Content $logpath -Encoding UTF8 | ForEach-Object { W ("  " + $_) }
} else { W "  没有日志" }

W "`n== 6) 内网目标连通性 =="
$probe = @($Targets | Where-Object { $_ } | ForEach-Object {
    $p = $_ -split ':', 3
    @{ h = $p[0]; p = [int]$(if ($p[1]) { $p[1] } else { 443 })
       n = $(if ($p.Count -gt 2 -and $p[2]) { $p[2] } else { $p[0] }) }
})
if ($probe.Count -eq 0) { W "  （未提供 -Targets，跳过）" }
foreach ($t in $probe) {
    $c = New-Object Net.Sockets.TcpClient
    $ok = $false
    try { $iar=$c.BeginConnect($t.h,$t.p,$null,$null); $ok=$iar.AsyncWaitHandle.WaitOne(5000,$false) -and $c.Connected } catch {}
    $c.Close()
    W ("  " + $t.h.PadRight(16) + ":" + $t.p.ToString().PadRight(6) + $t.n.PadRight(20) + $(if($ok){'REACHABLE'}else{'unreachable'}))
}
W "`n########## 完 ##########"
