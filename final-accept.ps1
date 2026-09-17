# 最终验收：连通性 + 真实数据 + 公网对照 + gost 崩溃自愈（提权运行）
$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\NetHub'
$log  = Join-Path $root 'final-accept.log'
Remove-Item $log -ErrorAction SilentlyContinue
function Say($m) { $m | Out-File -FilePath $log -Append -Encoding utf8 }
function Probe($ip, $port, $ms = 6000) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($ms, $false)) { $c.EndConnect($iar); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}

Say "=== 最终验收 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

Say "`n[1] 进程与监听"
Get-Process nethub -EA SilentlyContinue | ForEach-Object { Say "  nethub PID=$($_.Id)  窗口='$($_.MainWindowTitle)'  启动于 $($_.StartTime.ToString('HH:mm:ss'))" }
$g = Get-Process gost -EA SilentlyContinue
Say "  gost 子进程数 = $(@($g).Count)  PID=$(($g | ForEach-Object { $_.Id }) -join ',')"
netstat -ano | Select-String ':1080\s|:1081\s' | Where-Object { $_ -match 'LISTENING' } | ForEach-Object { Say ("  " + $_.Line.Trim()) }

Say "`n[2] 内网目标（6 个）"
$intra = @(@('10.0.1.10',5432,'DBHub PostgreSQL (proxy-a)'),
           @('10.0.1.11',6446,'DBHub MySQL (proxy-a)'),
           @('10.0.0.11',5000,'Navicat (proxy-a)'),
           @('10.0.0.10',443 ,'业务系统 app.example.com (proxy-a)'),
           @('10.0.0.12',9056,'内部 API (proxy-a)'),
           @('192.168.100.10',80 ,'site-b.example.com (proxy-b)'))
$okCount = 0
foreach ($t in $intra) {
    $r = Probe $t[0] $t[1]
    if ($r) { $okCount++ }
    Say ("  {0,-22} {1,-12} {2}" -f "$($t[0]):$($t[1])", $(if ($r) {'REACHABLE'} else {'unreachable'}), $t[2])
}
Say "  => $okCount/6"

Say "`n[3] 真实数据穿透（MySQL 8.0.41 握手包）"
try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('10.0.1.11', 6446); $s = $c.GetStream(); $s.ReadTimeout = 6000
    $b = New-Object byte[] 128
    $n = $s.Read($b, 0, 128)
    $txt = -join ($b[0..($n-1)] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
    Say "  OK 收到 $n 字节: $txt"
    $c.Close()
} catch { Say "  FAIL: $($_.Exception.Message)" }

Say "`n[4] 内部 API 真实 HTTP 响应 (10.0.0.12:9056)"
try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('10.0.0.12', 9056); $s = $c.GetStream(); $s.ReadTimeout = 8000
    $req = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: 10.0.0.12:9056`r`nConnection: close`r`n`r`n")
    $s.Write($req, 0, $req.Length); $s.Flush()
    $sr = New-Object IO.StreamReader($s)
    $head = @()
    for ($i = 0; $i -lt 12; $i++) { $l = $sr.ReadLine(); if ($l -eq $null) { break }; $head += $l }
    $head | ForEach-Object { Say "  $_" }
    $c.Close()
} catch { Say "  FAIL: $($_.Exception.Message)" }

Say "`n[5] 公网对照组（必须全通 = 没误伤）"
$inet = @(@('www.baidu.com',443),@('mirrors.aliyun.com',443),@('223.5.5.5',53))
$iok = 0
foreach ($t in $inet) { $r = Probe $t[0] $t[1]; if ($r) { $iok++ }; Say ("  {0,-30} {1}" -f "$($t[0]):$($t[1])", $(if ($r) {'REACHABLE'} else {'unreachable'})) }
Say "  => $iok/3"

Say "`n[6] 故障自愈：强杀一个 gost 子进程"
$victim = Get-Process gost -EA SilentlyContinue | Select-Object -First 1
if ($victim) {
    $oldPid = $victim.Id
    $victim.Kill()
    Say "  已强杀 gost PID=$oldPid，等待守护进程拉起…"
    $respawned = $false
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 2
        $now = Get-Process gost -EA SilentlyContinue
        if (@($now).Count -ge 2 -and -not ($now | Where-Object { $_.Id -eq $oldPid })) {
            Say "  +$($i*2)s 已恢复：gost PID=$(($now | ForEach-Object { $_.Id }) -join ',')"
            $respawned = $true; break
        }
    }
    if (-not $respawned) { Say "  !! $((15*2))s 内未恢复" }
    Start-Sleep -Seconds 4
    Say "  重启后连通性抽查:"
    foreach ($t in @(@('10.0.1.10',5432),@('192.168.100.10',80))) {
        Say ("    {0,-22} {1}" -f "$($t[0]):$($t[1])", $(if (Probe $t[0] $t[1]) {'REACHABLE'} else {'unreachable'}))
    }
} else { Say "  无 gost 子进程可杀" }

Say "`n[7] Proxifier 清场复核"
Say "  安装目录存在: $(Test-Path 'C:\Program Files (x86)\Proxifier')"
Say "  驱动文件存在: $(Test-Path 'C:\Windows\System32\drivers\ProxifierDrv.sys')"
$s = Get-Service ProxifierDrv -EA SilentlyContinue
Say "  驱动服务: $(if ($s) { $s.Status } else { '已不存在' })"
Say "  Run 键 Proxifier: $(if ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue).Proxifier) { '仍在' } else { '无' })"
Say "  旧 bat 已停用: $(Test-Path 'C:\Users\Administrator\Desktop\gost\gost-proxy-a.bat.disabled') / $(Test-Path 'C:\Users\Administrator\Desktop\gost\gost-proxy-b.bat.disabled')"

Say "`n[8] 日志尾部"
$f = Join-Path $root 'nethub.log'
if (Test-Path $f) { Get-Content $f -Encoding UTF8 | Select-Object -Last 12 | ForEach-Object { Say "  $_" } }
Say "=== done ==="
