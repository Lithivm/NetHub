# NetHub 端到端验收（提权运行）
#   1) 清掉旧 bat 起的 gost
#   2) 无界面启动 NetHub
#   3) 内网目标连通性 + 真实数据穿透（MySQL 握手包 / 内部 API HTTP）
#   4) 强杀 NetHub，验证 gost 子进程不残留（Job Object 生效）
$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\NetHub'
$log  = Join-Path $root 'e2e.log'
Remove-Item $log -ErrorAction SilentlyContinue
function Say($m) { $m | Out-File -FilePath $log -Append -Encoding utf8 }

Say "=== NetHub 端到端验收  $(Get-Date -Format 'HH:mm:ss') ==="
Say ("管理员: " + (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Say "`n--- 0) 停用 Proxifier（我们要替代它，去掉干扰变量）---"
Get-Process Proxifier -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill(); Say "  kill Proxifier PID=$($_.Id)" } catch {} }
Start-Sleep -Seconds 1
$q = (& sc.exe query ProxifierDrv 2>&1 | Out-String)
if ($q -match 'STATE') {
    Say "  ProxifierDrv: " + (($q -split "`n" | Select-String 'STATE').ToString().Trim())
    Say "  " + ((& sc.exe stop ProxifierDrv 2>&1 | Out-String).Trim())
    Say "  " + ((& sc.exe delete ProxifierDrv 2>&1 | Out-String).Trim())
} else {
    Say "  ProxifierDrv: 未安装"
}

Say "`n--- 1) 清理旧 gost（两个 .bat 起的）---"
Get-Process gost -ErrorAction SilentlyContinue | ForEach-Object {
    Say "  kill gost PID=$($_.Id)（启动于 $($_.StartTime)）"
    try { $_.Kill() } catch { Say "    失败: $($_.Exception.Message)" }
}
Start-Sleep -Seconds 2

Say "`n--- 2) 启动 NetHub -headless ---"
Remove-Item (Join-Path $root 'nethub.log') -ErrorAction SilentlyContinue
$p = Start-Process -FilePath (Join-Path $root 'nethub.exe') -ArgumentList '-headless' `
    -PassThru -WindowStyle Hidden
Say "  PID=$($p.Id)"

# 等就绪
$ready = $false
for ($i = 1; $i -le 25; $i++) {
    Start-Sleep -Seconds 1
    if ($p.HasExited) { Say "  !! 进程退出 exitCode=$($p.ExitCode)"; break }
    $f = Join-Path $root 'nethub.log'
    if ((Test-Path $f) -and (Get-Content $f -Raw -Encoding UTF8 -ErrorAction SilentlyContinue) -match '服务已就绪') {
        Say "  ✓ 就绪（耗时约 ${i}s）"; $ready = $true; break
    }
}
if (-not $ready -and -not $p.HasExited) { Say "  ⚠ 等待超时，继续测连通性" }

Say "`n--- 3a) 内网目标连通性 ---"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'porttest.ps1') |
    ForEach-Object { Say "  $_" }

Say "`n--- 3b) 真实数据：MySQL 握手包 (10.0.1.11:6446) ---"
try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('10.0.1.11', 6446)
    $s = $c.GetStream(); $s.ReadTimeout = 5000
    $buf = New-Object byte[] 128
    $n = $s.Read($buf, 0, 128)
    $ascii = -join ($buf[0..([Math]::Min($n,64)-1)] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
    Say "  ✓ 收到 $n 字节: $ascii"
    $c.Close()
} catch { Say "  ✗ $($_.Exception.Message)" }

Say "`n--- 3c) 真实数据：内部 API HTTP (10.0.0.12:9056) ---"
try {
    $c = New-Object Net.Sockets.TcpClient
    $c.Connect('10.0.0.12', 9056)
    $s = $c.GetStream(); $s.ReadTimeout = 5000
    $req = "GET / HTTP/1.0`r`nHost: 10.0.0.12:9056`r`nConnection: close`r`n`r`n"
    $b = [Text.Encoding]::ASCII.GetBytes($req)
    $s.Write($b, 0, $b.Length); $s.Flush()
    $buf = New-Object byte[] 128
    $n = $s.Read($buf, 0, 128)
    $line = (-join ($buf[0..($n-1)] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })) -split "`r?`n" | Select-Object -First 1
    Say "  ✓ $line"
    $c.Close()
} catch { Say "  ✗ $($_.Exception.Message)" }

Say "`n--- 3d) 对照组：公网应保持直连（不经我们）---"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'porttest-internet.ps1') |
    ForEach-Object { Say "  $_" }

Say "`n--- 4) 强杀 NetHub，验证子进程回收 ---"
if (-not $p.HasExited) { $p | Stop-Process -Force }
Start-Sleep -Seconds 3
$left = Get-Process gost -ErrorAction SilentlyContinue
if ($left) {
    Say "  ✗ 残留 gost: " + (($left | ForEach-Object { $_.Id }) -join ',')
} else {
    Say "  ✓ 无 gost 残留 —— Job Object 生效"
}
Say ("  relay 端口是否释放: " + $(if ((netstat -ano | Select-String ':1080 .*LISTENING')) { '1080 仍在监听!' } else { '1080 已释放' }))

Say "`n--- nethub.log 尾部 ---"
$f = Join-Path $root 'nethub.log'
if (Test-Path $f) {
    Get-Content $f -Encoding UTF8 -Tail 45 | ForEach-Object { Say "  $_" }
} else { Say "  (无日志文件)" }
Say "`n=== done ==="
