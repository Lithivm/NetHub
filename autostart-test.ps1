# 安装 netproxy 计划任务并实测自启链（提权运行）
$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\netproxy'
$exe  = Join-Path $root 'netproxy.exe'
$log  = Join-Path $root 'autostart-test.log'
Remove-Item $log -ErrorAction SilentlyContinue
function Say($m) { $m | Out-File -FilePath $log -Append -Encoding utf8 }

Say "=== 自启链实测 $(Get-Date -Format 'HH:mm:ss') ==="

# 1) 写入计划任务（同时由程序自己清掉旧的 HKCU\Run 值）
Say "`n[1] 安装计划任务"
$out = & $exe -no-elevate -autostart 2>&1 | Out-String
Say ("  " + $out.Trim())

Say "`n[2] 核对计划任务"
$t = Get-ScheduledTask -TaskName 'netproxy' -EA SilentlyContinue
if ($t) {
    Say "  存在: True   状态: $($t.State)"
    Say "  运行身份: $($t.Principal.UserId)  RunLevel=$($t.Principal.RunLevel)"
    Say "  触发器: " + (($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ',')
    Say "  动作: " + (($t.Actions | ForEach-Object { $_.Execute }) -join ',')
    Say "  运行时长上限: $($t.Settings.ExecutionTimeLimit)  (PT0S = 无限制)"
    Say "  电池时不启动: $($t.Settings.DisallowStartIfOnBatteries)"
    Say "`n  --- XML 关键片段 ---"
    $x = Export-ScheduledTask -TaskName 'netproxy'
    $x -split "`n" | Where-Object { $_ -match 'RunLevel|ExecutionTimeLimit|Delay|DisallowStartIfOnBatteries|MultipleInstances|Command|WorkingDirectory' } |
        ForEach-Object { Say ("    " + $_.Trim()) }
} else { Say "  !! 计划任务不存在，安装失败" }

Say "`n[3] HKCU\Run 里应已无 netproxy"
$rk = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
Say "  netproxy = " + $(if ($rk.'netproxy') { $rk.'netproxy' } else { '(已清除)' })

# 2) 杀掉当前实例，改由计划任务拉起
Say "`n[4] 杀当前实例，改由计划任务拉起"
Get-Process netproxy -EA SilentlyContinue | ForEach-Object { Say "  kill netproxy PID=$($_.Id)"; try { $_.Kill() } catch {} }
Start-Sleep -Seconds 3
Get-Process gost -EA SilentlyContinue | ForEach-Object { Say "  残留 gost PID=$($_.Id)（Job Object 未回收）"; try { $_.Kill() } catch {} }
Remove-Item (Join-Path $root 'netproxy.log') -ErrorAction SilentlyContinue

& schtasks.exe /run /tn 'netproxy' | Out-Null
Say "  schtasks /run 已发出"

for ($i = 1; $i -le 20; $i++) {
    Start-Sleep -Seconds 2
    $p = Get-Process netproxy -EA SilentlyContinue
    if ($p) {
        # 判断是否提权（能否读取受保护信息 / token 是否 elevated）
        $isAdmin = $false
        try { $isAdmin = $p.Handle -ne $null } catch {}
        $q = & whoami /groups 2>$null | Select-String 'S-1-16-12288'
        Say "  +$($i*2)s: netproxy PID=$($p.Id) 窗口标题='$($p.MainWindowTitle)'"
        break
    }
}

Start-Sleep -Seconds 6
Say "`n[5] 子进程与监听"
Get-Process gost -EA SilentlyContinue | ForEach-Object { Say "  gost PID=$($_.Id)" }
$ls = netstat -ano | Select-String ':1080 |:1081 '
if ($ls) { $ls | ForEach-Object { Say ("  " + $_.Line.Trim()) } } else { Say "  (无 1080/1081 监听)" }

Say "`n[6] 连通性"
foreach ($tp in @(@('10.0.1.10',5432),@('10.0.1.11',6446),@('10.0.0.11',5000),@('10.0.0.10',443),@('10.0.0.12',9056),@('192.168.100.10',80))) {
    $c = New-Object Net.Sockets.TcpClient
    try { $iar = $c.BeginConnect($tp[0], $tp[1], $null, $null)
          $ok  = $iar.AsyncWaitHandle.WaitOne(6000, $false)
          if ($ok) { $c.EndConnect($iar); Say "  $($tp[0]):$($tp[1])  REACHABLE" } else { Say "  $($tp[0]):$($tp[1])  unreachable(timeout)" }
    } catch { Say "  $($tp[0]):$($tp[1])  unreachable($($_.Exception.Message))" } finally { $c.Close() }
}

Say "`n--- netproxy.log ---"
$f = Join-Path $root 'netproxy.log'
if (Test-Path $f) { Get-Content $f -Encoding UTF8 | Select-Object -Last 25 | ForEach-Object { Say "  $_" } } else { Say "  (无日志)" }
Say "=== done ==="
