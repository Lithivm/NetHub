# 重启 netproxy GUI 并抓日志（提权运行）
$ErrorActionPreference = 'Continue'
$root = 'C:\Users\Administrator\Desktop\netproxy'
$out  = Join-Path $root 'guirun.log'
Remove-Item $out -ErrorAction SilentlyContinue
function Say($m) { $m | Out-File -FilePath $out -Append -Encoding utf8 }

Say "=== 重启 GUI $(Get-Date -Format 'HH:mm:ss') ==="
Get-Process netproxy -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill(); Say "  kill 旧实例 PID=$($_.Id)" } catch {} }
Get-Process gost     -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill(); Say "  kill 残留 gost PID=$($_.Id)" } catch {} }
Start-Sleep -Seconds 2

Remove-Item (Join-Path $root 'netproxy.log') -ErrorAction SilentlyContinue
$p = Start-Process -FilePath (Join-Path $root 'netproxy.exe') -PassThru
Say "  新实例 PID=$($p.Id)"
for ($i = 1; $i -le 10; $i++) {
    Start-Sleep -Seconds 2
    $q = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if (-not $q) { Say "  !! 进程在 $($i*2)s 后消失"; break }
}
Say "`n--- gost 子进程 ---"
$g = Get-Process gost -ErrorAction SilentlyContinue
if ($g) { $g | ForEach-Object { Say "  gost PID=$($_.Id)" } } else { Say "  (无 gost 子进程)" }
Say "`n--- 1080/1081 监听 ---"
$ls = netstat -ano | Select-String ':1080 |:1081 '
if ($ls) { $ls | ForEach-Object { Say ("  " + $_.Line.Trim()) } } else { Say "  (无监听)" }
Say "`n--- netproxy.log（本次启动全量）---"
$f = Join-Path $root 'netproxy.log'
if (Test-Path $f) { Get-Content $f -Encoding UTF8 | ForEach-Object { Say "  $_" } } else { Say "  (无日志)" }
Say "=== done ==="
