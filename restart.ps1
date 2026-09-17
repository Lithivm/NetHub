$root='C:\Users\Administrator\Desktop\NetHub'
$log=Join-Path $root 'restart.log'
Remove-Item $log -EA SilentlyContinue
function Say($m){ $m|Out-File $log -Append -Encoding utf8 }
Get-Process nethub -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
Start-Sleep 3
Get-Process gost -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
Remove-Item (Join-Path $root 'nethub.log') -EA SilentlyContinue
$p=Start-Process (Join-Path $root 'nethub.exe') -PassThru
Say "启动 PID=$($p.Id)"
Start-Sleep 16
$q=Get-Process -Id $p.Id -EA SilentlyContinue
if(-not $q){ Say "!! 已退出"; Get-Content (Join-Path $root 'nethub.log') -Encoding UTF8 -EA SilentlyContinue|Select-Object -Last 20|%{Say "  $_"}; exit }
Say "存活 PID=$($q.Id) 标题='$($q.MainWindowTitle)'"
Say "--- 子进程 ---"
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $q.Id } | %{ Say "  $($_.Name) PID=$($_.ProcessId)" }
Say "--- nethub.log ---"
Get-Content (Join-Path $root 'nethub.log') -Encoding UTF8 -EA SilentlyContinue | %{ Say "  $_" }
Say "--- 连通性 ---"
foreach($t in @(@('10.0.1.10',5432),@('10.0.1.11',6446),@('10.0.0.11',5000),@('10.0.0.10',443),@('10.0.0.12',9056),@('192.168.100.10',80))){
  $c=New-Object Net.Sockets.TcpClient
  try{ $iar=$c.BeginConnect($t[0],$t[1],$null,$null)
    if($iar.AsyncWaitHandle.WaitOne(6000,$false)){ $c.EndConnect($iar); Say "  $($t[0]):$($t[1])  REACHABLE" } else { Say "  $($t[0]):$($t[1])  unreachable" }
  }catch{ Say "  $($t[0]):$($t[1])  unreachable" } finally { $c.Close() }
}
