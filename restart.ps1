$root='C:\Users\Administrator\Desktop\netproxy'
$log=Join-Path $root 'restart.log'
Remove-Item $log -EA SilentlyContinue
function Say($m){ $m|Out-File $log -Append -Encoding utf8 }
Get-Process netproxy -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
Start-Sleep 3
Get-Process gost -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
Remove-Item (Join-Path $root 'netproxy.log') -EA SilentlyContinue
$p=Start-Process (Join-Path $root 'netproxy.exe') -PassThru
Say "启动 PID=$($p.Id)"
Start-Sleep 18
$q=Get-Process -Id $p.Id -EA SilentlyContinue
if(-not $q){ Say "!! 已退出"; exit }
Say "存活 PID=$($q.Id) 标题='$($q.MainWindowTitle)'"
Say ""
Say "=== 关键验证：有没有控制台窗口被反复创建 ==="
$cons = Get-CimInstance Win32_Process -Filter "Name='conhost.exe'" -EA SilentlyContinue
Say "  系统里 conhost.exe 总数 = $(@($cons).Count)"
Say "  schtasks.exe 现存 = $(@(Get-Process schtasks -EA SilentlyContinue).Count)（轮询路径不该再起它）"
Say ""
Say "=== 子进程树 ==="
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $q.Id } | %{ Say "  $($_.Name) PID=$($_.ProcessId)" }
Say ""
Say "=== netproxy.log ==="
Get-Content (Join-Path $root 'netproxy.log') -Encoding UTF8 -EA SilentlyContinue | %{ Say "  $_" }
Say ""
Say "=== 连通性 ==="
foreach($t in @(@('10.0.1.10',5432),@('10.0.1.11',6446),@('10.0.0.11',5000),@('10.0.0.10',443),@('10.0.0.12',9056),@('192.168.100.10',80))){
  $c=New-Object Net.Sockets.TcpClient
  try{ $iar=$c.BeginConnect($t[0],$t[1],$null,$null)
    if($iar.AsyncWaitHandle.WaitOne(6000,$false)){ $c.EndConnect($iar); Say "  $($t[0]):$($t[1])  REACHABLE" }
    else { Say "  $($t[0]):$($t[1])  unreachable(timeout)" }
  }catch{ Say "  $($t[0]):$($t[1])  unreachable" } finally { $c.Close() }
}
