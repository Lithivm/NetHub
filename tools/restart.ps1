param(
    # 重启后的连通性检查目标，host:port。仓库默认空 —— 不把客户地址写进代码。
    [string[]]$Targets = @()
)
$root = Join-Path (Split-Path -Parent $PSScriptRoot) 'run'
$probe = @($Targets | Where-Object { $_ } | ForEach-Object {
    $p = $_ -split ':', 3
    ,@($p[0], [int]$(if ($p[1]) { $p[1] } else { 443 }))
})
$log=Join-Path $root 'restart.log'
Remove-Item $log -EA SilentlyContinue
function Say($m){ $m|Out-File $log -Append -Encoding utf8 }

# 先请运行中的实例"优雅退出"：它会停服务、并 Shell_NotifyIcon(NIM_DELETE) 把托盘图标摘掉。
# 直接 Kill 会留下"僵尸图标"（进程没了、图标还在托盘里，鼠标扫过才消失）—— 反复重启就会堆一串。
$exe=Join-Path $root 'nethub.exe'
if(Get-Process nethub -EA SilentlyContinue){
  try{ & $exe -quit | Out-Null }catch{}
  for($i=0;$i -lt 20;$i++){
    if(-not (Get-Process nethub -EA SilentlyContinue)){ break }
    Start-Sleep -Milliseconds 500
  }
}
# 还没退（例如卡住了）才强杀，并说明原因
if(Get-Process nethub -EA SilentlyContinue){
  Say "优雅退出超时，改为强制结束（这次会留下一个僵尸图标，鼠标扫过托盘即消失）"
  Get-Process nethub -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
  Start-Sleep 2
}
Get-Process gost -EA SilentlyContinue|%{try{$_.Kill()}catch{}}
Remove-Item (Join-Path $root 'logs\nethub.log') -EA SilentlyContinue

$p=Start-Process $exe -PassThru
Say "启动 PID=$($p.Id)（若自动提权，它会把活交给提权副本后自己退出）"
Start-Sleep 16
# 提权重启会造成"原进程退出、提权副本继续"：所以按进程名再看一次，别跟丢
$q=Get-Process nethub -EA SilentlyContinue | Select-Object -First 1
if(-not $q){ Say "!! 已退出"; Get-Content (Join-Path $root 'logs\nethub.log') -Encoding UTF8 -EA SilentlyContinue|Select-Object -Last 20|%{Say "  $_"}; exit }
Say "存活 PID=$($q.Id) 标题='$($q.MainWindowTitle)'"
Say "--- nethub.log ---"
Get-Content (Join-Path $root 'logs\nethub.log') -Encoding UTF8 -EA SilentlyContinue | %{ Say "  $_" }
Say "--- 连通性 ---"
if ($probe.Count -eq 0) { Say "  （未提供 -Targets，跳过；现场用 -Targets '10.0.0.5:5432' 覆盖）" }
foreach($t in $probe){
  $c=New-Object Net.Sockets.TcpClient
  try{ $iar=$c.BeginConnect($t[0],$t[1],$null,$null)
    if($iar.AsyncWaitHandle.WaitOne(6000,$false)){ $c.EndConnect($iar); Say "  $($t[0]):$($t[1])  REACHABLE" } else { Say "  $($t[0]):$($t[1])  unreachable" }
  }catch{ Say "  $($t[0]):$($t[1])  unreachable" } finally { $c.Close() }
}
