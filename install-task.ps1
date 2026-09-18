# 注册/更新开机自启计划任务（NetHub）。
#
#   powershell -ExecutionPolicy Bypass -File install-task.ps1
#
# 为什么用计划任务而不是 HKCU\Run：
#   我们需要“开机静默提权”——开机后自动以管理员身份起来，且【不弹 UAC】。
#   计划任务的 RunLevel=HighestAvailable + InteractiveToken 正好满足；
#   而 Run 键启动的进程无法静默提权（会弹 UAC 或被降权）。
#
# 路径全部从本脚本所在目录推导，所以整个文件夹拷到任何地方都能用。
$ErrorActionPreference = 'Stop'

function Write-Log($m) { Write-Host $m }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here 'nethub.exe'
$cfg = Join-Path $here 'config.yaml'
$taskName = 'NetHub'

Write-Log "NetHub 目录: $here"
if (-not (Test-Path $exe)) { throw "找不到 nethub.exe: $exe" }

# ── 需要管理员 ──────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log '需要管理员权限，正在重新以管理员身份运行…'
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $MyInvocation.MyCommand.Path + '"'
    $psi.UseShellExecute = $true
    $psi.Verb = 'runas'
    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

# ── 清理旧任务（含历史名字，方便从旧版本升级）────────────────
foreach ($old in @($taskName)) {
    $o = & schtasks /delete /tn $old /f 2>&1 | Out-String
    if ($o -match '成功|SUCCESS') { Write-Log "  已删除旧任务: $old" }
}

# ── 生成任务定义 ────────────────────────────────────────────
$user = "$env:USERDOMAIN\$env:USERNAME"
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>NetHub 内网隧道代理（开机静默提权启动）</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$user</UserId>
      <Delay>PT20S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$user</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$exe</Command>
      <Arguments>-config "$cfg"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$xmlPath = Join-Path $here 'NetHub-task.xml'
[IO.File]::WriteAllText($xmlPath, $xml, [Text.Encoding]::Unicode)
Write-Log "已生成任务定义: $xmlPath"
Write-Log '  说明: ExecutionTimeLimit=PT0S —— 默认的 PT72H 会在 3 天后把进程杀掉'

# ── 注册 ────────────────────────────────────────────────────
$r = & schtasks /create /tn $taskName /xml $xmlPath /f 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "注册失败: $r" }
Write-Log '注册成功'

# ── 核对 ────────────────────────────────────────────────────
$q = & schtasks /query /tn $taskName /xml 2>&1 | Out-String
foreach ($k in @('RunLevel', 'LogonType', 'ExecutionTimeLimit', 'MultipleInstancesPolicy', '<Command>', '<Arguments>')) {
    $m = [regex]::Match($q, "<$k>([^<]*)</$k>")
    if ($m.Success) { Write-Log ("  {0,-28} = {1}" -f $k, $m.Groups[1].Value) }
}

Write-Log ''
Write-Log '完成。取消自启用:  nethub.exe -no-autostart'
Write-Log '或:              schtasks /delete /tn NetHub /f'
