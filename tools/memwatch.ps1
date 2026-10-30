# NetHub 长跑采样：进程内存/句柄/线程 + 引擎自报的两张表
#
# 为什么要它：客户机是"装一次连跑几个月"的用法，而我们**从来没验证过**它住不住。
# 代码里 dnsmap 有 TTL 摘除、连接表有上限、假 IP 池有 Sweep —— 都是"设计上应该不涨"，
# 但那是推理，不是数据。这个脚本只做一件事：按固定间隔把数落成 CSV，让"住不住"变成可看的趋势。
#
# 跑法（**不需要管理员**；故意不自我提权 —— 见 accept.ps1 里那段解释）：
#   pwsh -NoProfile -File ./tools/memwatch.ps1                 # 每 60s 采一次，一直采
#   pwsh -NoProfile -File ./tools/memwatch.ps1 -Every 30 -Samples 20
# 输出：run/memwatch.csv（追加写；重启过就多一行 note=RESTART，不会把两次运行混成一条趋势）
#
# 读法（判断"有没有泄漏"）：
#   看**同一个 pid 段内**的 workMB/privMB/handles/threads 是否呈单调上升 ——
#   .NET/Go 的运行时有自己的堆策略，小幅锯齿正常；**斜率恒正且不回头**才是泄漏。
#   再看 names（名字表）与 fake（假 IP 池）：这两张表按 TTL/容量有界，不该随连接数一直爬。
param(
    [int]$Every = 60,      # 采样间隔（秒）
    [int]$Samples = 0,     # 采多少次；0 = 一直采
    [string]$Out = ''      # 输出 CSV；默认 run/memwatch.csv
)

$ErrorActionPreference = 'Continue'
$OutputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$run = Join-Path $root 'run'
$logFile = Join-Path $run 'logs\nethub.log'
if (-not $Out) { $Out = Join-Path $run 'memwatch.csv' }

function Header { 'time,pid,uptime_s,workMB,privMB,handles,threads,cpu_s,total,active,names,fake_used,fake_cap,note' }
if (-not (Test-Path $Out)) { Header | Set-Content $Out -Encoding UTF8 }

# 引擎每 5 分钟写一行 `stats: total=.. active=.. names=.. fake=../..`；
# 从日志尾部找**最后一条**（日志会轮转，所以只读尾部几千行）。
#
# 注意：stats 行归 **verbose** 档（它是仪表盘快照，不是“刚发生了什么事”，见 logbus.Level）。
# 所以采样前要把档位切到 verbose，退出时改回去 —— 否则 normal 档下这个脚本会“在跑但一条数据都没有”。
$cfgFile = Join-Path $run 'config.yaml'
$restoreLevel = $null
function Get-LogLevel {
    if (-not (Test-Path $cfgFile)) { return 'normal' }
    $m = Select-String -Path $cfgFile -Pattern '^\s*log_level:\s*(\S+)' -Encoding UTF8 | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
    return 'normal'
}
function Set-LogLevel([string]$lv) {
    if (-not (Test-Path $cfgFile)) { return }
    $raw = [IO.File]::ReadAllText($cfgFile)
    $new = [regex]::Replace($raw, '(?m)^(\s*log_level:\s*)\S+', "`${1}$lv")
    # 不用 Set-Content（PS5 会写 BOM，yaml 那边就得额外兼容）：直接写无 BOM 的 UTF8
    [IO.File]::WriteAllText($cfgFile, $new, (New-Object Text.UTF8Encoding $false))
}
$curLevel = Get-LogLevel
if ($curLevel -eq 'normal') {
    $restoreLevel = 'normal'
    Set-LogLevel 'verbose'
    Write-Host '日志档位已临时切到 verbose（stats 行只在 verbose 档写），退出时切回 normal' -ForegroundColor Yellow
} elseif ($curLevel -ne 'verbose') {
    Write-Host "日志档位是 $curLevel（比 verbose 更详细），不动它" -ForegroundColor DarkGray
}
function LastStats {
    if (-not (Test-Path $logFile)) { return $null }
    $tail = Get-Content $logFile -Tail 3000 -Encoding UTF8 -ErrorAction SilentlyContinue
    for ($i = $tail.Count - 1; $i -ge 0; $i--) {
        if ($tail[$i] -match 'stats: total=(\d+) new=(\d+) active=(\d+)(?: names=(\d+) fake=(\d+)/(\d+))?') {
            return @{
                total = [int]$Matches[1]; active = [int]$Matches[3]
                names = if ($Matches[4]) { [int]$Matches[4] } else { -1 }
                fake  = if ($Matches[5]) { [int]$Matches[5] } else { -1 }
                cap   = if ($Matches[6]) { [int]$Matches[6] } else { -1 }
            }
        }
    }
    return $null
}

# try/finally：Ctrl+C 中止也要把档位改回去（否则这台机器的日志就一直停在 verbose 了）
try {
$prevPid = 0
$n = 0
while ($true) {
    $n++
    $p = Get-Process nethub -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) {
        $note = ''
        if ($prevPid -ne 0 -and $p.Id -ne $prevPid) { $note = 'RESTART' }
        elseif ($prevPid -eq 0) { $note = 'attach' }
        $prevPid = $p.Id
        $up = 0
        try { $up = [int]((Get-Date) - $p.StartTime).TotalSeconds } catch {}
        $st = LastStats
        $row = @(
            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
            $p.Id, $up,
            [math]::Round($p.WorkingSet64 / 1MB, 1),
            [math]::Round($p.PrivateMemorySize64 / 1MB, 1),
            $p.HandleCount, $p.Threads.Count,
            [math]::Round($p.TotalProcessorTime.TotalSeconds, 1),
            $(if ($st) { $st.total } else { -1 }),
            $(if ($st) { $st.active } else { -1 }),
            $(if ($st) { $st.names } else { -1 }),
            $(if ($st) { $st.fake } else { -1 }),
            $(if ($st) { $st.cap } else { -1 }),
            $note
        ) -join ','
    } else {
        $prevPid = 0
        $row = @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, -1, -1, 'NOPROC') -join ','
    }
    Add-Content $Out $row -Encoding UTF8

    if ($Samples -gt 0 -and $n -ge $Samples) { break }
    Start-Sleep -Seconds $Every
}
} finally {
    if ($null -ne $restore) {
        Set-FileLevel $restore
        if ($restore -eq '') {
            Write-Host '日志文件档已恢复为“跟随屏幕档”（配置已热生效，不用重启）' -ForegroundColor DarkGray
        } else {
            Write-Host "日志文件档已切回 $restore（配置已热生效，不用重启）" -ForegroundColor DarkGray
        }
    }
}
