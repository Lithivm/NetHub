# NetHub 验收门禁（一条命令，退出码可判）
#
# 为什么要它：原来 e2e.ps1 / final-accept.ps1 / verify-after-reboot.ps1 都是"人看着读日志"，
# **退出码永远是 0** —— 所以 v0.4.0 / v0.4.1 两个版本带着"设置页点不开也滚不动"发出去，
# 没有任何东西拦一下。门禁的要点不是"多测几条"，而是**失败必须让调用方能看见**。
#
# 跑法（**不需要管理员**）：
#   pwsh -NoProfile -File ./local/accept.ps1
#   pwsh -NoProfile -File ./local/accept.ps1 -InjectFault    # 自检：证明门禁真的会失败
#
# 为什么不需要提权：-check / -status / -apply / -quit 都是无权限操作（AGENTS.md 里写明了），
# sc query 也不用；而 Start-Process nethub.exe 时**它自己会提权**（把活交给提权副本后原进程退出）。
# 别在这脚本里再写一层 Start-Process -Verb RunAs：实测那层会把调用方卡死
# （elevated 子进程的 -Wait 与它派生的长命 nethub 搅在一起，管道/重定向永远等不到 EOF）。
#
# 退出码：0 = 全过；非 0 = 有失败项。结果同时写进 run/accept.log。
param(
    [switch]$InjectFault,  # 自检模式：故意制造故障，断言门禁会报 FAIL；自检通过时退出码给 0
    # 验收目标：host:port[:名字]。**仓库默认空** —— 不把任何客户地址写进代码。
    # 现场用法：-Targets '10.0.0.5:5432:PostgreSQL','10.0.0.6:443:HIS'
    [string[]]$Targets = @()
)

$ErrorActionPreference = 'Continue'
# nethub.exe 的输出是 UTF-8；不设这两行，中文 JSON 会被按 ANSI 解出来，ConvertFrom-Json 直接失败
# （踩过：rules[2].name 里一个中文就把整段 JSON 判成非法）。
$OutputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$run = Join-Path $root 'run'
$exe = Join-Path $run 'nethub.exe'
$cfg = Join-Path $run 'config.yaml'
$log = Join-Path $run 'accept.log'

# ── 验收目标集 ──
# 从 -Targets 来（host:port[:名字]）。**仓库里不放任何客户地址**：默认空时这一步 SKIP，
# 而不是拿一堆不通的示例地址去报 FAIL（那会变成"永远红灯的假门禁"）。
$probe = @($Targets | Where-Object { $_ } | ForEach-Object {
    $p = $_ -split ':', 3
    @{ h = $p[0]; p = [int]$(if ($p[1]) { $p[1] } else { 443 })
       n = $(if ($p.Count -gt 2 -and $p[2]) { $p[2] } else { $p[0] }) }
})

Remove-Item $log -ErrorAction SilentlyContinue
$script:fail = 0
function Say($m) { $m | Out-File $log -Append -Encoding utf8; Write-Output $m }
function Ok($name, $detail) { Say ("PASS  " + $name.PadRight(20) + $detail) }
function Bad($name, $detail) { $script:fail++; Say ("FAIL  " + $name.PadRight(20) + $detail) }
$script:ok = $false
function Check($name, $cond, $okDetail, $badDetail) {
    # 刻意不 return 任何值：`Check ...` 当语句用时，返回值会被 PowerShell 打到 stdout
    # 里（输出里会混出一堆 True/False）。需要结果就读 $script:ok。
    $script:ok = [bool]$cond
    if ($script:ok) { Ok $name $okDetail } else { Bad $name $badDetail }
}
function Probe($ip, $port, $ms = 6000) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($ms, $false)) { $c.EndConnect($iar); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}
function Nethub([string[]]$a) {
    $o = & $exe @a 2>&1 | Out-String
    return @{ code = $LASTEXITCODE; out = $o }
}
function Status {
    $r = Nethub @('-status')
    $j = $null
    try { $j = $r.out | ConvertFrom-Json } catch {}
    return @{ code = $r.code; json = $j; raw = $r.out }
}
function RulesOf($st) { if ($st.json -and $st.json.rules) { return @($st.json.rules).Count } return -1 }

Say ("=== NetHub 验收门禁 " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + " ===")
Say ("注入故障: " + $(if ($InjectFault) { 'ON（自检模式：必须有 FAIL，否则门禁不可信）' } else { 'off' }))
Say ''

# ─────────────────────── 1. 配置校验（正反两面） ───────────────────────
$r = Nethub @('-check')
Check '配置校验' ($r.code -eq 0) '(-check 退出码 0)' ("-check 退出码 " + $r.code + "`n" + $r.out)

# 反面：一份"引用了不存在的链"的配置**必须被拒** —— 证明校验器不是橡皮图章。
# 这条永远跑（不是只在自检模式下），因为它便宜，而且能挡住"校验器失效"这种退化。
$badCfg = Join-Path $run 'config.yaml.gate-invalid'
@"
relay: 127.0.0.1:0
chains:
  - name: proxy-a
    forward: socks5://127.0.0.1:1080
routes:
  - name: 坏规则
    targets:
      - 192.0.2.0/24
    chain: 不存在的链
"@ | Set-Content $badCfg -Encoding UTF8
$rb = Nethub @('-check', '-config', $badCfg)
Check '非法配置被拒' ($rb.code -ne 0) ("退出码 " + $rb.code) ("非法配置居然通过了校验（退出码 " + $rb.code + "）—— 校验器失效了`n" + $rb.out)
Remove-Item $badCfg -ErrorAction SilentlyContinue

# ─────────────────────── 2. 重启到干净状态 ───────────────────────
# 门禁要重启：不重启测的是"上一个进程碰巧活着"，测不出开机自启那条路。
& $exe -quit | Out-Null
for ($i = 0; $i -lt 20; $i++) {
    if (-not (Get-Process nethub -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 500
}
$killed = $false
if (Get-Process nethub -ErrorAction SilentlyContinue) {
    $killed = $true
    Get-Process nethub -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Kill() } catch {} }
    Start-Sleep -Seconds 2
}
Remove-Item (Join-Path $run 'logs\nethub.log') -ErrorAction SilentlyContinue
Start-Process $exe | Out-Null   # nethub 自己提权，这里不需要
$ready = $false
$secs = 0
for ($i = 1; $i -le 40; $i++) {
    Start-Sleep -Seconds 1
    $f = Join-Path $run 'logs\nethub.log'
    if ((Test-Path $f) -and (Get-Content $f -Raw -Encoding UTF8 -ErrorAction SilentlyContinue) -match '服务已就绪') {
        $ready = $true; $secs = $i; break
    }
}
$note = if ($killed) { '（优雅退出超时，被强杀 —— 这条要留意）' } else { '' }
Check '启动并就绪' $ready ("约 ${secs}s" + $note) '40 秒内日志没出现「服务已就绪」'

# ─────────────────────── 3. 内核驱动 ───────────────────────
# 对应 2026-09-28 那个坑：火绒的「漏洞驱动拦截」会拦 WinDivert64.sys，报出来的是
# 1450「系统资源不足」—— 门禁必须能看见"驱动没起来"，而不是等业务报故障。
$q = (& sc.exe query WinDivert 2>&1 | Out-String)
Check '内核驱动 RUNNING' ($q -match 'RUNNING') 'WinDivert 已加载' ('WinDivert 不是 RUNNING：' + (($q -split "`n" | Select-String 'STATE|EXIT') -join ' / '))

# ─────────────────────── 4. 内网目标连通 ───────────────────────
if ($InjectFault) {
    # 自检：塞一个必然不通的目标（203.0.113.0/24 是 TEST-NET-3，不会有人路由它）
    $probe += @{ h = '203.0.113.1'; p = 9; n = '自检（必然不通）' }
}
if ($probe.Count -eq 0) {
    Say 'SKIP  内网目标连通        未提供 -Targets（仓库默认不带客户地址；现场用 -Targets 覆盖）'
} else {
    $badT = @()
    foreach ($t in $probe) { if (-not (Probe $t.h $t.p)) { $badT += ($t.h + ':' + $t.p + '(' + $t.n + ')') } }
    Check '内网目标连通' ($badT.Count -eq 0) ("$($probe.Count)/$($probe.Count) 可达") ('不可达：' + ($badT -join ', '))
}

# ─────────────────────── 5. 配置热生效（改 → 等实例吃进去 → 改回） ───────────────────────
# 这是 `-apply` 的核心承诺：校验 → 落盘 → **等实例真的吃进去**才返回。
# 用一条无害的直连规则来测：直连规则的目标不进内核过滤器（零影响），
# 但规则数会 +1，能在 -status 里看到。
$before = Status
$n0 = RulesOf $before
$backup = Join-Path $run 'config.yaml.gate-backup'
$tmp = Join-Path $run 'config.yaml.gate-tmp'
Copy-Item $cfg $backup -Force
try {
    # ① 缩进必须**照抄文件自己的**：现网 config.yaml 的数量列表是 4 空格缩进，
    #    硬编码 2 空格会让后一条规则变成我这条的子键 → YAML 直接解析失败
    #    （踩过：`yaml: line 22: did not find expected key`）。
    $lines = Get-Content $cfg -Encoding UTF8
    $hit = $false
    $ind = ''
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        $out.Add($l)
        if (-not $hit -and $l -match '^routes:\s*$') {
            $hit = $true
            # routes: 之后第一条列表项的缩进，就是我该用的缩进
            $first = $lines | Where-Object { $_ -match '^\s*-\s' } | Select-Object -First 1
            $ind = if ($first) { ($first -replace '^(\s*)-.*$', '$1') } else { '  ' }
            $out.Add($ind + '- name: 门禁临时规则（accept.ps1 跑完即撤）')
            $out.Add($ind + '  targets:')
            $out.Add($ind + '    - 203.0.113.0/24')
            $out.Add($ind + '  chain: direct')
        }
    }
    if (-not $hit) { throw 'config.yaml 里找不到 routes: 这一行，门禁没法安全地插测试规则' }
    Set-Content $tmp $out -Encoding UTF8

    # ② 夹具自己先过校验：不先验的话，夹具写坏了会伪装成"热生效坏了"
    $rc = Nethub @('-check', '-config', $tmp)
    Check '门禁夹具自身有效' ($rc.code -eq 0) ("(缩进 '" + $ind + "')") ("临时配置自身不合法（缩进 '" + $ind + "'），是门禁自己写坏了：`n" + $rc.out)
    if (-not $script:ok) { throw '夹具不合法，跳过热生效测试' }

    $ap = Nethub @('-apply', $tmp)
    $mid = Status
    $n1 = RulesOf $mid
    $matched = $mid.json.runtime.configMatchesFile
    $ok = ($ap.code -eq 0) -and ($n1 -eq $n0 + 1) -and ($matched -eq $true)
    Check '配置热生效' $ok ("规则 $n0 → $n1，configMatchesFile=$matched") ("-apply 退出码 $($ap.code)，规则 $n0 → $n1，configMatchesFile=$matched`n" + $ap.out)
} catch {
    Bad '配置热生效' ('门禁自己出错：' + $_.Exception.Message)
} finally {
    # 无论成败都把原配置放回去 —— 门禁绝不能把现场配置留在临时状态。
    # 必须 -apply-force：-apply 有一条“目标比源文件新就拒绝覆盖”的防并发守卫，
    # 而备份是几分钟前拷的、比刚被写过的 config.yaml 旧 → 不加 force 会被拒（踩过）。
    # 还原正是“确认以源文件为准”的场景，force 就是为它准备的。
    $back = Nethub @('-apply', $backup, '-apply-force')
    $after = Status
    $n2 = RulesOf $after
    $matched2 = if ($after.json) { $after.json.runtime.configMatchesFile } else { $null }
    $okDetail = "规则回到 $n2，configMatchesFile=$matched2"
    $badDetail = "还原失败：-apply 退出码 $($back.code)，规则 $n2，configMatchesFile=$matched2（备份留在 $backup）`n" + $back.out
    Check '配置已还原' (($back.code -eq 0) -and ($n2 -eq $n0) -and ($matched2 -eq $true)) $okDetail $badDetail
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if (($n2 -eq $n0) -and ($matched2 -eq $true)) { Remove-Item $backup -ErrorAction SilentlyContinue }
}

# ─────────────────────── 6. 收尾与退出码 ───────────────────────
Say ''
if ($InjectFault) {
    # 自检模式：**必须**有 FAIL，否则说明这是个永远绿灯的假门禁。
    # 自检通过时退出码给 0（调用方关心的是"门禁本身可信吗"）。
    Say ("自检：注入的故障被检出 " + $script:fail + " 条 FAIL")
    if ($script:fail -gt 0) {
        Say '结果：门禁有效（注入的故障被检出）'
        exit 0
    }
    Say '结果：门禁不可信 —— 注入了故障却一条 FAIL 都没有'
    exit 1
}
Say ("合计：失败 " + $script:fail + " 条")
Say $(if ($script:fail -eq 0) { '结果：全部通过' } else { '结果：有失败项（见上面 FAIL 行）' })
exit $script:fail
