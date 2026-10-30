# NetHub 无人值守部署（一条命令从零到跑起来，并把"白名单"那步打出来）
#
# 为什么要它：现在装机是"解压 → 双击 → 界面里配 → **记得加白名单**"，每台机重复一遍，
# 而白名单那一步最容易漏（漏了开机起不来，还报一个像内存问题的 1450）——
# 现场就这么白查过一晚。所以部署脚本的价值一半在"装"，一半在**把该加的东西摆到眼前**。
#
# 跑法（**不需要管理员**；只有 -Service 才需要）：
#   pwsh -NoProfile -File ./tools/deploy.ps1 -Zip .\dist\NetHub.zip -Autostart -Start
#   pwsh -NoProfile -File ./tools/deploy.ps1 -Config .\my.yaml -Autostart -Start -Accept
#
# 幂等：重复跑不会炸（解压覆盖、自启是"设成开"、启动前先请旧实例退出）。
# 退出码：0 = 装完并校验通过；非 0 = 有 FAIL。
param(
    [string]$Zip = '',                       # NetHub.zip；不给就认为 -Dir 已经是程序目录
    [string]$Dir = '',                       # 程序目录；默认仓库的 run/
    [string]$Config = '',                    # 可选：要落盘的 config.yaml
    [switch]$Autostart,                      # 装开机自启（计划任务，用户登录后静默起）
    [switch]$Service,                        # 装成 Windows 服务（无人登录也跑；需要管理员）
    [switch]$Start,                          # 装完启动并等就绪
    [switch]$Accept                          # 装完跑一遍 local/accept.ps1 验收门禁
)

$ErrorActionPreference = 'Continue'
$OutputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
if (-not $Dir) { $Dir = Join-Path $root 'run' }
$exe = Join-Path $Dir 'nethub.exe'

$fail = 0
function Ok($n, $d) { Write-Output ("PASS  " + $n.PadRight(20) + $d) }
function Bad($n, $d) { $script:fail++; Write-Output ("FAIL  " + $n.PadRight(20) + $d) }
function Info($m) { Write-Output ("      " + $m) }

Write-Output ("=== NetHub 部署 " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + " ===")
Write-Output ("指定目录: $Dir")

# ── 1. 环境 ──
$a = [Environment]::Is64BitOperatingSystem
if ($a) { Ok '环境 x64' ([Environment]::OSVersion.VersionString) } else { Bad '环境 x64' '本程序只有 x64 构建' }

# ── 2. 解压 / 就位 ──
if ($Zip) {
    if (-not (Test-Path $Zip)) { Bad '解压' "找不到 $Zip"; Write-Output '结果：失败（zip 不存在）'; exit $fail }
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    try { Expand-Archive -Path $Zip -DestinationPath $Dir -Force; Ok '解压' $Zip }
    catch { Bad '解压' $_.Exception.Message }
}

# 发布包里有顶层 NetHub/ 目录（zip 里是 NetHub/nethub.exe），所以"程序目录"可能是 $Dir
# 往下的一层。不认出来的话，后面每一步都会找不到 exe（实测就是这么撞的）。
if (-not (Test-Path (Join-Path $Dir 'nethub.exe'))) {
    $sub = Get-ChildItem $Dir -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'nethub.exe') } | Select-Object -First 1
    if ($sub) { Info "包里带顶层目录，程序目录 = $($sub.FullName)"; $Dir = $sub.FullName }
}
$exe = Join-Path $Dir 'nethub.exe'
Write-Output ("程序目录: $Dir")

# 三个必需文件，少一个都起不来（驱动那两个正是白名单要加的东西）
$need = @('nethub.exe', 'WinDivert.dll', 'WinDivert64.sys')
$miss = @($need | Where-Object { -not (Test-Path (Join-Path $Dir $_)) })
if ($miss.Count -eq 0) { Ok '文件齐全' ($need -join ' / ') } else { Bad '文件齐全' ('缺 ' + ($miss -join ', ')) }

# ── 3. 配置 ──
# 有三种情况，分清楚（混在一起就会出现"部署成功但报 FAIL"的假警报）：
#   ① 给了 -Config：操作人手上有真配置 → 拷进去 → **-check 失败就是硬 FAIL**
#   ② 目录里已经有 config.yaml（升级/重装）：它是现役配置 → 同样按硬 FAIL 看
#   ③ 都没有（首次部署）：**不要拿 config.yaml.example 起一份** ——
#      那个模板里的上游是占位符（`YOUR_BASE64_...`），拿它当配置只会让 -check 报一个
#      假的"部署失败"（实测撞到）。首次启动时程序自己会生成默认配置。
$cfg = Join-Path $Dir 'config.yaml'
if ($Config) {
    if (-not (Test-Path $Config)) { Bad '落配置' "找不到 $Config" }
    else {
        # 源与目标可能是同一个文件（比如 -Config 就指向程序目录里那份）—— 直接 Copy 会报
        # "无法用自身覆盖项"，虽然无害，但输出里会冒一条红字，容易被当成失败。
        $same = $false
        try { $same = ((Resolve-Path $Config).Path -eq (Resolve-Path $cfg -EA SilentlyContinue).Path) } catch {}
        if ($same) { Ok '落配置' "配置已在目标位置（$cfg），不用拷" }
        elseif (Test-Path $exe) {
            # 用 -apply 而不是 Copy-Item：整份配置替换时，**本机偏好（日志档位）要保住**。
            # 直接 Copy 会把别人机器上那份的 log_level 一起搬过来（现场表现：部署完日志
            # 忽然从 verbose 变回 normal，事后回去查故障连判定面都没有）。
            $r = & $exe -apply-force -apply $Config -config $cfg 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3) { Ok '落配置' "(-apply 退出码 $LASTEXITCODE) $cfg" }
            else { Bad '落配置' ("-apply 退出码 $LASTEXITCODE`n" + $r) }
        }
        else { Copy-Item $Config $cfg -Force; Ok '落配置' "$cfg（没有 nethub.exe，直接拷：日志档位不保）" }
    }
}
if (Test-Path $cfg) {
    if (Test-Path $exe) {
        $r = & $exe -check -config $cfg 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { Ok '配置校验' '(-check 退出码 0)' }
        else { Bad '配置校验' ("-check 退出码 $LASTEXITCODE`n" + $r) }
    } else {
        Bad '配置校验' '没有 nethub.exe，跳过'
    }
} else {
    Info '首次部署：没有 config.yaml，启动时程序会自己生成一份默认的'
    Info '（改上游/网段看 config.yaml.example，里面每种写法都有注释）'
}

# ── 4. 白名单清单（这一步才是本脚本的重点）──
# 分清楚：主程序进"信任区"（防被杀软当木马删）；**驱动要单独进"例外驱动/驱动白名单"**，
# 因为火绒 6.0 的「漏洞驱动拦截」按文件把 WinDivert 判成漏洞驱动，在内核层直接拒加载，
# 而它报出来的是 1450「系统资源不足」—— 字面像内存不够，能骗人查一整天。
Write-Output ''
Write-Output '──── 装之前：在安全软件里放行这两个文件（漏了会一直报 1450）────'
Write-Output ('  1) 主程序（防被当木马删）: ' + (Join-Path $Dir 'nethub.exe') + '  → 杀软的信任区')
Write-Output ('  2) 驱动（防被内核层拦）: ' + (Join-Path $Dir 'WinDivert64.sys'))
Write-Output '       火绒 6.0：系统防护 → 漏洞驱动拦截 → 例外驱动'
Write-Output '       360 / 腾讯管家：驱动（内核）防护白名单'
Write-Output '     注意：只加信任区不够；加完要**重启安全软件**才生效（例外表是它启动时读进内存的）'
Write-Output ''

# ── 5. 开机自启 ──
if ($Autostart) {
    $r = & $exe -autostart 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Ok '开机自启' '已设为计划任务 NetHub（最高权限）' } else { Bad '开机自启' ("退出码 $LASTEXITCODE`n" + $r) }
}
if ($Service) {
    $elev = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $elev) { Bad '装服务' '需要管理员权限（用管理员终端跑，或改用 -Autostart）' }
    else {
        $r = & $exe -service-install 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { Ok '装服务' '已装为自动启动的 Windows 服务' } else { Bad '装服务' ("退出码 $LASTEXITCODE`n" + $r) }
    }
}

# ── 6. 启动并等就绪 ──
if ($Start) {
    & $exe -quit | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Process nethub -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    }
    Remove-Item (Join-Path $Dir 'logs\nethub.log') -ErrorAction SilentlyContinue
    Start-Process $exe | Out-Null          # nethub 自己提权，这里不需要
    $ready = $false; $secs = 0
    for ($i = 1; $i -le 40; $i++) {
        Start-Sleep -Seconds 1
        $f = Join-Path $Dir 'logs\nethub.log'
        if ((Test-Path $f) -and (Get-Content $f -Raw -Encoding UTF8 -ErrorAction SilentlyContinue) -match '服务已就绪') {
            $ready = $true; $secs = $i; break
        }
    }
    if ($ready) { Ok '启动并就绪' "约 ${secs}s" } else { Bad '启动并就绪' '40 秒内没出现「服务已就绪」（多半是白名单那步没做，看上面 4）' }
}

# ── 7. 可选：跑验收门禁 ──
if ($Accept) {
    Write-Output ''
    # accept.ps1 含现场地址，还没搬进 tools/ —— 两个位置都找一遍
    $accept = Join-Path $PSScriptRoot 'accept.ps1'
    if (-not (Test-Path $accept)) { $accept = Join-Path $root 'local\accept.ps1' }
    & pwsh -NoProfile -File $accept
    if ($LASTEXITCODE -eq 0) { Ok '验收门禁' 'accept.ps1 全过' } else { Bad '验收门禁' "accept.ps1 退出码 $LASTEXITCODE（见上面它的输出）" }
}

Write-Output ''
Write-Output ("合计：失败 " + $fail + " 条")
Write-Output $(if ($fail -eq 0) { '结果：部署完成' } else { '结果：有失败项（见上面 FAIL 行）' })
exit $fail
