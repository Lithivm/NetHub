# 打包一份可直接发给同事的 dist/。
#
#   powershell -ExecutionPolicy Bypass -File make-dist.ps1
#   powershell -ExecutionPolicy Bypass -File make-dist.ps1 -SkipBuild   # 不重新编译
#
# dist/ 里放的是“拿到就能跑”的最小集合。注意：
# 整包**不含任何配置与日志**：config.yaml（含上游凭据）、nethub*.log（含内网地址与访问记录）
# 都不放；内部运维脚本在 local/（不入库也不入包，它们写死了内网 IP 与域名）。
# 拿到包的人把 config.yaml.example 复制成 config.yaml，填自己的上游即可。
#     凭据不在日志/聊天里出现，但这个包本身是敏感的，别往公开地方传。
#   * dist/ 不进 git（见 .gitignore）：里面是二进制产物，入库没意义且会把仓库撑大。
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host $m }
function Die($m) { Write-Host "错误: $m" -ForegroundColor Red; exit 1 }

# Fix-ZipEntryNames 修正 .NET 打包出来的两处不合规：
#
#  1) **没设 UTF-8 文件名标志**（通用位 11 = 0x0800）。
#     .NET Framework 的 ZipFile.CreateFromDirectory 即使传了 UTF8Encoding，
#     名字字节按 UTF-8 写，但标志位不设（已知问题）—— 读的一方会按旧代码页
#     （中文机器上是 GBK）解释，非 ASCII 名字变乱码。
#     注意 flags 是 2 字节小端：低字节在偏移 8，高字节在 9。
#     bit11 = 0x0800 → 要改的是**偏移 9 的 0x08**。
#
#  2) **用反斜杠做路径分隔符**（NetHub\file）。zip 规范要求正斜杠 "/"，
#     部分工具（Info-ZIP unzip）会警告甚至解压失败。
#     '\'→'/' 是单字节替换，不改变长度，可以原地改。
function Fix-ZipEntryNames($zipPath) {
    $b = [IO.File]::ReadAllBytes($zipPath)

    $eocd = -1
    for ($i = $b.Length - 22; $i -ge 0; $i--) {
        if ($b[$i] -eq 0x50 -and $b[$i + 1] -eq 0x4B -and $b[$i + 2] -eq 0x05 -and $b[$i + 3] -eq 0x06) { $eocd = $i; break }
    }
    if ($eocd -lt 0) { throw '找不到 zip 的 EOCD，归档可能损坏' }

    $count = [BitConverter]::ToUInt16($b, $eocd + 10)
    $p = [BitConverter]::ToUInt32($b, $eocd + 16)   # 中央目录起始偏移

    # 本地文件头：flags 在 +6/+7，nameLen 在 +26，name 在 +30
    $fixLocal = {
        param($off)
        if ($b[$off] -eq 0x50 -and $b[$off + 1] -eq 0x4B -and $b[$off + 2] -eq 0x03 -and $b[$off + 3] -eq 0x04) {
            $b[$off + 7] = $b[$off + 7] -bor 0x08
            $ln = [BitConverter]::ToUInt16($b, $off + 26)
            for ($j = 0; $j -lt $ln; $j++) {
                if ($b[$off + 30 + $j] -eq 0x5C) { $b[$off + 30 + $j] = 0x2F }
            }
        }
    }

    for ($k = 0; $k -lt $count; $k++) {
        if (-not ($b[$p] -eq 0x50 -and $b[$p + 1] -eq 0x4B -and $b[$p + 2] -eq 0x01 -and $b[$p + 3] -eq 0x02)) {
            throw "中央目录第 $k 项头不合法"
        }
        $b[$p + 9] = $b[$p + 9] -bor 0x08          # UTF-8 文件名标志（高字节的 0x08）
        $nameLen = [BitConverter]::ToUInt16($b, $p + 28)
        $extraLen = [BitConverter]::ToUInt16($b, $p + 30)
        $cmtLen = [BitConverter]::ToUInt16($b, $p + 32)
        for ($j = 0; $j -lt $nameLen; $j++) {
            if ($b[$p + 46 + $j] -eq 0x5C) { $b[$p + 46 + $j] = 0x2F }
        }
        & $fixLocal ([BitConverter]::ToUInt32($b, $p + 42))
        $p += 46 + $nameLen + $extraLen + $cmtLen
    }
    [IO.File]::WriteAllBytes($zipPath, $b)
    Info "   已修正 $count 个条目：UTF-8 文件名标志 + 路径分隔符改正斜杠"
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $here 'dist'   # 只有一种包：永远不含配置与日志

# ── 1) 编译 ─────────────────────────────────────────────────
if (-not $SkipBuild) {
    Info '编译（-tags production，缺它 Wails 会弹构建错误框）…'
    $env:GOPROXY = 'https://goproxy.cn,direct'
    $env:GOSUMDB = 'off'
    # 先编译成临时名再换上去：nethub.exe 正在运行时 Windows 不允许覆盖，
    # 直接 -o nethub.exe 只会丢一个“拒绝访问”，看不出是“程序还开着”。
    Push-Location $here
    try {
        & go build -tags production -ldflags '-H=windowsgui -s -w' -o nethub.build.exe .
        if ($LASTEXITCODE -ne 0) { Die 'go build 失败' }
    } finally { Pop-Location }
    try {
        Move-Item -Force (Join-Path $here 'nethub.build.exe') (Join-Path $here 'nethub.exe')
    } catch {
        Remove-Item (Join-Path $here 'nethub.build.exe') -Force -ErrorAction SilentlyContinue
        Die 'nethub.exe 正在运行（被占用），请先从托盘退出 NetHub 再打包'
    }
    Info '  编译完成'
}

# ── 2) 重建输出目录 ────────────────────────────────────────
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path $dist | Out-Null

# 包里的东西：能跑起来 + 知道怎么用。
$files = @(
    @{n = 'nethub.exe';      must = $true;  desc = '主程序'},
    @{n = 'nethub.ico';      must = $true;  desc = '图标'},
    @{n = 'WinDivert.dll';   must = $true;  desc = 'WinDivert 运行库（LGPLv3）'},
    @{n = 'WinDivert64.sys'; must = $true;  desc = 'WinDivert 内核驱动（LGPLv3）'}, 
    @{n = 'WinDivert-LICENSE.txt'; src = 'third_party\WinDivert-LICENSE.txt'; must = $true; desc = 'WinDivert 许可证（随包分发）'},
    @{n = 'LICENSE';         must = $true;  desc = '本程序许可证'},
    @{n = 'config.yaml.example'; must = $true; desc = '配置模板（占位符，无凭据）'},
    @{n = 'README.md';       must = $false; desc = '完整文档'},
    @{n = 'install-task.ps1'; must = $false; desc = '注册开机自启'}
)

$missing = @()
foreach ($f in $files) {
    $rel = $f['src']; if (-not $rel) { $rel = $f.n }   # 少数文件源路径与包内名字不同
    $src = Join-Path $here $rel
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $dist $f.n) -Force
        Info ("  已放入 {0,-18} {1}" -f $f.n, $f.desc)
    } elseif ($f.must) {
        $missing += $f.n
    }
}
if ($missing.Count -gt 0) { Die ("缺少必需文件: " + ($missing -join ', ')) }

# ── 3) 使用说明（第一眼要看的） ────────────────────────────
$readme = @"
NetHub —— 内网隧道代理（分发版）
================================================

这是个 Windows 内网透明代理：把指定网段的 TCP 流量在**内核层**接管，
经你自己的上游代理转发出去。程序自带代理客户端，不需要 gost.exe。

【第 1 步】配置你自己的上游（**必做，否则起不来**）
  1) 把 config.yaml.example 复制成 config.yaml
  2) 打开 config.yaml，把 chains 里的
         forward: socks5+tls://YOUR-HOST:10080?auth=YOUR_BASE64_OF_user:pass
     换成你自己的上游地址（auth= 后面是「用户:口令」的 base64）
  3) 把 routes 里的示例网段换成你真正要走隧道的内网段

  ⚠ config.yaml 里含上游凭据，别提交进 git、别贴到聊天/工单里。

【第 2 步】让安全软件放行（**最容易漏，漏了就完全用不了**）
  火绒会拦截本程序要加载的驱动，表现是打不开、日志里反复报
  "Insufficient system resources ... (1450)"。

  1) 火绒 → 主界面「安全日志」→ 找到 WinDivert64.sys 的「已阻止」记录
     → 右键 → 信任
     更保险：火绒「信任区」里同时加入 nethub.exe 和 WinDivert64.sys
  2) **重启火绒**（或退出后重新打开）

  ★ 为什么第 2 步不能省：火绒的白名单是启动时读进内存的。
    加完不重启火绒，白名单不生效，重试依然报 1450。

【第 3 步】启动
  双击 nethub.exe。它会自己请求管理员权限（内网透明拦截需要）。
  启动后窗口可以点 X 收进托盘，服务继续跑；真退出走托盘右键 → 退出。

【可选】开机自启
  右键「以管理员身份运行」install-task.ps1。
  它注册一个开机静默提权的计划任务，以后开机自动起，不会弹 UAC。
  取消：nethub.exe -no-autostart

验证是否正常
  看「运行日志」页：应该出现
      内核过滤器: (outbound and tcp and ...)
      ✓ 服务已就绪：已接管 N 条规则，relay 127.0.0.1:xxxxx
  **不该**出现反复的 "WinDivert 打开失败(第 N/6 次)" —— 出现就是第 2 步没做全。

出问题先看
  * 驱动加载失败(1450) → 回到第 2 步，尤其确认火绒重启过
  * 内网连不上但日志有"已接管" → 界面里点「链路自检」
  * 新加了网段却没生效 → 改网段后要在界面上点「重启」（过滤器在启动时按网段展开）

第三方组件
  WinDivert（LGPLv3 / GPLv2 双许可）—— 见 WinDivert-LICENSE.txt。
  本程序以动态链接方式使用 WinDivert.dll。
"@
$readmePath = Join-Path $dist '使用说明.txt'
[IO.File]::WriteAllText($readmePath, $readme, (New-Object Text.UTF8Encoding $true))
Info '  已放入 使用说明.txt'

# ── 4) 打 zip（方便直接发出去） ─────────────────────────────
# 归档里带一层 NetHub/ 目录，对方解压不会把文件撒一地。
# 用 ZipFile.CreateFromDirectory 的 5 参重载显式指定 UTF-8 条目名 ——
# PowerShell 5.1 的 Compress-Archive 会用默认编码写条目名，
# 「使用说明.txt」这种中文名在别的工具里会变成乱码。
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stage = Join-Path $env:TEMP 'nethub-zip-stage'
$outer = Join-Path $stage 'NetHub'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $outer -Force | Out-Null
Get-ChildItem $dist -File | Copy-Item -Destination $outer -Force

$zip = Join-Path $dist 'NetHub.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $outer, $zip,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $true,                                  # includeBaseDirectory -> 顶层 NetHub/
    (New-Object Text.UTF8Encoding $false)
)
Remove-Item $stage -Recurse -Force
Fix-ZipEntryNames $zip
Info ('  已生成 {0} ({1:N1} MB)' -f (Split-Path $zip -Leaf), ((Get-Item $zip).Length / 1MB))

# 校验归档内容（也确认中文文件名没乱码）
$arch = [System.IO.Compression.ZipFile]::OpenRead($zip)
Info '  zip 内容:'
foreach ($e in $arch.Entries) { Info ('    {0,-26} {1,10:N0}' -f $e.FullName, $e.Length) }
$arch.Dispose()

# ── 5) 校验 ─────────────────────────────────────────────────
Info ''
Info "dist 目录: $dist"
$total = 0
Get-ChildItem $dist | Sort-Object Name | ForEach-Object {
    Info ("  {0,-20} {1,10:N0} 字节" -f $_.Name, $_.Length)
    if ($_.Extension -ne '.zip') { $total += $_.Length }
}
Info ("  文件合计 {0:N1} MB（不含 zip）" -f ($total / 1MB))

# exe 里是否真的带上了图标资源
Add-Type @"
using System;using System.Runtime.InteropServices;
public class Ic{
 [DllImport("shell32.dll",CharSet=CharSet.Unicode)] public static extern uint ExtractIconEx(string f,int i,IntPtr[] b,IntPtr[] s,uint n);
}
"@
$big = New-Object IntPtr[] 1
$n = [Ic]::ExtractIconEx((Join-Path $dist 'nethub.exe'), 0, $big, $null, 1)
if ($n -gt 0 -and $big[0] -ne [IntPtr]::Zero) { Info '  校验: exe 已内嵌图标资源 OK' }
else { Info '  校验: !! exe 没有图标资源（忘了 nethub.syso？）' }

Info ''
Info '打包完成。'
