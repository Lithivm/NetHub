# 在桌面创建 NetHub 快捷方式。
#
#   powershell -ExecutionPolicy Bypass -File make-shortcut.ps1
#   powershell -ExecutionPolicy Bypass -File make-shortcut.ps1 -Remove   # 删掉快捷方式
#
# 目标指向本脚本所在目录的 nethub.exe，所以整个文件夹挪位置后重新跑一次即可。
# 不需要在这里设置“以管理员身份运行”：nethub.exe 自己会请求提权。
param(
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here 'nethub.exe'
$ico = Join-Path $here 'nethub.ico'
$lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'NetHub.lnk'

if ($Remove) {
    if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host "已删除 $lnk" }
    else { Write-Host '桌面上没有 NetHub 快捷方式' }
    exit
}

if (-not (Test-Path $exe)) { throw "找不到 nethub.exe: $exe" }

$sh = New-Object -ComObject WScript.Shell
$s = $sh.CreateShortcut($lnk)
$s.TargetPath = $exe
$s.WorkingDirectory = $here
$s.Description = 'NetHub · 内网隧道代理'
$s.IconLocation = if (Test-Path $ico) { "$ico,0" } else { "$exe,0" }
$s.Save()

Write-Host "已创建快捷方式: $lnk"
Write-Host "  目标: $exe"
Write-Host "  图标: $(if (Test-Path $ico) { $ico } else { "$exe (内嵌)" })"
Write-Host "  工作目录: $here"
