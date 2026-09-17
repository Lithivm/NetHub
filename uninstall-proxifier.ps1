# 静默卸载 Proxifier 并清理驱动残留（提权运行）
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Administrator\Desktop\netproxy\uninstall-proxifier.log'
Remove-Item $log -ErrorAction SilentlyContinue
function Say($m) { $m | Out-File -FilePath $log -Append -Encoding utf8; }
function Say2($m) { $m | Out-File -FilePath $log -Append -Encoding utf8; }

Say "=== 卸载 Proxifier $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

# 0) 确保进程不在跑
Get-Process Proxifier,ProxyChecker -ErrorAction SilentlyContinue | ForEach-Object {
    Say "  kill $($_.ProcessName) PID=$($_.Id)"; try { $_.Kill() } catch {}
}
Start-Sleep -Seconds 1

# 1) 驱动服务若还在，先停再删
$svc = Get-Service -Name 'ProxifierDrv' -ErrorAction SilentlyContinue
if ($svc) {
    Say "  驱动服务仍在（$($svc.Status)），停止并删除"
    & sc.exe stop ProxifierDrv  | Out-Null
    Start-Sleep -Seconds 2
    & sc.exe delete ProxifierDrv | Out-Null
    Say "  sc delete 返回: $LASTEXITCODE"
} else { Say "  驱动服务已不存在" }

# 2) 跑 Inno 静默卸载
$unins = 'C:\Program Files (x86)\Proxifier\unins000.exe'
if (Test-Path $unins) {
    Say "  执行静默卸载: $unins"
    $p = Start-Process -FilePath $unins -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -PassThru
    Say "  卸载器 PID=$($p.Id)，等待完成"
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 2
        if (-not (Test-Path 'C:\Program Files (x86)\Proxifier\Proxifier.exe')) { Say "  安装目录已清空（$($i*2)s）"; break }
    }
} else { Say "  卸载器不存在（可能已卸载）" }

# 3) 清残留目录 / 驱动文件
$dir = 'C:\Program Files (x86)\Proxifier'
if (Test-Path $dir) {
    $left = Get-ChildItem $dir -Recurse -ErrorAction SilentlyContinue
    if ($left) { Say "  目录仍残留 $($left.Count) 项："; $left | ForEach-Object { Say ("    " + $_.FullName.Replace($dir,'')) } }
    try { Remove-Item $dir -Recurse -Force -ErrorAction Stop; Say "  已强制删除残留目录" }
    catch { Say "  删除目录失败: $($_.Exception.Message)" }
} else { Say "  安装目录已不存在" }

$drv = 'C:\Windows\System32\drivers\ProxifierDrv.sys'
if (Test-Path $drv) {
    try { Remove-Item $drv -Force -ErrorAction Stop; Say "  已删除驱动文件 ProxifierDrv.sys" }
    catch { Say "  删除驱动文件失败: $($_.Exception.Message)" }
} else { Say "  驱动文件已不存在" }

# 4) 复核
Say "`n=== 复核 ==="
Say "  Proxifier.exe 存在: $(Test-Path 'C:\Program Files (x86)\Proxifier\Proxifier.exe')"
Say "  安装目录存在: $(Test-Path 'C:\Program Files (x86)\Proxifier')"
Say "  驱动文件存在: $(Test-Path $drv)"
$s = Get-Service -Name 'ProxifierDrv' -ErrorAction SilentlyContinue
Say "  驱动服务: $(if ($s) { $s.Status } else { '已不存在' })"
$rk = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
Say "  Run 键 Proxifier: $(if ($rk.Proxifier) { $rk.Proxifier } else { '无' })"
$hklm = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
         Where-Object { $_.DisplayName -match 'Proxifier' }
Say "  注册表卸载项: $(if ($hklm) { '仍存在' } else { '已清除' })"
Say "=== done ==="
