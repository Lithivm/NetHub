param([int]$TimeoutMs = 3000,
      # 探测目标：host:port[:说明]。**仓库默认空** —— 不把客户地址写进代码。
      # 现场用法：-Targets '10.0.0.5:5432:PostgreSQL','10.0.0.6:443:HIS'
      [string[]]$Targets = @())

# 中文说明要在 GBK 控制台下也能看，否则打印出来是乱码
$OutputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
# 内网目标连通性探测（只发 TCP SYN，不传任何数据）
# 参数名是 $Targets，内部一律用 $probe —— 同名会让“传了 -Targets 却没生效”变成隐蔽 bug。
$probe = @($Targets | Where-Object { $_ } | ForEach-Object {
    $p = $_ -split ':', 3
    @{ h = $p[0]; p = [int]$(if ($p[1]) { $p[1] } else { 443 })
       note = $(if ($p.Count -gt 2 -and $p[2]) { $p[2] } else { '' }) }
})
if ($probe.Count -eq 0) {
    Write-Output '未提供 -Targets（仓库默认不带客户地址）。用法：-Targets "10.0.0.5:5432:PostgreSQL"'
}
foreach ($t in $probe) {
    $c = New-Object Net.Sockets.TcpClient
    $ok = $false
    try { $ok = $c.ConnectAsync($t.h, $t.p).Wait($TimeoutMs) } catch { $ok = $false }
    $c.Close()
    $state = if ($ok) { 'REACHABLE' } else { 'unreachable' }
    Write-Output ("{0,-20} {1,-12} {2}" -f ("$($t.h):$($t.p)"), $state, $t.note)
}
