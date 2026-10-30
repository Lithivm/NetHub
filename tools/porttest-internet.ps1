param([int]$TimeoutMs = 5000)
# 对照组：公网目标应当仍然"直连可达"（我们的内核过滤器只抓内网网段，不碰这些）
$targets = @(
    @{h='www.baidu.com'; p=443; note='公网 HTTPS'},
    @{h='mirrors.aliyun.com'; p=443; note='公网 HTTPS'},
    @{h='223.5.5.5'; p=53; note='公网 DNS TCP'}
)
foreach ($t in $targets) {
    $c = New-Object Net.Sockets.TcpClient
    $ok = $false
    try { $ok = $c.ConnectAsync($t.h, $t.p).Wait($TimeoutMs) } catch { $ok = $false }
    $c.Close()
    $state = if ($ok) { 'REACHABLE' } else { 'unreachable' }
    Write-Output ("{0,-22} {1,-12} {2}" -f ("$($t.h):$($t.p)"), $state, $t.note)
}
