param([int]$TimeoutMs = 3000)
# 内网目标连通性探测（只发 TCP SYN，不传任何数据）
$targets = @(
    @{h='10.0.1.10';  p=5432; note='DBHub PostgreSQL (proxy-a)'},
    @{h='10.0.1.11';  p=6446; note='DBHub MySQL (proxy-a)'},
    @{h='10.0.0.11';  p=5000; note='Navicat (proxy-a)'},
    @{h='10.0.0.10';  p=443;  note='业务系统 app.example.com (proxy-a)'},
    @{h='10.0.0.12';  p=9056; note='内部 API (proxy-a)'},
    @{h='192.168.100.10'; p=80;   note='site-b.example.com (proxy-b)'}
)
foreach ($t in $targets) {
    $c = New-Object Net.Sockets.TcpClient
    $ok = $false
    try { $ok = $c.ConnectAsync($t.h, $t.p).Wait($TimeoutMs) } catch { $ok = $false }
    $c.Close()
    $state = if ($ok) { 'REACHABLE' } else { 'unreachable' }
    Write-Output ("{0,-20} {1,-12} {2}" -f ("$($t.h):$($t.p)"), $state, $t.note)
}
