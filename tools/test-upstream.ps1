param([int]$Try = 3, [int]$TimeoutMs = 6000,
      # 上游入口（host:port）。仓库默认是文档保留地址 —— 真上游地址属于现场资产，不写进代码。
      # 现场用法：-Upstream '1.2.3.4:10080','5.6.7.8:33001'
      [string[]]$Upstream = @('203.0.113.10:10080', '203.0.113.11:33001'))

[Console]::OutputEncoding = [Text.Encoding]::UTF8
# 只看两个上游入口本身的可达性（我们的 gost 要连它们）
function Test-Up($h, $p) {
    $c = New-Object Net.Sockets.TcpClient
    $ok = $false
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { $ok = $c.ConnectAsync($h, $p).Wait($TimeoutMs) } catch { $ok = $false }
    $sw.Stop()
    $c.Close()
    "{0,-24} {1,-12} {2} ms" -f "${h}:${p}", $(if ($ok) { 'REACHABLE' } else { 'unreachable' }), $sw.ElapsedMilliseconds
}
foreach ($i in 1..$Try) {
    Write-Output "--- 第 $i 次 ---"
    foreach ($u in $Upstream) {
        $hp = $u -split ':'
        if ($hp.Count -ge 2) { Test-Up $hp[0] $hp[1] }
    }
}
