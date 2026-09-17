param([int]$Try = 3, [int]$TimeoutMs = 6000)
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
    Test-Up '203.0.113.10' 10080
    Test-Up '203.0.113.11'   33001
}
