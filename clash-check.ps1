# Clash 与 netproxy 的共存判定（只读，不改任何设置）
#
# 判定三件事：
#   1) 系统代理当前是什么模式（PAC / 普通系统代理 / 关）
#   2) 浏览器那条路会把内网域名判成 DIRECT 还是走代理
#   3) 内网"经 Clash 解析域名"和"直连"分别能不能通 —— 定位问题是 DNS 还是路由
#
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File clash-check.ps1
$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
function Sec($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Cyan }
function OK($t) { Write-Host "  [OK]   $t" -ForegroundColor Green }
function BAD($t) { Write-Host "  [BAD]  $t" -ForegroundColor Red }
function INFO($t) { Write-Host "  [info] $t" -ForegroundColor Gray }

Sec "1) 系统代理现状（WinINET —— 浏览器跟随的那套）"
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$p = Get-ItemProperty $k
$pac = $p.AutoConfigURL
INFO ("ProxyEnable   = " + $p.ProxyEnable)
INFO ("ProxyServer   = " + $(if ($p.ProxyServer) { $p.ProxyServer } else { '(未设置)' }))
INFO ("AutoConfigURL = " + $(if ($pac) { $pac } else { '(未设置)' }))
if ($pac) {
    BAD "当前是 PAC 模式 —— ProxyOverride 绕过列表在此模式下不生效"
    INFO "解释：PAC 由脚本决定去向；浏览器会把【域名】交给代理，代理用自己的 DNS 解析（看不到 hosts）"
} elseif ($p.ProxyEnable -eq 1) {
    OK "当前是普通系统代理模式 —— ProxyOverride 绕过列表会生效"
    $ov = $p.ProxyOverride
    foreach ($need in @('10.*', '172.*')) {
        if ($ov -like "*$need*") { OK "绕过列表含 $need" } else { BAD "绕过列表缺 $need" }
    }
} else {
    OK "系统代理关闭 —— 浏览器直连，解析走 hosts，交给 netproxy 内核拦截"
}

Sec "2) 浏览器那条路会把内网域名判成什么"
try {
    $w = [System.Net.WebRequest]::GetSystemWebProxy()
    foreach ($u in @('http://app.example.com/', 'http://opm.example.com/', 'http://10.0.0.10/', 'https://chatgpt.com/')) {
        $r = $w.GetProxy([uri]$u)
        $direct = ($r.AbsoluteUri.TrimEnd('/') -eq $u.TrimEnd('/'))
        if ($direct) { OK ("{0,-26} -> DIRECT 直连（安全：浏览器自己用 hosts 解析）" -f $u) }
        else { BAD ("{0,-26} -> 走代理 {1}（危险：代理用自己的 DNS，解析不到内网 IP）" -f $u, $r.AbsoluteUri) }
    }
} catch { BAD ("解析 PAC 失败: " + $_.Exception.Message) }

Sec "3) DNS 归属定位（同一个目标，两种解析方式）"
$curl = (Get-Command curl.exe -EA SilentlyContinue).Source
if (-not $curl) { INFO "没有 curl.exe，跳过" }
else {
    $proxyPort = 7897
    $m = Get-NetTCPConnection -State Listen -EA SilentlyContinue |
         Where-Object { $_.LocalAddress -in '127.0.0.1', '::' -and $_.LocalPort -in 7897, 7890 }
    if ($m) { $proxyPort = $m[0].LocalPort }
    INFO "Clash 混合端口 = $proxyPort"

    INFO "a) 由 Clash 解析域名（--socks5-hostname，= 浏览器走 PAC 的真实行为）"
    # 走 cmd /c 是为了不让 curl 的 stderr 被 PowerShell 包成 NativeCommandError
    $out = & cmd /c "`"$curl`" --socks5-hostname 127.0.0.1:$proxyPort -k -sS -o NUL -w `"%{http_code}`" --max-time 15 https://app.example.com/ 2>&1"
    $code = ($out | Out-String).Trim()
    if ($code -match '^\d{3}$' -and [int]$code -gt 0) {
        OK "HTTP $code —— Clash 能解析内网域名（DNS 走的是系统 hosts）"
    } else {
        BAD "TLS/连接失败 —— Clash 没把 app.example.com 解析到内网 IP"
        INFO "原因：Clash 用自己的 DNS（或 fake-ip），看不到系统 hosts 文件"
    }

    INFO "b) 直连（= netproxy 内核拦截接管的路径）"
    $out2 = & cmd /c "`"$curl`" -k -sS -o NUL -w `"%{http_code}|%{remote_ip}`" --max-time 15 https://app.example.com/ 2>&1"
    $code2 = ($out2 | Out-String).Trim()
    if ($code2 -match '^(\d{3})\|(.+)$') { OK ("HTTP " + $Matches[1] + "  连接IP=" + $Matches[2]) }
    else { BAD ("失败：" + $code2) }
}

Sec "4) 内网 6 个目标（netproxy 视角，与应用无关）"
$targets = @(
    @('10.0.1.10', 5432, 'DBHub PostgreSQL'),
    @('10.0.1.11', 6446, 'DBHub MySQL'),
    @('10.0.0.11', 5000, 'Navicat'),
    @('10.0.0.10', 443, '业务系统 app.example.com'),
    @('10.0.0.12', 9056, '内部 API'),
    @('192.168.100.10', 80, 'site-b.example.com')
)
$bad = 0
foreach ($t in $targets) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($t[0], $t[1], $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(6000, $false)) {
            $c.EndConnect($iar); OK ("{0,-22} {1}" -f "$($t[0]):$($t[1])", $t[2])
        } else { BAD ("{0,-22} {1}" -f "$($t[0]):$($t[1])", $t[2]); $bad++ }
    } catch { BAD ("{0,-22} {1}" -f "$($t[0]):$($t[1])", $t[2]); $bad++ } finally { $c.Close() }
}
if ($bad -eq 0) { OK "6/6 全通" } else { BAD "$bad/6 不通" }

Write-Host "`n结论怎么读：第 3 节 (a) 失败而 (b) 成功 = 问题在 Clash 的 DNS，不在路由。" -ForegroundColor Yellow
Write-Host "修法：让内网请求别经过 Clash（改直连/绕过，或关掉 PAC 用普通系统代理模式）。" -ForegroundColor Yellow
