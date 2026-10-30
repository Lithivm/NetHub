# 入库前门禁：扫一遍**要提交的内容**里有没有客户/现场信息。
#
# 为什么要有它（2026-10-30 的教训）：把示例写成 <客户真实域名>、把验收目标写死进脚本，
# 这类事在 review 里看不出来（它们长得就像正常代码），一旦 commit 就进了 git 历史 ——
# 删掉工作树也没用，只能 filter-repo 重写历史。挡在 commit 之前便宜一万倍。
#
# 黑名单从 local/sanitize/block.txt 读（**黑名单本身不入库**：它就是一串客户标识）。
# 没有黑名单时只跑内置规则（绝对路径 / 明文凭据），照样能挡住最常见的两种手滑。
#
# 用法：pwsh -File tools/check-secrets.ps1            # 扫已跟踪的工作树
#       pwsh -File tools/check-secrets.ps1 -Staged    # 只扫暂存区（pre-commit 用）
param([switch]$Staged)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $files = if ($Staged) {
        @(git diff --cached --name-only --diff-filter=ACMR)
    } else {
        @(git ls-files)
    }
    $files = $files | Where-Object { $_ -and $_ -notmatch '^(local|\.git)/' -and $_ -notmatch '\.(png|jpg|jpeg|ico|exe|dll|sys|zip)$' }
    if (-not $files) { Write-Output 'secret-scan: 没有要扫的文件'; exit 0 }

    # 扫描器出错（正则写坏、文件列表过长…）**必须报错退出**：以前这里 2>$null，
    # 结果“规则写错”被当成“没命中”，门禁静默放行 —— 比没有门禁更危险。
    function ScanTrim([string]$pattern, [bool]$fixed, [string]$tag, $scan) {
        if (-not $scan -or $scan.Count -eq 0) { return @() }
        $out = if ($fixed) {
            @(rg -n -i -F --no-heading -e $pattern -- $scan 2>&1)
        } else {
            @(rg -n --no-heading --pcre2 -e $pattern -- $scan 2>&1)
        }
        $rc = $LASTEXITCODE
        if ($rc -gt 1) { Write-Output ('secret-scan: 扫描器出错（规则「' + $tag + '」）：' + ($out -join ' / ')); exit 2 }
        return $out
    }

    $victims = @()

    # ① 本机精确串黑名单（一行一个 from|说明）。只用「像具体值」的串（域名/IP）：
    #    短泛词（HIS / NetHub 这类）会让门禁天天误报，被 --no-verify 绕过，等于没有。
    $block = Join-Path $root 'local\sanitize\block.txt'
    if (Test-Path $block) {
        $words = @(Get-Content $block -Encoding UTF8 |
            Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') } |
            ForEach-Object { ($_ -split '\|')[0].Trim() } |
            Where-Object { $_ })
        foreach ($w in $words) {
            $hits = ScanTrim $w $true '黑名单' $files
            if ($hits) { $victims += ($hits | ForEach-Object { '   [黑名单] ' + $_ }) }
        }
        Write-Output ('node: 精确串黑名单 ' + $words.Count + ' 条（local/sanitize/block.txt，不入库）')
    } else {
        Write-Output 'node: 没有本机黑名单（local/sanitize/block.txt），只跑内置规则'
    }

    # ② 内置规则。绝对路径用**字面匹配**（-F）而不是正则：正则里的反斜杠转义是这里
    #    最容易写错的地方，而它一写错就变成静默放行。
    $abs = 'C:' + [char]92 + 'Users' + [char]92
    $hits = ScanTrim $abs $true '绝对路径' $files
    if ($hits) { $victims += ($hits | ForEach-Object { '   [绝对路径] ' + $_ }) }

    # 凭据规则排除测试文件：测试里必然有假口令（eg "u:wrong"、"u:xxxx" 是刻意的用例），
    # 它们本来就该长得像真口令。真凭据写进测试这种情形由黑名单兜底。
    # 注意 rg 的 -g 对**显式文件列表**不生效，所以先筛列表。
    $noTest = @($files | Where-Object { $_ -notmatch '_test\.go$' })
    $cred = 'socks5(\+tls)?://[^\s:/]+:(?!pass|secret|XXXXXX|p%40ss%3Aword|xxxx)[^\s@]{4,}@'
    $hits = ScanTrim $cred $false '明文凭据' $noTest
    if ($hits) { $victims += ($hits | ForEach-Object { '   [明文凭据] ' + $_ }) }

    if ($victims.Count -gt 0) {
        Write-Output ''
        Write-Output 'secret-scan: FAIL —— 下面这些地方带了客户/现场信息，别提交：'
        $victims | Select-Object -First 40 | ForEach-Object { Write-Output $_ }
        Write-Output ''
        Write-Output '  改法：域名/IP 换成示例（*.example.com / 192.0.2.x / 203.0.113.x），'
        Write-Output '        目标改成参数（-Targets / -Upstream），文档里的真实值换成 <客户>占位。'
        exit 1
    }
    Write-Output ('secret-scan: OK（扫了 ' + $files.Count + ' 个文件）')
    exit 0
} finally { Pop-Location }