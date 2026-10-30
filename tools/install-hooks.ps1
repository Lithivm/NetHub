# 把仓库里的 pre-commit 接到本机（每台机器跑一次）。
# 用 core.hooksPath 而不是复制到 .git/hooks：改了仓库里的 hook，所有人下次就同步到。
$root = Split-Path -Parent $PSScriptRoot
git -C $root config core.hooksPath tools/hooks
Write-Output ('core.hooksPath = ' + (git -C $root config core.hooksPath))
Write-Output '已生效：下次 git commit 会先跑 secret-scan + BOM 检查。'