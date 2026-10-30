# Normalize every .ps1 in this repo (root + tools/ + local/) to UTF-8 WITH BOM.
#
# Why this exists (we hit it three times on 2026-09-18):
#   Windows PowerShell 5.1 decodes a BOM-less UTF-8 .ps1 as ANSI (GBK on zh-CN).
#   Chinese comments/strings then turn into mojibake, and a mangled trailing byte
#   can swallow the line ending -- so the NEXT line silently becomes part of a
#   comment. The script "runs" but skips code, with no error. Editors (and the
#   agent tools) strip the BOM when they rewrite a file, which re-arms the trap.
#
#   A UTF-8 BOM makes 5.1 read the file correctly; PowerShell 7 reads it fine
#   either way. Pure-ASCII scripts are left untouched (no BOM needed).
#
# Usage:
#   pwsh -File tools\fix-ps1-encoding.ps1          # fix in place (idempotent)
#   pwsh -File tools\fix-ps1-encoding.ps1 -Check   # report only, exit 1 if any
#
# Run it after editing any .ps1 with a tool that may drop the BOM.
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$self = Split-Path -Parent $MyInvocation.MyCommand.Path          # ...\local
$base = Split-Path -Parent $self                                  # repo root
if (-not (Test-Path (Join-Path $base 'main.go'))) { $base = $self }

$files = Get-ChildItem -Path $base, (Join-Path $base 'tools'), (Join-Path $base 'local') -Filter *.ps1 -File -ErrorAction SilentlyContinue |
         Sort-Object FullName -Unique
$need = @()
$warn = @()

foreach ($f in $files) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    if ($bytes.Length -eq 0) { continue }
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $nonAscii = $false
    foreach ($b in $bytes) { if ($b -gt 0x7F) { $nonAscii = $true; break } }
    if ($hasBom -or -not $nonAscii) { continue }

    # Refuse to touch anything that is not valid UTF-8 (e.g. a real ANSI/GBK file):
    # rewriting it would corrupt it further. Report instead.
    $text = [IO.File]::ReadAllText($f.FullName, (New-Object Text.UTF8Encoding $false))
    if ($text.Contains([char]0xFFFD)) {
        $warn += $f
        continue
    }
    $need += $f
    if (-not $Check) {
        [IO.File]::WriteAllText($f.FullName, $text, (New-Object Text.UTF8Encoding $true))
    }
}

foreach ($f in $warn) {
    "SKIP (not valid UTF-8, fix by hand): $($f.FullName)"
}
if ($need.Count -eq 0 -and $warn.Count -eq 0) {
    "OK: every non-ASCII .ps1 already has a UTF-8 BOM."
} else {
    $tag = if ($Check) { 'NEEDS BOM' } else { 'FIXED    ' }
    foreach ($f in $need) { "$tag : $($f.FullName)" }
    if ($Check) { exit 1 }
    ""
    "Fixed $($need.Count) file(s). Verify with:  pwsh -File tools\fix-ps1-encoding.ps1 -Check"
}
