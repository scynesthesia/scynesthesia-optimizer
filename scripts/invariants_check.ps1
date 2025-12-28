$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$searchRoot = Get-Item -LiteralPath $repoRoot

$flagToken = '$Global:' + 'NeedsReboot'
$pattern = $flagToken

$files = Get-ChildItem -Path $searchRoot.FullName -Recurse -File -ErrorAction Stop | Where-Object {
    $_.FullName -notmatch '[/\\]\\.git([/\\]|$)'
}

$violations = Select-String -Path $files.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue

if ($violations) {
    Write-Host "[FAIL] $flagToken usage detected. Please replace with Get-RebootRequired/Set-RebootRequired helpers." -ForegroundColor Red
    $violations | ForEach-Object {
        Write-Host (" - {0}:{1}" -f $_.Path, $_.LineNumber) -ForegroundColor Yellow
    }
    exit 1
}

Write-Host "[OK] No $flagToken usage found." -ForegroundColor Green
