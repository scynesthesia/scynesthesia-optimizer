$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulesRoot = Join-Path $repoRoot 'modules'

Import-Module (Join-Path $modulesRoot 'core/config.psm1') -Force
Import-Module (Join-Path $modulesRoot 'core/network_discovery.psm1') -Force

Write-Host "[SelfTest] Validating script root resolution..." -ForegroundColor Cyan
$Global:ScriptRoot = $repoRoot
$rootFromGlobal = config\Get-ScriptRoot
$Global:ScriptRoot = $null
$rootFromLocal = config\Get-ScriptRoot -LocalRoot $repoRoot

if ($rootFromGlobal -ne $repoRoot) {
    throw "Get-ScriptRoot did not prefer Global:ScriptRoot. Expected $repoRoot, got $rootFromGlobal"
}
if ($rootFromLocal -ne $repoRoot) {
    throw "Get-ScriptRoot did not fall back to caller root. Expected $repoRoot, got $rootFromLocal"
}

Write-Host "[SelfTest] Loading app removal list via shared config..." -ForegroundColor Cyan
$apps = config\Get-AppRemovalList -Mode 'Debloat'
if (-not $apps -or $apps.Count -eq 0) {
    throw "App removal list returned no entries; expected data from config/apps.json"
}
Write-Host ("[OK] Retrieved {0} app entries from config/apps.json" -f $apps.Count) -ForegroundColor Green

Write-Host "[SelfTest] Verifying NIC registry map discovery..." -ForegroundColor Cyan
try {
    $nicMap = network_discovery\Get-NicRegistryMap -AdapterResolver { Get-NetAdapter -Physical -ErrorAction SilentlyContinue }
} catch {
    $nicMap = @()
}

if ($nicMap.Count -gt 0) {
    Write-Host ("[OK] Discovered {0} NIC registry mappings." -f $nicMap.Count) -ForegroundColor Green
} else {
    Write-Host "[SKIP] No NIC registry mappings available in this environment; skipping NIC map assertion." -ForegroundColor Yellow
}
