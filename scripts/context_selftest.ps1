$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulesRoot = Join-Path $repoRoot 'modules'

Import-Module (Join-Path $modulesRoot 'core/context.psm1') -Force

Write-Host "[SelfTest] Validating reboot fallback isolation..." -ForegroundColor Cyan

$baselineContext = New-RunContext
if (Get-RebootRequired -Context $baselineContext) {
    throw "New-RunContext should initialize without a reboot requirement."
}

$freshContext = New-RunContext

Set-RebootRequired -Context $baselineContext | Out-Null
if (-not (Get-RebootRequired -Context $baselineContext)) {
    throw "Set-RebootRequired must mark the provided context."
}

if (Get-RebootRequired -Context $freshContext) {
    throw "Newly created contexts should not inherit reboot state from other runs."
}

Reset-NeedsReboot -Context $baselineContext | Out-Null
if (Get-RebootRequired -Context $baselineContext) {
    throw "Reset-NeedsReboot should clear the reboot flag on the provided context."
}

Write-Host "[OK] Reboot state is isolated to the provided context." -ForegroundColor Green
