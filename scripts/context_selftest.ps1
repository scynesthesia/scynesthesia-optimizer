$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulesRoot = Join-Path $repoRoot 'modules'

Import-Module (Join-Path $modulesRoot 'core/context.psm1') -Force

Write-Host "[SelfTest] Validating reboot fallback isolation..." -ForegroundColor Cyan

$baselineContext = New-RunContext
if (Get-RebootRequired -Context $baselineContext) {
    throw "New-RunContext should initialize without a reboot requirement."
}

Set-RebootRequired | Out-Null
if (-not (Get-RebootRequired)) {
    throw "Fallback reboot flag was not set when Set-RebootRequired ran without context."
}

$freshContext = New-RunContext

if (Get-RebootRequired) {
    throw "Fallback reboot flag should reset when creating a new run context."
}

if (Get-RebootRequired -Context $freshContext) {
    throw "Newly created context should not inherit reboot state from fallback."
}

if ($freshContext.NeedsReboot) {
    throw "Context.NeedsReboot should remain false after fallback-only reboot request."
}

Write-Host "[OK] Fallback reboot flag no longer contaminates new run contexts." -ForegroundColor Green
