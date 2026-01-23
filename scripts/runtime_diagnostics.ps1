$ErrorActionPreference = 'Stop'

function Write-Result {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][ValidateSet('OK','WARN','FAIL')][string]$Status,
        [string]$Details
    )

    $color = switch ($Status) {
        'OK' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }

    $message = if ($Details) { "[$Status] $Label - $Details" } else { "[$Status] $Label" }
    Write-Host $message -ForegroundColor $color
}

$results = [System.Collections.Generic.List[pscustomobject]]::new()

function Add-CheckResult {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][ValidateSet('OK','WARN','FAIL')][string]$Status,
        [string]$Details
    )

    $results.Add([pscustomobject]@{
        Label = $Label
        Status = $Status
        Details = $Details
    }) | Out-Null
}

$adminCheck = $false
try {
    $adminCheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $adminCheck = $false
}

if ($adminCheck) {
    Add-CheckResult -Label 'Administrator privileges' -Status 'OK'
} else {
    Add-CheckResult -Label 'Administrator privileges' -Status 'FAIL' -Details 'Not running as Administrator.'
}

$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 5) {
    Add-CheckResult -Label 'PowerShell version' -Status 'OK' -Details $psVersion.ToString()
} else {
    Add-CheckResult -Label 'PowerShell version' -Status 'FAIL' -Details $psVersion.ToString()
}

$osCaption = $null
try {
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
    Add-CheckResult -Label 'Operating System' -Status 'OK' -Details $osCaption
} catch {
    Add-CheckResult -Label 'Operating System' -Status 'WARN' -Details 'Unable to query Win32_OperatingSystem.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$moduleMapPath = Join-Path $repoRoot 'modules/modules.map.psd1'
if (-not (Test-Path $moduleMapPath)) {
    Add-CheckResult -Label 'Module map' -Status 'FAIL' -Details "Missing $moduleMapPath"
} else {
    Add-CheckResult -Label 'Module map' -Status 'OK' -Details $moduleMapPath
    try {
        $moduleMap = Import-PowerShellDataFile -Path $moduleMapPath -ErrorAction Stop
        $modulePaths = @()
        if ($moduleMap.Core) { $modulePaths += $moduleMap.Core }
        if ($moduleMap.Features) { $modulePaths += $moduleMap.Features }
        foreach ($modulePath in $modulePaths) {
            if (-not $modulePath) { continue }
            $resolved = if ([System.IO.Path]::IsPathRooted($modulePath)) {
                $modulePath
            } else {
                Join-Path $repoRoot $modulePath
            }
            if (Test-Path $resolved) {
                Add-CheckResult -Label "Module file: $modulePath" -Status 'OK'
            } else {
                Add-CheckResult -Label "Module file: $modulePath" -Status 'FAIL' -Details "Missing file at $resolved"
            }
        }
    } catch {
        Add-CheckResult -Label 'Module map parse' -Status 'FAIL' -Details $_.Exception.Message
    }
}

$requiredCommands = @(
    'bcdedit',
    'dism',
    'netsh',
    'powercfg',
    'reg',
    'sc',
    'schtasks',
    'vssadmin',
    'wevtutil'
)

foreach ($command in $requiredCommands) {
    if (Get-Command -Name $command -ErrorAction SilentlyContinue) {
        Add-CheckResult -Label "Command: $command" -Status 'OK'
    } else {
        Add-CheckResult -Label "Command: $command" -Status 'FAIL' -Details 'Command not found.'
    }
}

$requiredCmdlets = @(
    'Get-NetAdapter',
    'Get-NetAdapterAdvancedProperty',
    'Get-NetTCPSetting',
    'Get-SmbServerConfiguration',
    'Get-ComputerRestorePoint'
)

foreach ($cmdlet in $requiredCmdlets) {
    if (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue) {
        Add-CheckResult -Label "Cmdlet: $cmdlet" -Status 'OK'
    } else {
        Add-CheckResult -Label "Cmdlet: $cmdlet" -Status 'WARN' -Details 'Cmdlet not available in this session.'
    }
}

$restoreStatus = $null
try {
    $restoreStatus = (Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -First 1)
    Add-CheckResult -Label 'System Restore' -Status 'OK' -Details 'Restore point API available.'
} catch {
    Add-CheckResult -Label 'System Restore' -Status 'WARN' -Details 'Unable to query restore points.'
}

Write-Host "`n==== Scynesthesia Optimizer Diagnostics ====" -ForegroundColor Cyan
foreach ($item in $results) {
    Write-Result -Label $item.Label -Status $item.Status -Details $item.Details
}

$failures = $results | Where-Object { $_.Status -eq 'FAIL' }
$warnings = $results | Where-Object { $_.Status -eq 'WARN' }

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host ("Failures: {0}" -f $failures.Count) -ForegroundColor Red
Write-Host ("Warnings: {0}" -f $warnings.Count) -ForegroundColor Yellow

if ($failures.Count -gt 0) {
    Write-Host "`nOne or more FAIL checks indicate required components are missing or blocked. Review above output before running presets." -ForegroundColor Red
    exit 1
}

Write-Host "`nDiagnostics completed." -ForegroundColor Green
