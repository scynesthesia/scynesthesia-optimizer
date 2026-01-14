
[CmdletBinding()]
param(
    [switch]$DebugModules,
    [switch]$UnsafeMode
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

function Stop-RollbackTimerSafely {
    try {
        if (Get-Command -Name Stop-RollbackPersistenceTimer -ErrorAction SilentlyContinue) {
            Stop-RollbackPersistenceTimer -Timer $script:RollbackPersistTimer -Subscription $script:RollbackPersistSubscription -SourceIdentifier 'RegistryRollbackPersistence'
        }
    } catch { }

    if ($script:RollbackPersistTimer) {
        try { $script:RollbackPersistTimer.Dispose() } catch { }
    }
}

try {
    $modulesRoot = Join-Path $scriptRoot 'modules'
    $moduleMapPath = Join-Path $modulesRoot 'modules.map.psd1'

    if (-not $script:ModuleHashCache) {
        $script:ModuleHashCache = @{}
    }

    if (-not (Test-Path $moduleMapPath)) {
        throw "Module map not found: $moduleMapPath"
    }

    $moduleMap = Import-PowerShellDataFile -Path $moduleMapPath -ErrorAction Stop
    if ($null -eq $moduleMap -or $moduleMap.Count -eq 0) {
        throw 'El mapa de módulos está vacío o es inválido. Revisa modules/modules.map.psd1.'
    }
    $orderedModules = @()

    if ($moduleMap.Core) { $orderedModules += $moduleMap.Core }
    if ($moduleMap.Features) { $orderedModules += $moduleMap.Features }

    foreach ($modulePath in $orderedModules) {
        if (-not $modulePath) { continue }

        $resolvedPath = if ([System.IO.Path]::IsPathRooted($modulePath)) {
            $modulePath
        } else {
            Join-Path $scriptRoot $modulePath
        }

        if (-not (Test-Path $resolvedPath)) {
            throw "Module file not found: $resolvedPath"
        }

        $moduleFileName = [System.IO.Path]::GetFileName($resolvedPath)
        $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($moduleFileName)
        $loadedModule = Get-Module -Name $moduleName -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $resolvedPath }

        $moduleHash = (Get-FileHash -Path $resolvedPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $cachedHash = $script:ModuleHashCache[$resolvedPath]
        $moduleChanged = $cachedHash -and ($cachedHash -ne $moduleHash)
        $shouldForceReload = $DebugModules -or $moduleChanged

        if ($loadedModule -and -not $shouldForceReload) {
            if (-not $cachedHash) { $script:ModuleHashCache[$resolvedPath] = $moduleHash }
            Write-Host "[SKIP] Module already loaded: $moduleFileName (hash unchanged)" -ForegroundColor Yellow
            continue
        }

        $importParams = @{ Name = $resolvedPath; ErrorAction = 'Stop'; DisableNameChecking = $true; WarningAction = 'SilentlyContinue' }
        if ($shouldForceReload) { $importParams.Force = $true }

        Import-Module @importParams
        $script:ModuleHashCache[$resolvedPath] = $moduleHash

        $status = if ($loadedModule) {
            if ($DebugModules) { "reloaded (debug)" } elseif ($moduleChanged) { "reloaded (updated)" } else { "reloaded" }
        } else {
            "loaded"
        }
        Write-Host "[OK] Module ${status}: $moduleFileName" -ForegroundColor Green
    }

    Write-Host "Modules loaded successfully." -ForegroundColor Green
} catch {
    if (Get-Command Invoke-ErrorHandler -ErrorAction SilentlyContinue) {
        Invoke-ErrorHandler -Context "Loading modules" -ErrorRecord $_
    } else {
        Write-Error "Error loading modules: $($_.Exception.Message)"
    }
    Stop-RollbackTimerSafely
    Write-Host "Make sure the 'modules' folder is next to this script."
    Read-Host "Press Enter to exit"
    exit 1
}

function Ensure-ModuleCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CommandName,
        [Parameter(Mandatory)]
        [string]$ModuleRelativePath
    )

    if (Get-Command -Name $CommandName -ErrorAction SilentlyContinue) {
        return $true
    }

    $modulePath = Join-Path $scriptRoot $ModuleRelativePath
    if (-not (Test-Path $modulePath)) {
        Write-Error "Required module file not found: $modulePath (needed for $CommandName)"
        return $false
    }

    try {
        Import-Module -Name $modulePath -Force -Global -ErrorAction Stop
    } catch {
        Write-Error "Failed to load module for $CommandName ($modulePath): $($_.Exception.Message)"
        return $false
    }

    if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        Write-Error "Command $CommandName is still unavailable after loading $modulePath."
        return $false
    }

    return $true
}

if (-not (Ensure-ModuleCommand -CommandName 'Get-NeedsReboot' -ModuleRelativePath 'modules/core/context.psm1')) {
    Read-Host "Press Enter to exit"
    exit 1
}

if (-not (Ensure-ModuleCommand -CommandName 'Read-MenuChoice' -ModuleRelativePath 'modules/ui.psm1')) {
    Read-Host "Press Enter to exit"
    exit 1
}

$Context = New-RunContext -ScriptRoot $scriptRoot
$Context.RollbackPersistencePath = Get-RollbackPersistencePath
Restore-RollbackState -Context $Context -Path $Context.RollbackPersistencePath | Out-Null
$script:RollbackPersistencePath = $Context.RollbackPersistencePath
$script:Context = $Context
$script:Context.RegistryRollbackActions = if ($null -ne $Context.RegistryRollbackActions) { $Context.RegistryRollbackActions } else { [System.Collections.Generic.List[object]]::new() }
$script:Context.ServiceRollbackActions = if ($null -ne $Context.ServiceRollbackActions) { $Context.ServiceRollbackActions } else { [System.Collections.Generic.List[object]]::new() }
$script:Context.NetshRollbackActions = if ($null -ne $Context.NetshRollbackActions) { $Context.NetshRollbackActions } else { [System.Collections.Generic.List[object]]::new() }
$script:Context.NetworkHardwareRollbackActions = if ($null -ne $Context.NetworkHardwareRollbackActions) { $Context.NetworkHardwareRollbackActions } else { [System.Collections.Generic.List[object]]::new() }
$script:Logger = Get-Command Write-Log -ErrorAction SilentlyContinue
$script:UnsafeMode = $UnsafeMode

$script:RollbackPersistTimer = [System.Timers.Timer]::new()
$script:RollbackPersistTimer.Interval = 30000
$script:RollbackPersistTimer.AutoReset = $true
$script:RollbackPersistSubscription = Register-ObjectEvent -InputObject $script:RollbackPersistTimer -EventName Elapsed -SourceIdentifier 'RegistryRollbackPersistence' -Action {
    try {
        if ($script:Context) {
            Save-RollbackState -Context $script:Context -Path $script:Context.RollbackPersistencePath | Out-Null
        }
    } catch {
        Write-Verbose "Rollback persistence failed: $($_.Exception.Message)"
    }
} -ErrorAction SilentlyContinue
$script:RollbackPersistTimer.Start()

$TranscriptStarted = $false
if (Get-Confirmation "Enable session logging to a file? (Recommended for service records)" 'n') {
    $logDir = Join-Path $env:TEMP "ScynesthesiaOptimizer"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = Join-Path $logDir "Scynesthesia_Log_$timestamp.txt"
    
    try {
        Start-Transcript -Path $logFile -Append -ErrorAction Stop
        $TranscriptStarted = $true
        Write-Host "Logging started: $logFile" -ForegroundColor Gray
        $Global:ScynesthesiaTranscriptPath = $logFile
        $Global:ScynesthesiaLogPath = Join-Path $logDir "Scynesthesia_Runtime_$timestamp.jsonl"
    } catch {
        Write-Warning "Could not start logging. Check permissions."
    }
}

$script:HighImpactBlocked = $false
$script:HighImpactBlockReason = ""

function Initialize-SessionSummaryTracker {
    param([pscustomobject]$Context)

    $context = Get-RunContext -Context $Context
    if (-not $context.PSObject.Properties.Name.Contains('SessionSummary')) {
        $context | Add-Member -Name SessionSummary -MemberType NoteProperty -Value ([pscustomobject]@{
            Applied            = [System.Collections.Generic.List[string]]::new()
            DeclinedHighImpact = [System.Collections.Generic.List[string]]::new()
            GuardedBlocks      = [System.Collections.Generic.List[string]]::new()
            FailedHighImpact   = [System.Collections.Generic.List[string]]::new()
        })
    }

    foreach ($key in @('Applied','DeclinedHighImpact','GuardedBlocks','FailedHighImpact')) {
        if (-not ($context.SessionSummary.$key)) {
            $context.SessionSummary.$key = [System.Collections.Generic.List[string]]::new()
        }
    }

    return $context.SessionSummary
}

function Add-SessionSummaryItem {
    param(
        [pscustomobject]$Context,
        [ValidateSet('Applied','DeclinedHighImpact','GuardedBlocks','FailedHighImpact')]
        [string]$Bucket,
        [Parameter(Mandatory)][string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    $summary = Initialize-SessionSummaryTracker -Context $Context
    if (-not $summary) { return }

    if (-not ($summary.$Bucket -contains $Message)) {
        [void]$summary.$Bucket.Add($Message)
    }
}

function Reset-HighImpactBlock {
    $script:HighImpactBlocked = $false
    $script:HighImpactBlockReason = ""
}

function Set-HighImpactBlock {
    param([string]$Reason)

    $script:HighImpactBlocked = $true
    $script:HighImpactBlockReason = if ($Reason) { $Reason } else { "A restore point could not be created." }
    Write-Warning "[Safety] $($script:HighImpactBlockReason)"
    Write-Warning "[Safety] Aggressive and Hardcore changes are blocked until System Restore is enabled and a restore point is created. Only Safe tweaks are available."

    Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "High-impact actions blocked: $($script:HighImpactBlockReason)"
}

function Handle-RestorePointGate {
    param(
        [pscustomobject]$RestoreStatus,
        [string]$ActionLabel
    )

    if ($RestoreStatus -and -not $RestoreStatus.Enabled) {
        if (-not $script:RestoreRepairAttempted) {
            try {
                $vssService = Get-Service -Name "VSS" -ErrorAction Stop
                if ($vssService.StartType -eq "Disabled") {
                    Set-Service -Name "VSS" -StartupType Manual -ErrorAction Stop
                }
            } catch {
                Invoke-ErrorHandler -Context "Ensuring VSS service startup type" -ErrorRecord $_
            }

            try {
                & vssadmin resize shadowstorage /for=c: /on=c: /maxsize=5% | Out-Null
            } catch {
                Invoke-ErrorHandler -Context "Resizing VSS shadow storage on C:" -ErrorRecord $_
            }

            $script:RestoreRepairAttempted = $true
        }

        try {
            Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
            Start-Sleep -Seconds 1
        } catch {
            Invoke-ErrorHandler -Context "Enabling System Restore on C:" -ErrorRecord $_
        }

        $RestoreStatus = Invoke-RestorePointWithAutoEnable
    }

    if ($RestoreStatus -and $RestoreStatus.Created) {
        Reset-HighImpactBlock
        return $true
    }

    if ($script:UnsafeMode) {
        Write-Warning "[Safety] Proceeding without a restore point because UnsafeMode is enabled."
        Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "$ActionLabel proceeded without restore point (unsafe mode)"
        return $true
    }

    $reason = if ($RestoreStatus -and -not $RestoreStatus.Enabled) {
        "System Restore is disabled and was not enabled."
    } else {
        "A restore point could not be created for $ActionLabel."
    }

    Set-HighImpactBlock "$reason High-impact changes cannot proceed without an OS-level safety net."
    return $false
}

function Invoke-RestorePointWithAutoEnable {
    param(
        [switch]$EnableAuto
    )

    $previous = $global:ScynesthesiaRestoreAutoEnable
    $global:ScynesthesiaRestoreAutoEnable = [bool]($EnableAuto -or $script:UnsafeMode)
    try {
        return New-RestorePointSafe
    } finally {
        $global:ScynesthesiaRestoreAutoEnable = $previous
    }
}

function Assert-HighImpactAllowed {
    param([string]$ActionLabel)

    if (-not $script:HighImpactBlocked) { return $true }

    $label = if ($ActionLabel) { $ActionLabel } else { "This action" }
    Write-Warning "[Safety] $label is blocked: $($script:HighImpactBlockReason) Only Safe tweaks are available until a restore point succeeds."
    Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "$label blocked: $($script:HighImpactBlockReason)"
    return $false
}

function Confirm-HighImpactRestoreGate {
    param(
        [Parameter(Mandatory)][string]$ActionLabel,
        [switch]$AllowUnsafeOverride
    )

    $restoreStatus = Invoke-RestorePointWithAutoEnable
    $gatePassed = Handle-RestorePointGate -RestoreStatus $restoreStatus -ActionLabel $ActionLabel

    if ($script:Logger) {
        $restoreGateLevel = if ($gatePassed) { 'Info' } else { 'Warning' }
        Write-Log -Message "Restore point gate evaluated." -Level $restoreGateLevel -Data @{
            action         = $ActionLabel
            restoreCreated = [bool]($restoreStatus -and $restoreStatus.Created)
            restoreEnabled = if ($null -ne $restoreStatus) { [bool]$restoreStatus.Enabled } else { $null }
            unsafeMode     = [bool]$script:UnsafeMode
            gatePassed     = [bool]$gatePassed
        }
    }

    if ($gatePassed) {
        return [pscustomobject]@{
            Proceed = $true
            Unsafe  = $false
            Status  = $restoreStatus
        }
    }

    if ($AllowUnsafeOverride) {
        $proceedUnsafely = Get-Confirmation -Question "A restore point could not be created for $ActionLabel. Continue in UNSAFE mode anyway?" -Default 'n'
        if ($script:Logger) {
            $unsafeConfirmLevel = if ($proceedUnsafely) { 'Warning' } else { 'Info' }
            Write-Log -Message "Unsafe mode confirmation after restore gate failure." -Level $unsafeConfirmLevel -Data @{
                action         = $ActionLabel
                unsafeMode     = [bool]$script:UnsafeMode
                userConfirmed  = [bool]$proceedUnsafely
                restoreCreated = [bool]($restoreStatus -and $restoreStatus.Created)
            }
        }

        if ($proceedUnsafely) {
            if (-not $script:UnsafeMode) {
                $script:UnsafeMode = $true
            }
            Write-Warning "[Safety] Proceeding without a restore point due to unsafe override."
            Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "$ActionLabel forced without restore point (unsafe mode)"
            Reset-HighImpactBlock
            return [pscustomobject]@{
                Proceed = $true
                Unsafe  = $true
                Status  = $restoreStatus
            }
        }
    }

    Write-Warning "[Safety] $ActionLabel aborted because a restore point is required and unsafe override was declined."
    Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "$ActionLabel blocked: restore point unavailable (UnsafeMode=$($script:UnsafeMode))"
    return [pscustomobject]@{
        Proceed = $false
        Unsafe  = $false
        Status  = $restoreStatus
    }
}

function Show-Banner {
    Clear-Host
    $hardwareProfile = Get-HardwareProfile
    $activePlanName = 'Unknown'
    try {
        $activePlanOutput = powercfg -getactivescheme 2>$null
        if ($activePlanOutput -match '\((.+)\)') {
            $activePlanName = $Matches[1].Trim()
        }
    } catch { }
    $cpuCores = $env:NUMBER_OF_PROCESSORS
    $memoryDisplay = "{0} GB - {1}" -f ([math]::Round($hardwareProfile.TotalMemoryGB, 1)), $hardwareProfile.MemoryCategory
    $storageType = if ($hardwareProfile.HasSSD -and $hardwareProfile.HasHDD) {
        'Mixed'
    } elseif ($hardwareProfile.HasSSD) {
        'SSD'
    } elseif ($hardwareProfile.HasHDD) {
        'HDD'
    } else {
        'Unknown'
    }
    $banner = @'

 _____                                                                _____
( ___ )--------------------------------------------------------------( ___ )
 |   |                                                                |   | 
 |   |                                  _   _               _         |   | 
 |   |   ___  ___ _   _ _ __   ___  ___| |_| |__   ___  ___(_) __ _   |   | 
 |   |  / __|/ __| | | | '_ \ / _ \/ __| __| '_ \ / _ \/ __| |/ _` |  |   | 
 |   |  \__ \ (__| |_| | | | |  __/\__ \ |_| | | |  __/\__ \ | (_| |  |   | 
 |   |  |___/\___|\__, |_| |_|\___||___/\__|_| |_|\___||___/_|\__,_|  |   | 
 |   |       _    |___/   _             _                             |   | 
 |   |    __| | ___| |__ | | ___   __ _| |_ ___ _ __                  |   | 
 |   |   / _` |/ _ \ '_ \| |/ _ \ / _` | __/ _ \ '__|                 |   | 
 |   |  | (_| |  __/ |_) | | (_) | (_| | ||  __/ |                    |   | 
 |   |   \__,_|\___|_.__/|_|\___/ \__,_|\__\___|_|                    |   | 
 |   |                                                                |   | 
 |___|                                                                |___| 
(_____)--------------------------------------------------------------(_____)

'@
    Write-Host $banner -ForegroundColor Magenta
    Write-Host " Scynesthesia Windows Optimizer v1.0" -ForegroundColor Green
    Write-Host " Profiles: Safe | Slow PC / Aggressive" -ForegroundColor Gray
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " [ System Dashboard ]" -ForegroundColor Cyan
    Write-Host ("  CPU Logical Cores: {0}" -f $cpuCores) -ForegroundColor Gray
    Write-Host ("  Memory: {0}" -f $memoryDisplay) -ForegroundColor Gray
    Write-Host ("  Storage Type: {0}" -f $storageType) -ForegroundColor Gray
    Write-Host ("  Active Power Plan: {0}" -f $activePlanName) -ForegroundColor Gray
    Write-Host "------------------------------------------------------------`n" -ForegroundColor DarkGray
}

function Ensure-PowerPlan {
    param([ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance')
    Write-Host "  [i] Setting base power plan to: $Mode" -ForegroundColor Gray
    if ($Mode -eq 'HighPerformance') {
        try {
            powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null | Out-Null
            powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
            Write-Host "  [+] Base power plan set to $Mode (Ultimate Performance GUID)." -ForegroundColor Gray
        } catch {
            Write-Warning "  [!] Failed to activate Ultimate Performance GUID directly: $($_.Exception.Message)"
            try {
                powercfg /setactive SCHEME_MAX 2>$null
                Write-Host "  [+] High performance power plan activated via fallback." -ForegroundColor Gray
            } catch {
                Write-Warning "  [!] Failed to activate High performance fallback: $($_.Exception.Message)"
            }
        }
    } else {
        try {
            powercfg /setactive SCHEME_BALANCED 2>$null
            Write-Host "  [+] Balanced power plan activated." -ForegroundColor Gray
        } catch {
            Write-Warning "  [!] Failed to activate Balanced plan: $($_.Exception.Message)"
        }
    }
}

function Write-EndOfSessionSummary {
    param([pscustomobject]$Context)

    $context = Get-RunContext -Context $Context
    $summary = Initialize-SessionSummaryTracker -Context $context
    $networkBackupPath = "C:\ProgramData\Scynesthesia\network_backup.json"

    Write-Host ""
    Write-Host "===== End-of-Session Summary =====" -ForegroundColor Cyan

    $applied = @()
    if ($summary -and $summary.Applied) {
        $applied += @($summary.Applied | Where-Object { $_ } | Select-Object -Unique)
    }
    if ($context.PSObject.Properties.Name -contains 'DebloatRemovalLog' -and $context.DebloatRemovalLog -and $context.DebloatRemovalLog.Count -gt 0) {
        $applied += "App removals logged: $(@($context.DebloatRemovalLog | Where-Object { $_ } | Select-Object -Unique).Count) item(s)"
    }
    if ($context.PSObject.Properties.Name -contains 'AppliedTweaks' -and $context.AppliedTweaks.Keys.Count -gt 0) {
        $applied += "Repeat-protected tweaks applied: $($context.AppliedTweaks.Keys -join ', ')"
    }

    $serviceChanges = 0
    if ($context.PSObject.Properties.Name -contains 'ServiceRollbackActions' -and $context.ServiceRollbackActions) {
        $serviceChanges = @($context.ServiceRollbackActions | Where-Object { $_ }).Count
    } elseif ($context.PSObject.Properties.Name -contains 'NonRegistryChanges' -and $context.NonRegistryChanges -and $context.NonRegistryChanges.ServiceState) {
        $serviceChanges = @($context.NonRegistryChanges.ServiceState.GetEnumerator()).Count
    }

    $netshChanges = 0
    if ($context.PSObject.Properties.Name -contains 'NetshRollbackActions' -and $context.NetshRollbackActions) {
        $netshChanges = @($context.NetshRollbackActions | Where-Object { $_ }).Count
    } elseif ($context.PSObject.Properties.Name -contains 'NonRegistryChanges' -and $context.NonRegistryChanges -and $context.NonRegistryChanges.NetshGlobal) {
        $netshChanges = @($context.NonRegistryChanges.NetshGlobal.GetEnumerator()).Count
    }

    if ($serviceChanges -gt 0) {
        $applied += "Service state changes tracked: $serviceChanges"
    }
    if ($netshChanges -gt 0) {
        $applied += "Netsh TCP global changes tracked: $netshChanges"
    }

    if ($applied.Count -gt 0) {
        Write-Host "[+] Tweaks applied:" -ForegroundColor Green
        foreach ($item in ($applied | Select-Object -Unique)) {
            Write-Host "    - $item" -ForegroundColor Gray
        }
    } else {
        Write-Host "[ ] No tweak applications were recorded." -ForegroundColor DarkGray
    }

    $declined = if ($summary -and $summary.DeclinedHighImpact) { @($summary.DeclinedHighImpact | Where-Object { $_ } | Select-Object -Unique) } else { @() }
    if ($declined.Count -gt 0) {
        Write-Host "[!] High-impact prompts declined by user:" -ForegroundColor Yellow
        foreach ($item in $declined) {
            Write-Host "    - $item" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[ ] No user-declined high-impact prompts recorded." -ForegroundColor DarkGray
    }

    $guards = if ($summary -and $summary.GuardedBlocks) { @($summary.GuardedBlocks | Where-Object { $_ } | Select-Object -Unique) } else { @() }
    if ($guards.Count -gt 0) {
        Write-Host "[i] Tweaks blocked by safeguards or compatibility checks:" -ForegroundColor Cyan
        foreach ($item in $guards) {
            Write-Host "    - $item" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[ ] No guard-enforced skips recorded." -ForegroundColor DarkGray
    }

    $failedHighImpact = if ($summary -and $summary.FailedHighImpact) { @($summary.FailedHighImpact | Where-Object { $_ } | Select-Object -Unique) } else { @() }
    if ($failedHighImpact.Count -gt 0) {
        Write-Host "[X] High-impact tweaks skipped due to write failures:" -ForegroundColor Yellow
        foreach ($item in $failedHighImpact) {
            Write-Host "    - $item" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[ ] No high-impact registry failures recorded." -ForegroundColor DarkGray
    }

    $highRiskStatuses = @()
    foreach ($item in $declined) { $highRiskStatuses += "Declined: $item" }
    foreach ($item in $guards) { $highRiskStatuses += "Blocked: $item" }
    foreach ($item in $failedHighImpact) { $highRiskStatuses += "Failed: $item" }
    if ($highRiskStatuses.Count -gt 0) {
        Write-Host "[!] High-risk items requiring follow-up:" -ForegroundColor Yellow
        foreach ($item in ($highRiskStatuses | Select-Object -Unique)) {
            Write-Host "    - $item" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[ ] No high-risk prompts were declined or blocked." -ForegroundColor DarkGray
    }

    $rollbackNote = "Service/netsh changes rely on the network backup at $networkBackupPath for restoration via the Rollback or Network menu."
    if ($serviceChanges -gt 0 -or $netshChanges -gt 0) {
        Write-Host "[Reminder] $rollbackNote" -ForegroundColor Magenta
    } else {
        Write-Host "[Reminder] If you change services or netsh settings later, ensure $networkBackupPath is preserved for rollback." -ForegroundColor Magenta
    }
}

function Write-DebloatRemovalLog {
    param([pscustomobject]$Context)

    $context = Get-RunContext -Context $Context
    if (-not $context -or -not $context.PSObject.Properties.Name.Contains('DebloatRemovalLog')) { return }

    $removalLog = @($context.DebloatRemovalLog | Where-Object { $_ } | Select-Object -Unique | Sort-Object)

    Write-Host ""
    Write-Host "===== Debloat Removal Log =====" -ForegroundColor Cyan
    if ($removalLog.Count -eq 0) {
        Write-Host "[ ] No apps were removed during this session." -ForegroundColor DarkGray
        return
    }

    foreach ($pkg in $removalLog) {
        Write-Host "  - $pkg" -ForegroundColor Green
    }
}

function Invoke-SafeOptionalPrompts {
    param([string]$PresetName = 'Safe preset')

    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    Write-Section "Additional options for Safe preset"
    $options = @(
        @{ Key = '1'; Description = 'Disable Cortana in search'; Critical = $true; Action = {
            Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 -Context $script:Context -Critical -ReturnResult -OperationLabel 'Disable Cortana policy'
        } },
        @{ Key = '2'; Description = 'Disable Store suggestions in Start'; Critical = $false; Action = {
            Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 -Context $script:Context -ReturnResult -OperationLabel 'Disable Store suggestions'
        } },
        @{ Key = '3'; Description = 'Enable compact view in File Explorer'; Critical = $false; Action = {
            Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "UseCompactMode" 1 -Context $script:Context -ReturnResult -OperationLabel 'Enable compact view'
        } }
    )
    foreach ($opt in $options) {
        $label = "$($opt.Key) $($opt.Description)"
        if (Get-Confirmation $label -Default 'n') {
            $result = & $opt.Action
            $applied = $result -and $result.Success
            if ($applied) {
                Write-Host "[OK] $($opt.Description) applied." -ForegroundColor Green
            } else {
                if ($opt.Critical) {
                    Register-HighImpactRegistryFailure -Context $script:Context -Result $result -OperationLabel $opt.Description | Out-Null
                    if (Test-RegistryResultForPresetAbort -Result $result -PresetName $presetLabel -OperationLabel $opt.Description -Critical) { return $true }
                }
                Write-Host "[!] $($opt.Description) could not be applied (check permissions)." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipped: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
    return $false
}

function Handle-RebootIfNeeded {
    param(
        [pscustomobject]$Context,
        [switch]$OnExit
    )

    $needsReboot = Get-NeedsReboot -Context $Context
    if (-not $needsReboot) {
        if ($OnExit) {
            Write-Host "[i] No changes requiring a reboot were applied." -ForegroundColor Gray
        }
        return
    }

    $prompt = "Some changes (like Nagle/MSI Mode) require a reboot to fully apply. Do you want to restart now?"
    if (Get-Confirmation -Question $prompt -Default 'n') {
        $logContext = if ($OnExit) { "[System] User chose to reboot from main menu." } else { "[System] User chose to reboot before returning to the menu." }
        if ($script:Logger) { Write-Log $logContext }
        try {
            shutdown /r /t 0
        } catch {
            Write-Host "[System] Failed to initiate reboot: $($_.Exception.Message)" -ForegroundColor Red
            if ($script:Logger) { Write-Log "[System] Failed to initiate reboot: $($_.Exception.Message)" }
        }
    } else {
        if ($script:Logger) {
            $logMessage = if ($OnExit) { "[System] User chose NOT to reboot at the end of the script." } else { "[System] User chose NOT to reboot before returning to the menu." }
            Write-Log $logMessage
        }
        Write-Host "[System] Reminder: some changes will fully apply after a manual reboot." -ForegroundColor Yellow
    }

    Reset-NeedsReboot -Context $Context | Out-Null
}


function Run-SafePreset {
    $Status = @{ PackagesFailed = @(); PackagesRemoved = @(); RebootRequired = $false }
    if (-not $script:Context.PSObject.Properties.Name.Contains('RegistryPermissionFailures')) {
        $script:Context | Add-Member -Name RegistryPermissionFailures -MemberType NoteProperty -Value @()
    } else {
        $script:Context.RegistryPermissionFailures = @()
    }
    $HWProfile = Get-HardwareProfile

    Write-Section "Starting Preset 1: Safe"
    $restoreStatus = Invoke-RestorePointWithAutoEnable
    $restoreGatePassed = Handle-RestorePointGate -RestoreStatus $restoreStatus -ActionLabel "the Safe preset"
    if ($script:Logger) {
        Write-Log -Message "Restore point gate evaluated." -Level (if ($restoreGatePassed) { 'Info' } else { 'Warning' }) -Data @{
            preset         = 'Safe'
            restoreCreated = [bool]($restoreStatus -and $restoreStatus.Created)
            restoreEnabled = if ($null -ne $restoreStatus) { [bool]$restoreStatus.Enabled } else { $null }
            unsafeMode     = [bool]$script:UnsafeMode
            gatePassed     = [bool]$restoreGatePassed
        }
    }

    if (-not $restoreGatePassed) {
        $proceedUnsafely = $false
        if ($script:UnsafeMode) {
            $proceedUnsafely = Get-Confirmation -Question "A restore point could not be created. Continue in UNSAFE mode anyway?" -Default 'n'
            if ($script:Logger) {
                Write-Log -Message "Unsafe mode confirmation after restore gate failure." -Level (if ($proceedUnsafely) { 'Warning' } else { 'Info' }) -Data @{
                    preset         = 'Safe'
                    unsafeMode     = [bool]$script:UnsafeMode
                    userConfirmed  = [bool]$proceedUnsafely
                    restoreCreated = [bool]($restoreStatus -and $restoreStatus.Created)
                }
            }
        }

        if (-not $proceedUnsafely) {
            Write-Warning "[Safety] Safe preset aborted because a restore point is required. Re-run with -UnsafeMode to override."
            Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "Safe preset blocked: restore point unavailable (UnsafeMode=$($script:UnsafeMode))"
            return
        }

        Write-Warning "[Safety] Proceeding without a restore point due to -UnsafeMode." 
        Reset-HighImpactBlock
    }
    Clear-TempFiles -Context $script:Context

    $privacyAbort = Invoke-PrivacySafe -Context $script:Context
    if ($privacyAbort) {
        Write-Host "[!] Safe preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    $debloatResult = Invoke-DebloatSafe -Context $script:Context # Uses the default list defined in the module
    $Status.PackagesFailed += $debloatResult.Failed
    $Status.PackagesRemoved += $debloatResult.Removed

    $preferencesAbort = Invoke-PreferencesSafe -Context $script:Context -PresetName 'Safe preset'
    if ($preferencesAbort) {
        Write-Host "[!] Safe preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    if (Invoke-SafeOptionalPrompts) {
        Write-Host "[!] Safe preset aborted by user during optional tweaks." -ForegroundColor Red
        return
    }
    Invoke-SysMainOptimization -HardwareProfile $HWProfile
    $baselineAbort = Invoke-PerformanceBaseline -HardwareProfile $HWProfile -Context $script:Context -PresetName 'Safe preset'
    if ($baselineAbort) {
        Write-Host "[!] Safe preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    $performanceAbort = Invoke-SafePerformanceTweaks -Context $script:Context -PresetName 'Safe preset'
    if ($performanceAbort) {
        Write-Host "[!] Safe preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    Invoke-HardwareDeviceHardening -Context $script:Context -Level 'Safe'
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = Get-NeedsReboot -Context $script:Context
    $Status.RegistryPermissionFailures = @($script:Context.RegistryPermissionFailures)
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe preset applied. Restart when convenient to finalize settings." -ForegroundColor Green
    if (-not $script:Context.PSObject.Properties.Name.Contains('AppliedPresets')) {
        $script:Context | Add-Member -Name AppliedPresets -MemberType NoteProperty -Value @()
    } elseif (-not $script:Context.AppliedPresets) {
        $script:Context.AppliedPresets = @()
    }
    if (-not ($script:Context.AppliedPresets -contains 'Safe')) {
        $script:Context.AppliedPresets += 'Safe'
    }
}

function Run-PCSlowPreset {
    if (-not (Assert-HighImpactAllowed "The Aggressive preset")) { return }

    $Status = @{ PackagesFailed = @(); PackagesRemoved = @(); RebootRequired = $false }
    if (-not $script:Context.PSObject.Properties.Name.Contains('RegistryPermissionFailures')) {
        $script:Context | Add-Member -Name RegistryPermissionFailures -MemberType NoteProperty -Value @()
    } else {
        $script:Context.RegistryPermissionFailures = @()
    }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Starting Preset 2: Slow PC / Aggressive"
    $restoreStatus = Invoke-RestorePointWithAutoEnable -EnableAuto
    $restoreGatePassed = Handle-RestorePointGate -RestoreStatus $restoreStatus -ActionLabel "the Aggressive preset"
    if ($script:Logger) {
        $restoreGateLevel = if ($restoreGatePassed) { 'Info' } else { 'Warning' }
        Write-Log -Message "Restore point gate evaluated." -Level $restoreGateLevel -Data @{
            preset         = 'Aggressive'
            restoreCreated = [bool]($restoreStatus -and $restoreStatus.Created)
            restoreEnabled = if ($null -ne $restoreStatus) { [bool]$restoreStatus.Enabled } else { $null }
            unsafeMode     = [bool]$script:UnsafeMode
            gatePassed     = [bool]$restoreGatePassed
        }
    }

    if (-not $restoreGatePassed) {
        $proceedUnsafely = $false
        $proceedPrompt = if ($script:UnsafeMode) {
            "A restore point could not be created. Continue in UNSAFE mode anyway?"
        } else {
            "A restore point could not be created. Continue anyway (Unsafe mode)?"
        }
        $proceedUnsafely = Get-Confirmation -Question $proceedPrompt -Default 'n'
        if ($proceedUnsafely -and -not $script:UnsafeMode) {
            $script:UnsafeMode = $true
        }
        if ($script:Logger) {
            $unsafeConfirmLevel = if ($proceedUnsafely) { 'Warning' } else { 'Info' }
            Write-Log -Message "Unsafe mode confirmation after restore gate failure." -Level $unsafeConfirmLevel -Data @{
                preset         = 'Aggressive'
                unsafeMode     = [bool]$script:UnsafeMode
                userConfirmed  = [bool]$proceedUnsafely
                restoreCreated = [bool]($restoreStatus -and $restoreStatus.Created)
            }
        }

        if (-not $proceedUnsafely) {
            Write-Warning "[Safety] Aggressive preset aborted because a restore point is required."
            Add-SessionSummaryItem -Context $script:Context -Bucket 'GuardedBlocks' -Message "Aggressive preset blocked: restore point unavailable (UnsafeMode=$($script:UnsafeMode))"
            return
        }

        Write-Warning "[Safety] Proceeding without a restore point due to -UnsafeMode."
        Reset-HighImpactBlock
    }
    Clear-TempFiles -Context $script:Context

    $appliedPresets = @()
    if ($script:Context.PSObject.Properties.Name.Contains('AppliedPresets')) {
        $appliedPresets = @($script:Context.AppliedPresets)
    }
    $skipParentLayer = $appliedPresets -contains 'Safe'
    $privacyAbort = Invoke-PrivacyAggressive -Context $script:Context -SkipParentLayer:$skipParentLayer
    if ($privacyAbort) {
        Write-Host "[!] Aggressive preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }

    $debloatResult = Invoke-DebloatAggressive -Context $script:Context
    $Status.PackagesFailed += $debloatResult.Failed
    $Status.PackagesRemoved += $debloatResult.Removed

    $preferencesAbort = Invoke-PreferencesSafe -Context $script:Context -PresetName 'Aggressive preset'
    if ($preferencesAbort) {
        Write-Host "[!] Aggressive preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    $baselineAbort = Invoke-PerformanceBaseline -HardwareProfile $HWProfile -Context $script:Context -PresetName 'Aggressive preset'
    if ($baselineAbort) {
        Write-Host "[!] Aggressive preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    Ensure-PowerPlan -Mode 'HighPerformance'

    $aggressivePerformanceAbort = Invoke-AggressivePerformanceTweaks -OemServices $OemServices -Context $script:Context -PresetName 'Aggressive preset'
    if ($aggressivePerformanceAbort) {
        Write-Host "[!] Aggressive preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    $aggTweaksAbort = Invoke-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices -Context $script:Context -PresetName 'Aggressive preset'
    if ($aggTweaksAbort) {
        Write-Host "[!] Aggressive preset aborted by user due to critical registry failure." -ForegroundColor Red
        return
    }
    Invoke-HardwareDeviceHardening -Context $script:Context -Level 'Aggressive'

    $Status.RebootRequired = Get-NeedsReboot -Context $script:Context
    $Status.RegistryPermissionFailures = @($script:Context.RegistryPermissionFailures)
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Slow PC / Aggressive preset applied. Please restart." -ForegroundColor Green
    if (-not $script:Context.PSObject.Properties.Name.Contains('AppliedPresets')) {
        $script:Context | Add-Member -Name AppliedPresets -MemberType NoteProperty -Value @()
    } elseif (-not $script:Context.AppliedPresets) {
        $script:Context.AppliedPresets = @()
    }
    if (-not ($script:Context.AppliedPresets -contains 'Aggressive')) {
        $script:Context.AppliedPresets += 'Aggressive'
    }
}

function Show-NetworkTweaksMenu {
    do {
        Write-Section "Network Tweaks"
        Write-Host "1) Safe (Stability/Browsing)"
        Write-Host "2) Aggressive (Privacy/Noise reduction)"
        Write-Host "3) Gaming (Low latency)"
        Write-Host "4) Restore network tweaks from backup"
        Write-Host "5) Hardcore (Competitive/Advanced)"
        Write-Host "6) Back"
        Write-Host ""

        $netChoice = Read-MenuChoice "Select a network option" @('1','2','3','4','5','6')
        $backupFile = "C:\ProgramData\Scynesthesia\network_backup.json"

        $requireNetworkBackup = {
            param([string]$ProfileName)

            if (-not (Get-Command Save-NetworkBackupState -ErrorAction SilentlyContinue)) {
                Write-Host "  [!] Unable to create network backup; $ProfileName network tweaks aborted." -ForegroundColor Yellow
                return $false
            }

            if (-not (Get-Confirmation "$ProfileName network tweaks require a backup. Create/refresh it now?" 'y')) {
                Write-Host "  [!] $ProfileName network tweaks aborted because the required backup was declined." -ForegroundColor Yellow
                return $false
            }

            $backupResult = $null
            try {
                Write-Host "  [i] Creating mandatory network backup at $backupFile..." -ForegroundColor Gray
                $backupResult = Save-NetworkBackupState
            } catch {
                Invoke-ErrorHandler -Context "Saving network backup before $ProfileName network tweaks (Network Tweaks menu)" -ErrorRecord $_
            }

            $backupSuccess = ($backupResult -and $backupResult.PSObject.Properties['Success'] -and $backupResult.Success)
            if (-not $backupSuccess) {
                Write-Host "  [!] $ProfileName network tweaks aborted because the network backup did not complete successfully." -ForegroundColor Yellow
                return $false
            }

            return $true
        }

        switch ($netChoice) {
            '1' {
                if (-not (& $requireNetworkBackup 'Safe')) { break }
                if (Get-Confirmation "Apply Safe Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksSafe -Context $script:Context
                } else {
                    Write-Host "[ ] Safe Network Tweaks skipped." -ForegroundColor Gray
                }
            }
            '2' {
                if (-not (Assert-HighImpactAllowed "Aggressive network tweaks")) { break }
                if (-not (& $requireNetworkBackup 'Aggressive')) { break }
                if (Get-Confirmation "Apply Aggressive Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksAggressive -Context $script:Context
                } else {
                    Write-Host "[ ] Aggressive Network Tweaks skipped." -ForegroundColor Gray
                }
            }
            '3' {
                if (-not (Assert-HighImpactAllowed "Gaming network tweaks")) { break }
                if (-not (& $requireNetworkBackup 'Gaming')) { break }
                if (Get-Confirmation "Apply Gaming Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksGaming -Context $script:Context
                } else {
                    Write-Host "[ ] Gaming Network Tweaks skipped." -ForegroundColor Gray
                }
                if (Get-NeedsReboot -Context $script:Context) {
                    Write-Host "  [i] Some network/gaming changes will require a reboot. You will be prompted before exiting." -ForegroundColor Yellow
                }
            }
            '4' {
                Invoke-GlobalRollback -Context $script:Context
            }
            '5' {
                if (-not (Assert-HighImpactAllowed "Hardcore Network Tweaks")) { break }
                $restoreGate = Confirm-HighImpactRestoreGate -ActionLabel "Hardcore Network Tweaks" -AllowUnsafeOverride
                if (-not ($restoreGate -and $restoreGate.Proceed)) {
                    Write-Host "  [ ] Hardcore Network Tweaks skipped because restore point is unavailable." -ForegroundColor Gray
                    break
                }
                if (Get-Confirmation "Apply Hardcore Network Tweaks (Bufferbloat/MTU)?" 'n' -RiskSummary @("Can disrupt adapters during MTU discovery", "netsh changes may destabilize networking until reboot")) {
                    if (-not (Test-Path $backupFile)) {
                        try {
                            Save-NetworkBackupState
                        } catch {
                            Invoke-ErrorHandler -Context "Creating network backup before Hardcore tweaks (Network Tweaks menu)" -ErrorRecord $_
                        }
                    }

                    Write-Host "  [!] Warning: MTU discovery will run and may cause brief network disconnects." -ForegroundColor Yellow
                    try {
                        Invoke-NetworkTweaksHardcore -Context $script:Context
                        Set-NeedsReboot -Context $script:Context | Out-Null
                    } catch {
                        Invoke-ErrorHandler -Context "Applying Hardcore Network Tweaks from Network Tweaks menu" -ErrorRecord $_
                    }
                } else {
                    Write-Host "[ ] Hardcore Network Tweaks skipped." -ForegroundColor Gray
                }
            }
            '6' { return }
        }

        if ($netChoice -ne '6') { Read-Host "`nPress Enter to continue..." }
    } while ($true)
}

function Show-ExplorerTweaksMenu {
    do {
        Write-Section "UI & Explorer Tweaks"
        Write-Host "1) Enable classic context menus (Windows 10 style)"
        Write-Host "2) Add Take Ownership menu (files/folders)"
        Write-Host "3) Show extensions and hidden files"
        Write-Host "4) Apply all"
        Write-Host "5) Back"
        Write-Host ""

        $tweakChoice = Read-MenuChoice "Select a UI/Explorer option" @('1','2','3','4','5')

        switch ($tweakChoice) {
            '1' { Set-ClassicContextMenus -Context $script:Context }
            '2' { Add-TakeOwnershipMenu -Context $script:Context }
            '3' { Set-ExplorerProSettings -Context $script:Context }
            '4' {
                Set-ClassicContextMenus -Context $script:Context
                Add-TakeOwnershipMenu -Context $script:Context
                Set-ExplorerProSettings -Context $script:Context
            }
            '5' { return }
        }

        if ($tweakChoice -ne '5') { Read-Host "`n[DONE] Press Enter to return to the menu..." }
    } while ($true)
}


$exitRequested = $false
do {
    Reset-HighImpactBlock
    Show-Banner
    Write-Host "[ Automated Presets ]" -ForegroundColor Cyan
    Write-Host "1) Safe preset (Stability/Browsing)"
    Write-Host "2) Aggressive preset (Deep Debloat & Privacy)"
    Write-Host "3) Gaming preset (Low latency)"
    Write-Host ""
    Write-Host "[ Granular Tools ]" -ForegroundColor Yellow
    Write-Host "4) Repair & Update Center"
    Write-Host "5) Network tweaks"
    Write-Host "6) UI & Explorer tweaks"
    Write-Host "7) Optimization Audit (Verify applied tweaks)"
    Write-Host "8) Roll back changes from this session (registry + network)" -ForegroundColor Yellow
    Write-Host ""
    $rebootStatus = if (Get-NeedsReboot -Context $script:Context) { 'System Status: Reboot pending' } else { 'System Status: No reboot pending' }
    Write-Host $rebootStatus -ForegroundColor DarkCyan
    Write-Host "0) Exit" -ForegroundColor Gray
    Write-Host ""
    $choice = Read-MenuChoice "Select an option" @('1','2','3','4','5','6','7','8','0')

    switch ($choice) {
        '1' { Run-SafePreset }
        '2' { Run-PCSlowPreset }
        '3' {
            if (-not (Ensure-ModuleCommand -CommandName 'Save-NetworkBackupState' -ModuleRelativePath 'modules/network.psm1')) {
                Write-Warning "[Gaming] Required network module command Save-NetworkBackupState is unavailable. Gaming Mode cannot continue safely."
                break
            }
            Write-Section "Gaming Mode / FPS Boost"
            $restoreStatus = Invoke-RestorePointWithAutoEnable
            if (-not (Handle-RestorePointGate -RestoreStatus $restoreStatus -ActionLabel "Gaming Mode")) {
                $continueUnsafely = Get-Confirmation -Question "Unable to ensure a restore point. Continue at your own risk?" -Default 'n'
                if (-not $continueUnsafely) {
                    Write-Warning "[Safety] Gaming Mode aborted because no restore point is available."
                    break
                }
                Write-Warning "[Safety] Proceeding without a restore point at user request."
                $script:UnsafeMode = $true
                Reset-HighImpactBlock
            }
            $appliedPresets = @()
            if ($script:Context.PSObject.Properties.Name.Contains('AppliedPresets')) {
                $appliedPresets = @($script:Context.AppliedPresets)
            }
            $skipParentLayer = ($appliedPresets -contains 'Aggressive' -or $appliedPresets -contains 'Safe')
            $privacyAbort = Invoke-PrivacyGaming -Context $script:Context -SkipParentLayer:$skipParentLayer
            if ($privacyAbort) {
                Write-Host "[!] Gaming preset aborted by user due to critical registry failure." -ForegroundColor Red
                break
            }
            Invoke-GamingServiceOptimization -Context $script:Context
            $msiResult = Invoke-MsiModeOnce -Context $script:Context -Targets @('GPU','STORAGE') -PromptMessage "Enable MSI Mode for GPU and storage controllers? (Recommended for Gaming Mode. NIC can be adjusted separately from the Network Tweaks menu.)" -InvokeOnceId 'MSI:GPU+STORAGE' -DefaultResponse 'y'
            if ($script:Logger -and $msiResult -and $msiResult.Touched -gt 0) {
                Write-Log "[Gaming] MSI Mode enabled for GPU and storage controllers from main Gaming Mode."
            } elseif ($script:Logger -and $msiResult) {
                Write-Log "[Gaming] MSI Mode for GPU/storage already enabled or not applicable." -Level 'Info'
            }
            Write-Host "[+] Gaming tweaks applied." -ForegroundColor Magenta

            $backupFile = "C:\ProgramData\Scynesthesia\network_backup.json"
            $hardcoreGate = Confirm-HighImpactRestoreGate -ActionLabel "Hardcore Network Tweaks (Gaming Mode)" -AllowUnsafeOverride
            if ($hardcoreGate -and $hardcoreGate.Proceed -and (Get-Confirmation "Apply Hardcore Network Tweaks (Bufferbloat/MTU)?" 'n' -RiskSummary @("Can disrupt adapters during MTU discovery", "netsh changes may destabilize networking until reboot"))) {
                if (-not (Test-Path $backupFile)) {
                    try {
                        Save-NetworkBackupState
                    } catch {
                        Invoke-ErrorHandler -Context "Creating network backup before Hardcore tweaks" -ErrorRecord $_
                    }
                }

                Write-Host "  [!] Warning: MTU discovery will run and may cause brief network disconnects." -ForegroundColor Yellow
                try {
                    Invoke-NetworkTweaksHardcore -Context $script:Context
                    Set-NeedsReboot -Context $script:Context | Out-Null
                } catch {
                    Invoke-ErrorHandler -Context "Applying Hardcore Network Tweaks from Gaming preset" -ErrorRecord $_
                }
            } elseif (-not ($hardcoreGate -and $hardcoreGate.Proceed)) {
                Write-Host "  [ ] Hardcore Network Tweaks skipped because restore point is unavailable." -ForegroundColor DarkGray
            } else {
                Write-Host "  [ ] Hardcore Network Tweaks skipped." -ForegroundColor DarkGray
            }
        }
        '4' {
            Write-Section "Repair & Update Center"
            Invoke-NetworkSoftReset -Context $script:Context
            Invoke-SystemRepair
            Invoke-WindowsUpdateScan
        }
        '5' {
            Show-NetworkTweaksMenu
        }
        '6' {
            Show-ExplorerTweaksMenu
        }
        '7' {
            Write-Section "Optimization Audit"
            Invoke-OptimizationAudit -Context $script:Context
            Read-Host "`n[DONE] Press Enter to return to the menu..." | Out-Null
        }
        '8' {
            Write-Section "Rollback"
            Invoke-RegistryRollback -Context $script:Context
            try {
                Invoke-GlobalRollback -Context $script:Context
            } catch {
                Invoke-ErrorHandler -Context "Running global rollback (services/netsh)" -ErrorRecord $_
            }
            Read-Host "`n[DONE] Press Enter to return to the menu..." | Out-Null
        }
        '0' { $exitRequested = $true }
    }

    if (-not $exitRequested) {
        Write-Host "Tip: Run 'Safe Preset' before 'Gaming Mode' for best results." -ForegroundColor DarkGray
    }

    Handle-RebootIfNeeded -Context $Context -OnExit:$exitRequested

    if ($exitRequested) { break }

} while ($true)

try {
    Save-RollbackState -Context $script:Context -Path $script:Context.RollbackPersistencePath | Out-Null
} catch {
    Write-Verbose "Final rollback persistence failed: $($_.Exception.Message)"
}

Stop-RollbackTimerSafely

Write-EndOfSessionSummary -Context $script:Context
Write-DebloatRemovalLog -Context $script:Context

try {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        Write-Host "Log saved." -ForegroundColor Gray
    }
} catch {}
