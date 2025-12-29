# File saved as UTF-8 with BOM to avoid encoding issues on Windows PowerShell 5.1
# Scynesthesia Windows Optimizer v1.0
# Run this script as Administrator.

# ---------- 1. ADMIN CHECK ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Capture the script root so modules and sub-menus can resolve paths reliably without global scope.
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

# ---------- 2. MODULE IMPORTS (Moved up to ensure dependencies load early.) ----------
try {
    $modulesRoot = Join-Path $scriptRoot 'modules'
    $moduleMapPath = Join-Path $modulesRoot 'modules.map.psd1'

    if (-not (Test-Path $moduleMapPath)) {
        throw "Module map not found: $moduleMapPath"
    }

    $moduleMap = Import-PowerShellDataFile -Path $moduleMapPath -ErrorAction Stop
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
        Import-Module $resolvedPath -Force -ErrorAction Stop
        Write-Host "[OK] Module loaded: $moduleFileName" -ForegroundColor Green
    }

    Write-Host "Modules loaded successfully." -ForegroundColor Green
} catch {
    if (Get-Command Invoke-ErrorHandler -ErrorAction SilentlyContinue) {
        Invoke-ErrorHandler -Context "Loading modules" -ErrorRecord $_
    } else {
        Write-Error "Error loading modules: $($_.Exception.Message)"
    }
    Write-Host "Make sure the 'modules' folder is next to this script."
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------- 3. CONTEXT INITIALIZATION ----------
$Context = New-RunContext -ScriptRoot $scriptRoot
$Context.RollbackPersistencePath = Get-RollbackPersistencePath
Restore-RegistryRollbackState -Context $Context -Path $Context.RollbackPersistencePath | Out-Null
$script:RollbackPersistencePath = $Context.RollbackPersistencePath
$script:Context = $Context
Reset-NeedsReboot -Context $Context | Out-Null
$script:Context.RegistryRollbackActions = if ($Context.RegistryRollbackActions) { $Context.RegistryRollbackActions } else { [System.Collections.Generic.List[object]]::new() }
$script:Logger = Get-Command Write-Log -ErrorAction SilentlyContinue

# Periodically persist rollback entries so they can survive unexpected termination.
$script:RollbackPersistTimer = [System.Timers.Timer]::new()
$script:RollbackPersistTimer.Interval = 30000
$script:RollbackPersistTimer.AutoReset = $true
$script:RollbackPersistSubscription = Register-ObjectEvent -InputObject $script:RollbackPersistTimer -EventName Elapsed -SourceIdentifier 'RegistryRollbackPersistence' -Action {
    try {
        if ($script:Context) {
            Save-RegistryRollbackState -Context $script:Context -Path $script:Context.RollbackPersistencePath | Out-Null
        }
    } catch {
        Write-Verbose "Rollback persistence failed: $($_.Exception.Message)"
    }
} -ErrorAction SilentlyContinue
$script:RollbackPersistTimer.Start()

# ---------- 4. LOGGING (Transcript and logging initialization.) ----------
$TranscriptStarted = $false
# Get-Confirmation is now available from ui.psm1.
if (Get-Confirmation "Enable session logging to a file? (Recommended for service records)" 'n') {
    $logDir = Join-Path $env:TEMP "ScynesthesiaOptimizer"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = Join-Path $logDir "Scynesthesia_Log_$timestamp.txt"
    
    try {
        Start-Transcript -Path $logFile -Append -ErrorAction Stop
        $TranscriptStarted = $true
        Write-Host "Logging started: $logFile" -ForegroundColor Gray
        $Global:ScynesthesiaLogPath = $logFile
    } catch {
        Write-Warning "Could not start logging. Check permissions."
    }
}

# ---------- 5. LOCAL FUNCTIONS ----------

# Description: Displays the application banner with version and active power plan details.
# Parameters: None.
# Returns: None.
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

# Description: Ensures the requested Windows power plan is active.
# Parameters: Mode - Chooses between Balanced or HighPerformance power plans.
# Returns: None.
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

# Description: Writes a consolidated log of removed apps to the console/transcript.
# Parameters: Context - Optional run context holding DebloatRemovalLog.
# Returns: None.
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

# Description: Presents optional safe tweaks and applies selections based on user input.
# Parameters: None.
# Returns: None.
function Invoke-SafeOptionalPrompts {
    Write-Section "Additional options for Safe preset"
    $options = @(
        @{ Key = '1'; Description = 'Disable Cortana in search'; Action = {
            $result = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 -Context $script:Context -Critical -ReturnResult -OperationLabel 'Disable Cortana policy'
            return ($result -and $result.Success)
        } },
        @{ Key = '2'; Description = 'Disable Store suggestions in Start'; Action = {
            $result = Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 -Context $script:Context -ReturnResult -OperationLabel 'Disable Store suggestions'
            return ($result -and $result.Success)
        } },
        @{ Key = '3'; Description = 'Enable compact view in File Explorer'; Action = {
            $result = Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "UseCompactMode" 1 -Context $script:Context -ReturnResult -OperationLabel 'Enable compact view'
            return ($result -and $result.Success)
        } }
    )
    foreach ($opt in $options) {
        $label = "$($opt.Key) $($opt.Description)"
        if (Get-Confirmation $label -Default 'n') {
            $applied = & $opt.Action
            if ($applied) {
                Write-Host "[OK] $($opt.Description) applied." -ForegroundColor Green
            } else {
                Write-Host "[!] $($opt.Description) could not be applied (check permissions)." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Skipped: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

# Description: Handles reboot prompting based on the supplied context and resets the flag afterward.
# Parameters: Context - The current run context. OnExit - Indicates whether the prompt is shown while exiting.
# Returns: None. Mutates Context.NeedsReboot.
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

# ---------- 6. PRESETS ----------

# Description: Executes the Safe preset workflow focused on stability and baseline performance.
# Parameters: None.
# Returns: None. Updates global reboot flag as needed.
function Run-SafePreset {
    $Status = @{ PackagesFailed = @(); PackagesRemoved = @(); RebootRequired = $false }
    if (-not $script:Context.PSObject.Properties.Name.Contains('RegistryPermissionFailures')) {
        $script:Context | Add-Member -Name RegistryPermissionFailures -MemberType NoteProperty -Value @()
    } else {
        $script:Context.RegistryPermissionFailures = @()
    }
    $HWProfile = Get-HardwareProfile

    Write-Section "Starting Preset 1: Safe"
    $restoreStatus = New-RestorePointSafe
    if (-not $restoreStatus.Created) {
        Write-Warning "Restore point not created. Safe preset will continue without a rollback checkpoint."
    }
    Clear-TempFiles -Context $script:Context

    # Safe Debloat (Standard list)
    Invoke-PrivacyTelemetrySafe -Context $script:Context
    $debloatResult = Invoke-DebloatSafe -Context $script:Context # Uses the default list defined in the module
    $Status.PackagesFailed += $debloatResult.Failed
    $Status.PackagesRemoved += $debloatResult.Removed

    Invoke-PreferencesSafe -Context $script:Context
    Invoke-SafeOptionalPrompts
    Invoke-SysMainOptimization -HardwareProfile $HWProfile
    Invoke-PerformanceBaseline -HardwareProfile $HWProfile -Context $script:Context
    Invoke-SafePerformanceTweaks -Context $script:Context
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = Get-NeedsReboot -Context $script:Context
    $Status.RegistryPermissionFailures = @($script:Context.RegistryPermissionFailures)
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe preset applied. Restart when convenient to finalize settings." -ForegroundColor Green
}

# Description: Executes the Slow PC/Aggressive preset for deeper cleanup and performance tuning.
# Parameters: None.
# Returns: None. Updates global reboot flag and failed package list.
function Run-PCSlowPreset {
    $Status = @{ PackagesFailed = @(); PackagesRemoved = @(); RebootRequired = $false }
    if (-not $script:Context.PSObject.Properties.Name.Contains('RegistryPermissionFailures')) {
        $script:Context | Add-Member -Name RegistryPermissionFailures -MemberType NoteProperty -Value @()
    } else {
        $script:Context.RegistryPermissionFailures = @()
    }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Starting Preset 2: Slow PC / Aggressive"
    $restoreStatus = New-RestorePointSafe
    if (-not $restoreStatus.Created) {
        Write-Warning "Restore point not created. Aggressive preset will continue without a rollback checkpoint."
    }
    Clear-TempFiles -Context $script:Context

    Invoke-PrivacyTelemetrySafe -Context $script:Context

    # Deep cleaning using Aggressive Debloat profile.
    # Using updated function from debloat.psm1.
    $debloatResult = Invoke-DebloatAggressive -Context $script:Context
    $Status.PackagesFailed += $debloatResult.Failed
    $Status.PackagesRemoved += $debloatResult.Removed

    Invoke-PreferencesSafe -Context $script:Context
    Invoke-PerformanceBaseline -HardwareProfile $HWProfile -Context $script:Context
    Ensure-PowerPlan -Mode 'HighPerformance'

    # Additional tweaks specific to slow PCs
    Invoke-AggressivePerformanceTweaks -OemServices $OemServices -Context $script:Context
    Invoke-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices -Context $script:Context

    $Status.RebootRequired = Get-NeedsReboot -Context $script:Context
    $Status.RegistryPermissionFailures = @($script:Context.RegistryPermissionFailures)
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Slow PC / Aggressive preset applied. Please restart." -ForegroundColor Green
}

# Description: Presents the interactive menu for network tweak profiles and restoration.
# Parameters: None.
# Returns: None. May set global reboot flag when hardcore tweaks run.
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
                if (-not (& $requireNetworkBackup 'Aggressive')) { break }
                if (Get-Confirmation "Apply Aggressive Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksAggressive -Context $script:Context
                } else {
                    Write-Host "[ ] Aggressive Network Tweaks skipped." -ForegroundColor Gray
                }
            }
            '3' {
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
                Restore-NetworkBackupState
            }
            '5' {
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

# Description: Presents software installation and Windows Update controls.
# Parameters: None.
# Returns: None.
function Show-SoftwareUpdatesMenu {
    do {
        Write-Section "Software & Updates"
        Write-Host "1) Install essential software"
        Write-Host "2) Set Windows Update to Notify Only"
        Write-Host "3) Manual update scan"
        Write-Host "4) Back"
        Write-Host ""

        $swChoice = Read-MenuChoice "Select a software/update option" @('1','2','3','4')

        switch ($swChoice) {
            '1' {
                Invoke-SoftwareInstaller
            }
            '2' {
                Set-WindowsUpdateNotifyOnly -Context $script:Context
            }
            '3' {
                Invoke-WindowsUpdateScan
            }
            '4' { return }
        }

        if ($swChoice -ne '4') { Read-Host "`nPress Enter to continue..." }
    } while ($true)
}

# Description: Presents UI and Explorer tweaks that can be applied individually or together.
# Parameters: None.
# Returns: None. May set global reboot flag.
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

# ---------- 7. MAIN LOOP ----------

$exitRequested = $false
do {
    Show-Banner
    Write-Host "[ Automated Presets ]" -ForegroundColor Cyan
    Write-Host "1) Safe preset (Stability/Browsing)"
    Write-Host "2) Aggressive preset (Deep Debloat & Privacy)"
    Write-Host "3) Gaming preset (Low latency)"
    Write-Host ""
    Write-Host "[ Granular Tools ]" -ForegroundColor Yellow
    Write-Host "4) Repair tools"
    Write-Host "5) Network tweaks"
    Write-Host "6) Software & Updates"
    Write-Host "7) UI & Explorer tweaks"
    Write-Host "8) Roll back registry changes from this session" -ForegroundColor Yellow
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
            Write-Section "Gaming Mode / FPS Boost"
            $restoreStatus = New-RestorePointSafe
            if (-not $restoreStatus.Created) {
                Write-Warning "Restore point not created. Gaming Mode will continue without a rollback checkpoint."
            }
            Invoke-GamingOptimizations -Context $script:Context
            $msiResult = Invoke-MsiModeOnce -Context $script:Context -Targets @('GPU','STORAGE') -PromptMessage "Enable MSI Mode for GPU and storage controllers? (Recommended for Gaming Mode. NIC can be adjusted separately from the Network Tweaks menu.)" -InvokeOnceId 'MSI:GPU+STORAGE' -DefaultResponse 'y'
            if ($script:Logger -and $msiResult -and $msiResult.Touched -gt 0) {
                Write-Log "[Gaming] MSI Mode enabled for GPU and storage controllers from main Gaming Mode."
            } elseif ($script:Logger -and $msiResult) {
                Write-Log "[Gaming] MSI Mode for GPU/storage already enabled or not applicable." -Level 'Info'
            }
            Write-Host "[+] Gaming tweaks applied." -ForegroundColor Magenta

            $backupFile = "C:\ProgramData\Scynesthesia\network_backup.json"
            if (Get-Confirmation "Apply Hardcore Network Tweaks (Bufferbloat/MTU)?" 'n' -RiskSummary @("Can disrupt adapters during MTU discovery", "netsh changes may destabilize networking until reboot")) {
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
            } else {
                Write-Host "  [ ] Hardcore Network Tweaks skipped." -ForegroundColor DarkGray
            }
        }
        '4' {
            Write-Section "Repair Tools"
            Invoke-NetworkSoftReset -Context $script:Context
            Invoke-SystemRepair
        }
        '5' {
            Show-NetworkTweaksMenu
        }
        '6' {
            Show-SoftwareUpdatesMenu
        }
        '7' {
            Show-ExplorerTweaksMenu
        }
        '8' {
            Write-Section "Rollback"
            Invoke-RegistryRollback -Context $script:Context
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
    Save-RegistryRollbackState -Context $script:Context -Path $script:Context.RollbackPersistencePath | Out-Null
} catch {
    Write-Verbose "Final rollback persistence failed: $($_.Exception.Message)"
}

if ($script:RollbackPersistTimer) {
    $script:RollbackPersistTimer.Stop()
}
if (Get-EventSubscriber -SourceIdentifier 'RegistryRollbackPersistence' -ErrorAction SilentlyContinue) {
    Unregister-Event -SourceIdentifier 'RegistryRollbackPersistence' -ErrorAction SilentlyContinue
}
if ($script:RollbackPersistSubscription) {
    try { Remove-Job -Id $script:RollbackPersistSubscription.Id -ErrorAction SilentlyContinue } catch {}
}
if ($script:RollbackPersistTimer) {
    $script:RollbackPersistTimer.Dispose()
}

Write-DebloatRemovalLog -Context $script:Context

try {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        Write-Host "Log saved." -ForegroundColor Gray
    }
} catch {}
