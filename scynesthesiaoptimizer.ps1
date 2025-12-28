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

# Capture the script root globally so modules and sub-menus can resolve paths reliably.
$Global:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

# ---------- 2. MODULE IMPORTS (Moved up to ensure dependencies load early.) ----------
$Global:NeedsReboot = $false
try {
    $modulesRoot = Join-Path $Global:ScriptRoot 'modules'
    $coreModulesRoot = Join-Path $modulesRoot 'core'
    if (Test-Path $coreModulesRoot) {
        $contextModule = Join-Path $coreModulesRoot 'context.psm1'
        if (Test-Path $contextModule) {
            Import-Module $contextModule -Force -ErrorAction Stop
            Write-Host "[OK] Core module loaded: context.psm1" -ForegroundColor Green
        }
        $coreModuleFiles = Get-ChildItem -Path $coreModulesRoot -Filter '*.psm1' -File -ErrorAction Stop
        foreach ($coreModule in $coreModuleFiles) {
            if ($coreModule.Name -eq 'context.psm1') { continue }
            Import-Module $coreModule.FullName -Force -ErrorAction Stop
            Write-Host "[OK] Core module loaded: $($coreModule.Name)" -ForegroundColor Green
        }
    }
    $uiModule = Join-Path $modulesRoot 'ui.psm1'
    Import-Module $uiModule -Force -ErrorAction Stop
    Write-Host "[OK] Module loaded: ui.psm1" -ForegroundColor Green

    $servicesModule = Join-Path $modulesRoot 'services.psm1'
    Import-Module $servicesModule -Force -ErrorAction Stop
    Write-Host "[OK] Module loaded: services.psm1" -ForegroundColor Green

    $softwareModule = Join-Path $modulesRoot 'software.psm1'
    Import-Module $softwareModule -Force -ErrorAction Stop
    Write-Host "[OK] Module loaded: software.psm1" -ForegroundColor Green

    $tweaksModule = Join-Path $modulesRoot 'tweaks.psm1'
    Import-Module $tweaksModule -Force -ErrorAction Stop
    Write-Host "[OK] Module loaded: tweaks.psm1" -ForegroundColor Green

    $moduleFiles = Get-ChildItem -Path $modulesRoot -Filter '*.psm1' -File -ErrorAction Stop

    foreach ($module in $moduleFiles) {
        if ($module.Name -in @('ui.psm1','services.psm1','software.psm1','tweaks.psm1')) { continue }
        try {
            Import-Module $module.FullName -Force -ErrorAction Stop
            Write-Host "[OK] Module loaded: $($module.Name)" -ForegroundColor Green
        } catch {
            Write-Warning "Could not load module: $($module.Name). $($_.Exception.Message)"
            throw
        }
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

# ---------- 3. LOGGING (Transcript and logging initialization.) ----------
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

# ---------- 4. LOCAL FUNCTIONS ----------

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

# Description: Presents optional safe tweaks and applies selections based on user input.
# Parameters: None.
# Returns: None.
function Invoke-SafeOptionalPrompts {
    Write-Section "Additional options for Safe preset"
    $options = @(
        @{ Key = '1'; Description = 'Disable Cortana in search'; Action = { Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 } },
        @{ Key = '2'; Description = 'Disable Store suggestions in Start'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 } },
        @{ Key = '3'; Description = 'Enable compact view in File Explorer'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "UseCompactMode" 1 } }
    )
    foreach ($opt in $options) {
        $label = "$($opt.Key) $($opt.Description)"
        if (Get-Confirmation $label -Default 'n') {
            & $opt.Action
            Write-Host "[OK] $($opt.Description) applied." -ForegroundColor Green
        } else {
            Write-Host "Skipped: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

# ---------- 5. PRESETS ----------

# Description: Executes the Safe preset workflow focused on stability and baseline performance.
# Parameters: None.
# Returns: None. Updates global reboot flag as needed.
function Run-SafePreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile

    Write-Section "Starting Preset 1: Safe"
    New-RestorePointSafe
    Clear-TempFiles

    # Safe Debloat (Standard list)
    Invoke-PrivacyTelemetrySafe
    $debloatResult = Invoke-DebloatSafe # Uses the default list defined in the module
    $Status.PackagesFailed += $debloatResult.Failed

    Invoke-PreferencesSafe
    Invoke-SafeOptionalPrompts
    Invoke-SysMainOptimization -HardwareProfile $HWProfile
    Invoke-PerformanceBaseline -HardwareProfile $HWProfile
    Invoke-SafePerformanceTweaks
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = $Global:NeedsReboot
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe preset applied. Restart when convenient to finalize settings." -ForegroundColor Green
}

# Description: Executes the Slow PC/Aggressive preset for deeper cleanup and performance tuning.
# Parameters: None.
# Returns: None. Updates global reboot flag and failed package list.
function Run-PCSlowPreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Starting Preset 2: Slow PC / Aggressive"
    New-RestorePointSafe
    Clear-TempFiles

    Invoke-PrivacyTelemetrySafe

    # Deep cleaning using Aggressive Debloat profile.
    # Using updated function from debloat.psm1.
    $debloatResult = Invoke-DebloatAggressive
    $Status.PackagesFailed += $debloatResult.Failed

    Invoke-PreferencesSafe
    Invoke-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    # Additional tweaks specific to slow PCs
    Invoke-AggressivePerformanceTweaks -OemServices $OemServices
    Invoke-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices

    $Status.RebootRequired = $Global:NeedsReboot
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

        $ensureBackup = {
            if (-not (Test-Path $backupFile)) {
                if (Get-Confirmation "Save a backup of your current network configuration before applying tweaks (recommended)?" 'y') {
                    Save-NetworkBackupState
                }
            }
        }

        switch ($netChoice) {
            '1' {
                & $ensureBackup
                if (Get-Confirmation "Apply Safe Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksSafe
                } else {
                    Write-Host "[ ] Safe Network Tweaks skipped." -ForegroundColor Gray
                }
            }
            '2' {
                & $ensureBackup
                if (Get-Confirmation "Apply Aggressive Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksAggressive
                } else {
                    Write-Host "[ ] Aggressive Network Tweaks skipped." -ForegroundColor Gray
                }
            }
            '3' {
                & $ensureBackup
                if (Get-Confirmation "Apply Gaming Network Tweaks?" 'n') {
                    Invoke-NetworkTweaksGaming
                } else {
                    Write-Host "[ ] Gaming Network Tweaks skipped." -ForegroundColor Gray
                }
                if ($Global:NeedsReboot) {
                    Write-Host "  [i] Some network/gaming changes will require a reboot. You will be prompted before exiting." -ForegroundColor Yellow
                }
            }
            '4' {
                Restore-NetworkBackupState
            }
            '5' {
                if (Get-Confirmation "Apply Hardcore Network Tweaks (Bufferbloat/MTU)?" 'n') {
                    if (-not (Test-Path $backupFile)) {
                        try {
                            Save-NetworkBackupState
                        } catch {
                            Invoke-ErrorHandler -Context "Creating network backup before Hardcore tweaks (Network Tweaks menu)" -ErrorRecord $_
                        }
                    }

                    Write-Host "  [!] Warning: MTU discovery will run and may cause brief network disconnects." -ForegroundColor Yellow
                    try {
                        Invoke-NetworkTweaksHardcore
                        $Global:NeedsReboot = $true
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
                Set-WindowsUpdateNotifyOnly
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
            '1' { Set-ClassicContextMenus }
            '2' { Add-TakeOwnershipMenu }
            '3' { Set-ExplorerProSettings }
            '4' {
                Set-ClassicContextMenus
                Add-TakeOwnershipMenu
                Set-ExplorerProSettings
            }
            '5' { return }
        }

        if ($tweakChoice -ne '5') { Read-Host "`n[DONE] Press Enter to return to the menu..." }
    } while ($true)
}

# ---------- 6. MAIN LOOP ----------

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
    Write-Host ""
    $rebootStatus = if ($Global:NeedsReboot) { 'System Status: Reboot pending' } else { 'System Status: No reboot pending' }
    Write-Host $rebootStatus -ForegroundColor DarkCyan
    Write-Host "0) Exit" -ForegroundColor Gray
    Write-Host ""
    $choice = Read-MenuChoice "Select an option" @('1','2','3','4','5','6','7','0')

    switch ($choice) {
        '1' { Run-SafePreset }
        '2' { Run-PCSlowPreset }
        '3' {
            Write-Section "Gaming Mode / FPS Boost"
            $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
            Invoke-GamingOptimizations
            if (Get-Confirmation "Enable MSI Mode for GPU and storage controllers? (Recommended for Gaming Mode. NIC can be adjusted separately from the Network Tweaks menu.)" 'y') {
                $msiResult = Enable-MsiModeSafe -Target @('GPU','STORAGE')
                if ($logger -and $msiResult -and $msiResult.Touched -gt 0) {
                    Write-Log "[Gaming] MSI Mode enabled for GPU and storage controllers from main Gaming Mode."
                } elseif ($logger) {
                    Write-Log "[Gaming] MSI Mode for GPU/storage already enabled or not applicable." -Level 'Info'
                }
            } else {
                Write-Host "  [ ] MSI Mode skipped." -ForegroundColor DarkGray
            }
            Write-Host "[+] Gaming tweaks applied." -ForegroundColor Magenta

            $backupFile = "C:\ProgramData\Scynesthesia\network_backup.json"
            if (Get-Confirmation "Apply Hardcore Network Tweaks (Bufferbloat/MTU)?" 'n') {
                if (-not (Test-Path $backupFile)) {
                    try {
                        Save-NetworkBackupState
                    } catch {
                        Invoke-ErrorHandler -Context "Creating network backup before Hardcore tweaks" -ErrorRecord $_
                    }
                }

                Write-Host "  [!] Warning: MTU discovery will run and may cause brief network disconnects." -ForegroundColor Yellow
                try {
                    Invoke-NetworkTweaksHardcore
                    $Global:NeedsReboot = $true
                } catch {
                    Invoke-ErrorHandler -Context "Applying Hardcore Network Tweaks from Gaming preset" -ErrorRecord $_
                }
            } else {
                Write-Host "  [ ] Hardcore Network Tweaks skipped." -ForegroundColor DarkGray
            }
        }
        '4' {
            Write-Section "Repair Tools"
            Invoke-NetworkSoftReset
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
        '0' { break }
    }

    Write-Host "Tip: Run 'Safe Preset' before 'Gaming Mode' for best results." -ForegroundColor DarkGray

} while ($choice -ne '0')

$logger = Get-Command Write-Log -ErrorAction SilentlyContinue
if ($Global:NeedsReboot) {
    if (Get-Confirmation -Question "Some changes (like Nagle/MSI Mode) require a reboot to fully apply. Do you want to restart now?" -Default 'n') {
        if ($logger) { Write-Log "[System] User chose to reboot from main menu." }
        try {
            shutdown /r /t 0
        } catch {
            Write-Host "[System] Failed to initiate reboot: $($_.Exception.Message)" -ForegroundColor Red
            if ($logger) { Write-Log "[System] Failed to initiate reboot: $($_.Exception.Message)" }
        }
    } else {
        if ($logger) { Write-Log "[System] User chose NOT to reboot at the end of the script." }
        Write-Host "[System] Reminder: some changes will fully apply after a manual reboot." -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] No changes requiring a reboot were applied." -ForegroundColor Gray
}

try {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        Write-Host "Log saved." -ForegroundColor Gray
    }
} catch {}
