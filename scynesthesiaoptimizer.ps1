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

# ---------- 2. MODULE IMPORTS (Moved up to ensure dependencies load early.) ----------
$Global:NeedsReboot = $false
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
try {
    $modulesRoot = Join-Path $ScriptPath 'modules'
    $uiModule = Join-Path $modulesRoot 'ui.psm1'
    Import-Module $uiModule -Force -ErrorAction Stop
    Write-Host "[OK] Module loaded: ui.psm1" -ForegroundColor Green

    $moduleFiles = Get-ChildItem -Path $modulesRoot -Filter '*.psm1' -File -ErrorAction Stop

    foreach ($module in $moduleFiles) {
        if ($module.Name -eq 'ui.psm1') { continue }
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
    if (Get-Command Handle-Error -ErrorAction SilentlyContinue) {
        Handle-Error -Context "Loading modules" -ErrorRecord $_
    } else {
        Write-Error "Error loading modules: $($_.Exception.Message)"
    }
    Write-Host "Make sure the 'modules' folder is next to this script."
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------- 3. LOGGING (Transcript and logging initialization.) ----------
$TranscriptStarted = $false
# Ask-YesNo is now available from ui.psm1.
if (Ask-YesNo "Enable session logging to a file? / Habilitar registro de sesion en un archivo? (Recommended for Service Records) [y/N]" 'n') {
    $logDir = Join-Path $env:TEMP "ScynesthesiaOptimizer"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = Join-Path $logDir "Scynesthesia_Log_$timestamp.txt"
    
    try {
        Start-Transcript -Path $logFile -Append -ErrorAction Stop
        $TranscriptStarted = $true
        Write-Host "Logging started: $logFile" -ForegroundColor Gray
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
    $activePlanName = 'Unknown'
    try {
        $activePlanOutput = powercfg -getactivescheme 2>$null
        if ($activePlanOutput -match '\((.+)\)') {
            $activePlanName = $Matches[1].Trim()
        }
    } catch { }
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
    Write-Host " Preset 1: Safe | Preset 2: Slow PC / Aggressive" -ForegroundColor Gray
    Write-Host " Active power plan: $activePlanName" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------`n" -ForegroundColor DarkGray
}

# Description: Ensures the requested Windows power plan is active.
# Parameters: Mode - Chooses between Balanced or HighPerformance power plans.
# Returns: None.
function Ensure-PowerPlan {
    param([ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance')
    Write-Host "  [i] Setting base power plan to: $Mode" -ForegroundColor Gray
    if ($Mode -eq 'HighPerformance') {
        powercfg /setactive SCHEME_MAX
    } else {
        powercfg /setactive SCHEME_BALANCED
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
        if (Ask-YesNo $label -Default 'n') {
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

    Write-Section "Starting Preset 1: Safe (Main)"
    Create-RestorePointSafe
    Clear-TempFiles

    # Safe Debloat (Standard list)
    Apply-PrivacyTelemetrySafe
    $debloatResult = Apply-DebloatSafe # Uses the default list defined in the module
    $Status.PackagesFailed += $debloatResult.Failed

    Apply-PreferencesSafe
    Invoke-SafeOptionalPrompts
    Handle-SysMainPrompt -HardwareProfile $HWProfile
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Apply-SafePerformanceTweaks
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = $Global:NeedsReboot
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe preset applied. Restart when possible." -ForegroundColor Green
}

# Description: Executes the Slow PC/Aggressive preset for deeper cleanup and performance tuning.
# Parameters: None.
# Returns: None. Updates global reboot flag and failed package list.
function Run-PCSlowPreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Starting Preset 2: Slow PC / Aggressive"
    Create-RestorePointSafe
    Clear-TempFiles

    Apply-PrivacyTelemetrySafe
    
    # Deep cleaning using Aggressive Debloat profile.
    # Using updated function from debloat.psm1.
    $debloatResult = Apply-DebloatAggressive 
    $Status.PackagesFailed += $debloatResult.Failed
    
    Apply-PreferencesSafe
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    # Additional tweaks specific to slow PCs
    Apply-AggressivePerformanceTweaks
    Apply-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices

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
        Write-Host "1) Safe (Estabilidad / navegacion)"
        Write-Host "2) Aggressive (Privacidad / menos ruido LAN)"
        Write-Host "3) Gaming (Ping bajo / baja latencia)"
        Write-Host "4) Revertir tweaks de red (usar backup)"
        Write-Host "5) Hardcore (Competitive / Avanzado)"
        Write-Host "6) Volver"
        Write-Host ""

        $netChoice = Read-MenuChoice "Select a network option" @('1','2','3','4','5','6')
        $backupFile = "C:\ProgramData\Scynesthesia\network_backup.json"

        $ensureBackup = {
            if (-not (Test-Path $backupFile)) {
                if (Ask-YesNo "Save a backup of your current network configuration before applying tweaks (recommended)? / Queres guardar un backup de tu configuracion de red actual antes de aplicar tweaks (recomendado)?" 'y') {
                    Save-NetworkBackupState
                }
            }
        }

        switch ($netChoice) {
            '1' {
                & $ensureBackup
                if (Ask-YesNo "Apply Safe Network Tweaks? / Aplicar Tweaks de Red Seguros?" 'n') {
                    Invoke-NetworkTweaksSafe
                } else {
                    Write-Host "[ ] Safe Network Tweaks skipped." -ForegroundColor Gray
                }
                Write-Host ""
                Read-Host "Press Enter to return to the Network Tweaks menu"
            }
            '2' {
                & $ensureBackup
                if (Ask-YesNo "Apply Aggressive Network Tweaks? / Aplicar Tweaks de Red Agresivos?" 'n') {
                    Invoke-NetworkTweaksAggressive
                } else {
                    Write-Host "[ ] Aggressive Network Tweaks skipped." -ForegroundColor Gray
                }
                Write-Host ""
                Read-Host "Press Enter to return to the Network Tweaks menu"
            }
            '3' {
                & $ensureBackup
                if (Ask-YesNo "Apply Gaming Network Tweaks? / Aplicar Tweaks de Red para Gaming?" 'n') {
                    Invoke-NetworkTweaksGaming
                } else {
                    Write-Host "[ ] Gaming Network Tweaks skipped." -ForegroundColor Gray
                }
                if ($Global:NeedsReboot) {
                    Write-Host "  [i] Some network/gaming changes will require a reboot. You will be prompted before exiting." -ForegroundColor Yellow
                }
                Write-Host ""
                Read-Host "Press Enter to return to the Network Tweaks menu"
            }
            '4' {
                Restore-NetworkBackupState
                Write-Host ""
                Read-Host "Presiona Enter para volver al menu de Network Tweaks"
            }
            '5' {
                if (Ask-YesNo "Apply Hardcore Network Tweaks (Bufferbloat/MTU)? / ¿Aplicar Tweaks de Red Hardcore (Bufferbloat/MTU)?" 'n') {
                    if (-not (Test-Path $backupFile)) {
                        try {
                            Save-NetworkBackupState
                        } catch {
                            Handle-Error -Context "Creating network backup before Hardcore tweaks (Network Tweaks menu)" -ErrorRecord $_
                        }
                    }

                    Write-Host "  [!] Warning: MTU discovery will run and may cause brief network disconnects. / Advertencia: El descubrimiento de MTU se ejecutará y puede causar desconexiones breves." -ForegroundColor Yellow
                    try {
                        Invoke-NetworkTweaksHardcore
                        $Global:NeedsReboot = $true
                    } catch {
                        Handle-Error -Context "Applying Hardcore Network Tweaks from Network Tweaks menu" -ErrorRecord $_
                    }
                } else {
                    Write-Host "[ ] Hardcore Network Tweaks skipped. / [ ] Tweaks de Red Hardcore omitidos." -ForegroundColor Gray
                }
                Write-Host ""
                Read-Host "Press Enter to return to the Network Tweaks menu"
            }
            '6' { return }
        }
    } while ($true)
}

# ---------- 6. MAIN LOOP ----------

do {
    Show-Banner
    Write-Host "1) Safe preset / Preset Seguro (SOC / Navegacion)"
    Write-Host "2) Aggressive preset / Preset Agresivo (Deep Debloat / Privacidad)"
    Write-Host "3) Gaming preset / Modo Gaming (Baja latencia)"
    Write-Host "4) Repair tools / Herramientas de reparacion"
    Write-Host "5) Network Tweaks / Tweaks de red"
    Write-Host "0) Exit / Salir"
    Write-Host ""
    $choice = Read-MenuChoice "Select an option" @('1','2','3','4','5','0')

    switch ($choice) {
        '1' { Run-SafePreset }
        '2' { Run-PCSlowPreset }
        '3' {
            Write-Section "GAMING MODE / FPS BOOST"
            $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
            Invoke-GamingOptimizations
            if (Ask-YesNo "Enable MSI Mode for GPU and storage controllers? (Recommended for Gaming Mode. NIC can be adjusted separately from the Network Tweaks menu.) / Habilitar MSI Mode para GPU y controladores de almacenamiento? (Recomendado para Gaming Mode. La placa de red (NIC) se puede ajustar aparte desde el menu de Network Tweaks.)" 'y') {
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
            if (Ask-YesNo "Apply Hardcore Network Tweaks (Bufferbloat/MTU)? / ¿Aplicar Tweaks de Red Hardcore (Bufferbloat/MTU)?" 'n') {
                if (-not (Test-Path $backupFile)) {
                    try {
                        Save-NetworkBackupState
                    } catch {
                        Handle-Error -Context "Creating network backup before Hardcore tweaks" -ErrorRecord $_
                    }
                }

                Write-Host "  [!] Warning: MTU discovery will run and may cause brief network disconnects. / Advertencia: El descubrimiento de MTU se ejecutará y puede causar desconexiones breves." -ForegroundColor Yellow
                try {
                    Invoke-NetworkTweaksHardcore
                    $Global:NeedsReboot = $true
                } catch {
                    Handle-Error -Context "Applying Hardcore Network Tweaks from Gaming preset" -ErrorRecord $_
                }
            } else {
                Write-Host "  [ ] Hardcore Network Tweaks skipped. / [ ] Tweaks de Red Hardcore omitidos." -ForegroundColor DarkGray
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
        '0' { break }
    }

} while ($choice -ne '0')

$logger = Get-Command Write-Log -ErrorAction SilentlyContinue
if ($Global:NeedsReboot) {
    if (Ask-YesNo -Question "Some changes (like Nagle/MSI Mode) require a reboot to fully apply. Do you want to restart now? / Algunos cambios (como Nagle/MSI Mode) requieren reiniciar para aplicarse por completo. Queres reiniciar ahora?" -Default 'n') {
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
    Write-Host "[i] No changes requiring a reboot were applied. / No se aplicaron cambios que requieran reinicio." -ForegroundColor Gray
}

try {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        Write-Host "Log saved." -ForegroundColor Gray
    }
} catch {}
