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

function Show-Banner {
    Clear-Host
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
    Write-Host " Base power plan: High performance" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------`n" -ForegroundColor DarkGray
}

function Ensure-PowerPlan {
    param([ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance')
    Write-Host "  [i] Setting base power plan to: $Mode" -ForegroundColor Gray
    if ($Mode -eq 'HighPerformance') {
        powercfg /setactive SCHEME_MIN
    } else {
        powercfg /setactive SCHEME_BALANCED
    }
}

function Invoke-SafeOptionalPrompts {
    Write-Section "Additional options for Safe preset"
    $options = @(
        @{ Key = '1'; Description = 'Disable Cortana in search'; Action = { Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 } },
        @{ Key = '2'; Description = 'Disable Store suggestions in Start'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 } },
        @{ Key = '3'; Description = 'Enable compact view in File Explorer'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "UseCompactMode" 1 } }
    )
    foreach ($opt in $options) {
        $label = "$($opt.Key) $($opt.Description)"
        if (Ask-YesNo $label -Default $false) {
            & $opt.Action
            Write-Host "[OK] $($opt.Description) applied." -ForegroundColor Green
        } else {
            Write-Host "Skipped: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

# ---------- 5. PRESETS ----------

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

    $Status.RebootRequired = $true
    if ($Status.RebootRequired) {
        $Global:NeedsReboot = $true
    }
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe preset applied. Restart when possible." -ForegroundColor Green
}

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

    $Status.RebootRequired = $true
    if ($Status.RebootRequired) {
        $Global:NeedsReboot = $true
    }
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Slow PC / Aggressive preset applied. Please restart." -ForegroundColor Green
}

function Show-NetworkTweaksMenu {
    do {
        Write-Section "Network Tweaks"
        Write-Host "1) Safe (Estabilidad / navegacion)"
        Write-Host "2) Aggressive (Privacidad / menos ruido LAN)"
        Write-Host "3) Gaming (Ping bajo / baja latencia)"
        Write-Host "4) Revertir tweaks de red (usar backup)"
        Write-Host "5) Volver"
        Write-Host ""

        $netChoice = Read-MenuChoice "Select a network option" @('1','2','3','4','5')
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
                Write-Host ""
                Read-Host "Press Enter to return to the Network Tweaks menu"
            }
            '4' {
                Restore-NetworkBackupState
                Write-Host ""
                Read-Host "Presiona Enter para volver al menu de Network Tweaks"
            }
            '5' { return }
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
            Optimize-GamingScheduler
            Apply-CustomGamingPowerSettings
            Optimize-ProcessorScheduling
            if (Ask-YesNo "Enable MSI Mode for GPU and storage controllers? (Recommended for Gaming Mode. NIC can be adjusted separately from the Network Tweaks menu.) / Habilitar MSI Mode para GPU y controladores de almacenamiento? (Recomendado para Gaming Mode. La placa de red (NIC) se puede ajustar aparte desde el menu de Network Tweaks.)" 'y') {
                Enable-MsiModeSafe -Target @('GPU','STORAGE')
                if ($logger) {
                    Write-Log "[Gaming] MSI Mode enabled for GPU and storage controllers from main Gaming Mode."
                }
            } else {
                Write-Host "  [ ] MSI Mode skipped." -ForegroundColor DarkGray
            }
            Write-Host "[+] Gaming tweaks applied." -ForegroundColor Magenta
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

    if ($choice -ne '0') {
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
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
