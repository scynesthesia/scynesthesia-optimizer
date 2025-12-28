# Depends on: ui.psm1 (loaded by main script)
# Description: Adjusts scheduler priorities to favor foreground gaming workloads.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Logs actions when logger available.
function Optimize-GamingScheduler {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Process Priority (Gaming)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    if (Get-Confirmation "Prioritize GPU/CPU for foreground games?" 'y') {
        $gamesPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

        Set-RegistryValueSafe $gamesPath "GPU Priority" 8 -Context $Context
        Set-RegistryValueSafe $gamesPath "Priority" 6 -Context $Context
        Set-RegistryValueSafe $gamesPath "Scheduling Category" "High" ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context
        Set-RegistryValueSafe $gamesPath "SFIO Priority" "High" ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context

        Write-Host "  [+] Scheduler optimized for games." -ForegroundColor Green
        if ($logger) {
            Write-Log "[Gaming] Foreground game priorities set (GPU Priority=8, Priority=6, Scheduling/SFIO=High)."
        }

        Set-RebootRequired -Context $Context | Out-Null
    } else {
        Write-Host "  [ ] Scheduler left unchanged." -ForegroundColor DarkGray
    }
}


# Description: Retrieves or creates the custom 'Scynesthesia Gaming Mode' power plan.
# Parameters: None.
# Returns: Power plan CIM instance for the gaming profile.
function Get-OrCreate-GamingPlan {
    $planName = "Scynesthesia Gaming Mode"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    try {
        $plans = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop
    } catch {
        throw "Unable to query power plans via CIM: $_"
    }

    $existingPlan = $plans | Where-Object { $_.ElementName -eq $planName }
    if ($existingPlan) {
        if ($logger) {
            Write-Log "[Gaming] Reusing existing '$planName' power plan."
        }
        return $existingPlan
    }

    $activePlan = $plans | Where-Object { $_.IsActive -eq $true } | Select-Object -First 1
    if (-not $activePlan) {
        throw "Unable to detect active power plan."
    }

    $activeGuid = ($activePlan.InstanceID -split '[{}]')[1]
    if (-not $activeGuid) {
        throw "Unable to parse active power plan GUID."
    }

    $duplicateOutput = powercfg -duplicatescheme $activeGuid
    $duplicateMatch  = [regex]::Match($duplicateOutput, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')

    if (-not $duplicateMatch.Success) {
        throw "Unable to duplicate active power scheme."
    }

    $newGuid = $duplicateMatch.Groups[1].Value
    powercfg -changename $newGuid $planName
    if ($logger) {
        Write-Log "[Gaming] Duplicated active plan to '$planName' (GUID=$newGuid)."
    }

    $gamingPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop |
        Where-Object { $_.ElementName -eq $planName }

    if (-not $gamingPlan) {
        throw "Failed to locate gaming power plan after creation."
    }

    return $gamingPlan
}

# Description: Determines whether the system is currently running on battery power.
# Parameters: None.
# Returns: Boolean indicating active battery usage.
function Test-IsOnBatteryPower {
    try {
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    } catch {
        $battery = $null
    }

    if (-not $battery) { return $false }

    try {
        $status = $battery.BatteryStatus
        if ($null -ne $status) {
            $statusCode = [int]$status
            $dischargingStates = @(1, 4, 5, 11)
            return $dischargingStates -contains $statusCode
        }
    } catch { }

    return $false
}

# Description: Applies high-performance power settings tailored for gaming scenarios.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Activates or updates the gaming power plan.
function Invoke-CustomGamingPowerSettings {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Power Plan: 'Custom Gaming Tweaks'"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $isLaptop = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($isLaptop) {
        Write-Host "  [!] Laptop detected: these settings increase power draw and temperatures." -ForegroundColor Yellow
        Write-Host "      Recommended only while plugged into AC power." -ForegroundColor Yellow
    }

    $onBatteryPower = Test-IsOnBatteryPower
    if ($onBatteryPower) {
        Write-Host "  [!] System is currently running on battery power." -ForegroundColor Yellow
        Write-Host "      Aggressive tweaks disable USB/PCIe power management and assume stable AC power." -ForegroundColor Yellow
        if (-not (Get-Confirmation "Confirm you are plugged into AC before applying hardcore power tweaks." 'n')) {
            Write-Host "  [ ] Hardcore power tweaks skipped while on battery." -ForegroundColor DarkGray
            return
        }
    }

    Write-Host "Applying adjustments to the 'Scynesthesia Gaming Mode' plan." -ForegroundColor DarkGray

    if (Get-Confirmation "Apply hardcore power tweaks to prioritize FPS?" 'n') {
        try {
            $gamingPlan = Get-OrCreate-GamingPlan
            $gamingGuid = ($gamingPlan.InstanceID -split '[{}]')[1]

            if (-not $gamingGuid) {
                throw "Unable to parse gaming power plan GUID."
            }

            # 1) Disks / NVMe
            powercfg /setacvalueindex $gamingGuid SUB_DISK DISKIDLE 0
            powercfg /setacvalueindex $gamingGuid SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0

            # 2) CPU / Core parking / EPP
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR PROCTHROTTLEMIN 100
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 100
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0

            # 3) USB selective suspend OFF
            powercfg /setacvalueindex $gamingGuid `
                2a737441-1930-4402-8d77-b2bebba308a3 `
                48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

            # 4) PCIe Link State OFF
            powercfg /setacvalueindex $gamingGuid `
                501a4d13-42af-4429-9fd1-a8218c268e20 `
                ee12f906-d277-404b-b6da-e5fa1a576df5 0

            powercfg /setactive $gamingGuid

            Write-Host "  [+] Power settings for gaming applied." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Hardcore power plan tweaks applied and set active (GUID=$gamingGuid)."
            }

            Set-RebootRequired -Context $Context | Out-Null
        } catch {
            Invoke-ErrorHandler -Context "Applying gaming power settings" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] Hardcore power tweaks skipped." -ForegroundColor DarkGray
    }
}
# Description: Disables USB hub power management flags to minimize input latency.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Logs actions when logger is available.
function Set-UsbPowerManagementHardcore {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "USB Power Management"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $usbRoot = "HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB"
    $targetNames = @('USB Root Hub','Generic USB Hub')

    if (-not (Test-Path $usbRoot)) {
        Write-Host "  [!] USB registry path not found. Skipping USB power tweaks." -ForegroundColor Yellow
        return
    }

    $hubs = @()
    try {
        $hubs = Get-ChildItem -Path $usbRoot -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer } |
            ForEach-Object {
                try {
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                } catch {
                    return
                }

                $friendly = $props.FriendlyName
                $deviceDesc = $props.DeviceDesc
                if ($targetNames -contains $friendly -or $targetNames -contains $deviceDesc) {
                    return [pscustomobject]@{
                        Path = $_.PSPath
                        Name = if ($friendly) { $friendly } else { $deviceDesc }
                    }
                }
            } | Where-Object { $_ }
    } catch {
        Invoke-ErrorHandler -Context "Enumerating USB hubs" -ErrorRecord $_
        return
    }

    if ($hubs.Count -eq 0) {
        Write-Host "  [!] No USB hubs found for power override." -ForegroundColor Yellow
        return
    }

    foreach ($hub in $hubs) {
        try {
            Set-RegistryValueSafe -Path $hub.Path -Name 'PnPCapabilities' -Value 24 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context
            Write-Host "  [+] USB hub '$($hub.Name)' power disable applied." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] USB hub '$($hub.Name)' PnPCapabilities set to 24."
            }

            Set-RebootRequired -Context $Context | Out-Null
        } catch {
            Invoke-ErrorHandler -Context "Setting USB power flags on $($hub.Name)" -ErrorRecord $_
        }
    }

    Write-Host "[+] USB power management overrides applied." -ForegroundColor Magenta
}

# Description: Tunes HID class queue sizes to reduce input buffering latency.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Records changes when logger is present.
function Optimize-HidLatency {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "HID Latency Optimizations"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $hidPaths = @(
        @{ Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mouclass\\Parameters"; Name = 'MouseDataQueueSize' },
        @{ Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\kbdclass\\Parameters"; Name = 'KeyboardDataQueueSize' }
    )

    foreach ($entry in $hidPaths) {
        try {
            Set-RegistryValueSafe -Path $entry.Path -Name $entry.Name -Value 100 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context
            Write-Host "  [+] $($entry.Name) set to 100." -ForegroundColor Green
            if ($logger) { Write-Log "[Gaming] $($entry.Name) set to 100 for HID latency optimization." }
        } catch {
            Invoke-ErrorHandler -Context "Setting $($entry.Name) for HID latency" -ErrorRecord $_
        }
    }

    Set-RebootRequired -Context $Context | Out-Null
}
# Description: Tunes processor scheduling registry settings for lower input latency.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Records changes when logger is present.
function Optimize-ProcessorScheduling {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Processor Scheduling (Win32Priority)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Write-Host "Tweaks CPU allocation for active windows. Recommended for competitive gaming." -ForegroundColor Gray
    $priorityPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl"
    $currentValue = Get-ItemPropertyValue -Path $priorityPath -Name 'Win32PrioritySeparation' -ErrorAction SilentlyContinue

    if ($currentValue -eq 40) {
        Write-Host "Processor scheduling is already optimized" -ForegroundColor DarkGray
        return
    }

    # 0x28 (40 decimal): Short intervals + Fixed Quantum.
    # Better for consistent frametimes in games; not the classic dynamic foreground "boost."
    if (Get-Confirmation "Apply Fixed Priority Separation (28 Hex) for lower input latency?" 'n') {
        Set-RegistryValueSafe $priorityPath "Win32PrioritySeparation" 40 -Context $Context
        Write-Host "  [+] Processor scheduling set to 28 Hex (Fixed/Short)." -ForegroundColor Green
        if ($logger) {
            Write-Log "[Gaming] Win32PrioritySeparation set to 0x28 for fixed/short quanta."
        }

        Set-RebootRequired -Context $Context | Out-Null
    } else {
        Write-Host "  [ ] Processor scheduling left unchanged." -ForegroundColor DarkGray
    }
}

# Description: Disables Fullscreen Optimizations globally for DX11 input latency gains.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Sets reboot flag after applying registry overrides.
function Set-FsoGlobalOverride {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Fullscreen Optimizations (Global Override)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Write-Host "Disabling FSO reduces input lag but may cause slower or 'buggy' Alt+Tab transitions." -ForegroundColor Yellow
    $disableFso = Get-Confirmation "Disable Fullscreen Optimizations for maximum latency reduction?" 'n'
    try {
        if ($disableFso) {
            Set-RegistryValueSafe -Path "HKCU:\\System\\GameConfigStore" -Name 'GameDVR_FSEBehaviorMode' -Value 2 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context
            Set-RegistryValueSafe -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" -Name 'AllowGameDVR' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context

            Write-Host "  [+] Fullscreen Optimizations disabled globally." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Fullscreen Optimizations globally disabled (GameDVR_FSEBehaviorMode=2, AllowGameDVR=0)."
            }
        } else {
            Set-RegistryValueSafe -Path "HKCU:\\System\\GameConfigStore" -Name 'GameDVR_FSEBehaviorMode' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context
            Set-RegistryValueSafe -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" -Name 'AllowGameDVR' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context

            Write-Host "  [ ] Fullscreen Optimizations left at Windows defaults (restored)." -ForegroundColor DarkGray
            if ($logger) {
                Write-Log "[Gaming] Fullscreen Optimizations restored to defaults (GameDVR_FSEBehaviorMode=0, AllowGameDVR=1)."
            }
        }

        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [!] Reboot required to finalize Fullscreen Optimizations override." -ForegroundColor Yellow
    } catch {
        Invoke-ErrorHandler -Context "Applying Fullscreen Optimizations global override" -ErrorRecord $_
    }
}

# Description: Runs the complete Gaming preset sequence following modular standards.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Sequentially applies gaming optimizations and reports completion.
function Invoke-GamingOptimizations {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Optimize-GamingScheduler -Context $Context
    Invoke-CustomGamingPowerSettings -Context $Context
    Optimize-ProcessorScheduling -Context $Context
    Set-UsbPowerManagementHardcore -Context $Context
    Optimize-HidLatency -Context $Context
    Invoke-DriverTelemetry
    Set-FsoGlobalOverride -Context $Context

    Write-Host "[+] Global Gaming Optimizations complete." -ForegroundColor Magenta
}

Export-ModuleMember -Function Optimize-GamingScheduler, Invoke-CustomGamingPowerSettings, Optimize-ProcessorScheduling, Set-UsbPowerManagementHardcore, Optimize-HidLatency, Set-FsoGlobalOverride, Invoke-GamingOptimizations
