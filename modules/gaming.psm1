# Depends on: ui.psm1 (loaded by main script)
if (-not (Get-Command -Name 'Get-HardwareProfile' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'performance.psm1') -Force -Scope Local
}

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

        $gpuPriority = Set-RegistryValueSafe $gamesPath "GPU Priority" 8 -Context $Context -Critical -ReturnResult -OperationLabel 'Gaming scheduler GPU priority'
        $priority = Set-RegistryValueSafe $gamesPath "Priority" 6 -Context $Context -Critical -ReturnResult -OperationLabel 'Gaming scheduler priority'
        $schedCategory = Set-RegistryValueSafe $gamesPath "Scheduling Category" "High" ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel 'Gaming scheduler category'
        $sfioPriority = Set-RegistryValueSafe $gamesPath "SFIO Priority" "High" ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel 'Gaming scheduler SFIO priority'

        if (($gpuPriority -and $gpuPriority.Success) -and ($priority -and $priority.Success) -and ($schedCategory -and $schedCategory.Success) -and ($sfioPriority -and $sfioPriority.Success)) {
            Write-Host "  [+] Scheduler optimized for games." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Foreground game priorities set (GPU Priority=8, Priority=6, Scheduling/SFIO=High)."
            }
        } else {
            foreach ($entry in @(
                @{ Result = $gpuPriority; Label = 'Gaming scheduler GPU priority' },
                @{ Result = $priority; Label = 'Gaming scheduler priority' },
                @{ Result = $schedCategory; Label = 'Gaming scheduler category' },
                @{ Result = $sfioPriority; Label = 'Gaming scheduler SFIO priority' }
            )) {
                if (-not ($entry.Result -and $entry.Result.Success)) {
                    Register-HighImpactRegistryFailure -Context $Context -Result $entry.Result -OperationLabel $entry.Label | Out-Null
                }
            }
        }

        Set-RebootRequired -Context $Context | Out-Null
    } else {
        Write-Host "  [ ] Scheduler left unchanged." -ForegroundColor DarkGray
    }
}

# Description: Detects thin-and-light laptops that are more sensitive to aggressive power overrides.
# Parameters: HardwareProfile - Object returned by Get-HardwareProfile.
# Returns: Boolean indicating whether a conservative preset should be used.
function Test-ThinAndLightHardware {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    if (-not $HardwareProfile) { return $false }
    $isLaptop = $HardwareProfile.IsLaptop
    if (-not $isLaptop) { return $false }

    $memoryIsTight = $HardwareProfile.TotalMemoryGB -lt 16
    $ssdOnly = $HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD

    return $isLaptop -and ($memoryIsTight -or $ssdOnly -or (Test-ModernStandbySupported))
}

# Description: Detects Modern Standby (S0) capability to guard aggressive power overrides on laptops.
# Parameters: None.
# Returns: Boolean indicating Modern Standby support.
function Test-ModernStandbySupported {
    try {
        $output = & powercfg /a 2>$null
        if (-not $output) { return $false }
        return ($output -join "`n") -match '(?i)standby \\(s0'
    } catch {
        return $false
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

    $hardwareProfile = Get-HardwareProfile
    $isLaptop = $hardwareProfile -and $hardwareProfile.IsLaptop
    $isThinAndLight = Test-ThinAndLightHardware -HardwareProfile $hardwareProfile
    $hasModernStandby = Test-ModernStandbySupported
    if ($isLaptop) {
        Write-Host "  [!] Laptop detected: these settings increase power draw and temperatures." -ForegroundColor Yellow
        Write-Host "      Recommended only while plugged into AC power." -ForegroundColor Yellow
    }
    if ($isThinAndLight) {
        Write-Host "  [!] Thin-and-light hardware detected: scaling back USB/PCIe overrides to reduce throttling risk." -ForegroundColor Yellow
    }
    if ($hasModernStandby) {
        Write-Host "  [!] Modern Standby (S0) support detected: keeping some power safeguards to avoid firmware lockups." -ForegroundColor Yellow
    }

    $onBatteryPower = $hardwareProfile -and $hardwareProfile.OnBatteryPower
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

            # 3) USB selective suspend OFF (kept on for thin-and-light/Modern Standby)
            $usbSelectiveSuspend = if ($isThinAndLight -or $hasModernStandby) { 1 } else { 0 }
            powercfg /setacvalueindex $gamingGuid `
                2a737441-1930-4402-8d77-b2bebba308a3 `
                48e6b7a6-50f5-4782-a5d4-53bb8f07e226 $usbSelectiveSuspend

            # 4) PCIe Link State OFF (kept on for thin-and-light/Modern Standby)
            $pcieLinkState = if ($isThinAndLight -or $hasModernStandby) { 1 } else { 0 }
            powercfg /setacvalueindex $gamingGuid `
                501a4d13-42af-4429-9fd1-a8218c268e20 `
                ee12f906-d277-404b-b6da-e5fa1a576df5 $pcieLinkState

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
            $result = Set-RegistryValueSafe -Path $hub.Path -Name 'PnPCapabilities' -Value 24 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "USB hub power override: $($hub.Name)"
            if ($result -and $result.Success) {
                Write-Host "  [+] USB hub '$($hub.Name)' power disable applied." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Gaming] USB hub '$($hub.Name)' PnPCapabilities set to 24."
                }

                Set-RebootRequired -Context $Context | Out-Null
            } else {
                Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel "USB hub power override: $($hub.Name)" | Out-Null
            }
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
            $result = Set-RegistryValueSafe -Path $entry.Path -Name $entry.Name -Value 100 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set $($entry.Name) to 100"
            if ($result -and $result.Success) {
                Write-Host "  [+] $($entry.Name) set to 100." -ForegroundColor Green
                if ($logger) { Write-Log "[Gaming] $($entry.Name) set to 100 for HID latency optimization." }
            } else {
                Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel "Set $($entry.Name) to 100" | Out-Null
            }
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
        $result = Set-RegistryValueSafe $priorityPath "Win32PrioritySeparation" 40 -Context $Context -Critical -ReturnResult -OperationLabel 'Set Win32PrioritySeparation to 0x28'
        if ($result -and $result.Success) {
            Write-Host "  [+] Processor scheduling set to 28 Hex (Fixed/Short)." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Win32PrioritySeparation set to 0x28 for fixed/short quanta."
            }

            Set-RebootRequired -Context $Context | Out-Null
        } else {
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Set Win32PrioritySeparation to 0x28' | Out-Null
        }
    } else {
        Write-Host "  [ ] Processor scheduling left unchanged." -ForegroundColor DarkGray
    }
}

# Description: Disables Game DVR/Bar capture mechanisms to avoid overlay glitches.
# Parameters: Context - Run context used for rollback tracking.
# Returns: None. Records registry rollback data for all changes.
function Disable-GameDVR {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Write-Section "Disable Game DVR"
    Write-Host "Silencing Game Bar protocols to prevent visual glitches." -ForegroundColor DarkGray

    $appCapture = Set-RegistryValueSafe -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR" -Name 'AppCaptureEnabled' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $context -ReturnResult -OperationLabel 'Disable Game Bar AppCaptureEnabled'
    $gameDvrEnabled = Set-RegistryValueSafe -Path "HKCU:\\System\\GameConfigStore" -Name 'GameDVR_Enabled' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $context -ReturnResult -OperationLabel 'Disable GameDVR_Enabled'
    $allowGameDvr = Set-RegistryValueSafe -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" -Name 'AllowGameDVR' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $context -Critical -ReturnResult -OperationLabel 'Disable GameDVR policy'

    $allSucceeded = -not (@($appCapture, $gameDvrEnabled, $allowGameDvr) | Where-Object { -not ($_ -and $_.Success) })

    if ($allSucceeded) {
        Write-Host "  [+] Game DVR capture and policies disabled." -ForegroundColor Green
        if ($logger) {
            Write-Log "[Gaming] Game DVR disabled (AppCaptureEnabled=0, GameDVR_Enabled=0, AllowGameDVR=0)."
        }
    } else {
        foreach ($entry in @(
            @{ Result = $appCapture; Label = 'Disable Game Bar AppCaptureEnabled' },
            @{ Result = $gameDvrEnabled; Label = 'Disable GameDVR_Enabled' },
            @{ Result = $allowGameDvr; Label = 'Disable GameDVR policy' }
        )) {
            if (-not ($entry.Result -and $entry.Result.Success)) {
                if ($entry.Label -eq 'Disable GameDVR policy') {
                    Register-HighImpactRegistryFailure -Context $context -Result $entry.Result -OperationLabel $entry.Label | Out-Null
                } else {
                    Write-Host "  [!] $($entry.Label) could not be applied." -ForegroundColor Yellow
                }
            }
        }
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
            $fseBehavior = Set-RegistryValueSafe -Path "HKCU:\\System\\GameConfigStore" -Name 'GameDVR_FSEBehaviorMode' -Value 2 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel 'Set GameDVR_FSEBehaviorMode to 2'
            $allowGameDvr = Set-RegistryValueSafe -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" -Name 'AllowGameDVR' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable GameDVR policy'

            if (($fseBehavior -and $fseBehavior.Success) -and ($allowGameDvr -and $allowGameDvr.Success)) {
                Write-Host "  [+] Fullscreen Optimizations disabled globally." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Gaming] Fullscreen Optimizations globally disabled (GameDVR_FSEBehaviorMode=2, AllowGameDVR=0)."
                }
            } else {
                Write-Host "  [!] Fullscreen Optimization changes could not be fully applied." -ForegroundColor Yellow
                if (-not ($allowGameDvr -and $allowGameDvr.Success)) {
                    Register-HighImpactRegistryFailure -Context $Context -Result $allowGameDvr -OperationLabel 'Disable GameDVR policy' | Out-Null
                }
            }
        } else {
            $fseBehavior = Set-RegistryValueSafe -Path "HKCU:\\System\\GameConfigStore" -Name 'GameDVR_FSEBehaviorMode' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel 'Restore GameDVR_FSEBehaviorMode'
            $allowGameDvr = Set-RegistryValueSafe -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" -Name 'AllowGameDVR' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Restore GameDVR policy'

            if (($fseBehavior -and $fseBehavior.Success) -and ($allowGameDvr -and $allowGameDvr.Success)) {
                Write-Host "  [ ] Fullscreen Optimizations left at Windows defaults (restored)." -ForegroundColor DarkGray
                if ($logger) {
                    Write-Log "[Gaming] Fullscreen Optimizations restored to defaults (GameDVR_FSEBehaviorMode=0, AllowGameDVR=1)."
                }
            } else {
                Write-Host "  [!] Fullscreen Optimizations could not be restored completely." -ForegroundColor Yellow
                if (-not ($allowGameDvr -and $allowGameDvr.Success)) {
                    Register-HighImpactRegistryFailure -Context $Context -Result $allowGameDvr -OperationLabel 'Restore GameDVR policy' | Out-Null
                }
            }
        }

        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [!] Reboot required to finalize Fullscreen Optimizations override." -ForegroundColor Yellow
    } catch {
        Invoke-ErrorHandler -Context "Applying Fullscreen Optimizations global override" -ErrorRecord $_
    }
}

# Description: Disables UDP Segmentation Offload globally and on physical adapters to reduce burst-related latency.
# Parameters: Context - Run context for rollback/logging helpers.
# Returns: None. Reports adapters touched and warns when not supported.
function Disable-UdpSegmentOffload {
    param(
        [pscustomobject]$Context
    )

    Write-Section "UDP Segmentation Offload (USO)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $adapters = @()
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -ne 'Disabled' }
    } catch {
        Write-Host "  [!] Unable to enumerate physical adapters: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $globalApplied = $false
    $setNetOffload = Get-Command -Name 'Set-NetOffloadGlobalSetting' -ErrorAction SilentlyContinue
    if ($setNetOffload) {
        try {
            Set-NetOffloadGlobalSetting -UdpSegmentationOffload Disabled -ErrorAction Stop | Out-Null
            $globalApplied = $true
            Write-Host "  [+] Global USO disabled." -ForegroundColor Green
            if ($logger) { Write-Log "[Gaming] UDP Segmentation Offload disabled globally." }
        } catch {
            Write-Host "  [!] Could not disable global USO: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Global USO toggle unavailable on this platform." -ForegroundColor DarkGray
    }

    if (-not $adapters -or $adapters.Count -eq 0) {
        if (-not $globalApplied) {
            Write-Host "  [!] No eligible adapters found for USO changes." -ForegroundColor Yellow
        }
        return
    }

    $properties = @('UDP Segmentation Offload (IPv4)', 'UDP Segmentation Offload (IPv6)')
    $touched = New-Object System.Collections.Generic.List[string]
    foreach ($adapter in $adapters) {
        foreach ($property in $properties) {
            try {
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $property -DisplayValue 'Disabled' -NoRestart -ErrorAction Stop | Out-Null
                $touched.Add($adapter.Name) | Out-Null
                Write-Host "  [+] $property disabled on $($adapter.Name)." -ForegroundColor Green
                if ($logger) { Write-Log "[Gaming] $property disabled on $($adapter.Name)." }
            } catch {
                Write-Host "  [ ] $property unsupported on $($adapter.Name): $($_.Exception.Message)" -ForegroundColor DarkGray
            }
        }
    }

    if ($touched.Count -gt 0 -or $globalApplied) {
        Write-Host "  [+] UDP Segmentation Offload disabled where supported." -ForegroundColor Green
    } else {
        Write-Host "  [!] USO could not be disabled on detected adapters." -ForegroundColor Yellow
    }
}

# Description: Enables TCP Fast Open to reduce handshake latency for supporting applications.
# Parameters: Context - Optional run context for rollback/logging.
# Returns: None. Logs the action and surfaces compatibility warnings.
function Enable-TcpFastOpen {
    param(
        [pscustomobject]$Context
    )

    Write-Section "TCP Fast Open"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        netsh int tcp set global fastopen=enabled | Out-Null
        Write-Host "  [+] TCP Fast Open enabled in the global stack." -ForegroundColor Green
        if ($logger) { Write-Log "[Gaming] TCP Fast Open enabled via netsh." }
    } catch {
        Write-Host "  [!] Unable to enable TCP Fast Open: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Description: Disables ARP and Neighbor Solicitation offload on physical adapters for steadier packet pacing.
# Parameters: Context - Optional run context for rollback/logging.
# Returns: None. Reports adapters touched and warns on unsupported drivers.
function Disable-ArpNsOffload {
    param(
        [pscustomobject]$Context
    )

    Write-Section "ARP/Neighbor Solicitation Offload"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $adapters = @()
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -ne 'Disabled' }
    } catch {
        Write-Host "  [!] Unable to enumerate physical adapters: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for ARP/NS offload changes." -ForegroundColor Yellow
        return
    }

    $touched = New-Object System.Collections.Generic.List[string]
    foreach ($adapter in $adapters) {
        $powerManagementApplied = $false
        try {
            Set-NetAdapterPowerManagement -Name $adapter.Name -ArpOffload Disabled -NsOffload Disabled -ErrorAction Stop | Out-Null
            $powerManagementApplied = $true
            $touched.Add($adapter.Name) | Out-Null
            Write-Host "  [+] ARP/NS offload disabled via power management on $($adapter.Name)." -ForegroundColor Green
            if ($logger) { Write-Log "[Gaming] ARP/NS offload disabled on $($adapter.Name) through power management." }
        } catch {
            Write-Host "  [ ] Power management ARP/NS offload toggle unsupported on $($adapter.Name): $($_.Exception.Message)" -ForegroundColor DarkGray
        }

        foreach ($property in @('ARP Offload', 'NS Offload')) {
            try {
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $property -DisplayValue 'Disabled' -NoRestart -ErrorAction Stop | Out-Null
                if (-not $touched.Contains($adapter.Name)) { $touched.Add($adapter.Name) | Out-Null }
                Write-Host "  [+] $property disabled on $($adapter.Name)." -ForegroundColor Green
                if ($logger) { Write-Log "[Gaming] $property disabled on $($adapter.Name)." }
            } catch {
                if (-not $powerManagementApplied) {
                    Write-Host "  [ ] $property unsupported on $($adapter.Name): $($_.Exception.Message)" -ForegroundColor DarkGray
                }
            }
        }
    }

    if ($touched.Count -gt 0) {
        Write-Host "  [+] ARP/NS offload disabled where supported." -ForegroundColor Green
    } else {
        Write-Host "  [!] No ARP/NS offload settings could be changed on detected adapters." -ForegroundColor Yellow
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

# Description: Interactive creator for per-game QoS rules using DSCP 46 (Expedited Forwarding).
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Registers registry and service changes for rollback via the provided context.
function Manage-GameQoS {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Interactive QoS Rules (Expedited Forwarding)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Write-Host "Tip: You can find the executable name under Task Manager > Details while the game is running." -ForegroundColor DarkGray
    $invalidChars = [regex]::Escape(([string]::Join('', [System.IO.Path]::GetInvalidFileNameChars())))
    $invalidPattern = "[${invalidChars}]"
    $maxRuleLength = 60
    $maxExeLength = 80

    function Test-ExecutableInPath {
        param([string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        try {
            $paths = ($env:PATH -split ';') | Where-Object { $_ -and (Test-Path $_) }
            foreach ($p in $paths) {
                $candidate = Join-Path $p $Name
                if (Test-Path -Path $candidate -PathType Leaf) { return $true }
            }
        } catch { }
        return $false
    }

    $qwaveServices = @('QWAVE', 'SDRSVC')
    $qwaveConfigured = $false
    foreach ($svcName in $qwaveServices) {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $service) { continue }
        $qwaveConfigured = $true

        try {
            Add-ServiceRollbackAction -Context $Context -ServiceName $service.Name -StartupType $service.StartType.ToString() -Status $service.Status.ToString() | Out-Null
        } catch { }

        try {
            if ($service.StartType.ToString() -ne 'Automatic') {
                Set-Service -Name $service.Name -StartupType Automatic -ErrorAction Stop
            }
            if ($service.Status -ne 'Running') {
                Start-Service -Name $service.Name -ErrorAction SilentlyContinue
            }

            $message = "[QoS] $($service.DisplayName) ensured on Automatic start."
            Write-Host "  [+] $message" -ForegroundColor Cyan
            if ($logger) { Write-Log $message }
        } catch {
            Invoke-ErrorHandler -Context "Configuring service $($service.Name)" -ErrorRecord $_
        }

        break
    }

    if (-not $qwaveConfigured) {
        Write-Host "  [!] qWave service not found; unable to set Automatic startup." -ForegroundColor Yellow
    }

    while ($true) {
        $ruleName = (Read-Host "Name of the rule (e.g., Fortnite, CS2):").Trim()
        if ([string]::IsNullOrWhiteSpace($ruleName)) {
            Write-Host "  [ ] No rule name provided. Exiting QoS manager." -ForegroundColor DarkGray
            break
        }

        if ($ruleName -match $invalidPattern) {
            Write-Host "  [!] Rule name contains invalid characters. Use letters, numbers, spaces, dots, dashes or underscores only." -ForegroundColor Yellow
            continue
        }
        if ($ruleName.Length -gt $maxRuleLength) {
            Write-Host "  [!] Rule name is too long ($($ruleName.Length) chars). Please shorten it below $maxRuleLength characters." -ForegroundColor Yellow
            continue
        }

        $executable = (Read-Host "Executable name (e.g., FortniteClient-Win64-Shipping.exe):").Trim()
        if ([string]::IsNullOrWhiteSpace($executable)) {
            Write-Host "  [ ] No executable provided. Exiting QoS manager." -ForegroundColor DarkGray
            break
        }
        if ($executable -match $invalidPattern -or $executable -match '[\\/]' ) {
            Write-Host "  [!] Executable name contains invalid characters or path separators. Provide only the file name (e.g., game.exe)." -ForegroundColor Yellow
            continue
        }
        if (-not ($executable -match '(?i)\.exe$')) {
            Write-Host "  [!] Executable does not end with .exe; QoS rules may not apply. Enter a valid executable file name." -ForegroundColor Yellow
            continue
        }
        if ($executable.Length -gt $maxExeLength) {
            Write-Host "  [!] Executable name is too long ($($executable.Length) chars). Please use a shorter name." -ForegroundColor Yellow
            continue
        }

        $exeFound = Test-ExecutableInPath -Name $executable
        if (-not $exeFound) {
            if (-not (Get-Confirmation "Executable '$executable' was not found in PATH. Continue anyway?" 'n')) {
                Write-Host "  [ ] QoS rule not created. Provide a resolvable executable name." -ForegroundColor DarkGray
                continue
            }
        }

        $rulePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\QoS\\$ruleName"
        $settings = @(
            @{ Name = 'Version'; Value = '1.0' },
            @{ Name = 'App Name'; Value = $executable },
            @{ Name = 'Protocol'; Value = '*' },
            @{ Name = 'Local Port'; Value = '*' },
            @{ Name = 'Local IP'; Value = '*' },
            @{ Name = 'Remote Port'; Value = '*' },
            @{ Name = 'Remote IP'; Value = '*' },
            @{ Name = 'DSCP Value'; Value = '46' }
        )

        $stringType = [Microsoft.Win32.RegistryValueKind]::String
        $results = foreach ($entry in $settings) {
            Set-RegistryValueSafe -Path $rulePath -Name $entry.Name -Value $entry.Value -Type $stringType -Context $Context -Critical -ReturnResult -OperationLabel "QoS rule '$ruleName' -> $($entry.Name)"
        }

        $failed = $results | Where-Object { -not ($_ -and $_.Success) }
        if (-not $failed) {
            Write-Host "  [+] QoS rule '$ruleName' for $executable created with DSCP 46." -ForegroundColor Magenta
            if ($logger) {
                Write-Log "[QoS] Rule '$ruleName' created for $executable (DSCP 46, wildcard endpoints)."
            }
        } else {
            foreach ($result in $failed) {
                Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $result.Operation | Out-Null
            }
            Write-Host "  [!] QoS rule '$ruleName' encountered errors. Check permissions or policy scope." -ForegroundColor Yellow
        }
    }
}

Export-ModuleMember -Function Optimize-GamingScheduler, Invoke-CustomGamingPowerSettings, Optimize-ProcessorScheduling, Set-UsbPowerManagementHardcore, Optimize-HidLatency, Disable-GameDVR, Set-FsoGlobalOverride, Disable-UdpSegmentOffload, Enable-TcpFastOpen, Disable-ArpNsOffload, Invoke-GamingOptimizations, Manage-GameQoS
