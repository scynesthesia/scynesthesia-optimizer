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

# Description: Applies advanced keyboard/mouse peripheral optimizations.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Applies registry tuning for accessibility, USB, and keyboard response.
function Invoke-KbmAdvancedOptimizations {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $needsReboot = $false

    Write-Section "Accessibility Clean (Sticky/Filter/Toggle Keys)"
    $accessibilityEntries = @(
        @{ Path = "HKCU:\\Control Panel\\Accessibility\\StickyKeys"; Name = 'Flags'; Value = 506; Label = 'Disable StickyKeys prompts' },
        @{ Path = "HKCU:\\Control Panel\\Accessibility\\FilterKeys"; Name = 'Flags'; Value = 122; Label = 'Disable FilterKeys prompts' },
        @{ Path = "HKCU:\\Control Panel\\Accessibility\\ToggleKeys"; Name = 'Flags'; Value = 58; Label = 'Disable ToggleKeys prompts' }
    )

    foreach ($entry in $accessibilityEntries) {
        $result = Set-RegistryValueSafe -Path $entry.Path -Name $entry.Name -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel $entry.Label
        if ($result -and $result.Success) {
            Write-Host "  [+] $($entry.Label)." -ForegroundColor Green
        } else {
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $entry.Label | Out-Null
        }
    }

    Write-Section "USB Controller MSI & Power"
    $msiRiskSummary = @(
        "Enabling MSI on USB controllers can briefly disconnect connected peripherals while Windows reinitializes the bus."
    )
    $applyMsi = Get-Confirmation -Question "Enable MSI mode for USB controllers? Peripherals may briefly disconnect." -Default 'n' -RiskSummary $msiRiskSummary

    $controllers = @()
    try {
        $controllers = Get-CimInstance -ClassName Win32_USBController -ErrorAction Stop
    } catch {
        Invoke-ErrorHandler -Context "Enumerating USB controllers" -ErrorRecord $_
    }

    if (-not $controllers -or $controllers.Count -eq 0) {
        Write-Host "  [!] No USB controllers found for MSI/power tuning." -ForegroundColor Yellow
    } else {
        foreach ($controller in $controllers) {
            $pnpId = $controller.PNPDeviceID
            if ([string]::IsNullOrWhiteSpace($pnpId)) {
                Write-Host "  [!] USB controller missing PNPDeviceID; skipping." -ForegroundColor Yellow
                continue
            }

            $enumPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\$pnpId"
            if (-not (Test-Path $enumPath)) {
                Write-Host "  [!] Registry path not found for $pnpId; skipping." -ForegroundColor Yellow
                continue
            }

            if ($applyMsi) {
                $msiPath = Join-Path $enumPath "Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties"
                $msiResult = Set-RegistryValueSafe -Path $msiPath -Name 'MSISupported' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Enable MSI for $($controller.Name)"
                if ($msiResult -and $msiResult.Success) {
                    Write-Host "  [+] MSI enabled for $($controller.Name)." -ForegroundColor Green
                    if ($logger) { Write-Log "[Gaming] MSI enabled for USB controller: $($controller.Name)." }
                    $needsReboot = $true
                } else {
                    Register-HighImpactRegistryFailure -Context $Context -Result $msiResult -OperationLabel "Enable MSI for $($controller.Name)" | Out-Null
                }
            } else {
                Write-Host "  [ ] MSI enable skipped for $($controller.Name)." -ForegroundColor DarkGray
            }

            $deviceParamsPath = Join-Path $enumPath "Device Parameters"
            foreach ($name in @(
                'AllowIdleIrpInD3',
                'D3ColdSupported',
                'DeviceSelectiveSuspended',
                'EnableSelectiveSuspend',
                'EnhancedPowerManagementEnabled'
            )) {
                $powerResult = Set-RegistryValueSafe -Path $deviceParamsPath -Name $name -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Disable USB power save ($name) for $($controller.Name)"
                if ($powerResult -and $powerResult.Success) {
                    Write-Host "  [+] $name disabled for $($controller.Name)." -ForegroundColor Green
                    $needsReboot = $true
                } else {
                    Register-HighImpactRegistryFailure -Context $Context -Result $powerResult -OperationLabel "Disable USB power save ($name) for $($controller.Name)" | Out-Null
                }
            }
        }
    }

    Write-Section "Kernel Poll Interval"
    $pollResult = Set-RegistryValueSafe -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel" -Name 'DebugPollInterval' -Value 1000 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Set DebugPollInterval to 1000'
    if ($pollResult -and $pollResult.Success) {
        Write-Host "  [+] Kernel DebugPollInterval set to 1000." -ForegroundColor Green
        $needsReboot = $true
    } else {
        Register-HighImpactRegistryFailure -Context $Context -Result $pollResult -OperationLabel 'Set DebugPollInterval to 1000' | Out-Null
    }

    Write-Section "Keyboard Response"
    $keyboardEntries = @(
        @{ Name = 'KeyboardDelay'; Value = '0'; Label = 'Set KeyboardDelay to 0' },
        @{ Name = 'KeyboardSpeed'; Value = '31'; Label = 'Set KeyboardSpeed to 31' }
    )
    foreach ($entry in $keyboardEntries) {
        $kbResult = Set-RegistryValueSafe -Path "HKCU:\\Control Panel\\Keyboard" -Name $entry.Name -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel $entry.Label
        if ($kbResult -and $kbResult.Success) {
            Write-Host "  [+] $($entry.Label)." -ForegroundColor Green
        } else {
            Register-HighImpactRegistryFailure -Context $Context -Result $kbResult -OperationLabel $entry.Label | Out-Null
        }
    }

    if ($needsReboot) {
        Set-RebootRequired -Context $Context | Out-Null
    }
}

# Description: Sets 1:1 mouse movement by disabling acceleration and setting standard curves.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Records registry rollback data for changes.
function Optimize-MouseOneToOne {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Mouse 1:1 Movement"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $mousePath = "HKCU:\\Control Panel\\Mouse"
    $mouseCurves = @{
        SmoothMouseXCurve = [byte[]]@(
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00
        )
        SmoothMouseYCurve = [byte[]]@(
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00
        )
    }

    if (Get-Confirmation "Movimiento de ratón 1 a 1 (Eliminar Aceleración)" 'y') {
        try {
            $results = @()
            $results += Set-RegistryValueSafe -Path $mousePath -Name 'MouseSpeed' -Value '0' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel 'Set MouseSpeed to 0'
            $results += Set-RegistryValueSafe -Path $mousePath -Name 'MouseThreshold1' -Value '0' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel 'Set MouseThreshold1 to 0'
            $results += Set-RegistryValueSafe -Path $mousePath -Name 'MouseThreshold2' -Value '0' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel 'Set MouseThreshold2 to 0'
            $results += Set-RegistryValueSafe -Path $mousePath -Name 'MouseSensitivity' -Value '10' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context -Critical -ReturnResult -OperationLabel 'Set MouseSensitivity to 10'

            foreach ($curve in $mouseCurves.GetEnumerator()) {
                $results += Set-RegistryValueSafe -Path $mousePath -Name $curve.Key -Value $curve.Value -Type ([Microsoft.Win32.RegistryValueKind]::Binary) -Context $Context -Critical -ReturnResult -OperationLabel "Set $($curve.Key) curve"
            }

            if ($results | Where-Object { -not $_ -or -not $_.Success }) {
                foreach ($result in $results) {
                    if (-not ($result -and $result.Success)) {
                        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Mouse 1:1 movement tweak' | Out-Null
                    }
                }
                return
            }

            Write-Host "  [+] Mouse acceleration disabled for 1:1 movement." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Mouse 1:1 movement applied (MouseSpeed/Thresholds=0, Sensitivity=10, flat curves)."
            }

            Set-RebootRequired -Context $Context | Out-Null
        } catch {
            Invoke-ErrorHandler -Context "Applying mouse 1:1 movement tweaks" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] Mouse movement left unchanged." -ForegroundColor DarkGray
    }
}

# Description: Flattens mouse acceleration curves for 1:1 tracking.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Records registry rollback data for changes.
function Optimize-MouseCurve {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Mouse Acceleration Curve (Flattening)"
    $mousePath = "HKCU:\\Control Panel\\Mouse"
    $hardwareProfile = Get-HardwareProfile
    if ($hardwareProfile -and $hardwareProfile.IsLaptop) {
        Write-Host "  [!] Laptop detected: this tweak is not recommended for touchpads. Continue only if using an external mouse." -ForegroundColor Cyan
    }

    if (-not (Get-Confirmation "Disable mouse smoothing by flattening acceleration curves?" 'y')) {
        Write-Host "  [ ] Mouse smoothing left unchanged." -ForegroundColor DarkGray
        return
    }

    try {
        $flatCurve = New-Object byte[] 40
        $results = @(
            Set-RegistryValueSafe -Path $mousePath -Name 'SmoothMouseXCurve' -Value $flatCurve -Type ([Microsoft.Win32.RegistryValueKind]::Binary) -Context $Context -Critical -ReturnResult -OperationLabel 'Flatten SmoothMouseXCurve'
            Set-RegistryValueSafe -Path $mousePath -Name 'SmoothMouseYCurve' -Value $flatCurve -Type ([Microsoft.Win32.RegistryValueKind]::Binary) -Context $Context -Critical -ReturnResult -OperationLabel 'Flatten SmoothMouseYCurve'
        )

        if ($results | Where-Object { -not $_ -or -not $_.Success }) {
            foreach ($result in $results) {
                if (-not ($result -and $result.Success)) {
                    Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Mouse acceleration curve flattening' | Out-Null
                }
            }
            return
        }

        Write-Host "  [+] Mouse acceleration curves flattened for 1:1 movement." -ForegroundColor Green
        Set-RebootRequired -Context $Context | Out-Null
    } catch {
        Invoke-ErrorHandler -Context "Applying mouse curve flattening" -ErrorRecord $_
    }
}

# Description: Elevates csrss.exe to realtime priority for extreme latency reduction.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Records registry rollback data for changes.
function Set-CsrssPriorityHardcore {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "CSRSS Realtime Priority"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $riskSummary = @(
        "Setting csrss.exe to Realtime priority can cause a system hang or freeze; use only if you accept hard-reset recovery risk."
    )

    if (Get-Confirmation -Question "Apply realtime priority overrides for csrss.exe?" -Default 'n' -RiskSummary $riskSummary) {
        try {
            $perfPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\csrss.exe\\PerfOptions"
            $cpuPriority = Set-RegistryValueSafe -Path $perfPath -Name 'CpuPriorityClass' -Value 4 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Set csrss.exe CpuPriorityClass to Realtime'
            $ioPriority = Set-RegistryValueSafe -Path $perfPath -Name 'IoPriority' -Value 3 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Set csrss.exe IoPriority to High'

            if (($cpuPriority -and $cpuPriority.Success) -and ($ioPriority -and $ioPriority.Success)) {
                Write-Host "  [+] csrss.exe priority overrides applied (Realtime/High IO)." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Gaming] csrss.exe PerfOptions set (CpuPriorityClass=4, IoPriority=3)."
                }

                Set-RebootRequired -Context $Context | Out-Null
            } else {
                foreach ($entry in @(
                    @{ Result = $cpuPriority; Label = 'Set csrss.exe CpuPriorityClass to Realtime' },
                    @{ Result = $ioPriority; Label = 'Set csrss.exe IoPriority to High' }
                )) {
                    if (-not ($entry.Result -and $entry.Result.Success)) {
                        Register-HighImpactRegistryFailure -Context $Context -Result $entry.Result -OperationLabel $entry.Label | Out-Null
                    }
                }
            }
        } catch {
            Invoke-ErrorHandler -Context "Setting csrss.exe realtime priority overrides" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] csrss.exe priority overrides skipped." -ForegroundColor DarkGray
    }
}

# Description: Forces latency tolerance values to minimums for power and graphics subsystems.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Records registry rollback data for changes.
function Set-LatencyToleranceHardcore {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Latency Tolerance (Sub-millisecond Precision)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $riskSummary = @(
        "Forces the graphics kernel and power subsystem to operate without power-saving latency margins, which can increase power draw and heat."
    )

    if (Get-Confirmation -Question "Force minimum latency tolerance values for power and graphics subsystems?" -Default 'n' -RiskSummary $riskSummary) {
        try {
            $results = @()

            $dxgKrnlPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DXGKrnl"
            foreach ($name in @(
                'MonitorLatencyTolerance',
                'MonitorLatencyToleranceMsec',
                'MonitorRefreshLatencyTolerance',
                'MonitorRefreshLatencyToleranceMsec',
                'MonitorLatencyTolerancePerfOverride'
            )) {
                $results += Set-RegistryValueSafe -Path $dxgKrnlPath -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set DXGKrnl $name to 1"
            }

            $powerPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power"
            foreach ($name in @(
                'ExitLatency',
                'ExitLatencyCheckEnabled',
                'ExitLatencyControl',
                'ExitLatencyTolerance',
                'IdleDuration',
                'IdleTimeout',
                'LatencyTolerance',
                'LatencyToleranceDefault',
                'LatencyToleranceFallback',
                'LatencyTolerancePerfOverride',
                'LatencyToleranceVSyncEnabled',
                'RtlLatencyTolerance'
            )) {
                $results += Set-RegistryValueSafe -Path $powerPath -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set Power $name to 1"
            }

            $graphicsPowerPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Power"
            foreach ($name in @(
                'DefaultD3TransitionLatencyActivelyUsed',
                'DefaultD3TransitionLatencyIdle',
                'DefaultD3TransitionLatencyInCoolingMode',
                'DefaultD3TransitionLatencyOnD3Cold',
                'DefaultD3TransitionLatencyOnD3Hot'
            )) {
                $results += Set-RegistryValueSafe -Path $graphicsPowerPath -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set GraphicsDrivers Power $name to 1"
            }

            if ($results | Where-Object { -not ($_ -and $_.Success) }) {
                foreach ($result in $results) {
                    if (-not ($result -and $result.Success)) {
                        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $result.Operation | Out-Null
                    }
                }
                return
            }

            Write-Host "  [+] Latency tolerance registry overrides applied." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Latency tolerance values forced to 1 for DXGKrnl/Power/GraphicsDrivers."
            }

            Set-RebootRequired -Context $Context | Out-Null
        } catch {
            Invoke-ErrorHandler -Context "Applying latency tolerance registry overrides" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] Latency tolerance overrides skipped." -ForegroundColor DarkGray
    }
}

# Description: Applies NVIDIA driver registry tweaks for latency tolerance and contiguous memory usage.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Records registry rollback data for changes.
function Set-NvidiaLatencyTweaks {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "NVIDIA Latency Tolerance (Driver)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $riskSummary = @(
        "Targets NVIDIA GPU driver registry entries only; changes remove power-saving latency tolerance safeguards and can increase power draw and heat."
    )

    if (-not (Get-Confirmation -Question "Apply NVIDIA driver latency tolerance and contiguous memory tweaks?" -Default 'n' -RiskSummary $riskSummary)) {
        Write-Host "  [ ] NVIDIA latency tweaks skipped." -ForegroundColor DarkGray
        return
    }

    $classPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"
    $nvidiaPaths = @()

    try {
        $classKeys = Get-ChildItem -Path $classPath -ErrorAction Stop
    } catch {
        Invoke-ErrorHandler -Context "Discovering NVIDIA GPU registry keys" -ErrorRecord $_
        return
    }

    foreach ($key in $classKeys) {
        try {
            $provider = (Get-ItemProperty -Path $key.PSPath -Name 'ProviderName' -ErrorAction Stop).ProviderName
            if ($provider -match '(?i)nvidia') {
                $nvidiaPaths += $key.PSPath
            }
        } catch {
            Invoke-ErrorHandler -Context "Reading ProviderName for $($key.PSChildName)" -ErrorRecord $_
        }
    }

    if ($nvidiaPaths.Count -eq 0) {
        Write-Host "  [!] No NVIDIA GPU registry keys found for latency tweaks." -ForegroundColor Yellow
        return
    }

    $results = @()
    $appliedAny = $false

    foreach ($path in $nvidiaPaths) {
        try {
            $registryKey = Get-Item -Path $path -ErrorAction Stop
            $latencyNames = $registryKey.GetValueNames() | Where-Object { $_ -match '^NVIDIA Latency Tolerance' }

            foreach ($name in $latencyNames) {
                $results += Set-RegistryValueSafe -Path $path -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set $name to 1"
            }

            $results += Set-RegistryValueSafe -Path $path -Name 'PreferSystemMemoryContiguous' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Set PreferSystemMemoryContiguous to 1'
            $results += Set-RegistryValueSafe -Path $path -Name 'PciLatencyTimerControl' -Value 32 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Set PciLatencyTimerControl to 32'

            if ($logger) {
                Write-Log "[Gaming] NVIDIA registry tweaks applied at $path (LatencyTolerance, PreferSystemMemoryContiguous, PciLatencyTimerControl=32)."
            }
        } catch {
            Invoke-ErrorHandler -Context "Applying NVIDIA latency tweaks at $path" -ErrorRecord $_
        }
    }

    foreach ($result in $results) {
        if ($result -and $result.Success) {
            $appliedAny = $true
        } else {
            $label = if ($result -and $result.Operation) { $result.Operation } else { 'NVIDIA driver registry tweak' }
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $label | Out-Null
        }
    }

    if ($appliedAny) {
        Write-Host "  [+] NVIDIA latency tolerance tweaks applied." -ForegroundColor Green
        Set-RebootRequired -Context $Context | Out-Null
    }
}

# Description: Applies advanced NVIDIA Resource Manager and renderer internal tweaks.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Records registry rollback data for changes.
function Invoke-NvidiaAdvancedInternalTweaks {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "NVIDIA Advanced Internal Tweaks (RM/Renderer)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $riskSummary = @(
        "Disables driver safety validations (Blit sub-rect validation) and internal event tracking to shave milliseconds.",
        "These changes can reduce diagnostics/guardrails and may affect stability if the driver hits unexpected states."
    )

    if (-not (Get-Confirmation -Question "Apply NVIDIA Resource Manager and renderer internal tweaks?" -Default 'n' -RiskSummary $riskSummary)) {
        Write-Host "  [ ] NVIDIA internal tweaks skipped." -ForegroundColor DarkGray
        return
    }

    $classPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"
    $nvidiaPaths = @()

    try {
        $classKeys = Get-ChildItem -Path $classPath -ErrorAction Stop
    } catch {
        Invoke-ErrorHandler -Context "Discovering NVIDIA GPU registry keys (advanced internal tweaks)" -ErrorRecord $_
        return
    }

    foreach ($key in $classKeys) {
        try {
            $provider = (Get-ItemProperty -Path $key.PSPath -Name 'ProviderName' -ErrorAction Stop).ProviderName
            if ($provider -eq 'NVIDIA') {
                $nvidiaPaths += $key.PSPath
            }
        } catch {
            Invoke-ErrorHandler -Context "Reading ProviderName for $($key.PSChildName) (advanced internal tweaks)" -ErrorRecord $_
        }
    }

    if ($nvidiaPaths.Count -eq 0) {
        Write-Host "  [!] No NVIDIA GPU registry keys found for advanced internal tweaks." -ForegroundColor Yellow
        return
    }

    $results = @()
    $appliedAny = $false

    foreach ($path in $nvidiaPaths) {
        try {
            # RM: disables engine reset tracking to reduce bookkeeping latency.
            $results += Set-RegistryValueSafe -Path $path -Name 'TrackResetEngine' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set TrackResetEngine=0 at $path"
            # RM: disables blit sub-rect validation checks to reduce render validation overhead.
            $results += Set-RegistryValueSafe -Path $path -Name 'ValidateBlitSubRects' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set ValidateBlitSubRects=0 at $path"
            # RM: prioritize VRAM caching over system memory for faster resource residency.
            $results += Set-RegistryValueSafe -Path $path -Name 'RmCacheLoc' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set RmCacheLoc=0 at $path"
            # RM: enable paged DMA in FBSR to optimize memory transfers.
            $results += Set-RegistryValueSafe -Path $path -Name 'RmFbsrPagedDMA' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set RmFbsrPagedDMA=1 at $path"
            # RM: lower acceleration level to reduce driver overhead in internal scheduling.
            $results += Set-RegistryValueSafe -Path $path -Name 'Acceleration.Level' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set Acceleration.Level=0 at $path"
            # RM: disable kernel filter support flag to streamline device filtering paths.
            $results += Set-RegistryValueSafe -Path $path -Name 'NVDeviceSupportKFilter' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set NVDeviceSupportKFilter=0 at $path"
            # RM: remove desktop stereo shortcuts to reduce UI bloat.
            $results += Set-RegistryValueSafe -Path $path -Name 'DesktopStereoShortcuts' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set DesktopStereoShortcuts=0 at $path"
            # RM: set feature control level to reduce extra driver UI components.
            $results += Set-RegistryValueSafe -Path $path -Name 'FeatureControl' -Value 4 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set FeatureControl=4 at $path"
            # RM: allow profiling without admin requirement to enable telemetry access.
            $results += Set-RegistryValueSafe -Path $path -Name 'RmProfilingAdminOnly' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set RmProfilingAdminOnly=0 at $path"

            if ($logger) {
                Write-Log "[Gaming] NVIDIA advanced internal tweaks applied at $path (RM/Renderer settings)."
            }
        } catch {
            Invoke-ErrorHandler -Context "Applying NVIDIA advanced internal tweaks at $path" -ErrorRecord $_
        }
    }

    foreach ($result in $results) {
        if ($result -and $result.Success) {
            $appliedAny = $true
        } else {
            $label = if ($result -and $result.Operation) { $result.Operation } else { 'NVIDIA advanced internal tweak' }
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $label | Out-Null
        }
    }

    if ($appliedAny) {
        Write-Host "  [+] NVIDIA advanced internal tweaks applied." -ForegroundColor Green
        Set-RebootRequired -Context $Context | Out-Null
    }
}

# Description: Applies deep NVIDIA driver optimizations for latency, telemetry, and power savings removal.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Records registry rollback data and disables scheduled tasks.
function Invoke-NvidiaHardcoreTweaks {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "NVIDIA Hardcore Tweaks (HDCP/TCC/Telemetry/Power)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $riskSummary = @(
        "Disables HDCP in the NVIDIA driver, which will break DRM playback (Netflix, Prime Video, Disney+, etc.).",
        "Disables write combining in nvlddmkm (experimental) and may negatively impact stability or performance.",
        "Disables NVIDIA display power saving, telemetry, and driver power-saving controls which may increase power draw and heat."
    )

    if (-not (Get-Confirmation -Question "Apply NVIDIA hardcore driver tweaks?" -Default 'n' -RiskSummary $riskSummary)) {
        Write-Host "  [ ] NVIDIA hardcore tweaks skipped." -ForegroundColor DarkGray
        return
    }

    $classPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"
    $nvidiaPaths = @()

    try {
        $classKeys = Get-ChildItem -Path $classPath -ErrorAction Stop
    } catch {
        Invoke-ErrorHandler -Context "Discovering NVIDIA GPU registry keys" -ErrorRecord $_
        return
    }

    foreach ($key in $classKeys) {
        try {
            $provider = (Get-ItemProperty -Path $key.PSPath -Name 'ProviderName' -ErrorAction Stop).ProviderName
            if ($provider -eq 'NVIDIA') {
                $nvidiaPaths += $key.PSPath
            }
        } catch {
            Invoke-ErrorHandler -Context "Reading ProviderName for $($key.PSChildName)" -ErrorRecord $_
        }
    }

    if ($nvidiaPaths.Count -eq 0) {
        Write-Host "  [!] No NVIDIA GPU registry keys found for hardcore tweaks." -ForegroundColor Yellow
        return
    }

    $results = @()
    $appliedAny = $false

    foreach ($path in $nvidiaPaths) {
        try {
            $results += Set-RegistryValueSafe -Path $path -Name 'RMHdcpKeyGlobZero' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Disable HDCP at $($path)"
            $results += Set-RegistryValueSafe -Path $path -Name 'TCCSupported' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Disable TCC at $($path)"

            if ($logger) {
                Write-Log "[Gaming] NVIDIA hardcore tweaks applied at $path (RMHdcpKeyGlobZero=1, TCCSupported=0)."
            }
        } catch {
            Invoke-ErrorHandler -Context "Applying NVIDIA hardcore tweaks at $path" -ErrorRecord $_
        }
    }

    $servicePath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm"
    $nvTweakPath = "$servicePath\\Global\\NVTweak"
    $graphicsDriversPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers"
    $graphicsPowerPath = "$graphicsDriversPath\\Power"
    $telemetryPath = "HKLM:\\SOFTWARE\\NVIDIA Corporation\\NvControlPanel2\\Client"

    try {
        $results += Set-RegistryValueSafe -Path $servicePath -Name 'DisableWriteCombining' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable nvlddmkm write combining'
        $results += Set-RegistryValueSafe -Path $servicePath -Name 'RmGpsPsEnablePerCpuCoreDpc' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Enable nvlddmkm per-core DPC'
        $results += Set-RegistryValueSafe -Path $nvTweakPath -Name 'DisplayPowerSaving' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable NVIDIA display power saving'
        $results += Set-RegistryValueSafe -Path $graphicsDriversPath -Name 'RmGpsPsEnablePerCpuCoreDpc' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Enable GraphicsDrivers per-core DPC'
        $results += Set-RegistryValueSafe -Path $graphicsPowerPath -Name 'RmGpsPsEnablePerCpuCoreDpc' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Enable GraphicsDrivers Power per-core DPC'
        $results += Set-RegistryValueSafe -Path $telemetryPath -Name 'OptInOrOutPreference' -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable NVIDIA Control Panel telemetry'
    } catch {
        Invoke-ErrorHandler -Context "Applying NVIDIA service and telemetry registry tweaks" -ErrorRecord $_
    }

    $taskPrefixes = @('NvTmRep', 'NvTmMon', 'NvDriverUpdateCheck')
    $taskMatches = @()

    try {
        $taskMatches = Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $taskName = $_.TaskName
            $taskPrefixes | Where-Object { $taskName.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }
        }
    } catch {
        Invoke-ErrorHandler -Context "Enumerating NVIDIA scheduled tasks" -ErrorRecord $_
    }

    if ($taskMatches.Count -gt 0) {
        foreach ($task in $taskMatches) {
            $fullName = "{0}{1}" -f $task.TaskPath, $task.TaskName
            try {
                & schtasks.exe /change /disable /tn $fullName | Out-Null
                Write-Host "  [+] NVIDIA scheduled task disabled: $fullName" -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Gaming] NVIDIA scheduled task disabled: $fullName"
                }
            } catch {
                Invoke-ErrorHandler -Context "Disabling NVIDIA scheduled task $fullName" -ErrorRecord $_
            }
        }
    } else {
        Write-Host "  [ ] No NVIDIA scheduled tasks matching NvTmRep/NvTmMon/NvDriverUpdateCheck were found." -ForegroundColor DarkGray
    }

    foreach ($result in $results) {
        if ($result -and $result.Success) {
            $appliedAny = $true
        } else {
            $label = if ($result -and $result.Operation) { $result.Operation } else { 'NVIDIA hardcore tweak' }
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $label | Out-Null
        }
    }

    if ($appliedAny) {
        Write-Host "  [+] NVIDIA hardcore tweaks applied." -ForegroundColor Green
        Set-RebootRequired -Context $Context | Out-Null
    }
}

# Description: Disables NVIDIA dynamic P-States and Windows TDR for maximum GPU stability.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Records registry rollback data for changes.
function Invoke-VideoStabilityHardcore {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "GPU Power & Stability (Extreme Tweaks)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $riskSummary = @(
        "Disables NVIDIA dynamic P-States, which forces the GPU to stay in higher power states and increases heat/power draw.",
        "Disables Windows TDR recovery. If the GPU driver hangs, the system will freeze completely and require a hard reboot."
    )

    if (-not (Get-Confirmation -Question "Disable NVIDIA dynamic P-States and Windows TDR recovery?" -Default 'n' -RiskSummary $riskSummary)) {
        Write-Host "  [ ] GPU stability tweaks skipped." -ForegroundColor DarkGray
        return
    }

    $results = @()
    $appliedAny = $false

    $classPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}"
    $nvidiaPaths = @()

    try {
        $classKeys = Get-ChildItem -Path $classPath -ErrorAction Stop
    } catch {
        Invoke-ErrorHandler -Context "Discovering NVIDIA GPU registry keys (dynamic P-States)" -ErrorRecord $_
        return
    }

    foreach ($key in $classKeys) {
        try {
            $provider = (Get-ItemProperty -Path $key.PSPath -Name 'ProviderName' -ErrorAction Stop).ProviderName
            if ($provider -eq 'NVIDIA') {
                $nvidiaPaths += $key.PSPath
            }
        } catch {
            Invoke-ErrorHandler -Context "Reading ProviderName for $($key.PSChildName) (dynamic P-States)" -ErrorRecord $_
        }
    }

    if ($nvidiaPaths.Count -eq 0) {
        Write-Host "  [!] No NVIDIA GPU registry keys found for DisableDynamicPstate." -ForegroundColor Yellow
    } else {
        foreach ($path in $nvidiaPaths) {
            try {
                $results += Set-RegistryValueSafe -Path $path -Name 'DisableDynamicPstate' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "DisableDynamicPstate=1 at $path"
                if ($logger) {
                    Write-Log "[Gaming] NVIDIA DisableDynamicPstate set to 1 at $path."
                }
            } catch {
                Invoke-ErrorHandler -Context "Setting DisableDynamicPstate at $path" -ErrorRecord $_
            }
        }
    }

    $graphicsDriversPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers"
    foreach ($name in @('TdrLevel', 'TdrDelay', 'TdrDdiDelay', 'TdrLimitCount', 'TdrLimitTime')) {
        try {
            $results += Set-RegistryValueSafe -Path $graphicsDriversPath -Name $name -Value 0 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel "Set $name to 0"
        } catch {
            Invoke-ErrorHandler -Context "Setting GraphicsDrivers $name to 0" -ErrorRecord $_
        }
    }

    foreach ($result in $results) {
        if ($result -and $result.Success) {
            $appliedAny = $true
        } else {
            $label = if ($result -and $result.Operation) { $result.Operation } else { 'GPU stability registry tweak' }
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $label | Out-Null
        }
    }

    if ($appliedAny) {
        Write-Host "  [+] GPU stability overrides applied (DisableDynamicPstate + TDR off)." -ForegroundColor Green
        if ($logger) {
            Write-Log "[Gaming] GPU stability tweaks applied (DisableDynamicPstate=1, TDR=0)."
        }
        Set-RebootRequired -Context $Context | Out-Null
    }
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

# Description: Ensures Windows Game Mode auto-priority is enabled for scheduler improvements.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Records registry rollback data for the change.
function Enable-WindowsGameMode {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Windows Game Mode (Kernel Priority Enhancement)"
    Write-Host "Game Mode helps Windows prioritize game threads and quiet background processes for smoother scheduling." -ForegroundColor DarkGray

    $gameBarPath = "HKCU:\\Software\\Microsoft\\GameBar"
    $result = Set-RegistryValueSafe -Path $gameBarPath -Name 'AllowAutoGameMode' -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Enable Windows Game Mode'

    if ($result -and $result.Success) {
        Write-Host "  [+] Windows Game Mode auto-priority enabled." -ForegroundColor Green
    } else {
        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Enable Windows Game Mode' | Out-Null
    }
}

# Description: Applies kernel-level timers and security mitigation overrides for gaming.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Records BCD and registry changes and flags reboot requirement.
function Invoke-KernelSecurityTweaks {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Kernel & Security (Gaming Hardcore)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $riskSummary = @(
        'ESTÁS DESACTIVANDO LA SEGURIDAD DEL KERNEL (Spectre/Meltdown/ASLR). El sistema será vulnerable pero ganará máxima latencia.'
    )

    if (-not (Get-Confirmation -Question "Apply kernel & security hardcore tweaks for gaming?" -Default 'n' -RiskSummary $riskSummary)) {
        Write-Host "  [ ] Kernel & security tweaks skipped." -ForegroundColor DarkGray
        return
    }

    $null = Get-NonRegistryChangeTracker -Context $Context
    if (-not $Context.NonRegistryChanges.ContainsKey('BcdEdit')) {
        $Context.NonRegistryChanges['BcdEdit'] = @{}
    }

    function Get-BcdSettingValue {
        param([string]$Setting)
        try {
            $output = & bcdedit /enum {current} 2>$null
            if (-not $output) { return $null }
            foreach ($line in $output) {
                if ($line -match "^\s*${Setting}\s+(.+)$") {
                    return $Matches[1].Trim()
                }
            }
        } catch {
            return $null
        }
        return $null
    }

    Write-Host "  [i] Applying BCD timer optimizations..." -ForegroundColor DarkGray
    foreach ($entry in @(
        @{ Name = 'useplatformclock'; Value = 'No' },
        @{ Name = 'useplatformtick'; Value = 'No' },
        @{ Name = 'disabledynamictick'; Value = 'Yes' }
    )) {
        if (-not $Context.NonRegistryChanges.BcdEdit.ContainsKey($entry.Name)) {
            $Context.NonRegistryChanges.BcdEdit[$entry.Name] = @{
                Previous = Get-BcdSettingValue -Setting $entry.Name
                New = $entry.Value
            }
        }

        try {
            & bcdedit /set $entry.Name $entry.Value | Out-Null
            Write-Host "  [+] BCD $($entry.Name) set to $($entry.Value)." -ForegroundColor Green
            if ($logger) { Write-Log "[Gaming] BCD $($entry.Name) set to $($entry.Value)." }
        } catch {
            Invoke-ErrorHandler -Context "Setting BCD $($entry.Name)" -ErrorRecord $_
        }
    }

    Write-Host "  [i] Disabling memory compression and page combining..." -ForegroundColor DarkGray
    try {
        Disable-MMAgent -MemoryCompression -PageCombining -ErrorAction Stop
        Write-Host "  [+] MMAgent memory compression/page combining disabled." -ForegroundColor Green
        if ($logger) { Write-Log "[Gaming] MMAgent memory compression/page combining disabled." }
    } catch {
        Invoke-ErrorHandler -Context "Disabling MMAgent memory compression/page combining" -ErrorRecord $_
    }

    $registryEntries = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = 'FeatureSettingsOverride'; Value = 3; Label = 'Disable Spectre/Meltdown mitigations (override)' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = 'FeatureSettingsOverrideMask'; Value = 3; Label = 'Disable Spectre/Meltdown mitigations (mask)' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = 'EnableVirtualizationBasedSecurity'; Value = 0; Label = 'Disable VBS' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name = 'Enabled'; Value = 0; Label = 'Disable HVCI' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = 'DisableExecProtection'; Value = 1; Label = 'Disable DEP' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = 'MoveImages'; Value = 0; Label = 'Disable ASLR (MoveImages)' },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\FTH"; Name = 'Enabled'; Value = 0; Label = 'Disable Fault Tolerant Heap' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = 'DisablePagingExecutive'; Value = 1; Label = 'Disable paging executive' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = 'LargeSystemCache'; Value = 1; Label = 'Enable large system cache' },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"; Name = 'MaintenanceDisabled'; Value = 1; Label = 'Disable maintenance scheduling' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Name = 'CoalescingTimerInterval'; Value = 0; Label = 'Disable timer coalescing (Kernel)' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; Name = 'CoalescingTimerInterval'; Value = 0; Label = 'Disable timer coalescing (Power)' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"; Name = 'PowerThrottlingOff'; Value = 1; Label = 'Disable power throttling' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name = 'HwSchMode'; Value = 2; Label = 'Enable HAGS' },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Name = 'DistributeTimers'; Value = 1; Label = 'Enable DistributeTimers' }
    )

    foreach ($entry in $registryEntries) {
        $result = Set-RegistryValueSafe -Path $entry.Path -Name $entry.Name -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel $entry.Label
        if ($result -and $result.Success) {
            Write-Host "  [+] $($entry.Label)." -ForegroundColor Green
            if ($logger) { Write-Log "[Gaming] $($entry.Label)." }
        } else {
            Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel $entry.Label | Out-Null
        }
    }

    Write-Host "  [i] Applying NTFS memory usage tweaks..." -ForegroundColor DarkGray
    try {
        fsutil behavior set memoryusage 2 | Out-Null
        fsutil behavior set mftzone 4 | Out-Null
        Write-Host "  [+] NTFS memory usage and MFT zone set." -ForegroundColor Green
        if ($logger) { Write-Log "[Gaming] NTFS memoryusage=2 and mftzone=4 applied." }
    } catch {
        Invoke-ErrorHandler -Context "Applying NTFS performance tweaks" -ErrorRecord $_
    }

    Set-RebootRequired -Context $Context | Out-Null
}

# Description: Runs the complete Gaming preset sequence following modular standards.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Sequentially applies gaming optimizations and reports completion.
function Invoke-GamingOptimizations {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Invoke-KernelSecurityTweaks -Context $Context
    Invoke-GamingServiceOptimization -Context $Context
    Optimize-GamingScheduler -Context $Context
    Enable-WindowsGameMode -Context $Context
    Invoke-CustomGamingPowerSettings -Context $Context
    Optimize-ProcessorScheduling -Context $Context
    Set-UsbPowerManagementHardcore -Context $Context
    Optimize-HidLatency -Context $Context
    Optimize-MouseCurve -Context $Context
    Invoke-KbmAdvancedOptimizations -Context $Context
    Set-CsrssPriorityHardcore -Context $Context
    Set-LatencyToleranceHardcore -Context $Context
    Set-NvidiaLatencyTweaks -Context $Context
    Invoke-NvidiaAdvancedInternalTweaks -Context $Context
    Invoke-NvidiaHardcoreTweaks -Context $Context
    Invoke-DriverTelemetry
    Set-FsoGlobalOverride -Context $Context
    Invoke-VideoStabilityHardcore -Context $Context

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

Export-ModuleMember -Function Optimize-GamingScheduler, Invoke-CustomGamingPowerSettings, Optimize-ProcessorScheduling, Set-UsbPowerManagementHardcore, Optimize-HidLatency, Optimize-MouseCurve, Invoke-KbmAdvancedOptimizations, Set-CsrssPriorityHardcore, Set-LatencyToleranceHardcore, Set-NvidiaLatencyTweaks, Invoke-NvidiaAdvancedInternalTweaks, Invoke-NvidiaHardcoreTweaks, Invoke-VideoStabilityHardcore, Disable-GameDVR, Set-FsoGlobalOverride, Disable-UdpSegmentOffload, Enable-TcpFastOpen, Disable-ArpNsOffload, Enable-WindowsGameMode, Invoke-KernelSecurityTweaks, Invoke-GamingOptimizations, Manage-GameQoS
