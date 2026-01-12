function Get-HardwareProfile {
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $battery = $null
    try {
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop
    } catch {
        $warning = "[Performance] Battery information unavailable: $($_.Exception.Message). Assuming desktop."
        Write-Warning $warning
        if ($logger) { Write-Log -Message $warning -Level 'Warning' }
    }

    $onBatteryPower = $false
    if ($battery) {
        $batterySample = @($battery) | Select-Object -First 1
        try {
            $status = $batterySample.BatteryStatus
            if ($null -ne $status) {
                $statusCode = [int]$status
                $onBatteryPower = @(1, 4, 5, 11) -contains $statusCode
            }
        } catch { }
    }

    $system = $null
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    } catch {
        $warning = "[Performance] System information unavailable: $($_.Exception.Message). Memory size will be treated as 0 GB."
        Write-Warning $warning
        if ($logger) { Write-Log -Message $warning -Level 'Warning' }
    }

    $memoryBytes = if ($system) { $system.TotalPhysicalMemory } else { $null }
    $memoryGB = if ($memoryBytes) { [math]::Round($memoryBytes / 1GB, 1) } else { 0 }

    $disks = @()
    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
    } catch {
        $warning = "[Performance] Storage information unavailable: $($_.Exception.Message). Disk type assumptions may be inaccurate."
        Write-Warning $warning
        if ($logger) { Write-Log -Message $warning -Level 'Warning' }
        $disks = @()
    }
    $hasDiskData = $disks -ne $null -and $disks.Count -gt 0
    $hasSSD = $false
    $hasHDD = $false
    foreach ($disk in ($disks | Where-Object { $_ })) {
        $unknownMedia = $disk.MediaType -eq 'Unknown' -or $disk.MediaType -eq 'Unspecified' -or -not $disk.MediaType
        $unknownBus = $disk.BusType -eq 'Unknown' -or -not $disk.BusType

        if ($unknownMedia -or $unknownBus) {
            $hasSSD = $true
            continue
        }

        switch ($disk.MediaType) {
            'SSD' { $hasSSD = $true }
            'HDD' { $hasHDD = $true }
            default {
                if ($disk.RotationRate -gt 0) { $hasHDD = $true }
            }
        }
    }

    [pscustomobject]@{
        IsLaptop       = $battery -ne $null
        OnBatteryPower = $onBatteryPower
        TotalMemoryGB  = $memoryGB
        MemoryCategory = if ($memoryGB -lt 6) { 'Low' } else { 'Normal' }
        HasSSD         = $hasSSD
        HasHDD         = if ($hasDiskData) { $hasHDD } else { $false }
    }
}

function Get-OEMServiceInfo {
    $patterns = 'Dell','Alienware','HP','Hewlett','Lenovo','Acer','ASUS','MSI','Samsung','Razer'
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $displayName = $_.DisplayName
        $serviceName = $_.ServiceName
        foreach ($pattern in $patterns) {
            $escaped = [regex]::Escape($pattern)
            if ($displayName -match $escaped -or $serviceName -match $escaped) { return $true }
        }
        return $false
    }
    $services
}

function Invoke-SysMainOptimization {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    Write-Section "SysMain (Superfetch)"
    $hasHdd = [bool]$HardwareProfile.HasHDD
    $hint = if ($hasHdd) { 'Mechanical disk detected: keeping SysMain enabled is recommended to improve launch times.' } else { 'SSD-only system detected: you can disable SysMain to reduce unnecessary writes.' }
    Write-Host $hint -ForegroundColor Gray

    $defaultChoice = if ($hasHdd) { 'n' } else { 'y' }
    if (Get-Confirmation "Disable SysMain to prioritize resources?" $defaultChoice) {
        try {
            Stop-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Host "  [OK] SysMain disabled"
        } catch {
            Invoke-ErrorHandler -Context "Disabling SysMain service" -ErrorRecord $_
        }
    } elseif ($hasHdd) {
        try {
            Set-Service -Name "SysMain" -StartupType Automatic
            Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Write-Host "  [OK] SysMain ensured running for HDD optimization"
        } catch {
            Invoke-ErrorHandler -Context "Enabling SysMain service" -ErrorRecord $_
        }
    } elseif (Get-Confirmation "Ensure SysMain is enabled and Automatic?" 'y') {
        try {
            Set-Service -Name "SysMain" -StartupType Automatic
            Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Write-Host "  [OK] SysMain enabled"
        } catch {
            Invoke-ErrorHandler -Context "Enabling SysMain service" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] SysMain left unchanged."
    }
}

function Invoke-PerformanceBaseline {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile,
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    Write-Section "Baseline performance adjustments"
    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }

    $prefetchPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    $prefetchValue = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 1 } else { 3 }
    $prefetcherResult = Set-RegistryValueSafe $prefetchPath "EnablePrefetcher" $prefetchValue -Context $Context -Critical -ReturnResult -OperationLabel 'Configure prefetcher policy'
    $superfetchResult = Set-RegistryValueSafe $prefetchPath "EnableSuperfetch" $prefetchValue -Context $Context -Critical -ReturnResult -OperationLabel 'Configure superfetch policy'
    $prefetchSuccess = $prefetcherResult -and $prefetcherResult.Success
    $superfetchSuccess = $superfetchResult -and $superfetchResult.Success
    if ($prefetchSuccess -or $superfetchSuccess) {
        Set-RebootRequired -Context $Context | Out-Null
    }
    if (-not $prefetchSuccess) {
        Register-HighImpactRegistryFailure -Context $Context -Result $prefetcherResult -OperationLabel 'Configure prefetcher policy' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $prefetcherResult -PresetName $presetLabel -OperationLabel 'Configure prefetcher policy' -Critical) { return $true }
    }
    if (-not $superfetchSuccess) {
        Register-HighImpactRegistryFailure -Context $Context -Result $superfetchResult -OperationLabel 'Configure superfetch policy' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $superfetchResult -PresetName $presetLabel -OperationLabel 'Configure superfetch policy' -Critical) { return $true }
    }

    if ($HardwareProfile.MemoryCategory -eq 'Low') {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2 -Context $Context
        Write-Host "  [OK] Animations/effects tuned for performance (RAM <6GB)."
    } else {
        Write-Host "  [ ] Animations left as-is (RAM >=6GB)."
    }

    Invoke-UltimatePerformancePlan
    return $false
}

function Get-UltimatePerformancePlanGuid {
    $ultimateTemplateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"

    try {
        $powerPlans = powercfg -list 2>$null
        if ($powerPlans | Select-String -Pattern $ultimateTemplateGuid -SimpleMatch) {
            Write-Host "  [OK] Ultimate Performance plan already available."
            return $ultimateTemplateGuid
        }

        $existingUltimatePlanGuid = $null
        foreach ($planLine in $powerPlans) {
            $normalizedLine = $planLine.ToLowerInvariant()
            if ($normalizedLine -match 'power scheme guid:\s*([a-f0-9-]{36}).*ultimate performance') {
                $existingUltimatePlanGuid = $matches[1]
                break
            }
        }

        if ($existingUltimatePlanGuid) {
            Write-Host "  [OK] Ultimate Performance plan already available."
            return $existingUltimatePlanGuid
        }
    } catch {
        Write-Warning "  [!] Could not inspect power plans: $($_.Exception.Message)"
    }

    try {
        $duplicateOutput = powercfg -duplicatescheme $ultimateTemplateGuid 2>$null
        $duplicatedGuid = ($duplicateOutput | Select-String -Pattern '[A-Fa-f0-9-]{36}' -AllMatches | Select-Object -First 1).Matches.Value
        if (-not [string]::IsNullOrWhiteSpace($duplicatedGuid)) {
            Write-Host "  [OK] Ultimate Performance plan created."
            return $duplicatedGuid
        }
    } catch {
        Write-Warning "  [!] Failed to create Ultimate Performance power plan: $($_.Exception.Message)"
        return $null
    }

    Write-Warning "  [!] Could not determine Ultimate Performance power plan GUID."
    return $null
}

function Invoke-UltimatePerformancePlan {
    Write-Section "Enabling Ultimate Performance power plan"
    $guid = Get-UltimatePerformancePlanGuid
    if ([string]::IsNullOrWhiteSpace($guid)) {
        Write-Warning "  [!] Ultimate Performance plan not available; switching to High performance instead."
        try {
            powercfg -setactive SCHEME_MAX 2>$null
            Write-Host "  [OK] High performance plan activated as fallback." -ForegroundColor Gray
        } catch {
            Invoke-ErrorHandler -Context "Activating High performance fallback plan" -ErrorRecord $_
        }
        return
    }
    try {
        powercfg -setactive $guid
        Write-Host "  [OK] Ultimate Performance active."
    } catch {
        Invoke-ErrorHandler -Context "Activating Ultimate Performance power plan" -ErrorRecord $_
    }
}

function Set-RegistryPerformanceValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Type,
        [Parameter(Mandatory)][string]$ContextDescription,
        [Parameter(Mandatory)][string]$SuccessMessage,
        [Parameter(Mandatory)][pscustomobject]$RunContext
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log -Message "Created registry key $Path" -Level 'Info'
        }

        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Log -Message $SuccessMessage -Level 'Info'
        Set-RebootRequired -Context $RunContext | Out-Null
    } catch {
        Invoke-ErrorHandler -Context $ContextDescription -ErrorRecord $_
    }
}

function Invoke-NtfsLastAccessUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    $name = "NtfsDisableLastAccessUpdate"

    Set-RegistryPerformanceValue -Path $path -Name $name -Value 1 `
        -Type ([Microsoft.Win32.RegistryValueKind]::DWord) `
        -ContextDescription "Configuring NTFS Last Access update behavior" `
        -SuccessMessage "Set $name to 1 under $path to disable NTFS Last Access updates." `
        -RunContext $Context
}

function Invoke-MenuShowDelay {
    [CmdletBinding()]
    param(
        [ValidateRange(0,1000)]
        [int]$DelayMs = 20,
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKCU:\Control Panel\Desktop"
    $name = "MenuShowDelay"
    $value = $DelayMs.ToString()

    Set-RegistryPerformanceValue -Path $path -Name $name -Value $value `
        -Type ([Microsoft.Win32.RegistryValueKind]::String) `
        -ContextDescription "Configuring menu display delay" `
        -SuccessMessage "Set $name to $value under $path to adjust menu display delay." `
        -RunContext $Context
}

function Invoke-TransparencyEffectsDisable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    $name = "EnableTransparency"

    Set-RegistryPerformanceValue -Path $path -Name $name -Value 0 `
        -Type ([Microsoft.Win32.RegistryValueKind]::DWord) `
        -ContextDescription "Disabling transparency effects for the current user" `
        -SuccessMessage "Set $name to 0 under $path to disable transparency effects." `
        -RunContext $Context
}

function Invoke-VisualEffectsBestPerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $name = "VisualFXSetting"

    Set-RegistryPerformanceValue -Path $path -Name $name -Value 2 `
        -Type ([Microsoft.Win32.RegistryValueKind]::DWord) `
        -ContextDescription "Setting visual effects to Best Performance for the current user" `
        -SuccessMessage "Set $name to 2 under $path to enforce Best Performance visual effects." `
        -RunContext $Context
}

function Invoke-WaitToKillServiceTimeout {
    [CmdletBinding()]
    param(
        [int]$Milliseconds = 2000,
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control"
    $name = "WaitToKillServiceTimeout"
    $value = $Milliseconds.ToString()

    Set-RegistryPerformanceValue -Path $path -Name $name -Value $value `
        -Type ([Microsoft.Win32.RegistryValueKind]::String) `
        -ContextDescription "Configuring WaitToKillServiceTimeout for services" `
        -SuccessMessage "Set $name to $value under $path to reduce service shutdown timeout." `
        -RunContext $Context
}

function Invoke-MpoVisualFixDisable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
    $name = "OverlayTestMode"

    $result = Set-RegistryValueSafe -Path $path -Name $name -Value 5 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable MPO overlay test mode'
    if ($result -and $result.Success) {
        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [OK] MPO disabled for stability." -ForegroundColor Gray
    } else {
        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Disable MPO overlay test mode' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $result -PresetName $presetLabel -OperationLabel 'Disable MPO overlay test mode' -Critical) { return $true }
    }
    return $false
}

function Invoke-HagsPerformanceEnablement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    $name = "HwSchMode"

    $result = Set-RegistryValueSafe -Path $path -Name $name -Value 2 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Enable HAGS'
    if ($result -and $result.Success) {
        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [OK] HAGS enabled for performance." -ForegroundColor Gray
    } else {
        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Enable HAGS' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $result -PresetName $presetLabel -OperationLabel 'Enable HAGS' -Critical) { return $true }
    }
    return $false
}

function Invoke-PowerThrottlingDisablement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
    $name = "PowerThrottlingOff"

    $result = Set-RegistryValueSafe -Path $path -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable power throttling'
    if ($result -and $result.Success) {
        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [OK] Global power throttling disabled." -ForegroundColor Gray
    } else {
        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Disable power throttling' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $result -PresetName $presetLabel -OperationLabel 'Disable power throttling' -Critical) { return $true }
    }
    return $false
}

function Invoke-PagingExecutivePerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $name = "DisablePagingExecutive"

    $result = Set-RegistryValueSafe -Path $path -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -Critical -ReturnResult -OperationLabel 'Disable kernel paging'
    if ($result -and $result.Success) {
        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [OK] Kernel paging disabled (kept in RAM)." -ForegroundColor Gray
    } else {
        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel 'Disable kernel paging' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $result -PresetName $presetLabel -OperationLabel 'Disable kernel paging' -Critical) { return $true }
    }
    return $false
}

function Invoke-MemoryCompressionOptimization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $hardware = Get-HardwareProfile
    if ($hardware.TotalMemoryGB -ge 8) {
        Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
        Set-RebootRequired -Context $Context | Out-Null
        Write-Host "  [OK] Memory compression disabled (>=8GB RAM)." -ForegroundColor Gray
    } else {
        Write-Host "  [ ] Memory compression kept (RAM <8GB)." -ForegroundColor Gray
    }
}

function Invoke-SafePerformanceTweaks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    Write-Section "Applying Safe performance tweaks..."
    $abort = Invoke-MpoVisualFixDisable -Context $Context -PresetName $PresetName
    if ($abort) { return $true }
    Invoke-NtfsLastAccessUpdate -Context $Context
    Invoke-MenuShowDelay -DelayMs 20 -Context $Context
    Invoke-SafeServiceOptimization -Context $Context
    return $false
}

function Invoke-AggressivePerformanceTweaks {
    [CmdletBinding()]
    param(
        $OemServices,
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    Write-Section "Applying Aggressive/Low-end performance tweaks..."
    Invoke-NtfsLastAccessUpdate -Context $Context
    $hagsAbort = Invoke-HagsPerformanceEnablement -Context $Context -PresetName $PresetName
    if ($hagsAbort) { return $true }
    $powerThrottleAbort = Invoke-PowerThrottlingDisablement -Context $Context -PresetName $PresetName
    if ($powerThrottleAbort) { return $true }
    $pagingAbort = Invoke-PagingExecutivePerformance -Context $Context -PresetName $PresetName
    if ($pagingAbort) { return $true }
    Invoke-MemoryCompressionOptimization -Context $Context
    Invoke-MenuShowDelay -DelayMs 0 -Context $Context
    Invoke-WaitToKillServiceTimeout -Milliseconds 2000 -Context $Context
    Invoke-TransparencyEffectsDisable -Context $Context
    Invoke-VisualEffectsBestPerformance -Context $Context
    Invoke-AggressiveServiceOptimization -Context $Context -OemServices $OemServices
    return $false
}

Export-ModuleMember -Function Get-HardwareProfile, Get-OEMServiceInfo, Invoke-SysMainOptimization, Invoke-PerformanceBaseline, Invoke-UltimatePerformancePlan, Invoke-NtfsLastAccessUpdate, Invoke-MenuShowDelay, Invoke-TransparencyEffectsDisable, Invoke-VisualEffectsBestPerformance, Invoke-WaitToKillServiceTimeout, Invoke-MpoVisualFixDisable, Invoke-HagsPerformanceEnablement, Invoke-PowerThrottlingDisablement, Invoke-PagingExecutivePerformance, Invoke-MemoryCompressionOptimization, Invoke-SafePerformanceTweaks, Invoke-AggressivePerformanceTweaks
