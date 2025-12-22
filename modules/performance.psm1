# Description: Collects hardware traits such as battery presence, memory size, and disk types.
# Parameters: None.
# Returns: PSCustomObject summarizing laptop status, memory category, and storage mix.
function Get-HardwareProfile {
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $memoryBytes = $system.TotalPhysicalMemory
    $memoryGB = if ($memoryBytes) { [math]::Round($memoryBytes / 1GB, 1) } else { 0 }

    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    $hasSSD = $false
    $hasHDD = $false
    foreach ($disk in $disks) {
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
        TotalMemoryGB  = $memoryGB
        MemoryCategory = if ($memoryGB -lt 6) { 'Low' } else { 'Normal' }
        HasSSD         = $hasSSD
        HasHDD         = $hasHDD -or -not $hasSSD
    }
}

# Description: Retrieves OEM-related services based on common vendor name patterns.
# Parameters: None.
# Returns: Collection of services matching OEM identifiers.
function Get-OEMServiceInfo {
    $patterns = 'Dell','Alienware','HP','Hewlett','Lenovo','Acer','ASUS','MSI','Samsung','Razer'
    $services = Get-Service | Where-Object { $patterns -contains ($_.DisplayName.Split(' ')[0]) -or $patterns -contains ($_.ServiceName.Split(' ')[0]) }
    $services
}

# Description: Guides the user to enable or disable SysMain based on detected hardware.
# Parameters: HardwareProfile - Hardware characteristics influencing default choices.
# Returns: None.
function Handle-SysMainPrompt {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    Write-Section "SysMain (Superfetch)"
    $hint = if ($HardwareProfile.HasHDD -and -not $HardwareProfile.HasSSD) { 'HDD detected: SysMain can speed up launches.' } else { 'SSD detected: you can disable it to avoid extra IO.' }
    Write-Host $hint -ForegroundColor Gray

    $defaultChoice = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 'y' } else { 'n' }
    if (Ask-YesNo "Disable SysMain to prioritize resources?" $defaultChoice) {
        try {
            Stop-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Host "  [+] SysMain disabled"
        } catch {
            Handle-Error -Context "Disabling SysMain service" -ErrorRecord $_
        }
    } elseif (Ask-YesNo "Ensure SysMain is enabled and Automatic?" 'y') {
        try {
            Set-Service -Name "SysMain" -StartupType Automatic
            Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Write-Host "  [+] SysMain enabled"
        } catch {
            Handle-Error -Context "Enabling SysMain service" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] SysMain left unchanged."
    }
}

# Description: Applies baseline performance registry adjustments using hardware context.
# Parameters: HardwareProfile - Used to select appropriate prefetch and visual effect settings.
# Returns: None.
function Apply-PerformanceBaseline {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    Write-Section "Baseline performance adjustments"

    $prefetchPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    $prefetchValue = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 1 } else { 3 }
    Set-RegistryValueSafe $prefetchPath "EnablePrefetcher" $prefetchValue
    Set-RegistryValueSafe $prefetchPath "EnableSuperfetch" $prefetchValue

    if ($HardwareProfile.MemoryCategory -eq 'Low') {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2
        Write-Host "  [+] Animations/effects tuned for performance (RAM <6GB)."
    } else {
        Write-Host "  [ ] Animations left as-is (RAM >=6GB)."
    }

    Enable-UltimatePerformancePlan
}

# Description: Ensures the Ultimate Performance power plan GUID is available, duplicating if necessary.
# Parameters: None.
# Returns: GUID string for the Ultimate Performance power plan when found or created.
function Get-UltimatePerformancePlanGuid {
    $ultimateTemplateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"

    try {
        $powerPlans = powercfg -list
        if ($powerPlans | Select-String -Pattern $ultimateTemplateGuid -SimpleMatch) {
            Write-Host "  [+] Ultimate Performance plan already available."
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
            Write-Host "  [+] Ultimate Performance plan already available."
            return $existingUltimatePlanGuid
        }
    } catch {
        Write-Warning "  [!] Could not inspect power plans: $($_.Exception.Message)"
    }

    try {
        $duplicateOutput = powercfg -duplicatescheme $ultimateTemplateGuid
        $duplicatedGuid = ($duplicateOutput | Select-String -Pattern '[A-Fa-f0-9-]{36}' -AllMatches | Select-Object -First 1).Matches.Value
        if (-not [string]::IsNullOrWhiteSpace($duplicatedGuid)) {
            Write-Host "  [+] Ultimate Performance plan created."
            return $duplicatedGuid
        }
    } catch {
        Write-Warning "  [!] Failed to create Ultimate Performance power plan: $($_.Exception.Message)"
        return $null
    }

    Write-Warning "  [!] Could not determine Ultimate Performance power plan GUID."
    return $null
}

# Description: Activates the Ultimate Performance power plan when available.
# Parameters: None.
# Returns: None. Writes warnings if activation fails.
function Enable-UltimatePerformancePlan {
    Write-Section "Enabling Ultimate Performance power plan"
    $guid = Get-UltimatePerformancePlanGuid
    if ([string]::IsNullOrWhiteSpace($guid)) {
        Write-Warning "  [!] Ultimate Performance plan not activated because GUID could not be resolved."
        return
    }
    try {
        powercfg -setactive $guid
        Write-Host "  [+] Ultimate Performance active."
    } catch {
        Handle-Error -Context "Activating Ultimate Performance power plan" -ErrorRecord $_
    }
}

# Description: Creates or updates a registry value with logging and error handling.
# Parameters: Path, Name, Value, Type, Context, SuccessMessage - specify registry target and log messages.
# Returns: None.
function Set-RegistryPerformanceValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Type,
        [Parameter(Mandatory)][string]$Context,
        [Parameter(Mandatory)][string]$SuccessMessage
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log -Message "Created registry key $Path" -Level 'Info'
        }

        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Log -Message $SuccessMessage -Level 'Info'
    } catch {
        Handle-Error -Context $Context -ErrorRecord $_
    }
}

# Description: Disables NTFS Last Access time updates to reduce filesystem overhead.
# Parameters: None.
# Returns: None. Writes registry values to control last access behavior.
function Set-NtfsLastAccessUpdate {
    [CmdletBinding()]
    param()

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    $name = "NtfsDisableLastAccessUpdate"

    Set-RegistryPerformanceValue -Path $path -Name $name -Value 1 `
        -Type ([Microsoft.Win32.RegistryValueKind]::DWord) `
        -Context "Configuring NTFS Last Access update behavior" `
        -SuccessMessage "Set $name to 1 under $path to disable NTFS Last Access updates."
}

# Description: Adjusts menu display delay for the current user to improve responsiveness.
# Parameters: DelayMs - Desired delay in milliseconds.
# Returns: None. Updates registry value controlling menu display timing.
function Set-MenuShowDelay {
    [CmdletBinding()]
    param(
        [ValidateRange(0,1000)]
        [int]$DelayMs = 20
    )

    $path = "HKCU:\Control Panel\Desktop"
    $name = "MenuShowDelay"
    $value = $DelayMs.ToString()

    Set-RegistryPerformanceValue -Path $path -Name $name -Value $value `
        -Type ([Microsoft.Win32.RegistryValueKind]::String) `
        -Context "Configuring menu display delay" `
        -SuccessMessage "Set $name to $value under $path to adjust menu display delay."
}

# Description: Disables Windows transparency effects for the current user to reduce GPU overhead.
# Parameters: None.
# Returns: None. Sets registry key to turn off transparency effects.
function Disable-TransparencyEffects {
    [CmdletBinding()]
    param()

    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    $name = "EnableTransparency"

    Set-RegistryPerformanceValue -Path $path -Name $name -Value 0 `
        -Type ([Microsoft.Win32.RegistryValueKind]::DWord) `
        -Context "Disabling transparency effects for the current user" `
        -SuccessMessage "Set $name to 0 under $path to disable transparency effects."
}

# Description: Forces visual effects to the Best Performance preset for the current user.
# Parameters: None.
# Returns: None. Writes registry setting for visual effects mode.
function Set-VisualEffectsBestPerformance {
    [CmdletBinding()]
    param()

    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $name = "VisualFXSetting"

    Set-RegistryPerformanceValue -Path $path -Name $name -Value 2 `
        -Type ([Microsoft.Win32.RegistryValueKind]::DWord) `
        -Context "Setting visual effects to Best Performance for the current user" `
        -SuccessMessage "Set $name to 2 under $path to enforce Best Performance visual effects."
}

# Description: Reduces the service shutdown timeout to speed up system shutdowns.
# Parameters: Milliseconds - Target timeout value as a string-compatible integer.
# Returns: None. Updates registry value controlling service shutdown wait time.
function Set-WaitToKillServiceTimeout {
    [CmdletBinding()]
    param(
        [int]$Milliseconds = 2000
    )

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control"
    $name = "WaitToKillServiceTimeout"
    $value = $Milliseconds.ToString()

    Set-RegistryPerformanceValue -Path $path -Name $name -Value $value `
        -Type ([Microsoft.Win32.RegistryValueKind]::String) `
        -Context "Configuring WaitToKillServiceTimeout for services" `
        -SuccessMessage "Set $name to $value under $path to reduce service shutdown timeout."
}

# Description: Disables Multi-Plane Overlay (MPO) to mitigate flickering and stutter issues.
# Parameters: None.
# Returns: None. Sets registry value and flags reboot requirement.
function Disable-MpoVisualFix {
    [CmdletBinding()]
    param()

    $path = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
    $name = "OverlayTestMode"

    Set-RegistryValueSafe -Path $path -Name $name -Value 5 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    $Global:NeedsReboot = $true
    Write-Host "  [+] MPO disabled for stability / MPO desactivado para estabilidad." -ForegroundColor Gray
}

# Description: Enables Hardware-accelerated GPU scheduling (HAGS) for supported GPUs.
# Parameters: None.
# Returns: None. Sets registry value and flags reboot requirement.
function Enable-HagsPerformance {
    [CmdletBinding()]
    param()

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    $name = "HwSchMode"

    Set-RegistryValueSafe -Path $path -Name $name -Value 2 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    $Global:NeedsReboot = $true
    Write-Host "  [+] HAGS enabled for performance / HAGS habilitado para rendimiento." -ForegroundColor Gray
}

# Description: Disables global power throttling to maintain consistent CPU performance.
# Parameters: None.
# Returns: None. Writes registry value and flags reboot requirement.
function Disable-PowerThrottlingGlobal {
    [CmdletBinding()]
    param()

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
    $name = "PowerThrottlingOff"

    Set-RegistryValueSafe -Path $path -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    $Global:NeedsReboot = $true
    Write-Host "  [+] Global power throttling disabled / Limitación de energía global desactivada." -ForegroundColor Gray
}

# Description: Keeps the Windows kernel and drivers resident in physical memory.
# Parameters: None.
# Returns: None. Writes registry value and flags reboot requirement.
function Set-PagingExecutivePerformance {
    [CmdletBinding()]
    param()

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $name = "DisablePagingExecutive"

    Set-RegistryValueSafe -Path $path -Name $name -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    $Global:NeedsReboot = $true
    Write-Host "  [+] Kernel paging disabled (kept in RAM) / Paginación del kernel desactivada (se mantiene en RAM)." -ForegroundColor Gray
}

# Description: Disables Windows memory compression when sufficient RAM is available.
# Parameters: None.
# Returns: None. Evaluates hardware profile and adjusts compression accordingly.
function Optimize-MemoryCompression {
    [CmdletBinding()]
    param()

    $hardware = Get-HardwareProfile
    if ($hardware.TotalMemoryGB -ge 8) {
        Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
        $Global:NeedsReboot = $true
        Write-Host "  [+] Memory compression disabled (>=8GB RAM) / Compresión de memoria desactivada (>=8GB RAM)." -ForegroundColor Gray
    } else {
        Write-Host "  [ ] Memory compression kept (RAM <8GB) / Compresión de memoria mantenida (RAM <8GB)." -ForegroundColor Gray
    }
}

# Description: Applies conservative performance tweaks suitable for most systems.
# Parameters: None.
# Returns: None. Calls supporting registry tweak functions.
function Apply-SafePerformanceTweaks {
    [CmdletBinding()]
    param()

    Write-Section "Applying Safe performance tweaks..."
    Disable-MpoVisualFix
    Set-NtfsLastAccessUpdate
    Set-MenuShowDelay -DelayMs 20
    Optimize-ServicesSafe
}

# Description: Applies more aggressive performance tweaks for low-end systems.
# Parameters: None.
# Returns: None. Invokes multiple registry adjustments for responsiveness.
function Apply-AggressivePerformanceTweaks {
    [CmdletBinding()]
    param()

    Write-Section "Applying Aggressive/Low-end performance tweaks..."
    Set-NtfsLastAccessUpdate
    Enable-HagsPerformance
    Disable-PowerThrottlingGlobal
    Set-PagingExecutivePerformance
    Optimize-MemoryCompression
    Set-MenuShowDelay -DelayMs 0
    Set-WaitToKillServiceTimeout -Milliseconds 2000
    Disable-TransparencyEffects
    Set-VisualEffectsBestPerformance
    Optimize-ServicesAggressive
}

Export-ModuleMember -Function Get-HardwareProfile, Get-OEMServiceInfo, Handle-SysMainPrompt, Apply-PerformanceBaseline, Enable-UltimatePerformancePlan, Set-NtfsLastAccessUpdate, Set-MenuShowDelay, Disable-TransparencyEffects, Set-VisualEffectsBestPerformance, Set-WaitToKillServiceTimeout, Disable-MpoVisualFix, Enable-HagsPerformance, Disable-PowerThrottlingGlobal, Set-PagingExecutivePerformance, Optimize-MemoryCompression, Apply-SafePerformanceTweaks, Apply-AggressivePerformanceTweaks
