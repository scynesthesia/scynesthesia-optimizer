# Depends on: ui.psm1 (loaded by main script)
if (-not (Get-Module -Name 'config' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/config.psm1') -Force -Scope Local
}
if (-not (Get-Module -Name 'network_discovery' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/network_discovery.psm1') -Force -Scope Local
}
if (-not (Get-Module -Name 'network_shared' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/network_shared.psm1') -Force -Scope Local
}

# Description: Retrieves active physical adapters excluding virtual or VPN interfaces.
# Parameters: None.
# Returns: Collection of eligible adapters or empty array on failure.
function Get-EligibleNetAdapters {
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object {
                $_.Status -eq 'Up' -and
                $_.InterfaceDescription -notmatch '(?i)virtual|vmware|hyper-v|loopback|vpn|tap|wireguard|bluetooth'
            }
        return $adapters
    } catch {
        Invoke-ErrorHandler -Context 'Retrieving physical network adapters' -ErrorRecord $_
        return @()
    }
}

# Description: Determines whether the current PowerShell session is elevated.
# Parameters: None.
# Returns: Boolean indicating administrative context.
function Test-IsAdminSession {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# Description: Classifies adapters for hardcore tweaks, including fragile Wi-Fi detection.
# Parameters: Adapter - NetAdapter object to evaluate.
# Returns: Object describing Wi-Fi/fragility status.
function Get-HardcoreAdapterProfile {
    param(
        [Parameter(Mandatory)][object]$Adapter
    )

    $description = $Adapter.InterfaceDescription
    $ndisMedium = $null
    try {
        $ndisMedium = $Adapter | Select-Object -ExpandProperty NdisPhysicalMedium -ErrorAction SilentlyContinue
    } catch { }

    $isWifi = $false
    if ($ndisMedium -and $ndisMedium -match '(?i)802\.11|wireless') {
        $isWifi = $true
    } elseif ($description -match '(?i)(wi-?fi|wireless|802\.11)') {
        $isWifi = $true
    }

    $wifiWhitelistPatterns = @(
        '(?i)Intel\(R\).+Wi-?Fi',
        '(?i)Killer\(TM\).+Intel',
        '(?i)Qualcomm\(R\).+(FastConnect|Wi-?Fi 6|Wi-?Fi 7)',
        '(?i)Marvell.*AzureWave'
    )

    $fragileWifiPatterns = @(
        '(?i)Realtek.*(8821|8822|8723|8188|8192|8811)',
        '(?i)MediaTek|Ralink|MTK',
        '(?i)Broadcom.*(43|BCM43)',
        '(?i)Qualcomm.*(QCA9|Atheros AR9)'
    )

    $whitelistMatch = $wifiWhitelistPatterns | Where-Object { $description -match $_ } | Select-Object -First 1
    $fragileMatch = $fragileWifiPatterns | Where-Object { $description -match $_ } | Select-Object -First 1
    $isWhitelisted = $isWifi -and $null -ne $whitelistMatch
    $isFragile = $isWifi -and (-not $isWhitelisted) -and ($null -ne $fragileMatch)

    $riskReason = $null
    if ($isFragile) {
        $riskReason = "Wireless chipset '$description' is prone to driver lockups after aggressive interrupt/offload resets."
    }

    return [pscustomobject]@{
        IsWifi        = $isWifi
        IsWhitelisted = $isWhitelisted
        IsFragile     = $isFragile
        RiskReason    = $riskReason
    }
}

# Description: Evaluates a network adapter for legacy driver risks.
# Parameters: Adapter - NetAdapter object to evaluate.
# Returns: Object indicating whether Interrupt Moderation/MSI should be skipped along with metadata.
function Get-NicLegacyDriverAssessment {
    param(
        [Parameter(Mandatory)][object]$Adapter
    )

    $result = [pscustomobject]@{
        Adapter      = $Adapter
        InstanceId   = $null
        DriverDate   = $null
        HardwareIds  = @()
        IsLegacy     = $false
        Reason       = $null
    }

    $instanceId = $null
    foreach ($propName in @('PnPDeviceID', 'PnpDeviceID', 'DeviceID')) {
        try {
            if ($Adapter.PSObject.Properties[$propName] -and $Adapter.$propName) {
                $instanceId = $Adapter.$propName
                break
            }
        } catch { }
    }
    $result.InstanceId = $instanceId

    $pnpDevice = $null
    try {
        if ($instanceId) {
            $pnpDevice = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
        }
        if (-not $pnpDevice) {
            $pnpDevice = Get-PnpDevice -Class 'Net' -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq $Adapter.InterfaceDescription } | Select-Object -First 1
        }
    } catch { }

    $deviceIdForProps = $instanceId
    if ($pnpDevice -and $pnpDevice.InstanceId) {
        $deviceIdForProps = $pnpDevice.InstanceId
        if (-not $result.InstanceId) {
            $result.InstanceId = $pnpDevice.InstanceId
        }
    }

    if ($deviceIdForProps) {
        try {
            $driverDateProp = Get-PnpDeviceProperty -InstanceId $deviceIdForProps -KeyName 'DEVPKEY_Device_DriverDate' -ErrorAction SilentlyContinue
            if ($driverDateProp -and $driverDateProp.Data) {
                $parsed = $null
                if ([datetime]::TryParse($driverDateProp.Data, [ref]$parsed)) {
                    $result.DriverDate = $parsed
                }
            }
        } catch { }

        try {
            $hardwareProp = Get-PnpDeviceProperty -InstanceId $deviceIdForProps -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue
            if ($hardwareProp -and $hardwareProp.Data) {
                $result.HardwareIds = @($hardwareProp.Data) | Where-Object { $_ }
            }
        } catch { }
    }

    $problematicPrefixes = @(
        'VEN_10EC&DEV_8136',
        'VEN_10EC&DEV_8168',
        'VEN_10EC&DEV_8169',
        'VEN_10EC&DEV_8723',
        'VEN_168C&DEV_001C',
        'VEN_168C&DEV_002B',
        'VEN_168C&DEV_0032'
    )
    $normalizedHardware = $result.HardwareIds | ForEach-Object { $_.ToUpperInvariant() }
    $legacyCutoff = Get-Date '2018-01-01'

    $matchedPrefix = $null
    foreach ($hwId in $normalizedHardware) {
        $hit = $problematicPrefixes | Where-Object { $hwId -like "*$_*" }
        if ($hit) {
            $matchedPrefix = $hit | Select-Object -First 1
            break
        }
    }
    if ($result.DriverDate -and $result.DriverDate -lt $legacyCutoff) {
        $result.IsLegacy = $true
        $result.Reason = "Driver date $($result.DriverDate.ToShortDateString()) predates 2018."
    } elseif ($matchedPrefix) {
        $result.IsLegacy = $true
        $result.Reason = "Hardware ID matches known fragile PCI IDs ($($matchedPrefix))."
    }

    return $result
}

# Description: Applies advanced TCP/IP registry parameters for performance tuning.
# Parameters: Context - Optional run context for reboot tracking; FailureTracker - Optional tracker for critical registry failures.
# Returns: None. Sets reboot flag after changes.
function Set-TcpIpAdvancedParameters {
    param(
        [object]$Context,
        [pscustomobject]$FailureTracker
    )
    try {
        $buildNumber = [Environment]::OSVersion.Version.Build
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        $values = @{
            DefaultTTL          = 64
            Tcp1323Opts         = 1
            TcpMaxDupAcks       = 2
            MaxUserPort         = 65534
            TcpTimedWaitDelay   = 30
        }

        if ($buildNumber -ge 16299) {
            $values['SackOpts'] = 0
        } else {
            Write-Host "  [!] SackOpts skipped for build $buildNumber to maintain compatibility." -ForegroundColor Yellow
        }

        $anySuccess = $false
        foreach ($entry in $values.GetEnumerator()) {
            try {
                $result = Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Critical -ReturnResult
                $abort = Register-RegistryResult -Tracker $FailureTracker -Result $result -Critical
                if ($result -and $result.Success) {
                    Write-Host "  [+] $($entry.Key) set to $($entry.Value) in TCP parameters." -ForegroundColor Green
                    $anySuccess = $true
                } else {
                    Write-Host "  [!] Failed to set $($entry.Key) to $($entry.Value) in TCP parameters." -ForegroundColor Yellow
                }
                if ($abort) { break }
            } catch {
                Invoke-ErrorHandler -Context "Setting $($entry.Key) in TCP parameters" -ErrorRecord $_
            }
        }

        if ($FailureTracker -and $FailureTracker.Abort) {
            return
        }

        if ($null -eq $Context) {
            $Context = New-RunContext
        }
        if ($anySuccess) {
            Set-NeedsReboot -Context $Context | Out-Null
        }
    } catch {
        Invoke-ErrorHandler -Context 'Configuring advanced TCP/IP parameters' -ErrorRecord $_
    }
}

# Description: Disables network throttling via registry for maximum throughput.
# Parameters: Context - Optional run context for reboot tracking.
# Returns: None. Sets reboot flag on success.
function Set-NetworkThrottlingHardcore {
    param(
        [object]$Context
    )

    Invoke-NetworkThrottlingShared -Context $Context -LoggerPrefix '[NetworkHardcore]' -HostMessage 'Disabling network throttling' -OperationLabel 'Hardcore network throttling index' -SuccessMessage 'NetworkThrottlingIndex set to maximum performance.' -FailureMessage 'NetworkThrottlingIndex could not be set (permission issue?).' -MarkReboot | Out-Null
}

# Description: Configures TCP/IP service provider priorities for resolution order.
# Parameters: Context - Optional run context for reboot tracking; FailureTracker - Optional tracker for critical registry failures.
# Returns: None. Sets reboot flag after applying values.
function Set-ServicePriorities {
    param(
        [object]$Context,
        [pscustomobject]$FailureTracker
    )

    Invoke-ServiceProviderPrioritiesShared -Context $Context -FailureTracker $FailureTracker -LoggerPrefix '[NetworkHardcore]' -HostMessage 'Configuring Service Provider priorities' -MarkReboot | Out-Null
}

# Description: Applies Winsock parameter adjustments to align socket behavior.
# Parameters: Context - Optional run context for reboot tracking; FailureTracker - Optional tracker for critical registry failures.
# Returns: None. Sets reboot flag when updates are made.
function Set-WinsockOptimizations {
    param(
        [object]$Context,
        [pscustomobject]$FailureTracker
    )
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
        $values = @{
            MinSockAddrLength = 16
            MaxSockAddrLength = 16
        }

        $anySuccess = $false
        foreach ($entry in $values.GetEnumerator()) {
            try {
                $result = Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Critical -ReturnResult
                $abort = Register-RegistryResult -Tracker $FailureTracker -Result $result -Critical
                if ($result -and $result.Success) {
                    Write-Host "  [+] $($entry.Key) set to $($entry.Value) for Winsock." -ForegroundColor Green
                    $anySuccess = $true
                } else {
                    Write-Host "  [!] Failed to set $($entry.Key) for Winsock." -ForegroundColor Yellow
                }
                if ($abort) { break }
            } catch {
                Invoke-ErrorHandler -Context "Setting Winsock $($entry.Key)" -ErrorRecord $_
            }
        }

        if ($FailureTracker -and $FailureTracker.Abort) {
            return
        }

        if ($null -eq $Context) {
            $Context = New-RunContext
        }
        if ($anySuccess) {
            Set-NeedsReboot -Context $Context | Out-Null
        }
    } catch {
        Invoke-ErrorHandler -Context 'Applying Winsock optimizations' -ErrorRecord $_
    }
}

# Description: Tunes LanmanServer parameters for reduced latency and connection stability.
# Parameters: Context - Optional run context for reboot tracking.
# Returns: None. Sets reboot flag when registry changes occur.
function Optimize-LanmanServer {
    param(
        [object]$Context
    )
    try {
        $runContext = Get-RunContext -Context $Context
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $values = @{
            autodisconnect = 0
            Size           = 3
            EnableOplocks  = 0
            IRPStackSize   = 20
        }

        foreach ($entry in $values.GetEnumerator()) {
            try {
                $result = Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $runContext -Critical -ReturnResult -OperationLabel "LanmanServer: $($entry.Key)"
                if ($result -and $result.Success) {
                    Write-Host "  [+] $($entry.Key) set to $($entry.Value) for LanmanServer." -ForegroundColor Green
                } else {
                    Write-Host "  [!] Failed to set $($entry.Key) for LanmanServer." -ForegroundColor Yellow
                }
            } catch {
                Invoke-ErrorHandler -Context "Setting LanmanServer $($entry.Key)" -ErrorRecord $_
            }
        }

        if ($null -eq $runContext) {
            $runContext = New-RunContext
        }
        Set-NeedsReboot -Context $runContext | Out-Null
    } catch {
        Invoke-ErrorHandler -Context 'Optimizing LanmanServer parameters' -ErrorRecord $_
    }
}

# Description: Runs netsh commands to set advanced TCP/IP global options for performance.
# Parameters: Context - Optional run context for reboot tracking.
# Returns: None. Sets reboot flag following configuration.
function Set-NetshHardcoreGlobals {
    param(
        [object]$Context
    )
    try {
        $buildNumber = [Environment]::OSVersion.Version.Build
        $tcpGlobals = $null
        $ipGlobals = $null
        try {
            $tcpGlobals = netsh int tcp show global 2>&1
        } catch {
            Write-Host "  [!] Unable to probe TCP globals; capability checks will be limited (build $buildNumber)." -ForegroundColor Yellow
        }
        try {
            $ipGlobals = netsh int ip show global 2>&1
        } catch {
            Write-Host "  [!] Unable to probe IP globals; capability checks will be limited (build $buildNumber)." -ForegroundColor Yellow
        }
        try {
            $registerNetsh = Get-Command Register-NetshGlobalsForRollback -ErrorAction SilentlyContinue
            if ($registerNetsh) {
                & $registerNetsh -Context $Context -RawText ($tcpGlobals -join "`n") | Out-Null
            }
        } catch { }

        $netshCompatibility = @{
            'set global dca=enabled' = @{
                FeatureName        = 'Direct Cache Access (DCA)'
                Scope              = 'tcp'
                MinBuild           = 6000    # Vista+
                MaxBuild           = 10240   # Removed on later Windows 10/11 builds
                CapabilityPattern  = '(?i)direct cache access'
            }
            'set global netdma=enabled' = @{
                FeatureName        = 'NetDMA'
                Scope              = 'tcp'
                MinBuild           = 6000
                MaxBuild           = 10240   # Deprecated after early Windows 10
                CapabilityPattern  = '(?i)netdma'
            }
            'set global mpp=disabled' = @{
                FeatureName        = 'Memory Pressure Protection'
                Scope              = 'tcp'
                MinBuild           = 7600    # Windows 7+
                CapabilityPattern  = '(?i)memory pressure'
            }
            'set global neighborcachelimit=4096' = @{
                FeatureName        = 'Neighbor Cache Limit'
                Scope              = 'ip'
                MinBuild           = 7600
                CapabilityPattern  = '(?i)neighbor cache limit'
            }
        }

        $checkCompatibility = {
            param($commandEntry, $compatibilityMap, $tcpProbe, $ipProbe, $currentBuild)

            $rule = $null
            if ($compatibilityMap.ContainsKey($commandEntry.Command)) {
                $rule = $compatibilityMap[$commandEntry.Command]
            }

            if (-not $rule) {
                return [pscustomobject]@{ Supported = $true; Reason = $null }
            }

            $scope = if ($rule.Scope) { $rule.Scope } else { 'tcp' }
            $minBuild = if ($rule.MinBuild) { [int]$rule.MinBuild } else { 0 }
            $maxBuild = if ($rule.MaxBuild) { [int]$rule.MaxBuild } else { [int]::MaxValue }
            if ($currentBuild -lt $minBuild -or $currentBuild -gt $maxBuild) {
                $reason = "$($rule.FeatureName) not whitelisted for build $currentBuild (supported: $minBuild-$maxBuild)."
                return [pscustomobject]@{ Supported = $false; Reason = $reason }
            }

            $probeOutput = if ($scope -eq 'ip') { $ipProbe } else { $tcpProbe }
            if ($rule.CapabilityPattern) {
                if (-not $probeOutput) {
                    $reason = "Unable to confirm $($rule.FeatureName) support on build $currentBuild (no $scope probe)."
                    return [pscustomobject]@{ Supported = $false; Reason = $reason }
                }
                if ($probeOutput -notmatch $rule.CapabilityPattern) {
                    $reason = "$($rule.FeatureName) not exposed on build $currentBuild; skipping."
                    return [pscustomobject]@{ Supported = $false; Reason = $reason }
                }
            }

            return [pscustomobject]@{ Supported = $true; Reason = $null }
        }

        $tcpCommands = @(
            @{ Command = 'set global dca=enabled'; Description = 'DCA enabled' },
            @{ Command = 'set global netdma=enabled'; Description = 'NetDMA enabled' },
            @{ Command = 'set global nonsackrttresiliency=disabled'; Description = 'NonSackRTTResiliency disabled' },
            @{ Command = 'set global maxsynretransmissions=2'; Description = 'MaxSynRetransmissions set' },
            @{ Command = 'set global mpp=disabled'; Description = 'MPP disabled' },
            @{ Command = 'set security profiles=disabled'; Description = 'Security profiles disabled' },
            @{ Command = 'set heuristics disabled'; Description = 'Heuristics disabled' }
        )

        $ipCommands = @(
            @{ Command = 'set global neighborcachelimit=4096'; Description = 'NeighborCacheLimit set' }
        )

        $eligibleTcpCommands = New-Object System.Collections.Generic.List[object]
        foreach ($entry in $tcpCommands) {
            $check = & $checkCompatibility $entry $netshCompatibility $tcpGlobals $ipGlobals $buildNumber
            if ($check.Supported) {
                $eligibleTcpCommands.Add($entry) | Out-Null
            } else {
                Write-Host "  [ ] Skipping $($entry.Description): $($check.Reason)" -ForegroundColor Gray
            }
        }

        $eligibleIpCommands = New-Object System.Collections.Generic.List[object]
        foreach ($entry in $ipCommands) {
            $check = & $checkCompatibility $entry $netshCompatibility $tcpGlobals $ipGlobals $buildNumber
            if ($check.Supported) {
                $eligibleIpCommands.Add($entry) | Out-Null
            } else {
                Write-Host "  [ ] Skipping $($entry.Description): $($check.Reason)" -ForegroundColor Gray
            }
        }

        if ($eligibleTcpCommands.Count -eq 0 -and $eligibleIpCommands.Count -eq 0) {
            Write-Host "  [ ] No compatible netsh globals to apply for build $buildNumber." -ForegroundColor Gray
            return
        }

        $scriptBuilder = New-Object System.Text.StringBuilder
        $null = $scriptBuilder.AppendLine('pushd interface tcp')
        foreach ($entry in $eligibleTcpCommands) {
            $null = $scriptBuilder.AppendLine($entry.Command)
        }
        $null = $scriptBuilder.AppendLine('popd')
        foreach ($entry in $eligibleIpCommands) {
            $null = $scriptBuilder.AppendLine("int ip $($entry.Command)")
        }
        $netshScript = $scriptBuilder.ToString()

        $scriptPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("netsh_hardcore_{0}.txt" -f ([Guid]::NewGuid().ToString('N')))
        Set-Content -Path $scriptPath -Value $netshScript -Encoding ASCII

        Push-Location -Path ($env:SystemRoot | ForEach-Object { if ($_ -and (Test-Path $_)) { $_ } else { $env:WINDIR } })
        try {
            try {
                $output = & cmd.exe /c "netsh -f `"$scriptPath`"" 2>&1
                $exitCode = $LASTEXITCODE
                if ($exitCode -eq 0) {
                    foreach ($command in ($eligibleTcpCommands + $eligibleIpCommands)) {
                        Write-Host "  [+] $($command.Description)." -ForegroundColor Green
                    }
                } else {
                    Write-Host "  [!] netsh script returned exit code $exitCode. Review output for details." -ForegroundColor Yellow
                    if ($output) {
                        Write-Host $output -ForegroundColor Yellow
                    }
                }
            } catch {
                Invoke-ErrorHandler -Context 'Running netsh hardcore script' -ErrorRecord $_
            }
        } finally {
            Remove-Item -Path $scriptPath -ErrorAction SilentlyContinue
            Pop-Location -ErrorAction SilentlyContinue
        }

        if ($null -eq $Context) {
            $Context = New-RunContext
        }
        Set-NeedsReboot -Context $Context | Out-Null
    } catch {
        Invoke-ErrorHandler -Context 'Applying hardcore netsh globals' -ErrorRecord $_
    }
}

$script:NicRegistryAccessDenied = $false
$script:NicRegistryTweaksApplied = $false

# Description: Maps physical adapters to their registry class paths for advanced tweaks.
# Parameters: None.
# Returns: Collection of objects containing adapter references and registry paths.
function Get-NicRegistryPaths {
    if ($script:NicRegistryAccessDenied) {
        Write-Host "  [!] NIC registry access was previously denied; skipping registry mapping." -ForegroundColor Yellow
        return @()
    }

    return Get-SharedNicRegistryPaths -AdapterResolver { Get-EligibleNetAdapters } -AllowOwnershipFallback -LoggerPrefix '[NetworkHardcore]' -AccessDeniedFlag ([ref]$script:NicRegistryAccessDenied)
}

# Description: Applies hardcore NIC registry tweaks for power, wake, and latency behaviors.
# Parameters: Context - Optional run context for reboot tracking.
# Returns: None. Sets reboot flag after applying changes.
function Set-NicRegistryHardcore {
    param(
        [object]$Context
    )
    try {
        $runContext = Get-RunContext -Context $Context
        $nicPaths = Get-NicRegistryPaths
        if ($nicPaths.Count -eq 0) {
            Write-Host "  [!] No NIC registry paths found for tweaks." -ForegroundColor Yellow
            return
        }

        $setValueIfDifferent = {
            param($path, $name, $value, $type)
            $current = $null
            try {
                $existing = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
                $current = $existing.$name
            } catch { }
                if ($current -eq $value) { return 'Unchanged' }
                try {
                    $normalizedType = if ($type -is [Microsoft.Win32.RegistryValueKind]) {
                        $type
                    } else {
                        [System.Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$type, $true)
                    }
                    $result = Set-RegistryValueSafe -Path $path -Name $name -Value $value -Type $normalizedType -Context $runContext -Critical -ReturnResult -OperationLabel "NIC hardcore: $name"
                    if ($result -and $result.Success) {
                        return 'Changed'
                    }
                    return 'Failed'
                } catch {
                    return 'Failed'
                }
            }

        $sharedPowerFlags = @{
            '*EEE'                 = '0'
            '*WakeOnMagicPacket'   = '0'
            '*WakeOnPattern'       = '0'
            'AllowIdleIrp'         = '0'
            'DeepSleepMode'        = '0'
            'EEE'                  = '0'
            'EnableGreenEthernet'  = '0'
            'WakeOnMagicPacket'    = '0'
            'WakeOnPatternMatch'   = '0'
            'WolShutdownLinkSpeed' = '0'
        }

        $sharedPowerResult = Invoke-NicPowerRegistryTweaks -Context $runContext -NicPaths $nicPaths -Values $sharedPowerFlags -LoggerPrefix '[NetworkHardcore]' -InvokeOnceId 'NicPower:Shared' -CleanupInterfaceNoise

        $powerOffload = @{
            '*EEE'                 = '0'
            '*WakeOnMagicPacket'   = '0'
            '*WakeOnPattern'       = '0'
            'AllowIdleIrp'         = '0'
            'DeepSleepMode'        = '0'
            'EEE'                  = '0'
            'EnableGreenEthernet'  = '0'
            'GigaLite'             = '0'
            'NicAutoPowerSaver'    = '0'
            'WakeOnMagicPacket'    = '0'
            'WakeOnPatternMatch'   = '0'
            'EnableWakeOnLan'      = '0'
            'S5WakeOnLan'          = '0'
            'WakeOnLink'           = '0'
            'WakeOnDisconnect'     = '0'
            # Keep the shutdown link at full speed to avoid wake triggers from low-power renegotiation.
            'WolShutdownLinkSpeed' = '2'
        }

        $interruptDelays = @{
            'TxIntDelay'   = '0'
            'RxIntDelay'   = '0'
            'TxAbsIntDelay'= '0'
            'RxAbsIntDelay'= '0'
        }

        $powerOffloadRemaining = @{}
        foreach ($entry in $powerOffload.GetEnumerator()) {
            if (-not $sharedPowerFlags.ContainsKey($entry.Key) -or $sharedPowerFlags[$entry.Key] -ne $entry.Value) {
                $powerOffloadRemaining[$entry.Key] = $entry.Value
            }
        }

        $nagleResult = Invoke-NagleRegistryUpdate -Context (Get-RunContext -Context $Context) -Adapters ($nicPaths | ForEach-Object { $_.Adapter }) -LoggerPrefix '[NetworkHardcore]' -InvokeOnceId 'Nagle:Tcp'

        foreach ($item in $nicPaths) {
            $adapterName = $item.Adapter.Name
            $adapterProfile = Get-HardcoreAdapterProfile -Adapter $item.Adapter
            $adapterChanged = ($sharedPowerResult -and $sharedPowerResult.ChangedAdapters -contains $adapterName)

            foreach ($entry in $powerOffloadRemaining.GetEnumerator()) {
                try {
                    $status = & $setValueIfDifferent $item.Path $entry.Key $entry.Value ([Microsoft.Win32.RegistryValueKind]::String)
                    if ($status -eq 'Changed') {
                        Write-Host "    [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                        $adapterChanged = $true
                    } elseif ($status -eq 'Failed') {
                        Write-Host "    [!] Failed to set $($entry.Key) on $adapterName" -ForegroundColor Yellow
                    }
                } catch {
                    Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
                }
            }

            foreach ($entry in $interruptDelays.GetEnumerator()) {
                try {
                    $status = & $setValueIfDifferent $item.Path $entry.Key $entry.Value ([Microsoft.Win32.RegistryValueKind]::String)
                    if ($status -eq 'Changed') {
                        Write-Host "    [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                        $adapterChanged = $true
                    } elseif ($status -eq 'Failed') {
                        Write-Host "    [!] Failed to set $($entry.Key) on $adapterName" -ForegroundColor Yellow
                    }
                } catch {
                    Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
                }
            }

            try {
                if (-not $item.Guid) {
                    Write-Host "    [!] Missing interface GUID for $adapterName; skipping per-interface TCP parameters." -ForegroundColor Yellow
                    continue
                }

                $guidSegment = ($item.Guid.ToString().Trim('{}'))
                $interfacePath = Join-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ChildPath "{${guidSegment}}"
                $noiseKeys = @($powerOffload.Keys) + @($interruptDelays.Keys)
                foreach ($noiseKey in $noiseKeys | Select-Object -Unique) {
                    try {
                        $existingNoise = (Get-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue)
                        if ($existingNoise) {
                            Remove-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue
                            $adapterChanged = $true
                        }
                    } catch { }
                }

                if ($nagleResult -and $nagleResult.ChangedAdapters -contains $adapterName) {
                    Write-Host "    [+] Nagle parameters set (Ack=1, NoDelay=1, DelAckTicks=0)" -ForegroundColor Green
                    $adapterChanged = $true
                }
            } catch {
                Invoke-ErrorHandler -Context "Setting Nagle parameters for $adapterName" -ErrorRecord $_
            }

            if ($adapterChanged) {
                $allowAggressiveReset = $true
                if ($adapterProfile.IsFragile) {
                    $warning = "High-risk Wi-Fi chipset detected on $adapterName. Interrupt/offload resets can cause driver lockups or require a full reboot."
                    Write-Host "    [!] $warning" -ForegroundColor Yellow
                    if (-not (Get-Confirmation "Proceed with cache clears and adapter disable/enable for $adapterName? (High risk acknowledged)" 'n')) {
                        Write-Host "    [ ] Aggressive reset skipped for fragile Wi-Fi adapter $adapterName." -ForegroundColor DarkGray
                        $allowAggressiveReset = $false
                    }
                }

                if ($allowAggressiveReset) {
                    try {
                        & cmd.exe /c 'netsh int ip reset' 2>&1 | Out-Null
                        & cmd.exe /c 'netsh winsock reset' 2>&1 | Out-Null
                        Write-Host "    [+] Network stack cache cleared (IP/Winsock reset)" -ForegroundColor Green
                    } catch {
                        Invoke-ErrorHandler -Context "Resetting network stack for $adapterName" -ErrorRecord $_
                    }

                    try {
                        Disable-NetAdapter -Name $adapterName -Confirm:$false -PassThru -ErrorAction Stop | Out-Null
                        Start-Sleep -Seconds 3
                        Enable-NetAdapter -Name $adapterName -Confirm:$false -PassThru -ErrorAction Stop | Out-Null
                        Write-Host "    [+] Adapter reset to reload driver settings" -ForegroundColor Green
                    } catch {
                        Invoke-ErrorHandler -Context "Resetting adapter $adapterName" -ErrorRecord $_
                    }
                    $script:NicRegistryTweaksApplied = $true
                } else {
                    Write-Host "    [!] Registry tweaks applied without forcing resets; reboot or manual adapter toggle may be required for $adapterName." -ForegroundColor Yellow
                    $script:NicRegistryTweaksApplied = $true
                }
            }
        }

        if ($null -eq $Context) {
            $Context = New-RunContext
        }
        Set-NeedsReboot -Context $Context | Out-Null
    } catch {
        Invoke-ErrorHandler -Context 'Applying NIC-specific registry tweaks' -ErrorRecord $_
    }
}

# Description: Identifies the primary adapters based on speed and connection status.
# Parameters: Adapters - Collection of adapters to evaluate.
# Returns: Array of primary adapters or empty array when none qualify.
function Get-PrimaryNetAdapter {
    try {
        $adapters = Get-EligibleNetAdapters
        if ($adapters.Count -eq 0) { return $null }
        $sortedAdapters = $adapters |
            Sort-Object -Property @{ Expression = {
                    $parsed = Convert-LinkSpeedToBits -LinkSpeed $_.LinkSpeed
                    if ($null -eq $parsed) { return 0 }
                    return $parsed
                }
            } -Descending
        return $sortedAdapters | Select-Object -First 1
    } catch {
        Invoke-ErrorHandler -Context 'Selecting primary network adapter' -ErrorRecord $_
        return $null
    }
}

# Description: Hardens Wake-on-LAN settings through registry and adapter UI properties.
# Parameters: Context - Optional run context for permission tracking.
# Returns: None. Sets global reboot flag after changes.
function Set-WakeOnLanHardcore {
    param(
        [object]$Context
    )
    <#
        Wake-on-LAN needs both registry and UI alignment because many drivers honor multiple flags at once.
        WolShutdownLinkSpeed "2" keeps the link in "Not Speed Down" to avoid low-power renegotiation that re-enables WOL paths.
    #>
    Write-Host "  [>] Applying Wake-on-LAN hardening (registry + driver UI)" -ForegroundColor Cyan

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $runContext = Get-RunContext -Context $Context

    if ($script:NicRegistryAccessDenied) {
        $message = "NIC registry tweaks skipped because registry access was denied earlier. Run PowerShell as Administrator for full coverage."
        Write-Host "  [!] $message" -ForegroundColor Yellow
        if ($logger) { Write-Log "[NetworkHardcore] $message" -Level 'Warning' }
        return
    }

    $nicPaths = Get-NicRegistryPaths
    $adapters = Get-EligibleNetAdapters
    if ($adapters.Count -eq 0 -and $nicPaths.Count -gt 0) {
        $adapters = $nicPaths | ForEach-Object { $_.Adapter } | Where-Object { $_ } | Sort-Object -Property ifIndex -Unique
    }

    if ($adapters.Count -eq 0) {
        if ($script:NicRegistryTweaksApplied) {
            Write-Host "  [i] Wake-on-LAN registry settings applied; no adapters exposed for driver UI hardening." -ForegroundColor Gray
        } else {
            Write-Host "  [!] No adapters available for Wake-on-LAN hardening." -ForegroundColor Yellow
        }
        return
    }

    if ($nicPaths.Count -eq 0) {
        if ($script:NicRegistryAccessDenied) {
            $message = "NIC registry tweaks skipped because registry access was denied earlier. Run PowerShell as Administrator for full coverage."
            Write-Host "  [!] $message" -ForegroundColor Yellow
            if ($logger) { Write-Log "[NetworkHardcore] $message" -Level 'Warning' }
        } else {
            Write-Host "  [!] Unable to map NIC registry paths; skipping WOL registry enforcement." -ForegroundColor Yellow
        }
        return
    }

    $wolRegistryValues = @{
        '*WakeOnMagicPacket'   = '0'
        '*WakeOnPattern'       = '0'
        'WakeOnMagicPacket'    = '0'
        'WakeOnPatternMatch'   = '0'
        'EnableWakeOnLan'      = '0'
        'S5WakeOnLan'          = '0'
        'WakeOnLink'           = '0'
        'WakeOnDisconnect'     = '0'
        # "2" = Not Speed Down to keep the link at full speed during shutdown states.
        'WolShutdownLinkSpeed' = '2'
    }

    foreach ($adapter in $adapters) {
        $adapterName = $adapter.Name
        try {
            $pathEntry = $nicPaths | Where-Object { $_.Adapter.ifIndex -eq $adapter.ifIndex }
            if ($pathEntry) {
                Write-Host "    [>] Registry WOL sweep on $adapterName" -ForegroundColor Cyan
                foreach ($entry in $wolRegistryValues.GetEnumerator()) {
                    try {
                        $result = Set-RegistryValueSafe -Path $pathEntry.Path -Name $entry.Key -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $runContext -Critical -ReturnResult -OperationLabel "WOL hardening: $($entry.Key)"
                        if ($result -and $result.Success) {
                            Write-Host "      [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                        } else {
                            Write-Host "      [!] Failed to set $($entry.Key) to $($entry.Value)." -ForegroundColor Yellow
                        }
                    } catch {
                        Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName (WOL)" -ErrorRecord $_
                    }
                }
            } else {
                Write-Host "    [!] No registry path found for $adapterName; skipping registry WOL keys." -ForegroundColor Yellow
            }

            Write-Host "    [>] Driver UI WOL enforcement on $adapterName" -ForegroundColor Cyan
            $uiTargets = @(
                @{ Name = 'Wake on Magic Packet';   Value = 'Disabled' },
                @{ Name = 'Wake on Pattern Match';  Value = 'Disabled' },
                @{ Name = 'Shutdown Wake-on-LAN';   Value = 'Disabled' },
                @{ Name = 'WOL & Shutdown Link Speed'; Value = 'Not Speed Down' }
            )

            foreach ($target in $uiTargets) {
                Set-NetAdapterAdvancedPropertySafe -AdapterName $adapterName -DisplayName $target.Name -DisplayValue $target.Value
            }

            Write-Host "    [>] Verifying WOL properties via Get-NetAdapterAdvancedProperty" -ForegroundColor Cyan
            foreach ($target in $uiTargets) {
                try {
                    $current = Get-NetAdapterAdvancedProperty -Name $adapterName -DisplayName $target.Name -ErrorAction SilentlyContinue
                    if (-not $current) {
                        Write-Host "      [!] $($target.Name) not exposed on $adapterName; confirm driver limitations." -ForegroundColor Yellow
                        continue
                    }

                    $effective = $current.DisplayValue
                    if ($effective -eq $target.Value) {
                        Write-Host "      [+] $($target.Name) = $effective (OK)" -ForegroundColor Green
                        if ($logger) { Write-Log "[NetworkHardcore] $($target.Name) confirmed as $effective on $adapterName." }
                    } else {
                        Write-Host "      [!] $($target.Name) expected $($target.Value) but found $effective on $adapterName." -ForegroundColor Yellow
                    }
                } catch {
                    Invoke-ErrorHandler -Context "Verifying $($target.Name) on $adapterName" -ErrorRecord $_
                }
            }
        } catch {
            Invoke-ErrorHandler -Context "Applying Wake-on-LAN hardening on $adapterName" -ErrorRecord $_
        }
    }
}

# Description: Tests whether a given ICMP payload size passes without fragmentation.
# Parameters: PayloadSize - Size of the ICMP payload; Target - Host to ping.
# Returns: Object indicating Success/Fragmented flags plus raw output metadata.
function Test-MtuSize {
    param(
        [Parameter(Mandatory)][int]$PayloadSize,
        [string]$Target = '1.1.1.1'
    )
    try {
        $cmd = "ping -n 1 -w 1500 -f -l $PayloadSize $Target"
        $pingResult = & cmd.exe /c $cmd 2>&1
        $successExit = $LASTEXITCODE -eq 0
        $successTtl = $pingResult -match '(?i)ttl='
        $fragmented = ($pingResult -match '(?i)Packet needs to be fragmented but DF set')

        return [pscustomobject]@{
            Success      = ($successExit -and $successTtl)
            Fragmented   = $fragmented
            RawOutput    = $pingResult
            ExitCode     = $LASTEXITCODE
        }
    } catch {
        Invoke-ErrorHandler -Context "Testing MTU payload size $PayloadSize" -ErrorRecord $_
        return [pscustomobject]@{ Success = $false; Fragmented = $false; RawOutput = $null; ExitCode = $null }
    }
}

# Description: Performs a binary search to discover the optimal MTU for the target host.
# Parameters: Target - Hostname or IP used for MTU discovery.
# Returns: Integer MTU size when successful, otherwise null.
function Find-OptimalMtu {
    param(
        [string]$Target = '1.1.1.1'
    )
    try {
        $buildNumber = [Environment]::OSVersion.Version.Build
        if ($buildNumber -lt 16299) {
            $fallbackMtu = 1500
            Write-Host "  [ ] Advanced MTU discovery requires Windows 10 Build 16299 or later. Detected build $buildNumber; applying safe default MTU $fallbackMtu." -ForegroundColor Gray
            return [pscustomobject]@{ Mtu = $fallbackMtu; WasFallback = $true; SkippedReason = "Build $buildNumber below 16299" }
        }

        $getDefaultGateway = {
            try {
                $gateways = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty NextHop -ErrorAction SilentlyContinue
                return ($gateways | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -Unique | Select-Object -First 1)
            } catch {
                return $null
            }
        }

        $getDnsTargets = {
            try {
                $dnsEntries = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
                return ($dnsEntries | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
            } catch {
                return @()
            }
        }

        $testBasicPing = {
            param($probeTarget)
            $probeOutput = & cmd.exe /c "ping -n 1 -w 1200 -f -l 1400 $probeTarget" 2>&1
            return @{
                Success = ($LASTEXITCODE -eq 0 -and $probeOutput -match '(?i)ttl=')
                TimedOut = ($probeOutput -match '(?i)timed out')
                Raw     = $probeOutput
            }
        }

        $selectedTarget = $null
        $gateway = & $getDefaultGateway
        $dnsCandidates = & $getDnsTargets
        $candidateTargets = New-Object System.Collections.Generic.List[string]
        $addCandidate = {
            param($value)
            if ($null -ne $value -and "$value" -ne '') { $candidateTargets.Add("$value") | Out-Null }
        }

        & $addCandidate $Target
        & $addCandidate $gateway
        & $addCandidate '8.8.8.8'
        & $addCandidate '1.1.1.1'
        foreach ($dns in $dnsCandidates) { & $addCandidate $dns }
        $candidateTargets = $candidateTargets | Select-Object -Unique

        $baseSuccess = $false
        foreach ($candidate in $candidateTargets) {
            $probe = & $testBasicPing $candidate
            if ($probe.Success) {
                if ($candidate -ne $Target) {
                    Write-Host "  [i] Switching MTU probe target to $candidate after connectivity probe failure." -ForegroundColor Cyan
                }
                $selectedTarget = $candidate
                $baseSuccess = $true
                break
            }

            if (-not $probe.TimedOut -and $candidate -eq $Target -and $gateway) {
                Write-Host "  [!] Default target $Target refused MTU probe; trying gateway $gateway." -ForegroundColor Yellow
            }
        }

        if (-not $baseSuccess) {
            Write-Host "  [!] ISP/Router blocks DF packets; using safe MTU fallback of 1500." -ForegroundColor Yellow
            return [pscustomobject]@{ Mtu = 1500; WasFallback = $true }
        }

        $low = 1200
        $high = 1472 # 1500 - 28 bytes for ICMP/IPv4 headers
        $best = $low
        $step = 1
        $success = $false

        while ($low -le $high) {
            $mid = [int](($low + $high) / 2)
            $mtuCandidate = $mid + 28
            Write-Host "  [>] MTU test step ${step}: payload $mid bytes (candidate MTU $mtuCandidate)" -ForegroundColor Cyan
            $testResult = Test-MtuSize -PayloadSize $mid -Target $selectedTarget
            if ($testResult.Success) {
                $best = $mid
                $success = $true
                $low = $mid + 1
                Write-Host "      ✓ Success, raising floor to $low" -ForegroundColor Green
            } else {
                if ($testResult.Fragmented) {
                    $high = $mid - 1
                    Write-Host "      x Fragmentation detected, lowering ceiling to $high" -ForegroundColor Yellow
                } else {
                    Write-Host "      x Ping failed without fragmentation (code $($testResult.ExitCode)); stopping probe." -ForegroundColor Yellow
                    break
                }
            }
            $step++
        }

        if (-not $success) {
            $fallbackMtu = 1500
            Write-Host "  [!] No successful MTU probe responses. Using safe default $fallbackMtu" -ForegroundColor Yellow
            return [pscustomobject]@{ Mtu = $fallbackMtu; WasFallback = $true }
        }

        $mtu = $best + 28
        Write-Host "  [+] Optimal MTU discovered: $mtu bytes" -ForegroundColor Green
        return [pscustomobject]@{ Mtu = $mtu; WasFallback = $false }
    } catch {
        Invoke-ErrorHandler -Context 'Discovering optimal MTU' -ErrorRecord $_
        return $null
    }
}

# Description: Applies a specified MTU to a collection of adapters.
# Parameters: Mtu - MTU value to set; Adapters - Target adapters.
# Returns: None.
function Invoke-MtuToAdapters {
    param(
        [Parameter(Mandatory)][int]$Mtu,
        [System.Collections.IEnumerable]$Adapters
    )
    foreach ($adapter in $Adapters) {
        try {
            Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -NlMtu $Mtu -AddressFamily IPv4 -ErrorAction Stop | Out-Null
            Write-Host "  [+] MTU $Mtu applied to $($adapter.Name) (IPv4)." -ForegroundColor Green
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "[NetworkHardcore] MTU set to $Mtu on $($adapter.Name) (IPv4)."
            }
        } catch {
            Invoke-ErrorHandler -Context "Applying MTU to $($adapter.Name)" -ErrorRecord $_
        }
    }
}

# Description: Estimates hardware age in years based on BIOS release date.
# Parameters: None.
# Returns: Integer years when available, otherwise null.
function Get-HardwareAgeYears {
    try {
        $tryParseDate = {
            param($value)
            if (-not $value) { return $null }

            try {
                return [Management.ManagementDateTimeConverter]::ToDateTime($value)
            } catch { }

            $cleaned = ("$value") -replace '[^\d/:.\+\-\s]', ''
            if ($cleaned -and $cleaned -ne $value) { $value = $cleaned }

            $formats = @(
                'yyyyMMddHHmmss.ffffff+000',
                'yyyyMMddHHmmss',
                'yyyyMMdd',
                'MM/dd/yy',
                'MM/dd/yyyy',
                'dd/MM/yyyy',
                'yyyy-MM-dd'
            )

            foreach ($fmt in $formats) {
                try {
                    $candidate = $null
                    if ([DateTime]::TryParseExact($value, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$candidate)) {
                        return $candidate
                    }
                } catch { }
            }

            try {
                $fallback = $null
                if ([DateTime]::TryParse($value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$fallback)) {
                    return $fallback
                }
            } catch { }

            return $null
        }

        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $releaseDateRaw = $bios.ReleaseDate
        $parsedDate = & $tryParseDate $releaseDateRaw

        if (-not $parsedDate) {
            try {
                $regBios = Get-ItemProperty -Path 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\BIOS' -Name 'BIOSReleaseDate' -ErrorAction Stop
                $parsedDate = & $tryParseDate $regBios.BIOSReleaseDate
            } catch { }
        }

        if (-not $parsedDate) {
            try {
                $installReg = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name 'InstallDate' -ErrorAction Stop
                $installValue = $installReg.InstallDate
                if ($installValue -is [int] -or $installValue -is [long]) {
                    $parsedDate = [DateTimeOffset]::FromUnixTimeSeconds([int64]$installValue).DateTime
                } else {
                    $parsedDate = & $tryParseDate $installValue
                }
            } catch { }
        }

        if (-not $parsedDate) { return $null }
        $years = ((Get-Date) - $parsedDate).TotalDays / 365
        return [int][Math]::Round($years, 0)
    } catch {
        Invoke-ErrorHandler -Context 'Determining hardware age' -ErrorRecord $_
        return $null
    }
}

# Description: Suggests core affinity ranges for network IRQs to improve latency.
# Parameters: None.
# Returns: None.
function Suggest-NetworkIrqCores {
    try {
        $logical = [Environment]::ProcessorCount
        $half = [int][Math]::Ceiling($logical / 2)
        $range = "0-$(if ($half -gt 0) { $half - 1 } else { 0 })"
        Write-Host "  [i] Suggestion: Pin network IRQs to early cores (e.g., $range) for lowest latency." -ForegroundColor Cyan
    } catch {
        Invoke-ErrorHandler -Context 'Suggesting IRQ core distribution' -ErrorRecord $_
    }
}

# Description: Configures the TCP congestion provider, preferring BBR when available.
# Parameters: None.
# Returns: None. Writes status messages for chosen provider.
function Set-TcpCongestionProvider {
    try {
        $osVersion = [System.Environment]::OSVersion.Version
        $buildNumber = $osVersion.Build
        if ($osVersion.Major -lt 10 -or $buildNumber -lt 16299) {
            Write-Host "  [ ] Modern congestion control requires Windows 10 Build 16299 or later. Detected build $buildNumber; skipping congestion provider changes." -ForegroundColor Gray
            return
        }

        $supplemental = $null
        try {
            $supplemental = netsh int tcp show supplemental 2>&1
        } catch {
            Invoke-ErrorHandler -Context 'Checking supplemental congestion providers' -ErrorRecord $_
        }

        $bbrAvailable = $false
        if ($supplemental) {
            $bbrAvailable = $supplemental -match '(?i)bbr'
        }

        if ($bbrAvailable -and (Get-Confirmation "Enable experimental BBR congestion control?" 'n')) {
            try {
                netsh int tcp set global congestionprovider=bbr | Out-Null
                Write-Host "  [+] TCP congestion provider set to BBR (experimental, favors throughput and latency)." -ForegroundColor Green
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "[NetworkHardcore] TCP congestion provider set to BBR." }
                return
            } catch {
                Invoke-ErrorHandler -Context 'Setting TCP congestion provider to BBR' -ErrorRecord $_
            }
        }

        Write-Host "  [i] Defaulting to stable CUBIC congestion control." -ForegroundColor Cyan
        try {
            netsh int tcp set global congestionprovider=cubic | Out-Null
            Write-Host "  [+] TCP congestion provider set to CUBIC." -ForegroundColor Green
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "[NetworkHardcore] TCP congestion provider set to CUBIC." }
        } catch {
            Invoke-ErrorHandler -Context 'Setting TCP congestion provider to CUBIC' -ErrorRecord $_
        }
    } catch {
        Invoke-ErrorHandler -Context 'Evaluating TCP congestion provider' -ErrorRecord $_
    }
}

# Description: Applies advanced network optimizations including registry, driver, MTU, and congestion tweaks.
# Parameters: Context - Optional run context for reboot tracking.
# Returns: None. Sets reboot flag due to extensive changes.
function Invoke-NetworkTweaksHardcore {
    param(
        [object]$Context
    )
    Write-Section "Network Tweaks: Hardcore (Competitive Gaming)"
    Write-Host "  [!] Warning: MTU discovery will send test packets and adapters may reset, causing temporary disconnects." -ForegroundColor Yellow
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $backupFile = "C:\\ProgramData\\Scynesthesia\\network_backup.json"
    if (-not (Get-Command Save-NetworkBackupState -ErrorAction SilentlyContinue)) {
        $message = "Backup helper not available; hardcore network tweaks require a backup. Aborting."
        Write-Host "  [!] $message" -ForegroundColor Yellow
        if ($logger) { Write-Log "[NetworkHardcore] $message" -Level 'Error' }
        return
    }

    if (-not (Get-Confirmation "Hardcore network tweaks require a fresh network backup. Create/refresh it now?" 'y')) {
        $message = "Hardcore network tweaks aborted because the required backup was declined."
        Write-Host "  [!] $message" -ForegroundColor Yellow
        if ($logger) { Write-Log "[NetworkHardcore] $message" -Level 'Warning' }
        return
    }

    $backupResult = $null
    try {
        Write-Host "  [i] Creating mandatory network backup at $backupFile..." -ForegroundColor Gray
        $backupResult = Save-NetworkBackupState
    } catch {
        Invoke-ErrorHandler -Context 'Saving network backup before hardcore tweaks' -ErrorRecord $_
    }

    $hardStop = ($backupResult -and $backupResult.PSObject.Properties['HardStop'] -and $backupResult.HardStop)
    if ($hardStop) {
        $message = "Hard Stop: Unable to create the required network backup. Hardcore tweaks will not proceed."
        Write-Host "  [!] $message" -ForegroundColor Red
        if ($logger) {
            Write-Log "[NetworkHardcore] $message" -Level 'Error' -Data @{ BackupFile = $backupFile }
        }
        return
    }

    $backupSuccess = ($backupResult -and $backupResult.PSObject.Properties['Success'] -and $backupResult.Success)
    if (-not $backupSuccess) {
        $message = "Hardcore network tweaks aborted because the network backup did not complete successfully."
        Write-Host "  [!] $message" -ForegroundColor Yellow
        if ($logger) {
            Write-Log "[NetworkHardcore] $message" -Level 'Error' -Data @{
                BackupFile = $backupFile
                RegRollbackSnippetPrepared = ($backupResult -and $backupResult.PSObject.Properties['RegRollbackSnippet'] -and $backupResult.RegRollbackSnippet)
            }
        }
        return
    }

    if ($null -eq $Context) {
        $Context = New-RunContext
    }

    $failureTracker = New-RegistryFailureTracker -Name 'Network (Hardcore)'

    Set-TcpIpAdvancedParameters -Context $Context -FailureTracker $failureTracker
    if ($failureTracker.Abort) { Write-RegistryFailureSummary -Tracker $failureTracker; return }
    Set-NetworkThrottlingHardcore -Context $Context
    Set-ServicePriorities -Context $Context -FailureTracker $failureTracker
    if ($failureTracker.Abort) { Write-RegistryFailureSummary -Tracker $failureTracker; return }
    Set-WinsockOptimizations -Context $Context -FailureTracker $failureTracker
    if ($failureTracker.Abort) { Write-RegistryFailureSummary -Tracker $failureTracker; return }
    Optimize-LanmanServer -Context $Context
    Set-NetshHardcoreGlobals -Context $Context

    $adapters = Get-EligibleNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No active physical adapters detected." -ForegroundColor Yellow
        return
    }

    $primary = Get-PrimaryNetAdapter
    if (-not $primary) {
        Write-Host "  [!] Unable to determine primary adapter; using all adapters for tweaks." -ForegroundColor Yellow
        $primaryAdapters = $adapters
    } else {
        $primaryAdapters = @($primary)
        $isPrimaryWifi = $false
        try {
            $medium = $primary | Select-Object -ExpandProperty NdisPhysicalMedium -ErrorAction SilentlyContinue
            if ($medium -and $medium -match '(?i)802\\.11|wireless') {
                $isPrimaryWifi = $true
            } elseif ($primary.InterfaceDescription -match '(?i)(wi-?fi|wireless|802\\.11)') {
                $isPrimaryWifi = $true
            }
        } catch { }
        $parsedSpeed = Convert-LinkSpeedToBits -LinkSpeed $primary.LinkSpeed
        if ($null -eq $parsedSpeed -or $parsedSpeed -le 0) {
            $speedLabel = 'Unknown speed'
        } else {
            $speedMbps = [math]::Round($parsedSpeed / 1e6, 2)
            $speedLabel = if ($speedMbps -ge 1000) {
                "{0} Gbps" -f ([math]::Round($speedMbps / 1000, 2))
            } else {
                "{0} Mbps" -f $speedMbps
            }
        }
        Write-Host "  [i] Primary adapter detected: $($primary.Name) ($speedLabel)." -ForegroundColor Cyan
        if ($isPrimaryWifi) {
            $wifiWarning = "Primary adapter '$($primary.Name)' appears to be wireless; disabling offloads can destabilize some Wi-Fi drivers."
            Write-Host "  [!] $wifiWarning" -ForegroundColor Yellow
            if ($logger) { Write-Log "[NetworkHardcore] $wifiWarning" -Level 'Warning' }
            if (-not (Get-Confirmation "Continue with hardcore network tweaks on a Wi-Fi adapter?" 'n')) {
                Write-Host "  [ ] Hardcore network tweaks canceled for Wi-Fi adapter safety." -ForegroundColor DarkGray
                return
            }
        }
    }

    $legacyAssessments = @()
    foreach ($adapter in $adapters) {
        $assessment = Get-NicLegacyDriverAssessment -Adapter $adapter
        if ($assessment) {
            $legacyAssessments += $assessment
        }
    }
    $legacyFlagged = $legacyAssessments | Where-Object { $_.IsLegacy }
    $legacyInstanceIds = $legacyFlagged | Where-Object { $_.InstanceId } | Select-Object -ExpandProperty InstanceId -Unique
    foreach ($item in $legacyFlagged) {
        $legacyMessage = "Legacy Driver Check: $($item.Adapter.Name) flagged ($($item.Reason)). Interrupt Moderation and MSI Mode changes will be skipped for this adapter."
        Write-Host "  [!] $legacyMessage" -ForegroundColor Yellow
        if ($logger) { Write-Log "[NetworkHardcore] $legacyMessage" -Level 'Warning' }
    }

    Set-NicRegistryHardcore -Context $Context
    Set-WakeOnLanHardcore -Context $Context
    Invoke-AdvancedNetworkPipeline -Context $Context `
        -Adapters $adapters `
        -PrimaryAdapter $primary `
        -ProfileName 'Advanced Network Pipeline (Hardcore)' `
        -LoggerPrefix '[NetworkHardcore]' `
        -MsiTargets @('NIC') `
        -MsiPromptMessage "Enable MSI Mode for your NIC? Recommended on modern hardware. If you already applied MSI Mode elsewhere, you can skip this." `
        -MsiInvokeOnceId 'MSI:NIC' `
        -MsiDefaultResponse 'n' `
        -MsiSkipInstanceIds $legacyInstanceIds `
        -OffloadPromptMessage "Disable adapter offloads (RSC/LSO/Checksum) for lowest latency? Recommended for Hardcore tweaks." `
        -OffloadDefaultResponse 'y' `
        -OffloadInvokeOnceId 'Network:AdapterOffloads:Shared' `
        -InterruptModerationSkipInstanceIds $legacyInstanceIds `
        -SkipWirelessWarning | Out-Null

    if ($primaryAdapters) {
        foreach ($adapter in $primaryAdapters) {
            try {
                $rssCapabilities = Get-NetAdapterRss -Name $adapter.Name -ErrorAction SilentlyContinue
                if (-not $rssCapabilities) {
                    $linkBits = Convert-LinkSpeedToBits -LinkSpeed $adapter.LinkSpeed
                    if ($linkBits -and $linkBits -lt 1e9) {
                        $speedLabel = "{0} Mbps" -f ([math]::Round($linkBits / 1e6, 0))
                        Write-Host "  [i] RSS is a Gigabit+ feature; $($adapter.Name) is running at $speedLabel. Skipping RSS quietly." -ForegroundColor Gray
                    } else {
                        Write-Host "  [i] RSS not exposed by this hardware; skipping." -ForegroundColor Gray
                    }
                    continue
                }

                Set-NetAdapterRss -Name $adapter.Name -Profile Closest -ErrorAction Stop | Out-Null
                Write-Host "  [+] RSS profile set to Closest on $($adapter.Name)." -ForegroundColor Green
                if ($logger) { Write-Log "[NetworkHardcore] RSS profile set to Closest on $($adapter.Name)." }
            } catch {
                Invoke-ErrorHandler -Context "Configuring RSS on $($adapter.Name)" -ErrorRecord $_
            }
        }
    }

    Suggest-NetworkIrqCores

    try {
        netsh int tcp set global ecncapability=disabled | Out-Null
        Write-Host "  [+] ECN capability disabled." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] ECN capability disabled." }
    } catch {
        Invoke-ErrorHandler -Context 'Disabling ECN capability' -ErrorRecord $_
    }

    try {
        netsh int tcp set global timestamps=disabled | Out-Null
        Write-Host "  [+] TCP timestamps disabled." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] TCP timestamps disabled." }
    } catch {
        Invoke-ErrorHandler -Context 'Disabling TCP timestamps' -ErrorRecord $_
    }

    try {
        netsh int tcp set global initialrto=2000 | Out-Null
        Write-Host "  [+] Initial RTO set to 2000ms." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] InitialRTO set to 2000ms." }
    } catch {
        Invoke-ErrorHandler -Context 'Setting InitialRTO' -ErrorRecord $_
    }

    $ageYears = Get-HardwareAgeYears
    $ageKnown = ($null -ne $ageYears -and "$ageYears" -ne '')
    $autotuneLevel = if ($ageYears -and $ageYears -gt 6) { 'highlyrestricted' } else { 'disabled' }
    $ageLabel = if (-not $ageKnown) {
        'Unknown'
    } elseif ($ageYears -le 0) {
        'Less than a year'
    } else {
        "$ageYears years"
    }
    $ageSummaryLabel = if (-not $ageKnown) { 'Unknown' } elseif ($ageYears -le 0) { 'Less than a year' } else { "~$ageYears years" }
    if ($ageYears -ne $null) {
        $reason = if ($autotuneLevel -eq 'highlyrestricted') {
            "Older hardware ($ageSummaryLabel) detected; using safer autotuning."
        } else {
            "Modern hardware ($ageSummaryLabel) detected; disabling autotuning for latency."
        }
        Write-Host "  [i] $reason" -ForegroundColor Cyan
    }
    try {
        netsh int tcp set global autotuninglevel=$autotuneLevel | Out-Null
        Write-Host "  [+] Network autotuning set to $autotuneLevel (hardware age: $ageLabel)." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] Autotuning level set to $autotuneLevel (hardware age: $ageLabel)." }
    } catch {
        Invoke-ErrorHandler -Context 'Setting TCP autotuning level' -ErrorRecord $_
    }

    $mtuResult = Find-OptimalMtu
    if ($mtuResult -and $mtuResult.Mtu) {
        if ($mtuResult.WasFallback) {
            Write-Host "  [ ] Applying safe MTU fallback of $($mtuResult.Mtu) to avoid fragmentation issues." -ForegroundColor Gray
        }
        Invoke-MtuToAdapters -Mtu $mtuResult.Mtu -Adapters @($adapters)
    }

    Set-TcpCongestionProvider

    Write-RegistryFailureSummary -Tracker $failureTracker
    if ($failureTracker -and $failureTracker.Abort) { return }

    Write-Host "  [+] Hardcore network tweaks complete." -ForegroundColor Green
    Set-NeedsReboot -Context $Context | Out-Null
}

Export-ModuleMember -Function Invoke-NetworkTweaksHardcore
