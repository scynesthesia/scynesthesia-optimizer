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
# Description: Retrieves active physical network adapters excluding virtual or VPN interfaces.
# Parameters: None.
# Returns: Collection of adapter objects; returns empty array on failure.
function Get-PhysicalNetAdapters {
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object {
                $_.Status -ne 'Disabled' -and
                $_.InterfaceDescription -notmatch '(?i)virtual|vmware|hyper-v|loopback|vpn|tap|wireguard|bluetooth'
            }
        return $adapters
    } catch {
        Invoke-ErrorHandler -Context 'Retrieving network adapters' -ErrorRecord $_
        return @()
    }
}

# Description: Maps physical adapters to their registry class paths for advanced tweaks.
# Parameters: None.
# Returns: Collection of objects containing adapter references and registry paths.
function Get-NicRegistryPaths {
    return Get-SharedNicRegistryPaths -AdapterResolver { Get-PhysicalNetAdapters }
}

# Description: Flushes the DNS cache to clear resolver entries.
# Parameters: None.
# Returns: None.
function Invoke-NetworkFlush {
    Write-Host "  [+] Flushing DNS cache" -ForegroundColor Gray
    try {
        ipconfig /flushdns | Out-Null
    } catch {
        Invoke-ErrorHandler -Context 'Flushing DNS cache' -ErrorRecord $_
    }
}

# Description: Performs a Winsock reset to rebuild network stack defaults.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Sets reboot flag on the provided context when reset runs.
function Invoke-NetworkFullReset {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Host "  [+] Resetting Winsock catalog" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        netsh winsock reset | Out-Null
        Write-Host "      Reset complete. A reboot is recommended." -ForegroundColor Yellow
        Set-RebootRequired -Context $Context | Out-Null
        if ($logger) {
            Write-Log "[Network] Executed 'netsh winsock reset'."
        }
    } catch {
        Invoke-ErrorHandler -Context 'Resetting Winsock' -ErrorRecord $_
    }
}

# Description: Sets Cloudflare DNS servers on eligible adapters after prompting when manual DNS exists.
# Parameters: None.
# Returns: None.
function Set-NetworkDnsSafe {
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $adapters = Get-PhysicalNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for DNS update." -ForegroundColor Yellow
        return
    }

    foreach ($adapter in $adapters) {
        try {
            $dnsInfo = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
            $isManual = $dnsInfo.AddressOrigin -eq 'Static'
            if ($isManual) {
                if (-not (Get-Confirmation "Adapter '$($adapter.Name)' already has manual DNS. Overwrite with Cloudflare?" 'n')) {
                    Write-Host "  [ ] DNS left unchanged for $($adapter.Name)." -ForegroundColor Gray
                    continue
                }
            }

            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @('1.1.1.1','1.0.0.1') -ErrorAction Stop
            Write-Host "  [+] Cloudflare DNS applied to $($adapter.Name)." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Network] DNS set to Cloudflare on '$($adapter.Name)' (1.1.1.1/1.0.0.1)."
            }
        } catch {
            Invoke-ErrorHandler -Context "Setting DNS on $($adapter.Name)" -ErrorRecord $_
        }
    }
}

# Description: Configures TCP autotuning level to normal for compatibility.
# Parameters: None.
# Returns: None.
function Set-TcpAutotuningNormal {
    Write-Host "  [+] Setting TCP autotuning to 'normal'" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        netsh int tcp set global autotuninglevel=normal | Out-Null
        if ($logger) {
            Write-Log "[Network] TCP autotuning set to normal." 
        }
    } catch {
        Invoke-ErrorHandler -Context 'Configuring TCP autotuning' -ErrorRecord $_
    }
}

# Description: Prefers IPv4 addressing without disabling IPv6.
# Parameters: FailureTracker - Optional tracker used for aggregating critical registry failures; Context - Run context for reboot tracking.
# Returns: None. Sets reboot flag on the provided context after registry update.
function Set-IPvPreferenceIPv4First {
    param(
        [pscustomobject]$FailureTracker,
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Host "  [+] Preferring IPv4 over IPv6 (without disabling IPv6)" -ForegroundColor Gray
    try {
        $result = Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0x20 -Critical -ReturnResult -Context $Context -OperationLabel 'Prefer IPv4 over IPv6'
        $abort = Register-RegistryResult -Tracker $FailureTracker -Result $result -Critical
        if ($result -and $result.Success) {
            Set-RebootRequired -Context $Context | Out-Null
            Write-Host "      [>] Preference recorded. Reboot recommended." -ForegroundColor Yellow
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "[Network] IPv4 preference set (DisabledComponents=0x20)."
            }
        } else {
            Write-Host "      [!] Failed to record IPv4 preference in the registry." -ForegroundColor Yellow
        }
        if ($abort) {
            Write-RegistryFailureSummary -Tracker $FailureTracker
            return
        }
    } catch {
        Invoke-ErrorHandler -Context 'Setting IPv4 preference' -ErrorRecord $_
    }
}

# Description: Disables Link-Local Multicast Name Resolution to reduce noisy broadcasts.
# Parameters: None.
# Returns: None.
function Disable-LLMNR {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Host "  [+] Disabling LLMNR" -ForegroundColor Gray
    $result = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable LLMNR'
    if ($result -and $result.Success) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "[Network] Disabled LLMNR (EnableMulticast=0 under DNSClient policy)."
        }
    } else {
        Write-Host "  [!] Failed to disable LLMNR (permission issue?)." -ForegroundColor Yellow
    }
}

# Description: Disables NetBIOS over TCP/IP on eligible adapters.
# Parameters: None.
# Returns: None.
function Disable-NetBIOS {
    $adapters = Get-PhysicalNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for NetBIOS change." -ForegroundColor Yellow
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    foreach ($adapter in $adapters) {
        try {
            $cim = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index=$($adapter.ifIndex)" -ErrorAction Stop
            if (-not $cim) { continue }
            $result = Invoke-CimMethod -InputObject $cim -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } -ErrorAction Stop
            if ($result.ReturnValue -eq 0) {
                Write-Host "  [+] NetBIOS disabled on $($adapter.Name)." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Network] NetBIOS disabled on $($adapter.Name) via SetTcpipNetbios." 
                }
            } else {
                Write-Host "  [!] NetBIOS change on $($adapter.Name) returned code $($result.ReturnValue)." -ForegroundColor Yellow
            }
        } catch {
            Invoke-ErrorHandler -Context "Disabling NetBIOS on $($adapter.Name)" -ErrorRecord $_
        }
    }
}

# Description: Disables telemetry-related services and policies for networking.
# Parameters: None.
# Returns: None.
function Disable-NetworkTelemetry {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Host "  [+] Disabling network telemetry services" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        $result = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable network telemetry'
        if ($result -and $result.Success) {
            if ($logger) {
                Write-Log "[Network] Telemetry collection disabled (AllowTelemetry=0)."
            }
        } else {
            Write-Host "  [!] Failed to disable telemetry collection (permission issue?)." -ForegroundColor Yellow
        }
        foreach ($svc in 'DiagTrack','dmwappushservice') {
            try {
                Register-ServiceStateForRollback -Context $context -ServiceName $svc | Out-Null
                Stop-Service -Name $svc -ErrorAction SilentlyContinue
                if ($logger) {
                    Write-Log "[Network] Service '$svc' stopped for telemetry reduction."
                }
                Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                if ($logger) {
                    Write-Log "[Network] Service '$svc' startup disabled."
                }
            } catch { }
        }
    } catch {
        Invoke-ErrorHandler -Context 'Disabling telemetry' -ErrorRecord $_
    }
}

# Description: Disables Delivery Optimization downloads and service startup.
# Parameters: None.
# Returns: None.
function Disable-DeliveryOptimization {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Host "  [+] Disabling Delivery Optimization (WUDO)" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        $result = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Delivery Optimization'
        if ($result -and $result.Success) {
            if ($logger) {
                Write-Log "[Network] Delivery Optimization disabled (DODownloadMode=0)."
            }
        } else {
            Write-Host "  [!] Failed to disable Delivery Optimization (permission issue?)." -ForegroundColor Yellow
        }

        try {
            Register-ServiceStateForRollback -Context $context -ServiceName "DoSvc" | Out-Null
            Stop-Service -Name "DoSvc" -ErrorAction SilentlyContinue
            if ($logger) {
                Write-Log "[Network] Delivery Optimization service (DoSvc) stopped."
            }
            Set-Service -Name "DoSvc" -StartupType Disabled -ErrorAction SilentlyContinue
            if ($logger) {
                Write-Log "[Network] Delivery Optimization service (DoSvc) disabled."
            }
        } catch { }
    } catch {
        Invoke-ErrorHandler -Context 'Disabling Delivery Optimization' -ErrorRecord $_
    }
}

# Description: Sets reservable bandwidth policy to 0% to avoid QoS reservation overhead.
# Parameters: None.
# Returns: None.
function Set-ReservableBandwidth {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Host "  [+] Setting reservable bandwidth limit to 0%" -ForegroundColor Gray
    $result = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Set reservable bandwidth to 0%'
    if ($result -and $result.Success) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "[Network] Reservable bandwidth limit set to 0% (NonBestEffortLimit=0)."
        }
    } else {
        Write-Host "  [!] Failed to set reservable bandwidth (permission issue?)." -ForegroundColor Yellow
    }
}

# Description: Disables Remote Assistance via registry policy values.
# Parameters: None.
# Returns: None.
function Disable-RemoteAssistance {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Host "  [+] Disabling Remote Assistance" -ForegroundColor Gray
    try {
        $raResult = Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Remote Assistance (Control)'
        $tsResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Remote Assistance (Policy)'
        if ($raResult -and $raResult.Success -and $tsResult -and $tsResult.Success) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "[Network] Remote Assistance disabled (fAllowToGetHelp=0)."
            }
        } else {
            Write-Host "  [!] Remote Assistance keys could not be fully updated." -ForegroundColor Yellow
        }
    } catch {
        Invoke-ErrorHandler -Context 'Disabling Remote Assistance' -ErrorRecord $_
    }
}

# Description: Disables the Network Discovery firewall rule group.
# Parameters: None.
# Returns: None.
function Disable-NetworkDiscovery {
    Write-Host "  [+] Disabling Network Discovery firewall rules" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        netsh advfirewall firewall set rule group="Network Discovery" new enable=No | Out-Null
        if ($logger) {
            Write-Log "[Network] Network Discovery firewall group disabled via netsh."
        }
    } catch {
        Invoke-ErrorHandler -Context 'Disabling Network Discovery' -ErrorRecord $_
    }
}

# Description: Disables multimedia network throttling by setting the registry index.
# Parameters: None.
# Returns: None.
function Set-NetworkThrottling {
    param(
        [pscustomobject]$Context
    )

    Invoke-NetworkThrottlingShared -Context $Context -LoggerPrefix '[Network]' -HostMessage 'Disabling network throttling' -OperationLabel 'Disable network throttling index' -FailureMessage 'Failed to disable network throttling (permission issue?).' | Out-Null
}

# Description: Optimizes TCP acknowledgement parameters (Nagle-related) per adapter.
# Parameters: Context - Run context for reboot tracking and applied-tweak deduplication.
# Returns: None. Sets reboot flag on the provided context if registry changes occur.
function Set-NagleState {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    $adapters = Get-PhysicalNetAdapters
    $result = Invoke-NagleRegistryUpdate -Context $context -Adapters $adapters -LoggerPrefix '[Nagle]' -InvokeOnceId 'Nagle:Tcp'
    if ($result -and $result.Changed) {
        Set-RebootRequired -Context $context | Out-Null
    }
}

# Description: Sets advanced adapter properties when matching registry keywords exist.
# Parameters: Adapter - Target network adapter; Keywords - Patterns for registry keywords; Value - Desired registry value.
# Returns: None.
function Set-AdapterAdvancedPropertyIfPresent {
    param(
        [Parameter(Mandatory)][Microsoft.Management.Infrastructure.CimInstance]$Adapter,
        [Parameter(Mandatory)][string[]]$Keywords,
        [Parameter(Mandatory)][string]$Value
    )

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        $properties = Get-NetAdapterAdvancedProperty -InterfaceDescription $Adapter.InterfaceDescription -ErrorAction Stop
    } catch {
        Invoke-ErrorHandler -Context "Reading advanced properties on $($Adapter.Name)" -ErrorRecord $_
        return
    }

    foreach ($keyword in $Keywords) {
        $matches = $properties | Where-Object { $_.RegistryKeyword -like $keyword }
        foreach ($match in $matches) {
            try {
                Set-NetAdapterAdvancedProperty -InterfaceDescription $Adapter.InterfaceDescription -RegistryKeyword $match.RegistryKeyword -RegistryValue $Value -NoRestart -ErrorAction Stop
                Write-Host "  [+] Set $($match.RegistryKeyword) on $($Adapter.Name) to $Value." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Network] $($Adapter.Name): $($match.RegistryKeyword) set to $Value."
                }
            } catch {
                Invoke-ErrorHandler -Context "Setting advanced property $($match.RegistryKeyword) on $($Adapter.Name)" -ErrorRecord $_
            }
        }
    }
}

# Description: Disables Energy Efficient Ethernet features on applicable adapters.
# Parameters: None.
# Returns: None.
function Set-EnergyEfficientEthernet {
    $adapters = Get-PhysicalNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for Energy Efficient Ethernet adjustments." -ForegroundColor Yellow
        return
    }

    foreach ($adapter in $adapters) {
        Set-AdapterAdvancedPropertyIfPresent -Adapter $adapter -Keywords @('*EEE*','*EnergyEfficientEthernet*','*GreenEthernet*') -Value '0'
    }
}

# Description: Disables NIC-level power saving flags for gaming performance via registry.
# Parameters: None.
# Returns: None.
function Set-NicPowerManagementGaming {
    param(
        [pscustomobject]$Context
    )

    Write-Host "  [>] Applying NIC power management overrides" -ForegroundColor Cyan
    $nicPaths = Get-NicRegistryPaths
    if ($nicPaths.Count -eq 0) {
        Write-Host "  [!] No NIC registry paths found for gaming power tweaks." -ForegroundColor Yellow
        return
    }

    $powerFlags = @{
        '*WakeOnMagicPacket'  = '0'
        '*WakeOnPattern'      = '0'
        '*EEE'                = '0'
        'WakeOnMagicPacket'   = '0'
        'WakeOnPatternMatch'  = '0'
        'WolShutdownLinkSpeed'= '0'
        'AllowIdleIrp'        = '0'
        'DeepSleepMode'       = '0'
        'EnableGreenEthernet' = '0'
    }

    Invoke-NicPowerRegistryTweaks -Context (Get-RunContext -Context $Context) -NicPaths $nicPaths -Values $powerFlags -LoggerPrefix '[Network]' -InvokeOnceId 'NicPower:Shared' -CleanupInterfaceNoise | Out-Null
}

# Description: Enables Receive Side Scaling (RSS) on supported adapters without a restart.
# Parameters: None.
# Returns: None.
function Enable-RSS {
    $adapters = Get-PhysicalNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for RSS." -ForegroundColor Yellow
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) {
        try {
            $rssData = Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetAdapterRssSettingData' -Filter "Name='$($adapter.Name)'" -ErrorAction SilentlyContinue
        } catch {
            Invoke-ErrorHandler -Context "Checking RSS support on $($adapter.Name)" -ErrorRecord $_
            continue
        }

        if (-not $rssData) {
            Write-Host "  [i] RSS not supported/configurable for adapter '$($adapter.Name)'. Skipping RSS tweak." -ForegroundColor DarkGray
            if ($logger) {
                Write-Log "[Network] RSS not supported/configurable for adapter '$($adapter.Name)'." -Level 'Warning'
            }
            continue
        }

        try {
            Enable-NetAdapterRss -Name $adapter.Name -ErrorAction Stop | Out-Null
            Write-Host "  [+] RSS enabled on $($adapter.Name)." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Network] RSS enabled on $($adapter.Name)."
            }
        } catch {
            Invoke-ErrorHandler -Context "Enabling RSS on $($adapter.Name)" -ErrorRecord $_
        }
    }
}

# Description: Disables interrupt moderation on adapters supporting the setting.
# Parameters: None.
# Returns: None.
function Set-InterruptModeration {
    $adapters = Get-PhysicalNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for interrupt moderation changes." -ForegroundColor Yellow
        return
    }

    foreach ($adapter in $adapters) {
        Set-AdapterAdvancedPropertyIfPresent -Adapter $adapter -Keywords @('*InterruptModeration*') -Value '0'
    }
}

# Description: Applies safe network tweaks focused on stability and privacy.
# Parameters: Context - Run context for reboot tracking.
# Returns: None.
function Invoke-NetworkTweaksSafe {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Network tweaks (Safe profile)"
    $tracker = New-RegistryFailureTracker -Name 'Network'
    Invoke-NetworkFlush

    if (Get-Confirmation "Reset Winsock (requires reboot)?" 'n') {
        Invoke-NetworkFullReset -Context $Context
    } else {
        Write-Host "  [ ] Winsock left unchanged." -ForegroundColor Gray
    }

    if (Get-Confirmation "Use Cloudflare DNS (1.1.1.1 / 1.0.0.1) on all adapters?" 'y') {
        Set-NetworkDnsSafe
    } else {
        Write-Host "  [ ] DNS settings left unchanged." -ForegroundColor Gray
    }

    Set-TcpAutotuningNormal
    Set-IPvPreferenceIPv4First -FailureTracker $tracker -Context $Context
    if ($tracker.Abort) {
        Write-RegistryFailureSummary -Tracker $tracker
        return
    }
    Write-RegistryFailureSummary -Tracker $tracker
}

# Description: Applies aggressive network tweaks including autotuning and disabled discovery.
# Parameters: Context - Optional run context for permission tracking.
# Returns: None. May prompt for backup before changes.
function Invoke-NetworkTweaksAggressive {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Section "Network tweaks (Aggressive profile)"
    Disable-LLMNR -Context $context
    Disable-DeliveryOptimization -Context $context

    if (Get-Confirmation "Disable NetBIOS over TCP/IP? This may break legacy LAN shares and printers." 'n') {
        Disable-NetBIOS
    } else {
        Write-Host "  [ ] NetBIOS left enabled." -ForegroundColor Gray
    }

    Disable-NetworkTelemetry -Context $context
    Set-ReservableBandwidth -Context $context

    if (Get-Confirmation "Disable Remote Assistance?" 'y') {
        Disable-RemoteAssistance -Context $context
    } else {
        Write-Host "  [ ] Remote Assistance left enabled." -ForegroundColor Gray
    }

    if (Get-Confirmation "Disable Network Discovery entirely? You will stop seeing PCs and shared folders automatically on the network." 'n') {
        Disable-NetworkDiscovery
    } else {
        Write-Host "  [ ] Network Discovery left enabled." -ForegroundColor Gray
    }
}

# Description: Applies gaming-focused network tweaks for lower latency.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. May set reboot flag for certain changes.
function Invoke-NetworkTweaksGaming {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Network tweaks (Gaming profile)"
    Write-Host "  [i] Applying hardware power optimizations..." -ForegroundColor Gray
    Set-NicPowerManagementGaming -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Set-NetworkThrottling -Context $Context
    Set-NagleState -Context $Context
    Set-EnergyEfficientEthernet
    Enable-RSS

    if (Get-Confirmation "Disable interrupt moderation for lowest latency? (Higher CPU usage)" 'n') {
        Set-InterruptModeration
    } else {
        Write-Host "  [ ] Interrupt moderation left unchanged." -ForegroundColor Gray
    }

    Invoke-AdvancedNetworkPipeline -Context $Context -AdapterResolver { Get-PhysicalNetAdapters } -ProfileName 'Advanced Network Pipeline (Gaming)' -LoggerPrefix '[Network]' -MsiTargets @('NIC') -MsiPromptMessage "Enable MSI Mode for your NIC? Recommended on modern hardware. If you already applied MSI Mode elsewhere, you can skip this." -MsiInvokeOnceId 'MSI:NIC' -MsiDefaultResponse 'n' -OffloadPromptMessage "Disable adapter offloads (RSC/LSO/Checksum) for lower latency? May reduce throughput on some adapters." -OffloadDefaultResponse 'n' -OffloadInvokeOnceId 'Network:AdapterOffloads:Shared' | Out-Null

    if (Get-Confirmation "Apply advanced TCP tweaks (Chimney Offload / DCA)? These are experimental and may be unstable on older hardware or uncommon drivers." 'n') {
        try {
            $safePath = $env:SystemRoot
            if (-not $safePath) { $safePath = $env:WINDIR }
            if (-not $safePath) { $safePath = 'C:\Windows' }
            Register-NetshGlobalsForRollback -Context $Context | Out-Null

            Push-Location -Path $safePath
            try {
                netsh int tcp set global chimney=disabled | Out-Null
                Write-Host "  [+] TCP Chimney Offload disabled." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Network] TCP Chimney Offload set to disabled."
                }

                netsh int tcp set global dca=enabled | Out-Null
                Write-Host "  [+] Direct Cache Access enabled." -ForegroundColor Green
                if ($logger) {
                    Write-Log "[Network] Direct Cache Access set to enabled."
                }
            } finally {
                Pop-Location -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "  [!] Could not apply Chimney/DCA tweaks: $($_.Exception.Message)" -ForegroundColor Yellow
            if ($logger) {
                Write-Log "[Network] Could not apply Chimney/DCA tweaks: $($_.Exception.Message)" -Level 'Warning'
            }
        }
    } else {
        Write-Host "  [ ] Chimney/DCA tweaks skipped." -ForegroundColor Gray
    }
}

# Parses netsh TCP global output into a standardized map for rollback/restore.
function Convert-NetshGlobalsFromText {
    [CmdletBinding()]
    param(
        [string]$RawText
    )

    $result = @{}
    if (-not $RawText) { return $result }

    $text = if ($RawText -is [string[]]) { $RawText -join "`n" } else { [string]$RawText }
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $patterns = @{
        Chimney            = 'Chimney Offload State\s*:\s*(?<value>.+)'
        Dca                = 'Direct Cache Access.*:\s*(?<value>.+)'
        Autotuninglevel    = 'Receive Window Auto-Tuning Level\s*:\s*(?<value>.+)'
        CongestionProvider = '(Add-On Congestion Control Provider|Congestion Provider)\s*:\s*(?<value>.+)'
        EcnCapability      = 'ECN Capability\s*:\s*(?<value>.+)'
        Timestamps         = 'RFC 1323 Timestamps\s*:\s*(?<value>.+)'
        InitialRto         = 'Initial RTO\s*:\s*(?<value>.+)'
    }

    foreach ($key in $patterns.Keys) {
        $match = [regex]::Match($text, $patterns[$key], $regexOptions)
        if (-not $match.Success) { continue }
        $value = $match.Groups['value'].Value.Trim()
        if ($key -eq 'InitialRto') {
            $numeric = [regex]::Match($value, '(?<num>\d+)')
            if ($numeric.Success) { $value = $numeric.Groups['num'].Value }
        }
        if ($value -and -not $result.ContainsKey($key)) {
            $result[$key] = $value
        }
    }

    return $result
}

# Records the current netsh TCP global state into the rollback tracker.
function Register-NetshGlobalsForRollback {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        [string]$RawText
    )

    if (-not $Context) { return @{} }
    $map = Convert-NetshGlobalsFromText -RawText $RawText
    if (-not $map -or $map.Count -eq 0) {
        try {
            $probe = netsh int tcp show global 2>&1
            $map = Convert-NetshGlobalsFromText -RawText ($probe -join "`n")
        } catch {
            return @{}
        }
    }

    foreach ($key in $map.Keys) {
        try { Add-NetshRollbackAction -Context $Context -Setting $key -Value $map[$key] | Out-Null } catch { }
    }

    return $map
}

# Captures the current startup type and runtime state for a service into the rollback tracker.
function Register-ServiceStateForRollback {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        [string]$ServiceName
    )

    if (-not $Context -or [string]::IsNullOrWhiteSpace($ServiceName)) { return $null }
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) { return $null }
        $snapshot = [pscustomobject]@{
            Name        = $svc.Name
            StartupType = $svc.StartType.ToString()
            Status      = $svc.Status.ToString()
        }
        Add-ServiceRollbackAction -Context $Context -ServiceName $svc.Name -StartupType $snapshot.StartupType -Status $snapshot.Status | Out-Null
        return $snapshot
    } catch {
        return $null
    }
}

# Attempts to restore service startup types/runtime states from backup entries.
function Restore-ServiceStatesFromBackup {
    [CmdletBinding()]
    param(
        [array]$ServiceStates,
        $Logger
    )

    if (-not $ServiceStates) { return 0 }
    $restored = 0
    foreach ($entry in $ServiceStates) {
        $name = $entry.Name
        if (-not $name) { continue }
        $startup = $entry.StartupType
        $status = $entry.Status
        try {
            if ($startup) {
                Set-Service -Name $name -StartupType $startup -ErrorAction Stop
            }
            if ($status) {
                if ($status -eq 'Running') {
                    Start-Service -Name $name -ErrorAction SilentlyContinue
                } elseif ($status -eq 'Stopped') {
                    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                }
            }
            $restored++
            if ($Logger) {
                Write-Log "[Rollback] Restored service $name to startup '$startup' (status: $status)."
            }
        } catch { }
    }

    return $restored
}

# Applies netsh global settings from a saved map.
function Restore-NetshGlobalsFromMap {
    [CmdletBinding()]
    param(
        [hashtable]$GlobalsMap,
        $Logger
    )

    if (-not $GlobalsMap) { return 0 }

    $applied = 0
    $commandMap = @{
        Chimney            = { param($value) "chimney=$value" }
        Dca                = { param($value) "dca=$value" }
        Autotuninglevel    = { param($value) "autotuninglevel=$value" }
        CongestionProvider = { param($value) "congestionprovider=$value" }
        EcnCapability      = { param($value) "ecncapability=$value" }
        Timestamps         = { param($value) "timestamps=$value" }
        InitialRto         = { param($value) "initialrto=$value" }
    }

    foreach ($entry in $GlobalsMap.GetEnumerator()) {
        $key = $entry.Key
        if (-not $commandMap.ContainsKey($key)) { continue }
        $rawValue = if ($entry.Value -ne $null) { "$($entry.Value)".Trim() } else { $null }
        if (-not $rawValue) { continue }
        $normalized = if ($key -eq 'InitialRto') {
            $match = [regex]::Match($rawValue, '(?<num>\d+)')
            if ($match.Success) { $match.Groups['num'].Value } else { $rawValue }
        } else {
            $rawValue.ToLowerInvariant()
        }

        $argBuilder = $commandMap[$key]
        $argument = & $argBuilder $normalized
        try {
            netsh int tcp set global $argument | Out-Null
            $applied++
            if ($Logger) { Write-Log "[Rollback] netsh int tcp set global $argument" }
        } catch {
            if ($Logger) { Write-Log "[Rollback] Failed to apply netsh global '$key' ($normalized): $($_.Exception.Message)" -Level 'Warning' }
        }
    }

    return $applied
}

# Description: Saves current network-related registry and firewall settings to a JSON backup with a pre-check for writable storage.
# Parameters: None.
# Returns: PSCustomObject with Success flag, HardStop indicator, file path, and optional registry rollback snippet. Writes backup file to ProgramData when possible.
function Save-NetworkBackupState {
    $backupDir = "C:\ProgramData\Scynesthesia"
    $file = Join-Path $backupDir "network_backup.json"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $result = [pscustomobject]@{
        Success            = $false
        FilePath           = $file
        RegRollbackSnippet = $null
        HardStop           = $false
    }

    $directoryWritable = $true
    try {
        if (-not (Test-Path -Path $backupDir -PathType Container)) {
            New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $probePath = Join-Path $backupDir ([System.IO.Path]::GetRandomFileName())
        "probe" | Set-Content -Path $probePath -Encoding UTF8 -ErrorAction Stop
        Remove-Item -Path $probePath -Force -ErrorAction SilentlyContinue
    } catch {
        $directoryWritable = $false
        $result.HardStop = $true
        $message = "Hard Stop: Backup directory '$backupDir' is not writable. Aborting tweaks to avoid unsafe changes."
        Write-Host "[Backup] $message" -ForegroundColor Red
        if ($logger) {
            Write-Log "[Backup] $message" -Level 'Error' -Data @{ BackupDirectory = $backupDir; Reason = $_.Exception.Message }
        }
    }

    if (-not $directoryWritable) {
        return $result
    }

    $regRollbackMap = @{}
    $formatRegPath = {
        param([string]$Path)
        if (-not $Path) { return $null }
        $normalized = $Path
        $normalized = $normalized -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
        $normalized = $normalized -replace '^HKCU:', 'HKEY_CURRENT_USER'
        return $normalized
    }

    $appendRegValue = {
        param(
            [string]$Path,
            [string]$Name,
            $Value,
            [string]$Type = 'DWord'
        )

        if ($null -eq $Value) { return }
        $normalizedPath = & $formatRegPath $Path
        if (-not $normalizedPath) { return }
        if (-not $regRollbackMap.ContainsKey($normalizedPath)) {
            $regRollbackMap[$normalizedPath] = New-Object System.Collections.Generic.List[string]
        }

        $entry = switch ($Type.ToLower()) {
            'string' { "\"$Name\"=\"$Value\"" }
            default {
                $asInt64 = [int64]$Value
                "\"$Name\"=dword:$($asInt64.ToString('x8'))"
            }
        }
        $regRollbackMap[$normalizedPath].Add($entry) | Out-Null
    }

    $appendServiceState = {
        param([string]$Name)

        if (-not $Name) { return }
        try {
            $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if (-not $svc) { return }
            $backup.ServiceStates += [ordered]@{
                Name        = $svc.Name
                StartupType = $svc.StartType.ToString()
                Status      = $svc.Status.ToString()
            }
        } catch { }
    }

    $registryDefaults = Get-NetworkRegistryDefaults -IncludeCompatibilityPlaceholders
    $tcpParameterTemplate = [ordered]@{}
    if ($registryDefaults -and $registryDefaults.TcpParameters) {
        foreach ($name in $registryDefaults.TcpParameters.Keys) {
            $tcpParameterTemplate[$name] = $null
        }
    }
    if ($tcpParameterTemplate.Count -eq 0) {
        $tcpParameterTemplate = [ordered]@{
            DefaultTTL        = $null
            Tcp1323Opts       = $null
            TcpMaxDupAcks     = $null
            MaxUserPort       = $null
            TcpTimedWaitDelay = $null
            SackOpts          = $null
        }
    }

    $lanmanTemplate = [ordered]@{}
    if ($registryDefaults -and $registryDefaults.LanmanServer) {
        foreach ($name in $registryDefaults.LanmanServer.Keys) {
            $lanmanTemplate[$name] = $null
        }
    }
    if ($lanmanTemplate.Count -eq 0) {
        $lanmanTemplate = [ordered]@{
            autodisconnect = $null
            Size           = $null
            EnableOplocks  = $null
            IRPStackSize   = $null
        }
    }

    $backup = [ordered]@{
        Version                = 3
        Created                = Get-Date
        ServiceStates          = @()
        NetworkThrottlingIndex = $null
        Nagle                  = @()
        QoS                    = [ordered]@{ NonBestEffortLimit = $null }
        LLMNR                  = [ordered]@{ EnableMulticast = $null }
        NetBIOS                = @()
        DeliveryOptimization   = [ordered]@{ DODownloadMode = $null; DoSvcStartup = $null }
        NetworkDiscovery       = [ordered]@{ FirewallGroupDisabled = $null }
        AdapterAdvanced        = @()
        Hardcore               = [ordered]@{
            TcpParameters       = $tcpParameterTemplate
            ServiceProvider     = [ordered]@{
                LocalPriority = $null
                HostsPriority = $null
                DnsPriority   = $null
                NetbtPriority = $null
            }
            LanmanServer        = $lanmanTemplate
            Winsock             = [ordered]@{
                MinSockAddrLength = $null
                MaxSockAddrLength = $null
            }
            CongestionProvider  = $null
            NetshGlobals        = $null
            TcpGlobalsRaw       = $null
            RegRollbackSnippet  = $null
        }
    }

    try {
        $adapters = Get-PhysicalNetAdapters
        if ($adapters -and $adapters.Count -gt 0) {
            foreach ($adapter in $adapters) {
                $adapterEntry = [ordered]@{
                    Name               = $adapter.Name
                    InterfaceIndex     = $adapter.ifIndex
                    InterfaceDescription = $adapter.InterfaceDescription
                    AdvancedProperties = @()
                    Rsc                = $null
                }

                try {
                    $advanced = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction Stop
                    if ($advanced) {
                        $targets = @(
                            'Flow Control',
                            'Interrupt Moderation',
                            'Large Send Offload V2 (IPv4)',
                            'Large Send Offload V2 (IPv6)',
                            'IPv4 Checksum Offload',
                            'TCP Checksum Offload (IPv4)',
                            'TCP Checksum Offload (IPv6)',
                            'UDP Checksum Offload (IPv4)',
                            'UDP Checksum Offload (IPv6)',
                            'Receive Buffers',
                            'Transmit Buffers'
                        )

                        foreach ($target in $targets) {
                            $match = $advanced | Where-Object { $_.DisplayName -eq $target } | Select-Object -First 1
                            if ($match) {
                                $adapterEntry.AdvancedProperties += [ordered]@{
                                    DisplayName  = $match.DisplayName
                                    DisplayValue = $match.DisplayValue
                                }
                            }
                        }
                    }
                } catch { }

                try {
                    $rscInfo = Get-NetAdapterRsc -Name $adapter.Name -ErrorAction Stop | Select-Object -First 1
                    if ($rscInfo) {
                        $adapterEntry.Rsc = [ordered]@{
                            IPv4Enabled = $rscInfo.IPv4Enabled
                            IPv6Enabled = $rscInfo.IPv6Enabled
                        }
                    }
                } catch { }

                $backup.AdapterAdvanced += $adapterEntry
            }
        }
    } catch { }

    try {
        $backup.NetworkThrottlingIndex = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -ErrorAction Stop).NetworkThrottlingIndex
        & $appendRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'NetworkThrottlingIndex' $backup.NetworkThrottlingIndex 'DWord'
    } catch { }

    try {
        $interfaces = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction Stop
        foreach ($iface in $interfaces) {
            $entry = [ordered]@{ InterfaceKey = $iface.PSPath; TcpAckFrequency = $null; TCPNoDelay = $null; TcpDelAckTicks = $null }
            foreach ($name in 'TcpAckFrequency','TCPNoDelay','TcpDelAckTicks') {
                try {
                    $entry[$name] = (Get-ItemProperty -Path $iface.PSPath -Name $name -ErrorAction Stop).$name
                } catch { }
            }
            $backup.Nagle += $entry
        }
    } catch { }

    try {
        $backup.QoS.NonBestEffortLimit = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' -Name 'NonBestEffortLimit' -ErrorAction Stop).NonBestEffortLimit
    } catch { }

    try {
        $backup.LLMNR.EnableMulticast = (Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction Stop).EnableMulticast
    } catch { }

    try {
        $nbtInterfaces = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop
        foreach ($iface in $nbtInterfaces) {
            $entry = [ordered]@{ Key = $iface.PSPath; NetbiosOptions = $null }
            try {
                $entry.NetbiosOptions = (Get-ItemProperty -Path $iface.PSPath -Name 'NetbiosOptions' -ErrorAction Stop).NetbiosOptions
            } catch { }
            $backup.NetBIOS += $entry
        }
    } catch { }

    try {
        $backup.DeliveryOptimization.DODownloadMode = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -ErrorAction Stop).DODownloadMode
    } catch { }

    try {
        $backup.DeliveryOptimization.DoSvcStartup = (Get-Service -Name 'DoSvc' -ErrorAction Stop).StartType.ToString()
    } catch { }

    & $appendServiceState 'DoSvc'
    & $appendServiceState 'DiagTrack'
    & $appendServiceState 'dmwappushservice'

    try {
        $rules = Get-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction Stop
        if ($rules) {
            $enabledStates = $rules | Select-Object -ExpandProperty Enabled -Unique
            if ($enabledStates -contains 'False' -and -not ($enabledStates -contains 'True')) {
                $backup.NetworkDiscovery.FirewallGroupDisabled = $true
            } elseif ($enabledStates -contains 'True') {
                $backup.NetworkDiscovery.FirewallGroupDisabled = $false
            }
        }
    } catch { }

    try {
        $tcpParamsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        foreach ($name in $backup.Hardcore.TcpParameters.Keys) {
            try {
                $value = (Get-ItemProperty -Path $tcpParamsPath -Name $name -ErrorAction Stop).$name
                $backup.Hardcore.TcpParameters[$name] = $value
                & $appendRegValue $tcpParamsPath $name $value 'DWord'
            } catch { }
        }
    } catch { }

    try {
        $serviceProviderPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider'
        foreach ($name in $backup.Hardcore.ServiceProvider.Keys) {
            try {
                $value = (Get-ItemProperty -Path $serviceProviderPath -Name $name -ErrorAction Stop).$name
                $backup.Hardcore.ServiceProvider[$name] = $value
                & $appendRegValue $serviceProviderPath $name $value 'DWord'
            } catch { }
        }
    } catch { }

    try {
        $lanmanPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        foreach ($name in $backup.Hardcore.LanmanServer.Keys) {
            try {
                $value = (Get-ItemProperty -Path $lanmanPath -Name $name -ErrorAction Stop).$name
                $backup.Hardcore.LanmanServer[$name] = $value
                & $appendRegValue $lanmanPath $name $value 'DWord'
            } catch { }
        }
    } catch { }

    try {
        $winsockPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
        foreach ($name in $backup.Hardcore.Winsock.Keys) {
            try {
                $value = (Get-ItemProperty -Path $winsockPath -Name $name -ErrorAction Stop).$name
                $backup.Hardcore.Winsock[$name] = $value
                & $appendRegValue $winsockPath $name $value 'DWord'
            } catch { }
        }
    } catch { }

    try {
        $tcpGlobals = netsh int tcp show global 2>&1
        if ($tcpGlobals) {
            $tcpGlobalsString = ($tcpGlobals -join "`n")
            $backup.Hardcore.TcpGlobalsRaw = $tcpGlobalsString
            $parsedGlobals = Convert-NetshGlobalsFromText -RawText $tcpGlobalsString
            if ($parsedGlobals -and $parsedGlobals.Count -gt 0) {
                $backup.Hardcore.NetshGlobals = $parsedGlobals
                if ($parsedGlobals.ContainsKey('CongestionProvider')) {
                    $backup.Hardcore.CongestionProvider = $parsedGlobals['CongestionProvider']
                }
            }
        }
    } catch { }

    if ($regRollbackMap.Count -gt 0) {
        $regLines = New-Object System.Collections.Generic.List[string]
        $regLines.Add('Windows Registry Editor Version 5.00') | Out-Null
        $regLines.Add('') | Out-Null
        foreach ($path in $regRollbackMap.Keys) {
            $regLines.Add("[$path]") | Out-Null
            foreach ($entry in $regRollbackMap[$path]) {
                $regLines.Add($entry) | Out-Null
            }
            $regLines.Add('') | Out-Null
        }
        $backup.Hardcore.RegRollbackSnippet = ($regLines -join "`r`n")
        $result.RegRollbackSnippet = $backup.Hardcore.RegRollbackSnippet
        if ($logger) {
            Write-Log "[Backup] Prepared registry rollback snippet for hardcore network tweaks." -Level 'Info' -Data @{ SnippetPreview = ($backup.Hardcore.RegRollbackSnippet.Substring(0, [Math]::Min(200, $backup.Hardcore.RegRollbackSnippet.Length))) }
        }
    }

    try {
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $backup | ConvertTo-Json -Depth 8 | Set-Content -Path $file -Encoding UTF8 -ErrorAction Stop
        if ($logger) { Write-Log "[Backup] Network backup saved to $file" }
        Write-Host "[Backup] Network backup saved to $file" -ForegroundColor Green
        $result.Success = $true
    } catch {
        $result.HardStop = $true
        $message = "Hard Stop: Failed to save network backup to '$file'. No network or registry changes will be applied."
        Write-Host "[Backup] $message" -ForegroundColor Red
        if ($logger) { Write-Log "[Backup] $message" -Level 'Error' -Data @{ Reason = $_.Exception.Message } }
    }

    return $result
}

# Description: Restores network settings from the saved JSON backup if present.
# Parameters: None.
# Returns: None.
function Restore-NetworkBackupState {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        [hashtable]$FallbackNetshGlobals,
        [array]$FallbackServiceStates
    )

    $file = "C:\ProgramData\Scynesthesia\network_backup.json"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $data = $null
    $backupExists = Test-Path $file
    if (-not $backupExists) {
        if (-not $FallbackServiceStates -and (-not $FallbackNetshGlobals -or $FallbackNetshGlobals.Count -eq 0)) {
            Write-Host "[Backup] No network backup found to restore." -ForegroundColor Yellow
            return
        }
        $data = [pscustomobject]@{}
    } else {
        try {
            $data = Get-Content -Path $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Host "[Backup] Could not read network backup file." -ForegroundColor Yellow
            return
        }
    }

    $serviceStates = @()
    $netshGlobals = $null
    try {
        if ($data -and $data.PSObject.Properties.Name -contains 'ServiceStates' -and $data.ServiceStates) {
            $serviceStates = @($data.ServiceStates)
        }
    } catch { }

    if (-not $serviceStates -and $data.DeliveryOptimization -and $null -ne $data.DeliveryOptimization.DoSvcStartup) {
        $serviceStates = @([pscustomobject]@{
                Name        = 'DoSvc'
                StartupType = $data.DeliveryOptimization.DoSvcStartup
                Status      = $null
            })
    }

    if ($FallbackServiceStates) {
        $existingNames = @()
        if ($serviceStates) {
            $existingNames = $serviceStates | Where-Object { $_.Name } | ForEach-Object { $_.Name }
        }
        foreach ($svcEntry in $FallbackServiceStates) {
            if (-not $svcEntry -or -not $svcEntry.Name) { continue }
            if (-not ($existingNames -contains $svcEntry.Name)) {
                $serviceStates += $svcEntry
            }
        }
    }

    $restoredServices = Restore-ServiceStatesFromBackup -ServiceStates $serviceStates -Logger $logger

    try {
        if ($data -and $data.Hardcore -and $data.Hardcore.NetshGlobals) {
            $netshGlobals = @{}
            foreach ($key in $data.Hardcore.NetshGlobals.PSObject.Properties.Name) {
                $netshGlobals[$key] = $data.Hardcore.NetshGlobals.$key
            }
        } elseif ($data -and $data.Hardcore -and $data.Hardcore.TcpGlobalsRaw) {
            $netshGlobals = Convert-NetshGlobalsFromText -RawText $data.Hardcore.TcpGlobalsRaw
        }
    } catch { }

    if ($FallbackNetshGlobals) {
        if (-not $netshGlobals) { $netshGlobals = @{} }
        foreach ($key in $FallbackNetshGlobals.Keys) {
            if (-not $netshGlobals.ContainsKey($key)) {
                $netshGlobals[$key] = $FallbackNetshGlobals[$key]
            }
        }
    }

    try {
        if ($null -ne $data.NetworkThrottlingIndex) {
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value $data.NetworkThrottlingIndex -PropertyType DWord -Force | Out-Null
            if ($logger) { Write-Log "[Backup] Restored NetworkThrottlingIndex=$($data.NetworkThrottlingIndex)" }
        }
    } catch { }

    if ($data.Nagle) {
        foreach ($entry in $data.Nagle) {
            $path = $entry.InterfaceKey
            if (-not $path) { continue }
            foreach ($name in 'TcpAckFrequency','TCPNoDelay','TcpDelAckTicks') {
                $value = $entry.$name
                try {
                    New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                    if ($null -ne $value) {
                        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null
                        if ($logger) { Write-Log "[Backup] Restored $name=$value at $path" }
                    } else {
                        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                        if ($logger) { Write-Log "[Backup] Removed $name at $path (was null)" }
                    }
                } catch { }
            }
        }
    }

    try {
        if ($null -ne $data.QoS.NonBestEffortLimit) {
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' -Name 'NonBestEffortLimit' -Value $data.QoS.NonBestEffortLimit -PropertyType DWord -Force | Out-Null
            if ($logger) { Write-Log "[Backup] Restored NonBestEffortLimit=$($data.QoS.NonBestEffortLimit)" }
        }
    } catch { }

    try {
        if ($null -ne $data.LLMNR.EnableMulticast) {
            New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value $data.LLMNR.EnableMulticast -PropertyType DWord -Force | Out-Null
            if ($logger) { Write-Log "[Backup] Restored EnableMulticast=$($data.LLMNR.EnableMulticast)" }
        }
    } catch { }

    if ($data.NetBIOS) {
        foreach ($entry in $data.NetBIOS) {
            $path = $entry.Key
            if (-not $path) { continue }
            try {
                New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                if ($null -ne $entry.NetbiosOptions) {
                    New-ItemProperty -Path $path -Name 'NetbiosOptions' -Value $entry.NetbiosOptions -PropertyType DWord -Force | Out-Null
                    if ($logger) { Write-Log "[Backup] Restored NetbiosOptions=$($entry.NetbiosOptions) at $path" }
                } else {
                    Remove-ItemProperty -Path $path -Name 'NetbiosOptions' -ErrorAction SilentlyContinue
                    if ($logger) { Write-Log "[Backup] Removed NetbiosOptions at $path (was null)" }
                }
            } catch { }
        }
    }

    if ($data.AdapterAdvanced) {
        foreach ($adapterEntry in $data.AdapterAdvanced) {
            $adapterName = $adapterEntry.Name
            if (-not $adapterName) { continue }

            if ($adapterEntry.AdvancedProperties) {
                foreach ($prop in $adapterEntry.AdvancedProperties) {
                    $displayName = $prop.DisplayName
                    if (-not $displayName) { continue }
                    $displayValue = $prop.DisplayValue
                    try {
                        if ($null -ne $displayValue -and "$displayValue" -ne '') {
                            Set-NetAdapterAdvancedProperty -Name $adapterName -DisplayName $displayName -DisplayValue $displayValue -NoRestart -ErrorAction Stop | Out-Null
                            if ($logger) { Write-Log "[Backup] Restored $displayName on $adapterName to $displayValue." }
                        }
                    } catch { }
                }
            }

            if ($adapterEntry.Rsc) {
                $ipv4Enabled = $adapterEntry.Rsc.IPv4Enabled
                $ipv6Enabled = $adapterEntry.Rsc.IPv6Enabled

                try {
                    if ($ipv4Enabled -eq $true) {
                        Enable-NetAdapterRsc -Name $adapterName -IPv4 -ErrorAction Stop | Out-Null
                        if ($logger) { Write-Log "[Backup] RSC IPv4 enabled on $adapterName." }
                    } elseif ($ipv4Enabled -eq $false) {
                        Disable-NetAdapterRsc -Name $adapterName -IPv4 -ErrorAction Stop | Out-Null
                        if ($logger) { Write-Log "[Backup] RSC IPv4 disabled on $adapterName." }
                    }
                } catch { }

                try {
                    if ($ipv6Enabled -eq $true) {
                        Enable-NetAdapterRsc -Name $adapterName -IPv6 -ErrorAction Stop | Out-Null
                        if ($logger) { Write-Log "[Backup] RSC IPv6 enabled on $adapterName." }
                    } elseif ($ipv6Enabled -eq $false) {
                        Disable-NetAdapterRsc -Name $adapterName -IPv6 -ErrorAction Stop | Out-Null
                        if ($logger) { Write-Log "[Backup] RSC IPv6 disabled on $adapterName." }
                    }
                } catch { }
            }
        }
    }

    try {
        if ($null -ne $data.DeliveryOptimization.DODownloadMode) {
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Value $data.DeliveryOptimization.DODownloadMode -PropertyType DWord -Force | Out-Null
            if ($logger) { Write-Log "[Backup] Restored DODownloadMode=$($data.DeliveryOptimization.DODownloadMode)" }
        }
    } catch { }

    try {
        if ($restoredServices -eq 0 -and $null -ne $data.DeliveryOptimization.DoSvcStartup) {
            Set-Service -Name 'DoSvc' -StartupType $data.DeliveryOptimization.DoSvcStartup -ErrorAction Stop
            if ($logger) { Write-Log "[Backup] Restored DoSvc startup type to $($data.DeliveryOptimization.DoSvcStartup)" }
        }
    } catch { }

    try {
        if ($data.NetworkDiscovery.FirewallGroupDisabled -eq $true -or $data.NetworkDiscovery.FirewallGroupDisabled -eq $false) {
            if ($data.NetworkDiscovery.FirewallGroupDisabled -eq $true) {
                try {
                    Set-NetFirewallRule -DisplayGroup 'Network Discovery' -Enabled True -ErrorAction Stop | Out-Null
                    if ($logger) { Write-Log "[Backup] Network Discovery firewall group re-enabled." }
                } catch { }
            }
        }
    } catch { }

    try {
        $netshApplied = Restore-NetshGlobalsFromMap -GlobalsMap $netshGlobals -Logger $logger
        if ($netshApplied -gt 0) {
            Write-Host "[Backup] Restored $netshApplied netsh TCP global setting(s)." -ForegroundColor Cyan
        }
    } catch { }

    Write-Host "[Backup] Network configuration restored from backup." -ForegroundColor Cyan
    if ($logger) { Write-Log "[Backup] Network settings restored from $file" }
}

# Restores non-registry changes using context tracking and network backup data.
function Invoke-GlobalRollback {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    $runContext = Get-RunContext -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $fallbackServices = @()
    $fallbackNetsh = $null
    try {
        if ($runContext.PSObject.Properties.Name -contains 'ServiceRollbackActions' -and $runContext.ServiceRollbackActions) {
            $fallbackServices = @($runContext.ServiceRollbackActions)
        }
        if ($runContext.PSObject.Properties.Name -contains 'NetshRollbackActions' -and $runContext.NetshRollbackActions) {
            $fallbackNetsh = @{}
            foreach ($entry in $runContext.NetshRollbackActions) {
                if (-not $entry -or -not $entry.Name) { continue }
                if (-not $fallbackNetsh.ContainsKey($entry.Name)) {
                    $fallbackNetsh[$entry.Name] = $entry.Value
                }
            }
        }

        # Preserve legacy tracker entries for compatibility with older sessions.
        $tracker = Get-NonRegistryChangeTracker -Context $runContext
        if ($tracker -and $tracker.ServiceState) {
            $existingNames = $fallbackServices | Where-Object { $_.Name } | ForEach-Object { $_.Name }
            foreach ($svc in $tracker.ServiceState.Values) {
                if (-not $svc -or -not $svc.Name) { continue }
                if (-not ($existingNames -contains $svc.Name)) {
                    $fallbackServices += $svc
                }
            }
        }
        if ($tracker -and $tracker.NetshGlobal) {
            if (-not $fallbackNetsh) { $fallbackNetsh = @{} }
            foreach ($key in $tracker.NetshGlobal.Keys) {
                if (-not $fallbackNetsh.ContainsKey($key)) {
                    $fallbackNetsh[$key] = $tracker.NetshGlobal[$key]
                }
            }
        }
    } catch { }

    if ($logger) {
        Write-Log "[Rollback] Initiating global rollback (services/netsh globals) using tracked context data and network backup when available."
    }
    else {
        Write-Host "[Rollback] Restoring services and netsh globals from tracked changes/backup..." -ForegroundColor Cyan
    }

    Restore-NetworkBackupState -Context $runContext -FallbackNetshGlobals $fallbackNetsh -FallbackServiceStates $fallbackServices
}

Export-ModuleMember -Function Invoke-NetworkTweaksSafe, Invoke-NetworkTweaksAggressive, Invoke-NetworkTweaksGaming, Set-NetworkDnsSafe, Save-NetworkBackupState, Restore-NetworkBackupState, Invoke-GlobalRollback
