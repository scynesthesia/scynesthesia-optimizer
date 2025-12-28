# Depends on: ui.psm1 (loaded by main script)
if (-not (Get-Module -Name 'config' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/config.psm1') -Force -Scope Local
}
if (-not (Get-Module -Name 'network_discovery' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/network_discovery.psm1') -Force -Scope Local
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
    $map = network_discovery\Get-NicRegistryMap -AdapterResolver { Get-PhysicalNetAdapters }
    return $map | ForEach-Object {
        [pscustomobject]@{
            Adapter = $_.AdapterObject
            Path    = $_.RegistryPath
            Guid    = $_.InterfaceGuid
            IfIndex = $_.IfIndex
        }
    }
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
# Parameters: None.
# Returns: None. Sets global reboot flag when reset runs.
function Invoke-NetworkFullReset {
    Write-Host "  [+] Resetting Winsock catalog" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        netsh winsock reset | Out-Null
        Write-Host "      Reset complete. A reboot is recommended." -ForegroundColor Yellow
        Set-RebootRequired | Out-Null
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
# Parameters: None.
# Returns: None. Sets global reboot flag after registry update.
function Set-IPvPreferenceIPv4First {
    Write-Host "  [+] Preferring IPv4 over IPv6 (without disabling IPv6)" -ForegroundColor Gray
    try {
        Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0x20
        Set-RebootRequired | Out-Null
        Write-Host "      [>] Preference recorded. Reboot recommended." -ForegroundColor Yellow
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "[Network] IPv4 preference set (DisabledComponents=0x20)."
        }
    } catch {
        Invoke-ErrorHandler -Context 'Setting IPv4 preference' -ErrorRecord $_
    }
}

# Description: Disables Link-Local Multicast Name Resolution to reduce noisy broadcasts.
# Parameters: None.
# Returns: None.
function Disable-LLMNR {
    Write-Host "  [+] Disabling LLMNR" -ForegroundColor Gray
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log "[Network] Disabled LLMNR (EnableMulticast=0 under DNSClient policy)."
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
    Write-Host "  [+] Disabling network telemetry services" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
        if ($logger) {
            Write-Log "[Network] Telemetry collection disabled (AllowTelemetry=0)."
        }
        foreach ($svc in 'DiagTrack','dmwappushservice') {
            try {
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
    Write-Host "  [+] Disabling Delivery Optimization (WUDO)" -ForegroundColor Gray
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
        if ($logger) {
            Write-Log "[Network] Delivery Optimization disabled (DODownloadMode=0)."
        }

        try {
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
    Write-Host "  [+] Setting reservable bandwidth limit to 0%" -ForegroundColor Gray
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log "[Network] Reservable bandwidth limit set to 0% (NonBestEffortLimit=0)."
    }
}

# Description: Disables Remote Assistance via registry policy values.
# Parameters: None.
# Returns: None.
function Disable-RemoteAssistance {
    Write-Host "  [+] Disabling Remote Assistance" -ForegroundColor Gray
    try {
        Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" 0
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" 0
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "[Network] Remote Assistance disabled (fAllowToGetHelp=0)."
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
    Write-Host "  [+] Disabling network throttling" -ForegroundColor Gray
    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xFFFFFFFF
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log "[Network] NetworkThrottlingIndex set to 0xFFFFFFFF."
    }
}

# Description: Optimizes TCP acknowledgement parameters (Nagle-related) per adapter.
# Parameters: None.
# Returns: None. Sets global reboot flag if registry changes occur.
function Set-NagleState {
    $adapters = Get-PhysicalNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for Nagle adjustments." -ForegroundColor Yellow
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $changesMade = $false

    foreach ($adapter in $adapters) {
        $guid = $adapter.InterfaceGuid
        if (-not $guid) { continue }

        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$guid}"
        try {
            $existing = @{}
            foreach ($name in 'TcpAckFrequency','TCPNoDelay','TcpDelAckTicks') {
                try {
                    $existing[$name] = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
                } catch { $existing[$name] = $null }
            }

            New-Item -Path $path -Force -ErrorAction Stop | Out-Null

            $newValues = @{
                TcpAckFrequency = 1
                TCPNoDelay      = 1
                TcpDelAckTicks  = 0
            }

            foreach ($entry in $newValues.GetEnumerator()) {
                New-ItemProperty -Path $path -Name $entry.Key -Value $entry.Value -PropertyType DWord -Force | Out-Null
                if ($logger) {
                    Write-Log "[Nagle] Interface '$($adapter.Name)' $($entry.Key): $($existing[$entry.Key]) -> $($entry.Value)"
                }
                if ($existing[$entry.Key] -ne $entry.Value) {
                    $changesMade = $true
                }
            }
            Write-Host "  [+] Nagle-related parameters optimized for $($adapter.Name)." -ForegroundColor Green
        } catch {
            Invoke-ErrorHandler -Context "Setting Nagle parameters on $($adapter.Name)" -ErrorRecord $_
        }
    }

    if ($changesMade) {
        Set-RebootRequired | Out-Null
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
    Write-Host "  [>] Applying NIC power management overrides" -ForegroundColor Cyan
    $nicPaths = Get-NicRegistryPaths
    if ($nicPaths.Count -eq 0) {
        Write-Host "  [!] No NIC registry paths found for gaming power tweaks." -ForegroundColor Yellow
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
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

    foreach ($item in $nicPaths) {
        $adapterName = $item.Adapter.Name
        Write-Host "  [>] Optimizing $adapterName power profile" -ForegroundColor Cyan
        try {
            Set-RegistryValueSafe -Path $item.Path -Name 'PnPCapabilities' -Value 24 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
            Write-Host "    [+] PnPCapabilities set to 24 (power management disabled)" -ForegroundColor Green
            if ($logger) { Write-Log "[Network] $adapterName PnPCapabilities set to 24 for gaming profile." }
        } catch {
            Invoke-ErrorHandler -Context "Setting PnPCapabilities on $adapterName" -ErrorRecord $_
        }

        foreach ($entry in $powerFlags.GetEnumerator()) {
            try {
                Set-RegistryValueSafe -Path $item.Path -Name $entry.Key -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::String)
                Write-Host "    [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                if ($logger) { Write-Log "[Network] $adapterName $($entry.Key) set to $($entry.Value) for gaming power." }
            } catch {
                Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
            }
        }

        try {
            $interfacePath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($item.Guid)"
            $cleanupKeys = @($powerFlags.Keys) + @('PnPCapabilities')
            foreach ($noiseKey in $cleanupKeys | Select-Object -Unique) {
                try {
                    Remove-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue
                } catch { }
            }
        } catch {
            Invoke-ErrorHandler -Context "Cleaning interface overrides for $adapterName" -ErrorRecord $_
        }
    }
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
# Parameters: None.
# Returns: None.
function Invoke-NetworkTweaksSafe {
    Write-Section "Network tweaks (Safe profile)"
    Invoke-NetworkFlush

    if (Get-Confirmation "Reset Winsock (requires reboot)?" 'n') {
        Invoke-NetworkFullReset
    } else {
        Write-Host "  [ ] Winsock left unchanged." -ForegroundColor Gray
    }

    if (Get-Confirmation "Use Cloudflare DNS (1.1.1.1 / 1.0.0.1) on all adapters?" 'y') {
        Set-NetworkDnsSafe
    } else {
        Write-Host "  [ ] DNS settings left unchanged." -ForegroundColor Gray
    }

    Set-TcpAutotuningNormal
    Set-IPvPreferenceIPv4First
}

# Description: Applies aggressive network tweaks including autotuning and disabled discovery.
# Parameters: None.
# Returns: None. May prompt for backup before changes.
function Invoke-NetworkTweaksAggressive {
    Write-Section "Network tweaks (Aggressive profile)"
    Disable-LLMNR
    Disable-DeliveryOptimization

    if (Get-Confirmation "Disable NetBIOS over TCP/IP? This may break legacy LAN shares and printers." 'n') {
        Disable-NetBIOS
    } else {
        Write-Host "  [ ] NetBIOS left enabled." -ForegroundColor Gray
    }

    Disable-NetworkTelemetry
    Set-ReservableBandwidth

    if (Get-Confirmation "Disable Remote Assistance?" 'y') {
        Disable-RemoteAssistance
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
# Parameters: None.
# Returns: None. May set global reboot flag for certain changes.
function Invoke-NetworkTweaksGaming {
    Write-Section "Network tweaks (Gaming profile)"
    Write-Host "  [i] Applying hardware power optimizations..." -ForegroundColor Gray
    Set-NicPowerManagementGaming
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Set-NetworkThrottling
    Set-NagleState
    Set-EnergyEfficientEthernet
    Enable-RSS

    if (Get-Confirmation "Disable interrupt moderation for lowest latency? (Higher CPU usage)" 'n') {
        Set-InterruptModeration
    } else {
        Write-Host "  [ ] Interrupt moderation left unchanged." -ForegroundColor Gray
    }

    if (Get-Confirmation "Enable MSI Mode for your NIC? Recommended on modern hardware. If you already applied MSI Mode elsewhere, you can skip this." 'n') {
        $msiResult = Enable-MsiModeSafe -Target 'NIC'
        if ($logger -and $msiResult -and $msiResult.Touched -gt 0) {
            Write-Log "[Network] MSI Mode enabled for NIC via gaming profile."
        } elseif ($logger) {
            Write-Log "[Network] MSI Mode for NIC already enabled or not applicable." -Level 'Info'
        }
    } else {
        Write-Host "  [ ] MSI Mode for NIC skipped." -ForegroundColor Gray
    }

    if (Get-Confirmation "Apply advanced TCP tweaks (Chimney Offload / DCA)? These are experimental and may be unstable on older hardware or uncommon drivers." 'n') {
        try {
            $safePath = $env:SystemRoot
            if (-not $safePath) { $safePath = $env:WINDIR }
            if (-not $safePath) { $safePath = 'C:\Windows' }

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

# Description: Saves current network-related registry and firewall settings to a JSON backup.
# Parameters: None.
# Returns: None. Writes backup file to ProgramData when possible.
function Save-NetworkBackupState {
    $backupDir = "C:\ProgramData\Scynesthesia"
    $file = Join-Path $backupDir "network_backup.json"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $backup = [ordered]@{
        Version                = 1
        Created                = Get-Date
        NetworkThrottlingIndex = $null
        Nagle                  = @()
        QoS                    = [ordered]@{ NonBestEffortLimit = $null }
        LLMNR                  = [ordered]@{ EnableMulticast = $null }
        NetBIOS                = @()
        DeliveryOptimization   = [ordered]@{ DODownloadMode = $null; DoSvcStartup = $null }
        NetworkDiscovery       = [ordered]@{ FirewallGroupDisabled = $null }
    }

    try {
        $backup.NetworkThrottlingIndex = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -ErrorAction Stop).NetworkThrottlingIndex
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
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $backup | ConvertTo-Json -Depth 6 | Set-Content -Path $file -Encoding UTF8 -ErrorAction Stop
        if ($logger) { Write-Log "[Backup] Network backup saved to $file" }
        Write-Host "[Backup] Network backup saved to $file" -ForegroundColor Green
    } catch {
        Write-Host "[Backup] Failed to save network backup." -ForegroundColor Yellow
        if ($logger) { Write-Log "[Backup] Failed to save network backup: $($_.Exception.Message)" }
    }
}

# Description: Restores network settings from the saved JSON backup if present.
# Parameters: None.
# Returns: None.
function Restore-NetworkBackupState {
    $file = "C:\ProgramData\Scynesthesia\network_backup.json"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    if (-not (Test-Path $file)) {
        Write-Host "[Backup] No network backup found to restore." -ForegroundColor Yellow
        return
    }

    try {
        $data = Get-Content -Path $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host "[Backup] Could not read network backup file." -ForegroundColor Yellow
        return
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

    try {
        if ($null -ne $data.DeliveryOptimization.DODownloadMode) {
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Value $data.DeliveryOptimization.DODownloadMode -PropertyType DWord -Force | Out-Null
            if ($logger) { Write-Log "[Backup] Restored DODownloadMode=$($data.DeliveryOptimization.DODownloadMode)" }
        }
    } catch { }

    try {
        if ($null -ne $data.DeliveryOptimization.DoSvcStartup) {
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

    Write-Host "[Backup] Network configuration restored from backup." -ForegroundColor Cyan
    if ($logger) { Write-Log "[Backup] Network settings restored from $file" }
}

Export-ModuleMember -Function Invoke-NetworkTweaksSafe, Invoke-NetworkTweaksAggressive, Invoke-NetworkTweaksGaming, Set-NetworkDnsSafe, Save-NetworkBackupState, Restore-NetworkBackupState
