# Depends on: ui.psm1 (loaded by main script)
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

# Description: Converts a link speed value to bytes per second, handling string units.
# Parameters: LinkSpeed - Raw speed value or string with units.
# Returns: Int64 representing bytes per second, or null when parsing fails.
function Convert-LinkSpeedToBytes {
    param(
        [Parameter(Mandatory)]$LinkSpeed
    )

    try {
        if ($null -eq $LinkSpeed) { return $null }

        if ($LinkSpeed -is [string]) {
            $match = [regex]::Match($LinkSpeed, '(?i)(\d+(?:\.\d+)?)\s*(g|m)?bps')
            if ($match.Success) {
                $value = [double]$match.Groups[1].Value
                $unit = $match.Groups[2].Value.ToLower()
                switch ($unit) {
                    'g' { return [int64]($value * 1GB) }
                    'm' { return [int64]($value * 1MB) }
                    default { return [int64]$value }
                }
            }
        }

        if ($LinkSpeed -is [IConvertible]) {
            return [int64][double]$LinkSpeed
        }
    } catch {
        Invoke-ErrorHandler -Context 'Parsing adapter link speed' -ErrorRecord $_
    }

    return $null
}

# Description: Applies advanced TCP/IP registry parameters for performance tuning.
# Parameters: None.
# Returns: None. Sets global reboot flag after changes.
function Set-TcpIpAdvancedParameters {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        $values = @{
            DefaultTTL          = 64
            Tcp1323Opts         = 1
            TcpMaxDupAcks       = 2
            SackOpts            = 0
            MaxUserPort         = 65534
            TcpTimedWaitDelay   = 30
        }

        foreach ($entry in $values.GetEnumerator()) {
            try {
                Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type DWord
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) in TCP parameters." -ForegroundColor Green
            } catch {
                Invoke-ErrorHandler -Context "Setting $($entry.Key) in TCP parameters" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context 'Configuring advanced TCP/IP parameters' -ErrorRecord $_
    }
}

# Description: Disables network throttling via registry for maximum throughput.
# Parameters: None.
# Returns: None. Sets global reboot flag on success.
function Set-NetworkThrottlingHardcore {
    try {
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
        try {
            Set-RegistryValueSafe -Path $path -Name 'NetworkThrottlingIndex' -Value 0xFFFFFFFF -Type DWord
            Write-Host "  [+] NetworkThrottlingIndex set to maximum performance." -ForegroundColor Green
            $Global:NeedsReboot = $true
        } catch {
            Invoke-ErrorHandler -Context 'Setting NetworkThrottlingIndex' -ErrorRecord $_
        }
    } catch {
        Invoke-ErrorHandler -Context 'Configuring network throttling' -ErrorRecord $_
    }
}

# Description: Configures TCP/IP service provider priorities for resolution order.
# Parameters: None.
# Returns: None. Sets global reboot flag after applying values.
function Set-ServicePriorities {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider'
        $values = @{
            LocalPriority  = 4
            HostsPriority  = 5
            DnsPriority    = 6
            NetbtPriority  = 7
        }

        foreach ($entry in $values.GetEnumerator()) {
            try {
                Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type DWord
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) in ServiceProvider." -ForegroundColor Green
            } catch {
                Invoke-ErrorHandler -Context "Setting $($entry.Key) service priority" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context 'Configuring ServiceProvider priorities' -ErrorRecord $_
    }
}

# Description: Applies Winsock parameter adjustments to align socket behavior.
# Parameters: None.
# Returns: None. Sets global reboot flag when updates are made.
function Set-WinsockOptimizations {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
        $values = @{
            MinSockAddrLength = 16
            MaxSockAddrLength = 16
        }

        foreach ($entry in $values.GetEnumerator()) {
            try {
                Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type DWord
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) for Winsock." -ForegroundColor Green
            } catch {
                Invoke-ErrorHandler -Context "Setting Winsock $($entry.Key)" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context 'Applying Winsock optimizations' -ErrorRecord $_
    }
}

# Description: Tunes LanmanServer parameters for reduced latency and connection stability.
# Parameters: None.
# Returns: None. Sets global reboot flag when registry changes occur.
function Optimize-LanmanServer {
    try {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $values = @{
            autodisconnect = 0
            Size           = 3
            EnableOplocks  = 0
            IRPStackSize   = 20
        }

        foreach ($entry in $values.GetEnumerator()) {
            try {
                Set-RegistryValueSafe -Path $path -Name $entry.Key -Value $entry.Value -Type DWord
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) for LanmanServer." -ForegroundColor Green
            } catch {
                Invoke-ErrorHandler -Context "Setting LanmanServer $($entry.Key)" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context 'Optimizing LanmanServer parameters' -ErrorRecord $_
    }
}

# Description: Runs netsh commands to set advanced TCP/IP global options for performance.
# Parameters: None.
# Returns: None. Sets global reboot flag following configuration.
function Set-NetshHardcoreGlobals {
    try {
        $commands = @(
            @{ Cmd = 'netsh int tcp set global dca=enabled'; Description = 'DCA enabled' },
            @{ Cmd = 'netsh int tcp set global netdma=enabled'; Description = 'NetDMA enabled' },
            @{ Cmd = 'netsh int tcp set global nonsackrttresiliency=disabled'; Description = 'NonSackRTTResiliency disabled' },
            @{ Cmd = 'netsh int tcp set global maxsynretransmissions=2'; Description = 'MaxSynRetransmissions set' },
            @{ Cmd = 'netsh int tcp set global mpp=disabled'; Description = 'MPP disabled' },
            @{ Cmd = 'netsh int tcp set security profiles=disabled'; Description = 'Security profiles disabled' },
            @{ Cmd = 'netsh int tcp set heuristics disabled'; Description = 'Heuristics disabled' },
            @{ Cmd = 'netsh int ip set global neighborcachelimit=4096'; Description = 'NeighborCacheLimit set' }
        )

        Push-Location -Path ($env:SystemRoot | ForEach-Object { if ($_ -and (Test-Path $_)) { $_ } else { $env:WINDIR } })
        try {
            foreach ($command in $commands) {
                try {
                    & cmd.exe /c $command.Cmd 2>&1 | Out-Null
                    Write-Host "  [+] $($command.Description)." -ForegroundColor Green
                } catch {
                    Invoke-ErrorHandler -Context "Running $($command.Cmd)" -ErrorRecord $_
                }
            }
        } finally {
            Pop-Location -ErrorAction SilentlyContinue
        }

        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context 'Applying hardcore netsh globals' -ErrorRecord $_
    }
}

# Description: Maps physical adapters to their registry class paths for advanced tweaks.
# Parameters: None.
# Returns: Collection of objects containing adapter references and registry paths.
function Get-NicRegistryPaths {
    try {
        $classPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}'
        $adapters = Get-EligibleNetAdapters
        $results = @()
        $entries = @()
        $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

        try {
            $entries = Get-ChildItem -Path $classPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
        } catch {
            if ($_.Exception -is [System.UnauthorizedAccessException]) {
                $message = "Insufficient registry permissions to enumerate $classPath. Run PowerShell as Administrator to apply NIC registry tweaks."
                Write-Host "  [!] $message" -ForegroundColor Yellow
                if ($logger) { Write-Log "[NetworkHardcore] $message" -Level 'Warning' }
                return @()
            }

            Invoke-ErrorHandler -Context 'Enumerating NIC registry class entries' -ErrorRecord $_
            return @()
        }

        foreach ($adapter in $adapters) {
            try {
                $guidString = Get-NormalizedGuid -Value $adapter.InterfaceGuid
                if (-not $guidString) { continue }
                foreach ($entry in $entries) {
                    try {
                        $netCfg = (Get-ItemProperty -Path $entry.PSPath -Name 'NetCfgInstanceId' -ErrorAction SilentlyContinue).NetCfgInstanceId
                        $netCfgString = Get-NormalizedGuid -Value $netCfg
                        if ($netCfgString -and ($netCfgString -eq $guidString)) {
                            $results += [pscustomobject]@{ Adapter = $adapter; Path = $entry.PSPath; Guid = $guidString }
                            break
                        }
                    } catch { }
                }
            } catch {
                Invoke-ErrorHandler -Context "Finding registry path for $($adapter.Name)" -ErrorRecord $_
            }
        }

        return $results
    } catch {
        Invoke-ErrorHandler -Context 'Enumerating NIC registry paths' -ErrorRecord $_
        return @()
    }
}

# Description: Applies hardcore NIC registry tweaks for power, wake, and latency behaviors.
# Parameters: None.
# Returns: None. Sets global reboot flag after applying changes.
function Set-NicRegistryHardcore {
    try {
        $nicPaths = Get-NicRegistryPaths
        if ($nicPaths.Count -eq 0) {
            Write-Host "  [!] No NIC registry paths found for tweaks." -ForegroundColor Yellow
            return
        }

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

        foreach ($item in $nicPaths) {
            $adapterName = $item.Adapter.Name
            Write-Host "  [>] Applying registry tweaks to $adapterName" -ForegroundColor Cyan
            try {
                Set-RegistryValueSafe -Path $item.Path -Name 'PnPCapabilities' -Value 24 -Type DWord
                Write-Host "    [+] PnPCapabilities set to 24 (power management disabled)" -ForegroundColor Green
            } catch {
                Invoke-ErrorHandler -Context "Setting PnPCapabilities on $adapterName" -ErrorRecord $_
            }

            foreach ($entry in $powerOffload.GetEnumerator()) {
                try {
                    Set-RegistryValueSafe -Path $item.Path -Name $entry.Key -Value $entry.Value -Type String
                    Write-Host "    [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                } catch {
                    Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
                }
            }

            foreach ($entry in $interruptDelays.GetEnumerator()) {
                try {
                    Set-RegistryValueSafe -Path $item.Path -Name $entry.Key -Value $entry.Value -Type String
                    Write-Host "    [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                } catch {
                    Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
                }
            }

            try {
                $interfacePath = "${'HKLM'}:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($item.Guid)"
                $noiseKeys = @($powerOffload.Keys) + @($interruptDelays.Keys)
                foreach ($noiseKey in $noiseKeys | Select-Object -Unique) {
                    try {
                        Remove-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue
                    } catch { }
                }

                Set-RegistryValueSafe -Path $interfacePath -Name 'TcpAckFrequency' -Value 1 -Type DWord
                Set-RegistryValueSafe -Path $interfacePath -Name 'TCPNoDelay' -Value 1 -Type DWord
                Set-RegistryValueSafe -Path $interfacePath -Name 'TcpDelAckTicks' -Value 0 -Type DWord
                Write-Host "    [+] Nagle parameters set (Ack=1, NoDelay=1, DelAckTicks=0)" -ForegroundColor Green
            } catch {
                Invoke-ErrorHandler -Context "Setting Nagle parameters for $adapterName" -ErrorRecord $_
            }

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
        }

        $Global:NeedsReboot = $true
        Write-Host "  [i] Some Device Manager changes may require a full reboot to reflect visually." -ForegroundColor Gray
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
                    $parsed = Convert-LinkSpeedToBytes -LinkSpeed $_.LinkSpeed
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

# Description: Sets an adapter advanced property when a matching display name exists.
# Parameters: AdapterName - Target adapter name; DisplayName - Property display label; DisplayValue - Desired value.
# Returns: None.
function Set-NetAdapterAdvancedPropertySafe {
    param(
        [Parameter(Mandatory)][string]$AdapterName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$DisplayValue
    )
    try {
        $property = Get-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if (-not $property) {
            Write-Host "  [!] $DisplayName not available on $AdapterName; skipping." -ForegroundColor Yellow
            return
        }

        $valuesToTry = @($DisplayValue)
        if ($DisplayName -eq 'Transmit Buffers') {
            $fallbackDefault = if ($property.DefaultDisplayValue) { $property.DefaultDisplayValue } else { $property.DisplayValue }
            $valuesToTry = @('4096', '128', $fallbackDefault) | Where-Object { $_ }
        }

        foreach ($value in $valuesToTry) {
            try {
                Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -DisplayValue $value -ErrorAction Stop | Out-Null
                Write-Host "  [+] $DisplayName set to $value on $AdapterName" -ForegroundColor Green
                return
            } catch {
                Write-Host "  [!] Failed to set $DisplayName to $value on $AdapterName; trying fallback." -ForegroundColor Yellow
            }
        }

        Write-Host "  [!] Unable to set $DisplayName on $AdapterName after fallbacks." -ForegroundColor Yellow
    } catch {
        Invoke-ErrorHandler -Context "Setting $DisplayName on $AdapterName" -ErrorRecord $_
    }
}

# Description: Hardens Wake-on-LAN settings through registry and adapter UI properties.
# Parameters: None.
# Returns: None. Sets global reboot flag after changes.
function Set-WakeOnLanHardcore {
    <#
        Wake-on-LAN needs both registry and UI alignment because many drivers honor multiple flags at once.
        WolShutdownLinkSpeed "2" keeps the link in "Not Speed Down" to avoid low-power renegotiation that re-enables WOL paths.
    #>
    Write-Host "  [>] Applying Wake-on-LAN hardening (registry + driver UI)" -ForegroundColor Cyan
    $adapters = Get-EligibleNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No adapters available for Wake-on-LAN hardening." -ForegroundColor Yellow
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $nicPaths = Get-NicRegistryPaths
    if ($nicPaths.Count -eq 0) {
        Write-Host "  [!] Unable to map NIC registry paths; skipping WOL registry enforcement." -ForegroundColor Yellow
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
                        Set-RegistryValueSafe -Path $pathEntry.Path -Name $entry.Key -Value $entry.Value -Type String
                        Write-Host "      [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
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
# Returns: Boolean indicating success of the ping test.
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
        return ($successExit -and $successTtl)
    } catch {
        Invoke-ErrorHandler -Context "Testing MTU payload size $PayloadSize" -ErrorRecord $_
        return $false
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
        $low = 1200
        $high = 1472 # 1500 - 28 bytes for ICMP/IPv4 headers
        $best = $low
        $step = 1
        $success = $false

        while ($low -le $high) {
            $mid = [int](($low + $high) / 2)
            $mtuCandidate = $mid + 28
            Write-Host "  [>] MTU test step ${step}: payload $mid bytes (candidate MTU $mtuCandidate)" -ForegroundColor Cyan
            if (Test-MtuSize -PayloadSize $mid -Target $Target) {
                $best = $mid
                $success = $true
                $low = $mid + 1
                Write-Host "      ✓ Success, raising floor to $low" -ForegroundColor Green
            } else {
                $high = $mid - 1
                Write-Host "      x Fragmentation detected, lowering ceiling to $high" -ForegroundColor Yellow
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
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $releaseDate = $bios.ReleaseDate
        if (-not $releaseDate) { return $null }
        try {
            $parsedDate = [Management.ManagementDateTimeConverter]::ToDateTime($releaseDate)
        } catch {
            return $null
        }
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
        if ($osVersion.Major -lt 10) {
            Write-Host "  [!] Modern congestion control not supported on this OS." -ForegroundColor Yellow
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
# Parameters: None.
# Returns: None. Sets global reboot flag due to extensive changes.
function Invoke-NetworkTweaksHardcore {
    Write-Section "Network Tweaks: Hardcore (Competitive Gaming)"
    Write-Host "  [!] Warning: MTU discovery will send test packets and adapters may reset, causing temporary disconnects." -ForegroundColor Yellow
    $backupFile = "C:\\ProgramData\\Scynesthesia\\network_backup.json"
    if (Get-Command Save-NetworkBackupState -ErrorAction SilentlyContinue) {
        try {
            if (-not (Test-Path -Path $backupFile)) {
                Write-Host "  [i] No existing network backup found at $backupFile; creating one now." -ForegroundColor Gray
                Save-NetworkBackupState
            } else {
                Write-Host "  [i] Network backup already present at $backupFile; proceeding with tweaks." -ForegroundColor Gray
            }
        } catch {
            Invoke-ErrorHandler -Context 'Saving network backup before hardcore tweaks' -ErrorRecord $_
        }
    } else {
        Write-Host "  [!] Backup helper not available; proceeding without automatic network backup." -ForegroundColor Yellow
    }
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    Set-TcpIpAdvancedParameters
    Set-NetworkThrottlingHardcore
    Set-ServicePriorities
    Set-WinsockOptimizations
    Optimize-LanmanServer
    Set-NetshHardcoreGlobals

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
        $parsedSpeed = Convert-LinkSpeedToBytes -LinkSpeed $primary.LinkSpeed
        if ($null -eq $parsedSpeed) { $parsedSpeed = 0 }
        $speedMbps = [math]::Round($parsedSpeed / 1MB, 2)
        $speedLabel = if ($parsedSpeed -gt 0) {
            if ($speedMbps -ge 1000) { "{0} Gbps" -f ([math]::Round($speedMbps / 1000, 2)) } else { "{0} Mbps" -f $speedMbps }
        } else {
            'Unknown speed'
        }
        Write-Host "  [i] Primary adapter detected: $($primary.Name) ($speedLabel)." -ForegroundColor Cyan
    }

    Set-NicRegistryHardcore
    Set-WakeOnLanHardcore

    foreach ($adapter in $adapters) {
        try {
            Disable-NetAdapterRsc -Name $adapter.Name -ErrorAction Stop | Out-Null
            Write-Host "  [+] RSC disabled on $($adapter.Name)." -ForegroundColor Green
            if ($logger) { Write-Log "[NetworkHardcore] Disabled RSC on $($adapter.Name)." }
        } catch {
            Invoke-ErrorHandler -Context "Disabling RSC on $($adapter.Name)" -ErrorRecord $_
        }

        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'Large Send Offload V2 (IPv4)' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'Large Send Offload V2 (IPv6)' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'IPv4 Checksum Offload' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'TCP Checksum Offload (IPv4)' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'TCP Checksum Offload (IPv6)' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'UDP Checksum Offload (IPv4)' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'UDP Checksum Offload (IPv6)' -DisplayValue 'Disabled'

        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'Receive Buffers' -DisplayValue '512'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'Transmit Buffers' -DisplayValue '4096'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'Flow Control' -DisplayValue 'Disabled'
        Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName 'Interrupt Moderation' -DisplayValue 'Disabled'
    }

    if ($primaryAdapters) {
        foreach ($adapter in $primaryAdapters) {
            try {
                $rssCapabilities = Get-NetAdapterRss -Name $adapter.Name -ErrorAction SilentlyContinue
                if (-not $rssCapabilities) {
                Write-Host "  [i] RSS not supported by this hardware; skipping." -ForegroundColor Gray
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
    $autotuneLevel = if ($ageYears -and $ageYears -gt 6) { 'highlyrestricted' } else { 'disabled' }
    if ($ageYears -ne $null) {
        $reason = if ($autotuneLevel -eq 'highlyrestricted') {
            "Older hardware (~$ageYears years) detected; using safer autotuning."
        } else {
            "Modern hardware (~$ageYears years) detected; disabling autotuning for latency."
        }
        Write-Host "  [i] $reason" -ForegroundColor Cyan
    }
    try {
        netsh int tcp set global autotuninglevel=$autotuneLevel | Out-Null
        $ageLabel = if ($null -ne $ageYears -and "$ageYears" -ne '') { "$ageYears years" } else { 'Unknown' }
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

    Write-Host "  [+] Hardcore network tweaks complete." -ForegroundColor Green
    $Global:NeedsReboot = $true
}

Export-ModuleMember -Function Invoke-NetworkTweaksHardcore
