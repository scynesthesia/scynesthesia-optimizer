function Get-EligibleNetAdapters {
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object {
                $_.Status -eq 'Up' -and
                $_.InterfaceDescription -notmatch '(?i)virtual|vmware|hyper-v|loopback|vpn|tap|wireguard|bluetooth'
            }
        return $adapters
    } catch {
        Handle-Error -Context 'Retrieving physical network adapters' -ErrorRecord $_
        return @()
    }
}

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
        Handle-Error -Context 'Parsing adapter link speed' -ErrorRecord $_
    }

    return $null
}

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
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) in TCP parameters / $($entry.Key) configurado a $($entry.Value) en parámetros TCP." -ForegroundColor Green
            } catch {
                Handle-Error -Context "Setting $($entry.Key) in TCP parameters" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Handle-Error -Context 'Configuring advanced TCP/IP parameters' -ErrorRecord $_
    }
}

function Set-NetworkThrottlingHardcore {
    try {
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
        try {
            Set-RegistryValueSafe -Path $path -Name 'NetworkThrottlingIndex' -Value 0xFFFFFFFF -Type DWord
            Write-Host "  [+] NetworkThrottlingIndex set to maximum performance / NetworkThrottlingIndex configurado para máximo rendimiento." -ForegroundColor Green
            $Global:NeedsReboot = $true
        } catch {
            Handle-Error -Context 'Setting NetworkThrottlingIndex' -ErrorRecord $_
        }
    } catch {
        Handle-Error -Context 'Configuring network throttling' -ErrorRecord $_
    }
}

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
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) in ServiceProvider / $($entry.Key) configurado a $($entry.Value) en ServiceProvider." -ForegroundColor Green
            } catch {
                Handle-Error -Context "Setting $($entry.Key) service priority" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Handle-Error -Context 'Configuring ServiceProvider priorities' -ErrorRecord $_
    }
}

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
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) for Winsock / $($entry.Key) configurado a $($entry.Value) para Winsock." -ForegroundColor Green
            } catch {
                Handle-Error -Context "Setting Winsock $($entry.Key)" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Handle-Error -Context 'Applying Winsock optimizations' -ErrorRecord $_
    }
}

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
                Write-Host "  [+] $($entry.Key) set to $($entry.Value) for LanmanServer / $($entry.Key) configurado a $($entry.Value) para LanmanServer." -ForegroundColor Green
            } catch {
                Handle-Error -Context "Setting LanmanServer $($entry.Key)" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
    } catch {
        Handle-Error -Context 'Optimizing LanmanServer parameters' -ErrorRecord $_
    }
}

function Set-NetshHardcoreGlobals {
    try {
        $commands = @(
            @{ Cmd = 'netsh int tcp set global dca=enabled'; Description = 'DCA enabled / DCA habilitado' },
            @{ Cmd = 'netsh int tcp set global netdma=enabled'; Description = 'NetDMA enabled / NetDMA habilitado' },
            @{ Cmd = 'netsh int tcp set global nonsackrttresiliency=disabled'; Description = 'NonSackRTTResiliency disabled / NonSackRTTResiliency deshabilitado' },
            @{ Cmd = 'netsh int tcp set global maxsynretransmissions=2'; Description = 'MaxSynRetransmissions set / MaxSynRetransmissions configurado' },
            @{ Cmd = 'netsh int tcp set global mpp=disabled'; Description = 'MPP disabled / MPP deshabilitado' },
            @{ Cmd = 'netsh int tcp set security profiles=disabled'; Description = 'Security profiles disabled / Perfiles de seguridad deshabilitados' },
            @{ Cmd = 'netsh int tcp set heuristics disabled'; Description = 'Heuristics disabled / Heurísticas deshabilitadas' },
            @{ Cmd = 'netsh int ip set global neighborcachelimit=4096'; Description = 'NeighborCacheLimit set / NeighborCacheLimit configurado' }
        )

        Push-Location -Path ($env:SystemRoot | ForEach-Object { if ($_ -and (Test-Path $_)) { $_ } else { $env:WINDIR } })
        try {
            foreach ($command in $commands) {
                try {
                    & cmd.exe /c $command.Cmd 2>&1 | Out-Null
                    Write-Host "  [+] $($command.Description)." -ForegroundColor Green
                } catch {
                    Handle-Error -Context "Running $($command.Cmd)" -ErrorRecord $_
                }
            }
        } finally {
            Pop-Location -ErrorAction SilentlyContinue
        }

        $Global:NeedsReboot = $true
    } catch {
        Handle-Error -Context 'Applying hardcore netsh globals' -ErrorRecord $_
    }
}

function Get-NicRegistryPaths {
    try {
        $classPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}'
        $adapters = Get-EligibleNetAdapters
        $results = @()

        function Normalize-GuidString {
            param($Value)

            try {
                if ($null -eq $Value) { return $null }

                if ($Value -is [string]) {
                    $trimmed = $Value.Trim('{}').Trim()
                    if (-not $trimmed) { return $null }
                    return "{$trimmed}".ToUpperInvariant()
                }

                if ($Value -is [guid]) {
                    return $Value.ToString('B').ToUpperInvariant()
                }

                return ([guid]$Value).ToString('B').ToUpperInvariant()
            } catch {
                return $null
            }
        }

        foreach ($adapter in $adapters) {
            try {
                $guidString = Normalize-GuidString -Value $adapter.InterfaceGuid
                if (-not $guidString) { continue }
                $entries = Get-ChildItem -Path $classPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
                foreach ($entry in $entries) {
                    try {
                        $netCfg = (Get-ItemProperty -Path $entry.PSPath -Name 'NetCfgInstanceId' -ErrorAction SilentlyContinue).NetCfgInstanceId
                        $netCfgString = Normalize-GuidString -Value $netCfg
                        if ($netCfgString -and ($netCfgString -eq $guidString)) {
                            $results += [pscustomobject]@{ Adapter = $adapter; Path = $entry.PSPath; Guid = $guidString }
                            break
                        }
                    } catch { }
                }
            } catch {
                Handle-Error -Context "Finding registry path for $($adapter.Name)" -ErrorRecord $_
            }
        }

        return $results
    } catch {
        Handle-Error -Context 'Enumerating NIC registry paths' -ErrorRecord $_
        return @()
    }
}

function Set-NicRegistryHardcore {
    try {
        $nicPaths = Get-NicRegistryPaths
        if ($nicPaths.Count -eq 0) {
            Write-Host "  [!] No NIC registry paths found for tweaks. / No se encontraron rutas de registro de NIC para ajustes." -ForegroundColor Yellow
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
            # Keep shutdown link at full rate to prevent hidden wake conditions / Mantener el enlace en apagado a velocidad completa para evitar condiciones de wake ocultas.
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
            Write-Host "  [>] Applying registry tweaks to $adapterName / Aplicando ajustes de registro a $adapterName" -ForegroundColor Cyan
            try {
                Set-RegistryValueSafe -Path $item.Path -Name 'PnPCapabilities' -Value 24 -Type DWord
                Write-Host "    [+] PnPCapabilities set to 24 (power management disabled) / PnPCapabilities configurado a 24 (gestión de energía deshabilitada)" -ForegroundColor Green
            } catch {
                Handle-Error -Context "Setting PnPCapabilities on $adapterName" -ErrorRecord $_
            }

            foreach ($entry in $powerOffload.GetEnumerator()) {
                try {
                    Set-RegistryValueSafe -Path $item.Path -Name $entry.Key -Value $entry.Value -Type String
                    Write-Host "    [+] $($entry.Key) set to $($entry.Value) / $($entry.Key) configurado a $($entry.Value)" -ForegroundColor Green
                } catch {
                    Handle-Error -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
                }
            }

            foreach ($entry in $interruptDelays.GetEnumerator()) {
                try {
                    Set-RegistryValueSafe -Path $item.Path -Name $entry.Key -Value $entry.Value -Type String
                    Write-Host "    [+] $($entry.Key) set to $($entry.Value) / $($entry.Key) configurado a $($entry.Value)" -ForegroundColor Green
                } catch {
                    Handle-Error -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
                }
            }

            try {
                $interfacePath = "${'HKLM'}:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($item.Guid)"
                $noiseKeys = @($powerOffload.Keys + $interruptDelays.Keys)
                foreach ($noiseKey in $noiseKeys | Select-Object -Unique) {
                    try {
                        Remove-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue
                    } catch { }
                }

                Set-RegistryValueSafe -Path $interfacePath -Name 'TcpAckFrequency' -Value 1 -Type DWord
                Set-RegistryValueSafe -Path $interfacePath -Name 'TCPNoDelay' -Value 1 -Type DWord
                Set-RegistryValueSafe -Path $interfacePath -Name 'TcpDelAckTicks' -Value 0 -Type DWord
                Write-Host "    [+] Nagle parameters set (Ack=1, NoDelay=1, DelAckTicks=0) / Parámetros Nagle configurados (Ack=1, NoDelay=1, DelAckTicks=0)" -ForegroundColor Green
            } catch {
                Handle-Error -Context "Setting Nagle parameters for $adapterName" -ErrorRecord $_
            }

            try {
                & cmd.exe /c 'netsh int ip reset' 2>&1 | Out-Null
                & cmd.exe /c 'netsh winsock reset' 2>&1 | Out-Null
                Write-Host "    [+] Network stack cache cleared (IP/Winsock reset) / Caché de pila de red borrada (reinicio IP/Winsock)" -ForegroundColor Green
            } catch {
                Handle-Error -Context "Resetting network stack for $adapterName" -ErrorRecord $_
            }

            try {
                Disable-NetAdapter -Name $adapterName -Confirm:$false -PassThru -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 3
                Enable-NetAdapter -Name $adapterName -Confirm:$false -PassThru -ErrorAction Stop | Out-Null
                Write-Host "    [+] Adapter reset to reload driver settings / Adaptador reiniciado para recargar configuraciones del controlador" -ForegroundColor Green
            } catch {
                Handle-Error -Context "Resetting adapter $adapterName" -ErrorRecord $_
            }
        }

        $Global:NeedsReboot = $true
        Write-Host "  [i] Some Device Manager changes may require a full reboot to reflect visually. / [i] Algunos cambios en el Administrador de dispositivos pueden requerir un reinicio completo para reflejarse visualmente." -ForegroundColor Gray
    } catch {
        Handle-Error -Context 'Applying NIC-specific registry tweaks' -ErrorRecord $_
    }
}

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
        Handle-Error -Context 'Selecting primary network adapter' -ErrorRecord $_
        return $null
    }
}

function Set-NetAdapterAdvancedPropertySafe {
    param(
        [Parameter(Mandatory)][string]$AdapterName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$DisplayValue
    )
    try {
        $property = Get-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if (-not $property) {
            Write-Host "  [!] $DisplayName not available on $AdapterName; skipping. / $DisplayName no disponible en $AdapterName; se omite." -ForegroundColor Yellow
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
                Write-Host "  [+] $DisplayName set to $value on $AdapterName / $DisplayName configurado a $value en $AdapterName" -ForegroundColor Green
                return
            } catch {
                Write-Host "  [!] Failed to set $DisplayName to $value on $AdapterName; trying fallback. / Falló configurar $DisplayName a $value en $AdapterName; probando alternativa." -ForegroundColor Yellow
            }
        }

        Write-Host "  [!] Unable to set $DisplayName on $AdapterName after fallbacks. / No se pudo configurar $DisplayName en $AdapterName tras alternativas." -ForegroundColor Yellow
    } catch {
        Handle-Error -Context "Setting $DisplayName on $AdapterName" -ErrorRecord $_
    }
}

function Set-WakeOnLanHardcore {
    <#
        Wake-on-LAN needs both registry and UI alignment because many drivers honor multiple flags at once.
        Wake-on-LAN requiere alineación entre registro y UI porque muchos drivers evalúan múltiples banderas simultáneas.
        WolShutdownLinkSpeed "2" keeps the link in "Not Speed Down" to avoid low-power renegotiation that re-enables WOL paths.
        WolShutdownLinkSpeed "2" mantiene el enlace en "Not Speed Down" para evitar renegociación de bajo consumo que reactive rutas WOL.
    #>
    Write-Host "  [>] Applying Wake-on-LAN hardening (registry + driver UI) / Aplicando refuerzo Wake-on-LAN (registro + UI del controlador)" -ForegroundColor Cyan
    $adapters = Get-EligibleNetAdapters
    if ($adapters.Count -eq 0) {
        Write-Host "  [!] No adapters available for Wake-on-LAN hardening. / [!] No hay adaptadores disponibles para refuerzo Wake-on-LAN." -ForegroundColor Yellow
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $nicPaths = Get-NicRegistryPaths
    if ($nicPaths.Count -eq 0) {
        Write-Host "  [!] Unable to map NIC registry paths; skipping WOL registry enforcement. / [!] No se pudieron mapear rutas de registro NIC; se omite la aplicación WOL en registro." -ForegroundColor Yellow
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
        # "2" = Not Speed Down para mantener el enlace a velocidad completa durante apagado.
        'WolShutdownLinkSpeed' = '2'
    }

    foreach ($adapter in $adapters) {
        $adapterName = $adapter.Name
        try {
            $pathEntry = $nicPaths | Where-Object { $_.Adapter.ifIndex -eq $adapter.ifIndex }
            if ($pathEntry) {
                Write-Host "    [>] Registry WOL sweep on $adapterName / Barrido WOL en registro para $adapterName" -ForegroundColor Cyan
                foreach ($entry in $wolRegistryValues.GetEnumerator()) {
                    try {
                        Set-RegistryValueSafe -Path $pathEntry.Path -Name $entry.Key -Value $entry.Value -Type String
                        Write-Host "      [+] $($entry.Key) set to $($entry.Value) / $($entry.Key) configurado a $($entry.Value)" -ForegroundColor Green
                    } catch {
                        Handle-Error -Context "Setting $($entry.Key) on $adapterName (WOL)" -ErrorRecord $_
                    }
                }
            } else {
                Write-Host "    [!] No registry path found for $adapterName; skipping registry WOL keys. / [!] No se encontró ruta de registro para $adapterName; se omiten claves WOL." -ForegroundColor Yellow
            }

            Write-Host "    [>] Driver UI WOL enforcement on $adapterName / Refuerzo WOL en UI del controlador para $adapterName" -ForegroundColor Cyan
            $uiTargets = @(
                @{ Name = 'Wake on Magic Packet';   Value = 'Disabled' },
                @{ Name = 'Wake on Pattern Match';  Value = 'Disabled' },
                @{ Name = 'Shutdown Wake-on-LAN';   Value = 'Disabled' },
                @{ Name = 'WOL & Shutdown Link Speed'; Value = 'Not Speed Down' }
            )

            foreach ($target in $uiTargets) {
                Set-NetAdapterAdvancedPropertySafe -AdapterName $adapterName -DisplayName $target.Name -DisplayValue $target.Value
            }

            Write-Host "    [>] Verifying WOL properties via Get-NetAdapterAdvancedProperty / Verificando propiedades WOL con Get-NetAdapterAdvancedProperty" -ForegroundColor Cyan
            foreach ($target in $uiTargets) {
                try {
                    $current = Get-NetAdapterAdvancedProperty -Name $adapterName -DisplayName $target.Name -ErrorAction SilentlyContinue
                    if (-not $current) {
                        Write-Host "      [!] $($target.Name) not exposed on $adapterName; confirm driver limitations. / [!] $($target.Name) no expuesto en $adapterName; confirmar limitaciones del controlador." -ForegroundColor Yellow
                        continue
                    }

                    $effective = $current.DisplayValue
                    if ($effective -eq $target.Value) {
                        Write-Host "      [+] $($target.Name) = $effective (OK) / $($target.Name) = $effective (OK)" -ForegroundColor Green
                        if ($logger) { Write-Log "[NetworkHardcore] $($target.Name) confirmed as $effective on $adapterName. / $($target.Name) confirmado como $effective en $adapterName." }
                    } else {
                        Write-Host "      [!] $($target.Name) expected $($target.Value) but found $effective on $adapterName. / [!] $($target.Name) esperaba $($target.Value) pero se encontró $effective en $adapterName." -ForegroundColor Yellow
                    }
                } catch {
                    Handle-Error -Context "Verifying $($target.Name) on $adapterName" -ErrorRecord $_
                }
            }
        } catch {
            Handle-Error -Context "Applying Wake-on-LAN hardening on $adapterName" -ErrorRecord $_
        }
    }
}

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
        Handle-Error -Context "Testing MTU payload size $PayloadSize" -ErrorRecord $_
        return $false
    }
}

function Find-OptimalMtu {
    param(
        [string]$Target = '1.1.1.1'
    )
    try {
        $low = 1200
        $high = 1472 # 1500 - 28 bytes for ICMP/IPv4 headers
        $best = $low
        $step = 1

        while ($low -le $high) {
            $mid = [int](($low + $high) / 2)
            $mtuCandidate = $mid + 28
            Write-Host "  [>] MTU test step ${step}: payload $mid bytes (candidate MTU $mtuCandidate) / Prueba MTU paso ${step}: carga $mid bytes (MTU candidato $mtuCandidate)" -ForegroundColor Cyan
            if (Test-MtuSize -PayloadSize $mid -Target $Target) {
                $best = $mid
                $low = $mid + 1
                Write-Host "      ✓ Success, raising floor to $low / ✓ Exito, se aumenta el minimo a $low" -ForegroundColor Green
            } else {
                $high = $mid - 1
                Write-Host "      x Fragmentation detected, lowering ceiling to $high / x Fragmentacion detectada, se reduce el maximo a $high" -ForegroundColor Yellow
            }
            $step++
        }

        $mtu = $best + 28
        Write-Host "  [+] Optimal MTU discovered: $mtu bytes / MTU óptimo encontrado: $mtu bytes" -ForegroundColor Green
        return $mtu
    } catch {
        Handle-Error -Context 'Discovering optimal MTU' -ErrorRecord $_
        return $null
    }
}

function Apply-MtuToAdapters {
    param(
        [Parameter(Mandatory)][int]$Mtu,
        [System.Collections.IEnumerable]$Adapters
    )
    foreach ($adapter in $Adapters) {
        try {
            Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -NlMtu $Mtu -AddressFamily IPv4 -ErrorAction Stop | Out-Null
            Write-Host "  [+] MTU $Mtu applied to $($adapter.Name) (IPv4) / MTU $Mtu aplicado a $($adapter.Name) (IPv4)." -ForegroundColor Green
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log "[NetworkHardcore] MTU set to $Mtu on $($adapter.Name) (IPv4). / MTU configurado a $Mtu en $($adapter.Name) (IPv4)."
            }
        } catch {
            Handle-Error -Context "Applying MTU to $($adapter.Name)" -ErrorRecord $_
        }
    }
}

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
        Handle-Error -Context 'Determining hardware age' -ErrorRecord $_
        return $null
    }
}

function Suggest-NetworkIrqCores {
    try {
        $logical = [Environment]::ProcessorCount
        $half = [int][Math]::Ceiling($logical / 2)
        $range = "0-$(if ($half -gt 0) { $half - 1 } else { 0 })"
        Write-Host "  [i] Suggestion: Pin network IRQs to early cores (e.g., $range) for lowest latency. / Sugerencia: Fijar las IRQ de red a los primeros núcleos (ej. $range) para menor latencia." -ForegroundColor Cyan
    } catch {
        Handle-Error -Context 'Suggesting IRQ core distribution' -ErrorRecord $_
    }
}

function Set-TcpCongestionProvider {
    try {
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -lt 10) {
            Write-Host "  [!] Modern congestion control not supported on this OS. / Control de congestión moderno no soportado en este sistema." -ForegroundColor Yellow
            return
        }

        $supplemental = $null
        try {
            $supplemental = netsh int tcp show supplemental 2>&1
        } catch {
            Handle-Error -Context 'Checking supplemental congestion providers' -ErrorRecord $_
        }

        $bbrAvailable = $false
        if ($supplemental) {
            $bbrAvailable = $supplemental -match '(?i)bbr'
        }

        if ($bbrAvailable -and (Ask-YesNo "Enable experimental BBR congestion control? / ¿Habilitar control de congestión BBR experimental?" 'n')) {
            try {
                netsh int tcp set global congestionprovider=bbr | Out-Null
                Write-Host "  [+] TCP congestion provider set to BBR (experimental, favors throughput+latency). / Proveedor de congestión TCP configurado a BBR (experimental, prioriza rendimiento y latencia)." -ForegroundColor Green
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "[NetworkHardcore] TCP congestion provider set to BBR. / Proveedor de congestión TCP configurado a BBR." }
                return
            } catch {
                Handle-Error -Context 'Setting TCP congestion provider to BBR' -ErrorRecord $_
            }
        }

        Write-Host "  [i] Defaulting to stable CUBIC congestion control. / Se usará CUBIC como control de congestión estable." -ForegroundColor Cyan
        try {
            netsh int tcp set global congestionprovider=cubic | Out-Null
            Write-Host "  [+] TCP congestion provider set to CUBIC. / Proveedor de congestión TCP configurado a CUBIC." -ForegroundColor Green
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "[NetworkHardcore] TCP congestion provider set to CUBIC. / Proveedor de congestión TCP configurado a CUBIC." }
        } catch {
            Handle-Error -Context 'Setting TCP congestion provider to CUBIC' -ErrorRecord $_
        }
    } catch {
        Handle-Error -Context 'Evaluating TCP congestion provider' -ErrorRecord $_
    }
}

function Invoke-NetworkTweaksHardcore {
    Write-Section "Network Tweaks: Hardcore (Competitive Gaming) / Tweaks de Red: Hardcore (Gaming Competitivo)"
    Write-Host "  [!] Warning: MTU discovery will send test packets and adapters may reset, causing temporary disconnects. / Advertencia: El descubrimiento de MTU enviará paquetes de prueba y los adaptadores pueden reiniciarse, causando desconexiones temporales." -ForegroundColor Yellow
    $backupFile = "C:\\ProgramData\\Scynesthesia\\network_backup.json"
    if (Get-Command Save-NetworkBackupState -ErrorAction SilentlyContinue) {
        try {
            if (-not (Test-Path -Path $backupFile)) {
                Write-Host "  [i] No existing network backup found at $backupFile; creating one now. / [i] No se encontró un respaldo de red en $backupFile; se creará uno ahora." -ForegroundColor Gray
                Save-NetworkBackupState
            } else {
                Write-Host "  [i] Network backup already present at $backupFile; proceeding with tweaks. / [i] Respaldo de red ya existente en $backupFile; se continúa con los tweaks." -ForegroundColor Gray
            }
        } catch {
            Handle-Error -Context 'Saving network backup before hardcore tweaks' -ErrorRecord $_
        }
    } else {
        Write-Host "  [!] Backup helper not available; proceeding without automatic network backup. / [!] Herramienta de respaldo no disponible; se continúa sin backup automático de red." -ForegroundColor Yellow
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
        Write-Host "  [!] No active physical adapters detected. / No se detectaron adaptadores físicos activos." -ForegroundColor Yellow
        return
    }

    $primary = Get-PrimaryNetAdapter
    if (-not $primary) {
        Write-Host "  [!] Unable to determine primary adapter; using all adapters for tweaks. / No se pudo determinar el adaptador primario; se usarán todos los adaptadores para los tweaks." -ForegroundColor Yellow
        $primaryAdapters = $adapters
    } else {
        $primaryAdapters = @($primary)
        $parsedSpeed = Convert-LinkSpeedToBytes -LinkSpeed $primary.LinkSpeed
        if ($null -eq $parsedSpeed) { $parsedSpeed = 0 }
        $speedMbps = [math]::Round($parsedSpeed / 1MB, 2)
        $speedLabel = if ($parsedSpeed -gt 0) {
            if ($speedMbps -ge 1000) { "{0} Gbps" -f ([math]::Round($speedMbps / 1000, 2)) } else { "{0} Mbps" -f $speedMbps }
        } else {
            'Unknown speed / Velocidad desconocida'
        }
        Write-Host "  [i] Primary adapter detected: $($primary.Name) ($speedLabel). / Adaptador primario detectado: $($primary.Name) ($speedLabel)." -ForegroundColor Cyan
    }

    Set-NicRegistryHardcore
    Set-WakeOnLanHardcore

    foreach ($adapter in $adapters) {
        try {
            Disable-NetAdapterRsc -Name $adapter.Name -ErrorAction Stop | Out-Null
            Write-Host "  [+] RSC disabled on $($adapter.Name). / RSC deshabilitado en $($adapter.Name)." -ForegroundColor Green
            if ($logger) { Write-Log "[NetworkHardcore] Disabled RSC on $($adapter.Name). / RSC deshabilitado en $($adapter.Name)." }
        } catch {
            Handle-Error -Context "Disabling RSC on $($adapter.Name)" -ErrorRecord $_
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
                    Write-Host "  [i] RSS not supported by this hardware; skipping. / RSS no soportado por este hardware; se omite." -ForegroundColor Gray
                    continue
                }

                Set-NetAdapterRss -Name $adapter.Name -Profile Closest -ErrorAction Stop | Out-Null
                Write-Host "  [+] RSS profile set to Closest on $($adapter.Name). / Perfil RSS configurado en Closest para $($adapter.Name)." -ForegroundColor Green
                if ($logger) { Write-Log "[NetworkHardcore] RSS profile set to Closest on $($adapter.Name). / Perfil RSS configurado en Closest para $($adapter.Name)." }
            } catch {
                Handle-Error -Context "Configuring RSS on $($adapter.Name)" -ErrorRecord $_
            }
        }
    }

    Suggest-NetworkIrqCores

    try {
        netsh int tcp set global ecncapability=disabled | Out-Null
        Write-Host "  [+] ECN capability disabled. / Capacidad ECN deshabilitada." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] ECN capability disabled. / Capacidad ECN deshabilitada." }
    } catch {
        Handle-Error -Context 'Disabling ECN capability' -ErrorRecord $_
    }

    try {
        netsh int tcp set global timestamps=disabled | Out-Null
        Write-Host "  [+] TCP timestamps disabled. / Timestamps TCP deshabilitados." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] TCP timestamps disabled. / Timestamps TCP deshabilitados." }
    } catch {
        Handle-Error -Context 'Disabling TCP timestamps' -ErrorRecord $_
    }

    try {
        netsh int tcp set global initialrto=2000 | Out-Null
        Write-Host "  [+] Initial RTO set to 2000ms. / RTO inicial configurado a 2000ms." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] InitialRTO set to 2000ms. / InitialRTO configurado a 2000ms." }
    } catch {
        Handle-Error -Context 'Setting InitialRTO' -ErrorRecord $_
    }

    $ageYears = Get-HardwareAgeYears
    $autotuneLevel = if ($ageYears -and $ageYears -gt 6) { 'highlyrestricted' } else { 'disabled' }
    if ($ageYears -ne $null) {
        $reason = if ($autotuneLevel -eq 'highlyrestricted') {
            "Older hardware (~$ageYears years) detected; using safer autotuning. / Hardware más antiguo (~$ageYears años) detectado; se usa autotuning más conservador."
        } else {
            "Modern hardware (~$ageYears years) detected; disabling autotuning for latency. / Hardware moderno (~$ageYears años) detectado; se desactiva autotuning para menor latencia."
        }
        Write-Host "  [i] $reason" -ForegroundColor Cyan
    }
    try {
        netsh int tcp set global autotuninglevel=$autotuneLevel | Out-Null
        $ageLabel = if ($null -ne $ageYears -and "$ageYears" -ne '') { "$ageYears years / $ageYears años" } else { 'Unknown / Desconocida' }
        Write-Host "  [+] Network autotuning set to $autotuneLevel (hardware age: $ageLabel). / Autotuning de red configurado a $autotuneLevel (edad de hardware: $ageLabel)." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] Autotuning level set to $autotuneLevel (hardware age: $ageLabel). / Nivel de autotuning configurado a $autotuneLevel (edad de hardware: $ageLabel)." }
    } catch {
        Handle-Error -Context 'Setting TCP autotuning level' -ErrorRecord $_
    }

    $mtu = Find-OptimalMtu
    if ($mtu) {
        Apply-MtuToAdapters -Mtu $mtu -Adapters @($adapters)
    }

    Set-TcpCongestionProvider

    Write-Host "  [+] Hardcore network tweaks complete. / Tweaks de red hardcore completados." -ForegroundColor Green
    $Global:NeedsReboot = $true
}

Export-ModuleMember -Function Invoke-NetworkTweaksHardcore
