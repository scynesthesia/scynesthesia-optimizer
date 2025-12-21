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
