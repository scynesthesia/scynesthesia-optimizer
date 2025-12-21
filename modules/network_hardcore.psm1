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

function Get-PrimaryNetAdapter {
    try {
        $adapters = Get-EligibleNetAdapters
        if ($adapters.Count -eq 0) { return $null }
        return $adapters | Sort-Object -Property LinkSpeed -Descending | Select-Object -First 1
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
        Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -DisplayValue $DisplayValue -ErrorAction Stop | Out-Null
        Write-Host "  [+] $DisplayName set to $DisplayValue on $AdapterName / $DisplayName configurado a $DisplayValue en $AdapterName" -ForegroundColor Green
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
        $pingResult = ping -f -l $PayloadSize -n 1 $Target 2>&1
        $success = $pingResult -notmatch 'frag' -and $pingResult -match 'TTL='
        return $success
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

        while ($low -le $high) {
            $mid = [int](($low + $high) / 2)
            if (Test-MtuSize -PayloadSize $mid -Target $Target) {
                $best = $mid
                $low = $mid + 1
            } else {
                $high = $mid - 1
            }
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
                Write-Log "[NetworkHardcore] MTU set to $Mtu on $($adapter.Name) (IPv4)."
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
        $parsedDate = [Management.ManagementDateTimeConverter]::ToDateTime($releaseDate)
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

        if ($bbrAvailable -and Ask-YesNo "Enable experimental BBR congestion control? / ¿Habilitar control de congestión BBR experimental?" 'n') {
            try {
                netsh int tcp set global congestionprovider=bbr | Out-Null
                Write-Host "  [+] TCP congestion provider set to BBR. / Proveedor de congestión TCP configurado a BBR." -ForegroundColor Green
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "[NetworkHardcore] TCP congestion provider set to BBR." }
                return
            } catch {
                Handle-Error -Context 'Setting TCP congestion provider to BBR' -ErrorRecord $_
            }
        }

        try {
            netsh int tcp set global congestionprovider=cubic | Out-Null
            Write-Host "  [+] TCP congestion provider set to CUBIC. / Proveedor de congestión TCP configurado a CUBIC." -ForegroundColor Green
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log "[NetworkHardcore] TCP congestion provider set to CUBIC." }
        } catch {
            Handle-Error -Context 'Setting TCP congestion provider to CUBIC' -ErrorRecord $_
        }
    } catch {
        Handle-Error -Context 'Evaluating TCP congestion provider' -ErrorRecord $_
    }
}

function Invoke-NetworkTweaksHardcore {
    Write-Section "Network Tweaks: Hardcore (Competitive Gaming) / Tweaks de Red: Hardcore (Gaming Competitivo)"
    Write-Host "  [!] Warning: MTU discovery and adapter resets may cause brief network drops. / Advertencia: El descubrimiento MTU y los reinicios de adaptador pueden causar caídas temporales." -ForegroundColor Yellow
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
        Write-Host "  [i] Primary adapter detected: $($primary.Name) ($([math]::Round($primary.LinkSpeed/1MB,2)) Mbps). / Adaptador primario detectado: $($primary.Name) ($([math]::Round($primary.LinkSpeed/1MB,2)) Mbps)." -ForegroundColor Cyan
    }

    foreach ($adapter in $adapters) {
        try {
            Disable-NetAdapterRsc -Name $adapter.Name -ErrorAction Stop | Out-Null
            Write-Host "  [+] RSC disabled on $($adapter.Name). / RSC deshabilitado en $($adapter.Name)." -ForegroundColor Green
            if ($logger) { Write-Log "[NetworkHardcore] Disabled RSC on $($adapter.Name)." }
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
                Set-NetAdapterRss -Name $adapter.Name -Profile ClosestProcessor -ErrorAction Stop | Out-Null
                Write-Host "  [+] RSS profile set to ClosestProcessor on $($adapter.Name). / Perfil RSS configurado en ClosestProcessor para $($adapter.Name)." -ForegroundColor Green
                if ($logger) { Write-Log "[NetworkHardcore] RSS profile set to ClosestProcessor on $($adapter.Name)." }
            } catch {
                Handle-Error -Context "Configuring RSS on $($adapter.Name)" -ErrorRecord $_
            }
        }
    }

    Suggest-NetworkIrqCores

    try {
        netsh int tcp set global ecncapability=disabled | Out-Null
        Write-Host "  [+] ECN capability disabled. / Capacidad ECN deshabilitada." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] ECN capability disabled." }
    } catch {
        Handle-Error -Context 'Disabling ECN capability' -ErrorRecord $_
    }

    try {
        netsh int tcp set global timestamps=disabled | Out-Null
        Write-Host "  [+] TCP timestamps disabled. / Timestamps TCP deshabilitados." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] TCP timestamps disabled." }
    } catch {
        Handle-Error -Context 'Disabling TCP timestamps' -ErrorRecord $_
    }

    try {
        netsh int tcp set global initialrto=2000 | Out-Null
        Write-Host "  [+] Initial RTO set to 2000ms. / RTO inicial configurado a 2000ms." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] InitialRTO set to 2000ms." }
    } catch {
        Handle-Error -Context 'Setting InitialRTO' -ErrorRecord $_
    }

    $ageYears = Get-HardwareAgeYears
    $autotuneLevel = if ($ageYears -and $ageYears -gt 6) { 'highlyrestricted' } else { 'disabled' }
    try {
        netsh int tcp set global autotuninglevel=$autotuneLevel | Out-Null
        Write-Host "  [+] Network autotuning set to $autotuneLevel. / Autotuning de red configurado a $autotuneLevel." -ForegroundColor Green
        if ($logger) { Write-Log "[NetworkHardcore] Autotuning level set to $autotuneLevel (hardware age: $ageYears years)." }
    } catch {
        Handle-Error -Context 'Setting TCP autotuning level' -ErrorRecord $_
    }

    $mtu = Find-OptimalMtu
    if ($mtu) {
        Apply-MtuToAdapters -Mtu $mtu -Adapters $adapters
    }

    Set-TcpCongestionProvider

    Write-Host "  [+] Hardcore network tweaks complete. / Tweaks de red hardcore completados." -ForegroundColor Green
    $Global:NeedsReboot = $true
}

Export-ModuleMember -Function Invoke-NetworkTweaksHardcore
