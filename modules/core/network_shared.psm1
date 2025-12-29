# Description: Shared helpers for network tweaks reused across presets.

function Convert-LinkSpeedToBits {
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
                    'g' { return [int64]($value * 1e9) }
                    'm' { return [int64]($value * 1e6) }
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

function Get-SharedNicRegistryPaths {
    param(
        [ScriptBlock]$AdapterResolver,
        [string]$LoggerPrefix = '[Network]',
        [switch]$AllowOwnershipFallback,
        [ref]$AccessDeniedFlag
    )

    $parameters = @{
        AdapterResolver        = $AdapterResolver
        AllowOwnershipFallback = $AllowOwnershipFallback
        LoggerPrefix           = $LoggerPrefix
    }

    if ($PSBoundParameters.ContainsKey('AccessDeniedFlag')) {
        $parameters['AccessDeniedFlag'] = $AccessDeniedFlag
    }

    $map = network_discovery\Get-NicRegistryMap @parameters
    return $map | ForEach-Object {
        [pscustomobject]@{
            Adapter = $_.AdapterObject
            Path    = $_.RegistryPath
            Guid    = $_.InterfaceGuid
            IfIndex = $_.IfIndex
        }
    }
}

function Invoke-NagleRegistryUpdate {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][object[]]$Adapters,
        [string]$LoggerPrefix = '[Network]',
        [string]$InvokeOnceId = 'Nagle:Tcp'
    )

    $context = Get-RunContext -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    if (-not $Adapters -or $Adapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for Nagle adjustments." -ForegroundColor Yellow
        return [pscustomobject]@{ Applied = $false; Changed = $false; ChangedAdapters = @() }
    }

    $nagleAllowed = Invoke-Once -Context $context -Id $InvokeOnceId -Action { $true }
    if (-not $nagleAllowed) {
        Write-Host "  [ ] Nagle-related parameters already applied this session; skipping." -ForegroundColor Gray
        return [pscustomobject]@{ Applied = $false; Changed = $false; ChangedAdapters = @() }
    }

    $changesMade = $false
    $changedAdapters = @()

    foreach ($adapter in $Adapters) {
        $guid = $adapter.InterfaceGuid
        if (-not $guid) { continue }

        $normalizedGuid = ($guid.ToString()).Trim('{}')
        $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{$normalizedGuid}"
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
                New-ItemProperty -Path $path -Name $entry.Key -Value $entry.Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                if ($logger) {
                    Write-Log "$LoggerPrefix Nagle for '$($adapter.Name)': $($entry.Key) $(if ($existing[$entry.Key] -eq $entry.Value) { 'unchanged' } else { "$($existing[$entry.Key]) -> $($entry.Value)" })"
                }
                if ($existing[$entry.Key] -ne $entry.Value) {
                    $changesMade = $true
                    $changedAdapters += $adapter.Name
                }
            }
            Write-Host "  [+] Nagle-related parameters optimized for $($adapter.Name)." -ForegroundColor Green
        } catch {
            Invoke-ErrorHandler -Context "Setting Nagle parameters on $($adapter.Name)" -ErrorRecord $_
        }
    }

    if ($changesMade) {
        Set-RebootRequired -Context $context | Out-Null
    }

    return [pscustomobject]@{
        Applied         = $true
        Changed         = $changesMade
        ChangedAdapters = ($changedAdapters | Select-Object -Unique)
    }
}

function Invoke-NicPowerRegistryTweaks {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][object[]]$NicPaths,
        [hashtable]$Values,
        [int]$PnPCapabilitiesValue = 24,
        [string]$LoggerPrefix = '[Network]',
        [string]$InvokeOnceId = 'NicPower:Base',
        [switch]$CleanupInterfaceNoise
    )

    $context = Get-RunContext -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $allowed = Invoke-Once -Context $context -Id $InvokeOnceId -Action { $true }
    if (-not $allowed) {
        Write-Host "  [ ] NIC power tweaks already applied this session; skipping." -ForegroundColor Gray
        return [pscustomobject]@{ Applied = $false; Changed = $false; ChangedAdapters = @() }
    }

    $changedAdapters = @()
    foreach ($item in $NicPaths) {
        $adapterName = $item.Adapter.Name
        $adapterChanged = $false
        try {
            $currentPnP = $null
            try {
                $currentPnP = (Get-ItemProperty -Path $item.Path -Name 'PnPCapabilities' -ErrorAction Stop).PnPCapabilities
            } catch { }

            if ($currentPnP -ne $PnPCapabilitiesValue) {
                $pnPResult = Set-RegistryValueSafe -Path $item.Path -Name 'PnPCapabilities' -Value $PnPCapabilitiesValue -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $context -Critical -ReturnResult -OperationLabel "$LoggerPrefix $adapterName PnPCapabilities"
                if ($pnPResult -and $pnPResult.Success) {
                    Write-Host "    [+] PnPCapabilities set to $PnPCapabilitiesValue (power management disabled)" -ForegroundColor Green
                    if ($logger) { Write-Log "$LoggerPrefix $adapterName PnPCapabilities set to $PnPCapabilitiesValue." }
                    $adapterChanged = $true
                } else {
                    Write-Host "    [!] Failed to set PnPCapabilities for $adapterName (permission issue?)." -ForegroundColor Yellow
                }
            }
        } catch {
            Invoke-ErrorHandler -Context "Setting PnPCapabilities on $adapterName" -ErrorRecord $_
        }

        foreach ($entry in $Values.GetEnumerator()) {
            try {
                $currentValue = $null
                try {
                    $currentValue = (Get-ItemProperty -Path $item.Path -Name $entry.Key -ErrorAction Stop).$entry.Key
                } catch { }

                if ($currentValue -ne $entry.Value) {
                    $valueResult = Set-RegistryValueSafe -Path $item.Path -Name $entry.Key -Value $entry.Value -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $context -Critical -ReturnResult -OperationLabel "$LoggerPrefix $adapterName $($entry.Key)"
                    if ($valueResult -and $valueResult.Success) {
                        Write-Host "    [+] $($entry.Key) set to $($entry.Value)" -ForegroundColor Green
                        if ($logger) { Write-Log "$LoggerPrefix $adapterName $($entry.Key) set to $($entry.Value)." }
                        $adapterChanged = $true
                    } else {
                        Write-Host "    [!] Failed to set $($entry.Key) for $adapterName (permission issue?)." -ForegroundColor Yellow
                    }
                }
            } catch {
                Invoke-ErrorHandler -Context "Setting $($entry.Key) on $adapterName" -ErrorRecord $_
            }
        }

        if ($CleanupInterfaceNoise) {
            try {
                $normalizedGuid = ($item.Guid.ToString()).Trim('{}')
                $interfacePath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{$normalizedGuid}"
                $cleanupKeys = @($Values.Keys) + @('PnPCapabilities')
                foreach ($noiseKey in $cleanupKeys | Select-Object -Unique) {
                    try {
                        if (Get-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue) {
                            Remove-ItemProperty -Path $interfacePath -Name $noiseKey -ErrorAction SilentlyContinue
                            $adapterChanged = $true
                        }
                    } catch { }
                }
            } catch {
                Invoke-ErrorHandler -Context "Cleaning interface overrides for $adapterName" -ErrorRecord $_
            }
        }

        if ($adapterChanged) {
            $changedAdapters += $adapterName
        }
    }

    if ($changedAdapters.Count -gt 0) {
        Set-RebootRequired -Context $context | Out-Null
    }

    return [pscustomobject]@{
        Applied         = $true
        Changed         = ($changedAdapters.Count -gt 0)
        ChangedAdapters = ($changedAdapters | Select-Object -Unique)
    }
}

function Invoke-MsiModeOnce {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string[]]$Targets,
        [string]$PromptMessage,
        [string]$InvokeOnceId,
        [char]$DefaultResponse = 'n'
    )

    $context = Get-RunContext -Context $Context
    $id = if ($InvokeOnceId) { $InvokeOnceId } else { "MSI:$([string]::Join(',', ($Targets | Sort-Object)))" }

    $allowed = Invoke-Once -Context $context -Id $id -Action { $true }
    if (-not $allowed) {
        Write-Host "  [ ] MSI Mode already applied for $($Targets -join ', ') this session; skipping." -ForegroundColor Gray
        return $null
    }

    if ($PromptMessage) {
        if (-not (Get-Confirmation $PromptMessage $DefaultResponse)) {
            Write-Host "  [ ] MSI Mode skipped." -ForegroundColor Gray
            return $null
        }
    }

    return Enable-MsiModeSafe -Target $Targets -Context $context
}

function Set-NetAdapterAdvancedPropertySafe {
    param(
        [Parameter(Mandatory)][string]$AdapterName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$DisplayValue
    )
    try {
        $adapterInfo = $null
        try {
            $adapterInfo = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
        } catch { }
        $linkSpeedBits = if ($adapterInfo) { Convert-LinkSpeedToBits -LinkSpeed $adapterInfo.LinkSpeed } else { $null }
        $isSubGigabit = ($linkSpeedBits -and $linkSpeedBits -lt 1e9)
        $isHundredMbps = ($linkSpeedBits -and [math]::Abs($linkSpeedBits - 1e8) -lt 1e7)

        $property = Get-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -ErrorAction SilentlyContinue
        if (-not $property) {
            Write-Host "  [!] $DisplayName not available on $AdapterName; skipping." -ForegroundColor Yellow
            return $false
        }

        if ($property.DisplayValue -eq $DisplayValue) {
            Write-Host "  [i] $DisplayName already set to $DisplayValue on $AdapterName; no change needed." -ForegroundColor Gray
            if ($DisplayName -in @('Transmit Buffers', 'Receive Buffers') -and "$DisplayValue" -eq '128') {
                Write-Host "  [i] Value restricted by driver/hardware capacity." -ForegroundColor Gray
            }
            return $false
        }

        $valuesToTry = New-Object System.Collections.Generic.List[string]
        $preferredBufferValues = New-Object System.Collections.Generic.List[string]
        $addUnique = {
            param($list, $candidate)
            if (-not $candidate) { return }
            $valString = "$candidate"
            if (-not $list.Contains($valString)) { $list.Add($valString) | Out-Null }
        }

        if ($DisplayName -in @('Transmit Buffers', 'Receive Buffers')) {
            $collectValidValues = {
                param($source)
                $collected = @()
                if (-not $source) { return $collected }
                $possibleKeys = @('ValidDisplayValues', 'ValidRegistryValues')
                foreach ($key in $possibleKeys) {
                    try {
                        if ($source.PSObject.Properties[$key]) {
                            $raw = $source.$key
                            if ($raw -is [System.Array]) {
                                $collected += $raw
                            } elseif ($null -ne $raw) {
                                $collected += @($raw)
                            }
                        }
                    } catch { }
                }

                $collected = $collected | Where-Object { $_ -ne $null -and ("$_").Trim() -ne '' }
                if ($collected.Count -eq 0) { return @() }

                $numeric = @()
                $nonNumeric = @()
                foreach ($item in $collected) {
                    $valueString = ("$item").Trim()
                    $parsed = 0
                    if ([long]::TryParse($valueString, [ref]$parsed)) {
                        $numeric += $parsed
                    } else {
                        $nonNumeric += $valueString
                    }
                }

                $numeric = $numeric | Sort-Object -Unique
                $nonNumeric = $nonNumeric | Sort-Object -Unique
                return @($numeric + $nonNumeric)
            }

            $validValues = & $collectValidValues $property
            foreach ($value in $validValues) {
                & $addUnique $valuesToTry $value
            }

            if ($DisplayName -eq 'Transmit Buffers') {
                if ($isSubGigabit) {
                    & $addUnique $preferredBufferValues 256
                } elseif (-not $isHundredMbps) {
                    & $addUnique $preferredBufferValues 512
                    & $addUnique $preferredBufferValues 4096
                }
            } elseif ($DisplayName -eq 'Receive Buffers') {
                if ($isSubGigabit) {
                    & $addUnique $preferredBufferValues 128
                } else {
                    & $addUnique $preferredBufferValues 512
                    & $addUnique $preferredBufferValues 1024
                }
            }
        } else {
            $preferredBufferValues.Add($DisplayValue) | Out-Null
        }

        $orderedValues = New-Object System.Collections.Generic.List[string]
        foreach ($value in $preferredBufferValues) {
            & $addUnique $orderedValues $value
        }
        foreach ($value in $valuesToTry) {
            & $addUnique $orderedValues $value
        }

        $anyApplied = $false
        foreach ($value in $orderedValues) {
            try {
                Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName $DisplayName -DisplayValue $value -NoRestart -ErrorAction Stop | Out-Null
                Write-Host "  [+] $DisplayName set to $value on $AdapterName." -ForegroundColor Green
                $anyApplied = $true
                break
            } catch {
                if ($orderedValues.Count -eq 1) {
                    Invoke-ErrorHandler -Context "Setting $DisplayName to $value on $AdapterName" -ErrorRecord $_
                }
            }
        }

        if (-not $anyApplied) {
            Write-Host "  [!] Unable to set $DisplayName on $AdapterName; driver rejected provided values." -ForegroundColor Yellow
        }

        return $anyApplied
    } catch {
        Invoke-ErrorHandler -Context "Setting advanced property $DisplayName on $AdapterName" -ErrorRecord $_
        return $false
    }
}

function Invoke-AdapterOffloadToggle {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][object[]]$Adapters,
        [object]$PrimaryAdapter,
        [string]$PromptMessage = "Disable adapter offloads (RSC/LSO/Checksum) for lower latency? May reduce throughput.",
        [char]$DefaultResponse = 'y',
        [string]$InvokeOnceId = 'Network:AdapterOffloads',
        [string]$LoggerPrefix = '[Network]',
        [switch]$SkipWirelessWarning
    )

    $context = Get-RunContext -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    if (-not $Adapters -or $Adapters.Count -eq 0) {
        Write-Host "  [!] No adapters available for offload adjustments." -ForegroundColor Yellow
        return [pscustomobject]@{ Applied = $false; ChangedAdapters = @() }
    }

    if ($PromptMessage) {
        if (-not (Get-Confirmation $PromptMessage $DefaultResponse)) {
            Write-Host "  [ ] Adapter offload toggles skipped." -ForegroundColor Gray
            return [pscustomobject]@{ Applied = $false; ChangedAdapters = @() }
        }
    }

    $primary = $PrimaryAdapter
    if (-not $primary -and $Adapters.Count -gt 0) {
        $primary = $Adapters | Select-Object -First 1
    }

    if (-not $SkipWirelessWarning -and $primary) {
        $isPrimaryWifi = $false
        try {
            $medium = $primary | Select-Object -ExpandProperty NdisPhysicalMedium -ErrorAction SilentlyContinue
            if ($medium -and $medium -match '(?i)802\.11|wireless') {
                $isPrimaryWifi = $true
            } elseif ($primary.InterfaceDescription -match '(?i)(wi-?fi|wireless|802\.11)') {
                $isPrimaryWifi = $true
            }
        } catch { }

        if ($isPrimaryWifi) {
            $wifiWarning = "Primary adapter '$($primary.Name)' appears to be wireless; disabling offloads can destabilize some Wi-Fi drivers."
            Write-Host "  [!] $wifiWarning" -ForegroundColor Yellow
            if ($logger) { Write-Log "$LoggerPrefix $wifiWarning" -Level 'Warning' }
            if (-not (Get-Confirmation "Continue with adapter offload changes on a Wi-Fi adapter?" $DefaultResponse)) {
                Write-Host "  [ ] Adapter offload toggles canceled for Wi-Fi safety." -ForegroundColor DarkGray
                return [pscustomobject]@{ Applied = $false; ChangedAdapters = @() }
            }
        }
    }

    $allowed = Invoke-Once -Context $context -Id $InvokeOnceId -Action { $true }
    if (-not $allowed) {
        Write-Host "  [ ] Adapter offload toggles already applied this session; skipping." -ForegroundColor Gray
        return [pscustomobject]@{ Applied = $false; ChangedAdapters = @() }
    }

    $touched = New-Object System.Collections.Generic.List[string]

    foreach ($adapter in $Adapters) {
        try {
            Disable-NetAdapterRsc -Name $adapter.Name -ErrorAction Stop | Out-Null
            Write-Host "  [+] RSC disabled on $($adapter.Name)." -ForegroundColor Green
            if ($logger) { Write-Log "$LoggerPrefix Disabled RSC on $($adapter.Name)." }
            $touched.Add($adapter.Name) | Out-Null
        } catch {
            Invoke-ErrorHandler -Context "Disabling RSC on $($adapter.Name)" -ErrorRecord $_
        }

        foreach ($entry in @(
                @{ Name = 'Large Send Offload V2 (IPv4)'; Value = 'Disabled' },
                @{ Name = 'Large Send Offload V2 (IPv6)'; Value = 'Disabled' },
                @{ Name = 'IPv4 Checksum Offload'; Value = 'Disabled' },
                @{ Name = 'TCP Checksum Offload (IPv4)'; Value = 'Disabled' },
                @{ Name = 'TCP Checksum Offload (IPv6)'; Value = 'Disabled' },
                @{ Name = 'UDP Checksum Offload (IPv4)'; Value = 'Disabled' },
                @{ Name = 'UDP Checksum Offload (IPv6)'; Value = 'Disabled' },
                @{ Name = 'Receive Buffers'; Value = '512' },
                @{ Name = 'Transmit Buffers'; Value = '4096' },
                @{ Name = 'Flow Control'; Value = 'Disabled' },
                @{ Name = 'Interrupt Moderation'; Value = 'Disabled' }
            )) {
            $changed = Set-NetAdapterAdvancedPropertySafe -AdapterName $adapter.Name -DisplayName $entry.Name -DisplayValue $entry.Value
            if ($changed) { $touched.Add($adapter.Name) | Out-Null }
        }
    }

    return [pscustomobject]@{
        Applied         = $true
        ChangedAdapters = ($touched | Select-Object -Unique)
    }
}

function Invoke-AdvancedNetworkPipeline {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [object[]]$Adapters,
        [ScriptBlock]$AdapterResolver,
        [object]$PrimaryAdapter,
        [ScriptBlock]$PrimaryAdapterResolver,
        [string]$ProfileName = 'Advanced Network Pipeline',
        [string]$LoggerPrefix = '[Network]',
        [string]$MsiPromptMessage,
        [string[]]$MsiTargets,
        [char]$MsiDefaultResponse = 'n',
        [string]$MsiInvokeOnceId,
        [string]$OffloadPromptMessage = "Disable adapter offloads (RSC/LSO/Checksum) for lower latency? May reduce throughput.",
        [char]$OffloadDefaultResponse = 'y',
        [string]$OffloadInvokeOnceId = 'Network:AdapterOffloads',
        [switch]$SkipWirelessWarning
    )

    $context = Get-RunContext -Context $Context
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $resolvedAdapters = $Adapters
    if (-not $resolvedAdapters -or $resolvedAdapters.Count -eq 0) {
        if ($AdapterResolver) {
            try {
                $resolvedAdapters = & $AdapterResolver
            } catch {
                Invoke-ErrorHandler -Context "Resolving adapters for $ProfileName" -ErrorRecord $_
            }
        }
    }

    if (-not $resolvedAdapters -or $resolvedAdapters.Count -eq 0) {
        Write-Host "  [!] No eligible adapters found for $ProfileName." -ForegroundColor Yellow
        return [pscustomobject]@{ Ran = $false; Msi = $null; Offloads = $null; Adapters = @() }
    }

    $primary = $PrimaryAdapter
    if (-not $primary -and $PrimaryAdapterResolver) {
        try {
            $primary = & $PrimaryAdapterResolver
        } catch {
            Invoke-ErrorHandler -Context "Resolving primary adapter for $ProfileName" -ErrorRecord $_
        }
    }
    if (-not $primary -and $resolvedAdapters.Count -gt 0) {
        $primary = $resolvedAdapters | Select-Object -First 1
    }

    $result = [ordered]@{
        Ran      = $true
        Msi      = $null
        Offloads = $null
        Adapters = $resolvedAdapters
    }

    if ($MsiTargets -and $MsiTargets.Count -gt 0 -and $MsiPromptMessage) {
        $msiParams = @{
            Context         = $context
            Targets         = $MsiTargets
            PromptMessage   = $MsiPromptMessage
            DefaultResponse = $MsiDefaultResponse
        }
        if ($MsiInvokeOnceId) {
            $msiParams['InvokeOnceId'] = $MsiInvokeOnceId
        }

        $result.Msi = Invoke-MsiModeOnce @msiParams

        if ($logger -and $result.Msi -and $result.Msi.Touched -gt 0) {
            Write-Log "$LoggerPrefix MSI Mode enabled for targets: $($MsiTargets -join ', ')."
        } elseif ($logger -and $result.Msi) {
            Write-Log "$LoggerPrefix MSI Mode already enabled or skipped for targets: $($MsiTargets -join ', ')." -Level 'Info'
        }
    }

    $result.Offloads = Invoke-AdapterOffloadToggle -Context $context -Adapters $resolvedAdapters -PrimaryAdapter $primary -PromptMessage $OffloadPromptMessage -DefaultResponse $OffloadDefaultResponse -InvokeOnceId $OffloadInvokeOnceId -LoggerPrefix $LoggerPrefix -SkipWirelessWarning:$SkipWirelessWarning

    return [pscustomobject]$result
}

Export-ModuleMember -Function Get-SharedNicRegistryPaths, Invoke-NagleRegistryUpdate, Invoke-NicPowerRegistryTweaks, Invoke-MsiModeOnce, Convert-LinkSpeedToBits, Set-NetAdapterAdvancedPropertySafe, Invoke-AdapterOffloadToggle, Invoke-AdvancedNetworkPipeline
