# Description: Shared helpers for network tweaks reused across presets.

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

Export-ModuleMember -Function Get-SharedNicRegistryPaths, Invoke-NagleRegistryUpdate, Invoke-NicPowerRegistryTweaks, Invoke-MsiModeOnce
