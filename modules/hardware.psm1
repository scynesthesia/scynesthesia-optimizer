function Enable-MsiModeSafe {
    param(
        [string[]]$Target = 'GPU',
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string[]]$SkipInstanceIds
    )

    Write-Section "MSI Mode (Message Signaled Interrupts)"
    Write-Host "Reduces DPC latency by changing how devices communicate with CPU." -ForegroundColor Gray
    Write-Host "WARNING: Only compatible devices will be touched. Reboot required." -ForegroundColor Yellow

    $osVersion = [System.Environment]::OSVersion.Version
    $isWin10Pre1903 = ($osVersion.Major -eq 10 -and $osVersion.Build -lt 18362)

    $targetMap = @{
        'GPU'     = @{ Classes = @('Display'); ClassGuids = @('{4d36e968-e325-11ce-bfc1-08002be10318}'); Description = 'GPU/Display adapters' }
        'NIC'     = @{ Classes = @('Net'); ClassGuids = @('{4d36e972-e325-11ce-bfc1-08002be10318}'); Description = 'Network adapters' }
        'STORAGE' = @{ Classes = @('SCSIAdapter','HDC'); ClassGuids = @('{4d36e97b-e325-11ce-bfc1-08002be10318}', '{4d36e96a-e325-11ce-bfc1-08002be10318}'); Description = 'Storage controllers' }
    }

    $msiOptOutPciIds = @{
        'NIC' = @(
            'VEN_10EC&DEV_8168', # Realtek PCIe GBE Family Controller (inconsistent MSI stability on some boards)
            'VEN_14E4&DEV_16B1', # Broadcom NetXtreme BCM57781/BCM57785
            'VEN_8086&DEV_10D3'  # Intel 82574L (desktop server NICs with MSI quirks)
        )
        'STORAGE' = @(
            'VEN_1B21&DEV_0612', # ASMedia 106x SATA controllers
            'VEN_1B4B&DEV_9172', # Marvell 88SE9172 SATA
            'VEN_197B&DEV_2368'  # JMicron JMB36x SATA/PATA controllers
        )
    }

    $normalizedTargets = $Target | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique
    $classQueries = @()
    foreach ($t in $normalizedTargets) {
        if ($targetMap.ContainsKey($t)) {
            foreach ($className in $targetMap[$t].Classes) {
                $classQueries += [pscustomobject]@{ Class = $className; ClassGuids = $targetMap[$t].ClassGuids; TargetKey = $t }
            }
            Write-Host "  [>] Targeting: $($targetMap[$t].Description)" -ForegroundColor Gray
        } else {
            Write-Host "  [!] Unknown target '$t'. Skipping." -ForegroundColor Yellow
        }
    }

    if (-not $classQueries) {
        Write-Host "  [!] No valid targets supplied for MSI Mode." -ForegroundColor Yellow
        return [pscustomobject]@{ Touched = 0 }
    }

    $normalizedSkips = @()
    if ($SkipInstanceIds) {
        $normalizedSkips = $SkipInstanceIds | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() }
    }

    $touched = 0
    foreach ($query in ($classQueries | Sort-Object Class -Unique)) {
        $devices = Get-PnpDevice -Class $query.Class -Status OK -ErrorAction SilentlyContinue
        if ($devices -and $query.ClassGuids) {
            $devices = $devices | Where-Object { $query.ClassGuids -contains $_.ClassGuid }
        }
        foreach ($dev in $devices) {
            try {
                if ($normalizedSkips -and $dev.InstanceId) {
                    $normalizedInstanceId = $dev.InstanceId.ToUpperInvariant()
                    $skipMatches = $normalizedSkips | Where-Object { $normalizedInstanceId -like $_ -or $normalizedInstanceId -like "*$_*" }
                    if ($skipMatches) {
                        Write-Host "  [ ] Skipping MSI enable for $($dev.FriendlyName) due to legacy driver safeguards." -ForegroundColor DarkGray
                        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                            Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message "MSI Mode skipped for $($dev.FriendlyName): legacy driver safeguard match"
                        }
                        continue
                    }
                }

                $driverDate = $null
                $driverDateProperty = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverDate' -ErrorAction SilentlyContinue
                if ($driverDateProperty -and $driverDateProperty.Data) {
                    [datetime]::TryParse($driverDateProperty.Data, [ref]$driverDate) | Out-Null
                }

                $hardwareIds = @()
                $hardwareIdProperty = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue
                if ($hardwareIdProperty -and $hardwareIdProperty.Data) {
                    $hardwareIds = @($hardwareIdProperty.Data) | Where-Object { $_ }
                }

                $driverProvider = $null
                $driverProviderProperty = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DEVPKEY_Device_DriverProvider' -ErrorAction SilentlyContinue
                if ($driverProviderProperty -and $driverProviderProperty.Data) {
                    $driverProvider = [string]$driverProviderProperty.Data
                }

                $isInboxDriver = ($isWin10Pre1903 -and $driverProvider -and $driverProvider -match '^(?i)microsoft')

                if ($driverDate) {
                    if ($driverDate -lt (Get-Date '2014-01-01')) {
                        Write-Host "  [!] Skipping $($dev.FriendlyName): driver date $driverDate is older than 2014-01-01." -ForegroundColor Yellow
                        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                            Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message "MSI Mode skipped for $($dev.FriendlyName): driver dated $($driverDate.ToShortDateString())"
                        }
                        continue
                    }

                    if ($dev.Manufacturer -and ($dev.Manufacturer -match '^(?i)(Realtek|JMicron)') -and $driverDate -lt (Get-Date '2017-01-01')) {
                        Write-Host "  [!] Skipping $($dev.FriendlyName): $($dev.Manufacturer) driver date $driverDate is older than 2017-01-01." -ForegroundColor Yellow
                        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                            Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message "MSI Mode skipped for $($dev.FriendlyName): $($dev.Manufacturer) driver age safeguard"
                        }
                        continue
                    }
                }

                if ($msiOptOutPciIds.ContainsKey($query.TargetKey) -and $hardwareIds) {
                    $normalizedIds = $hardwareIds | ForEach-Object { $_.ToUpperInvariant() }
                    $matchedOptOut = $msiOptOutPciIds[$query.TargetKey] | Where-Object { $opt = $_; $normalizedIds | Where-Object { $_ -like "*$opt*" } }
                    if ($matchedOptOut) {
                        Write-Host "  [!] Skipping $($dev.FriendlyName): hardware ID matches MSI opt-out ($($matchedOptOut -join ', '))." -ForegroundColor Yellow
                        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                            Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message "MSI Mode skipped for $($dev.FriendlyName): hardware ID opt-out ($($matchedOptOut -join ', '))"
                        }
                        continue
                    }
                }

                if ($isInboxDriver) {
                    Write-Host "  [!] Skipping $($dev.FriendlyName): Microsoft inbox driver detected on Windows 10 build $($osVersion.Build) (pre-1903) often rejects MSI mode and may cause boot loops." -ForegroundColor Yellow
                    if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                        Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message "MSI Mode skipped for $($dev.FriendlyName): inbox driver on pre-1903 build"
                    }
                    continue
                }

                $regPath = "HKLM\SYSTEM\CurrentControlSet\Enum\$($dev.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
                if (-not (Test-Path $regPath)) { continue }

                $currentVal = Get-ItemProperty -Path $regPath -Name "MSISupported" -ErrorAction SilentlyContinue
                if ($null -eq $currentVal -or $currentVal.MSISupported -ne 1) {
                    $result = Set-RegistryValueSafe $regPath "MSISupported" 1 -Context $Context -Critical -ReturnResult -OperationLabel "Enable MSI for $($dev.FriendlyName)"
                    if ($result -and $result.Success) {
                        Write-Host "  [OK] MSI enabled for: $($dev.FriendlyName)" -ForegroundColor Green
                        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                            Write-Log "[MSI] Enabled for $($dev.InstanceId)" -Level 'Info'
                        }
                        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                            Add-SessionSummaryItem -Context $Context -Bucket 'Applied' -Message "MSI Mode enabled for $($dev.FriendlyName)"
                        }
                        $touched++
                    } else {
                        Register-HighImpactRegistryFailure -Context $Context -Result $result -OperationLabel "Enable MSI for $($dev.FriendlyName)" | Out-Null
                    }
                } else {
                    Write-Host "  [=] MSI already active for: $($dev.FriendlyName)" -ForegroundColor DarkGray
                }
            } catch {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log "[MSI] Error enabling on $($dev.InstanceId): $($_.Exception.Message)" -Level 'Warning'
                }
            }
        }
    }

    if ($touched -gt 0) {
        Set-RebootRequired -Context $Context | Out-Null
        Write-Host ""
        Write-Host "  [!] A REBOOT is required to apply MSI Mode changes." -ForegroundColor Magenta
    } else {
        Write-Host "  [i] No applicable devices found or already enabled." -ForegroundColor DarkGray
    }

    return [pscustomobject]@{ Touched = $touched }
}

Export-ModuleMember -Function Enable-MsiModeSafe
