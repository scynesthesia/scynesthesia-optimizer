function Disable-ServiceByRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [pscustomobject]$Context
    )

    try {
        $isDebug = $DebugPreference -ne 'SilentlyContinue'
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $service) {
            if ($isDebug) {
                $message = "[Services] Service not found: $Name"
                Write-Host "  [!] $message" -ForegroundColor Yellow
                Write-Log -Message $message -Level 'Warning'
            }
            return
        }

        $servicePath = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\$Name"
        $serviceKeyPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$Name"
        $result = Set-RegistryValueSafe -Path $servicePath -Name 'Start' -Value 4 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel "Disable service $Name"

        if ($result -and $result.ErrorCategory -eq 'PermissionDenied') {
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')

            if ($Name -in @('DPS', 'WdiServiceHost', 'WdiSystemHost')) {
                $message = "[Services] $Name registry update denied. Attempting .NET access control update for S-1-5-32-544."
                Write-Host "  [!] $message" -ForegroundColor Yellow
                Write-Log -Message $message -Level 'Warning'

                $netAclApplied = $false
                try {
                    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                        "SYSTEM\\CurrentControlSet\\Services\\$Name",
                        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                        [System.Security.AccessControl.RegistryRights]::ChangePermissions
                    )
                    if ($regKey) {
                        $regAcl = $regKey.GetAccessControl()
                        $regRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                            $adminSid,
                            'FullControl',
                            'ContainerInherit,ObjectInherit',
                            'None',
                            'Allow'
                        )
                        $regAcl.SetAccessRule($regRule)
                        $regKey.SetAccessControl($regAcl)
                        $regKey.Close()
                        $netAclApplied = $true
                        Write-Log -Message "[Services] .NET ACL applied for $serviceKeyPath." -Level 'Info'
                    } else {
                        Write-Log -Message "[Services] .NET ACL update skipped. Registry key not found for $serviceKeyPath." -Level 'Warning'
                    }
                } catch {
                    Write-Log -Message "[Services] Failed .NET ACL update for $serviceKeyPath. Error: $($_.Exception.Message)" -Level 'Warning'
                }

                if ($netAclApplied) {
                    $result = Set-RegistryValueSafe -Path $servicePath -Name 'Start' -Value 4 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel "Disable service $Name (post-.NET ACL)"
                }
            }

            if ($result -and $result.ErrorCategory -eq 'PermissionDenied') {
                $message = "[Services] $Name registry update denied. Attempting take ownership and grant S-1-5-32-544 full control."
                Write-Host "  [!] $message" -ForegroundColor Yellow
                Write-Log -Message $message -Level 'Warning'

                $ownershipApplied = $false
                try {
                    $acl = Get-Acl -Path $serviceKeyPath -ErrorAction Stop
                    $acl.SetOwner($adminSid)
                    $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                        $adminSid,
                        'FullControl',
                        'ContainerInherit,ObjectInherit',
                        'None',
                        'Allow'
                    )
                    $acl.SetAccessRule($accessRule)
                    Set-Acl -Path $serviceKeyPath -AclObject $acl -ErrorAction Stop
                    $ownershipApplied = $true
                    Write-Log -Message "[Services] Ownership updated for $serviceKeyPath." -Level 'Info'
                } catch {
                    Write-Log -Message "[Services] Failed to update ownership for $serviceKeyPath. Error: $($_.Exception.Message)" -Level 'Warning'
                }

                if ($ownershipApplied) {
                    $result = Set-RegistryValueSafe -Path $servicePath -Name 'Start' -Value 4 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel "Disable service $Name (post-ownership)"
                }
            }
        }

        if ($result -and $result.Success) {
            Write-Host "  [OK] [Services] $Name disabled (Start=4)." -ForegroundColor Gray
            Write-Log -Message "[Services] $Name disabled via registry." -Level 'Info'
        } else {
            Write-Host "  [!] [Services] Failed to disable $Name via registry." -ForegroundColor Yellow
            Write-Log -Message "[Services] Failed to disable $Name via registry." -Level 'Warning'
        }

        if ($result -and $result.ErrorCategory -eq 'PermissionDenied') {
            $message = "[Services] $Name registry update denied (protected service)."
            Write-Host "  [!] $message" -ForegroundColor Yellow
            Write-Log -Message $message -Level 'Warning'
            if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message $message
            }
            return
        }

        if ($service) {
            $isDriver = ($service.ServiceType -band [System.ServiceProcess.ServiceType]::KernelDriver) -or
                ($service.ServiceType -band [System.ServiceProcess.ServiceType]::FileSystemDriver)
            if ($isDriver) {
                Write-Host "  [ ] Skipping stop for driver service $Name." -ForegroundColor DarkGray
            } else {
                Stop-Service -Name $Name -Force -NoWait -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Invoke-ErrorHandler -Context "Disabling service $Name" -ErrorRecord $_
    }
}

function Invoke-SafeServiceOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    Write-Section "Service hardening (Safe)"
    $safeServices = @(
        'RetailDemo',
        'MapsBroker',
        'stisvc',
        'WpcMonSvc',
        'SensorDataService',
        'SensrSvc',
        'SensorService',
        'PhoneSvc'
    )
    $safeDrivers = @(
        'Beep',
        'cdrom',
        'AcpiPmi'
    )

    foreach ($svc in $safeServices + $safeDrivers) {
        Disable-ServiceByRegistry -Name $svc -Context $Context
    }
}

function Invoke-AggressiveServiceOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        $OemServices
    )

    Write-Section "Service reductions (Aggressive)"
    Invoke-SafeServiceOptimization -Context $Context

    $aggressiveServices = @(
        'RemoteRegistry',
        'WerSvc',
        'DiagTrack',
        'diagsvc',
        'DPS',
        'WdiServiceHost',
        'WdiSystemHost',
        'defragsvc',
        'edgeupdate',
        'edgeupdatem',
        'Themes',
        'lfsvc'
    )
    $aggressiveDrivers = @(
        'acpipagr',
        'CSC',
        'tcpipreg',
        'dam'
    )

    foreach ($svc in $aggressiveServices + $aggressiveDrivers) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Disable-ServiceByRegistry -Name $svc -Context $Context
        }
    }

    $windowsUpdateKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wuauserv"
    if (Test-Path $windowsUpdateKey) {
        $windowsUpdatePath = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv"
        $wuResult = Set-RegistryValueSafe -Path $windowsUpdatePath -Name 'Start' -Value 3 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel 'Set Windows Update to manual'
        if ($wuResult -and $wuResult.Success) {
            Write-Host "  [OK] [Services] wuauserv set to manual start (Start=3)." -ForegroundColor Gray
            Write-Log -Message "[Services] wuauserv set to manual start (Start=3)." -Level 'Info'
        } else {
            Write-Host "  [!] [Services] Failed to set wuauserv to manual start." -ForegroundColor Yellow
            Write-Log -Message "[Services] Failed to set wuauserv to manual start (Start=3)." -Level 'Warning'
        }
    }

    $skipSpooler = $OemServices -and $OemServices.Count -gt 0
    if ($skipSpooler) {
        $oemDisplayNames = $OemServices | ForEach-Object { $_.DisplayName } | Where-Object { $_ }
        $oemLabel = if ($oemDisplayNames) { ($oemDisplayNames -join ', ') } else { 'OEM services' }
        Write-Host "  [!] OEM services detected: $oemLabel" -ForegroundColor Yellow
        Write-Host "      Skipping Print Spooler prompt to avoid breaking vendor tooling." -ForegroundColor Yellow
        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
            Add-SessionSummaryItem -Context $Context -Bucket 'GuardedBlocks' -Message 'Print Spooler preserved due to OEM services safeguard'
        }
    } else {
        if (Get-Confirmation "Disable Print Spooler service?" 'n') {
            if (Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue) {
                Disable-ServiceByRegistry -Name 'Spooler' -Context $Context
            }
            if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                Add-SessionSummaryItem -Context $Context -Bucket 'Applied' -Message 'Print Spooler disabled'
            }
        } else {
            Write-Host "  [ ] Print Spooler kept enabled." -ForegroundColor DarkGray
            if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                Add-SessionSummaryItem -Context $Context -Bucket 'DeclinedHighImpact' -Message 'Print Spooler disable prompt declined'
            }
        }
    }

    if (Get-Confirmation "Disable Bluetooth Support service?" 'n') {
        if (Get-Service -Name 'bthserv' -ErrorAction SilentlyContinue) {
            Disable-ServiceByRegistry -Name 'bthserv' -Context $Context
        }
    } else {
        Write-Host "  [ ] Bluetooth Support kept enabled." -ForegroundColor DarkGray
    }
}

function Invoke-GamingServiceOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    Write-Section "Service tuning (Gaming)"
    Invoke-AggressiveServiceOptimization -Context $Context

    Write-Host "  [!] VPN protocols and DRM (PEAUTH) will be disabled." -ForegroundColor Yellow
    $gamingServices = @(
        'WSearch',
        'WMPNetworkSvc',
        'PcaSvc',
        'TapiSrv',
        'OneSyncSvc',
        'TabletInputService',
        'BcastDVRUserService',
        'CaptureService',
        'MessagingService'
    )
    $gamingDrivers = @(
        'GpuEnergyDrv',
        'RasAcd',
        'Rasl2tp',
        'RasPppoe',
        'RasSstp',
        'PEAUTH',
        'luafv'
    )
    foreach ($svc in $gamingServices + $gamingDrivers) {
        Disable-ServiceByRegistry -Name $svc -Context $Context
    }

    Write-Host "  [!] Optional network services may impact LAN connectivity." -ForegroundColor Yellow
    if (Get-Confirmation "Deshabilitar LanmanWorkstation y CryptSvc? Advertencia: Pérdida de red local." 'n') {
        Disable-ServiceByRegistry -Name 'LanmanWorkstation' -Context $Context
        Disable-ServiceByRegistry -Name 'CryptSvc' -Context $Context
    } else {
        Write-Host "  [ ] LanmanWorkstation/CryptSvc kept enabled." -ForegroundColor DarkGray
    }
}

function Invoke-DriverTelemetryOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    Write-Section "Driver telemetry cleanup"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $isDebug = $DebugPreference -ne 'SilentlyContinue'

    $nvidiaServices = @('NvTelemetryContainer')
    foreach ($svc in $nvidiaServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Disable-ServiceByRegistry -Name $svc -Context $Context
        } elseif ($isDebug) {
            $message = "[Services] NVIDIA telemetry service not found: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }

    $amdServices = @('AMD Crash User Service','AMD Link Service')
    foreach ($svc in $amdServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Disable-ServiceByRegistry -Name $svc -Context $Context
        } elseif ($isDebug) {
            $message = "[Services] AMD telemetry service not found: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }
}

Export-ModuleMember -Function Invoke-SafeServiceOptimization, Invoke-AggressiveServiceOptimization, Invoke-GamingServiceOptimization, Invoke-DriverTelemetryOptimization
