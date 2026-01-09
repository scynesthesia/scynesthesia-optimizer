# Depends on: ui.psm1 (loaded by main script)
# Description: Internal helper to disable a service by setting its registry start value and stopping it.
# Parameters: Name - Service name; Context - run context for rollback tracking.
# Returns: None. Logs operations and handles protected service errors.
function Disable-ServiceByRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [pscustomobject]$Context
    )

    try {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $service) {
            $message = "[Services] Service not found: $Name"
            Write-Host "  [!] $message" -ForegroundColor Yellow
            Write-Log -Message $message -Level 'Warning'
            return
        }

        $servicePath = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\$Name"
        $result = Set-RegistryValueSafe -Path $servicePath -Name 'Start' -Value 4 -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Context $Context -ReturnResult -OperationLabel "Disable service $Name"

        if ($result -and $result.Success) {
            Write-Host "  [+] [Services] $Name disabled (Start=4)." -ForegroundColor Gray
            Write-Log -Message "[Services] $Name disabled via registry." -Level 'Info'
        } else {
            Write-Host "  [!] [Services] Failed to disable $Name via registry." -ForegroundColor Yellow
            Write-Log -Message "[Services] Failed to disable $Name via registry." -Level 'Warning'
        }

        if ($result -and $result.ErrorCategory -eq 'PermissionDenied') {
            $exception = [System.UnauthorizedAccessException]::new("Registry update denied for service $Name.")
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception,
                'ServiceRegistryAccessDenied',
                [System.Management.Automation.ErrorCategory]::PermissionDenied,
                $Name
            )
            Invoke-ErrorHandler -Context "Disabling protected service $Name (TrustedInstaller)" -ErrorRecord $errorRecord
        }

        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    } catch {
        Invoke-ErrorHandler -Context "Disabling service $Name" -ErrorRecord $_
    }
}

# Description: Applies conservative service optimizations suitable for Safe preset.
# Parameters: None.
# Returns: None. Disables non-essential consumer/demo services.
function Invoke-SafeServiceOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    Write-Section "Service hardening (Safe)"
    $safeServices = 'RetailDemo','MapsBroker','stisvc'

    foreach ($svc in $safeServices) {
        Disable-ServiceByRegistry -Name $svc -Context $Context
    }
}

# Description: Applies aggressive service reductions with optional prompts for key services.
# Parameters: None.
# Returns: None. Disables telemetry and remote access services with user confirmation for printing/Bluetooth.
function Invoke-AggressiveServiceOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        $OemServices
    )

    Write-Section "Service reductions (Aggressive)"
    Invoke-SafeServiceOptimization -Context $Context

    $coreTargets = 'RemoteRegistry','WerSvc','lfsvc','DiagTrack'
    foreach ($svc in $coreTargets) {
        Disable-ServiceByRegistry -Name $svc -Context $Context
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
            Disable-ServiceByRegistry -Name 'Spooler' -Context $Context
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
        Disable-ServiceByRegistry -Name 'bthserv' -Context $Context
    } else {
        Write-Host "  [ ] Bluetooth Support kept enabled." -ForegroundColor DarkGray
    }
}

# Description: Applies gaming service optimizations layered on safe and aggressive presets.
# Parameters: Context - Run context for rollback tracking.
# Returns: None. Disables gaming-focused services and handles optional network-impacting services.
function Invoke-GamingServiceOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    Write-Section "Service tuning (Gaming)"
    Invoke-AggressiveServiceOptimization -Context $Context

    $gamingServices = 'WSearch','WMPNetworkSvc','PcaSvc'
    foreach ($svc in $gamingServices) {
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

# Description: Disables GPU vendor telemetry services for gaming profile stability.
# Parameters: None.
# Returns: None. Stops and disables NVIDIA/AMD telemetry listeners when present.
function Invoke-DriverTelemetryOptimization {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    Write-Section "Driver telemetry cleanup"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $nvidiaServices = @('NvTelemetryContainer')
    foreach ($svc in $nvidiaServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Disable-ServiceByRegistry -Name $svc -Context $Context
        } else {
            $message = "[Services] NVIDIA telemetry service not found: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }

    $amdServices = @('AMD Crash User Service','AMD Link Service')
    foreach ($svc in $amdServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Disable-ServiceByRegistry -Name $svc -Context $Context
        } else {
            $message = "[Services] AMD telemetry service not found: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }
}

Export-ModuleMember -Function Invoke-SafeServiceOptimization, Invoke-AggressiveServiceOptimization, Invoke-GamingServiceOptimization, Invoke-DriverTelemetryOptimization
