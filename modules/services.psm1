# Depends on: ui.psm1 (loaded by main script)
# Description: Internal helper to configure service startup and runtime state with logging.
# Parameters: Name - Service name; StartupType - Desired startup mode; Status - Desired runtime status (Running/Stopped).
# Returns: None. Logs operations and errors using existing utilities.
function Set-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Automatic','Manual','Disabled')][string]$StartupType,
        [Parameter(Mandatory)][ValidateSet('Running','Stopped')][string]$Status,
        [pscustomobject]$Context
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) {
        $message = "[Services] Service not found: $Name"
        Write-Host "  [!] $message" -ForegroundColor Yellow
        Write-Log -Message $message -Level 'Warning'
        return
    }

    $serviceSnapshot = $null
    try {
        $serviceSnapshot = [pscustomobject]@{
            Name        = $service.Name
            StartupType = $service.StartType.ToString()
            Status      = $service.Status.ToString()
        }
    } catch { }

    try {
        if ($Context -and $serviceSnapshot) {
            try {
                Add-ServiceRollbackAction -Context $Context -ServiceName $service.Name -StartupType $serviceSnapshot.StartupType -Status $serviceSnapshot.Status | Out-Null
            } catch { }
        }

        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop

        if ($Status -eq 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        } else {
            Start-Service -Name $Name -ErrorAction SilentlyContinue
        }

        $message = "[Services] $Name set to $StartupType; runtime: $Status"
        Write-Host "  [+] $message" -ForegroundColor Gray
        Write-Log -Message $message -Level 'Info'
    } catch {
        Invoke-ErrorHandler -Context "Configuring service $Name" -ErrorRecord $_
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
        Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped' -Context $Context
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

    $coreTargets = 'RemoteRegistry','WerSvc','lfsvc','DiagTrack'
    foreach ($svc in $coreTargets) {
        Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped' -Context $Context
    }

    $skipSpooler = $OemServices -and $OemServices.Count -gt 0
    if ($skipSpooler) {
        $oemDisplayNames = $OemServices | ForEach-Object { $_.DisplayName } | Where-Object { $_ }
        $oemLabel = if ($oemDisplayNames) { ($oemDisplayNames -join ', ') } else { 'OEM services' }
        Write-Host "  [!] OEM services detected: $oemLabel" -ForegroundColor Yellow
        Write-Host "      Skipping Print Spooler prompt to avoid breaking vendor tooling." -ForegroundColor Yellow
    } else {
        if (Get-Confirmation "Disable Print Spooler service?" 'n') {
            Set-ServiceState -Name 'Spooler' -StartupType 'Disabled' -Status 'Stopped' -Context $Context
        } else {
            Write-Host "  [ ] Print Spooler kept enabled." -ForegroundColor DarkGray
        }
    }

    if (Get-Confirmation "Disable Bluetooth Support service?" 'n') {
        Set-ServiceState -Name 'bthserv' -StartupType 'Disabled' -Status 'Stopped' -Context $Context
    } else {
        Write-Host "  [ ] Bluetooth Support kept enabled." -ForegroundColor DarkGray
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
            Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped' -Context $Context
        } else {
            $message = "[Services] NVIDIA telemetry service not found: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }

    $amdServices = @('AMD Crash User Service','AMD Link Service')
    foreach ($svc in $amdServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped' -Context $Context
        } else {
            $message = "[Services] AMD telemetry service not found: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }
}

Export-ModuleMember -Function Invoke-SafeServiceOptimization, Invoke-AggressiveServiceOptimization, Invoke-DriverTelemetryOptimization
