# Depends on: ui.psm1 (loaded by main script)
# Description: Internal helper to configure service startup and runtime state with logging.
# Parameters: Name - Service name; StartupType - Desired startup mode; Status - Desired runtime status (Running/Stopped).
# Returns: None. Logs operations and errors using existing utilities.
function Set-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Automatic','Manual','Disabled')][string]$StartupType,
        [Parameter(Mandatory)][ValidateSet('Running','Stopped')][string]$Status
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) {
        $message = "[Services] Service not found: $Name / Servicio no encontrado: $Name"
        Write-Host "  [!] $message" -ForegroundColor Yellow
        Write-Log -Message $message -Level 'Warning'
        return
    }

    try {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop

        if ($Status -eq 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        } else {
            Start-Service -Name $Name -ErrorAction SilentlyContinue
        }

        $message = "[Services] $Name set to $StartupType / Estado en tiempo de ejecucion: $Status"
        Write-Host "  [+] $message" -ForegroundColor Gray
        Write-Log -Message $message -Level 'Info'
    } catch {
        Invoke-ErrorHandler -Context "Configuring service $Name" -ErrorRecord $_
    }
}

# Description: Applies conservative service optimizations suitable for Safe preset.
# Parameters: None.
# Returns: None. Disables non-essential consumer/demo services.
function Optimize-ServicesSafe {
    [CmdletBinding()]
    param()

    Write-Section "Service hardening (Safe) / Endurecimiento de servicios (Seguro)"
    $safeServices = 'RetailDemo','MapsBroker','stisvc'

    foreach ($svc in $safeServices) {
        Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped'
    }
}

# Description: Applies aggressive service reductions with optional prompts for key services.
# Parameters: None.
# Returns: None. Disables telemetry and remote access services with user confirmation for printing/Bluetooth.
function Optimize-ServicesAggressive {
    [CmdletBinding()]
    param()

    Write-Section "Service reductions (Aggressive) / Reduccion de servicios (Agresivo)"

    $coreTargets = 'RemoteRegistry','WerSvc','lfsvc','DiagTrack'
    foreach ($svc in $coreTargets) {
        Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped'
    }

    if (Get-Confirmation "Disable Print Spooler service? / ¿Deshabilitar el servicio de impresion?" 'n') {
        Set-ServiceState -Name 'Spooler' -StartupType 'Disabled' -Status 'Stopped'
    } else {
        Write-Host "  [ ] Print Spooler kept enabled / Cola de impresion mantenida." -ForegroundColor DarkGray
    }

    if (Get-Confirmation "Disable Bluetooth Support service? / ¿Deshabilitar el servicio de Bluetooth?" 'n') {
        Set-ServiceState -Name 'bthserv' -StartupType 'Disabled' -Status 'Stopped'
    } else {
        Write-Host "  [ ] Bluetooth Support kept enabled / Soporte de Bluetooth mantenido." -ForegroundColor DarkGray
    }
}

# Description: Disables GPU vendor telemetry services for gaming profile stability.
# Parameters: None.
# Returns: None. Stops and disables NVIDIA/AMD telemetry listeners when present.
function Optimize-DriverTelemetry {
    [CmdletBinding()]
    param()

    Write-Section "Driver telemetry cleanup / Limpieza de telemetría de drivers"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $nvidiaServices = @('NvTelemetryContainer')
    foreach ($svc in $nvidiaServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped'
        } else {
            $message = "[Services] NVIDIA telemetry service not found: $svc / Servicio de telemetría NVIDIA no encontrado: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }

    $amdServices = @('AMD Crash User Service','AMD Link Service')
    foreach ($svc in $amdServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Set-ServiceState -Name $svc -StartupType 'Disabled' -Status 'Stopped'
        } else {
            $message = "[Services] AMD telemetry service not found: $svc / Servicio de telemetría AMD no encontrado: $svc"
            Write-Host "  [ ] $message" -ForegroundColor DarkGray
            if ($logger) { Write-Log -Message $message -Level 'Warning' }
        }
    }
}

Export-ModuleMember -Function Optimize-ServicesSafe, Optimize-ServicesAggressive, Optimize-DriverTelemetry
