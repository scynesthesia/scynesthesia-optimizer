# Scynesthesia Windows Optimizer - Remote Installer
# This script downloads the full repository to handle modular dependencies.

# Enforce TLS 1.2 without removing existing flags / Forzar TLS 1.2 sin quitar opciones existentes
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$repoUrls = @(
    'https://codeload.github.com/scynesthesia/scynesthesia-optimizer/zip/refs/heads/main',
    'https://github.com/scynesthesia/scynesthesia-optimizer/archive/refs/heads/main.zip'
)
$userAgent = 'Scynesthesia-Optimizer-Installer/1.0 (+https://github.com/scynesthesia/scynesthesia-optimizer)'
$tempDir = Join-Path $env:TEMP 'ScynesthesiaTemp'
$zipFile = Join-Path $tempDir 'repo.zip'
$maxAttempts = 5

function Invoke-DownloadHelper {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][string] $UserAgent
    )

    $invokeParams = @{
        Uri         = $Uri
        OutFile      = $Destination
        ErrorAction = 'Stop'
        Headers     = @{ 'User-Agent' = $UserAgent }
    }

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $invokeParams['UseBasicParsing'] = $true
    }

    try {
        Invoke-WebRequest @invokeParams
        return
    } catch {
        $primaryError = $_.Exception
    }

    $bitsTransfer = Get-Command -Name Start-BitsTransfer -ErrorAction SilentlyContinue
    if ($bitsTransfer) {
        try {
            Start-BitsTransfer -Source $Uri -Destination $Destination -ErrorAction Stop
            return
        } catch {
            $bitsError = $_.Exception
        }
    }

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers['User-Agent'] = $UserAgent
        $webClient.DownloadFile($Uri, $Destination)
        return
    } catch {
        $webClientError = $_.Exception
    }

    $messages = @()
    if ($primaryError) { $messages += "Invoke-WebRequest: $($primaryError.Message)" }
    if ($bitsError) { $messages += "Start-BitsTransfer: $($bitsError.Message)" }
    if ($webClientError) { $messages += "WebClient: $($webClientError.Message)" }
    $allMessages = [string]::Join(' | ', $messages)
    throw "All download methods failed. Details: $allMessages"
}

function Invoke-RepositoryDownload {
    param(
        [Parameter(Mandatory = $true)][string[]] $Uris,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][string] $UserAgent,
        [int] $MaxAttempts = 5
    )

    $attempt = 0
    $downloaded = $false
    $rand = New-Object System.Random

    while (-not $downloaded -and $attempt -lt $MaxAttempts) {
        $attempt++
        foreach ($uri in $Uris) {
            Write-Host "[*] Attempt $attempt/$MaxAttempts from $uri ... / Intento $attempt/$MaxAttempts desde $uri ..." -ForegroundColor Cyan
            try {
                Invoke-DownloadHelper -Uri $uri -Destination $Destination -UserAgent $UserAgent
                $downloaded = $true
                break
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Warning "[!] Download from $uri failed: $errorMsg / Descarga desde $uri falló: $errorMsg"
            }
        }

        if (-not $downloaded -and $attempt -lt $MaxAttempts) {
            $backoff = [Math]::Pow(2, $attempt)
            $jitter = $rand.Next(0, 1000) / 1000
            $sleepSeconds = [Math]::Min(30, $backoff + $jitter)
            Write-Host "[*] Retrying in $([Math]::Round($sleepSeconds, 2)) seconds... ($($MaxAttempts - $attempt) left) / Reintentando en $([Math]::Round($sleepSeconds, 2)) segundos... (quedan $($MaxAttempts - $attempt))" -ForegroundColor DarkGray
            Start-Sleep -Seconds $sleepSeconds
        }
    }

    if (-not $downloaded) {
        throw "Failed to download repository after $MaxAttempts attempts. / No se pudo descargar el repositorio tras $MaxAttempts intentos."
    }
}

# Clear any stale payload from previous runs to avoid mixed versions being executed
if (Test-Path $tempDir) {
    try {
        $fullTemp = [System.IO.Path]::GetFullPath($tempDir)
        $fullEnvTemp = [System.IO.Path]::GetFullPath($env:TEMP)
        if ($fullTemp.StartsWith($fullEnvTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
        } else {
            Write-Warning "[!] Skipping cleanup because path validation failed: $tempDir / Omitiendo limpieza porque falló la validación de ruta: $tempDir"
        }
    } catch {
        Write-Warning "[!] Could not clean previous download at $tempDir. Continuing with existing files may cause issues. / No se pudo limpiar la descarga previa en $tempDir. Continuar con archivos existentes puede causar problemas."
    }
}

# Create temp directory if it doesn't exist
if (-not (Test-Path $tempDir)) {
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    } catch {
        Write-Error "[X] Cannot create temporary directory at $tempDir. / No se puede crear el directorio temporal en $tempDir."
        exit 1
    }
}

Write-Host "[*] Downloading Scynesthesia Windows Optimizer components... / Descargando componentes de Scynesthesia Windows Optimizer..." -ForegroundColor Cyan
try {
    Invoke-RepositoryDownload -Uris $repoUrls -Destination $zipFile -UserAgent $userAgent -MaxAttempts $maxAttempts
} catch {
    Write-Error "[X] Download failed: $($_.Exception.Message) / Descarga falló: $($_.Exception.Message)"
    Read-Host "Press Enter to exit / Presiona Enter para salir"
    exit 1
}

Write-Host "[*] Extracting files... / Extrayendo archivos..." -ForegroundColor Cyan
try {
    Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force -ErrorAction Stop
} catch {
    Write-Error "[X] Failed to extract files. Ensure no other instances are running. / No se pudieron extraer los archivos. Asegúrese de que no haya otras instancias en ejecución."
    exit 1
}

# Locate the main orchestrator within the extracted folder
$mainScript = Get-ChildItem -Path $tempDir -Filter 'scynesthesiaoptimizer.ps1' -Recurse -File | Select-Object -First 1

if (-not $mainScript) {
    Write-Error "[X] Could not find the main orchestrator (scynesthesiaoptimizer.ps1). / No se pudo encontrar el orquestador principal (scynesthesiaoptimizer.ps1)."
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    if ($logger) { Write-Log "[Setup] scynesthesiaoptimizer.ps1 not found after extraction in $tempDir" }
    exit 1
}

$scriptRoot = $mainScript.Directory.FullName
$launchPath = Join-Path $scriptRoot 'scynesthesiaoptimizer.ps1'

Write-Host "[+] Launching Optimizer... / Iniciando Optimizer..." -ForegroundColor Green
Set-Location $scriptRoot
& $launchPath
