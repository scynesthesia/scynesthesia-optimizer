
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
            Write-Host "[*] Attempt $attempt/$MaxAttempts from $uri ..." -ForegroundColor Cyan
            try {
                Invoke-DownloadHelper -Uri $uri -Destination $Destination -UserAgent $UserAgent
                $downloaded = $true
                break
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Warning "[!] Download from $uri failed: $errorMsg"
            }
        }

        if (-not $downloaded -and $attempt -lt $MaxAttempts) {
            $backoff = [Math]::Pow(2, $attempt)
            $jitter = $rand.Next(0, 1000) / 1000
            $sleepSeconds = [Math]::Min(30, $backoff + $jitter)
            Write-Host "[*] Retrying in $([Math]::Round($sleepSeconds, 2)) seconds... ($($MaxAttempts - $attempt) left)" -ForegroundColor DarkGray
            Start-Sleep -Seconds $sleepSeconds
        }
    }

    if (-not $downloaded) {
        throw "Failed to download repository after $MaxAttempts attempts."
    }
}

if (Test-Path $tempDir) {
    try {
        $fullTemp = [System.IO.Path]::GetFullPath($tempDir)
        $fullEnvTemp = [System.IO.Path]::GetFullPath($env:TEMP)
        if ($fullTemp.StartsWith($fullEnvTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
        } else {
            Write-Warning "[!] Skipping cleanup because path validation failed: $tempDir"
        }
    } catch {
        Write-Warning "[!] Could not clean previous download at $tempDir. Continuing with existing files may cause issues."
    }
}

if (-not (Test-Path $tempDir)) {
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    } catch {
        Write-Error "[X] Cannot create temporary directory at $tempDir."
        exit 1
    }
}

Write-Host "[*] Downloading Scynesthesia Windows Optimizer components..." -ForegroundColor Cyan
try {
    Invoke-RepositoryDownload -Uris $repoUrls -Destination $zipFile -UserAgent $userAgent -MaxAttempts $maxAttempts
} catch {
    Write-Error "[X] Download failed: $($_.Exception.Message)"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[*] Extracting files..." -ForegroundColor Cyan
try {
    Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force -ErrorAction Stop
} catch {
    Write-Error "[X] Failed to extract files. Ensure no other instances are running."
    exit 1
}

$mainScript = Get-ChildItem -Path $tempDir -Filter 'scynesthesiaoptimizer.ps1' -Recurse -File | Select-Object -First 1

if (-not $mainScript) {
    Write-Error "[X] Could not find the main orchestrator (scynesthesiaoptimizer.ps1)."
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    if ($logger) { Write-Log "[Setup] scynesthesiaoptimizer.ps1 not found after extraction in $tempDir" }
    exit 1
}

$launchPath = $mainScript.FullName
$scriptDir = $mainScript.Directory.FullName

Write-Host '[+] Launching Optimizer in a new interactive window...' -ForegroundColor Green
# Usamos una sola cadena para ArgumentList para evitar errores de parseo de arrays
$argList = "-NoExit -ExecutionPolicy Bypass -File `"$launchPath`""

Start-Process powershell.exe -ArgumentList $argList -WorkingDirectory $scriptDir
