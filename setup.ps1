[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Scynesthesia Windows Optimizer - Remote Installer
# This script downloads the full repository to handle modular dependencies.

$url = "https://github.com/scynesthesia/scynesthesia-optimizer/archive/refs/heads/main.zip"
$tempDir = Join-Path $env:TEMP "ScynesthesiaTemp"
$zipFile = Join-Path $tempDir "repo.zip"

# Clear any stale payload from previous runs to avoid mixed versions being executed
if (Test-Path $tempDir) {
    try {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not clean previous download at $tempDir. Continuing with existing files may cause issues."
    }
}

# Create temp directory if it doesn't exist
if (!(Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

Write-Host "[*] Downloading Scynesthesia Windows Optimizer components..." -ForegroundColor Cyan
$maxAttempts = 3
$attempt = 0
$downloaded = $false
$lastErrorMessage = $null
while (-not $downloaded -and $attempt -lt $maxAttempts) {
    $attempt++
    try {
        Invoke-WebRequest -Uri $url -OutFile $zipFile -ErrorAction Stop -UseBasicParsing -UserAgent "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045; en-US) PowerShell/5.1"
        $downloaded = $true
    } catch {
        $lastErrorMessage = $_.Exception.Message
        $remaining = $maxAttempts - $attempt
        Write-Host "[!] Download attempt $attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
        if ($remaining -gt 0) {
            Write-Host "    Retrying in 3 seconds... ($remaining retries left)" -ForegroundColor DarkGray
            Start-Sleep -Seconds 3
        }
    }
}

if (-not $downloaded) {
    Write-Host "[!] Failed to download the repository after $maxAttempts attempts. Please check your internet connection." -ForegroundColor Red
    if ($lastErrorMessage) {
        Write-Host "[!] Error: $lastErrorMessage" -ForegroundColor DarkGray
    }
    Read-Host "Press Enter to exit / Presiona Enter para salir"
    exit 1
}

Write-Host "[*] Extracting files..." -ForegroundColor Cyan
try {
    Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force -ErrorAction Stop
} catch {
    Write-Error "Failed to extract files. Ensure no other instances are running."
    exit 1
}


# Locate the main orchestrator within the extracted folder
$mainScript = Get-ChildItem -Path $tempDir -Filter "scynesthesiaoptimizer.ps1" -Recurse -File | Select-Object -First 1

if (-not $mainScript) {
    Write-Host "[!] Could not find the main orchestrator (scynesthesiaoptimizer.ps1)." -ForegroundColor Red
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    if ($logger) { Write-Log "[Setup] scynesthesiaoptimizer.ps1 not found after extraction in $tempDir" }
    exit 1
}

$scriptRoot = $mainScript.Directory.FullName
$launchPath = Join-Path $scriptRoot 'scynesthesiaoptimizer.ps1'

Write-Host "[+] Launching Optimizer..." -ForegroundColor Green
Set-Location $scriptRoot
& $launchPath
