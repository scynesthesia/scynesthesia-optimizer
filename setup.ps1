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
try {
    Invoke-WebRequest -Uri $url -OutFile $zipFile -ErrorAction Stop
} catch {
    Write-Error "Failed to download the repository. Please check your internet connection."
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




