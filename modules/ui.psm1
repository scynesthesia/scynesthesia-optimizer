function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "========== $Text ==========" -ForegroundColor Cyan
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp [$Level] $Message"

    switch ($Level) {
        'Error'   { Write-Host $logEntry -ForegroundColor Red }
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        default   { Write-Host $logEntry -ForegroundColor Gray }
    }
}

function Handle-Error {
    param(
        [Parameter(Mandatory)]
        [string]$Context,
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $message = "${Context}: $($ErrorRecord.Exception.Message)"
    Write-Host "[!] $message" -ForegroundColor Yellow
    Write-Log -Message $message -Level 'Warning'
}

function Ask-YesNo {
    param(
        [string]$Question,
        [string]$Default = 'n'
    )

    $defaultText = if ($Default -match '^[yY]$') { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $resp = Read-Host "$Question $defaultText"
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $Default }

        switch ($resp.ToLower()) {
            { $_ -in 'y', 'yes' } { return $true }
            { $_ -in 'n', 'no' } { return $false }
            default { Write-Host "  [!] Invalid option. Please respond with y or n." -ForegroundColor Yellow }
        }
    }
}

function Read-MenuChoice {
    param(
        [string]$Prompt,
        [string[]]$ValidOptions
    )

    while ($true) {
        $choice = Read-Host $Prompt
        if ($ValidOptions -contains $choice) { return $choice }
        Write-Host "[!] Invalid option" -ForegroundColor Yellow
    }
}

function Set-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )

    try {
        # Auto-fix: HKLM\ / HKCU\ -> HKLM:\ / HKCU:\
        if ($Path -match "^HK(LM|CU)\\" -and $Path -notmatch "^HK(LM|CU):\\") {
            $Path = $Path -replace "^HK(LM|CU)\\", 'HK$1:\'
        }

        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Handle-Error -Context "Setting registry value $Path -> $Name" -ErrorRecord $_
    }
}

function Write-OutcomeSummary {
    param(
        [hashtable]$Status
    )

    Write-Host ""
    Write-Host "===== Summary =====" -ForegroundColor Cyan
    Write-Host "[+] Privacy hardened" -ForegroundColor Green
    Write-Host "[+] Debloat applied" -ForegroundColor Green
    Write-Host "[+] Performance tweaks applied" -ForegroundColor Green

    if ($Status.PackagesFailed.Count -gt 0) {
        Write-Host "[X] Some packages could not be removed ($($Status.PackagesFailed -join ', '))" -ForegroundColor Yellow
    } else {
        Write-Host "[+] All targeted packages removed" -ForegroundColor Green
    }

    if ($Status.RebootRequired) {
        Write-Host "[!] Reboot required" -ForegroundColor Yellow
    } else {
        Write-Host "[ ] Reboot optional" -ForegroundColor Gray
    }
}

Export-ModuleMember -Function Write-Section, Write-Log, Handle-Error, Ask-YesNo, Read-MenuChoice, Set-RegistryValueSafe, Write-OutcomeSummary
