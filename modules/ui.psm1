# Depends on: ui.psm1 (loaded by main script)
# Description: Prints a formatted section header to the console.
# Parameters: Text - Section title to display.
# Returns: None.
function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "========== $Text ==========" -ForegroundColor Cyan
}

# Description: Writes a timestamped log message to the console with severity coloring.
# Parameters: Message - Text to log; Level - Severity level (Info, Warning, Error).
# Returns: None.
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

# Description: Normalizes GUID input into uppercase brace-enclosed string form.
# Parameters: Value - Input GUID or string representation.
# Returns: Normalized GUID string or null when conversion fails.
function Get-NormalizedGuid {
    param($Value)

    try {
        if ($null -eq $Value) { return $null }

        if ($Value -is [string]) {
            $trimmed = $Value.Trim('{}').Trim()
            if (-not $trimmed) { return $null }
            return "{$trimmed}".ToUpperInvariant()
        }

        if ($Value -is [guid]) {
            return $Value.ToString('B').ToUpperInvariant()
        }

        return ([guid]$Value).ToString('B').ToUpperInvariant()
    } catch {
        return $null
    }
}

# Description: Logs and displays a warning message for an encountered error.
# Parameters: Context - Operation being performed; ErrorRecord - Error details from the exception.
# Returns: None.
function Invoke-ErrorHandler {
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

# Description: Prompts the user for a yes/no response with default handling.
# Parameters: Question - Prompt text; Default - Default answer when input is empty.
# Returns: Boolean indicating user choice.
function Get-Confirmation {
    param(
        [string]$Question,
        [string]$Default = 'n'
    )

    $defaultNormalized = if ([string]::IsNullOrWhiteSpace($Default)) { 'n' } else { [string]$Default }
    $defaultText = if ($defaultNormalized.ToLowerInvariant() -eq 'y' -or $defaultNormalized.ToLowerInvariant() -eq 'yes') { '[Y/n]' } else { '[y/N]' }

    $questionText = $Question.Trim()
    $appendPrompt = -not ($questionText -match '\[[yYnN]/?[yYnN]?\]$')
    $prompt = if ($appendPrompt) { "$questionText $defaultText".Trim() } else { $questionText }

    while ($true) {
        $resp = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $defaultNormalized }

        $resp = [string]$resp
        switch ($resp.ToLowerInvariant()) {
            { $_ -in 'y', 'yes' } { return $true }
            { $_ -in 'n', 'no' } { return $false }
            default { Write-Host "  [!] Invalid option. Please respond with y or n." -ForegroundColor Yellow }
        }
    }
}

# Description: Reads user input until a valid menu option is provided.
# Parameters: Prompt - Displayed prompt text; ValidOptions - Allowed option values.
# Returns: The selected option string.
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

# Description: Safely creates or updates a registry value with basic validation and logging.
# Parameters: Path - Registry path; Name - Value name; Value - Data to set; Type - Registry value type.
# Returns: None.
function Set-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )

    if ([string]::IsNullOrWhiteSpace($Name) -and $Name -ne "(default)") {
        $warning = "[!] Attempted to set a registry value with an empty name at path $Path. Skipping."
        Write-Host $warning -ForegroundColor Yellow
        Write-Log -Message $warning -Level 'Warning'
        return
    }

    try {
        # Auto-fix: HKLM\ / HKCU\ -> HKLM:\ / HKCU:\
        if ($Path -match "^HK(LM|CU)\\" -and $Path -notmatch "^HK(LM|CU):\\") {
            $Path = $Path -replace "^HK(LM|CU)\\", 'HK$1:\'
        }

        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        if ($Name -eq "(default)") {
            Set-ItemProperty -Path $Path -Name '(default)' -Value $Value -Type $Type -Force -ErrorAction Stop | Out-Null
        }
        else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Invoke-ErrorHandler -Context "Setting registry value $Path -> $Name" -ErrorRecord $_
    }
}

# Description: Prints a summary of tweak results including package removal and reboot status.
# Parameters: Status - Hashtable containing outcome details such as PackagesFailed and RebootRequired.
# Returns: None.
function Write-OutcomeSummary {
    param(
        [hashtable]$Status,
        [bool]$PrivacyApplied = $true,
        [bool]$DebloatApplied = $true,
        [bool]$PerformanceApplied = $true
    )

    Write-Host ""
    Write-Host "===== Summary =====" -ForegroundColor Cyan
    $privacyStatus = if ($PrivacyApplied) { 'Applied' } else { 'Skipped' }
    $debloatStatus = if ($DebloatApplied) { 'Applied' } else { 'Skipped' }
    $performanceStatus = if ($PerformanceApplied) { 'Applied' } else { 'Skipped' }

    Write-Host "[+] Privacy hardened: $privacyStatus" -ForegroundColor Green
    Write-Host "[+] Debloat: $debloatStatus" -ForegroundColor Green
    Write-Host "[+] Performance tweaks: $performanceStatus" -ForegroundColor Green

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

Export-ModuleMember -Function Write-Section, Write-Log, Get-NormalizedGuid, Invoke-ErrorHandler, Get-Confirmation, Read-MenuChoice, Set-RegistryValueSafe, Write-OutcomeSummary
