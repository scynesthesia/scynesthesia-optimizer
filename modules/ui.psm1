# Depends on: ui.psm1 (loaded by main script)
$script:RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()

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

function Get-RegistryExceptionDetails {
    param([Exception]$Exception)

    if (-not $Exception) { return 'Unknown error' }

    $details = "${($Exception.GetType().Name)}: $($Exception.Message)"
    $inner = $Exception.InnerException
    while ($inner) {
        $details += " | Inner ${($inner.GetType().Name)}: $($inner.Message)"
        $inner = $inner.InnerException
    }

    return $details
}

function Format-RegistryDataForLog {
    param($Data)

    if ($null -eq $Data) { return '<null>' }
    if ($Data -is [byte[]]) { return ($Data | ForEach-Object { $_.ToString('X2') }) -join ' ' }
    if ($Data -is [System.Collections.IEnumerable] -and -not ($Data -is [string])) {
        return ($Data | ForEach-Object { $_ }) -join ', '
    }

    return [string]$Data
}

function Resolve-RegistryPathComponents {
    param([Parameter(Mandatory)][string]$Path)

    $normalized = $Path.Trim()
    $firstSeparator = $normalized.IndexOf('\\')
    if ($firstSeparator -lt 0) {
        throw [System.ArgumentException]::new("Registry path is missing a subkey: $Path")
    }

    $hiveSegment = $normalized.Substring(0, $firstSeparator).TrimEnd(':')
    $subPath = $normalized.Substring($firstSeparator).TrimStart('\\')

    $hiveName = $hiveSegment.ToUpperInvariant()
    $hiveEnum = switch ($hiveName) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKEY_LOCAL_MACHINE' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKEY_CURRENT_USER' { [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKCR' { [Microsoft.Win32.RegistryHive]::ClassesRoot }
        'HKEY_CLASSES_ROOT' { [Microsoft.Win32.RegistryHive]::ClassesRoot }
        'HKU' { [Microsoft.Win32.RegistryHive]::Users }
        'HKEY_USERS' { [Microsoft.Win32.RegistryHive]::Users }
        'HKCC' { [Microsoft.Win32.RegistryHive]::CurrentConfig }
        'HKEY_CURRENT_CONFIG' { [Microsoft.Win32.RegistryHive]::CurrentConfig }
        default { $null }
    }

    if (-not $hiveEnum) {
        throw [System.ArgumentException]::new("Unsupported registry hive in path: $Path")
    }

    if ([string]::IsNullOrWhiteSpace($subPath)) {
        throw [System.ArgumentException]::new("Registry path is missing a key name: $Path")
    }

    $fullPath = "${hiveSegment.TrimEnd(':')}\\$subPath"

    return [pscustomobject]@{
        Hive = $hiveEnum
        SubKey = $subPath
        FullPath = $fullPath
        HiveName = $hiveSegment.TrimEnd(':')
    }
}

function ConvertTo-RegistryValueData {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Type
    )

    switch ($Type) {
        ([Microsoft.Win32.RegistryValueKind]::DWord) {
            try { return [int]$Value } catch { throw [System.ArgumentException]::new("Value '$Value' is not valid for type DWord.", $_.Exception) }
        }
        ([Microsoft.Win32.RegistryValueKind]::QWord) {
            try { return [long]$Value } catch { throw [System.ArgumentException]::new("Value '$Value' is not valid for type QWord.", $_.Exception) }
        }
        ([Microsoft.Win32.RegistryValueKind]::String) { return [string]$Value }
        ([Microsoft.Win32.RegistryValueKind]::ExpandString) { return [string]$Value }
        ([Microsoft.Win32.RegistryValueKind]::MultiString) {
            if ($Value -is [string[]]) { return $Value }
            if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
                return @($Value | ForEach-Object { [string]$_ })
            }

            return ,([string]$Value)
        }
        ([Microsoft.Win32.RegistryValueKind]::Binary) {
            if ($Value -is [byte[]]) { return $Value }
            if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
                try { return @($Value | ForEach-Object { [byte]$_ }) } catch { throw [System.ArgumentException]::new("Value '$Value' is not valid for type Binary.", $_.Exception) }
            }

            throw [System.ArgumentException]::new("Value '$Value' is not valid for type Binary.")
        }
        default {
            throw [System.ArgumentException]::new("Unsupported registry value kind: $Type")
        }
    }
}

function Add-RegistryRollbackRecord {
    param(
        [Parameter(Mandatory)][pscustomobject]$Record,
        [object]$Context
    )

    $targetCollection = $null
    if ($Context -and $Context.PSObject.Properties.Name -contains 'RegistryRollbackActions') {
        $targetCollection = $Context.RegistryRollbackActions
        if (-not $targetCollection) {
            $Context.RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()
            $targetCollection = $Context.RegistryRollbackActions
        }
    }

    if (-not $targetCollection) {
        if (-not $script:RegistryRollbackActions) {
            $script:RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()
        }
        $targetCollection = $script:RegistryRollbackActions
    }

    [void]$targetCollection.Add($Record)
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

# Description: Safely creates or updates a registry value with validation, logging, and rollback capture.
# Parameters: Path - Registry path; Name - Value name; Value - Data to set; Type - Registry value type; Critical - Stop on error when specified; Context - optional run context that can hold RegistryRollbackActions.
# Returns: None.
function Set-RegistryValueSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord,
        [switch]$Critical,
        [object]$Context
    )

    if ([string]::IsNullOrWhiteSpace($Name) -and $Name -ne '(default)') {
        $warning = "[!] Attempted to set a registry value with an empty name at path $Path. Skipping."
        Write-Host $warning -ForegroundColor Yellow
        Write-Log -Message $warning -Level 'Warning'
        return
    }

    $displayName = if ([string]::IsNullOrWhiteSpace($Name) -or $Name -eq '(default)') { '(default)' } else { $Name }
    $valueName = if ($displayName -eq '(default)') { '' } else { $Name }

    try {
        $target = Resolve-RegistryPathComponents -Path $Path
    } catch {
        $message = "Failed to resolve registry path for $Path -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Missing hive or key. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        Write-Log -Message $message -Level 'Error'
        if ($Critical) { throw }
        return
    }

    $baseKey = $null
    $subKey = $null
    $previousValue = $null
    $previousType = $null
    $valueExisted = $false
    $keyExisted = $false
    $convertedValue = $null

    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($target.Hive, [Microsoft.Win32.RegistryView]::Default)
        if (-not $baseKey) { throw [System.IO.IOException]::new("Could not open base registry hive for $($target.HiveName)") }

        $subKey = $baseKey.OpenSubKey($target.SubKey, $true)
        if (-not $subKey) {
            $subKey = $baseKey.CreateSubKey($target.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        } else {
            $keyExisted = $true
        }

        if (-not $subKey) {
            throw [System.IO.IOException]::new("Could not create or open subkey $($target.FullPath)")
        }

        try {
            $valueNames = $subKey.GetValueNames()
            $valueExisted = $valueNames -contains $valueName
            if ($valueExisted) {
                $previousValue = $subKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $previousType = $subKey.GetValueKind($valueName)
            }
        } catch [System.ArgumentException] { }

        $convertedValue = ConvertTo-RegistryValueData -Value $Value -Type $Type
        $subKey.SetValue($valueName, $convertedValue, $Type)

        $rollbackGuidance = if ($valueExisted) {
            "Restore previous value ($([string]$previousType)): $(Format-RegistryDataForLog $previousValue)"
        } elseif (-not $keyExisted) {
            'Delete the created key to revert.'
        } else {
            'Remove the value to revert.'
        }

        $rollbackRecord = [pscustomobject]@{
            Path = $target.FullPath
            Name = $displayName
            PreviousExists = $valueExisted
            PreviousValue = $previousValue
            PreviousType = if ($previousType) { $previousType.ToString() } else { $null }
            KeyExisted = $keyExisted
            IntendedType = $Type.ToString()
            IntendedValue = $convertedValue
            Guidance = $rollbackGuidance
        }
        Add-RegistryRollbackRecord -Record $rollbackRecord -Context $Context

        $successMessage = "Set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $convertedValue)). Rollback guidance recorded."
        Write-Log -Message $successMessage -Level 'Info'
    }
    catch [System.UnauthorizedAccessException] {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Permission denied. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        $level = if ($Critical) { 'Error' } else { 'Warning' }
        Write-Log -Message $message -Level $level
        if ($Critical) { throw }
    }
    catch [System.Security.SecurityException] {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Permission denied. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        $level = if ($Critical) { 'Error' } else { 'Warning' }
        Write-Log -Message $message -Level $level
        if ($Critical) { throw }
    }
    catch [System.ArgumentException] {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Invalid type or value. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        Write-Log -Message $message -Level 'Error'
        if ($Critical) { throw }
    }
    catch {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Registry access failure. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        Write-Log -Message $message -Level 'Error'
        if ($Critical) { throw }
    }
    finally {
        if ($subKey) { $subKey.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
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
