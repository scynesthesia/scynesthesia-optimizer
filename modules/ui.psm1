# Depends on: ui.psm1 (loaded by main script)
$script:RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()
$script:DefaultLogDirectory = Join-Path $env:TEMP 'ScynesthesiaOptimizer'
$script:DefaultLogPath = Join-Path $script:DefaultLogDirectory 'Scynesthesia_Runtime.log'

# Description: Prints a formatted section header to the console.
# Parameters: Text - Section title to display.
# Returns: None.
function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "========== $Text ==========" -ForegroundColor Cyan
}

# Description: Writes a timestamped log message to the console and log file with optional structured metadata.
# Parameters: Message - Text to log; Level - Severity level (Info, Warning, Error); Data - Optional structured metadata; NoConsole - Suppresses console output when set.
# Returns: None.
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info',
        [hashtable]$Data,
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = [ordered]@{
        timestamp = $timestamp
        level     = $Level
        message   = $Message
    }

    if ($Data) {
        $entry.data = $Data
    }

    $logLine = ($entry | ConvertTo-Json -Depth 6 -Compress)

    if (-not $NoConsole) {
        $color = switch ($Level) {
            'Error'   { 'Red' }
            'Warning' { 'Yellow' }
            default   { 'Gray' }
        }
        Write-Host $logLine -ForegroundColor $color
    }

    $logPath = if ($global:ScynesthesiaLogPath) { $global:ScynesthesiaLogPath } else { $script:DefaultLogPath }
    try {
        if (-not (Test-Path -Path $logPath)) {
            $dir = Split-Path -Path $logPath
            if (-not (Test-Path -Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            New-Item -ItemType File -Path $logPath -Force | Out-Null
        }

        Add-Content -Path $logPath -Value $logLine
    } catch {
        if (-not $NoConsole) {
            Write-Host "Logging failure: $($_.Exception.Message)" -ForegroundColor Red
        }
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

function Get-RegistryRollbackRecords {
    param([object]$Context)

    if ($Context -and $Context.PSObject.Properties.Name -contains 'RegistryRollbackActions' -and $Context.RegistryRollbackActions) {
        return @($Context.RegistryRollbackActions)
    }

    return @($script:RegistryRollbackActions)
}

function ConvertTo-RegistryValueKindSafe {
    param(
        [string]$TypeName,
        [Microsoft.Win32.RegistryValueKind]$Fallback = [Microsoft.Win32.RegistryValueKind]::String
    )

    if ([string]::IsNullOrWhiteSpace($TypeName)) { return $Fallback }

    $parsed = $null
    if ([System.Enum]::TryParse([Microsoft.Win32.RegistryValueKind], $TypeName, $true, [ref]$parsed)) {
        return $parsed
    }

    return $Fallback
}

function Invoke-RegistryRollback {
    [CmdletBinding()]
    param([pscustomobject]$Context)

    $records = @(Get-RegistryRollbackRecords -Context $Context)
    if (-not $records -or $records.Count -eq 0) {
        Write-Host "[ ] No registry rollback entries recorded for this session." -ForegroundColor Gray
        return
    }

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Write-Host "[i] Attempting rollback of $($records.Count) registry change(s)." -ForegroundColor Cyan

    $total = $records.Count
    $success = 0
    $failed = 0

    # Roll back in reverse order to mirror application order.
    for ($i = $records.Count - 1; $i -ge 0; $i--) {
        $record = $records[$i]
        $valueName = if ($record.Name -eq '(default)' -or [string]::IsNullOrWhiteSpace($record.Name)) { '' } else { $record.Name }
        $target = $null
        try {
            $target = Resolve-RegistryPathComponents -Path $record.Path
        } catch {
            $failed++
            $msg = "[Rollback] Could not resolve registry path: $($record.Path) -> $($record.Name). Error: $($_.Exception.Message)"
            Write-Host "  [!] $msg" -ForegroundColor Yellow
            if ($logger) { Write-Log -Message $msg -Level 'Warning' }
            continue
        }

        $baseKey = $null
        $subKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($target.Hive, [Microsoft.Win32.RegistryView]::Default)
            if (-not $baseKey) { throw [System.IO.IOException]::new("Unable to open base key for $($target.HiveName)") }

            $subKey = $baseKey.OpenSubKey($target.SubKey, $true)
            if (-not $subKey -and $record.KeyExisted) {
                throw [System.IO.IOException]::new("Original key missing: $($target.FullPath)")
            }

            if ($record.PreviousExists) {
                $kind = ConvertTo-RegistryValueKindSafe -TypeName $record.PreviousType -Fallback ([Microsoft.Win32.RegistryValueKind]::String)
                $converted = ConvertTo-RegistryValueData -Value $record.PreviousValue -Type $kind
                if (-not $subKey) {
                    $subKey = $baseKey.CreateSubKey($target.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                }
                $subKey.SetValue($valueName, $converted, $kind)
                $success++
                $msg = "[Rollback] Restored $($record.Path) -> $($record.Name) to previous value."
                Write-Host "  [+] $msg" -ForegroundColor Green
                if ($logger) { Write-Log -Message $msg -Level 'Info' }
            }
            elseif (-not $record.KeyExisted) {
                # Key did not exist before; remove it entirely if present.
                if ($subKey) {
                    $subKey.Dispose(); $subKey = $null
                }
                $baseKey.DeleteSubKeyTree($target.SubKey, $false)
                $success++
                $msg = "[Rollback] Removed created key $($record.Path)."
                Write-Host "  [+] $msg" -ForegroundColor Green
                if ($logger) { Write-Log -Message $msg -Level 'Info' }
            }
            else {
                # Value did not exist before; remove it if present.
                if ($subKey) {
                    try {
                        $subKey.DeleteValue($valueName, $false)
                    } catch [System.ArgumentException] {
                        # Value already absent; treat as successful cleanup.
                    }
                }
                $success++
                $msg = "[Rollback] Removed new value at $($record.Path) -> $($record.Name)."
                Write-Host "  [+] $msg" -ForegroundColor Green
                if ($logger) { Write-Log -Message $msg -Level 'Info' }
            }
        }
        catch {
            $failed++
            $msg = "[Rollback] Failed to revert $($record.Path) -> $($record.Name): $(Get-RegistryExceptionDetails $_.Exception)"
            Write-Host "  [!] $msg" -ForegroundColor Yellow
            if ($logger) { Write-Log -Message $msg -Level 'Error' }
        }
        finally {
            if ($subKey) { $subKey.Dispose() }
            if ($baseKey) { $baseKey.Dispose() }
        }
    }

    Write-Host "[i] Registry rollback completed. Success: $success / $total, Failed: $failed." -ForegroundColor Cyan
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

# Description: Logs and displays a structured error block with remediation hints.
# Parameters: Context - Operation being performed; ErrorRecord - Error details from the exception; Path/Key/Value/Command - Optional explicit metadata about the failing operation.
# Returns: None.
function Invoke-ErrorHandler {
    param(
        [Parameter(Mandatory)]
        [string]$Context,
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Path,
        [string]$Key,
        [object]$Value,
        [string]$Command
    )

    $invocation = $ErrorRecord.InvocationInfo
    $bound = $invocation?.BoundParameters

    if (-not $Path -and $bound -and $bound.ContainsKey('Path')) { $Path = [string]$bound['Path'] }
    if (-not $Key -and $bound -and $bound.ContainsKey('Name')) { $Key = [string]$bound['Name'] }
    if (-not $Value -and $bound -and $bound.ContainsKey('Value')) { $Value = $bound['Value'] }
    if (-not $Path -and $ErrorRecord.TargetObject) { $Path = [string]$ErrorRecord.TargetObject }
    if (-not $Command -and $invocation) { $Command = $invocation.InvocationName }

    $exceptionChain = @()
    $ex = $ErrorRecord.Exception
    while ($ex) {
        $exceptionChain += "$($ex.GetType().Name): $($ex.Message)"
        $ex = $ex.InnerException
    }

    $hintMessages = @()
    $exceptionText = $exceptionChain -join ' | '
    if ($exceptionText -match 'denied' -or $ErrorRecord.Exception -is [System.UnauthorizedAccessException]) {
        $hintMessages += 'Try running as administrator.'
        $hintMessages += 'Check policy restrictions (ExecutionPolicy/GPO).'
    }
    if ($exceptionText -match 'cannot find (path|file)' -or $ErrorRecord.CategoryInfo.Reason -eq 'ItemNotFoundException') {
        $hintMessages += 'If running a module standalone, ensure ScriptRoot/config files exist.'
    }
    if (($Command -and $Command -match 'netsh') -or $exceptionText -match 'netsh') {
        $hintMessages += 'Consider rebooting, resetting the network stack, or checking for driver issues.'
    }

    $remediation = if ($hintMessages) { $hintMessages -join ' ' } else { 'Review the log entry for details and retry.' }
    $valueDisplay = Format-RegistryDataForLog -Data $Value

    $structured = [ordered]@{
        operation   = $Context
        path        = if ($Path) { $Path } else { '<unknown>' }
        key         = if ($Key) { $Key } else { '<n/a>' }
        value       = if ($null -ne $Value) { $valueDisplay } else { '<n/a>' }
        command     = if ($Command) { $Command } else { '<unspecified>' }
        exception   = $exceptionChain
        remediation = $remediation
        script      = $invocation?.ScriptName
        line        = $invocation?.ScriptLineNumber
    }

    Write-Log -Message "Operation failed: $Context" -Level 'Error' -Data $structured -NoConsole

    $logReference = if ($global:ScynesthesiaLogPath) { $global:ScynesthesiaLogPath } else { $script:DefaultLogPath }
    $block = @(
        ''
        '=== Operation Error ==='
        "Operation : $Context"
        "Path      : $($structured.path)"
        "Key/Value : $($structured.key) / $($structured.value)"
        "Command   : $($structured.command)"
        'Exception :'
    )

    foreach ($line in $exceptionChain) {
        $block += "  - $line"
    }

    $block += @(
        "Remediation: $remediation"
        "Log entry  : $logReference"
        '========================'
    )

    foreach ($line in $block) { Write-Host $line -ForegroundColor Yellow }
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

# Description: Adds a permission failure entry to the run context for later reporting.
# Parameters: Context - Run context that stores permission failures; Result - Result object produced by Set-RegistryValueSafe; Operation - Friendly label for the attempted operation.
# Returns: Boolean indicating whether a failure was recorded.
function Add-RegistryPermissionFailure {
    param(
        [pscustomobject]$Context,
        [pscustomobject]$Result,
        [string]$Operation
    )

    if (-not $Context) { return $false }
    if (-not $Result -or $Result.Success -or $Result.ErrorCategory -ne 'PermissionDenied') { return $false }

    if (-not $Context.PSObject.Properties.Name.Contains('RegistryPermissionFailures')) {
        $Context | Add-Member -Name RegistryPermissionFailures -MemberType NoteProperty -Value @()
    }

    $operationLabel = if (-not [string]::IsNullOrWhiteSpace($Operation)) {
        $Operation
    } elseif ($Result.PSObject.Properties.Name -contains 'Operation' -and -not [string]::IsNullOrWhiteSpace($Result.Operation)) {
        $Result.Operation
    } else {
        "$($Result.Path) -> $($Result.Name)"
    }

    $Context.RegistryPermissionFailures += [pscustomobject]@{
        Operation = $operationLabel
        Path      = $Result.Path
        Name      = $Result.Name
    }
    return $true
}

# Description: Safely creates or updates a registry value with validation, logging, rollback capture, and optional result reporting.
# Parameters: Path - Registry path; Name - Value name; Value - Data to set; Type - Registry value type; Critical - Stop on error when specified; Context - optional run context that can hold RegistryRollbackActions; ReturnResult - emits a result object with Success/WasCreated/ErrorCategory.
# Returns: Nothing by default; when -ReturnResult is passed, returns a PSCustomObject with Success, WasCreated, ErrorCategory, Path, and Name.
function Set-RegistryValueSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord,
        [switch]$Critical,
        [object]$Context,
        [switch]$ReturnResult,
        [string]$OperationLabel
    )

    if ([string]::IsNullOrWhiteSpace($Name) -and $Name -ne '(default)') {
        $warning = "[!] Attempted to set a registry value with an empty name at path $Path. Skipping."
        Write-Host $warning -ForegroundColor Yellow
        Write-Log -Message $warning -Level 'Warning'
        $emptyNameResult = [pscustomobject]@{
            Success       = $false
            WasCreated    = $false
            ErrorCategory = 'MissingValueName'
            Path          = $Path
            Name          = '(unspecified)'
        }
        if ($ReturnResult) { return $emptyNameResult }
        return
    }

    $displayName = if ([string]::IsNullOrWhiteSpace($Name) -or $Name -eq '(default)') { '(default)' } else { $Name }
    $valueName = if ($displayName -eq '(default)') { '' } else { $Name }
    $result = [pscustomobject]@{
        Success       = $false
        WasCreated    = $false
        ErrorCategory = $null
        Path          = $Path
        Name          = $displayName
        Operation     = if (-not [string]::IsNullOrWhiteSpace($OperationLabel)) { $OperationLabel } else { "$Path -> $displayName" }
    }
    $shouldThrowOnFailure = $Critical -and -not $ReturnResult

    try {
        $target = Resolve-RegistryPathComponents -Path $Path
        $result.Path = $target.FullPath
    } catch {
        $message = "Failed to resolve registry path for $Path -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Missing hive or key. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        $result.ErrorCategory = 'PathResolution'
        Write-Log -Message $message -Level 'Error'
        if ($shouldThrowOnFailure) { throw }
        if ($ReturnResult) { return $result }
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
        $result.Success = $true
        $result.WasCreated = -not $valueExisted
        $result.ErrorCategory = $null
    }
    catch [System.UnauthorizedAccessException] {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Permission denied. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        $level = if ($Critical) { 'Error' } else { 'Warning' }
        Write-Log -Message $message -Level $level
        $result.ErrorCategory = 'PermissionDenied'
        Add-RegistryPermissionFailure -Context $Context -Result $result -Operation $OperationLabel | Out-Null
        if ($shouldThrowOnFailure) { throw }
    }
    catch [System.Security.SecurityException] {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Permission denied. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        $level = if ($Critical) { 'Error' } else { 'Warning' }
        Write-Log -Message $message -Level $level
        $result.ErrorCategory = 'PermissionDenied'
        Add-RegistryPermissionFailure -Context $Context -Result $result -Operation $OperationLabel | Out-Null
        if ($shouldThrowOnFailure) { throw }
    }
    catch [System.ArgumentException] {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Invalid type or value. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        Write-Log -Message $message -Level 'Error'
        $result.ErrorCategory = 'InvalidData'
        if ($shouldThrowOnFailure) { throw }
    }
    catch {
        $message = "Failed to set registry value at $($target.FullPath) -> $displayName (Type: $Type, Data: $(Format-RegistryDataForLog $Value)). Category: Registry access failure. Error: $(Get-RegistryExceptionDetails $_.Exception)"
        Write-Log -Message $message -Level 'Error'
        $result.ErrorCategory = 'RegistryAccessFailure'
        if ($shouldThrowOnFailure) { throw }
    }
    finally {
        if ($subKey) { $subKey.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
    }

    if ($ReturnResult) { return $result }
}

# Description: Initializes a tracker for counting critical registry write failures within a module.
# Parameters: Name - Module or feature label for reporting.
# Returns: PSCustomObject with Name, CriticalFailures, and Abort flag.
function New-RegistryFailureTracker {
    param([Parameter(Mandatory)][string]$Name)

    [pscustomobject]@{
        Name             = $Name
        CriticalFailures = 0
        Abort            = $false
    }
}

# Description: Registers the outcome of a registry write and marks the tracker for aborting when a critical failure occurs.
# Parameters: Tracker - Tracker object created by New-RegistryFailureTracker; Result - Result object returned by Set-RegistryValueSafe; Critical - Treat failure as abort-worthy.
# Returns: Boolean indicating whether the module should abort further actions.
function Register-RegistryResult {
    param(
        [Parameter(Mandatory)][pscustomobject]$Tracker,
        [Parameter(Mandatory)][pscustomobject]$Result,
        [switch]$Critical
    )

    if (-not $Tracker) { return $false }
    if (-not $Critical) { return $false }
    if (-not $Result -or $Result.Success) { return $false }

    $Tracker.CriticalFailures++
    $Tracker.Abort = $true
    return $true
}

# Description: Emits a single summary line when critical registry failures were encountered in a module.
# Parameters: Tracker - Tracker object created by New-RegistryFailureTracker.
# Returns: None.
function Write-RegistryFailureSummary {
    param([pscustomobject]$Tracker)

    if ($Tracker -and $Tracker.CriticalFailures -gt 0) {
        Write-Host "Module $($Tracker.Name) completed with $($Tracker.CriticalFailures) critical failures; aborting further actions." -ForegroundColor Red
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

    $permissionFailures = @()
    if ($Status -and $Status.ContainsKey('RegistryPermissionFailures')) {
        $permissionFailures = @($Status.RegistryPermissionFailures)
    }

    if ($permissionFailures.Count -gt 0) {
        Write-Host "[!] Some tweaks could not be applied due to permission issues:" -ForegroundColor Yellow
        foreach ($failure in ($permissionFailures | Where-Object { $_ } | Select-Object -Unique)) {
            $label = if ($failure.PSObject.Properties.Name -contains 'Operation' -and -not [string]::IsNullOrWhiteSpace($failure.Operation)) {
                $failure.Operation
            } else {
                "$($failure.Path) -> $($failure.Name)"
            }
            Write-Host "    - $label" -ForegroundColor Yellow
        }
    }

    if ($Status.RebootRequired) {
        Write-Host "[!] Reboot required" -ForegroundColor Yellow
    } else {
        Write-Host "[ ] Reboot optional" -ForegroundColor Gray
    }
}

Export-ModuleMember -Function Write-Section, Write-Log, Get-NormalizedGuid, Invoke-ErrorHandler, Get-Confirmation, Read-MenuChoice, Set-RegistryValueSafe, Write-OutcomeSummary, New-RegistryFailureTracker, Register-RegistryResult, Write-RegistryFailureSummary, Add-RegistryPermissionFailure
