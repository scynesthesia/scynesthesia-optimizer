# Description: Provides a per-run context object and helpers to track execution state.

# Creates a new run context with defaults suitable for a single execution.
# Returns: PSCustomObject with ScriptRoot, NeedsReboot, RollbackActions, LogPath.
function New-RunContext {
    [CmdletBinding()]
    param(
        [string]$ScriptRoot
    )

    $resolvedRoot = if ($ScriptRoot) {
        $ScriptRoot
    } elseif (Get-Command -Name Get-ScriptRoot -ErrorAction SilentlyContinue) {
        Get-ScriptRoot -LocalRoot $PSScriptRoot
    } elseif ($PSScriptRoot) {
        $PSScriptRoot
    } else {
        Split-Path -Parent $MyInvocation.MyCommand.Definition
    }

    [pscustomobject]@{
        ScriptRoot      = $resolvedRoot
        NeedsReboot     = $false
        RollbackActions = @()
        RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()
        ServiceRollbackActions = [System.Collections.Generic.List[object]]::new()
        NetshRollbackActions = [System.Collections.Generic.List[object]]::new()
        NetworkHardwareRollbackActions = [System.Collections.Generic.List[object]]::new()
        NonRegistryChanges = @{
            ServiceState = @{}
            NetshGlobal  = @{}
        }
        RollbackPersistencePath = $null
        LogPath         = $null
        AppliedTweaks   = @{}
        RegistryPermissionFailures = @()
        DebloatRemovalLog = [System.Collections.Generic.List[string]]::new()
    }
}

# Ensures an action runs only once per identifier within the provided context.
# Parameters:
#   Context - Run context tracking applied tweaks.
#   Id      - Unique identifier for the action.
#   Action  - Script block to execute when not previously applied.
function Invoke-Once {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    if (-not $Context.PSObject.Properties.Name.Contains('AppliedTweaks')) {
        $Context | Add-Member -Name AppliedTweaks -MemberType NoteProperty -Value @{}
    }

    if ($Context.AppliedTweaks.ContainsKey($Id)) {
        Write-Host "Skipped $Id (already applied)"
        return $false
    }

    & $Action
    $Context.AppliedTweaks[$Id] = $true
    return $true
}

# Returns the provided context or creates a new one when none is supplied.
# Parameters: Context - Optional existing PSCustomObject to reuse.
function Get-RunContext {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    if ($Context) { return $Context }
    return New-RunContext
}

# Marks that a reboot is required on the provided context.
# Parameters: Context - Run context to update.
function Set-RebootRequired {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $Context.NeedsReboot = $true
    return $Context
}

# Retrieves the reboot-required flag from the provided context.
# Parameters: Context - Run context to inspect.
function Get-RebootRequired {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    return [bool]$Context.NeedsReboot
}

# Marks the supplied context as requiring a reboot.
# Parameters: Context - The run context to update.
function Set-NeedsReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    return Set-RebootRequired -Context $Context
}

# Retrieves the reboot flag from the supplied context.
# Parameters: Context - The run context to inspect.
function Get-NeedsReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    return Get-RebootRequired -Context $Context
}

# Resets the reboot flag on the supplied context and clears the module fallback mirror.
# Parameters: Context - The run context to update.
function Reset-NeedsReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $Context.NeedsReboot = $false
    return $Context
}

# Ensures the context exposes a NonRegistryChanges tracker with ServiceState and NetshGlobal buckets.
# Parameters: Context - Run context to initialize or return.
function Get-NonRegistryChangeTracker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $runContext = Get-RunContext -Context $Context
    if (-not $runContext.PSObject.Properties.Name.Contains('NonRegistryChanges')) {
        $runContext | Add-Member -Name NonRegistryChanges -MemberType NoteProperty -Value @{
            ServiceState = @{}
            NetshGlobal  = @{}
        }
    }
    elseif (-not $runContext.NonRegistryChanges) {
        $runContext.NonRegistryChanges = @{
            ServiceState = @{}
            NetshGlobal  = @{}
        }
    }

    if (-not $runContext.NonRegistryChanges.ContainsKey('ServiceState')) {
        $runContext.NonRegistryChanges['ServiceState'] = @{}
    }
    if (-not $runContext.NonRegistryChanges.ContainsKey('NetshGlobal')) {
        $runContext.NonRegistryChanges['NetshGlobal'] = @{}
    }

    return $runContext.NonRegistryChanges
}

# Records a non-registry change (services/netsh) into the provided context if not already tracked.
# Parameters: Context - Run context; Area - ServiceState or NetshGlobal; Key - Identifier (service name/setting); Value - Original state data.
function Add-NonRegistryChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [Parameter(Mandatory)]
        [ValidateSet('ServiceState','NetshGlobal')]
        [string]$Area,
        [Parameter(Mandatory)]
        [string]$Key,
        [Parameter(Mandatory)]
        $Value
    )

    $tracker = Get-NonRegistryChangeTracker -Context $Context
    if (-not $tracker[$Area].ContainsKey($Key)) {
        $tracker[$Area][$Key] = $Value
    }

    return $tracker[$Area][$Key]
}

# Ensures the context exposes rollback collections for registry, service, and netsh actions.
function Initialize-RollbackCollections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $runContext = Get-RunContext -Context $Context

    if (-not $runContext.PSObject.Properties.Name.Contains('RegistryRollbackActions') -or -not $runContext.RegistryRollbackActions) {
        if ($runContext.PSObject.Properties.Name.Contains('RegistryRollbackActions')) {
            $runContext.RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()
        } else {
            $runContext | Add-Member -Name RegistryRollbackActions -MemberType NoteProperty -Value ([System.Collections.Generic.List[object]]::new())
        }
    }

    if (-not $runContext.PSObject.Properties.Name.Contains('ServiceRollbackActions') -or -not $runContext.ServiceRollbackActions) {
        if ($runContext.PSObject.Properties.Name.Contains('ServiceRollbackActions')) {
            $runContext.ServiceRollbackActions = [System.Collections.Generic.List[object]]::new()
        } else {
            $runContext | Add-Member -Name ServiceRollbackActions -MemberType NoteProperty -Value ([System.Collections.Generic.List[object]]::new())
        }
    }

    if (-not $runContext.PSObject.Properties.Name.Contains('NetshRollbackActions') -or -not $runContext.NetshRollbackActions) {
        if ($runContext.PSObject.Properties.Name.Contains('NetshRollbackActions')) {
            $runContext.NetshRollbackActions = [System.Collections.Generic.List[object]]::new()
        } else {
            $runContext | Add-Member -Name NetshRollbackActions -MemberType NoteProperty -Value ([System.Collections.Generic.List[object]]::new())
        }
    }

    if (-not $runContext.PSObject.Properties.Name.Contains('NetworkHardwareRollbackActions') -or -not $runContext.NetworkHardwareRollbackActions) {
        if ($runContext.PSObject.Properties.Name.Contains('NetworkHardwareRollbackActions')) {
            $runContext.NetworkHardwareRollbackActions = [System.Collections.Generic.List[object]]::new()
        } else {
            $runContext | Add-Member -Name NetworkHardwareRollbackActions -MemberType NoteProperty -Value ([System.Collections.Generic.List[object]]::new())
        }
    }

    return $runContext
}

# Adds or retrieves a service rollback snapshot keyed by service name.
function Add-ServiceRollbackAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$StartupType,
        [string]$Status
    )

    $runContext = Initialize-RollbackCollections -Context $Context
    $existing = $runContext.ServiceRollbackActions | Where-Object { $_.Name -and $_.Name -ieq $ServiceName }
    if ($existing) { return $existing[0] }

    $record = [pscustomobject]@{
        Name        = $ServiceName
        StartupType = $StartupType
        Status      = $Status
    }
    [void]$runContext.ServiceRollbackActions.Add($record)
    return $record
}

# Adds or updates a netsh global rollback entry keyed by setting name.
function Add-NetshRollbackAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)]$Value
    )

    $runContext = Initialize-RollbackCollections -Context $Context
    $existing = $runContext.NetshRollbackActions | Where-Object { $_.Name -and $_.Name -ieq $Setting }
    if ($existing) {
        $existing[0].Value = $Value
        return $existing[0]
    }

    $record = [pscustomobject]@{
        Name  = $Setting
        Value = $Value
    }
    [void]$runContext.NetshRollbackActions.Add($record)
    return $record
}

# Returns the persistence path for registry rollback actions and, optionally, creates the parent directory.
function Get-RollbackPersistencePath {
    [CmdletBinding()]
    param(
        [string]$FileName = 'session_rollback.json'
    )

    if ([string]::IsNullOrWhiteSpace($FileName)) {
        $FileName = 'session_rollback.json'
    }

    $root = if ($env:ProgramData) { Join-Path $env:ProgramData 'Scynesthesia' } else { 'C:\ProgramData\Scynesthesia' }
    return Join-Path $root $FileName
}

# Persists rollback actions from the context to disk so they can be restored after crashes.
function Save-RollbackState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$Path
    )

    $targetPath = if ($Path) { $Path } else { Get-RollbackPersistencePath }
    $parent = Split-Path -Parent $targetPath
    if (-not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $runContext = Initialize-RollbackCollections -Context $Context

    $registryRecords = @()
    if ($runContext.RegistryRollbackActions) {
        $registryRecords = @($runContext.RegistryRollbackActions)
    }

    $serviceRecords = @()
    if ($runContext.ServiceRollbackActions) {
        $serviceRecords = @($runContext.ServiceRollbackActions)
    }

    $netshRecords = @()
    if ($runContext.NetshRollbackActions) {
        $netshRecords = @($runContext.NetshRollbackActions)
    }

    $networkHardwareRecords = @()
    if ($runContext.NetworkHardwareRollbackActions) {
        $networkHardwareRecords = @($runContext.NetworkHardwareRollbackActions)
    }

    $payload = [pscustomobject]@{
        LastUpdated = (Get-Date).ToString('o')
        Registry    = $registryRecords
        Services    = $serviceRecords
        Netsh       = $netshRecords
        NetworkHardware = $networkHardwareRecords
    }

    try {
        $json = $payload | ConvertTo-Json -Depth 8 -ErrorAction Stop
        Set-Content -Path $targetPath -Value $json -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "Failed to persist rollback actions to $targetPath: $($_.Exception.Message)"
    }

    return $targetPath
}

# Maintains backward compatibility for callers expecting registry-only persistence.
function Save-RegistryRollbackState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$Path
    )

    return Save-RollbackState -Context $Context -Path $Path
}

# Restores rollback actions from disk into the supplied context.
function Restore-RollbackState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$Path
    )

    $targetPath = if ($Path) { $Path } else { Get-RollbackPersistencePath }
    if (-not (Test-Path $targetPath)) { return $false }

    try {
        $content = Get-Content -Path $targetPath -Raw -ErrorAction Stop
        $data = $content | ConvertFrom-Json -ErrorAction Stop
        $registryRecords = @()
        if ($data -and $data.PSObject.Properties.Name -contains 'Registry' -and $data.Registry) {
            $registryRecords = @($data.Registry)
        } elseif ($data -and $data.PSObject.Properties.Name -contains 'Records' -and $data.Records) {
            $registryRecords = @($data.Records)
        }

        $serviceRecords = @()
        if ($data -and $data.PSObject.Properties.Name -contains 'Services' -and $data.Services) {
            $serviceRecords = @($data.Services)
        }

        $netshRecords = @()
        if ($data -and $data.PSObject.Properties.Name -contains 'Netsh' -and $data.Netsh) {
            $netshRecords = @($data.Netsh)
        }

        $networkHardwareRecords = @()
        if ($data -and $data.PSObject.Properties.Name -contains 'NetworkHardware' -and $data.NetworkHardware) {
            $networkHardwareRecords = @($data.NetworkHardware)
        }

        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($record in $registryRecords) { [void]$list.Add($record) }

        $serviceList = [System.Collections.Generic.List[object]]::new()
        foreach ($svcRecord in $serviceRecords) { [void]$serviceList.Add($svcRecord) }

        $netshList = [System.Collections.Generic.List[object]]::new()
        foreach ($netRecord in $netshRecords) { [void]$netshList.Add($netRecord) }

        $hardwareList = [System.Collections.Generic.List[object]]::new()
        foreach ($hwRecord in $networkHardwareRecords) { [void]$hardwareList.Add($hwRecord) }

        $runContext = Initialize-RollbackCollections -Context $Context
        $runContext.RegistryRollbackActions = $list
        $runContext.ServiceRollbackActions = $serviceList
        $runContext.NetshRollbackActions = $netshList
        $runContext.NetworkHardwareRollbackActions = $hardwareList
        return $true
    } catch {
        Write-Warning "Failed to restore rollback actions from $targetPath: $($_.Exception.Message)"
        return $false
    }
}

# Maintains backward compatibility for callers expecting registry-only restoration.
function Restore-RegistryRollbackState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [string]$Path
    )

    return Restore-RollbackState -Context $Context -Path $Path
}

function Stop-RollbackPersistenceTimer {
    [CmdletBinding()]
    param(
        [System.Timers.Timer]$Timer,
        $Subscription,
        [string]$SourceIdentifier = 'RegistryRollbackPersistence'
    )

    if ($Timer) {
        try { $Timer.Stop() } catch {}
    }

    if ($SourceIdentifier) {
        $subscriber = Get-EventSubscriber -SourceIdentifier $SourceIdentifier -ErrorAction SilentlyContinue
        if ($subscriber) {
            Unregister-Event -SourceIdentifier $SourceIdentifier -ErrorAction SilentlyContinue
        }
    }

    if ($Subscription) {
        try { Remove-Job -Id $Subscription.Id -ErrorAction SilentlyContinue } catch {}
    }

    if ($Timer) {
        try { $Timer.Dispose() } catch {}
    }
}

function Invoke-RegistryTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [pscustomobject]$Context,
        [string]$Name
    )

    $runContext = Get-RunContext -Context $Context
    if (-not $runContext.PSObject.Properties.Name.Contains('RegistryRollbackActions')) {
        $runContext | Add-Member -Name RegistryRollbackActions -MemberType NoteProperty -Value ([System.Collections.Generic.List[object]]::new())
    }
    elseif (-not $runContext.RegistryRollbackActions) {
        $runContext.RegistryRollbackActions = [System.Collections.Generic.List[object]]::new()
    }

    $transactionLabel = if ([string]::IsNullOrWhiteSpace($Name)) { 'registry transaction' } else { $Name }
    $startIndex = $runContext.RegistryRollbackActions.Count
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $caughtError = $null
    $results = $null
    try {
        $results = & $ScriptBlock
    } catch {
        $caughtError = $_
    }

    $criticalFailure = $false
    if ($caughtError) {
        $criticalFailure = $true
    }
    elseif ($results) {
        foreach ($item in @($results)) {
            if ($item -is [psobject] -and $item.PSObject.Properties.Name -contains 'Success' -and -not [bool]$item.Success) {
                $criticalFailure = $true
                break
            }
        }
    }

    if (-not $criticalFailure) { return $results }

    $transactionRecords = @()
    $allRecords = $runContext.RegistryRollbackActions
    if ($allRecords -and $allRecords.Count -gt $startIndex) {
        $transactionRecords = @($allRecords[$startIndex..($allRecords.Count - 1)])
    }

    $messagePrefix = "[$transactionLabel]"
    $introMessage = "$messagePrefix Critical registry failure detected; initiating rollback of $($transactionRecords.Count) change(s)."
    if ($logger) { Write-Log -Message $introMessage -Level 'Warning' } else { Write-Host $introMessage -ForegroundColor Yellow }

    $resolvePath = {
        param([Parameter(Mandatory)][string]$Path)

        $normalized = $Path.Trim()
        $firstSeparator = $normalized.IndexOf('\\')
        if ($firstSeparator -lt 0) { throw [System.ArgumentException]::new("Registry path is missing a subkey: $Path") }

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

        if (-not $hiveEnum) { throw [System.ArgumentException]::new("Unsupported registry hive in path: $Path") }
        if ([string]::IsNullOrWhiteSpace($subPath)) { throw [System.ArgumentException]::new("Registry path is missing a key name: $Path") }

        $fullPath = "${hiveSegment.TrimEnd(':')}\\$subPath"
        return [pscustomobject]@{
            Hive     = $hiveEnum
            SubKey   = $subPath
            FullPath = $fullPath
        }
    }

    $toKind = {
        param([string]$TypeName)
        $parsed = $null
        if ([System.Enum]::TryParse([Microsoft.Win32.RegistryValueKind], $TypeName, $true, [ref]$parsed)) {
            return $parsed
        }
        return [Microsoft.Win32.RegistryValueKind]::String
    }

    $convertValue = {
        param(
            [Parameter(Mandatory)]$Value,
            [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Kind
        )

        switch ($Kind) {
            ([Microsoft.Win32.RegistryValueKind]::DWord) { return [int]$Value }
            ([Microsoft.Win32.RegistryValueKind]::QWord) { return [long]$Value }
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
            default { return $Value }
        }
    }

    $rollbackSucceeded = 0
    $rollbackFailed = 0

    for ($i = $transactionRecords.Count - 1; $i -ge 0; $i--) {
        $record = $transactionRecords[$i]
        $valueName = if ($record.Name -eq '(default)' -or [string]::IsNullOrWhiteSpace($record.Name)) { '' } else { $record.Name }
        $baseKey = $null
        $subKey = $null

        try {
            $target = & $resolvePath -Path $record.Path
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($target.Hive, [Microsoft.Win32.RegistryView]::Default)
            if (-not $baseKey) { throw [System.IO.IOException]::new("Unable to open base hive for $($target.FullPath)") }

            $subKey = $baseKey.OpenSubKey($target.SubKey, $true)
            if (-not $subKey -and $record.KeyExisted) {
                throw [System.IO.IOException]::new("Original registry key missing: $($target.FullPath)")
            }

            if ($record.PreviousExists) {
                $kind = & $toKind -TypeName $record.PreviousType
                $converted = & $convertValue -Value $record.PreviousValue -Kind $kind
                if (-not $subKey) {
                    $subKey = $baseKey.CreateSubKey($target.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
                }
                $subKey.SetValue($valueName, $converted, $kind)
            }
            elseif (-not $record.KeyExisted) {
                if ($subKey) {
                    $subKey.Dispose()
                    $subKey = $null
                }
                $baseKey.DeleteSubKeyTree($target.SubKey, $false)
            }
            else {
                if ($subKey) {
                    try { $subKey.DeleteValue($valueName, $false) } catch [System.ArgumentException] { }
                }
            }

            $rollbackSucceeded++
        }
        catch {
            $rollbackFailed++
            $errorMessage = "$messagePrefix Failed to rollback $($record.Path) -> $($record.Name): $($_.Exception.Message)"
            if ($logger) { Write-Log -Message $errorMessage -Level 'Error' } else { Write-Host $errorMessage -ForegroundColor Yellow }
        }
        finally {
            if ($subKey) { $subKey.Dispose() }
            if ($baseKey) { $baseKey.Dispose() }
        }
    }

    if ($allRecords -and $allRecords.Count -gt $startIndex) {
        for ($idx = $allRecords.Count - 1; $idx -ge $startIndex; $idx--) {
            $allRecords.RemoveAt($idx)
        }
    }

    $summaryMessage = "$messagePrefix Rollback completed. Success: $rollbackSucceeded / $($transactionRecords.Count). Failed: $rollbackFailed."
    if ($logger) { Write-Log -Message $summaryMessage -Level 'Info' } else { Write-Host $summaryMessage -ForegroundColor Cyan }

    if ($caughtError) { throw $caughtError }
    throw [System.InvalidOperationException]::new("One or more registry operations failed within $transactionLabel; changes were rolled back.")
}

Export-ModuleMember -Function New-RunContext, Get-RunContext, Set-NeedsReboot, Get-NeedsReboot, Reset-NeedsReboot, Set-RebootRequired, Get-RebootRequired, Invoke-Once, Get-RollbackPersistencePath, Save-RegistryRollbackState, Restore-RegistryRollbackState, Save-RollbackState, Restore-RollbackState, Invoke-RegistryTransaction, Get-NonRegistryChangeTracker, Add-NonRegistryChange, Initialize-RollbackCollections, Add-ServiceRollbackAction, Add-NetshRollbackAction, Stop-RollbackPersistenceTimer
