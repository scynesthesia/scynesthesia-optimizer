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

# Persists the registry rollback actions from the context to disk so they can be restored after crashes.
function Save-RegistryRollbackState {
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

    $records = @()
    if ($Context.PSObject.Properties.Name -contains 'RegistryRollbackActions' -and $Context.RegistryRollbackActions) {
        $records = @($Context.RegistryRollbackActions)
    }

    $payload = [pscustomobject]@{
        LastUpdated = (Get-Date).ToString('o')
        Records     = $records
    }

    try {
        $json = $payload | ConvertTo-Json -Depth 8 -ErrorAction Stop
        Set-Content -Path $targetPath -Value $json -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "Failed to persist rollback actions to $targetPath: $($_.Exception.Message)"
    }

    return $targetPath
}

# Restores registry rollback actions from disk into the supplied context.
function Restore-RegistryRollbackState {
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
        $records = @()
        if ($data -and $data.PSObject.Properties.Name -contains 'Records' -and $data.Records) {
            $records = @($data.Records)
        }

        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($record in $records) {
            [void]$list.Add($record)
        }

        $Context.RegistryRollbackActions = $list
        return $true
    } catch {
        Write-Warning "Failed to restore rollback actions from $targetPath: $($_.Exception.Message)"
        return $false
    }
}

Export-ModuleMember -Function New-RunContext, Get-RunContext, Set-NeedsReboot, Get-NeedsReboot, Reset-NeedsReboot, Set-RebootRequired, Get-RebootRequired, Invoke-Once, Get-RollbackPersistencePath, Save-RegistryRollbackState, Restore-RegistryRollbackState
