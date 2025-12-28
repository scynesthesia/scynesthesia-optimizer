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
        LogPath         = $null
    }
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

# Marks the supplied context as requiring a reboot.
# Parameters: Context - The run context to update.
function Set-NeedsReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $Context.NeedsReboot = $true
    return $Context
}

# Retrieves the reboot flag from the supplied context.
# Parameters: Context - The run context to inspect.
function Get-NeedsReboot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    return $Context.NeedsReboot
}

Export-ModuleMember -Function New-RunContext, Get-RunContext, Set-NeedsReboot, Get-NeedsReboot
