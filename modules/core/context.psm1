# Description: Provides a per-run context object and helpers to track execution state.

$script:NeedsRebootFallback = $false

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

# Marks that a reboot is required. Mirrors to context when provided, otherwise uses module-scoped fallback.
# Parameters: Context - Optional run context to update.
function Set-RebootRequired {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    if ($Context) {
        $Context.NeedsReboot = $true
        return $Context
    }

    $script:NeedsRebootFallback = $true
    return $true
}

# Retrieves the reboot-required flag from context or the module-scoped fallback when no context is supplied.
# Parameters: Context - Optional run context to inspect.
function Get-RebootRequired {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    if ($Context) {
        if (-not $Context.NeedsReboot -and $script:NeedsRebootFallback) {
            $Context.NeedsReboot = $true
        }

        return $Context.NeedsReboot
    }

    return [bool]$script:NeedsRebootFallback
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
    $script:NeedsRebootFallback = $false
    return $Context
}

Export-ModuleMember -Function New-RunContext, Get-RunContext, Set-NeedsReboot, Get-NeedsReboot, Reset-NeedsReboot, Set-RebootRequired, Get-RebootRequired
