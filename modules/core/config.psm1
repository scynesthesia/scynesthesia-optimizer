# Description: Shared configuration helpers for resolving script roots and loading app removal lists.
$script:AppRemovalConfig = $null
$script:AppRemovalConfigPath = $null

# Description: Resolves the script root using the orchestrator's global setting when available,
# falling back to the caller's PSScriptRoot or the invocation path when imported standalone.
# Parameters: LocalRoot - Optional fallback path (defaults to the caller's PSScriptRoot if present).
# Returns: Resolved script root path.
function Get-ScriptRoot {
    param([string]$LocalRoot)

    $preferredRoot = if ($Global:ScriptRoot) {
        $Global:ScriptRoot
    } elseif ($LocalRoot) {
        $LocalRoot
    } elseif ($PSScriptRoot) {
        $PSScriptRoot
    } else {
        Split-Path -Parent $MyInvocation.MyCommand.Definition
    }

    if (-not $preferredRoot) {
        return (Get-Location).Path
    }

    try {
        return (Resolve-Path $preferredRoot -ErrorAction Stop).Path
    } catch {
        return $preferredRoot
    }
}

# Description: Retrieves a normalized list of applications to remove for a given mode.
# Parameters: Mode - Debloat or Aggressive profile; ConfigPath - Optional apps.json path override; Key - Optional config key override.
# Returns: Array of app identifiers; empty array when the configuration cannot be loaded.
function Get-AppRemovalList {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Debloat','Aggressive')]
        [string] $Mode,
        [string] $ConfigPath,
        [string] $Key
    )

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $configRoot = Get-ScriptRoot -LocalRoot $PSScriptRoot
    $resolvedPath = if ($ConfigPath) { $ConfigPath } else { Join-Path $configRoot 'config/apps.json' }

    if (-not (Test-Path $resolvedPath)) {
        $message = "[Config] App configuration file not found: $resolvedPath. Skipping app removal stage."
        Write-Host $message -ForegroundColor Yellow
        if ($logger) { Write-Log $message }
        return @()
    }

    $normalizedPath = try { (Resolve-Path $resolvedPath -ErrorAction Stop).Path } catch { $resolvedPath }

    if (-not $script:AppRemovalConfig -or $script:AppRemovalConfigPath -ne $normalizedPath) {
        try {
            $script:AppRemovalConfig = Get-Content $normalizedPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $script:AppRemovalConfigPath = $normalizedPath
        } catch {
            $errorMessage = "[Config] Failed to parse app configuration file ($normalizedPath): $($_.Exception.Message)"
            Write-Host $errorMessage -ForegroundColor Red
            if ($logger) { Write-Log $errorMessage }
            return @()
        }
    }

    $keyName = if ($Key) {
        $Key
    } elseif ($Mode -eq 'Aggressive') {
        'AggressiveRemove'
    } else {
        'SafeRemove'
    }

    $list = $script:AppRemovalConfig.$keyName
    if (-not $list) {
        return @()
    }

    return [string[]]$list
}

Export-ModuleMember -Function Get-ScriptRoot, Get-AppRemovalList
