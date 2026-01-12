$script:AppRemovalConfig = $null
$script:AppRemovalConfigPath = $null

function Get-ScriptRoot {
    param(
        [pscustomobject]$Context,
        [string]$LocalRoot
    )

    $preferredRoot = if ($Context -and $Context.ScriptRoot) {
        $Context.ScriptRoot
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

function Get-AppRemovalList {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Debloat','Aggressive')]
        [string] $Mode,
        [pscustomobject]$Context,
        [string] $ConfigPath,
        [string] $Key
    )

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $configRoot = Get-ScriptRoot -Context $Context -LocalRoot $PSScriptRoot
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
