# Depends on: ui.psm1 (loaded by main script)
if (-not (Get-Module -Name 'config' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/config.psm1') -Force -Scope Local
}

$script:AppxPackageCache = $null

function Get-InstalledAppxPackages {
    if ($null -eq $script:AppxPackageCache) {
        $script:AppxPackageCache = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
    }

    return $script:AppxPackageCache
}

# Description: Retrieves an app removal list from the configuration JSON using the specified key.
# Parameters: Key - Config property to read; Path - Optional path to the apps configuration file; Context - Optional run context with ScriptRoot.
# Returns: Array of app package names; empty array when config missing or invalid.
function Get-AppRemovalList {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Key,
        [string] $Path,
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    return (config\Get-AppRemovalList -Mode 'Debloat' -ConfigPath $Path -Key $Key -Context $context)
}

# Description: Creates a system restore point for rollback safety.
# Parameters: None.
# Returns: None.
function New-RestorePointSafe {
    Write-Section "Creating restore point"
    try {
        Checkpoint-Computer -Description "Scynesthesia Windows Optimizer v1.0" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "  [+] Restore point created."
    } catch {
        Invoke-ErrorHandler -Context "Creating restore point" -ErrorRecord $_
    }
}

# Description: Clears common temporary directories and Windows Update cache.
# Parameters: Context - Optional run context to align cleanup with ScriptRoot.
# Returns: None.
function Clear-TempFiles {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context

    Write-Section "Clearing basic temporary files"
    $paths = @(
        "${env:TEMP}",
        "${env:WINDIR}\Temp"
    )

    # Avoid deleting the currently running payload (downloaded into %TEMP% by setup.ps1).
    $protectedRoots = @()
    if ($context -and $context.ScriptRoot) {
        try {
            $resolvedRoot = (Resolve-Path $context.ScriptRoot -ErrorAction Stop).Path
            $protectedRoots += $resolvedRoot
        } catch {
            $protectedRoots += $context.ScriptRoot
        }
    }

    $installerTemp = Join-Path $env:TEMP 'ScynesthesiaTemp'
    if (Test-Path $installerTemp) {
        $protectedRoots += (Resolve-Path $installerTemp -ErrorAction SilentlyContinue).Path
    }

    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }

        Write-Host "  [+] Cleaning $p"
        try {
            $items = Get-ChildItem $p -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $full = $item.FullName
                $skip = $false

                foreach ($root in $protectedRoots) {
                    if ($root -and ($full -like "$root*")) {
                        $skip = $true
                        break
                    }
                }

                if ($skip) {
                    Write-Host "  [ ] Skipping $full (used by optimizer)" -ForegroundColor DarkGray
                    continue
                }

                Remove-Item $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
            }
        } catch {
            Invoke-ErrorHandler -Context "Cleaning path $p" -ErrorRecord $_
        }
    }

    $wu = "${env:WINDIR}\SoftwareDistribution\Download"
    if (Test-Path $wu) {
        Write-Host "  [+] Cleaning Windows Update cache"
        try {
            Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Invoke-ErrorHandler -Context "Cleaning Windows Update cache" -ErrorRecord $_
        }
    }
}

# Description: Performs deeper cleanup including thumbnail cache removal.
# Parameters: Context - Optional run context to align cleanup with ScriptRoot.
# Returns: None.
function Clear-DeepTempAndThumbs {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context

    Write-Section "Extra cleanup (temp + thumbnails)"
    Clear-TempFiles -Context $context

    $thumbDir = "${env:LOCALAPPDATA}\Microsoft\Windows\Explorer"
    if (Test-Path $thumbDir) {
        Write-Host "  [+] Removing thumbnail cache"
        try {
            Get-ChildItem $thumbDir -Filter "thumbcache_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Invoke-ErrorHandler -Context "Clearing thumbnail cache" -ErrorRecord $_
        }
    }
}

# Description: Removes common bloatware while preserving core Windows Store functionality.
# Parameters: AppList - Optional list of packages to remove instead of default SafeRemove list; Context - Optional run context with ScriptRoot.
# Returns: PSCustomObject containing any failed package removals.
function Invoke-DebloatSafe {
    param(
        [string[]] $AppList,
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context

    if (-not $PSBoundParameters.ContainsKey('AppList') -or -not $AppList) {
        $AppList = Get-AppRemovalList -Key "SafeRemove" -Context $context
    }

    Write-Section "Safe debloat (removes common bloatware, keeps Store and essentials)"

    $installedPackages = Get-InstalledAppxPackages
    $targets = $installedPackages | Where-Object { $AppList -contains $_.Name }
    $missing = $AppList | Where-Object { -not ($installedPackages.Name -contains $_) }

    foreach ($name in $missing) {
        Write-Host "  [ ] $name is not installed."
    }

    $failed = @()
    $targetNames = $targets.Name

    foreach ($name in $targetNames) {
        Write-Host "  [+] Removing $name"
    }

    if ($targets) {
        $removeErrors = @()
        $targets | Remove-AppxPackage -ErrorAction SilentlyContinue -ErrorVariable removeErrors

        $uncapturedFailure = $false
        foreach ($err in $removeErrors) {
            $failedName = if ($err.TargetObject -and $err.TargetObject.Name) { $err.TargetObject.Name } elseif ($err.TargetObject) { $err.TargetObject } else { $null }
            if ($failedName) {
                $failed += $failedName
            } else {
                $uncapturedFailure = $true
            }
            $displayName = if ($failedName) { $failedName } else { 'Unknown package' }
            Write-Host "  [SKIPPED] $displayName" -ForegroundColor DarkGray
            Write-Log -Message "Skipped protected app: $displayName" -Level 'Info'
        }

        if ($uncapturedFailure -and -not $failed) {
            $failed += $targetNames
        }

        $failedNames = $failed | Select-Object -Unique
        $successful = $targetNames | Where-Object { $failedNames -notcontains $_ }

        if ($successful) {
            $script:AppxPackageCache = $script:AppxPackageCache | Where-Object { $successful -notcontains $_.Name }
        }

        $failed = $failedNames
    }

    $failedUnique = $failed | Select-Object -Unique

    [pscustomobject]@{
        Failed = $failedUnique
    }
}

# Description: Removes a broader set of apps and optionally provisioned packages.
# Parameters: AppList - Optional list of packages to remove instead of default AggressiveRemove list; Context - Optional run context with ScriptRoot.
# Returns: PSCustomObject containing any failed package removals.
function Invoke-DebloatAggressive {
    param(
        [string[]] $AppList,
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context

    if (-not $PSBoundParameters.ContainsKey('AppList') -or -not $AppList) {
        $AppList = Get-AppRemovalList -Key "AggressiveRemove" -Context $context
    }

    Write-Section "Aggressive debloat (includes optional removal of provisioned packages)"

    $installedPackages = Get-InstalledAppxPackages
    $targets = $installedPackages | Where-Object { $AppList -contains $_.Name }
    $missing = $AppList | Where-Object { -not ($installedPackages.Name -contains $_) }

    foreach ($name in $missing) {
        Write-Host "  [ ] $name is not installed."
    }

    $failed = @()
    $targetNames = $targets.Name

    foreach ($name in $targetNames) {
        Write-Host "  [+] Removing $name"
    }

    if ($targets) {
        $removeErrors = @()
        $targets | Remove-AppxPackage -ErrorAction SilentlyContinue -ErrorVariable removeErrors

        $uncapturedFailure = $false
        foreach ($err in $removeErrors) {
            $failedName = if ($err.TargetObject -and $err.TargetObject.Name) { $err.TargetObject.Name } elseif ($err.TargetObject) { $err.TargetObject } else { $null }
            if ($failedName) {
                $failed += $failedName
            } else {
                $uncapturedFailure = $true
            }
            $displayName = if ($failedName) { $failedName } else { 'Unknown package' }
            Write-Host "  [SKIPPED] $displayName" -ForegroundColor DarkGray
            Write-Log -Message "Skipped protected app: $displayName" -Level 'Info'
        }

        if ($uncapturedFailure -and -not $failed) {
            $failed += $targetNames
        }

        $failedNames = $failed | Select-Object -Unique
        $successful = $targetNames | Where-Object { $failedNames -notcontains $_ }

        if ($successful) {
            $script:AppxPackageCache = $script:AppxPackageCache | Where-Object { $successful -notcontains $_.Name }
        }

        $failed = $failedNames
    }

    if (Get-Confirmation -Question "Also remove provisioned packages for future users? (More aggressive)" -Default 'n') {
        try {
            $prov = Get-AppxProvisionedPackage -Online | Where-Object { $AppList -contains $_.PackageName }
        } catch {
            $warningMessage = "[Debloat] Failed to enumerate provisioned packages: $($_.Exception.Message). Skipping provisioned removal."
            Write-Host $warningMessage -ForegroundColor Yellow
            Write-Log -Message $warningMessage -Level 'Warning'
            $prov = @()
        }
        foreach ($p in $prov) {
            Write-Host "  [+] Removing provisioned package $($p.PackageName)"
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName | Out-Null
            } catch {
                $failed += $p.PackageName
                Write-Host "  [SKIPPED] $($p.PackageName)" -ForegroundColor DarkGray
                Write-Log -Message "Skipped protected app: $($p.PackageName)" -Level 'Info'
            }
        }
    }

    $failedUnique = $failed | Select-Object -Unique

    [pscustomobject]@{
        Failed = $failedUnique
    }
}

Export-ModuleMember -Function New-RestorePointSafe, Clear-TempFiles, Clear-DeepTempAndThumbs, Invoke-DebloatSafe, Invoke-DebloatAggressive
