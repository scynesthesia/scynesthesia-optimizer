$script:AppRemovalConfig = $null

function Get-AppRemovalList {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Key,
        [string] $Path = "$PSScriptRoot\..\config\apps.json"
    )

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $configPath = $Path

    if (-not (Test-Path $configPath)) {
        $message = "[Debloat] No se encontro el archivo de configuracion de apps: $configPath. Saltando la fase de App Removal."
        Write-Host $message -ForegroundColor Yellow
        if ($logger) { Write-Log $message }
        return @()
    }

    if (-not $script:AppRemovalConfig -or $script:AppRemovalConfigPath -ne (Resolve-Path $configPath).Path) {
        try {
            $script:AppRemovalConfig = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $script:AppRemovalConfigPath = (Resolve-Path $configPath).Path
        } catch {
            $errorMessage = "[Debloat] Error al analizar el archivo de configuracion de apps ($configPath): $($_.Exception.Message)"
            Write-Host $errorMessage -ForegroundColor Red
            if ($logger) { Write-Log $errorMessage }
            return @()
        }
    }

    $list = $script:AppRemovalConfig.$Key
    if (-not $list) {
        return @()
    }

    return [string[]]$list
}

function Create-RestorePointSafe {
    Write-Section "Creating restore point"
    try {
        Checkpoint-Computer -Description "Scynesthesia Windows Optimizer v1.0" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "  [+] Restore point created."
    } catch {
        Handle-Error -Context "Creating restore point" -ErrorRecord $_
    }
}

function Clear-TempFiles {
    Write-Section "Clearing basic temporary files"
    $paths = @(
        "${env:TEMP}",
        "${env:WINDIR}\Temp"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Host "  [+] Cleaning $p"
            try {
                Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            } catch {
                Handle-Error -Context "Cleaning path $p" -ErrorRecord $_
            }
        }
    }

    $wu = "${env:WINDIR}\SoftwareDistribution\Download"
    if (Test-Path $wu) {
        Write-Host "  [+] Cleaning Windows Update cache"
        try {
            Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Handle-Error -Context "Cleaning Windows Update cache" -ErrorRecord $_
        }
    }
}

function Clear-DeepTempAndThumbs {
    Write-Section "Extra cleanup (temp + thumbnails)"
    Clear-TempFiles

    $thumbDir = "${env:LOCALAPPDATA}\Microsoft\Windows\Explorer"
    if (Test-Path $thumbDir) {
        Write-Host "  [+] Removing thumbnail cache"
        try {
            Get-ChildItem $thumbDir -Filter "thumbcache_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Handle-Error -Context "Clearing thumbnail cache" -ErrorRecord $_
        }
    }
}

function Apply-DebloatSafe {
    param(
        [string[]] $AppList
    )

    if (-not $PSBoundParameters.ContainsKey('AppList') -or -not $AppList) {
        $AppList = Get-AppRemovalList -Key "SafeRemove"
    }

    Write-Section "Safe debloat (removes common bloatware, keeps Store and essentials)"

    $failed = @()
    foreach ($a in $AppList) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  [+] Removing $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $failed += $a
                Write-Host "  [SKIPPED] $a" -ForegroundColor DarkGray
                Write-Log -Message "Skipped protected app: $a" -Level 'Info'
            }
        } else {
            Write-Host "  [ ] $a is not installed."
        }
    }

    [pscustomobject]@{
        Failed = $failed
    }
}

function Apply-DebloatAggressive {
    param(
        [string[]] $AppList
    )

    if (-not $PSBoundParameters.ContainsKey('AppList') -or -not $AppList) {
        $AppList = Get-AppRemovalList -Key "AggressiveRemove"
    }

    Write-Section "Aggressive debloat (includes optional removal of provisioned packages)"

    $failed = @()
    foreach ($a in $AppList) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  [+] Removing $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $failed += $a
                Write-Host "  [SKIPPED] $a" -ForegroundColor DarkGray
                Write-Log -Message "Skipped protected app: $a" -Level 'Info'
            }
        } else {
            Write-Host "  [ ] $a is not installed."
        }
    }

    if (Ask-YesNo -Question "Also remove provisioned packages for future users? (More aggressive) [y/N]" -Default 'n') {
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

    [pscustomobject]@{
        Failed = $failed
    }
}

Export-ModuleMember -Function Create-RestorePointSafe, Clear-TempFiles, Clear-DeepTempAndThumbs, Apply-DebloatSafe, Apply-DebloatAggressive
