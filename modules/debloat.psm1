if (-not (Get-Module -Name 'config' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/config.psm1') -Force -Scope Local -DisableNameChecking -WarningAction SilentlyContinue
}

function Initialize-DebloatRemovalLog {
    param([pscustomobject]$Context)

    if (-not $Context) { return $null }

    if (-not $Context.PSObject.Properties.Name.Contains('DebloatRemovalLog')) {
        $Context | Add-Member -Name DebloatRemovalLog -MemberType NoteProperty -Value ([System.Collections.Generic.List[string]]::new())
    } elseif (-not $Context.DebloatRemovalLog) {
        $Context.DebloatRemovalLog = [System.Collections.Generic.List[string]]::new()
    }

    return $Context.DebloatRemovalLog
}

function Add-DebloatRemovalLogEntry {
    param(
        [pscustomobject]$Context,
        [string[]]$PackageNames
    )

    $log = Initialize-DebloatRemovalLog -Context $Context
    if (-not $log) { return }

    foreach ($pkg in ($PackageNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if (-not $log.Contains($pkg)) {
            $log.Add($pkg) | Out-Null
        }
    }
}

function Get-XboxRelatedPackages {
    param([System.Collections.IEnumerable]$Packages)

    $patterns = @('^Microsoft\.Xbox', '^Microsoft\.GamingApp', '^Microsoft\.GamePass')
    $matches = @()

    foreach ($pkg in ($Packages | Where-Object { $_ })) {
        $name = if ($pkg.PSObject.Properties.Name -contains 'Name') { [string]$pkg.Name } else { [string]$pkg }

        foreach ($pattern in $patterns) {
            if ($name -match $pattern) {
                $matches += $pkg
                break
            }
        }
    }

    return @($matches)
}

function Confirm-XboxAppRemoval {
    param(
        [System.Collections.IEnumerable]$Targets,
        [pscustomobject]$Context
    )

    $targetsArray = @($Targets | Where-Object { $_ })
    $xboxTargets = @(Get-XboxRelatedPackages -Packages $targetsArray)

    $result = [pscustomobject]@{
        Targets   = $targetsArray
        Prompted  = $false
        Consent   = $true
        XboxNames = @()
    }

    if (-not $xboxTargets) { return $result }

    $xboxNames = @($xboxTargets | ForEach-Object { $_.Name } | Where-Object { $_ } | Select-Object -Unique)
    $result.Prompted = $true
    $result.XboxNames = $xboxNames

    $question = "Xbox/Game Pass apps detected ($($xboxNames -join ', ')). Remove them? This may impact Xbox services and Game Pass."
    $consent = Get-Confirmation -Question $question -Default 'n' -RiskSummary @("Removing these apps can break Xbox/Game Pass features for this PC.")
    $result.Consent = $consent

    if ($consent) {
        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
            Add-SessionSummaryItem -Context $Context -Bucket 'Applied' -Message "User approved removal of Xbox/Game Pass apps: $($xboxNames -join ', ')."
        }
        return $result
    }

    if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
        Add-SessionSummaryItem -Context $Context -Bucket 'DeclinedHighImpact' -Message "User declined removal of Xbox/Game Pass apps: $($xboxNames -join ', ')."
    }
    Write-Host "  [ ] Keeping Xbox/Game Pass apps by user choice." -ForegroundColor DarkGray
    $result.Targets = @($targetsArray | Where-Object { $xboxNames -notcontains $_.Name })
    return $result
}

function Get-InstalledAppxPackages {
    return Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
}

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

function New-RestorePointSafe {
    Write-Section "Creating restore point"

    $status = [pscustomobject]@{
        Enabled = $true
        Created = $false
    }

    try {
        $restoreEnabled = $true
        $disableReasons = @()
        $driveRestoreEnabled = $true

        $srserviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\srservice"
        $driveConfigPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\Cfg\C:"

        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"
        $configPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"

        if (Test-Path $srserviceRegPath) {
            $srserviceProps = Get-ItemProperty -Path $srserviceRegPath -ErrorAction SilentlyContinue
            if ($srserviceProps.Start -eq 4) {
                Write-Warning "System Restore service is disabled in the registry. Attempting to enable it."
                try {
                    Set-ItemProperty -Path $srserviceRegPath -Name Start -Value 3 -ErrorAction Stop
                    $srserviceService = Get-Service -Name 'srservice' -ErrorAction SilentlyContinue
                    if ($srserviceService) {
                        Set-Service -Name 'srservice' -StartupType Manual -ErrorAction SilentlyContinue
                    }
                    Write-Host "  [OK] System Restore service set to Manual startup." -ForegroundColor Gray
                } catch {
                    Invoke-ErrorHandler -Context "Enabling System Restore service startup" -ErrorRecord $_
                }
            }
        }

        if (Test-Path $driveConfigPath) {
            $driveConfig = Get-ItemProperty -Path $driveConfigPath -ErrorAction SilentlyContinue
            if ($driveConfig.DisableSR -eq 1) {
                $driveRestoreEnabled = $false
                $disableReasons += "Drive C: DisableSR"
            }
        } else {
            $driveRestoreEnabled = $false
            $disableReasons += "Drive C: config missing"
        }

        if (Test-Path $policyPath) {
            $policyProps = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
            if ($policyProps.DisableSR -eq 1) {
                $restoreEnabled = $false
                $disableReasons += "Policy DisableSR"
            }
            if ($policyProps.DisableConfig -eq 1) {
                $restoreEnabled = $false
                $disableReasons += "Policy DisableConfig"
            }
        }

        if (Test-Path $configPath) {
            $configProps = Get-ItemProperty -Path $configPath -ErrorAction SilentlyContinue
            if ($configProps.DisableSR -eq 1) {
                $restoreEnabled = $false
                $disableReasons += "Local DisableSR"
            }
        }

        if (-not $restoreEnabled -or -not $driveRestoreEnabled) {
            $reasonText = if ($disableReasons) { " ($($disableReasons -join ', '))" } else { "" }
            Write-Warning "System Restore appears to be disabled$reasonText."
            Write-Host "  [i] Attempting to enable System Restore on C: automatically." -ForegroundColor Gray
            try {
                Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
                Set-Service -Name srservice -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name srservice -ErrorAction SilentlyContinue
                Write-Host "  [OK] System Restore enabled on C:." -ForegroundColor Gray
            } catch {
                Invoke-ErrorHandler -Context "Enabling System Restore on C:" -ErrorRecord $_
            }

            $srserviceService = Get-Service -Name 'srservice' -ErrorAction SilentlyContinue
            if ($srserviceService -and $srserviceService.Status -ne 'Running') {
                try {
                    Start-Service -Name 'srservice' -ErrorAction Stop
                    $srserviceService = Get-Service -Name 'srservice' -ErrorAction SilentlyContinue
                    Write-Host "  [OK] System Restore service started." -ForegroundColor Gray
                } catch {
                    Invoke-ErrorHandler -Context "Starting System Restore service" -ErrorRecord $_
                }
            }

            $restoreEnabled = $true
            $driveRestoreEnabled = $true
            if (Test-Path $driveConfigPath) {
                $driveConfig = Get-ItemProperty -Path $driveConfigPath -ErrorAction SilentlyContinue
                if ($driveConfig.DisableSR -eq 1) {
                    $driveRestoreEnabled = $false
                }
            } else {
                $driveRestoreEnabled = $false
            }

            if (Test-Path $policyPath) {
                $policyProps = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
                if ($policyProps.DisableSR -eq 1) {
                    $restoreEnabled = $false
                }
                if ($policyProps.DisableConfig -eq 1) {
                    $restoreEnabled = $false
                }
            }

            if (Test-Path $configPath) {
                $configProps = Get-ItemProperty -Path $configPath -ErrorAction SilentlyContinue
                if ($configProps.DisableSR -eq 1) {
                    $restoreEnabled = $false
                }
            }

            if (-not $srserviceService -or $srserviceService.Status -ne 'Running') {
                $restoreEnabled = $false
            }
        }

        if (-not $restoreEnabled -or -not $driveRestoreEnabled) {
            $status.Enabled = $false
            return $status
        }

        try {
            $requiredServices = @('VSS', 'swprv', 'srservice')
            $disabledServices = @()
            foreach ($svc in $requiredServices) {
                $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($service -and $service.StartType -eq 'Disabled') {
                    $disabledServices += $service.Name
                }
            }

            if ($disabledServices.Count -gt 0) {
                Write-Warning "System Restore dependencies are disabled: $($disabledServices -join ', '). Restore point skipped."
                $status.Enabled = $false
                return $status
            }

            Checkpoint-Computer -Description "Scynesthesia Windows Optimizer v1.0" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Host "  [OK] Restore point created." -ForegroundColor Green
            $status.Created = $true
        } catch {
            $status.Created = $false
            $status.Enabled = $false
            Write-Warning "Restore point creation failed. System Restore may be disabled."
            Invoke-ErrorHandler -Context "Creating restore point" -ErrorRecord $_
        }
    } catch {
        Invoke-ErrorHandler -Context "Creating restore point" -ErrorRecord $_
    }

    return $status
}

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

        Write-Host "  [OK] Cleaning $p"
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
        Write-Host "  [OK] Cleaning Windows Update cache"
        try {
            Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Invoke-ErrorHandler -Context "Cleaning Windows Update cache" -ErrorRecord $_
        }
    }
}

function Clear-DeepTempAndThumbs {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context

    Write-Section "Extra cleanup (temp + thumbnails)"
    Clear-TempFiles -Context $context

    $thumbDir = "${env:LOCALAPPDATA}\Microsoft\Windows\Explorer"
    if (Test-Path $thumbDir) {
        Write-Host "  [OK] Removing thumbnail cache"
        try {
            Get-ChildItem $thumbDir -Filter "thumbcache_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Invoke-ErrorHandler -Context "Clearing thumbnail cache" -ErrorRecord $_
        }
    }
}

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

    $targetNames = @()
    $targets = @(Get-InstalledAppxPackages | Where-Object {
            $match = $AppList -contains $_.Name
            if ($match) { $targetNames += $_.Name }
            $match
        })

    $confirmation = Confirm-XboxAppRemoval -Targets $targets -Context $context
    $targets = @($confirmation.Targets)
    $targetNames = $targets.Name
    $effectiveAppList = if ($confirmation -and -not $confirmation.Consent -and $confirmation.XboxNames) {
        $AppList | Where-Object { $confirmation.XboxNames -notcontains $_ }
    } else {
        $AppList
    }
    $failed = @()
    $removed = @()
    $targetNames = $targets.Name

    foreach ($name in $targetNames) {
        Write-Host "  [OK] Removing $name"
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
            $removed += $successful
        }

        $failed = $failedNames
    }

    $failedUnique = $failed | Select-Object -Unique
    $removedUnique = $removed | Select-Object -Unique

    if ($removedUnique) {
        Add-DebloatRemovalLogEntry -Context $context -PackageNames $removedUnique
    }

    [pscustomobject]@{
        Failed  = $failedUnique
        Removed = $removedUnique
    }
}

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

    $targetNames = @()
    $targets = @(Get-InstalledAppxPackages | Where-Object {
            $match = $AppList -contains $_.Name
            if ($match) { $targetNames += $_.Name }
            $match
        })

    $confirmation = Confirm-XboxAppRemoval -Targets $targets -Context $context
    $targets = @($confirmation.Targets)
    $targetNames = $targets.Name
    $effectiveAppList = if ($confirmation -and -not $confirmation.Consent -and $confirmation.XboxNames) {
        $AppList | Where-Object { $confirmation.XboxNames -notcontains $_ }
    } else {
        $AppList
    }
    $failed = @()
    $removed = @()
    $targetNames = $targets.Name

    foreach ($name in $targetNames) {
        Write-Host "  [OK] Removing $name"
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
            $removed += $successful
        }

        $failed = $failedNames
    }

    if (Get-Confirmation -Question "Also remove provisioned packages for future users? (More aggressive)" -Default 'n' -RiskSummary @("Removing provisioned packages affects all future user accounts created on this PC")) {
        try {
            $prov = Get-AppxProvisionedPackage -Online | Where-Object { $effectiveAppList -contains $_.PackageName }
        } catch {
            $warningMessage = "[Debloat] Failed to enumerate provisioned packages: $($_.Exception.Message). Skipping provisioned removal."
            Write-Host $warningMessage -ForegroundColor Yellow
            Write-Log -Message $warningMessage -Level 'Warning'
            $prov = @()
        }
        $provisionedTargets = @($prov)
        $provisionedNames = $provisionedTargets.PackageName

        if ($provisionedNames) {
            Write-Host "  [OK] Removing provisioned packages: $($provisionedNames -join ', ')"

            $provRemoveErrors = @()
            $uncapturedProvFailure = $false

            try {
                $provisionedTargets | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue -ErrorVariable provRemoveErrors | Out-Null
            } catch {
                $uncapturedProvFailure = $true
                $provRemoveErrors += $_
            }

            foreach ($err in $provRemoveErrors) {
                $failedName = if ($err.TargetObject -and $err.TargetObject.PackageName) { $err.TargetObject.PackageName } elseif ($err.TargetObject) { $err.TargetObject } else { $null }
                if ($failedName) {
                    $failed += $failedName
                } else {
                    $uncapturedProvFailure = $true
                }
                $displayName = if ($failedName) { $failedName } else { 'Unknown package' }
                Write-Host "  [SKIPPED] $displayName" -ForegroundColor DarkGray
                Write-Log -Message "Skipped protected app: $displayName" -Level 'Info'
            }

            if ($uncapturedProvFailure -and -not ($failed | Where-Object { $provisionedNames -contains $_ })) {
                $failed += $provisionedNames
            }

            $provFailedNames = $failed | Where-Object { $provisionedNames -contains $_ } | Select-Object -Unique
            $provSuccessful = $provisionedNames | Where-Object { $provFailedNames -notcontains $_ }

            if ($provSuccessful) {
                $removed += $provSuccessful
            }
        }
    }

    $failedUnique = $failed | Select-Object -Unique
    $removedUnique = $removed | Select-Object -Unique

    if ($removedUnique) {
        Add-DebloatRemovalLogEntry -Context $context -PackageNames $removedUnique
    }

    [pscustomobject]@{
        Failed  = $failedUnique
        Removed = $removedUnique
    }
}

Export-ModuleMember -Function Get-InstalledAppxPackages, New-RestorePointSafe, Clear-TempFiles, Clear-DeepTempAndThumbs, Invoke-DebloatSafe, Invoke-DebloatAggressive
