if (-not (Get-Module -Name 'config' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'core/config.psm1') -Force -Scope Local -DisableNameChecking -WarningAction SilentlyContinue
}
if (-not (Get-Module -Name 'debloat' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'debloat.psm1') -Force -Scope Global -DisableNameChecking -WarningAction SilentlyContinue
}

function Get-AppRemovalListFromConfig {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Key,
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    return (config\Get-AppRemovalList -Mode 'Aggressive' -Key $Key -Context $context)
}

function Invoke-AggressiveTweaks {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile,
        [Parameter(Mandatory)]
        [ref]$FailedPackages,
        $OemServices,
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $context = Get-RunContext -Context $Context
    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    Write-Section "Additional tweaks for slow PCs (more aggressive)"
    $appxCommand = Get-Command -Name 'Get-InstalledAppxPackages' -ErrorAction SilentlyContinue
    if ($appxCommand) {
        $appxPackages = @(& $appxCommand)
    } else {
        $appxPackages = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
        Write-Warning "Get-InstalledAppxPackages not available; falling back to Get-AppxPackage."
    }

    $hibernationWarning = "WARNING: Disabling hibernation on laptops will disable Fast Startup and may prevent the system from saving state if the battery dies."
    $hibernationPrompt = if ($HardwareProfile.IsLaptop) {
        "$hibernationWarning`nDisable hibernation on this laptop to free disk space and speed up boot?"
    } else {
        "$hibernationWarning`nDisable hibernation to free disk space and speed up boot?"
    }

    if (Get-Confirmation $hibernationPrompt 'y') {
        Write-Host "  [OK] Disabling hibernation"
        try {
            powercfg -h off
            if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                Add-SessionSummaryItem -Context $context -Bucket 'Applied' -Message 'Hibernation disabled'
            }
        } catch {
            Invoke-ErrorHandler -Context "Disabling hibernation" -ErrorRecord $_
        }
    } else {
        $message = if ($HardwareProfile.IsLaptop) {
            "  [ ] Laptop detected: hibernation left enabled unless you confirm otherwise."
        } else {
            "  [ ] Hibernation left unchanged."
        }
        Write-Host $message -ForegroundColor Yellow
        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
            Add-SessionSummaryItem -Context $context -Bucket 'DeclinedHighImpact' -Message 'Hibernation disable prompt declined'
        }
    }

    Write-Host "  [OK] Blocking background apps"
    $backgroundAppsResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 -Context $context -Critical -ReturnResult -OperationLabel 'Block background apps'
    if (-not ($backgroundAppsResult -and $backgroundAppsResult.Success)) {
        Register-HighImpactRegistryFailure -Context $context -Result $backgroundAppsResult -OperationLabel 'Block background apps' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $backgroundAppsResult -PresetName $presetLabel -OperationLabel 'Block background apps' -Critical) { return $true }
    }

    Write-Host "  [OK] Additional debloat for slow PCs"
    $extra = Get-AppRemovalListFromConfig -Key "AggressiveTweaksRemove" -Context $context
    foreach ($a in $extra) {
        $pkg = $appxPackages | Where-Object { $_.Name -eq $a }
        if ($pkg) {
            Write-Host "    [OK] Removing $a"
            try {
                $pkg | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $FailedPackages.Value += $a
                Write-Host "    [SKIPPED] $a" -ForegroundColor DarkGray
                Write-Log -Message "Skipped protected app: $a" -Level 'Info'
            }
        }
    }

    if ($OemServices -and $OemServices.Count -gt 0) {
        Write-Host "  [!] OEM services detected: $($OemServices.DisplayName -join ', ')" -ForegroundColor Yellow
        Write-Host "      Skipping OEM services to avoid breaking vendor tools."
    }

    if (-not $OemServices -or $OemServices.Count -eq 0) {
        if (Get-Confirmation "Disable Print Spooler if you do not use printers?" 'n') {
            try {
                try {
                    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "Failed to stop Print Spooler service: $($_.Exception.Message)"
                }
                Set-Service -Name "Spooler" -StartupType Disabled
                Write-Host "  [OK] Print Spooler disabled"
                if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                    Add-SessionSummaryItem -Context $context -Bucket 'Applied' -Message 'Print Spooler disabled'
                }
            } catch {
                Invoke-ErrorHandler -Context "Disabling Print Spooler service" -ErrorRecord $_
            }
        } else {
            if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
                Add-SessionSummaryItem -Context $context -Bucket 'DeclinedHighImpact' -Message 'Print Spooler disable prompt declined'
            }
        }
    } else {
        Write-Host "  [ ] Spooler left untouched because OEM services are present."
        if (Get-Command -Name Add-SessionSummaryItem -ErrorAction SilentlyContinue) {
            Add-SessionSummaryItem -Context $context -Bucket 'GuardedBlocks' -Message 'Print Spooler protected due to OEM services detected'
        }
    }

    if (Get-Confirmation "Block OneDrive from starting automatically?" 'y') {
        try {
            Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskPath "\\Microsoft\\OneDrive\\" -TaskName "OneDrive Standalone Update Task-S-1-5-21" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [OK] OneDrive will not auto-start"
        } catch {
            Invoke-ErrorHandler -Context "Blocking OneDrive auto-start" -ErrorRecord $_
        }
    }

    if (Get-Confirmation "Disable Consumer Experience tasks (suggested content)?" 'y') {
        $tasks = @(
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
            "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
        )
        $system32Path = if ($env:SystemRoot) { Join-Path $env:SystemRoot "System32" } else { "C:\\Windows\\System32" }
        Push-Location -Path $system32Path
        try {
            foreach ($t in $tasks) {
                try {
                    $taskName = Split-Path $t -Leaf
                    $taskPath = (Split-Path $t -Parent) -replace '^\\\\', '\'
                    if (-not $taskPath.EndsWith("\")) {
                        $taskPath += "\"
                    }

                    $scheduledTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                    if ($scheduledTask) {
                        $scheduledTask | Disable-ScheduledTask -ErrorAction Stop | Out-Null
                        Write-Host "  [OK] Task $t disabled"
                    }
                } catch {
                    Invoke-ErrorHandler -Context "Disabling scheduled task $t" -ErrorRecord $_
                }
            }
        } finally {
            Pop-Location -ErrorAction SilentlyContinue
        }
    }

    if (Get-Confirmation "Do you use Copilot? If not, uninstall it?" 'n') {
        $copilotPkgs = $appxPackages | Where-Object { $_.Name -like 'Microsoft.Copilot' -or $_.Name -like '*Copilot*' }

        if ($copilotPkgs.Count -gt 0) {
            foreach ($pkg in $copilotPkgs | Select-Object -Unique) {
                Write-Host "  [OK] Removing $($pkg.Name)"
                try {
                    $pkg | Remove-AppxPackage -ErrorAction SilentlyContinue
                } catch {
                    $FailedPackages.Value += $pkg.Name
                    Write-Host "  [SKIPPED] $($pkg.Name)" -ForegroundColor DarkGray
                    Write-Log -Message "Skipped protected app: $($pkg.Name)" -Level 'Info'
                }
            }
        }
    } else {
        Write-Host "  [ ] Copilot stays installed."
    }

    if (Get-Confirmation "Disable auto-start for Microsoft Teams (personal)?" 'y') {
        try {
            Stop-Process -Name "Teams" -Force -ErrorAction SilentlyContinue
        } catch { }

        try {
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
            Write-Host "  [OK] Auto-start for Teams (personal) disabled"
        } catch {
            Invoke-ErrorHandler -Context "Disabling Teams auto-start" -ErrorRecord $_
        }
    }

    Clear-DeepTempAndThumbs -Context $context

    Write-Host ""
    if (Get-Confirmation "Remove OneDrive from this system?" 'n') {
        Write-Host "  [OK] Attempting to uninstall OneDrive"
        try {
            Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
            $pathSys = "${env:SystemRoot}\System32\OneDriveSetup.exe"
            $pathWow = "${env:SystemRoot}\SysWOW64\OneDriveSetup.exe"
            if (Test-Path $pathWow) {
                & $pathWow /uninstall
            } elseif (Test-Path $pathSys) {
                & $pathSys /uninstall
            }
        } catch {
            Invoke-ErrorHandler -Context "Uninstalling OneDrive" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] OneDrive stays installed."
    }

    return $false
}

Export-ModuleMember -Function Invoke-AggressiveTweaks
