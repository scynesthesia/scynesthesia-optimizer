$script:AppRemovalConfig = $null

function Get-AppRemovalListFromConfig {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Key
    )

    if (-not $script:AppRemovalConfig) {
        $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
        $configPath = Join-Path (Split-Path $PSScriptRoot -Parent) "config/apps.json"
        if (-not (Test-Path $configPath)) {
            $message = "[Debloat] No se encontro el archivo de configuracion de apps: $configPath. Saltando la fase de App Removal."
            Write-Host $message -ForegroundColor Yellow
            if ($logger) { Write-Log $message }
            return @()
        }

        try {
            $script:AppRemovalConfig = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "Failed to load app removal configuration from ${configPath}: $_"
        }
    }

    $list = $script:AppRemovalConfig.$Key
    if (-not $list) {
        return @()
    }

    return [string[]]$list
}

function Apply-AggressiveTweaks {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile,
        [Parameter(Mandatory)]
        [ref]$FailedPackages,
        $OemServices
    )

    Write-Section "Additional tweaks for slow PCs (more aggressive)"

    if ($HardwareProfile.IsLaptop) {
        Write-Host "  [ ] Laptop detected: hibernation kept to avoid breaking sleep." -ForegroundColor Yellow
    } elseif (Ask-YesNo "Disable hibernation to free disk space and speed up boot?" 'y') {
        Write-Host "  [+] Disabling hibernation"
        try {
            powercfg -h off
        } catch {
            Handle-Error -Context "Disabling hibernation" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] Hibernation left unchanged."
    }

    Write-Host "  [+] Blocking background apps"
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2

    Write-Host "  [+] Additional debloat for slow PCs"
    $extra = Get-AppRemovalListFromConfig -Key "AggressiveTweaksRemove"
    foreach ($a in $extra) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "    [+] Removing $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
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
        if (Ask-YesNo "Disable Print Spooler if you do not use printers?" 'n') {
            try {
                try {
                    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "Failed to stop Print Spooler service: $($_.Exception.Message)"
                }
                Set-Service -Name "Spooler" -StartupType Disabled
                Write-Host "  [+] Print Spooler disabled"
            } catch {
                Handle-Error -Context "Disabling Print Spooler service" -ErrorRecord $_
            }
        }
    } else {
        Write-Host "  [ ] Spooler left untouched because OEM services are present."
    }

    if (Ask-YesNo "Block OneDrive from starting automatically?" 'y') {
        try {
            taskkill /F /IM OneDrive.exe -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskPath "\\Microsoft\\OneDrive\\" -TaskName "OneDrive Standalone Update Task-S-1-5-21" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [+] OneDrive will not auto-start"
        } catch {
            Handle-Error -Context "Blocking OneDrive auto-start" -ErrorRecord $_
        }
    }

    if (Ask-YesNo "Disable Consumer Experience tasks (suggested content)?" 'y') {
        $tasks = @(
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
            "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
        )
        foreach ($t in $tasks) {
            try {
                schtasks /Change /TN $t /Disable | Out-Null
                Write-Host "  [+] Task $t disabled"
            } catch {
                Handle-Error -Context "Disabling scheduled task $t" -ErrorRecord $_
            }
        }
    }

    if (Ask-YesNo "Do you use Copilot? If not, uninstall it?" 'n') {
        $copilotPkgs = @()
        $copilotPkgs += Get-AppxPackage -AllUsers -Name "Microsoft.Copilot" -ErrorAction SilentlyContinue
        $copilotPkgs += Get-AppxPackage -AllUsers -Name "*Copilot*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Copilot*' }

        if ($copilotPkgs.Count -eq 0) {
            Write-Host "  [ ] Copilot is not installed."
        } else {
            foreach ($pkg in $copilotPkgs | Select-Object -Unique) {
                Write-Host "  [+] Removing $($pkg.Name)"
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

    if (Ask-YesNo "Disable auto-start for Microsoft Teams (personal)?" 'y') {
        try {
            taskkill /F /IM Teams.exe -ErrorAction SilentlyContinue
        } catch { }

        try {
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
            Write-Host "  [+] Auto-start for Teams (personal) disabled"
        } catch {
            Handle-Error -Context "Disabling Teams auto-start" -ErrorRecord $_
        }
    }

    Clear-DeepTempAndThumbs

    Write-Host ""
    if (Ask-YesNo "Remove OneDrive from this system?" 'n') {
        Write-Host "  [+] Attempting to uninstall OneDrive"
        try {
            taskkill /F /IM OneDrive.exe -ErrorAction SilentlyContinue
            $pathSys = "${env:SystemRoot}\System32\OneDriveSetup.exe"
            $pathWow = "${env:SystemRoot}\SysWOW64\OneDriveSetup.exe"
            if (Test-Path $pathWow) {
                & $pathWow /uninstall
            } elseif (Test-Path $pathSys) {
                & $pathSys /uninstall
            }
        } catch {
            Handle-Error -Context "Uninstalling OneDrive" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] OneDrive stays installed."
    }
}

Export-ModuleMember -Function Apply-AggressiveTweaks
