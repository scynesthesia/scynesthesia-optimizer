# Depends on: ui.psm1 (loaded by main script)

function Test-WingetAvailable {
    try {
        $command = Get-Command -Name 'winget' -ErrorAction SilentlyContinue

        if (-not $command) {
            return $false
        }

        if ($command.CommandType -eq 'Application' -and (Test-Path -LiteralPath $command.Source)) {
            return $true
        }

        if ($command.CommandType -eq 'Alias' -and -not [string]::IsNullOrWhiteSpace($command.Definition)) {
            return (Test-Path -LiteralPath $command.Definition)
        }

        $appCommand = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue
        if ($appCommand -and (Test-Path -LiteralPath $appCommand.Source)) {
            return $true
        }

        return $false
    } catch {
        return $false
    }
}

function Invoke-SoftwareInstaller {
    Write-Section "Software Installer"

    if (-not (Test-WingetAvailable)) {
        Write-Host "[X] Winget (App Installer) is not available. Please install it from the Microsoft Store: https://aka.ms/GetTheAppInstaller" -ForegroundColor Red
        return
    }

    $apps = @(
        @{ Name = 'Microsoft Visual C++ Runtimes (x64)'; Id = 'Microsoft.VCRedist.2015+.x64'; Category = 'Runtimes'; Default = 'y' },
        @{ Name = 'Brave Browser'; Id = 'Brave.Brave'; Category = 'Browsers'; Default = 'n' },
        @{ Name = 'Steam (Valve)'; Id = 'Valve.Steam'; Category = 'Gaming'; Default = 'n' },
        @{ Name = 'Discord'; Id = 'Discord.Discord'; Category = 'Social'; Default = 'n' }
    )

    $currentCategory = ''
    foreach ($app in $apps) {
        if ($currentCategory -ne $app.Category) {
            $currentCategory = $app.Category
            Write-Host "" 
            Write-Host "== $($app.Category) ==" -ForegroundColor Cyan
        }

        $question = "Install $($app.Name)?"
        if (Get-Confirmation -Question $question -Default $app.Default) {
            Write-Host "  [>] Installing $($app.Name)..." -ForegroundColor Gray
            try {
                $wingetArgs = @(
                    'install', '--id', $app.Id,
                    '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'
                )

                $process = Start-Process -FilePath 'winget' -ArgumentList $wingetArgs -Wait -NoNewWindow -PassThru -ErrorAction Stop

                switch ($process.ExitCode) {
                    0 {
                        Write-Host "  [+] $($app.Name) installed." -ForegroundColor Green
                    }
                    0x8A150029 {
                        Write-Host "  [ ] $($app.Name) already installed." -ForegroundColor DarkGray
                    }
                    default {
                        $message = "  [X] $($app.Name) could not be installed (exit code $($process.ExitCode))."
                        Write-Host $message -ForegroundColor Yellow
                        Write-Log -Message "Winget install for $($app.Id) exited with code $($process.ExitCode)." -Level 'Warning'
                    }
                }
            } catch {
                Invoke-ErrorHandler -Context "Installing $($app.Name) via winget" -ErrorRecord $_
            }
        } else {
            Write-Host "  [ ] Skipped $($app.Name)." -ForegroundColor DarkGray
        }
    }
}

function Set-WindowsUpdateNotifyOnly {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $name = "AUOptions"
    $value = 2

    Write-Host "[i] Setting Windows Update to Notify for download and auto install." -ForegroundColor Gray
    Set-RegistryValueSafe -Path $path -Name $name -Value $value -Type ([Microsoft.Win32.RegistryValueKind]::DWord)

    $Global:NeedsReboot = $true
    Write-Host "[+] Windows Update set to Notify Only. A reboot is recommended." -ForegroundColor Yellow
}

function Invoke-WindowsUpdateScan {
    Write-Host "[i] Triggering Windows Update scan..." -ForegroundColor Gray

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[X] Administrative privileges are required to start the scan." -ForegroundColor Yellow
        return
    }

    try {
        Start-Process -FilePath "usoclient" -ArgumentList "StartInteractiveScan" -WindowStyle Hidden -ErrorAction Stop | Out-Null
        Write-Host "[+] Scan started in the background." -ForegroundColor Green
    } catch {
        Invoke-ErrorHandler -Context "Starting Windows Update interactive scan" -ErrorRecord $_
    }
}

Export-ModuleMember -Function Test-WingetAvailable, Invoke-SoftwareInstaller, Set-WindowsUpdateNotifyOnly, Invoke-WindowsUpdateScan
