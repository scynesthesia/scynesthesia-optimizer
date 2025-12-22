# Depends on: ui.psm1 (loaded by main script)

function Test-WingetAvailable {
    try {
        $command = Get-Command winget -ErrorAction SilentlyContinue
        return [bool]$command
    } catch {
        return $false
    }
}

function Invoke-SoftwareInstaller {
    Write-Section "Software Installer / Instalador de Software"

    if (-not (Test-WingetAvailable)) {
        Write-Host "[X] Winget (App Installer) is not available. Please install it from the Microsoft Store: https://aka.ms/GetTheAppInstaller" -ForegroundColor Red
        Write-Host "[X] Winget (App Installer) no está disponible. Instálalo desde Microsoft Store: https://aka.ms/GetTheAppInstaller" -ForegroundColor Red
        return
    }

    $apps = @(
        @{ Name = 'Microsoft Visual C++ Runtimes (x64)'; Id = 'Microsoft.VCRedist.2015+.x64'; Category = 'Runtimes / Runtimes'; Default = 'y' },
        @{ Name = 'Brave Browser'; Id = 'Brave.Brave'; Category = 'Browsers / Navegadores'; Default = 'n' },
        @{ Name = 'Steam (Valve)'; Id = 'Valve.Steam'; Category = 'Gaming / Juegos'; Default = 'n' },
        @{ Name = 'Discord'; Id = 'Discord.Discord'; Category = 'Social / Social'; Default = 'n' }
    )

    $currentCategory = ''
    foreach ($app in $apps) {
        if ($currentCategory -ne $app.Category) {
            $currentCategory = $app.Category
            Write-Host "" 
            Write-Host "== $($app.Category) ==" -ForegroundColor Cyan
        }

        $question = "Install $($app.Name)? / ¿Instalar $($app.Name)?"
        if (Ask-YesNo -Question $question -Default $app.Default) {
            Write-Host "  [>] Installing $($app.Name)... / Instalando $($app.Name)..." -ForegroundColor Gray
            try {
                winget install --id $($app.Id) --silent --accept-package-agreements --accept-source-agreements | Out-Null
                Write-Host "  [+] $($app.Name) installed. / $($app.Name) instalado." -ForegroundColor Green
            } catch {
                Handle-Error -Context "Installing $($app.Name) via winget" -ErrorRecord $_
            }
        } else {
            Write-Host "  [ ] Skipped $($app.Name). / Omitido $($app.Name)." -ForegroundColor DarkGray
        }
    }
}

function Set-WindowsUpdateNotifyOnly {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $name = "AUOptions"
    $value = 2

    Write-Host "[i] Setting Windows Update to Notify for download and auto install. / Configurando Windows Update en Notificar para descargar e instalar automaticamente." -ForegroundColor Gray
    Set-RegistryValueSafe -Path $path -Name $name -Value $value -Type ([Microsoft.Win32.RegistryValueKind]::DWord)

    $Global:NeedsReboot = $true
    Write-Host "[+] Windows Update set to Notify Only. A reboot is recommended. / Windows Update configurado en Solo Notificar. Se recomienda reiniciar." -ForegroundColor Yellow
}

function Invoke-WindowsUpdateScan {
    Write-Host "[i] Triggering Windows Update scan... / Iniciando escaneo de Windows Update..." -ForegroundColor Gray
    try {
        Start-Process -FilePath "usoclient" -ArgumentList "StartInteractiveScan" -WindowStyle Hidden -ErrorAction Stop | Out-Null
        Write-Host "[+] Scan started in the background. / Escaneo iniciado en segundo plano." -ForegroundColor Green
    } catch {
        Handle-Error -Context "Starting Windows Update interactive scan" -ErrorRecord $_
    }
}

Export-ModuleMember -Function Test-WingetAvailable, Invoke-SoftwareInstaller, Set-WindowsUpdateNotifyOnly, Invoke-WindowsUpdateScan
