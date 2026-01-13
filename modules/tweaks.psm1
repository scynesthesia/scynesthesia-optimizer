
function Set-ClassicContextMenus {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        Set-RegistryValueSafe -Path $path -Name '(default)' -Value '' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context
        Write-Host "[OK] Classic context menu enabled." -ForegroundColor Green
        Set-RebootRequired -Context $Context | Out-Null
    } catch {
        Invoke-ErrorHandler -Context "Enabling classic context menus" -ErrorRecord $_
    }
}

function Add-TakeOwnershipMenu {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $entries = @(
        @{ Path = 'HKCR:\*\shell\TakeOwnership'; Command = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant *S-1-5-32-544:F' },
        @{ Path = 'HKCR:\Directory\shell\TakeOwnership'; Command = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant *S-1-5-32-544:F /t' }
    )

    if (-not (Test-Path HKCR:)) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }

    foreach ($entry in $entries) {
        $commandPath = "$($entry.Path)\\command"
        $entrySucceeded = $true
        try {
            Set-RegistryValueSafe -Path $entry.Path -Name 'MUIVerb' -Value 'Take Ownership' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context
            Set-RegistryValueSafe -Path $entry.Path -Name 'HasLUAShield' -Value '' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context
            Set-RegistryValueSafe -Path $entry.Path -Name 'Icon' -Value 'imageres.dll,-78' -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context

            if (-not (Test-Path -LiteralPath $commandPath)) {
                New-Item -Path $commandPath -Force | Out-Null
            }
            Set-RegistryValueSafe -Path $commandPath -Name '(default)' -Value $entry.Command -Type ([Microsoft.Win32.RegistryValueKind]::String) -Context $Context
        } catch {
            $entrySucceeded = $false
            Invoke-ErrorHandler -Context "Configuring Take Ownership context menu at $($entry.Path)" -ErrorRecord $_
        }

        if ($entrySucceeded) {
            Write-Host "[OK] Take Ownership menu added for files and folders." -ForegroundColor Green
        }
    }
    Set-RebootRequired -Context $Context | Out-Null
}

function Set-ExplorerProSettings {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    try {
        Set-RegistryValueSafe -Path $path -Name 'HideFileExt' -Value 0 -Context $Context
        Set-RegistryValueSafe -Path $path -Name 'Hidden' -Value 1 -Context $Context
        Write-Host "[OK] Explorer visibility tweaks applied." -ForegroundColor Green
        Set-RebootRequired -Context $Context | Out-Null
    } catch {
        Invoke-ErrorHandler -Context "Configuring Explorer visibility preferences" -ErrorRecord $_
    }
}

Export-ModuleMember -Function Set-ClassicContextMenus, Add-TakeOwnershipMenu, Set-ExplorerProSettings
