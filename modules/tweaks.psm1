# Depends on: ui.psm1 (loaded by main script)

# Description: Forces classic Windows 10-style context menus on Windows 11 by clearing the shell handler value.
# Parameters: None.
# Returns: None. Sets global reboot flag.
function Set-ClassicContextMenus {
    $path = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        Set-RegistryValueSafe -Path $path -Name '(default)' -Value '' -Type ([Microsoft.Win32.RegistryValueKind]::String)
        Write-Host "[+] Classic context menu enabled." -ForegroundColor Green
        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context "Enabling classic context menus" -ErrorRecord $_
    }
}

# Description: Adds Take Ownership context menu entries for files and directories using takeown and icacls.
# Parameters: None.
# Returns: None. Sets global reboot flag.
function Add-TakeOwnershipMenu {
    $entries = @(
        @{ Path = 'HKCR:\*\shell\TakeOwnership'; Command = 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F' },
        @{ Path = 'HKCR:\Directory\shell\TakeOwnership'; Command = 'cmd.exe /c takeown /f "%1" /r /d y && icacls "%1" /grant administrators:F /t' }
    )

    foreach ($entry in $entries) {
        $commandPath = Join-Path -Path $entry.Path -ChildPath 'command' -ErrorAction SilentlyContinue
        try {
            Set-RegistryValueSafe -Path $entry.Path -Name 'MUIVerb' -Value 'Take Ownership' -Type ([Microsoft.Win32.RegistryValueKind]::String)
            Set-RegistryValueSafe -Path $entry.Path -Name 'HasLUAShield' -Value '' -Type ([Microsoft.Win32.RegistryValueKind]::String)
            Set-RegistryValueSafe -Path $entry.Path -Name 'Icon' -Value 'imageres.dll,-78' -Type ([Microsoft.Win32.RegistryValueKind]::String)

            if ([string]::IsNullOrWhiteSpace($commandPath)) {
                Write-Log -Message "Skipping Take Ownership command registration because the command path could not be resolved for $($entry.Path)." -Level 'Warning'
                continue
            }

            if (-not (Test-Path $commandPath)) {
                New-Item -Path $commandPath -Force | Out-Null
            }
            Set-RegistryValueSafe -Path $commandPath -Name '(default)' -Value $entry.Command -Type ([Microsoft.Win32.RegistryValueKind]::String)
        } catch {
            Invoke-ErrorHandler -Context "Configuring Take Ownership context menu at $($entry.Path)" -ErrorRecord $_
        }
    }

    Write-Host "[+] Take Ownership menu added for files and folders." -ForegroundColor Green
    $Global:NeedsReboot = $true
}

# Description: Enables advanced Explorer visibility settings for file extensions and hidden items.
# Parameters: None.
# Returns: None. Sets global reboot flag.
function Set-ExplorerProSettings {
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    try {
        Set-RegistryValueSafe -Path $path -Name 'HideFileExt' -Value 0
        Set-RegistryValueSafe -Path $path -Name 'Hidden' -Value 1
        Write-Host "[+] Explorer visibility tweaks applied." -ForegroundColor Green
        $Global:NeedsReboot = $true
    } catch {
        Invoke-ErrorHandler -Context "Configuring Explorer visibility preferences" -ErrorRecord $_
    }
}

Export-ModuleMember -Function Set-ClassicContextMenus, Add-TakeOwnershipMenu, Set-ExplorerProSettings
