# Depends on: ui.psm1 (loaded by main script)
# Description: Applies privacy-focused registry changes suitable for the Safe preset.
# Parameters: None.
# Returns: None. Prompts for optional Cortana and Storage Sense adjustments.
function Apply-PrivacyTelemetrySafe {
    Write-Section "Applying privacy/telemetry tweaks (Safe preset)"

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

    $sysPol = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-RegistryValueSafe $sysPol "EnableActivityFeed" 0
    Set-RegistryValueSafe $sysPol "PublishUserActivities" 0
    Set-RegistryValueSafe $sysPol "UploadUserActivities" 0

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_Enabled" 0
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2

    if (Ask-YesNo "Disable Cortana and online searches in Start?" 'y') {
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
        Write-Host "  [+] Cortana and Bing in Start disabled"
    } else {
        Write-Host "  [ ] Cortana/Bing remain unchanged."
    }

    if (Ask-YesNo "Enable Storage Sense for basic automatic cleanup?" 'n') {
        $storageSense = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense"
        Set-RegistryValueSafe $storageSense "AllowStorageSenseGlobal" 1
        Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "01" 1
        Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "04" 1
        Write-Host "  [+] Storage Sense enabled"
    } else {
        Write-Host "  [ ] Storage Sense left as-is."
    }

    if (Ask-YesNo "Hide recommendations and suggested content?" 'y') {
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0
        Write-Host "  [+] Recommendations disabled"
    } else {
        Write-Host "  [ ] Recommendations left as-is."
    }

    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\PowerShellCore\Telemetry" "EnableTelemetry" 0
}

# Description: Configures user experience preferences for Explorer, mouse, and keyboard behavior.
# Parameters: None.
# Returns: None. Writes registry values for consistent UX defaults.
function Apply-PreferencesSafe {
    Write-Section "Adjusting UX preferences (Start, Explorer, etc.)"

    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0

    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseSpeed" 0
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold1" 0
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold2" 0

    Set-RegistryValueSafe "HKCU\Control Panel\Accessibility\StickyKeys" "Flags" 506

    Set-RegistryValueSafe "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "" "" ([Microsoft.Win32.RegistryValueKind]::String)

    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

    Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" "DisplayParameters" 1

    Set-RegistryValueSafe "HKCU\Control Panel\Keyboard" "InitialKeyboardIndicators" 2147483650
}

Export-ModuleMember -Function Apply-PrivacyTelemetrySafe, Apply-PreferencesSafe
