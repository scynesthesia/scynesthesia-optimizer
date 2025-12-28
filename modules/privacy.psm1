# Depends on: ui.psm1 (loaded by main script)
# Description: Applies privacy-focused registry changes suitable for the Safe preset.
# Parameters: Context - Optional run context for rollback tracking.
# Returns: None. Prompts for optional Cortana and Storage Sense adjustments.
function Invoke-DriverTelemetry {
    Write-Section "Disabling GPU driver telemetry services"

    $telemetryServices = @(
        'NvTelemetryContainer',
        'NvContainerLocalSystem',
        'NvContainerNetworkService',
        'AMD Crash Defender Service',
        'AMD Crash User Service',
        'AMD External Events Utility'
    )

    foreach ($service in $telemetryServices) {
        Stop-Service -Name $service -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }

    Write-Host "  [+] Driver telemetry services disabled where present." -ForegroundColor Green
}

function Invoke-PrivacyTelemetrySafe {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Section "Applying privacy/telemetry tweaks (Safe preset)"

    $cloudContentResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Consumer Experience features'
    $telemetryResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Windows telemetry (AllowTelemetry)'

    $sysPol = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $activityFeedResult = Set-RegistryValueSafe $sysPol "EnableActivityFeed" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Activity Feed'
    $publishActivitiesResult = Set-RegistryValueSafe $sysPol "PublishUserActivities" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Block publishing user activities'
    $uploadActivitiesResult = Set-RegistryValueSafe $sysPol "UploadUserActivities" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Block uploading user activities'

    $locationResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1 -Context $context -Critical -ReturnResult -OperationLabel 'Disable location services'
    $wifiOemResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Block OEM Wi-Fi auto-connect'

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable GameDVR (HKLM)' | Out-Null
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_Enabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable GameDVR (HKCU)' | Out-Null
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2 -Context $context -ReturnResult -OperationLabel 'Set GameDVR FSE behavior' | Out-Null

    if (Get-Confirmation "Disable Cortana and online searches in Start?" 'y') {
        $bingResult = Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable Bing search in Start'
        $cortanaConsentResult = Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0 -Context $context -ReturnResult -OperationLabel 'Disable Cortana consent'
        if (($bingResult -and $bingResult.Success) -and ($cortanaConsentResult -and $cortanaConsentResult.Success)) {
            Write-Host "  [+] Cortana and Bing in Start disabled"
        } else {
            Write-Host "  [!] Cortana/Bing search changes could not be fully applied." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Cortana/Bing remain unchanged."
    }

    if (Get-Confirmation "Enable Storage Sense for basic automatic cleanup?" 'n') {
        $storageSense = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense"
        $ssGlobal = Set-RegistryValueSafe $storageSense "AllowStorageSenseGlobal" 1 -Context $context -ReturnResult -OperationLabel 'Enable Storage Sense'
        $ssPolicy01 = Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "01" 1 -Context $context -ReturnResult -OperationLabel 'Configure Storage Sense (01)'
        $ssPolicy04 = Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "04" 1 -Context $context -ReturnResult -OperationLabel 'Configure Storage Sense (04)'
        if (($ssGlobal -and $ssGlobal.Success) -and ($ssPolicy01 -and $ssPolicy01.Success) -and ($ssPolicy04 -and $ssPolicy04.Success)) {
            Write-Host "  [+] Storage Sense enabled"
        } else {
            Write-Host "  [!] Storage Sense settings could not be fully applied." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Storage Sense left as-is."
    }

    if (Get-Confirmation "Hide recommendations and suggested content?" 'y') {
        $recResults = @(
            Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable system pane suggestions',
            Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable subscribed content 338387',
            Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable subscribed content 338388',
            Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable subscribed content 338389',
            Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable subscribed content 353694'
        )
        if ($recResults | Where-Object { -not $_.Success }) {
            Write-Host "  [!] Some recommendation settings could not be changed." -ForegroundColor Yellow
        } else {
            Write-Host "  [+] Recommendations disabled"
        }
    } else {
        Write-Host "  [ ] Recommendations left as-is."
    }

    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\PowerShellCore\Telemetry" "EnableTelemetry" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable PowerShell telemetry' | Out-Null
}

# Description: Configures user experience preferences for Explorer, mouse, and keyboard behavior.
# Parameters: Context - Optional run context used for rollback and permission tracking.
# Returns: None. Writes registry values for consistent UX defaults.
function Invoke-PreferencesSafe {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Section "Adjusting UX preferences (Start, Explorer, etc.)"

    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1 -Context $context -ReturnResult -OperationLabel 'Show hidden files' | Out-Null
    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 -Context $context -ReturnResult -OperationLabel 'Show file extensions' | Out-Null

    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseSpeed" 0 -Context $context -ReturnResult -OperationLabel 'Mouse speed baseline' | Out-Null
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold1" 0 -Context $context -ReturnResult -OperationLabel 'Mouse threshold 1 baseline' | Out-Null
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold2" 0 -Context $context -ReturnResult -OperationLabel 'Mouse threshold 2 baseline' | Out-Null

    Set-RegistryValueSafe "HKCU\Control Panel\Accessibility\StickyKeys" "Flags" 506 -Context $context -ReturnResult -OperationLabel 'Disable sticky keys prompts' | Out-Null

    Set-RegistryValueSafe "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "(default)" "" ([Microsoft.Win32.RegistryValueKind]::String) -Context $context -ReturnResult -OperationLabel 'Enable classic context menu' | Out-Null

    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1 -Context $context -ReturnResult -OperationLabel 'Set Explorer launch to This PC' | Out-Null

    Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" "DisplayParameters" 1 -Context $context -Critical -ReturnResult -OperationLabel 'Show crash control parameters' | Out-Null

    Set-RegistryValueSafe "HKCU\Control Panel\Keyboard" "InitialKeyboardIndicators" 2147483650 -Context $context -ReturnResult -OperationLabel 'Enable num lock at startup' | Out-Null
}

Export-ModuleMember -Function Invoke-DriverTelemetry, Invoke-PrivacyTelemetrySafe, Invoke-PreferencesSafe
