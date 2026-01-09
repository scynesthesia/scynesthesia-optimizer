# Depends on: ui.psm1 (loaded by main script)
# Description: Applies privacy-focused registry changes suitable for the Safe preset.
# Parameters: Context - Optional run context for rollback tracking; PresetName - Label for the active preset.
# Returns: Boolean indicating whether the caller should abort the preset after a critical failure prompt.
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
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $context = Get-RunContext -Context $Context
    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    Write-Section "Applying privacy/telemetry tweaks (Safe preset)"

    $cloudContentResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Consumer Experience features'
    $telemetryResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Windows telemetry (AllowTelemetry)'

    $sysPol = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    $activityFeedResult = Set-RegistryValueSafe $sysPol "EnableActivityFeed" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable Activity Feed'
    $publishActivitiesResult = Set-RegistryValueSafe $sysPol "PublishUserActivities" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Block publishing user activities'
    $uploadActivitiesResult = Set-RegistryValueSafe $sysPol "UploadUserActivities" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Block uploading user activities'

    $locationResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1 -Context $context -Critical -ReturnResult -OperationLabel 'Disable location services'
    $wifiOemResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Block OEM Wi-Fi auto-connect'

    $gameDvrPolicy = Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable GameDVR (HKLM)'
    $gameDvrEnabled = Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_Enabled" 0 -Context $context -ReturnResult -OperationLabel 'Disable GameDVR (HKCU)'
    $gameDvrFse = Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2 -Context $context -ReturnResult -OperationLabel 'Set GameDVR FSE behavior'

    $criticalResults = @(
        @{ Result = $cloudContentResult; Label = 'Disable Consumer Experience features' },
        @{ Result = $telemetryResult; Label = 'Disable Windows telemetry (AllowTelemetry)' },
        @{ Result = $activityFeedResult; Label = 'Disable Activity Feed' },
        @{ Result = $publishActivitiesResult; Label = 'Block publishing user activities' },
        @{ Result = $uploadActivitiesResult; Label = 'Block uploading user activities' },
        @{ Result = $locationResult; Label = 'Disable location services' },
        @{ Result = $wifiOemResult; Label = 'Block OEM Wi-Fi auto-connect' },
        @{ Result = $gameDvrPolicy; Label = 'Disable GameDVR (HKLM)' }
    )
    foreach ($entry in $criticalResults) {
        if (-not ($entry.Result -and $entry.Result.Success)) {
            Register-HighImpactRegistryFailure -Context $context -Result $entry.Result -OperationLabel $entry.Label | Out-Null
            if (Test-RegistryResultForPresetAbort -Result $entry.Result -PresetName $presetLabel -OperationLabel $entry.Label -Critical) { return $true }
        }
    }

    if (-not ($gameDvrEnabled -and $gameDvrEnabled.Success)) {
        Write-Host "  [!] GameDVR (HKCU) setting could not be updated." -ForegroundColor Yellow
    }
    if (-not ($gameDvrFse -and $gameDvrFse.Success)) {
        Write-Host "  [!] GameDVR full screen optimization behavior could not be updated." -ForegroundColor Yellow
    }

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
        if ($recResults | Where-Object { -not ($_ -and $_.Success) }) {
            Write-Host "  [!] Some recommendation settings could not be changed." -ForegroundColor Yellow
        } else {
            Write-Host "  [+] Recommendations disabled"
        }
    } else {
        Write-Host "  [ ] Recommendations left as-is."
    }

    $powerShellTelemetryResult = Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\PowerShellCore\Telemetry" "EnableTelemetry" 0 -Context $context -Critical -ReturnResult -OperationLabel 'Disable PowerShell telemetry'
    if (-not ($powerShellTelemetryResult -and $powerShellTelemetryResult.Success)) {
        Register-HighImpactRegistryFailure -Context $context -Result $powerShellTelemetryResult -OperationLabel 'Disable PowerShell telemetry' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $powerShellTelemetryResult -PresetName $presetLabel -OperationLabel 'Disable PowerShell telemetry' -Critical) { return $true }
    }

    return $false
}

# Description: Applies baseline privacy tweaks (Safe layer) for telemetry and advertising controls.
# Parameters: Context - Optional run context for rollback tracking.
# Returns: Boolean indicating whether the caller should abort the preset after a critical failure prompt.
function Invoke-PrivacySafe {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Section "Privacy hardening (Safe layer)"

    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling telemetry (AllowTelemetry)" -ErrorRecord $_
    }

    try {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling advertising ID" -ErrorRecord $_
    }

    try {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\InputPersonalization" "RestrictedImplicitTextCollection" 1 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Restricting handwriting and speech collection" -ErrorRecord $_
    }

    try {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling feedback frequency prompts" -ErrorRecord $_
    }

    return $false
}

# Description: Extends privacy tweaks with app permission and Edge hardening (Aggressive layer).
# Parameters: Context - Optional run context for rollback tracking.
# Returns: Boolean indicating whether the caller should abort the preset after a critical failure prompt.
function Invoke-PrivacyAggressive {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Section "Privacy hardening (Aggressive layer)"

    $abort = Invoke-PrivacySafe -Context $context
    if ($abort) { return $true }

    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" "AllowPrelaunch" 0 -Context $context -Critical
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" "AllowTabPreloading" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling Edge prelaunch and tab preloading" -ErrorRecord $_
    }

    $riskSummary = @(
        "Disables global camera access for all apps.",
        "Disables global microphone access for all apps."
    )
    if (Get-Confirmation -Question "Disable global camera/microphone access for apps?" -Default 'n' -RiskSummary $riskSummary) {
        try {
            Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" 0 -Context $context -Critical
            Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" 0 -Context $context -Critical
        } catch {
            Invoke-ErrorHandler -Context "Disabling global app camera/microphone access" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] App camera/microphone access left unchanged." -ForegroundColor DarkGray
    }

    return $false
}

# Description: Applies additional privacy tweaks for activity history and background sync (Gaming layer).
# Parameters: Context - Optional run context for rollback tracking.
# Returns: Boolean indicating whether the caller should abort the preset after a critical failure prompt.
function Invoke-PrivacyGaming {
    param(
        [pscustomobject]$Context
    )

    $context = Get-RunContext -Context $Context
    Write-Section "Privacy hardening (Gaming layer)"

    $abort = Invoke-PrivacyAggressive -Context $context
    if ($abort) { return $true }

    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling activity history feed" -ErrorRecord $_
    }

    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling clipboard sync history" -ErrorRecord $_
    }

    try {
        Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 -Context $context -Critical
    } catch {
        Invoke-ErrorHandler -Context "Disabling Cortana search" -ErrorRecord $_
    }

    return $false
}

# Description: Configures user experience preferences for Explorer, mouse, and keyboard behavior.
# Parameters: Context - Optional run context used for rollback and permission tracking; PresetName - Label for the active preset.
# Returns: Boolean indicating whether the caller should abort the preset after a critical failure prompt.
function Invoke-PreferencesSafe {
    param(
        [pscustomobject]$Context,
        [string]$PresetName = 'current preset'
    )

    $context = Get-RunContext -Context $Context
    $presetLabel = if (-not [string]::IsNullOrWhiteSpace($PresetName)) { $PresetName } else { 'current preset' }
    Write-Section "Adjusting UX preferences (Start, Explorer, etc.)"

    $hiddenResult = Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1 -Context $context -ReturnResult -OperationLabel 'Show hidden files'
    $hideExtResult = Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 -Context $context -ReturnResult -OperationLabel 'Show file extensions'

    $mouseSpeedResult = Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseSpeed" 0 -Context $context -ReturnResult -OperationLabel 'Mouse speed baseline'
    $mouseThreshold1Result = Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold1" 0 -Context $context -ReturnResult -OperationLabel 'Mouse threshold 1 baseline'
    $mouseThreshold2Result = Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold2" 0 -Context $context -ReturnResult -OperationLabel 'Mouse threshold 2 baseline'

    $stickyKeysResult = Set-RegistryValueSafe "HKCU\Control Panel\Accessibility\StickyKeys" "Flags" 506 -Context $context -ReturnResult -OperationLabel 'Disable sticky keys prompts'

    $classicContextResult = Set-RegistryValueSafe "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "(default)" "" ([Microsoft.Win32.RegistryValueKind]::String) -Context $context -ReturnResult -OperationLabel 'Enable classic context menu'

    $launchToResult = Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1 -Context $context -ReturnResult -OperationLabel 'Set Explorer launch to This PC'

    $crashControlResult = Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" "DisplayParameters" 1 -Context $context -Critical -ReturnResult -OperationLabel 'Show crash control parameters'

    $numLockResult = Set-RegistryValueSafe "HKCU\Control Panel\Keyboard" "InitialKeyboardIndicators" 2147483650 -Context $context -ReturnResult -OperationLabel 'Enable num lock at startup'

    $results = @(
        @{ Result = $hiddenResult; Label = 'Show hidden files' },
        @{ Result = $hideExtResult; Label = 'Show file extensions' },
        @{ Result = $mouseSpeedResult; Label = 'Mouse speed baseline' },
        @{ Result = $mouseThreshold1Result; Label = 'Mouse threshold 1 baseline' },
        @{ Result = $mouseThreshold2Result; Label = 'Mouse threshold 2 baseline' },
        @{ Result = $stickyKeysResult; Label = 'Disable sticky keys prompts' },
        @{ Result = $classicContextResult; Label = 'Enable classic context menu' },
        @{ Result = $launchToResult; Label = 'Set Explorer launch to This PC' },
        @{ Result = $numLockResult; Label = 'Enable num lock at startup' }
    )
    foreach ($entry in $results) {
        if (-not ($entry.Result -and $entry.Result.Success)) {
            Write-Host "  [!] $($entry.Label) could not be fully applied." -ForegroundColor Yellow
        }
    }

    if (-not ($crashControlResult -and $crashControlResult.Success)) {
        Register-HighImpactRegistryFailure -Context $context -Result $crashControlResult -OperationLabel 'Show crash control parameters' | Out-Null
        if (Test-RegistryResultForPresetAbort -Result $crashControlResult -PresetName $presetLabel -OperationLabel 'Show crash control parameters' -Critical) { return $true }
    }

    return $false
}

Export-ModuleMember -Function Invoke-DriverTelemetry, Invoke-PrivacyTelemetrySafe, Invoke-PrivacySafe, Invoke-PrivacyAggressive, Invoke-PrivacyGaming, Invoke-PreferencesSafe
