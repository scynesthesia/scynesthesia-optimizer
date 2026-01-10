# Depends on: ui.psm1 (loaded by main script)
# Description: Disables selected hardware devices per tier using native PnP cmdlets.
# Parameters: Level - Safe, Aggressive, or Gaming tier; Context - Run context for rollback tracking.
# Returns: PSCustomObject summary of devices touched.
function Invoke-HardwareDeviceHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,
        [ValidateSet('Safe','Aggressive','Gaming')]
        [string]$Level = 'Safe'
    )

    $tierOrder = @('Safe','Aggressive','Gaming')
    $tierIndex = [array]::IndexOf($tierOrder, $Level)
    $tiersToApply = $tierOrder[0..$tierIndex]

    $safeDevices = @(
        'Microsoft GS Wavetable Synth',
        'Microsoft RRAS Root Enumerator'
    )

    $aggressiveDevices = @(
        'High Precision Event Timer',
        'System Speaker'
    )

    $wanMiniports = @(
        'WAN Miniport (IP)',
        'WAN Miniport (IPv6)',
        'WAN Miniport (L2TP)',
        'WAN Miniport (PPPOE)',
        'WAN Miniport (PPTP)',
        'WAN Miniport (SSTP)',
        'WAN Miniport (Network Monitor)'
    )

    $gamingDevices = @(
        'Intel(R) Management Engine Interface',
        'AMD PSP Device',
        'Composite Bus Enumerator',
        'UMBus Root Bus Enumerator'
    )

    $tracker = Get-NonRegistryChangeTracker -Context $Context

    $summary = [pscustomobject]@{
        Level   = $Level
        Touched = 0
        Skipped = 0
    }

    function Disable-HardwareDevices {
        param(
            [string]$SectionLabel,
            [string[]]$Names,
            [switch]$IncludeWanMiniports,
            [switch]$WarnOnWanMiniports
        )

        Write-Section $SectionLabel

        if ($WarnOnWanMiniports) {
            Write-Host "  [!] Warning: disabling WAN Miniports can break VPN connectivity." -ForegroundColor Yellow
        }

        $pnpErrors = $null
        $devices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue -ErrorVariable pnpErrors
        if ($pnpErrors) {
            Invoke-ErrorHandler -Context "Enumerating PnP devices for $SectionLabel" -ErrorRecord $pnpErrors[-1]
        }
        if (-not $devices) {
            Write-Host "  [!] No PnP devices returned. Skipping." -ForegroundColor Yellow
            return
        }

        $targets = $devices | Where-Object {
            ($Names -contains $_.FriendlyName) -or ($IncludeWanMiniports -and $_.FriendlyName -match '^WAN Miniport')
        }

        if (-not $targets) {
            Write-Host "  [i] No matching hardware devices found." -ForegroundColor DarkGray
            return
        }

        foreach ($device in $targets) {
            if (-not $device.InstanceId) {
                $summary.Skipped++
                continue
            }

            if ($device.Status -and $device.Status -eq 'Disabled') {
                Write-Host "  [=] Already disabled: $($device.FriendlyName)" -ForegroundColor DarkGray
                $summary.Skipped++
                continue
            }

            if (-not $tracker.HardwareDevices.ContainsKey($device.InstanceId)) {
                $tracker.HardwareDevices[$device.InstanceId] = @{
                    FriendlyName = $device.FriendlyName
                    Status       = $device.Status
                }
            }

            $disableErrors = $null
            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable disableErrors | Out-Null

            if ($disableErrors) {
                Invoke-ErrorHandler -Context "Disabling hardware device $($device.FriendlyName)" -ErrorRecord $disableErrors[-1]
                $summary.Skipped++
                continue
            }

            Write-Host "  [+] Disabled: $($device.FriendlyName)" -ForegroundColor Green
            $summary.Touched++
        }
    }

    if ($tiersToApply -contains 'Safe') {
        Disable-HardwareDevices -SectionLabel 'Hardware Device Hardening (Safe)' -Names $safeDevices
    }

    if ($tiersToApply -contains 'Aggressive') {
        Disable-HardwareDevices -SectionLabel 'Hardware Device Hardening (Aggressive)' -Names $aggressiveDevices -IncludeWanMiniports -WarnOnWanMiniports
    }

    if ($tiersToApply -contains 'Gaming') {
        Disable-HardwareDevices -SectionLabel 'Hardware Device Hardening (Gaming)' -Names $gamingDevices
    }

    return $summary
}

Export-ModuleMember -Function Invoke-HardwareDeviceHardening
