function Enable-MsiModeSafe {
    param(
        [string[]]$Target = 'GPU'
    )

    Write-Section "MSI Mode (Message Signaled Interrupts)"
    Write-Host "Reduces DPC latency by changing how devices communicate with CPU." -ForegroundColor Gray
    Write-Host "WARNING: Only compatible devices will be touched. Reboot required." -ForegroundColor Yellow

    $targetMap = @{
        'GPU'     = @{ Classes = @('{4d36e968-e325-11ce-bfc1-08002be10318}'); Description = 'GPU/Display adapters' }
        'NIC'     = @{ Classes = @('{4d36e972-e325-11ce-bfc1-08002be10318}'); Description = 'Network adapters' }
        'STORAGE' = @{ Classes = @('{4d36e97b-e325-11ce-bfc1-08002be10318}', '{4d36e96a-e325-11ce-bfc1-08002be10318}'); Description = 'Storage controllers' }
    }

    $normalizedTargets = $Target | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique
    $classGuids = @()
    foreach ($t in $normalizedTargets) {
        if ($targetMap.ContainsKey($t)) {
            $classGuids += $targetMap[$t].Classes
            Write-Host "  [>] Targeting: $($targetMap[$t].Description)" -ForegroundColor Gray
        } else {
            Write-Host "  [!] Unknown target '$t'. Skipping." -ForegroundColor Yellow
        }
    }

    if (-not $classGuids) {
        Write-Host "  [!] No valid targets supplied for MSI Mode." -ForegroundColor Yellow
        return
    }

    $touched = 0
    foreach ($classGuid in ($classGuids | Select-Object -Unique)) {
        $devices = Get-PnpDevice -Class $classGuid -Status OK -ErrorAction SilentlyContinue
        foreach ($dev in $devices) {
            try {
                $regPath = "HKLM\SYSTEM\CurrentControlSet\Enum\$($dev.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
                if (-not (Test-Path $regPath)) { continue }

                $currentVal = Get-ItemProperty -Path $regPath -Name "MSISupported" -ErrorAction SilentlyContinue
                if ($null -eq $currentVal -or $currentVal.MSISupported -ne 1) {
                    Set-RegistryValueSafe $regPath "MSISupported" 1
                    Write-Host "  [+] MSI enabled for: $($dev.FriendlyName)" -ForegroundColor Green
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        Write-Log "[MSI] Enabled for $($dev.InstanceId)" -Level 'Info'
                    }
                    $touched++
                } else {
                    Write-Host "  [=] MSI already active for: $($dev.FriendlyName)" -ForegroundColor DarkGray
                }
            } catch {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log "[MSI] Error enabling on $($dev.InstanceId): $($_.Exception.Message)" -Level 'Warning'
                }
            }
        }
    }

    if ($touched -gt 0) {
        $Global:NeedsReboot = $true
        Write-Host ""
        Write-Host "  [!] A REBOOT is required to apply MSI Mode changes." -ForegroundColor Magenta
    } else {
        Write-Host "  [i] No applicable devices found or already enabled." -ForegroundColor DarkGray
    }
}

Export-ModuleMember -Function Enable-MsiModeSafe
