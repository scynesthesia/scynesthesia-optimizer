function Optimize-GamingScheduler {
    Write-Section "Process Priority (Gaming)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    if (Ask-YesNo "Prioritize GPU/CPU for foreground games?" 'y') {
        $gamesPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

        Set-RegistryValueSafe $gamesPath "GPU Priority" 8
        Set-RegistryValueSafe $gamesPath "Priority" 6
        Set-RegistryValueSafe $gamesPath "Scheduling Category" "High" ([Microsoft.Win32.RegistryValueKind]::String)
        Set-RegistryValueSafe $gamesPath "SFIO Priority" "High" ([Microsoft.Win32.RegistryValueKind]::String)

        Write-Host "  [+] Scheduler optimized for games." -ForegroundColor Green
        if ($logger) {
            Write-Log "[Gaming] Foreground game priorities set (GPU Priority=8, Priority=6, Scheduling/SFIO=High)."
        }
    } else {
        Write-Host "  [ ] Scheduler left unchanged." -ForegroundColor DarkGray
    }
}


function Get-OrCreate-GamingPlan {
    $planName = "Scynesthesia Gaming Mode"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    try {
        $plans = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop
    } catch {
        throw "Unable to query power plans via CIM: $_"
    }

    $existingPlan = $plans | Where-Object { $_.ElementName -eq $planName }
    if ($existingPlan) {
        if ($logger) {
            Write-Log "[Gaming] Reusing existing '$planName' power plan."
        }
        return $existingPlan
    }

    $activePlan = $plans | Where-Object { $_.IsActive -eq $true } | Select-Object -First 1
    if (-not $activePlan) {
        throw "Unable to detect active power plan."
    }

    $activeGuid = ($activePlan.InstanceID -split '[{}]')[1]
    if (-not $activeGuid) {
        throw "Unable to parse active power plan GUID."
    }

    $duplicateOutput = powercfg -duplicatescheme $activeGuid
    $duplicateMatch  = [regex]::Match($duplicateOutput, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')

    if (-not $duplicateMatch.Success) {
        throw "Unable to duplicate active power scheme."
    }

    $newGuid = $duplicateMatch.Groups[1].Value
    powercfg -changename $newGuid $planName
    if ($logger) {
        Write-Log "[Gaming] Duplicated active plan to '$planName' (GUID=$newGuid)."
    }

    $gamingPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop |
        Where-Object { $_.ElementName -eq $planName }

    if (-not $gamingPlan) {
        throw "Failed to locate gaming power plan after creation."
    }

    return $gamingPlan
}

function Apply-CustomGamingPowerSettings {
    Write-Section "Power Plan: 'Custom Gaming Tweaks'"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue

    $isLaptop = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($isLaptop) {
        Write-Host "  [!] Laptop detected: these settings increase power draw and temperatures." -ForegroundColor Yellow
        Write-Host "      Recommended only while plugged into AC power." -ForegroundColor Yellow
    }

    Write-Host "Applying adjustments to the 'Scynesthesia Gaming Mode' plan." -ForegroundColor DarkGray

    if (Ask-YesNo "Apply hardcore power tweaks to prioritize FPS?" 'n') {
        try {
            $gamingPlan = Get-OrCreate-GamingPlan
            $gamingGuid = ($gamingPlan.InstanceID -split '[{}]')[1]

            if (-not $gamingGuid) {
                throw "Unable to parse gaming power plan GUID."
            }

            # 1) Disks / NVMe
            powercfg /setacvalueindex $gamingGuid SUB_DISK DISKIDLE 0
            powercfg /setacvalueindex $gamingGuid SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0

            # 2) CPU / Core parking / EPP
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR PROCTHROTTLEMIN 100
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 100
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0

            # 3) USB selective suspend OFF
            powercfg /setacvalueindex $gamingGuid `
                2a737441-1930-4402-8d77-b2bebba308a3 `
                48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

            # 4) PCIe Link State OFF
            powercfg /setacvalueindex $gamingGuid `
                501a4d13-42af-4429-9fd1-a8218c268e20 `
                ee12f906-d277-404b-b6da-e5fa1a576df5 0

            powercfg /setactive $gamingGuid

            Write-Host "  [+] Power settings for gaming applied." -ForegroundColor Green
            if ($logger) {
                Write-Log "[Gaming] Hardcore power plan tweaks applied and set active (GUID=$gamingGuid)."
            }
        } catch {
            Handle-Error -Context "Applying gaming power settings" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] Hardcore power tweaks skipped." -ForegroundColor DarkGray
    }
}
function Optimize-ProcessorScheduling {
    Write-Section "Processor Scheduling (Win32Priority)"
    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    Write-Host "Tweaks CPU allocation for active windows. Recommended for competitive gaming." -ForegroundColor Gray
    
    # 0x28 (40 decimal): Short intervals + Fixed Quantum.
    # Better for consistent frametimes in games; not the classic dynamic foreground "boost."
    if (Ask-YesNo "Apply Fixed Priority Separation (28 Hex) for lower input latency?" 'n') {
        Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" 40
        Write-Host "  [+] Processor scheduling set to 28 Hex (Fixed/Short)." -ForegroundColor Green
        if ($logger) {
            Write-Log "[Gaming] Win32PrioritySeparation set to 0x28 for fixed/short quanta."
        }
    } else {
        Write-Host "  [ ] Processor scheduling left unchanged." -ForegroundColor DarkGray
    }
}

Export-ModuleMember -Function Optimize-GamingScheduler, Apply-CustomGamingPowerSettings, Optimize-ProcessorScheduling
