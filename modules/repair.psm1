# Depends on: ui.psm1 (loaded by main script)
# Description: Performs a basic network repair including DNS flush and IP renewal.
# Parameters: None.
# Returns: None. Can set global reboot flag if Winsock reset is run.
function Invoke-NetworkSoftReset {
    Write-Section "Basic Network Repair"

    Write-Host "This will clear DNS and renew the IP. It does NOT touch the firewall or advanced settings." -ForegroundColor Gray

    if (Ask-YesNo "Run the basic network repair?" 'n') {
        ipconfig /flushdns | Out-Null
        ipconfig /release | Out-Null
        ipconfig /renew | Out-Null
        Write-Host "[OK] Basic network repair completed." -ForegroundColor Green

        if (Ask-YesNo "Also run 'netsh winsock reset'? (Requires reboot)" 'n') {
            netsh winsock reset | Out-Null
            Write-Host "[OK] Winsock reset. Reboot to apply changes." -ForegroundColor Yellow
            $Global:NeedsReboot = $true
        }
    }
}

# Description: Runs System File Checker to scan and repair Windows integrity issues.
# Parameters: None.
# Returns: None.
function Invoke-SystemRepair {
    Write-Section "Windows Integrity Check (SFC)"
    Write-Host "This scans for corrupt system files and repairs them automatically." -ForegroundColor Gray

    if (Ask-YesNo "Start SFC /scannow?" 'n') {
        sfc /scannow
        Write-Host "[OK] SFC completed." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Invoke-NetworkSoftReset, Invoke-SystemRepair
