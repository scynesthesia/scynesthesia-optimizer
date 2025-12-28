# Depends on: ui.psm1 (loaded by main script)
# Description: Performs a basic network repair including DNS flush and IP renewal.
# Parameters: Context - Run context for reboot tracking.
# Returns: None. Can set reboot flag on the provided context if Winsock reset is run.
function Invoke-NetworkSoftReset {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Write-Section "Basic Network Repair"

    Write-Host "This will clear DNS and renew the IP. It does NOT touch the firewall or advanced settings." -ForegroundColor Gray

    if (Get-Confirmation "Run the basic network repair?" 'n') {
        ipconfig /flushdns | Out-Null
        ipconfig /release | Out-Null
        ipconfig /renew | Out-Null
        Write-Host "[OK] Basic network repair completed." -ForegroundColor Green

        if (Get-Confirmation "Also run 'netsh winsock reset'? (Requires reboot)" 'n') {
            netsh winsock reset | Out-Null
            Write-Host "[OK] Winsock reset. Reboot to apply changes." -ForegroundColor Yellow
            Set-RebootRequired -Context $Context | Out-Null
        }
    }
}

# Description: Runs System File Checker to scan and repair Windows integrity issues.
# Parameters: None.
# Returns: None.
function Invoke-SystemRepair {
    Write-Section "Windows Integrity Check (SFC)"
    Write-Host "This scans for corrupt system files and repairs them automatically." -ForegroundColor Gray

    if (Get-Confirmation "Start SFC /scannow?" 'n') {
        Write-Host "The System File Checker (SFC) scan is starting. This process typically takes 10-20 minutes depending on your hardware. The progress percentage may appear to pause at certain points; please do not close the window until it completes." -ForegroundColor Cyan
        sfc /scannow
        Write-Host "[OK] SFC completed." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Invoke-NetworkSoftReset, Invoke-SystemRepair
