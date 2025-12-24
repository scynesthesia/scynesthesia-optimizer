# Description: Shared network discovery helpers.

function Resolve-CoreNormalizedGuid {
    param($Value)

    try {
        if ($null -eq $Value) { return $null }

        if ($Value -is [string]) {
            $trimmed = $Value.Trim('{}').Trim()
            if (-not $trimmed) { return $null }
            return "{$trimmed}".ToUpperInvariant()
        }

        if ($Value -is [guid]) {
            return $Value.ToString('B').ToUpperInvariant()
        }

        return ([guid]$Value).ToString('B').ToUpperInvariant()
    } catch {
        return $null
    }
}

function Invoke-CoreError {
    param(
        [string]$Context,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $handler = Get-Command Invoke-ErrorHandler -ErrorAction SilentlyContinue
    if ($handler) {
        Invoke-ErrorHandler -Context $Context -ErrorRecord $ErrorRecord
    } else {
        Write-Error "$Context failed: $($ErrorRecord.Exception.Message)"
    }
}

# Description: Maps network adapters to their registry class paths.
# Parameters:
#   AdapterResolver - ScriptBlock returning adapter objects (defaults to Get-NetAdapter -Physical).
#   ClassGuid - Registry class GUID string.
#   AllowOwnershipFallback - Attempt temporary ownership to read class entries when access is denied.
#   LoggerPrefix - Optional prefix for log messages.
#   AccessDeniedFlag - [ref] flag set when registry access is blocked.
# Returns: Objects containing AdapterName, InterfaceGuid, NetCfgInstanceId, RegistryPath, IfIndex, AdapterObject.
function Get-NicRegistryMap {
    param(
        [ScriptBlock]$AdapterResolver,
        [string]$ClassGuid = '{4D36E972-E325-11CE-BFC1-08002BE10318}',
        [switch]$AllowOwnershipFallback,
        [string]$LoggerPrefix,
        [ref]$AccessDeniedFlag
    )

    $logger = Get-Command Write-Log -ErrorAction SilentlyContinue
    $classPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\$ClassGuid"
    $results = @()
    $prefix = if ($LoggerPrefix) { $LoggerPrefix } else { '[Network]' }

    $adapters = @()
    try {
        if ($AdapterResolver) {
            $adapters = & $AdapterResolver
        } else {
            $adapters = Get-NetAdapter -Physical -ErrorAction Stop
        }
    } catch {
        Invoke-CoreError -Context 'Retrieving network adapters' -ErrorRecord $_
        return @()
    }

    if (-not $adapters) { return @() }

    $entries = @()
    try {
        $entries = Get-ChildItem -Path $classPath -ErrorAction Stop | Where-Object { $_.PSChildName -match '^\d{4}$' }
    } catch {
        $isUnauthorized = ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception -is [System.Security.SecurityException])
        if ($isUnauthorized -and $AllowOwnershipFallback) {
            $ownershipAdjusted = $false
            $originalOwner = $null
            $ownerRef = $null
            try {
                $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
                $acl = Get-Acl -Path $classPath -ErrorAction Stop
                $originalOwner = $acl.Owner
                if ($acl.Owner -ne $adminsSid.Value) {
                    $acl.SetOwner($adminsSid)
                }
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule($adminsSid, 'ReadKey', 'ContainerInherit', 'None', 'Allow')
                $acl.SetAccessRule($rule)
                Set-Acl -Path $classPath -AclObject $acl -ErrorAction Stop
                $ownershipAdjusted = $true
                Write-Host "  [i] Temporary ownership granted on $classPath for NIC discovery." -ForegroundColor Cyan
                try {
                    $ownerRef = New-Object System.Security.Principal.SecurityIdentifier($originalOwner)
                } catch {
                    $ownerRef = New-Object System.Security.Principal.NTAccount($originalOwner)
                }
            } catch {
                $ownershipAdjusted = $false
            }

            try {
                $entries = Get-ChildItem -Path $classPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
            } finally {
                if ($ownershipAdjusted -and $ownerRef) {
                    try {
                        $acl = Get-Acl -Path $classPath -ErrorAction Stop
                        $acl.SetOwner($ownerRef)
                        Set-Acl -Path $classPath -AclObject $acl -ErrorAction Stop
                        Write-Host "  [i] Restored original ownership on $classPath after discovery." -ForegroundColor Cyan
                    } catch { }
                }
            }

            if ($entries.Count -gt 0) {
                $note = if ($ownershipAdjusted) {
                    'Registry access tightened; temporary ownership was used to read NIC entries. Prefer driver-exposed properties when possible.'
                } else {
                    'Partial registry access detected; proceeding with readable NIC entries only.'
                }
                Write-Host "  [!] $note" -ForegroundColor Yellow
                if ($logger) { Write-Log "$prefix $note" -Level 'Warning' }
            } else {
                $isAdmin = $false
                $adminChecker = Get-Command Test-IsAdminSession -ErrorAction SilentlyContinue
                if ($adminChecker) {
                    try { $isAdmin = Test-IsAdminSession } catch { $isAdmin = $false }
                }
                $message = if ($isAdmin) {
                    "Registry protection blocked access to $classPath even in an elevated session. Prefer Set-NetAdapterAdvancedProperty where exposed, or take ownership of the key temporarily to proceed."
                } else {
                    "Insufficient registry permissions to enumerate $classPath. Run PowerShell as Administrator to apply NIC registry tweaks or rely on driver properties instead of registry edits."
                }
                Write-Host "  [!] $message" -ForegroundColor Yellow
                if ($logger) { Write-Log "$prefix $message" -Level 'Warning' }
                if ($AccessDeniedFlag) { $AccessDeniedFlag.Value = $true }
                return @()
            }
        } else {
            Invoke-CoreError -Context 'Enumerating NIC registry class entries' -ErrorRecord $_
            if ($logger) { Write-Log "$prefix Registry class enumeration failed; adapter registry tweaks skipped." -Level 'Warning' }
            if ($isUnauthorized -and $AccessDeniedFlag) { $AccessDeniedFlag.Value = $true }
            return @()
        }
    }

    foreach ($adapter in $adapters) {
        try {
            $guidString = Resolve-CoreNormalizedGuid -Value $adapter.InterfaceGuid
            if (-not $guidString) { continue }
            foreach ($entry in $entries) {
                try {
                    $netCfg = (Get-ItemProperty -Path $entry.PSPath -Name 'NetCfgInstanceId' -ErrorAction SilentlyContinue).NetCfgInstanceId
                    $netCfgString = Resolve-CoreNormalizedGuid -Value $netCfg
                    if ($netCfgString -and ($netCfgString -eq $guidString)) {
                        $results += [pscustomobject]@{
                            AdapterName      = $adapter.Name
                            InterfaceGuid    = $guidString
                            NetCfgInstanceId = $netCfgString
                            RegistryPath     = $entry.PSPath
                            IfIndex          = $adapter.ifIndex
                            AdapterObject    = $adapter
                        }
                        break
                    }
                } catch { }
            }
        } catch {
            Invoke-CoreError -Context "Finding registry path for $($adapter.Name)" -ErrorRecord $_
        }
    }

    return $results
}

Export-ModuleMember -Function Get-NicRegistryMap
