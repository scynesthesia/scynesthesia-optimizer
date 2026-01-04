param(
    [switch]$VerboseOutput
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$uiModule = Join-Path $repoRoot 'modules/ui.psm1'
Import-Module $uiModule -Force

$context = [pscustomobject]@{ RegistryRollbackActions = [System.Collections.Generic.List[object]]::new() }
$testPath = 'HKCU:\Software\ScynesthesiaOptimizer\RegistrySelfTest'

$tests = @(
    @{ Name = 'DWordTest';   Type = [Microsoft.Win32.RegistryValueKind]::DWord;       Value = 123 },
    @{ Name = 'QWordTest';   Type = [Microsoft.Win32.RegistryValueKind]::QWord;       Value = 1234567890123 },
    @{ Name = 'StringTest';  Type = [Microsoft.Win32.RegistryValueKind]::String;      Value = 'plain text' },
    @{ Name = 'ExpandTest';  Type = [Microsoft.Win32.RegistryValueKind]::ExpandString;Value = '%TEMP%\\scytest' },
    @{ Name = 'MultiTest';   Type = [Microsoft.Win32.RegistryValueKind]::MultiString; Value = @('one','two','three') },
    @{ Name = 'BinaryTest';  Type = [Microsoft.Win32.RegistryValueKind]::Binary;      Value = [byte[]](0xDE,0xAD,0xBE,0xEF) }
)

function Get-TestRegistryKey {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Default)
    try {
        $subKey = $base.OpenSubKey('Software', $true)
        if (-not $subKey) { throw 'Unable to open HKCU\\Software for testing.' }
        return $subKey.CreateSubKey('ScynesthesiaOptimizer\\RegistrySelfTest', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
    } finally {
        if ($base) { $base.Dispose() }
    }
}

$results = @()
$regKey = $null
try {
    $regKey = Get-TestRegistryKey

    foreach ($test in $tests) {
        Write-Host "[+] Writing $($test.Name) as $($test.Type)" -ForegroundColor Cyan
        $writeResult = Set-RegistryValueSafe -Path $testPath -Name $test.Name -Value $test.Value -Type $test.Type -Context $context -Critical -ReturnResult -OperationLabel "Self-test: $($test.Name)"
        if (-not ($writeResult -and $writeResult.Success)) {
            $reason = Get-RegistryFailureReason -Result $writeResult
            Write-Host "    [!] Write failed for $($test.Name): $reason" -ForegroundColor Yellow
            $results += [pscustomobject]@{
                Name         = $test.Name
                ExpectedType = $test.Type.ToString()
                ActualType   = '(write failed)'
                Matches      = $false
            }
            continue
        }

        $valueName = if ($test.Name -eq '(default)') { '' } else { $test.Name }
        $readValue = $regKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $readKind = $regKey.GetValueKind($valueName)

        $matches = $true
        switch ($test.Type) {
            ([Microsoft.Win32.RegistryValueKind]::Binary) {
                if ($readValue -isnot [byte[]]) { $matches = $false; break }
                if ($readValue.Length -ne $test.Value.Length) { $matches = $false; break }
                $matches = $true
                for ($i = 0; $i -lt $readValue.Length; $i++) {
                    if ($readValue[$i] -ne $test.Value[$i]) { $matches = $false; break }
                }
            }
            ([Microsoft.Win32.RegistryValueKind]::MultiString) {
                if ($readValue -isnot [string[]]) { $matches = $false; break }
                if ($readValue.Length -ne $test.Value.Length) { $matches = $false; break }
                $matches = ($null -eq (Compare-Object -ReferenceObject $readValue -DifferenceObject $test.Value -SyncWindow 0 -CaseSensitive))
            }
            default {
                $matches = ($readValue -eq $test.Value)
            }
        }

        $result = [pscustomobject]@{
            Name = $test.Name
            ExpectedType = $test.Type.ToString()
            ActualType = $readKind.ToString()
            Matches = ($matches -and ($readKind -eq $test.Type))
        }
        $results += $result

        if ($VerboseOutput) {
            Write-Host "    Expected: $($test.Value) | Read: $readValue" -ForegroundColor Gray
        }
    }
}
finally {
    if ($regKey) { $regKey.Dispose() }
    try { Remove-Item -LiteralPath $testPath -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

$failed = $results | Where-Object { -not $_.Matches }
if ($failed.Count -gt 0) {
    Write-Host "[X] Registry self-test failed for: $($failed.Name -join ', ')" -ForegroundColor Red
    $results | Format-Table -AutoSize
    exit 1
}

Write-Host "[OK] Registry self-test succeeded for all value kinds." -ForegroundColor Green
$results | Format-Table -AutoSize

Write-Host "[i] Rollback actions recorded: $($context.RegistryRollbackActions.Count)" -ForegroundColor Gray
