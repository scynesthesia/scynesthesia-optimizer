Import-Module (Join-Path $PSScriptRoot '..' 'modules' 'core' 'context.psm1') -Force

$context = New-RunContext
$counter = 0

$firstResult = Invoke-Once -Context $context -Id 'demo' -Action { $counter++ }
$secondResult = Invoke-Once -Context $context -Id 'demo' -Action { $counter++ }

if ($counter -ne 1) {
    throw "Invoke-Once should run the action exactly once. Actual: $counter"
}

if (-not $firstResult -or $secondResult) {
    throw "Invoke-Once should return `$true for first run and `$false for subsequent runs. Actual: first=$firstResult, second=$secondResult"
}

Write-Host 'Invoke-Once self-test passed.'
