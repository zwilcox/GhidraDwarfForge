param(
    [Parameter(Mandatory = $true)] [string] $GhidraDirectory,
    [Parameter(Mandatory = $true)] [string] $ArgumentsFile
)

# Owned fixture arguments are passed as an array, never evaluated as shell code.
$ErrorActionPreference = 'Stop'
$arguments = @(Get-Content -Raw -Encoding utf8 $ArgumentsFile | ConvertFrom-Json)
$headless = Join-Path $GhidraDirectory 'support\analyzeHeadless.bat'
& $headless @arguments
exit $LASTEXITCODE
