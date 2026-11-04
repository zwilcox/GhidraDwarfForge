#Requires -Version 7.0
# Exercise the production encoder without starting Java or requesting authorization.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$launcher = Join-Path $PSScriptRoot '../../../support/ghidra-dwarf-forge-attach.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path $launcher).Path, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw "Launcher parse failed: $errors" }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Encode-PathArgument'
}, $true))
if ($functions.Count -ne 1) { throw 'Expected one production path encoder' }
# Only load the repository-owned function; do not execute the launcher's entry point.
. ([scriptblock]::Create($functions[0].Extent.Text))
$checks = 0
foreach ($literal in @('/tmp/λ 空 😀.json', 'C:\path with spaces\λ [literal] $() ` ;.json', ('空' * 16384))) {
    $encoded = Encode-PathArgument $literal
    if ($encoded -cnotmatch '^[A-Za-z0-9+/]*={0,2}$') { throw 'Transport is not ASCII Base64' }
    $decoded = [Text.UTF8Encoding]::new($false, $true).GetString([Convert]::FromBase64String($encoded))
    if ($decoded -cne $literal) { throw 'Literal path changed during transport' }
    $checks++
}
if ((Encode-PathArgument '/tmp/λ 空 😀.json') -cne 'L3RtcC/OuyDnqbog8J+YgC5qc29u') { throw 'Java/PowerShell fixed vector mismatch' }
$checks++
foreach ($invalid in @('', ('bad' + [char]0 + 'path'), ('a' * 16385), [string][char]0xD800)) {
    $rejected = $false
    try { Encode-PathArgument $invalid | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid literal path accepted' }
    $checks++
}
Write-Output "attachment-path-argument=PASS checks=$checks native-windows-launch=false"
