#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReportFile,
    [string]$BeforeFile,
    [string]$Function,
    [switch]$Summary,
    [string]$GhidraDirectory = $env:GHIDRA_INSTALL_DIR,
    [string]$ExtensionDirectory = (Split-Path -Parent $PSScriptRoot),
    [string]$JavaExecutable
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($GhidraDirectory)) { throw 'GhidraDirectory or GHIDRA_INSTALL_DIR is required' }
$ghidra = (Resolve-Path -LiteralPath $GhidraDirectory).Path
$extension = (Resolve-Path -LiteralPath $ExtensionDirectory).Path
if ([string]::IsNullOrWhiteSpace($JavaExecutable)) {
    $javaName = if ($IsWindows) { 'java.exe' } else { 'java' }
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) { $JavaExecutable = Join-Path $env:JAVA_HOME "bin/$javaName" }
    else { $JavaExecutable = (Get-Command $javaName -CommandType Application).Source }
}
$java = (Resolve-Path -LiteralPath $JavaExecutable).Path
$dependencies = @(
    (Join-Path $extension 'lib/GhidraDwarfForge.jar'),
    (Join-Path $ghidra 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'),
    (Join-Path $ghidra 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar')
)
foreach ($dependency in $dependencies) {
    if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) { throw "Missing installed dependency: $dependency" }
    if ($dependency.Contains([IO.Path]::PathSeparator)) { throw 'Installation path contains the Java classpath separator' }
}
function Encode-PathArgument([string]$Value) {
    if ($Value.Length -eq 0 -or $Value.Length -gt 16384 -or $Value.Contains([char]0)) { throw 'Path must be nonempty, bounded and contain no NUL' }
    return [Convert]::ToBase64String([Text.UTF8Encoding]::new($false, $true).GetBytes($Value))
}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = $java
$info.UseShellExecute = $false
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
$info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
foreach ($argument in @('-cp',($dependencies -join [IO.Path]::PathSeparator),
        'ghidradwarfforge.output.CoverageReportTool','--report-utf8-base64',(Encode-PathArgument $ReportFile))) {
    $info.ArgumentList.Add($argument)
}
if ($PSBoundParameters.ContainsKey('BeforeFile')) { $info.ArgumentList.Add('--before-utf8-base64'); $info.ArgumentList.Add((Encode-PathArgument $BeforeFile)) }
if ($PSBoundParameters.ContainsKey('Function')) { $info.ArgumentList.Add('--function'); $info.ArgumentList.Add($Function) }
if ($Summary) { $info.ArgumentList.Add('--summary') }
$child = [Diagnostics.Process]::new()
$child.StartInfo = $info
$started = $false
try {
    if (-not $child.Start()) { throw 'Could not start report reader' }
    $started = $true
    # Drain both pipes concurrently without retaining an entire large comparison.
    $stdout = $child.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
    $stderr = $child.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())
    $child.WaitForExit()
    $stdout.GetAwaiter().GetResult()
    $stderr.GetAwaiter().GetResult()
    exit $child.ExitCode
}
finally {
    if ($started -and -not $child.HasExited) { $child.Kill($true); $child.WaitForExit() }
    $child.Dispose()
}
