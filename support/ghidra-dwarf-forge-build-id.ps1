#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RequestFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$RequestSha256,
    [string]$GhidraDirectory = $env:GHIDRA_INSTALL_DIR,
    [string]$ExtensionDirectory = (Split-Path -Parent $PSScriptRoot),
    [string]$JavaExecutable,
    [string]$CancellationFile,
    [switch]$Preview,
    [switch]$EnableSecurityPrivilege
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This launcher requires Windows and PowerShell 7 or later' }
if (-not [IO.Path]::IsPathFullyQualified($RequestFile)) { throw 'RequestFile must be absolute' }
if ([string]::IsNullOrWhiteSpace($GhidraDirectory)) { throw 'GhidraDirectory or GHIDRA_INSTALL_DIR is required' }
$ghidra = (Resolve-Path -LiteralPath $GhidraDirectory).Path
$extension = (Resolve-Path -LiteralPath $ExtensionDirectory).Path
if ([string]::IsNullOrWhiteSpace($JavaExecutable)) {
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) { $JavaExecutable = Join-Path $env:JAVA_HOME 'bin/java.exe' }
    else { $JavaExecutable = (Get-Command java.exe -CommandType Application).Source }
}
$java = (Resolve-Path -LiteralPath $JavaExecutable).Path
if (-not (Test-Path -LiteralPath $java -PathType Leaf) -or [IO.Path]::GetExtension($java) -ine '.exe') {
    throw 'Select a Java executable, not a shell script'
}
$dependencies = @(
    (Join-Path $extension 'lib/GhidraDwarfForge.jar'),
    (Join-Path $ghidra 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'),
    (Join-Path $ghidra 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar')
)
foreach ($dependency in $dependencies) {
    if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) { throw "Missing installed dependency: $dependency" }
    if ($dependency.Contains(';')) { throw 'Java classpath installation paths cannot contain a semicolon' }
}
function Encode-PathArgument([string]$Value) {
    if ($Value.Length -eq 0 -or $Value.Length -gt 16384 -or $Value.Contains([char]0)) { throw 'Invalid path argument' }
    return [Convert]::ToBase64String([Text.UTF8Encoding]::new($false, $true).GetBytes($Value))
}
$arguments = [Collections.Generic.List[string]]::new()
foreach ($argument in @('--enable-native-access=ALL-UNNAMED', '-cp', ($dependencies -join ';'),
        'ghidradwarfforge.output.BuildIdHelper', '--request-utf8-base64', (Encode-PathArgument $RequestFile),
        '--request-sha256', $RequestSha256)) { $arguments.Add($argument) }
if (-not [string]::IsNullOrWhiteSpace($CancellationFile)) {
    if (-not [IO.Path]::IsPathFullyQualified($CancellationFile)) { throw 'CancellationFile must be absolute' }
    $arguments.Add('--cancel-file-utf8-base64')
    $arguments.Add((Encode-PathArgument $CancellationFile))
}
function Invoke-Helper([bool]$ReadOnly) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $java
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
    if ($ReadOnly) { $info.ArgumentList.Add('--preview') }
    elseif ($EnableSecurityPrivilege) { $info.ArgumentList.Add('--enable-security-privilege') }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Could not start build-ID helper' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        # Never kill a publishing transaction because a launcher timeout expired.
        # CancellationFile is the cooperative cancellation mechanism.
        $process.WaitForExit()
        [Console]::Out.Write($stdout.GetAwaiter().GetResult())
        [Console]::Error.Write($stderr.GetAwaiter().GetResult())
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}
$status = Invoke-Helper $true
if ($status -ne 0 -or $Preview) { exit $status }
exit (Invoke-Helper $false)
