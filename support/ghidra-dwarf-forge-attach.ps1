#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RequestFile,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$RequestSha256,
    [string]$GhidraDirectory = $env:GHIDRA_INSTALL_DIR,
    [string]$ExtensionDirectory = (Split-Path -Parent $PSScriptRoot),
    [string]$JavaExecutable,
    [string]$CancellationFile,
    [switch]$Recover,
    [switch]$Preview,
    [switch]$ConfirmTargetChange,
    [switch]$Authorize
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This launcher requires Windows and PowerShell 7 or later' }
if (-not [IO.Path]::IsPathFullyQualified($RequestFile)) { throw 'RequestFile must be absolute' }
if ([string]::IsNullOrWhiteSpace($GhidraDirectory)) { throw 'GhidraDirectory or GHIDRA_INSTALL_DIR is required' }
$ghidra = (Resolve-Path -LiteralPath $GhidraDirectory).Path
$extension = (Resolve-Path -LiteralPath $ExtensionDirectory).Path
if ([string]::IsNullOrWhiteSpace($JavaExecutable)) {
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        $JavaExecutable = Join-Path $env:JAVA_HOME 'bin/java.exe'
    }
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
$arguments = [Collections.Generic.List[string]]::new()
function Encode-PathArgument([string]$Value) {
    if ($Value.Length -eq 0 -or $Value.Length -gt 16384 -or $Value.Contains([char]0)) {
        throw 'Path argument must be nonempty, bounded and contain no NUL'
    }
    # Java 21's Windows launcher converts argv through the active ANSI code
    # page. Keep literal selected paths in ASCII transport until Java decodes.
    return [Convert]::ToBase64String([Text.UTF8Encoding]::new($false, $true).GetBytes($Value))
}
foreach ($argument in @('--enable-native-access=ALL-UNNAMED','-cp',($dependencies -join ';'),
        'ghidradwarfforge.output.AttachmentHelper','--request-utf8-base64',(Encode-PathArgument $RequestFile),'--request-sha256',$RequestSha256)) {
    $arguments.Add($argument)
}
if ($Recover) { $arguments.Add('--recover') }
if (-not [string]::IsNullOrWhiteSpace($CancellationFile)) {
    if (-not [IO.Path]::IsPathFullyQualified($CancellationFile)) { throw 'CancellationFile must be absolute' }
    $arguments.Add('--cancel-file-utf8-base64')
    $arguments.Add((Encode-PathArgument $CancellationFile))
}

# ArgumentList performs Windows argument quoting. No cmd.exe, -Command,
# Invoke-Expression, interpolated script or temporary command file is used.
function New-StartInfo([bool]$Elevated, [bool]$ReadOnly) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $java
    $info.UseShellExecute = $Elevated
    if ($Elevated) { $info.Verb = 'runas' }
    foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
    if ($ReadOnly) {
        $info.ArgumentList.Add('--preview')
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
        $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    }
    else {
        $info.ArgumentList.Add('--confirm-target-change')
        $info.ArgumentList.Add('--enable-security-privilege')
    }
    return $info
}

$review = [Diagnostics.Process]::new()
$review.StartInfo = New-StartInfo $false $true
try {
    if (-not $review.Start()) { throw 'Could not start read-only selection preview' }
    $stdout = $review.StandardOutput.ReadToEndAsync()
    $stderr = $review.StandardError.ReadToEndAsync()
    if (-not $review.WaitForExit(60000)) {
        $review.Kill($true)
        $review.WaitForExit()
        throw 'Read-only preview timed out; attachment was not started'
    }
    [Console]::Out.Write($stdout.GetAwaiter().GetResult())
    [Console]::Error.Write($stderr.GetAwaiter().GetResult())
    if ($review.ExitCode -ne 0) { exit $review.ExitCode }
}
finally { $review.Dispose() }
if ($Preview) { exit 0 }
if (-not $ConfirmTargetChange) {
    [Console]::Error.WriteLine('Review the selection and pass -ConfirmTargetChange to modify the executable.')
    exit 64
}
[Console]::Error.WriteLine('Starting explicit target change. The separate helper enables only its existing SeSecurityPrivilege and restores its original state. Preserve the selected recovery request, backups and receipts.')
$child = [Diagnostics.Process]::new()
$child.StartInfo = New-StartInfo $Authorize.IsPresent $false
try {
    # UAC is requested only by -Authorize. Decline or permission failure is final;
    # never silently retry a non-elevated operation with a different token.
    if (-not $child.Start()) { throw 'Could not start attachment helper' }
    $child.WaitForExit()
    $status = $child.ExitCode
    if ($Authorize) {
        # ShellExecute/UAC cannot redirect the elevated console. Durable
        # transaction receipts remain authoritative if that console is closed.
        [Console]::Out.WriteLine((@{ launcherExitCode=$status; receiptIsAuthoritative=$true } | ConvertTo-Json -Compress))
    }
    exit $status
}
finally { $child.Dispose() }
