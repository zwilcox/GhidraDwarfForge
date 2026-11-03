param(
    [Parameter(Mandatory=$true)][string]$ExtensionZip,
    [Parameter(Mandatory=$true)][string]$NativeDiagnostics,
    [Parameter(Mandatory=$true)][string]$Results
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Native Windows execution is required' }
if (Test-Path -LiteralPath $Results) { throw 'Fresh results directory required' }
$root = (New-Item -ItemType Directory -Path $Results).FullName
$utf8 = [Text.UTF8Encoding]::new($false)
$provenance = (New-Item -ItemType Directory -Path (Join-Path $root 'provenance')).FullName
$classes = (New-Item -ItemType Directory -Path (Join-Path $root 'classes')).FullName
$expanded = Join-Path $root 'extension'
Expand-Archive -LiteralPath $ExtensionZip -DestinationPath $expanded
$jar = @(Get-ChildItem -LiteralPath $expanded -Recurse -Filter 'GhidraDwarfForge.jar')
if ($jar.Count -ne 1) { throw 'Expected one production extension JAR' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$paths = @(
    $jar[0].FullName,
    (Join-Path $NativeDiagnostics 'file-metadata/provenance/jna-5.14.0.jar'),
    (Join-Path $NativeDiagnostics 'file-metadata/provenance/gson-2.9.0.jar'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsAttachmentHostSmoke.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsAttachmentTransactionSmoke.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsFileSecurityProbe.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsAttachmentPrivilegeProbe.java'),
    $PSCommandPath
)
$hashes = [ordered]@{}
foreach ($path in $paths) {
    $copy = Join-Path $provenance ([IO.Path]::GetFileName($path))
    Copy-Item -LiteralPath $path -Destination $copy
    $hashes[$path] = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $copy).Hash.ToLowerInvariant() -cne $hashes[$path]) {
        throw 'Retained dependency/source differs'
    }
}
$hashes[$ExtensionZip] = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExtensionZip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $provenance 'origin.json'), ($hashes | ConvertTo-Json -Depth 10), $utf8)
$commands = [Collections.Generic.List[object]]::new()
function Run([string]$Label, [string]$Program, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Program
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        if (-not $child.Start()) { throw 'Could not launch isolated test process' }
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        $timeout = -not $child.WaitForExit(180000)
        if ($timeout) { $child.Kill($true); $child.WaitForExit() }
        [IO.File]::WriteAllText((Join-Path $root "$Label.stdout"), $stdout.GetAwaiter().GetResult(), $utf8)
        [IO.File]::WriteAllText((Join-Path $root "$Label.stderr"), $stderr.GetAwaiter().GetResult(), $utf8)
        $commands.Add([ordered]@{label=$Label; executable=$Program; arguments=$Arguments; exit=$child.ExitCode; timedOut=$timeout})
        [IO.File]::WriteAllText((Join-Path $root 'commands.json'), ($commands.ToArray() | ConvertTo-Json -Depth 10), $utf8)
        if ($timeout -or $child.ExitCode -ne 0) { throw "Isolated host test failed: $Label" }
    }
    finally { $child.Dispose() }
}
$dependencies = ((@('GhidraDwarfForge.jar','jna-5.14.0.jar','gson-2.9.0.jar') | ForEach-Object { Join-Path $provenance $_ }) -join ';')
Run 'java-version' (Join-Path $env:JAVA_HOME 'bin/java.exe') @('-version')
if (-not ([IO.File]::ReadAllText((Join-Path $root 'java-version.stderr')) -match 'version "21[.]')) { throw 'Java 21 required' }
Run 'compile' (Join-Path $env:JAVA_HOME 'bin/javac.exe') @('--release','21','-cp',$dependencies,'-d',$classes,
    (Join-Path $provenance 'WindowsFileSecurityProbe.java'), (Join-Path $provenance 'WindowsAttachmentHostSmoke.java'),
    (Join-Path $provenance 'WindowsAttachmentTransactionSmoke.java'), (Join-Path $provenance 'WindowsAttachmentPrivilegeProbe.java'))
Run 'helper-privilege' (Join-Path $env:JAVA_HOME 'bin/java.exe') @('-Xint','-XX:+UseSerialGC','--enable-native-access=ALL-UNNAMED',
    '-cp',($classes + ';' + $dependencies),'ghidradwarfforge.output.WindowsAttachmentPrivilegeProbe')
if ([IO.File]::ReadAllText((Join-Path $root 'helper-privilege.stderr')).Length -ne 0) { throw 'Unexpected helper privilege diagnostics' }
if (-not [IO.File]::ReadAllText((Join-Path $root 'helper-privilege.stdout')).Contains('windows-attachment-privilege=PASS')) {
    throw 'Missing helper privilege acceptance result'
}
Run 'host-stores' (Join-Path $env:JAVA_HOME 'bin/java.exe') @('-Xint','-XX:+UseSerialGC','--enable-native-access=ALL-UNNAMED',
    '-cp',($classes + ';' + $dependencies),'ghidradwarfforge.output.WindowsAttachmentHostSmoke',(Join-Path $root 'owned'))
if ([IO.File]::ReadAllText((Join-Path $root 'host-stores.stderr')).Length -ne 0) { throw 'Unexpected host diagnostics' }
Run 'host-transaction' (Join-Path $env:JAVA_HOME 'bin/java.exe') @('--enable-native-access=ALL-UNNAMED',
    '-cp',($classes + ';' + $dependencies),'ghidradwarfforge.output.WindowsAttachmentTransactionSmoke',(Join-Path $root 'transactions'))
if ([IO.File]::ReadAllText((Join-Path $root 'host-transaction.stderr')).Length -ne 0) { throw 'Unexpected transaction diagnostics' }
Write-Output 'windows-attachment-host-harness=PASS'
