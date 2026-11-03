param(
    [Parameter(Mandatory=$true)][string]$JavaExe,
    [Parameter(Mandatory=$true)][string]$JavacExe,
    [Parameter(Mandatory=$true)][string]$Compiler,
    [Parameter(Mandatory=$true)][string]$Jna,
    [Parameter(Mandatory=$true)][string]$Gson,
    [Parameter(Mandatory=$true)][string]$Results
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Native Windows execution is required' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
if (Test-Path -LiteralPath $Results) { throw 'Results must be a fresh directory' }
$root = (New-Item -ItemType Directory -Path $Results).FullName
$provenance = (New-Item -ItemType Directory -Path (Join-Path $root 'provenance')).FullName
$classes = (New-Item -ItemType Directory -Path (Join-Path $root 'classes')).FullName
$utf8 = [Text.UTF8Encoding]::new($false)
$env:PATH = (Split-Path -Parent $Compiler) + [IO.Path]::PathSeparator + $env:PATH
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Save-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -Depth 60 -InputObject $Value) + "`n", $utf8)
}
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
$sources = @(
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/WindowsFileMetadata.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsFileMetadataProbe.java'),
    (Join-Path $repo 'src/test/native/windows-metadata-contract.c'),
    (Join-Path $repo 'src/test/native/windows-metadata-api.json'),
    (Join-Path $PSScriptRoot 'attachment-host-observations/NativeWindowsHostFacts.cs'),
    (Join-Path $PSScriptRoot 'attachment-host-observations/NativeWindowsSecurityBytes.cs'),
    $PSCommandPath, $Jna, $Gson
)
$hashes = [ordered]@{}
foreach ($sourcePath in $sources) {
    $sourcePath = (Resolve-Path -LiteralPath $sourcePath).Path
    $hashes[$sourcePath] = Hash $sourcePath
    $copy = Join-Path $provenance ([IO.Path]::GetFileName($sourcePath))
    Copy-Item -LiteralPath $sourcePath -Destination $copy
    Require ((Hash $copy) -eq $hashes[$sourcePath]) 'Retained source/dependency differs'
}
Save-Json (Join-Path $provenance 'origin.json') $hashes
$commands = [Collections.Generic.List[object]]::new()
function Run-Captured([string]$Label, [string]$Executable, [string[]]$Arguments, [bool]$Success=$true) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        Require ($child.Start()) 'Could not start isolated child'
        $outTask = $child.StandardOutput.ReadToEndAsync()
        $errTask = $child.StandardError.ReadToEndAsync()
        $timedOut = -not $child.WaitForExit(30000)
        if ($timedOut) {
            $child.Kill($true)
            Require ($child.WaitForExit(5000)) 'Isolated child did not terminate'
        }
        $stdout = $outTask.GetAwaiter().GetResult()
        $stderr = $errTask.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $root "$Label.stdout"), $stdout, $utf8)
        [IO.File]::WriteAllText((Join-Path $root "$Label.stderr"), $stderr, $utf8)
        $commands.Add([ordered]@{label=$Label; executable=$Executable; arguments=$Arguments; exit=$child.ExitCode; timedOut=$timedOut})
        Save-Json (Join-Path $root 'commands.json') $commands.ToArray()
        Require (-not $timedOut) "Isolated metadata child timed out: $Label"
        Require (($child.ExitCode -eq 0) -eq $Success) "$Label unexpected exit; inspect retained output: $stderr"
        return [pscustomobject]@{stdout=$stdout; stderr=$stderr; exit=$child.ExitCode}
    }
    finally { $child.Dispose() }
}
$contract = Join-Path $root 'native-contract.exe'
$null = Run-Captured 'compile-contract' $Compiler @('-std=c11','-Wall','-Wextra','-Werror',
    (Join-Path $provenance 'windows-metadata-contract.c'),'-ladvapi32','-o',$contract)
$null = Run-Captured 'native-contract' $contract @()
$dependencies = (Join-Path $provenance ([IO.Path]::GetFileName($Jna))) + ';' +
    (Join-Path $provenance ([IO.Path]::GetFileName($Gson)))
$null = Run-Captured 'compile-java' $JavacExe @('--release','21','-cp',$dependencies,'-d',$classes,
    (Join-Path $provenance 'WindowsFileMetadata.java'), (Join-Path $provenance 'WindowsFileMetadataProbe.java'))
$version = Run-Captured 'java-version' $JavaExe @('-version')
Require ($version.stderr -match 'version "21[.]') 'Actual Java 21 required'
$prefix = @('-cp', ($classes + ';' + $dependencies), 'ghidradwarfforge.output.WindowsFileMetadataProbe')
function Run-Probe([string]$Label, [string[]]$Arguments, [bool]$Success=$true, [bool]$Interpreted=$false) {
    $request = Join-Path $root "$Label.request.json"
    Save-Json $request $Arguments
    $options = if ($Interpreted) { @('-Xint') } else { @() }
    return Run-Captured $Label $JavaExe ($options + $prefix + @('--request-file',$request)) $Success
}
Add-Type -Path (Join-Path $provenance 'NativeWindowsHostFacts.cs')
Add-Type -Path (Join-Path $provenance 'NativeWindowsSecurityBytes.cs')
$owned = (New-Item -ItemType Directory -Path (Join-Path $root 'owned')).FullName
$original = Join-Path $owned 'ordinary λ source'
$stageParent = (New-Item -ItemType Directory -Path (Join-Path $owned 'private stage')).FullName
$stage = Join-Path $stageParent 'candidate'
$transport = Run-Probe 'request-roundtrip' @('request-roundtrip',$original,$stage)
$roundtrip = ConvertFrom-Json -InputObject $transport.stdout
Require ($roundtrip.Count -eq 3 -and $roundtrip[1] -ceq $original -and $roundtrip[2] -ceq $stage) 'Unicode probe request changed'
[IO.File]::WriteAllBytes($original, [byte[]]@(1,2,0,255,10))
[IO.File]::WriteAllText($stage, 'different private-stage contents and size', $utf8)
[IO.File]::SetCreationTimeUtc($original, [DateTime]::FromFileTimeUtc(133713240001234567L))
[IO.File]::SetLastWriteTimeUtc($original, [DateTime]::FromFileTimeUtc(133713240009876543L))
$observations = [Collections.Generic.List[object]]::new()
function Binary-Hex($Value) {
    $bytes = [byte[]]::new($Value.BinaryLength)
    $Value.GetBinaryForm($bytes, 0)
    return [Convert]::ToHexString($bytes).ToLowerInvariant()
}
function Independent-State([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $acl = Get-Acl -LiteralPath $Path
    $managed = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    # Get-Acl's CommonAcl representation can sort ACEs while serializing.
    # Read independent raw native bytes for the exact preservation oracle.
    $nativeBytes = [ForgeHostResearch.NativeWindowsSecurityBytes]::Read($Path)
    $legacyBytes = [ForgeHostResearch.NativeWindowsSecurityBytes]::ReadLegacy($Path)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($nativeBytes, 0)
    $native = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($Path, $false, $true)
    Require ($native.status -eq 'OBSERVED' -and $native.fileIdStatus -eq 'OBSERVED') 'Independent identity unavailable'
    return [ordered]@{sha256=(Hash $Path); bytes=$item.Length; attributes=[int]$item.Attributes;
        created=$item.CreationTimeUtc.ToFileTimeUtc(); modified=$item.LastWriteTimeUtc.ToFileTimeUtc();
        volume=$native.volume128; fileId=$native.fileId128; links=$native.links;
        control=[int]$raw.ControlFlags; owner=(Binary-Hex $raw.Owner); group=(Binary-Hex $raw.Group);
        dacl=$(if ($null -eq $raw.DiscretionaryAcl) { $null } else { Binary-Hex $raw.DiscretionaryAcl });
        nativeDescriptor=[Convert]::ToHexString($nativeBytes).ToLowerInvariant();
        legacyDescriptor=[Convert]::ToHexString($legacyBytes).ToLowerInvariant();
        managedDacl=$(if ($null -eq $managed.DiscretionaryAcl) { $null } else { Binary-Hex $managed.DiscretionaryAcl })}
}
function Inspect-Case([string]$Label, [string]$Path) {
    $before = Independent-State $Path
    Save-Json (Join-Path $root "$Label.independent.json") $before
    $capture = Run-Probe $Label @('inspect',$Path)
    $snapshot = ConvertFrom-Json -AsHashtable $capture.stdout
    foreach ($key in @('bytes','attributes','created','modified','links')) {
        Require ($snapshot.facts[$key] -eq $before[$key]) "Native observation differs: $key"
    }
    $parts = $snapshot.facts.identity.Split(':')
    Require ($parts[0].PadLeft(16,'0') -eq $before.volume -and $parts[1] -eq $before.fileId) 'Native identity differs'
    foreach ($key in @('control','owner','group','dacl')) {
        $actual = if ($snapshot.security.ContainsKey($key)) { $snapshot.security[$key] } else { $null }
        Require ($actual -eq $before[$key]) "Native security observation differs: $key expected=$($before[$key]) actual=$actual"
    }
    $streams = [ForgeHostResearch.NativeWindowsHostFacts]::DataStreams($Path)
    Require ($streams.status -eq 'OBSERVED') 'Independent data-stream enumeration unavailable'
    Require ($snapshot.dataStreams.Count -eq $streams.streams.Count) 'Native stream count differs'
    foreach ($stream in $streams.streams) {
        Require ($snapshot.dataStreams.ContainsKey($stream.name) -and
            $snapshot.dataStreams[$stream.name] -eq $stream.size) 'Native stream name/size differs'
    }
    Require ((ConvertTo-Json -Compress (Independent-State $Path)) -ceq (ConvertTo-Json -Compress $before)) 'Inspection changed source'
    $observations.Add([ordered]@{case=$Label; independent=$before; independentStreams=$streams; java=$snapshot})
    Save-Json (Join-Path $root 'observations.json') $observations.ToArray()
    return (Join-Path $root "$Label.stdout")
}
function Apply-Case([string]$Label) {
    $snapshot = Inspect-Case "$Label-before" $original
    $before = Independent-State $original
    $prior = Independent-State $stage
    $null = Run-Probe $Label @('apply',$original,$stage,$snapshot,'-1')
    $after = Independent-State $stage
    foreach ($key in @('attributes','created','modified','control','owner','group','dacl')) {
        Require ($after[$key] -eq $before[$key]) "Metadata application differs: $key"
    }
    Require ($after.sha256 -eq $prior.sha256 -and $after.fileId -eq $prior.fileId) 'Stage bytes/identity changed'
    Require ((ConvertTo-Json -Compress (Independent-State $original)) -ceq (ConvertTo-Json -Compress $before)) 'Application changed source'
    $null = Inspect-Case "$Label-after" $stage
}
Apply-Case 'ordinary-inherited'
$acl = Get-Acl -LiteralPath $original
$acl.SetAccessRuleProtection($true, $true)
Set-Acl -LiteralPath $original -AclObject $acl
Apply-Case 'explicit-protected'
[IO.File]::SetAttributes($original, ([IO.File]::GetAttributes($original) -bor [IO.FileAttributes]::ReadOnly -bor [IO.FileAttributes]::Hidden))
Apply-Case 'readonly-hidden'
[IO.File]::SetAttributes($original, [IO.FileAttributes]::Archive)
[IO.File]::SetAttributes($stage, [IO.FileAttributes]::Archive)
$snapshot = Inspect-Case 'stale-snapshot' $original
[IO.File]::SetLastWriteTimeUtc($original, [DateTime]::FromFileTimeUtc(133713240009876544L))
$before = Independent-State $stage
$refused = Run-Probe 'stale-rejection' @('apply',$original,$stage,$snapshot,'-1') $false
Require ($refused.stderr.Contains('source changed')) 'Unexpected stale-snapshot rejection'
Require ((ConvertTo-Json -Compress (Independent-State $stage)) -ceq (ConvertTo-Json -Compress $before)) 'Stale rejection changed stage'
$snapshot = Inspect-Case 'cancellation-snapshot' $original
$before = Independent-State $original
foreach ($poll in @('0','2','9','14','16','20')) {
    $refused = Run-Probe "cancel-$poll" @('apply',$original,$stage,$snapshot,$poll) $false
    Require ($refused.stderr.Contains('CancellationException')) 'Unexpected cancellation result'
    Require ((ConvertTo-Json -Compress (Independent-State $original)) -ceq (ConvertTo-Json -Compress $before)) 'Cancellation changed source'
}
$null = Run-Probe 'same-file-rejection' @('apply',$original,$original,$snapshot,'-1') $false
$link = Join-Path $owned 'hardlink'
$null = New-Item -ItemType HardLink -Path $link -Target $original
$snapshot = Inspect-Case 'hardlink-snapshot' $original
$refused = Run-Probe 'hardlink-rejection' @('apply',$original,$stage,$snapshot,'-1') $false
Require ($refused.stderr.Contains('rejects hardlinks')) 'Unexpected hardlink rejection'
Remove-Item -LiteralPath $link
[IO.File]::WriteAllText(($original + ':forge_stream'), 'owned alternate stream')
$snapshot = Inspect-Case 'named-stream-snapshot' $original
$refused = Run-Probe 'named-stream-rejection' @('apply',$original,$stage,$snapshot,'-1') $false
Require ($refused.stderr.Contains('rejects named')) 'Unexpected named-stream rejection'
$null = Run-Probe 'alternate-path-rejection' @('inspect',($original + ':forge_stream')) $false
$symbolic = Join-Path $owned 'symbolic'
$null = New-Item -ItemType SymbolicLink -Path $symbolic -Target $original
$null = Run-Probe 'symlink-rejection' @('inspect',$symbolic) $false
$null = Run-Probe 'directory-rejection' @('inspect',$owned) $false
$empty = Join-Path $owned 'empty'
[IO.File]::WriteAllBytes($empty, [byte[]]::new(0))
$null = Inspect-Case 'empty-file' $empty
$locked = [IO.File]::Open($stage, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    $refused = Run-Probe 'sharing-lock' @('inspect',$stage) $false
    Require ($refused.stderr.Contains('error=32')) 'Unexpected sharing-lock rejection'
}
finally { $locked.Dispose() }
$null = Run-Probe 'native-handle-lifetime' @('leak-controls',$original) $true $true
foreach ($sourcePath in $hashes.Keys) { Require ((Hash $sourcePath) -eq $hashes[$sourcePath]) 'Protected source/dependency changed' }
Save-Json (Join-Path $root 'result.json') ([ordered]@{status='PASS'; observations=$observations.ToArray();
    scope='Opened Windows identity and accessible owner/group/DACL/attribute/time copying; not complete host admission, SACL/EA preservation or durability'})
Write-Output 'windows-file-metadata=PASS'
