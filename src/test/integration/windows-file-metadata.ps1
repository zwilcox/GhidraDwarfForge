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
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/DebuglinkBasename.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/DebuglinkBasenameSmoke.java'),
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/WindowsFileMetadata.java'),
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/WindowsFileSecurity.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsFileSecurityProbe.java'),
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/WindowsBackupStreams.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsBackupStreamsProbe.java'),
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/WindowsDirectorySync.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsDirectorySyncProbe.java'),
    (Join-Path $repo 'src/test/native/windows-directory-flush.c'),
    (Join-Path $repo 'src/test/native/windows-directory-api.json'),
    (Join-Path $repo 'src/test/native/windows-security-visibility.c'),
    (Join-Path $repo 'src/test/native/windows-security-visibility-api.json'),
    (Join-Path $repo 'src/test/native/windows-backup-contract.c'),
    (Join-Path $repo 'src/test/native/windows-ea-fixture.c'),
    (Join-Path $repo 'src/test/native/windows-backup-api.json'),
    (Join-Path $repo 'src/main/java/ghidradwarfforge/output/WindowsFileRename.java'),
    (Join-Path $repo 'src/test/java/ghidradwarfforge/output/WindowsFileRenameProbe.java'),
    (Join-Path $repo 'src/test/native/windows-rename-contract.c'),
    (Join-Path $repo 'src/test/native/windows-rename-api.json'),
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
$renameContract = Join-Path $root 'rename-contract.exe'
$null = Run-Captured 'compile-rename-contract' $Compiler @('-std=c11','-Wall','-Wextra','-Werror',
    (Join-Path $provenance 'windows-rename-contract.c'),'-o',$renameContract)
$null = Run-Captured 'rename-contract' $renameContract @()
$backupContract = Join-Path $root 'backup-contract.exe'
$null = Run-Captured 'compile-backup-contract' $Compiler @('-std=c11','-Wall','-Wextra','-Werror',
    (Join-Path $provenance 'windows-backup-contract.c'),'-o',$backupContract)
$null = Run-Captured 'backup-contract' $backupContract @()
$eaFixture = Join-Path $root 'ea-fixture.exe'
$null = Run-Captured 'compile-ea-fixture' $Compiler @('-std=c11','-Wall','-Wextra','-Werror','-municode',
    (Join-Path $provenance 'windows-ea-fixture.c'),'-lntdll','-o',$eaFixture)
$dependencies = (Join-Path $provenance ([IO.Path]::GetFileName($Jna))) + ';' +
    (Join-Path $provenance ([IO.Path]::GetFileName($Gson)))
$null = Run-Captured 'compile-java' $JavacExe @('--release','21','-cp',$dependencies,'-d',$classes,
    (Join-Path $provenance 'DebuglinkBasename.java'), (Join-Path $provenance 'DebuglinkBasenameSmoke.java'),
    (Join-Path $provenance 'WindowsDirectorySync.java'), (Join-Path $provenance 'WindowsDirectorySyncProbe.java'),
    (Join-Path $provenance 'WindowsFileMetadata.java'), (Join-Path $provenance 'WindowsFileMetadataProbe.java'),
    (Join-Path $provenance 'WindowsFileSecurity.java'), (Join-Path $provenance 'WindowsFileSecurityProbe.java'),
    (Join-Path $provenance 'WindowsBackupStreams.java'), (Join-Path $provenance 'WindowsBackupStreamsProbe.java'),
    (Join-Path $provenance 'WindowsFileRename.java'), (Join-Path $provenance 'WindowsFileRenameProbe.java'))
$version = Run-Captured 'java-version' $JavaExe @('-version')
Require ($version.stderr -match 'version "21[.]') 'Actual Java 21 required'
$null = Run-Captured 'debuglink-basename-policy' $JavaExe @('-cp',$classes,'ghidradwarfforge.output.DebuglinkBasenameSmoke')
$prefix = @('-cp', ($classes + ';' + $dependencies), 'ghidradwarfforge.output.WindowsFileMetadataProbe')
function Run-Probe([string]$Label, [string[]]$Arguments, [bool]$Success=$true, [bool]$Interpreted=$false) {
    $request = Join-Path $root "$Label.request.json"
    Save-Json $request $Arguments
    $options = @()
    if ($Interpreted) { $options = @('-Xint') }
    return Run-Captured $Label $JavaExe ($options + $prefix + @('--request-file',$request)) $Success
}
Add-Type -Path (Join-Path $provenance 'NativeWindowsHostFacts.cs')
Add-Type -Path (Join-Path $provenance 'NativeWindowsSecurityBytes.cs')
$owned = (New-Item -ItemType Directory -Path (Join-Path $root 'owned')).FullName
$original = Join-Path $owned 'ordinary λ source'
$stageParent = (New-Item -ItemType Directory -Path (Join-Path $owned 'private stage')).FullName
$stage = Join-Path $stageParent 'candidate'
foreach ($interpreted in @($false,$true)) {
    $transport = Run-Probe "request-roundtrip-$interpreted" @('request-roundtrip',$original,$stage) $true $interpreted
    $roundtrip = ConvertFrom-Json -InputObject $transport.stdout
    Require ($roundtrip.Count -eq 3 -and $roundtrip[1] -ceq $original -and $roundtrip[2] -ceq $stage) 'Unicode probe request changed'
}
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
$acl = Get-Acl -LiteralPath $original
$acl.SetAccessRuleProtection($false, $true)
Set-Acl -LiteralPath $original -AclObject $acl
Apply-Case 'modern-inherited'
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
# Actual namespace operations on exclusively owned fixture paths. They do not
# provide the complete host metadata or durability policy.
function Run-Rename([string]$Label, [string[]]$Arguments, [bool]$Success=$true, [bool]$Interpreted=$false) {
    $request = Join-Path $root "$Label.rename-request.json"
    Save-Json $request $Arguments
    $options = @()
    if ($Interpreted) { $options = @('-Xint') }
    $renameArgs = @('-cp', ($classes + [IO.Path]::PathSeparator + $dependencies),
        'ghidradwarfforge.output.WindowsFileRenameProbe', '--request-file', $request)
    return Run-Captured $Label $JavaExe ($options + $renameArgs) $Success
}
function Same-State($Expected, [string]$Path) {
    Require ((ConvertTo-Json -Compress (Independent-State $Path)) -ceq
        (ConvertTo-Json -Compress $Expected)) "Namespace changed protected bytes/metadata/identity: $Path"
}
$renameResults = [Collections.Generic.List[object]]::new()
function Rename-Case([string]$Label, [string]$Mode, [bool]$Existing=$false, [bool]$Success=$true) {
    $dir = (New-Item -ItemType Directory -Path (Join-Path $owned ('rename-' + $Label))).FullName
    $stageDir = (New-Item -ItemType Directory -Path (Join-Path $dir 'private stage')).FullName
    $renameStage = Join-Path $stageDir 'image λ'
    $renameTarget = Join-Path $dir 'final λ ;$[ ] image.dbg'
    [IO.File]::WriteAllText($renameStage, 'complete owned new image', $utf8)
    [IO.File]::SetLastWriteTimeUtc($renameStage, [DateTime]::FromFileTimeUtc(133713240009876543L))
    if ($Existing) { [IO.File]::WriteAllText($renameTarget, 'complete prior image', $utf8) }
    $stageState = Independent-State $renameStage
    $targetState = if ($Existing) { Independent-State $renameTarget } else { $null }
    $outcome = Run-Rename $Label @($Mode,$renameStage,$renameTarget) $Success
    if ($Success) {
        Require (-not (Test-Path -LiteralPath $renameStage)) 'Successful rename retained stage name'
        Same-State $stageState $renameTarget
    }
    else {
        if ($Mode -eq 'stale-stage') {
            Require ([IO.File]::ReadAllText($renameStage) -ceq 'changed stage after snapshot; must remain') 'Stale stage was lost'
        }
        elseif ($Mode -eq 'late-stage') {
            Require ([IO.File]::ReadAllText($renameStage) -ceq 'concurrent stage; must remain') 'Concurrent stage was lost'
            Same-State $stageState ($renameStage + '.retained')
        }
        else { Same-State $stageState $renameStage }
        if ($Mode -in @('stale-target','late-target','last-moment-collision')) {
            $expectedText = switch ($Mode) {
                'stale-target' { 'changed target after snapshot; must remain' }
                'late-target' { 'concurrent target; must remain' }
                'last-moment-collision' { 'concurrent new target; must remain' }
            }
            Require ([IO.File]::ReadAllText($renameTarget) -ceq $expectedText) 'Concurrent target was lost'
        }
        elseif ($Existing) { Same-State $targetState $renameTarget }
        else { Require (-not (Test-Path -LiteralPath $renameTarget)) 'Failed rename created a final target' }
        if ($Mode -like 'cancel-*') { Require ($outcome.stderr.Contains('CancellationException')) 'Cancellation not propagated' }
        if ($Mode -eq 'last-moment-collision') { Require ($outcome.stderr.Contains('FileRenameInfo failed')) 'Collision did not reach native no-overwrite request' }
    }
    $row = [ordered]@{case=$Label; mode=$Mode; success=$Success; stageBefore=$stageState; targetBefore=$targetState;
        stageAfter=$(if (Test-Path -LiteralPath $renameStage) { Independent-State $renameStage } else { $null });
        targetAfter=$(if (Test-Path -LiteralPath $renameTarget) { Independent-State $renameTarget } else { $null })}
    $renameResults.Add($row)
    Save-Json (Join-Path $root 'rename-observations.json') $renameResults.ToArray()
    return [pscustomobject]@{stage=$renameStage; target=$renameTarget; directory=$dir}
}
$null = Rename-Case 'publish-new' 'publish'
$null = Rename-Case 'replace-existing' 'replace' $true
$null = Rename-Case 'existing-refusal' 'publish' $true $false
$null = Rename-Case 'stale-stage' 'stale-stage' $false $false
$null = Rename-Case 'stale-target' 'stale-target' $true $false
$null = Rename-Case 'late-stage' 'late-stage' $false $false
$null = Rename-Case 'late-target' 'late-target' $true $false
$null = Rename-Case 'collision-at-native-call' 'last-moment-collision' $false $false
$null = Rename-Case 'cancel-before-rename' 'cancel-before' $false $false
$control = Rename-Case 'cancel-open-rename' 'cancel-open' $false $false
$renameStage = $control.stage
$renameTarget = $control.target
$beforeStage = Independent-State $renameStage
$null = Run-Rename 'rename-alias' @('replace',$renameStage,$renameStage) $false
Same-State $beforeStage $renameStage
$hard = Join-Path $control.directory 'hardlink'
$null = New-Item -ItemType HardLink -Path $hard -Target $renameStage
$linkedBefore = Independent-State $renameStage
$null = Run-Rename 'rename-hardlink' @('publish',$renameStage,$renameTarget) $false
Same-State $linkedBefore $renameStage
Remove-Item -LiteralPath $hard
$dangling = Join-Path $control.directory 'dangling'
$null = New-Item -ItemType SymbolicLink -Path $dangling -Target (Join-Path $control.directory 'absent')
$null = Run-Rename 'rename-dangling' @('publish',$renameStage,$dangling) $false
Require ((Get-Item -LiteralPath $dangling -Force).LinkType -eq 'SymbolicLink') 'Dangling destination was removed'
$null = Run-Rename 'rename-stream-path' @('publish',$renameStage,($renameTarget + ':named')) $false
[IO.File]::WriteAllText($renameTarget, 'locked prior image', $utf8)
$beforeTarget = Independent-State $renameTarget
# Allow reads so metadata succeeds; deny deletion so the actual namespace call fails.
$locked = [IO.File]::Open($renameTarget, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try {
    $refused = Run-Rename 'rename-sharing-lock' @('replace',$renameStage,$renameTarget) $false
    Require ($refused.stderr.Contains('FileRenameInfo failed')) 'Sharing-lock control did not reach rename'
}
finally { $locked.Dispose() }
Same-State $beforeStage $renameStage
Same-State $beforeTarget $renameTarget
[IO.File]::SetAttributes($renameTarget, [IO.FileAttributes]::ReadOnly)
$readonlyBefore = Independent-State $renameTarget
$null = Run-Rename 'rename-readonly-target' @('replace',$renameStage,$renameTarget) $false
Same-State $readonlyBefore $renameTarget
Same-State $beforeStage $renameStage
[IO.File]::SetAttributes($renameTarget, [IO.FileAttributes]::Archive)
Remove-Item -LiteralPath $renameTarget
$crossRoot = Join-Path ([IO.Path]::GetTempPath()) ('forge-rename-cross-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $crossRoot
$crossMarker = Join-Path $crossRoot 'owned marker'
$crossTarget = Join-Path $crossRoot 'absent target'
[IO.File]::WriteAllText($crossMarker, 'owned cross-volume observer', $utf8)
$crossFacts = Independent-State $crossMarker
$crossResult = [ordered]@{tested=$false; stageVolume=$beforeStage.volume; destinationVolume=$crossFacts.volume}
if ($beforeStage.volume -ne $crossFacts.volume) {
    $refused = Run-Rename 'rename-cross-volume' @('publish',$renameStage,$crossTarget) $false
    Require ($refused.stderr.Contains('FileRenameInfo failed (error=17)')) 'Cross-volume request did not fail as a rename'
    Same-State $beforeStage $renameStage
    Require (-not (Test-Path -LiteralPath $crossTarget)) 'Cross-volume refusal copied a destination'
    $crossResult.tested = $true
}
else { $crossResult['reason'] = 'Runner temporary directory is on the same volume; cross-volume control unavailable' }
Same-State $crossFacts $crossMarker
Save-Json (Join-Path $root 'rename-cross-volume.json') $crossResult
Remove-Item -LiteralPath $crossMarker
Remove-Item -LiteralPath $crossRoot
$null = Run-Rename 'rename-handle-lifetime' @('lifetime',$renameStage,$renameTarget) $true $true
Same-State $beforeStage $renameStage
Require (-not (Test-Path -LiteralPath $renameTarget)) 'Lifetime test left a target'

$backupPrefix = @('-cp', ($classes + ';' + $dependencies), 'ghidradwarfforge.output.WindowsBackupStreamsProbe')
function Run-Backup([string]$Label, [string[]]$Arguments, [bool]$Success=$true,
        [bool]$Interpreted=$false, [bool]$SerialGc=$false, [bool]$VmLog=$false) {
    $request = Join-Path $root "$Label.request.json"
    Save-Json $request $Arguments
    $options = @()
    if ($Interpreted) { $options = @('-Xint') }
    if ($SerialGc) { $options += '-XX:+UseSerialGC' }
    if ($VmLog) { $options += "-Xlog:os+thread=debug,gc+task=debug:file=$Label.vm.log:time,uptime,level,tags" }
    return Run-Captured $Label $JavaExe ($options + $backupPrefix + @('--request-file',$request)) $Success
}
$eaSource = Join-Path $owned 'EA source λ [literal]'
$eaStage = Join-Path $stageParent 'EA stage'
foreach ($interpreted in @($false,$true)) {
    $transport = Run-Backup "backup-roundtrip-$interpreted" @('request-roundtrip',$eaSource,$eaStage) $true $interpreted
    $values = ConvertFrom-Json $transport.stdout
    Require ($values.Count -eq 3 -and $values[1] -ceq $eaSource -and $values[2] -ceq $eaStage) 'Backup probe changed Unicode request/output'
}
[IO.File]::WriteAllText($eaSource, 'source must remain unchanged', $utf8)
[IO.File]::WriteAllText($eaStage, 'private stage must remain unchanged', $utf8)
$beforeEaSource = Independent-State $eaSource
$beforeEaStage = Independent-State $eaStage
$ordinaryEa = Run-Captured 'ea-ordinary-query' $eaFixture @('query',$eaSource)
Require ($null -eq (ConvertFrom-Json $ordinaryEa.stdout).eaBytes) 'Ordinary file unexpectedly has EAs'
$ordinaryBackup = Run-Backup 'backup-ordinary' @('ordinary',$eaSource)
$inventory = ConvertFrom-Json $ordinaryBackup.stdout
Require ($inventory.streams.Count -eq 1 -and $inventory.streams[0].kind -eq 1 -and
    $inventory.streams[0].bytes -eq $beforeEaSource.bytes) 'Ordinary backup inventory differs'
Same-State $beforeEaSource $eaSource
$empty = Join-Path $owned 'empty backup source'
[IO.File]::WriteAllBytes($empty, [byte[]]::new(0))
$null = Run-Backup 'backup-empty' @('ordinary',$empty)
$setEa = Run-Captured 'ea-source-set' $eaFixture @('set',$eaSource)
$eaBytes = (ConvertFrom-Json $setEa.stdout).eaBytes
Require ($eaBytes -eq '00000000000a0500464f5247455f544553540000ff420a19') 'Independent EA payload differs'
$eaBefore = Independent-State $eaSource
$eaInventory = Run-Backup 'backup-ea' @('inspect',$eaSource)
$eaStreams = @((ConvertFrom-Json $eaInventory.stdout).streams | Where-Object { $_.kind -eq 2 })
Require ($eaStreams.Count -eq 1 -and $eaStreams[0].bytes -gt 0) 'Backup inventory missed actual EA data'
$refused = Run-Backup 'backup-ea-reject' @('ordinary',$eaSource) $false
Require ($refused.stderr.Contains('unsupported metadata streams')) 'EA rejection did not identify unsupported streams'
$snapshot = Inspect-Case 'ea-source-snapshot' $eaSource
$refused = Run-Probe 'ea-source-apply-reject' @('apply',$eaSource,$eaStage,$snapshot,'-1') $false
Require ($refused.stderr.Contains('unsupported metadata streams')) 'Source EA application was not refused'
Same-State $eaBefore $eaSource
Same-State $beforeEaStage $eaStage
$queryEa = Run-Captured 'ea-source-after' $eaFixture @('query',$eaSource)
Require ((ConvertFrom-Json $queryEa.stdout).eaBytes -eq $eaBytes) 'Source EA changed during refusal'
# Swap roles: the source has no EA and the owned stage has one. Admission must
# reject before applying even ordinary metadata to that stage.
$snapshot = Inspect-Case 'ea-stage-source-snapshot' $eaStage
$refused = Run-Probe 'ea-stage-apply-reject' @('apply',$eaStage,$eaSource,$snapshot,'-1') $false
Require ($refused.stderr.Contains('unsupported metadata streams')) 'Stage EA application was not refused'
Same-State $eaBefore $eaSource
Same-State $beforeEaStage $eaStage
$queryEa = Run-Captured 'ea-stage-after' $eaFixture @('query',$eaSource)
Require ((ConvertFrom-Json $queryEa.stdout).eaBytes -eq $eaBytes) 'Stage EA changed during refusal'
$null = Run-Backup 'backup-cancel' @('cancel',$eaSource)
$null = Run-Captured 'backup-native-lifetime' $eaFixture @('backup-lifetime',$eaSource)
# Default G1 lazily starts worker threads (and their OS handles). Retain that
# observation separately; resource acceptance still requires exact equality
# using serial GC, plus an independent native process with the same API calls.
$null = Run-Backup 'backup-default-gc-observation' @('lifetime-observation',$eaSource) $true $true $false $true
$null = Run-Backup 'backup-lifetime' @('lifetime',$eaSource) $true $true $true $true
Same-State $eaBefore $eaSource
$adsSource = Join-Path $owned 'backup named stream'
[IO.File]::WriteAllText($adsSource, 'ordinary bytes', $utf8)
[IO.File]::WriteAllText(($adsSource + ':extra λ'), 'alternate bytes', $utf8)
$adsBefore = Independent-State $adsSource
$adsInventory = Run-Backup 'backup-ads' @('inspect',$adsSource)
$adsStreams = @((ConvertFrom-Json $adsInventory.stdout).streams | Where-Object { $_.kind -eq 4 })
Require ($adsStreams.Count -eq 1 -and $adsStreams[0].name -ceq ':extra λ:$DATA' -and
    $adsStreams[0].bytes -eq $utf8.GetByteCount('alternate bytes')) 'Backup named stream differs'
$null = Run-Backup 'backup-ads-reject' @('ordinary',$adsSource) $false
Same-State $adsBefore $adsSource
Require ([IO.File]::ReadAllText(($adsSource + ':extra λ'), $utf8) -ceq 'alternate bytes') 'Named stream changed'
$backupResults = [ordered]@{ordinary=(ConvertFrom-Json $ordinaryBackup.stdout);
    extendedAttributes=(ConvertFrom-Json $eaInventory.stdout); independentEaBytes=$eaBytes;
    alternateStreams=(ConvertFrom-Json $adsInventory.stdout); cancellationAfterHeader=$true; handleCycles=128}
Save-Json (Join-Path $root 'backup-streams.json') $backupResults

# Research only: retain actual directory-flush results; neither success nor refusal
# establishes a complete filesystem durability contract. Ordinary-file positive
# and negative controls and exact repeated handle cleanup are mandatory.
$directoryProbe = Join-Path $root 'directory-flush.exe'
$null = Run-Captured 'compile-directory-flush' $Compiler @('-std=c11','-Wall','-Wextra','-Werror','-municode',
    (Join-Path $provenance 'windows-directory-flush.c'),'-o',$directoryProbe)
$null = Run-Captured 'directory-token-privileges' (Join-Path $env:SystemRoot 'System32/whoami.exe') @('/priv')
$directoryPath = Join-Path $owned 'directory flush λ'
$directoryRun = Run-Captured 'directory-flush' $directoryProbe @($directoryPath)
$directoryFacts = ConvertFrom-Json $directoryRun.stdout
Require ($directoryFacts.status -eq 'OBSERVED' -and $directoryFacts.fileFlush -and
    $directoryFacts.readOnlyFileError -eq 5 -and $directoryFacts.handleCycles -eq 128 -and
    $directoryFacts.handlesBefore -eq $directoryFacts.handlesAfter -and
    -not $directoryFacts.powerLossRecoveryProven) 'Directory experiment controls did not pass'
$directoryNative = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($directoryPath, $false, $false)
Require ($directoryNative.status -eq 'OBSERVED' -and
    $directoryNative.volume128 -ceq $directoryFacts.volume128 -and
    $directoryNative.fileId128 -ceq $directoryFacts.fileId128) 'Independent directory identity differs'
$directoryChild = Join-Path $directoryPath 'after'
Require ([Convert]::ToHexString([IO.File]::ReadAllBytes($directoryChild)) -ceq '00FF420A19') 'Renamed child bytes differ'
Require (@(Get-ChildItem -LiteralPath $directoryPath -Force).Count -eq 1) 'Unexpected owned directory contents'
$directoryBefore = Independent-State $directoryChild
$refused = Run-Captured 'directory-existing-reject' $directoryProbe @($directoryPath) $false
Require ($refused.stderr.Contains('exclusive directory creation failed')) 'Existing directory was not refused'
Same-State $directoryBefore $directoryChild
Save-Json (Join-Path $root 'directory-flush.json') ([ordered]@{
    status='OBSERVED'; native=$directoryFacts; independent=$directoryNative;
    scope='Owned ordinary directory flush mechanism only; not power-loss recovery or production host admission'})

# Execute the production JNA directory binding only after the independent C
# experiment and ABI/signature assertions have completed successfully.
function Run-Directory([string]$Label, [string[]]$Arguments, [bool]$Success=$true, [bool]$Lifetime=$false) {
    $request = Join-Path $root "$Label.request.json"
    Save-Json $request $Arguments
    $options = @()
    if ($Lifetime) { $options = @('-Xint','-XX:+UseSerialGC') }
    return Run-Captured $Label $JavaExe ($options + @('-cp',($classes + ';' + $dependencies),
        'ghidradwarfforge.output.WindowsDirectorySyncProbe','--request-file',$request)) $Success
}
$directorySyncResults = [Collections.Generic.List[object]]::new()
foreach ($mode in @('inspect','sync')) {
    $result = Run-Directory "directory-java-$mode" @($mode,$directoryPath)
    $actual = ConvertFrom-Json $result.stdout
    Require ($actual.identity -ceq (([Convert]::ToUInt64($directoryFacts.volume128,16).ToString('x')) + ':' + $directoryFacts.fileId128) -and
        $actual.volumeSerial -eq $directoryFacts.volumeSerial -and $actual.maximumNameUnits -eq $directoryFacts.maximumNameUnits -and
        $actual.fileSystemFlags -eq $directoryFacts.fileSystemFlags -and $actual.fileSystem -ceq 'NTFS') 'Java directory facts differ from C/C#'
    Same-State $directoryBefore $directoryChild
    $directorySyncResults.Add([ordered]@{mode=$mode; actual=$actual; independent=$directoryFacts})
}
foreach ($mode in @('cancel-before','cancel-open')) {
    $refused = Run-Directory "directory-java-$mode" @($mode,$directoryPath) $false
    Require ($refused.stderr.Contains('CancellationException')) 'Directory cancellation was not propagated'
    Same-State $directoryBefore $directoryChild
}
foreach ($mode in @('stale','late')) {
    $concurrent = (New-Item -ItemType Directory -Path (Join-Path $owned "directory $mode λ")).FullName
    $sentinel = Join-Path $concurrent 'sentinel'
    [IO.File]::WriteAllBytes($sentinel, [byte[]]@(1,0,255,2))
    $expected = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($concurrent, $false, $false)
    $sentinelHash = Hash $sentinel
    $refused = Run-Directory "directory-java-$mode" @($mode,$concurrent) $false
    Require ($refused.stderr.Contains('Windows directory') -and $refused.stderr.Contains('changed')) 'Changed directory was not refused'
    $retained = [ForgeHostResearch.NativeWindowsHostFacts]::Observe(($concurrent + '.retained'), $false, $false)
    $replacement = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($concurrent, $false, $false)
    Require ($retained.fileId128 -ceq $expected.fileId128 -and $replacement.fileId128 -cne $expected.fileId128 -and
        (Hash (Join-Path ($concurrent + '.retained') 'sentinel')) -eq $sentinelHash -and
        @(Get-ChildItem -LiteralPath $concurrent -Force).Count -eq 0) 'Concurrent directory fixture changed unexpectedly'
    $directorySyncResults.Add([ordered]@{mode=$mode; original=$expected; retained=$retained; replacement=$replacement})
}
$directoryLink = Join-Path $owned 'directory junction'
$null = New-Item -ItemType Junction -Path $directoryLink -Target $directoryPath
$null = Run-Directory 'directory-java-reparse-reject' @('inspect',$directoryLink) $false
Require ((Get-Item -LiteralPath $directoryLink -Force).LinkType -eq 'Junction') 'Directory junction was changed'
$null = Run-Directory 'directory-java-file-reject' @('inspect',$directoryChild) $false
$null = Run-Directory 'directory-java-stream-path-reject' @('inspect',($directoryPath + ':extra')) $false
$null = Run-Directory 'directory-java-traversal-reject' @('inspect',($directoryPath + '\..')) $false
$denied = (New-Item -ItemType Directory -Path (Join-Path $owned 'directory deny write')).FullName
$acl = Get-Acl -LiteralPath $denied
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $sid = $identity.User } finally { $identity.Dispose() }
$deny = [Security.AccessControl.FileSystemAccessRule]::new($sid,
    [Security.AccessControl.FileSystemRights]::WriteData,[Security.AccessControl.AccessControlType]::Deny)
$acl.AddAccessRule($deny)
Set-Acl -LiteralPath $denied -AclObject $acl
$denyBefore = (Get-Acl -LiteralPath $denied).Sddl
$null = Run-Directory 'directory-java-denied-inspect' @('inspect',$denied)
$refused = Run-Directory 'directory-java-denied-sync' @('sync',$denied) $false
Require ($refused.stderr.Contains('CreateFileW directory failed (error=5)')) 'Directory write denial did not propagate'
Require ((Get-Acl -LiteralPath $denied).Sddl -ceq $denyBefore -and
    @(Get-ChildItem -LiteralPath $denied -Force).Count -eq 0) 'Denied directory changed'
$null = Run-Directory 'directory-java-lifetime' @('lifetime',$directoryPath) $true $true
Same-State $directoryBefore $directoryChild
Save-Json (Join-Path $root 'directory-java.json') ([ordered]@{status='PASS';
    observations=$directorySyncResults.ToArray(); cycles=128; deniedWritePreserved=$true;
    scope='Opened-directory JNA identity/flush/cancellation and refusal; not a complete production Host or power-loss recovery'})

# This native child adjusts only its own token, on an exclusively created
# fixture. It is a security-visibility experiment, not a product elevation path.
$securityProbe = Join-Path $root 'security-visibility.exe'
$null = Run-Captured 'compile-security-visibility' $Compiler @('-std=c11','-Wall','-Wextra','-Werror','-municode',
    (Join-Path $provenance 'windows-security-visibility.c'),'-ladvapi32','-o',$securityProbe)
$securityPath = Join-Path $owned 'full security λ'
$securityRun = Run-Captured 'security-visibility-create' $securityProbe @('create',$securityPath)
$securityFacts = ConvertFrom-Json $securityRun.stdout
Require ($securityFacts.status -eq 'OBSERVED' -and $securityFacts.created -and
    $securityFacts.queryFields -eq 0x101ff -and $securityFacts.queryAccess -eq 0x01020000 -and
    $securityFacts.disabledPrivilegeOpenError -eq 1314 -and $securityFacts.insufficientHandleQueryError -eq 5 -and
    $securityFacts.complete.saclPresent -and $securityFacts.complete.auditAces -eq 1 -and
    $securityFacts.complete.labelAces -eq 1 -and -not $securityFacts.ordinary.saclPresent -and
    $securityFacts.initialPrivilegeAttributes -eq $securityFacts.restoredPrivilegeAttributes -and
    $securityFacts.handlesBefore -eq $securityFacts.handlesAfter -and $securityFacts.handleCycles -eq 128) 'Full-security visibility controls differ'
Require ([Convert]::ToHexString([IO.File]::ReadAllBytes($securityPath)) -ceq '4100FF190A') 'Security fixture bytes changed'
$securityBefore = Independent-State $securityPath
$refused = Run-Captured 'security-existing-reject' $securityProbe @('create',$securityPath) $false
Require ($refused.stderr.Contains('exclusive security fixture creation failed')) 'Existing security fixture was not refused'
Same-State $securityBefore $securityPath
$securityRead = Run-Captured 'security-visibility-read' $securityProbe @('read',$securityPath)
$securityAfter = ConvertFrom-Json $securityRead.stdout
Require (-not $securityAfter.created -and $securityAfter.complete.saclHex -ceq $securityFacts.complete.saclHex -and
    $securityAfter.complete.control -eq $securityFacts.complete.control -and
    $securityAfter.before.saclHex -ceq $securityFacts.complete.saclHex -and
    $securityAfter.initialPrivilegeAttributes -eq $securityAfter.restoredPrivilegeAttributes -and
    $securityAfter.handlesBefore -eq $securityAfter.handlesAfter -and $securityAfter.handleCycles -eq 128) 'Read-only whole-security observation changed'
Same-State $securityBefore $securityPath
Save-Json (Join-Path $root 'security-visibility.json') ([ordered]@{status='OBSERVED';
    create=$securityFacts; read=$securityAfter;
    scope='Test-only child token and owned audit/label fixture; complete descriptor agrees across two native APIs. No production elevation, host admission or metadata-preservation claim'})

# Production reader in an isolated Java 21 process. Only the test probe adjusts
# its own already-owned privilege, and restores it before exiting. No parent
# token, product process or account policy is changed.
$securityPrefix = @('-cp', ($classes + ';' + $dependencies), 'ghidradwarfforge.output.WindowsFileSecurityProbe')
$securityJava = Run-Captured 'security-java-inspect' $JavaExe ($securityPrefix + @('inspect',$securityPath))
$securityJavaFacts = ConvertFrom-Json $securityJava.stdout
Require ($securityJavaFacts.descriptor.control -eq $securityFacts.complete.control -and
    $securityJavaFacts.descriptor.saclPresent -eq $securityFacts.complete.saclPresent -and
    $securityJavaFacts.descriptor.saclDefaulted -eq $securityFacts.complete.saclDefaulted -and
    $securityJavaFacts.descriptor.saclHex -ceq $securityFacts.complete.saclHex) 'Java full-security bytes differ from independent native APIs'
Same-State $securityBefore $securityPath
foreach ($mode in @('denied','cancel-before','cancel-open')) {
    $negative = Run-Captured "security-java-$mode" $JavaExe ($securityPrefix + @($mode,$securityPath)) $false
    if ($mode -eq 'denied') { Require ($negative.stderr.Contains('error=1314')) 'Insufficient privilege did not fail at open' }
    else { Require ($negative.stderr.Contains('CancellationException')) 'Security cancellation was not honored' }
    Same-State $securityBefore $securityPath
}
$securityLate = Join-Path $owned 'security late path'
[IO.File]::WriteAllText($securityLate, 'retained security sentinel', $utf8)
$lateHash = Hash $securityLate
$late = Run-Captured 'security-java-late' $JavaExe ($securityPrefix + @('late',$securityLate)) $false
Require ($late.stderr.Contains('selected metadata path changed')) 'Changed security path was not rejected'
Require ((Hash "$securityLate.retained") -eq $lateHash -and
    [IO.File]::ReadAllText($securityLate) -ceq 'replacement sentinel') 'Late-path control changed retained data'
$directoryRefused = Run-Captured 'security-java-directory' $JavaExe ($securityPrefix + @('inspect',$owned)) $false
Require ($directoryRefused.stderr.Contains('regular non-link file')) 'Directory security input was not refused'
$securityCycles = Run-Captured 'security-java-cycles' $JavaExe (@('-Xint','-XX:+UseSerialGC') + $securityPrefix + @('cycles',$securityPath))
Require ($securityCycles.stdout.Contains('windows-security-handles=PASS cycles=128')) 'Security resource cycles incomplete'
Same-State $securityBefore $securityPath
$nativeAfterJava = Run-Captured 'security-native-after-java' $securityProbe @('read',$securityPath)
$nativeAfterJavaFacts = ConvertFrom-Json $nativeAfterJava.stdout
Require ($nativeAfterJavaFacts.complete.saclHex -ceq $securityFacts.complete.saclHex -and
    $nativeAfterJavaFacts.complete.control -eq $securityFacts.complete.control) 'Java reads changed full native security'
Save-Json (Join-Path $root 'security-java.json') ([ordered]@{status='OBSERVED'; snapshot=$securityJavaFacts;
    nativeAfter=$nativeAfterJavaFacts; cycles=128;
    scope='Complete descriptor JNA observation with native SACL agreement, insufficient privilege, cancellation, changed path and lifetime controls; not a production Host or elevation policy'})

foreach ($sourcePath in $hashes.Keys) { Require ((Hash $sourcePath) -eq $hashes[$sourcePath]) 'Protected source/dependency changed' }
Save-Json (Join-Path $root 'result.json') ([ordered]@{status='PASS'; observations=$observations.ToArray();
    renameObservations=$renameResults.ToArray(); renameCrossVolume=$crossResult; backupStreams=$backupResults; directoryFlush=$directoryFacts;
    scope='Opened Windows identity, accessible metadata and verified-stage rename; unsupported backup-stream rejection; not complete host admission, SACL preservation or durability'})
Write-Output 'windows-file-metadata=PASS'
