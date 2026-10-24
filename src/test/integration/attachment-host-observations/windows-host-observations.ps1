# Test-only provisioner and independent native oracle. No executable replacement.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WorkspaceParent,
    [string]$Java = 'java',
    [string]$Javac = 'javac'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw 'This probe requires native Windows and PowerShell 7.'
}
$parent = (Resolve-Path -LiteralPath $WorkspaceParent).ProviderPath
if (-not [IO.Directory]::Exists($parent)) { throw 'Workspace parent must already exist.' }
$root = Join-Path $parent ('run.windows.' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root -ErrorAction Stop
$fixtures = Join-Path $root 'fixtures'
$evidence = Join-Path $root 'evidence'
$null = New-Item -ItemType Directory -Path $fixtures, $evidence
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$records = [ordered]@{}
$provision = [Collections.Generic.List[object]]::new()
$checks = [Collections.Generic.List[string]]::new()
$lock = $null
$failure = $null
$nativeLoaded = $false
$cleanupFaults = [Collections.Generic.List[object]]::new()
$status = 'HOST_OBSERVATIONS_FAILED_OR_INCOMPLETE'

function Save-Json([string]$Name, $Value) {
    $path = Join-Path $evidence $Name
    $bytes = $utf8.GetBytes(($Value | ConvertTo-Json -Depth 40) + "`n")
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
}
function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $checks.Add($Message)
}
function Bytes([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        if ($stream.Length -gt 1048576) { throw 'Owned fixture unexpectedly exceeds 1MiB.' }
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $digest = $hash.ComputeHash($stream) } finally { $hash.Dispose() }
        return [ordered]@{ bytes = $stream.Length; sha256 = [Convert]::ToHexString($digest).ToLowerInvariant() }
    } finally { $stream.Dispose() }
}
function Security-Facts([string]$Path) {
    try {
        # Get-Acl without -Audit requests access/owner/group, not a full SACL claim.
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        $dacl = $null
        if ($null -ne $raw.DiscretionaryAcl) {
            if ($raw.DiscretionaryAcl.Count -gt 256 -or $raw.DiscretionaryAcl.BinaryLength -gt 65536) {
                throw 'DACL observation bound exceeded.'
            }
            $buffer = [byte[]]::new($raw.DiscretionaryAcl.BinaryLength)
            $raw.DiscretionaryAcl.GetBinaryForm($buffer, 0)
            $dacl = [Convert]::ToBase64String($buffer)
        }
        $entries = @($acl.Access | ForEach-Object {
            [ordered]@{ identity = $_.IdentityReference.Value; rights = [int64]$_.FileSystemRights
                type = $_.AccessControlType.ToString(); inherited = $_.IsInherited
                inheritanceFlags = $_.InheritanceFlags.ToString(); propagationFlags = $_.PropagationFlags.ToString() }
        })
        return [ordered]@{ status = 'OBSERVED'; owner = $raw.Owner.Value; group = $raw.Group.Value
            controlFlags = [int]$raw.ControlFlags; daclBase64 = $dacl; entries = $entries
            observationScope = 'Path-based Get-Acl owner/group/DACL, not bound to native opened identity handle'
            saclIntegrityResourceSecurity = 'UNKNOWN_NOT_REQUESTED'
            completeNativeSecurityMetadata = 'UNKNOWN' }
    } catch {
        return [ordered]@{ status = 'UNAVAILABLE'; exception = $_.Exception.GetType().FullName
            message = $_.Exception.Message; completeNativeSecurityMetadata = 'UNKNOWN' }
    }
}
function Add-Control([string]$Id, [string]$Policy, [string]$Path, [scriptblock]$Setup) {
    try {
        & $Setup
        $records[$Id] = [ordered]@{ path = $Path; policy = $Policy }
        $provision.Add([ordered]@{ id = $Id; status = 'CREATED'; path = $Path })
    } catch {
        $provision.Add([ordered]@{ id = $Id; status = 'UNAVAILABLE'; path = $Path
            exception = $_.Exception.GetType().FullName; message = $_.Exception.Message })
    }
}
function Snapshot {
    $result = [ordered]@{}
    foreach ($id in $records.Keys) {
        $path = $records[$id].path
        $item = [ordered]@{
            nofollow = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($path, $false, $false)
            follow = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($path, $true, $false)
            security = Security-Facts $path
        }
        if ($records[$id].policy -eq 'READ') {
            try { $item.content = Bytes $path } catch {
                $item.content = [ordered]@{ status = 'UNAVAILABLE'; message = $_.Exception.Message }
            }
        }
        if ($id -in @('base', 'equal', 'acl', 'readonly', 'locked', 'ads_base')) {
            $item.dataStreams = [ForgeHostResearch.NativeWindowsHostFacts]::DataStreams($path)
            $item.dataStreams['streams'] = @($item.dataStreams.streams | Sort-Object name)
        }
        $result[$id] = $item
    }
    return $result
}
function Run-Process([string]$Label, [string]$Executable, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $pidObserved = $process.Id
        $timedOut = -not $process.WaitForExit(120000)
        $killError = $null
        $exited = -not $timedOut
        if ($timedOut) {
            try { $process.Kill() } catch { $killError = $_.Exception.Message }
            $exited = $process.WaitForExit(5000)
        }
        $drainError = $null
        try { $drained = [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 5000) }
        catch { $drained = $false; $drainError = $_.Exception.Message }
        $out = if ($stdout.IsCompletedSuccessfully) { $stdout.GetAwaiter().GetResult() } else { '<INCOMPLETE STDOUT>' }
        $err = if ($stderr.IsCompletedSuccessfully) { $stderr.GetAwaiter().GetResult() } else { '<INCOMPLETE STDERR>' }
        $exitCode = if ($exited) { $process.ExitCode } else { $null }
        [IO.File]::WriteAllText((Join-Path $evidence ($Label + '.stdout')), $out, $utf8)
        [IO.File]::WriteAllText((Join-Path $evidence ($Label + '.stderr')), $err, $utf8)
        Save-Json ($Label + '.command.json') ([ordered]@{ executable = $Executable; arguments = $Arguments
            exitCode = $exitCode; timeout = $timedOut; pid = $pidObserved; exited = $exited; drained = $drained
            killError = $killError; drainError = $drainError; scope = 'Trusted direct probe/JDK process; no descendant containment claim' })
        Require (-not $timedOut -and $exited -and $drained -and $exitCode -eq 0) ($Label + ' completed successfully')
        return [ordered]@{ stdout = $out; stderr = $err }
    } finally { $process.Dispose() }
}
function Identity($Value) {
    Require ($Value.status -eq 'OBSERVED' -and $Value.fileIdStatus -eq 'OBSERVED') 'Native 128-bit opened-file identity observed'
    return $Value.volume128 + ':' + $Value.fileId128
}

try {
    Add-Type -Path (Join-Path $PSScriptRoot 'NativeWindowsHostFacts.cs')
    $layouts = [ForgeHostResearch.NativeWindowsHostFacts]::Layouts()
    $nativeLoaded = $true
    Save-Json 'native-layouts.json' $layouts
    $sourceHashes = [ordered]@{}
    foreach ($name in @('HostFacts.java', 'NativeWindowsHostFacts.cs', 'windows-host-observations.ps1', 'windows-api-contract.json')) {
        $sourceHashes[$name] = Bytes (Join-Path $PSScriptRoot $name)
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $evidence $name)
    }
    $javaPath = (Get-Command $Java -ErrorAction Stop).Source
    $javacPath = (Get-Command $Javac -ErrorAction Stop).Source
    $toolHashes = [ordered]@{ java = [ordered]@{ path = $javaPath; before = Bytes $javaPath }; javac = [ordered]@{ path = $javacPath; before = Bytes $javacPath } }
    Save-Json 'tool-before.json' $toolHashes
    $version = Run-Process 'java-version' $javaPath @('-version')
    Require (($version.stdout + $version.stderr) -match '(?m)^(openjdk|java) version "21[.+"]') 'Actual Java21 runtime'
    $null = Run-Process 'javac-version' $javacPath @('-version')
    $classes = Join-Path $evidence 'classes'
    $null = New-Item -ItemType Directory -Path $classes
    $null = Run-Process 'compile' $javacPath @('--release', '21', '-d', $classes, (Join-Path $evidence 'HostFacts.java'))
    $seed = $utf8.GetBytes('owned host metadata fixture; never execute')
    $base = Join-Path $fixtures 'base.dat'
    Add-Control 'base' 'READ' $base { [IO.File]::WriteAllBytes($base, $seed) }
    $equal = Join-Path $fixtures 'equal.dat'
    Add-Control 'equal' 'READ' $equal { [IO.File]::WriteAllBytes($equal, $seed) }
    $hard = Join-Path $fixtures 'hard.dat'
    Add-Control 'hard' 'READ' $hard { $null = New-Item -ItemType HardLink -Path $hard -Target $base }
    $symbolic = Join-Path $fixtures 'symbolic.dat'
    Add-Control 'symbolic' 'READ' $symbolic { $null = New-Item -ItemType SymbolicLink -Path $symbolic -Target $base }
    $dangling = Join-Path $fixtures 'dangling.dat'
    Add-Control 'dangling' 'METADATA' $dangling {
        $null = New-Item -ItemType SymbolicLink -Path $dangling -Target (Join-Path $fixtures 'intentionally-absent')
    }
    $directory = Join-Path $fixtures 'real-directory'
    Add-Control 'directory' 'METADATA' $directory { $null = New-Item -ItemType Directory -Path $directory }
    $junction = Join-Path $fixtures 'directory-junction'
    Add-Control 'junction' 'METADATA' $junction { $null = New-Item -ItemType Junction -Path $junction -Target $directory }
    $adsBase = Join-Path $fixtures 'streams.dat'
    Add-Control 'ads_base' 'READ' $adsBase { [IO.File]::WriteAllBytes($adsBase, $seed) }
    $ads = $adsBase + ':fixture_stream'
    Add-Control 'ads' 'READ' $ads { [IO.File]::WriteAllBytes($ads, $utf8.GetBytes('owned alternate DATA bytes')) }
    $aclParent = Join-Path $fixtures 'acl-parent'
    $null = New-Item -ItemType Directory -Path $aclParent
    $aclPath = Join-Path $aclParent 'acl.dat'
    Add-Control 'acl' 'READ' $aclPath {
        [IO.File]::WriteAllBytes($aclPath, $seed)
        $security = Get-Acl -LiteralPath $aclPath
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,
            [Security.AccessControl.FileSystemRights]::WriteData, [Security.AccessControl.AccessControlType]::Deny)
        $security.AddAccessRule($rule)
        Set-Acl -LiteralPath $aclPath -AclObject $security
    }
    $readonly = Join-Path $fixtures 'readonly.dat'
    Add-Control 'readonly' 'READ' $readonly {
        [IO.File]::WriteAllBytes($readonly, $seed)
        [IO.File]::SetAttributes($readonly, [IO.FileAttributes]::ReadOnly)
    }
    $locked = Join-Path $fixtures 'locked.dat'
    Add-Control 'locked' 'READ' $locked { [IO.File]::WriteAllBytes($locked, $seed) }
    Save-Json 'provisioning.json' $provision.ToArray()
    $before = Snapshot
    Save-Json 'before.json' $before
    Save-Json 'parent-security.json' ([ordered]@{ fixtures = Security-Facts $fixtures; aclParent = Security-Facts $aclParent })
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("FORGE_HOST_FACTS`t1")
    foreach ($id in $records.Keys) {
        $lines.Add("FILE`t$id`t" + [Convert]::ToBase64String($utf8.GetBytes($records[$id].path)) + "`t" + $records[$id].policy)
    }
    foreach ($pair in @(@('base', 'base'), @('base', 'equal'), @('base', 'hard'),
            @('base', 'symbolic'), @('directory', 'junction'), @('ads_base', 'ads'))) {
        if ($records.Contains($pair[0]) -and $records.Contains($pair[1])) { $lines.Add("PAIR`t" + $pair[0] + "`t" + $pair[1]) }
    }
    $manifest = Join-Path $evidence 'manifest.tsv'
    [IO.File]::WriteAllText($manifest, ($lines -join "`n") + "`n", $utf8)
    $lock = [IO.File]::Open($locked, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $lockedNative = [ordered]@{
        metadata = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($locked, $true, $false)
        genericRead = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($locked, $true, $true)
    }
    Save-Json 'while-locked-native.json' $lockedNative
    $factsProcess = Run-Process 'facts' $javaPath @('-Xmx64m', '-cp', $classes, 'HostFacts', $manifest)
    $lock.Dispose(); $lock = $null
    $facts = $factsProcess.stdout | ConvertFrom-Json -AsHashtable
    Require ($factsProcess.stderr.Length -eq 0) 'Java facts stderr empty'
    Require ($facts.schemaVersion -eq 1 -and $facts.scope -eq 'INSPECTION_ONLY') 'Java protocol schema and inspection scope'
    Require ($facts.manifestSHA256 -eq (Bytes $manifest).sha256) 'Java manifest binding'
    Require ($facts.host.javaVersion.StartsWith('21.')) 'Java facts runtime version21'
    Require ($facts.host.maxHeap -le 67108864 -and $facts.host.maxHeap -gt 0) 'Java max heap at most64MiB'
    $after = Snapshot
    Save-Json 'after.json' $after
    Require (@($provision | Where-Object status -ne 'CREATED').Count -eq 0) 'Every minimal Windows control provisioned without skip'
    Require ((Identity $before.base.follow) -eq (Identity $before.hard.follow)) 'Native hardlink identity equality'
    Require ($before.base.follow.links -eq 2 -and $before.hard.follow.links -eq 2) 'Native hardlink count exactly2'
    Require ((Identity $before.base.follow) -ne (Identity $before.equal.follow)) 'Equal-byte file has distinct native identity'
    Require ($before.base.content.sha256 -eq $before.equal.content.sha256) 'Equal-byte contrast is nonvacuous'
    Require ((Identity $before.base.follow) -eq (Identity $before.symbolic.follow)) 'Followed symbolic link selects expected referent'
    Require (($before.symbolic.nofollow.attributes -band 0x400) -ne 0 -and $before.symbolic.nofollow.reparseTag -ne 0) 'Native symbolic leaf reports reparse metadata'
    Require (($before.junction.nofollow.attributes -band 0x400) -ne 0 -and $before.junction.nofollow.reparseTag -ne 0) 'Native junction reports reparse metadata'
    Require ((Identity $before.directory.follow) -eq (Identity $before.junction.follow)) 'Junction follows expected directory'
    Require ($before.dangling.nofollow.status -eq 'OBSERVED' -and $before.dangling.follow.status -eq 'UNAVAILABLE') 'Dangling reparse leaf separated from missing referent'
    Require ($before.ads_base.dataStreams.status -eq 'OBSERVED') 'Native DATA stream enumeration complete within its scope'
    Require (@($before.ads_base.dataStreams.streams | Where-Object name -eq ':fixture_stream:$DATA').Count -eq 1) 'Named DATA stream visible'
    Require (@($before.acl.security.entries | Where-Object { $_.type -eq 'Deny' -and -not $_.inherited }).Count -ge 1) 'Explicit deny ACL observed'
    Require (@($before.acl.security.entries | Where-Object inherited).Count -ge 1) 'Inherited ACL entries observed'
    Require ($lockedNative.genericRead.status -eq 'UNAVAILABLE' -and $lockedNative.genericRead.openWin32Error -eq 32) 'Locked file denies GENERIC_READ with sharing violation'
    Require ($facts.files.locked.reads.status -eq 'UNAVAILABLE') 'Java locked content read unavailable'
    Require ($facts.files.readonly.dosFollow.value.readOnly -eq $true) 'Java read-only DOS contrast observed'
    foreach ($id in $records.Keys) {
        $a = $before[$id]; $b = $after[$id]
        foreach ($side in @('nofollow', 'follow')) {
            Require ($a[$side].status -eq $b[$side].status) ($id + ' stable native query outcome ' + $side)
            if ($a[$side].status -eq 'OBSERVED') {
                foreach ($key in @('attributes', 'links', 'size', 'creationTime', 'writeTime', 'legacyVolume', 'legacyFileId', 'fileIdStatus', 'volume128', 'fileId128', 'attributeTagStatus')) {
                    Require ($a[$side][$key] -ceq $b[$side][$key]) ($id + ' unchanged ' + $side + '/' + $key)
                }
                if ($a[$side].attributeTagStatus -eq 'OBSERVED') {
                    Require ($a[$side].reparseTag -eq $b[$side].reparseTag -and $a[$side].tagAttributes -eq $b[$side].tagAttributes) ($id + ' reparse tag and attributes preserved ' + $side)
                }
                $second = $a[$side].secondSimultaneousHandle
                Require ($second.status -eq 'OBSERVED' -and $second.volume128 -eq $a[$side].volume128 -and $second.fileId128 -eq $a[$side].fileId128) ($id + ' second simultaneous handle agrees ' + $side)
            }
        }
        Require (($a.security | ConvertTo-Json -Depth 12 -Compress) -ceq ($b.security | ConvertTo-Json -Depth 12 -Compress)) ($id + ' owner/group/DACL/control observations preserved')
        if ($a.Contains('content')) {
            Require (($a.content | ConvertTo-Json -Compress) -ceq ($b.content | ConvertTo-Json -Compress)) ($id + ' selected bytes preserved')
        }
        if ($a.Contains('dataStreams')) {
            Require (($a.dataStreams | ConvertTo-Json -Depth 12 -Compress) -ceq ($b.dataStreams | ConvertTo-Json -Depth 12 -Compress)) ($id + ' DATA stream observations preserved')
        }
        $j = $facts.files[$id]
        Require ($j.path -ceq $records[$id].path -and $j.policy -ceq $records[$id].policy) ($id + ' Java requested path/policy binding')
        if ($j.follow.status -eq 'OBSERVED' -and $a.follow.status -eq 'OBSERVED' -and ($a.follow.attributes -band 0x10) -eq 0) {
            Require ([uint64]$j.follow.value.size -eq [uint64]$a.follow.size) ($id + ' Java/native byte size')
            $epochNanos = ([decimal]$a.follow.writeTime - [decimal]116444736000000000) * 100
            Require ([decimal]$j.follow.value.modifiedNanos -eq $epochNanos) ($id + ' Java/native modified time')
        }
        if ($records[$id].policy -eq 'READ' -and $id -notin @('ads', 'locked')) {
            Require ($j.reads.status -eq 'OBSERVED') ($id + ' Java double read observed')
            foreach ($read in @('first', 'second')) {
                Require ($j.reads.value[$read].sha256 -eq $a.content.sha256 -and $j.reads.value[$read].bytes -eq $a.content.bytes) ($id + ' Java/native content ' + $read)
            }
        }
        if ($id -eq 'ads' -and $j.reads.status -eq 'OBSERVED') {
            Require ($j.reads.value.first.sha256 -eq $a.content.sha256 -and $j.reads.value.second.sha256 -eq $a.content.sha256) 'Java ADS content agrees if provider accepts path'
        }
    }
    $expectedPairs = @('base:base', 'base:equal', 'base:hard', 'base:symbolic', 'directory:junction', 'ads_base:ads') | Sort-Object
    $observedPairs = @($facts.pairs | ForEach-Object { $_.left + ':' + $_.right }) | Sort-Object
    Require (($expectedPairs -join ',') -ceq ($observedPairs -join ',')) 'Java exact PAIR multiset'
    foreach ($pair in $facts.pairs) {
        if ($pair.left -eq 'base' -and $pair.right -in @('base', 'equal', 'hard', 'symbolic')) {
            Require ($pair.isSameFile.status -eq 'OBSERVED') 'Java pair relation observed'
            Require ($pair.isSameFile.value -eq ($pair.right -ne 'equal')) ('Java pair expected identity ' + $pair.right)
        }
    }
    Require ((Identity $before.ads_base.follow) -eq (Identity $before.ads.follow)) 'ADS/base file identity does not identify selected stream bytes'
    Require ($before.ads_base.content.sha256 -ne $before.ads.content.sha256) 'ADS contrast contains different selected bytes'
    Require ((($facts.files.Keys | Sort-Object) -join ',') -ceq (($records.Keys | Sort-Object) -join ',')) 'Java exact selected ID inventory'
    $retained = [ordered]@{}
    $copyDirectory = Join-Path $evidence 'selected-bytes'
    $null = New-Item -ItemType Directory -Path $copyDirectory
    foreach ($id in $records.Keys) {
        if ($records[$id].policy -ne 'READ') { continue }
        $path = $records[$id].path
        $state = Bytes $path
        Require ($state.bytes -le 1048576) ($id + ' bounded retained selected bytes')
        $copy = Join-Path $copyDirectory ($id + '.bytes')
        $raw = [IO.File]::ReadAllBytes($path)
        $stream = [IO.File]::Open($copy, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($raw, 0, $raw.Length) } finally { $stream.Dispose() }
        $copyState = Bytes $copy
        Require ($copyState.sha256 -eq $state.sha256 -and $copyState.bytes -eq $state.bytes -and
            $state.sha256 -eq $after[$id].content.sha256) ($id + ' retained copy agrees with post-probe byte observation')
        $retained[$id] = [ordered]@{ path = $copy; original = $path; bytes = $copyState.bytes; sha256 = $copyState.sha256 }
    }
    Save-Json 'retained-bytes.json' $retained
    foreach ($name in $sourceHashes.Keys) {
        Require ((Bytes (Join-Path $PSScriptRoot $name)).sha256 -eq $sourceHashes[$name].sha256) ($name + ' probe source unchanged')
    }
    Save-Json 'source-hashes.json' $sourceHashes
    foreach ($key in $toolHashes.Keys) {
        $toolHashes[$key].after = Bytes $toolHashes[$key].path
        Require ($toolHashes[$key].before.sha256 -eq $toolHashes[$key].after.sha256 -and
            $toolHashes[$key].before.bytes -eq $toolHashes[$key].after.bytes) ($key + ' launcher bytes unchanged')
    }
    Save-Json 'tool-after.json' ([ordered]@{ tools = $toolHashes; scope = 'Resolved launcher executable bytes/version only; JDK dependencies not authenticated' })
    $status = 'READ_ONLY_HOST_OBSERVATIONS_COMPLETE'
} catch {
    $failure = [ordered]@{ exception = $_.Exception.GetType().FullName; message = $_.Exception.Message; position = $_.InvocationInfo.PositionMessage }
    $status = 'HOST_OBSERVATIONS_FAILED_OR_INCOMPLETE'
} finally {
    if ($null -ne $lock) {
        try { $lock.Dispose() } catch {
            $cleanupFaults.Add([ordered]@{ phase = 'lock-dispose'; exception = $_.Exception.GetType().FullName; message = $_.Exception.Message })
        }
    }
    if ($nativeLoaded) {
        try { Save-Json 'finally-after.json' (Snapshot) } catch {
            $cleanupFaults.Add([ordered]@{ phase = 'finally-after-observation'; exception = $_.Exception.GetType().FullName; message = $_.Exception.Message })
        }
    }
    if ($cleanupFaults.Count -gt 0) { $status = 'HOST_OBSERVATIONS_FAILED_OR_INCOMPLETE' }
    $result = [ordered]@{ schemaVersion = 1; status = $status; scope = 'INSPECTION_ONLY'; root = $root
        powershell = $PSVersionTable.PSVersion.ToString(); os = [Environment]::OSVersion.VersionString
        checks = $checks.ToArray(); provisioned = $provision.ToArray(); failure = $failure; cleanupFaults = $cleanupFaults.ToArray()
        limits = @('No target replacement, independent backup, transaction receipt, metadata preservation or durability operation.',
            'Native and Java facts are observations at separate times, not an atomic snapshot or protection against races.',
            'SACL, integrity labels, resource claims and full security/EA metadata remain UNKNOWN.',
            'FindFirstStreamW covers DATA streams only; Java user views are not a complete native namespace inventory.',
            'Access-time observations may change from reading; not restored or included in unchanged-metadata checks.',
            'Attribute-only native opens may succeed while FileShare.None prevents content access; no replacement permission inferred.',
            'All fixtures remain retained; none is executable or a user target. Native Windows acceptance requires this actual run.') }
    Save-Json 'result.json' $result
    Write-Output ('host-observations-results=' + $root)
}
if ($null -ne $failure) { throw ('Host observation failed; retained evidence: ' + $root + '; ' + $failure.message) }

if ($cleanupFaults.Count -gt 0) { throw ('Host observation cleanup/evidence failed; retained evidence: ' + $root) }
