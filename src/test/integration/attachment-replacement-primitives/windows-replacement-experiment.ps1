# Ignored owned-fixture experiment. No product transaction or arbitrary target paths.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$WorkspaceParent)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Native Windows and PowerShell7 required; no emulation claim.'
}
$parent = (Resolve-Path -LiteralPath $WorkspaceParent).ProviderPath
if (-not [IO.Directory]::Exists($parent)) { throw 'Existing owned workspace parent required.' }
$root = Join-Path $parent ('replacement.' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$fixtures = Join-Path $root 'fixtures'
$evidence = Join-Path $root 'evidence'
$null = New-Item -ItemType Directory -Path $fixtures, $evidence
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$paths = [ordered]@{}
$operations = [Collections.Generic.List[object]]::new()
$checks = [Collections.Generic.List[string]]::new()
$cleanupFaults = [Collections.Generic.List[object]]::new()
$primaryFailure = $null
$held = $null
$nativeLoaded = $false
$phase = 'setup'

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $checks.Add($Message)
}
function Owned([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Path escaped the newly owned fixture root.'
    }
    return $full
}
function Save([string]$Name, $Value) {
    if ($Name -notmatch '^[a-z0-9-]+\.json$') { throw 'Invalid fixed evidence name.' }
    $raw = $utf8.GetBytes(($Value | ConvertTo-Json -Depth 40) + "`n")
    $s = [IO.File]::Open((Owned (Join-Path $evidence $Name)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $s.Write($raw, 0, $raw.Length) } finally { $s.Dispose() }
}
function Bytes([string]$Path) {
    $s = [IO.File]::Open((Owned $Path), [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        if ($s.Length -gt 4096) { throw 'Fixture exceeds bounded evidence size.' }
        $raw = [byte[]]::new([int]$s.Length)
        $s.ReadExactly($raw, 0, $raw.Length)
        return [ordered]@{ bytes = $raw.Length; sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
            base64 = [Convert]::ToBase64String($raw) }
    } finally { $s.Dispose() }
}
function Register([string]$Name, [string]$Leaf) {
    if ($paths.Contains($Name)) { throw 'Duplicate fixture ID.' }
    $path = Owned (Join-Path $fixtures $Leaf)
    $paths[$Name] = $path
    return $path
}
function New-Bytes([string]$Path, [string]$Text) {
    $raw = $utf8.GetBytes($Text)
    $s = [IO.File]::Open((Owned $Path), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $s.Write($raw, 0, $raw.Length) } finally { $s.Dispose() }
}
function Security([string]$Path) {
    $acl = Get-Acl -LiteralPath (Owned $Path)
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    return [ordered]@{ owner = $sd.Owner.Value; group = $sd.Group.Value; flags = [int]$sd.ControlFlags
        accessSddl = $sd.GetSddlForm([Security.AccessControl.AccessControlSections]::Access)
        scope = 'Path-based owner/group/DACL only; complete security/SACL/EA UNKNOWN' }
}
function Snapshot {
    $all = [ordered]@{}
    foreach ($name in $paths.Keys) {
        $path = Owned $paths[$name]
        $n = [ForgeHostResearch.NativeWindowsHostFacts]::Observe($path, $false, $false)
        $entry = [ordered]@{ path = $path; native = $n }
        if ($n.status -eq 'OBSERVED') {
            if (($n.attributes -band 0x400) -ne 0) { throw 'Unexpected reparse fixture.' }
            $entry.security = Security $path
            if (($n.attributes -band 0x10) -eq 0) {
                $entry.content = Bytes $path
                $streams = [ForgeHostResearch.NativeWindowsHostFacts]::DataStreams($path)
                $entry.streamEnumeration = $streams
                $entry.streamBytes = [ordered]@{}
                if ($streams.status -eq 'OBSERVED') {
                    foreach ($stream in @($streams.streams | Sort-Object name)) {
                        if ($stream.name -eq '::$DATA') { continue }
                        if ($stream.name -notmatch '^:[a-z_]{1,32}:\$DATA$') { throw 'Unexpected owned stream spelling.' }
                        $entry.streamBytes[$stream.name] = Bytes ($path + $stream.name)
                    }
                }
            }
        }
        $all[$name] = $entry
    }
    return $all
}
function Identity($Entry) {
    Require ($Entry.native.status -eq 'OBSERVED' -and $Entry.native.fileIdStatus -eq 'OBSERVED') 'Native128 identity available'
    return $Entry.native.volume128 + ':' + $Entry.native.fileId128
}
function Stable($Entry) {
    $n = $Entry.native
    Require ($Entry.streamEnumeration.status -ceq 'OBSERVED') 'Stable-byte comparison requires observed DATA enumeration'
    return ([ordered]@{ identity = Identity $Entry; attributes = $n.attributes; links = $n.links
        size = $n.size; creation = $n.creationTime; write = $n.writeTime; security = $Entry.security
        tagStatus = $n.attributeTagStatus; reparseTag = $n.reparseTag; tagAttributes = $n.tagAttributes
        content = $Entry.content; streamStatus = $Entry.streamEnumeration.status
        streams = $Entry.streamBytes } | ConvertTo-Json -Depth 30 -Compress)
}
function Selected-Bytes($Entry) {
    Require ($Entry.streamEnumeration.status -eq 'OBSERVED') 'Complete selected DATA enumeration observed'
    $rows = @($Entry.streamEnumeration.streams | Sort-Object name)
    Require ($rows.Count -eq $Entry.streamBytes.Count + 1 -and @($rows.name | Select-Object -Unique).Count -eq $rows.Count) 'Exact unique default and named DATA inventory'
    $selected = @(
        foreach ($row in $rows) {
            $bytes = if ($row.name -ceq '::$DATA') { $Entry.content } else { $Entry.streamBytes[$row.name] }
            Require ($null -ne $bytes -and $bytes.bytes -eq $row.size) 'Observed stream size equals retained byte count'
            [ordered]@{ name = $row.name; bytes = $bytes.bytes; sha256 = $bytes.sha256 }
        }
    )
    Require (@($rows | Where-Object { $_.name -ceq '::$DATA' }).Count -eq 1) 'Exactly one default DATA stream'
    return ConvertTo-Json -InputObject $selected -Depth 10 -Compress
}
function Copy-New([string]$Source, [string]$Destination) {
    $observation = [ForgeHostResearch.WindowsReplacementPrimitives]::CopyNew((Owned $Source), (Owned $Destination))
    $operations.Add($observation)
    return $observation
}
function Replace-Owned([string]$Target, [string]$Candidate) {
    $observation = [ForgeHostResearch.WindowsReplacementPrimitives]::Replace((Owned $Target), (Owned $Candidate))
    $operations.Add($observation)
    return $observation
}

try {
    Add-Type -Path (Join-Path $PSScriptRoot 'NativeWindowsHostFacts.cs')
    Add-Type -Path (Join-Path $PSScriptRoot 'WindowsReplacementPrimitives.cs')
    $nativeLoaded = $true
    Save 'native-layouts.json' ([ForgeHostResearch.NativeWindowsHostFacts]::Layouts())
    $source = [ordered]@{}
    foreach ($name in @('NativeWindowsHostFacts.cs', 'WindowsReplacementPrimitives.cs', 'windows-replacement-experiment.ps1', 'api-provenance.json')) {
        $raw = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name))
        $source[$name] = [ordered]@{ bytes = $raw.Length; sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant() }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $evidence $name)
    }
    Save 'sources.json' $source
    $launcher = (Get-Process -Id $PID).MainModule.FileName
    $launcherBefore = [ordered]@{ path = $launcher; bytes = (Get-Item -LiteralPath $launcher).Length
        sha256 = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant() }
    Save 'host.json' ([ordered]@{ powershell = $PSVersionTable.PSVersion.ToString()
        os = [Environment]::OSVersion.VersionString; architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        filesystem = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)).DriveFormat
        launcher = $launcherBefore; dependencies = 'NOT_RETAINED_OR_AUTHENTICATED' })

    $phase = 'copy'
    $original = Register 'copy_original' 'copy-original.dat'
    $backup = Register 'copy_backup' 'copy-backup.dat'
    $sentinel = Register 'copy_sentinel' 'copy-existing.dat'
    New-Bytes $original 'owned source bytes; never executable'
    New-Bytes ($original + ':source_stream') 'owned source DATA'
    New-Bytes $sentinel 'exclusive destination sentinel'
    $acl = Get-Acl -LiteralPath $original
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,
        [Security.AccessControl.FileSystemRights]::WriteData, [Security.AccessControl.AccessControlType]::Deny))
    Set-Acl -LiteralPath $original -AclObject $acl
    [IO.File]::SetAttributes($original, [IO.FileAttributes]::ReadOnly)
    $copyBefore = Snapshot; Save 'copy-before.json' $copyBefore
    $copied = Copy-New $original $backup
    Save 'copy-api.json' $copied
    $copyAfter = Snapshot; Save 'copy-after.json' $copyAfter
    Require $copied.success 'CopyFileW owned exclusive backup succeeds'
    Require ((Identity $copyAfter.copy_original) -ne (Identity $copyAfter.copy_backup)) 'Copied backup has distinct native identity'
    Require ($copyAfter.copy_original.native.links -eq 1 -and $copyAfter.copy_backup.native.links -eq 1) 'Backup and source have one link'
    Require ((Stable $copyBefore.copy_original) -ceq (Stable $copyAfter.copy_original)) 'Copy leaves observed source unchanged except atime'
    Require ((Selected-Bytes $copyAfter.copy_original) -ceq (Selected-Bytes $copyAfter.copy_backup)) 'Copy exact default and named DATA inventories agree'
    Require (($copyAfter.copy_backup.native.attributes -band 1) -eq 1) 'Copy readonly attribute observed'
    Save 'copy-metadata-comparison.json' ([ordered]@{ source = $copyAfter.copy_original.security; backup = $copyAfter.copy_backup.security
        daclEqual = $copyAfter.copy_original.security.accessSddl -ceq $copyAfter.copy_backup.security.accessSddl
        scope = 'Observed owner/group/DACL/attribute comparison; not complete backup metadata or durability' })
    $collision = Copy-New $original $sentinel
    Save 'copy-collision-api.json' $collision
    $collisionAfter = Snapshot; Save 'copy-collision-after.json' $collisionAfter
    Require (-not $collision.success) 'CopyFileW failIfExists refuses existing destination'
    Require ((Stable $copyAfter.copy_sentinel) -ceq (Stable $collisionAfter.copy_sentinel)) 'Existing sentinel unchanged after copy failure'

    foreach ($mode in @('success', 'locked')) {
        $phase = 'replace-' + $mode
        $target = Register ($mode + '_target') ($mode + '-target.dat')
        $candidate = Register ($mode + '_candidate') ($mode + '-candidate.dat')
        $independentBackup = Register ($mode + '_backup') ($mode + '-backup.dat')
        New-Bytes $target ('owned original ' + $mode)
        New-Bytes ($target + ':original_only') 'original DATA'
        New-Bytes $candidate ('owned candidate ' + $mode)
        New-Bytes ($candidate + ':candidate_only') 'candidate DATA'
        $backupOp = Copy-New $target $independentBackup
        Save ($mode + '-backup-api.json') $backupOp
        Require $backupOp.success 'Independent backup copy succeeds before primitive'
        $before = Snapshot; Save ($mode + '-before.json') $before
        Require ((Identity $before[($mode + '_target')]) -ne (Identity $before[($mode + '_backup')])) 'Backup is independently copied, not a link'
        Require ($before[($mode + '_target')].native.links -eq 1 -and $before[($mode + '_backup')].native.links -eq 1) 'Target and independent backup each have one link before replacement'
        Require ((Selected-Bytes $before[($mode + '_target')]) -ceq (Selected-Bytes $before[($mode + '_backup')])) 'Independent backup selected bytes verified before replacement'
        Save ($mode + '-backup-metadata.json') ([ordered]@{
            targetSecurity = $before[($mode + '_target')].security; backupSecurity = $before[($mode + '_backup')].security
            targetAttributes = $before[($mode + '_target')].native.attributes
            backupAttributes = $before[($mode + '_backup')].native.attributes
            scope = 'Observed owner/group/DACL/attribute comparison only; byte agreement does not establish complete metadata' })
        if ($mode -eq 'locked') {
            $held = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            Save 'held-handle.json' ([ordered]@{ path = $target; access = 'Read'; sharing = 'ReadWrite'; deleteSharing = $false })
        }
        $outcome = Replace-Owned $target $candidate
        Save ($mode + '-replace-api.json') $outcome
        $after = Snapshot; Save ($mode + '-after-call.json') $after
        if ($mode -eq 'success') {
            Require $outcome.success 'ReplaceFileW positive owned primitive succeeds'
            Require ((Identity $after.success_target) -eq (Identity $before.success_candidate)) 'Installed identity comes from candidate'
            Require ($after.success_target.content.sha256 -eq $before.success_candidate.content.sha256) 'Installed default bytes are candidate bytes'
            Require ($after.success_candidate.native.status -eq 'UNAVAILABLE' -and $after.success_candidate.native.openWin32Error -eq 2) 'Candidate old name absent after success'
            Require ($after.success_target.streamBytes[':original_only:$DATA'].sha256 -eq $before.success_target.streamBytes[':original_only:$DATA'].sha256) 'Original nonconflicting DATA stream merged'
            Require ($after.success_target.streamBytes[':candidate_only:$DATA'].sha256 -eq $before.success_candidate.streamBytes[':candidate_only:$DATA'].sha256) 'Candidate DATA stream remains'
        } else {
            Require (-not $outcome.success -and $outcome.win32Error -eq 32) 'Deny-delete sharing blocks own ReplaceFileW'
            Require ((Stable $before.locked_target) -ceq (Stable $after.locked_target)) 'This sharing-failure target remains observed unchanged'
            Require ((Stable $before.locked_candidate) -ceq (Stable $after.locked_candidate)) 'This sharing-failure candidate remains observed unchanged'
            $held.Dispose(); $held = $null
            $afterClose = Snapshot; Save 'locked-after-close.json' $afterClose
            Require ((Stable $before.locked_target) -ceq (Stable $afterClose.locked_target)) 'Target remains unchanged after closing held handle'
            Require ((Stable $before.locked_candidate) -ceq (Stable $afterClose.locked_candidate)) 'Candidate remains unchanged after closing held handle'
        }
        Require ((Stable $before[($mode + '_backup')]) -ceq (Stable $after[($mode + '_backup')])) 'Independent backup unchanged across replacement attempt'
    }

    $phase = 'flush'
    $flushFile = Register 'flush_file' 'flush-file.dat'
    New-Bytes $flushFile 'owned flush return observation'
    $flushDir = Register 'flush_directory' 'flush-directory'
    $null = New-Item -ItemType Directory -Path $flushDir
    $flushBefore = Snapshot; Save 'flush-before.json' $flushBefore
    $fileFlush = [ForgeHostResearch.WindowsReplacementPrimitives]::Flush((Owned $flushFile), $false)
    $operations.Add($fileFlush); Save 'file-flush-api.json' $fileFlush
    $dirFlush = [ForgeHostResearch.WindowsReplacementPrimitives]::Flush((Owned $flushDir), $true)
    $operations.Add($dirFlush); Save 'directory-flush-api.json' $dirFlush
    $flushAfter = Snapshot; Save 'flush-after.json' $flushAfter
    Require ($fileFlush.stage -eq 'FLUSH' -and $fileFlush.success) 'Ordinary owned file FlushFileBuffers returns success'
    Require ((Stable $flushBefore.flush_file) -ceq (Stable $flushAfter.flush_file)) 'Flush leaves selected file observations unchanged except atime'
    # Directory outcome is explicitly observed, including OPEN/FLUSH failure; no durability assertion.
    $launcherAfter = [ordered]@{ path = $launcher; bytes = (Get-Item -LiteralPath $launcher).Length
        sha256 = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant() }
    Save 'launcher-after.json' $launcherAfter
    Require ($launcherAfter.sha256 -eq $launcherBefore.sha256 -and $launcherAfter.bytes -eq $launcherBefore.bytes) 'Observed PowerShell launcher bytes unchanged'
    $phase = 'complete'
} catch {
    $primaryFailure = [ordered]@{ phase = $phase; exception = $_.Exception.GetType().FullName
        message = $_.Exception.Message; position = $_.InvocationInfo.PositionMessage }
} finally {
    if ($null -ne $held) {
        try { $held.Dispose() } catch { $cleanupFaults.Add([ordered]@{ phase = 'held-close'; message = $_.Exception.Message }) }
    }
    if ($nativeLoaded) {
        try { Save 'finally-after.json' (Snapshot) } catch { $cleanupFaults.Add([ordered]@{ phase = 'final-snapshot'; message = $_.Exception.Message }) }
    }
    Save 'result.json' ([ordered]@{ schemaVersion = 1; status = $(if ($null -eq $primaryFailure -and $cleanupFaults.Count -eq 0) { 'OWNED_PRIMITIVE_OBSERVATIONS_COMPLETE' } else { 'FAILED_OR_INCOMPLETE' })
        root = $root; powershell = $PSVersionTable.PSVersion.ToString(); os = [Environment]::OSVersion.VersionString
        checks = $checks.ToArray(); operations = $operations.ToArray(); failure = $primaryFailure; cleanupFaults = $cleanupFaults.ToArray()
        limits = @('Only new owned nonexecutable fixtures; all files/evidence retained.',
            'No durable backup completeness, transaction, recovery, race safety or public host support claim.',
            'ReplaceFileW errors1176/1177 can partially change names/metadata; this run does not inject those outcomes.',
            'Denying delete sharing can block our own replacement, not provide conditional replacement ownership.',
            'File/directory flush returns do not establish namespace or power-loss durability. No volume flush or privilege request.',
            'Observed path security and DATA streams do not cover complete SACL/EA/labels/resource metadata; atime may change.') })
    Write-Output ('primitive-evidence=' + $root)
}
if ($null -ne $primaryFailure -or $cleanupFaults.Count -gt 0) { throw ('Owned primitive observation incomplete; evidence=' + $root) }
