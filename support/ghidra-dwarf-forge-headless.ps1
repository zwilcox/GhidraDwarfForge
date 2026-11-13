param(
    [string] $GhidraDirectory = $env:GHIDRA_INSTALL_DIR,
    [string] $Libdwarf,
    [string] $Libdwarfp,
    [Alias('Input')] [string] $OriginalElf,
    [string] $Output,
    [switch] $GdbLoader,
    [string] $Formatters,
    [string] $CompressDebugSections = 'none',
    [string] $SourceContext = 'off',
    [string] $SourceLines,
    [string] $TargetProfile,
    [string] $RawFirmware,
    [string] $FirmwareInputs,
    [ValidateSet('off', 'strict', 'conditioned')] [string] $SynthesizeUnwind = 'off',
    [string] $UnwindStackSeparation,
    [ValidateSet('off', 'fixed')] [string] $UnwindRelocatedPointers = 'off',
    [string] $AnnotationRecordLimit,
    [string] $AnnotationTextLimit,
    [string] $AnnotationSourceLimit,
    [string] $Import,
    [string] $ProjectDirectory,
    [string] $ProjectName,
    [string] $Program,
    [string] $Log,
    [ValidateRange(1, 2147483647)] [int] $AnalysisTimeout = 120
)

$ErrorActionPreference = 'Stop'

function Exit-Usage([string] $Message) {
    [Console]::Error.WriteLine("ghidra-dwarf-forge-headless: $Message")
    exit 64
}

if ($CompressDebugSections -notin @('none', 'zlib')) {
    Exit-Usage '-CompressDebugSections must be none or zlib'
}
if ($SourceContext -cnotin @('off', 'assembly', 'pcode', 'both')) {
    Exit-Usage '-SourceContext must be off, assembly, pcode or both'
}
if ($PSBoundParameters.ContainsKey('TargetProfile') -and $TargetProfile -cne 'cortex-m3') {
    Exit-Usage '-TargetProfile must be cortex-m3'
}
if ($PSBoundParameters.ContainsKey('RawFirmware') -and $RawFirmware -cne 'cortex-m3') {
    Exit-Usage '-RawFirmware must be cortex-m3'
}
if ($PSBoundParameters.ContainsKey('FirmwareInputs') -and [string]::IsNullOrWhiteSpace($FirmwareInputs)) {
    Exit-Usage '-FirmwareInputs requires a selection file'
}
if ($PSBoundParameters.ContainsKey('SourceLines')) {
    $sourceLineValue = 0
    if ($SourceLines -cnotmatch '^[1-9][0-9]{0,9}$' -or
            -not [int]::TryParse($SourceLines, [ref] $sourceLineValue)) {
        Exit-Usage '-SourceLines must be an integer from 1 to 2147483647'
    }
}

function Get-AbsoluteFilesystemPath([string] $Path) {
    $provider = $null
    $drive = $null
    # Set-Location does not update Environment.CurrentDirectory. Resolve with
    # PowerShell's filesystem provider, just as Tee-Object resolves its path.
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $Path, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem') {
        throw "path must use the filesystem provider: $Path"
    }
    return $full
}

function Get-CanonicalPath([string] $Path, [int] $LinkDepth = 0) {
    if ($LinkDepth -gt 40) {
        throw "too many symbolic links while resolving $Path"
    }
    $full = Get-AbsoluteFilesystemPath $Path
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([string]::IsNullOrEmpty($parent)) {
        return $full
    }
    $canonicalParent = Get-CanonicalPath $parent $LinkDepth
    $candidate = Join-Path $canonicalParent ([IO.Path]::GetFileName($full))
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.LinkType -in @('SymbolicLink', 'Junction')) {
        $target = @($item.Target)[0]
        if (-not [IO.Path]::IsPathRooted($target)) {
            $target = Join-Path $canonicalParent $target
        }
        return Get-CanonicalPath $target ($LinkDepth + 1)
    }
    return $candidate
}

function Get-FileIdentity([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    if ($env:OS -ne 'Windows_NT') {
        # Enables the same collision regression on PowerShell's Unix runtime.
        $stat = (Get-Item -LiteralPath $Path -Force).UnixStat
        if ($null -eq $stat) {
            throw "file identity is unavailable for $Path"
        }
        return "$($stat.DeviceId):$($stat.Inode)"
    }
    return [GhidraDwarfForge.LogFileIdentity]::Get($Path)
}

function Assert-LogNotAlias([string] $ProtectedPath) {
    if ([string]::IsNullOrWhiteSpace($ProtectedPath)) {
        return
    }
    $canonical = Get-CanonicalPath $ProtectedPath
    $identity = Get-FileIdentity $canonical
    if ([string]::Equals($script:canonicalLog, $canonical, $script:pathComparison) -or
            ($null -ne $script:logIdentity -and $script:logIdentity -eq $identity)) {
        Exit-Usage "log path aliases a protected input/output file: $ProtectedPath"
    }
}

function Assert-LogNotInTree([string] $ProtectedDirectory) {
    $canonical = Get-CanonicalPath $ProtectedDirectory
    $prefix = $canonical.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if ([string]::Equals($script:canonicalLog, $canonical, $script:pathComparison) -or
            $script:canonicalLog.StartsWith($prefix, $script:pathComparison)) {
        Exit-Usage "log path is inside a protected library/project directory: $ProtectedDirectory"
    }
    if ($null -ne $script:logIdentity -and
            (Test-Path -LiteralPath $canonical -PathType Container)) {
        foreach ($file in Get-ChildItem -LiteralPath $canonical -File -Recurse -Force) {
            Assert-LogNotAlias $file.FullName
        }
    }
}

function Test-SourceBundleName([string] $Name) {
    $pattern = '^forge-src-([0-9]{6}-[0-9a-f]{64}\.c|[0-9a-f]{64}\.json)$'
    if ($env:OS -eq 'Windows_NT') { return $Name -match $pattern }
    return $Name -cmatch $pattern
}

function Assert-LogNotSourceBundle([string] $Directory) {
    $canonical = Get-CanonicalPath $Directory
    if ([string]::Equals([IO.Path]::GetDirectoryName($script:canonicalLog), $canonical,
            $script:pathComparison) -and (Test-SourceBundleName ([IO.Path]::GetFileName($script:canonicalLog)))) {
        Exit-Usage "log path aliases the reserved source bundle namespace: $Log"
    }
    if (Test-Path -LiteralPath $canonical -PathType Container) {
        foreach ($file in Get-ChildItem -LiteralPath $canonical -Force) {
            if (Test-SourceBundleName $file.Name) { Assert-LogNotAlias $file.FullName }
        }
    }
}

function Assert-SafeLogPath {
    if ($projectMode -and [string]::IsNullOrWhiteSpace($OriginalElf)) {
        Exit-Usage '-Log in existing-project mode requires -OriginalElf so the original and default outputs can be protected; otherwise omit -Log to use a private temporary log'
    }
    if ($env:OS -eq 'Windows_NT') {
        $absoluteLog = Get-AbsoluteFilesystemPath $Log
        $root = [IO.Path]::GetPathRoot($absoluteLog)
        if ($absoluteLog.Substring($root.Length).Contains(':')) {
            Exit-Usage 'log path must not name an alternate data stream'
        }
    }
    if ($env:OS -eq 'Windows_NT' -and
            $null -eq ('GhidraDwarfForge.LogFileIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace GhidraDwarfForge {
    public static class LogFileIdentity {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME AccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME WriteTime;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string path, uint access,
            uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle,
            out FileInformation information);
        public static string Get(string path) {
            using (var handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                FileInformation info;
                if (!GetFileInformationByHandle(handle, out info))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return info.VolumeSerial + ":" + info.IndexHigh + ":" + info.IndexLow;
            }
        }
    }
}
'@
    }
    $script:pathComparison = if ($env:OS -eq 'Windows_NT') {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    $script:canonicalLog = Get-CanonicalPath $Log
    $script:logIdentity = Get-FileIdentity $script:canonicalLog
    if ((Test-Path -LiteralPath $Log) -and
            -not (Test-Path -LiteralPath $Log -PathType Leaf)) {
        Exit-Usage "log path is not a regular file: $Log"
    }
    $selectedInput = if ([string]::IsNullOrWhiteSpace($OriginalElf)) { $Import } else { $OriginalElf }
    $selectedOutput = $Output
    if ([string]::IsNullOrWhiteSpace($selectedOutput) -and
            -not [string]::IsNullOrWhiteSpace($selectedInput)) {
        $selectedOutput = "$selectedInput.dbg"
    }
    foreach ($protected in @($Import, $OriginalElf, $selectedOutput,
            $Libdwarf, $Libdwarfp, $Formatters, $headless, $PSCommandPath)) {
        Assert-LogNotAlias $protected
    }
    if (-not [string]::IsNullOrWhiteSpace($selectedOutput)) {
        Assert-LogNotAlias "$selectedOutput.c"
        Assert-LogNotAlias "$selectedOutput.gdb.py"
        Assert-LogNotAlias "$selectedOutput.unwind.json"
        Assert-LogNotAlias "$selectedOutput.firmware.json"
        $formatterHasher = [Security.Cryptography.SHA256]::Create()
        try {
            $formatterHash = [BitConverter]::ToString($formatterHasher.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFileName($selectedOutput)))).Replace('-', '').ToLowerInvariant()
        }
        finally { $formatterHasher.Dispose() }
        $formatterDirectory = [IO.Path]::GetDirectoryName((Get-AbsoluteFilesystemPath $selectedOutput))
        Assert-LogNotAlias (Join-Path $formatterDirectory "forge_formatters_$formatterHash.py")
        Assert-LogNotSourceBundle $formatterDirectory
    }
    if ($projectMode) {
        Assert-LogNotAlias (Join-Path $ProjectDirectory "$ProjectName.gpr")
        Assert-LogNotAlias (Join-Path $ProjectDirectory "$ProjectName.lock")
        Assert-LogNotInTree (Join-Path $ProjectDirectory "$ProjectName.rep")
    }
    Assert-LogNotInTree (Join-Path $PSScriptRoot '..\os')
    Assert-LogNotInTree (Join-Path $PSScriptRoot '..\lib')
    Assert-LogNotInTree (Join-Path $GhidraDirectory 'Ghidra\Extensions\GhidraDwarfForge\os')
    Assert-LogNotInTree (Join-Path $GhidraDirectory 'Ghidra\Extensions\GhidraDwarfForge\lib')
}

if ([string]::IsNullOrWhiteSpace($GhidraDirectory)) {
    Exit-Usage '-GhidraDirectory or GHIDRA_INSTALL_DIR is required'
}
if ([string]::IsNullOrWhiteSpace($Libdwarf) -ne
        [string]::IsNullOrWhiteSpace($Libdwarfp)) {
    Exit-Usage '-Libdwarf and -Libdwarfp must be supplied together'
}
$importMode = -not [string]::IsNullOrWhiteSpace($Import)
$projectValues = @($ProjectDirectory, $ProjectName, $Program) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$projectMode = $projectValues.Count -ne 0
if ([int]$importMode + [int]$projectMode -ne 1) {
    Exit-Usage 'select exactly one of -Import or existing-project mode'
}
if ($projectMode -and $projectValues.Count -ne 3) {
    Exit-Usage 'existing-project mode requires -ProjectDirectory, -ProjectName, and -Program'
}
if ($projectMode -and $ProjectName -match '[/\\]') {
    Exit-Usage '-ProjectName must not contain a path separator'
}
if ($RawFirmware) {
    if (-not $projectMode -or [string]::IsNullOrWhiteSpace($OriginalElf)) {
        Exit-Usage '-RawFirmware requires existing-project mode and -Input'
    }
    if (-not $Program.StartsWith('/')) {
        Exit-Usage 'raw -Program must be an absolute project path'
    }
    if ($TargetProfile -or $Formatters -or $GdbLoader) {
        Exit-Usage 'raw mode cannot combine -TargetProfile, -Formatters or -GdbLoader'
    }
    if ($SynthesizeUnwind -cne 'off' -or $UnwindStackSeparation -or $UnwindRelocatedPointers -cne 'off') {
        Exit-Usage 'raw mode does not support unwind synthesis'
    }
}
elseif ($FirmwareInputs) {
    Exit-Usage '-FirmwareInputs requires -RawFirmware'
}
if ($FirmwareInputs -and $Log) {
    Exit-Usage '-FirmwareInputs requires a private temporary log; omit -Log to protect every selected input'
}

$headless = Join-Path $GhidraDirectory 'support\analyzeHeadless.bat'
$requiredFiles = @($headless)
if (-not [string]::IsNullOrWhiteSpace($Libdwarf)) {
    $requiredFiles += @($Libdwarf, $Libdwarfp)
}
foreach ($required in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Exit-Usage "required file does not exist: $required"
    }
}

$temporaryRoot = $null
$temporaryLog = $false
if ([string]::IsNullOrWhiteSpace($Log)) {
    $Log = Join-Path ([IO.Path]::GetTempPath()) (
        "ghidra-dwarf-forge-headless-report-$([guid]::NewGuid()).log")
    $temporaryLog = $true
}
else {
    try {
        $logParent = Split-Path -Parent (Get-AbsoluteFilesystemPath $Log)
        if (-not (Test-Path -LiteralPath $logParent -PathType Container)) {
            Exit-Usage "log directory does not exist: $logParent"
        }
        Assert-SafeLogPath
    }
    catch {
        Exit-Usage "cannot validate log path: $($_.Exception.Message)"
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($Libdwarf)) {
        $exportOptions = @('--packaged-natives')
        $packagedDirectory = Join-Path $PSScriptRoot '..\os\win_x86_64'
        if (Test-Path $packagedDirectory -PathType Container) {
            $env:PATH = "$(Resolve-Path $packagedDirectory);$env:PATH"
        }
    }
    else {
        $exportOptions = @('--libdwarf', $Libdwarf, '--libdwarfp', $Libdwarfp)
    }
    if (-not [string]::IsNullOrWhiteSpace($OriginalElf)) {
        $exportOptions += @('--input', $OriginalElf)
    }
    if (-not [string]::IsNullOrWhiteSpace($Output)) {
        $exportOptions += @('--output', $Output)
    }
    if (-not [string]::IsNullOrWhiteSpace($Formatters)) {
        $exportOptions += @("--formatters=$Formatters")
    }
    if ($GdbLoader) {
        $exportOptions += @('--gdb-loader')
    }
    if ($CompressDebugSections -eq 'zlib') {
        $exportOptions += @('--compress-debug-sections=zlib')
    }
    if ($SynthesizeUnwind -cne 'off') {
        $exportOptions += @("--synthesize-unwind=$SynthesizeUnwind")
    }
    if ($PSBoundParameters.ContainsKey('UnwindStackSeparation')) {
        $exportOptions += @("--unwind-stack-separation=$UnwindStackSeparation")
    }
    if ($UnwindRelocatedPointers -cne 'off') {
        $exportOptions += @("--unwind-relocated-pointers=$UnwindRelocatedPointers")
    }
    if ($SourceContext -cne 'off') {
        $exportOptions += @("--source-context=$SourceContext")
    }
    if ($PSBoundParameters.ContainsKey('SourceLines')) {
        $exportOptions += @("--source-lines=$SourceLines")
    }
    if ($PSBoundParameters.ContainsKey('TargetProfile')) {
        $exportOptions += @("--target-profile=$TargetProfile")
    }
    if ($RawFirmware) {
        $exportOptions += @("--raw-firmware=$RawFirmware")
    }
    if ($FirmwareInputs) {
        $exportOptions += @("--firmware-inputs=$FirmwareInputs")
    }
    foreach ($entry in @(
        @('AnnotationRecordLimit', 'annotation-record-limit'),
        @('AnnotationTextLimit', 'annotation-text-limit'),
        @('AnnotationSourceLimit', 'annotation-source-limit')
    )) {
        if ($PSBoundParameters.ContainsKey($entry[0])) {
            $exportOptions += @("--$($entry[1])=$($PSBoundParameters[$entry[0]])")
        }
    }

    if ($importMode) {
        if (-not (Test-Path -LiteralPath $Import -PathType Leaf)) {
            Exit-Usage "import ELF does not exist: $Import"
        }
        if ([string]::IsNullOrWhiteSpace($OriginalElf)) {
            $exportOptions += @('--input', $Import)
        }
        $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
            "ghidra-dwarf-forge-headless-wrapper-$([guid]::NewGuid())")
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
        $headlessArguments = @(
            $temporaryRoot, 'GhidraDwarfForgeHeadless', '-deleteProject',
            '-import', $Import, '-loader', 'ElfLoader',
            '-analysisTimeoutPerFile', "$AnalysisTimeout",
            '-postScript', 'GhidraDwarfForge.java'
        ) + $exportOptions
    }
    else {
        if (-not (Test-Path -LiteralPath $ProjectDirectory -PathType Container)) {
            Exit-Usage "project directory does not exist: $ProjectDirectory"
        }
        $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
            "ghidra-dwarf-forge-headless-wrapper-$([guid]::NewGuid())")
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
        $savedProgram = $Program
        if (-not $savedProgram.StartsWith('/')) { $savedProgram = '/' + $savedProgram }
        $headlessArguments = @(
            $temporaryRoot, 'GhidraDwarfForgeHeadless', '-deleteProject', '-noanalysis',
            '-postScript', 'GhidraDwarfForgeReadOnly.java',
            (Get-AbsoluteFilesystemPath $ProjectDirectory), $ProjectName, $savedProgram
        ) + $exportOptions
    }

    & $headless @headlessArguments 2>&1 | Tee-Object -LiteralPath $Log
    $headlessStatus = $LASTEXITCODE
    $reportLines = @(Get-Content -LiteralPath $Log | Where-Object {
        $_ -match 'GhidraDwarfForge report: '
    })
    if ($reportLines.Count -ne 1) {
        [Console]::Error.WriteLine(
            "ghidra-dwarf-forge-headless: expected one export report, found $($reportLines.Count)")
        exit 12
    }
    if ($reportLines[0] -notmatch
            'GhidraDwarfForge report: \{"schemaVersion":[0-9]+,"status":"([A-Z]+)"') {
        [Console]::Error.WriteLine('ghidra-dwarf-forge-headless: malformed export report')
        exit 12
    }
    $status = $Matches[1]
    switch ($status) {
        { $_ -in @('SUCCESS', 'PARTIAL') } {
            if ($headlessStatus -ne 0) {
                [Console]::Error.WriteLine(
                    "ghidra-dwarf-forge-headless: Ghidra exited $headlessStatus after $status")
                exit 12
            }
            exit 0
        }
        'FATAL' { exit 10 }
        'CANCELLED' { exit 11 }
        default {
            [Console]::Error.WriteLine(
                "ghidra-dwarf-forge-headless: unknown report status: $status")
            exit 12
        }
    }
}
catch {
    [Console]::Error.WriteLine("ghidra-dwarf-forge-headless: $($_.Exception.Message)")
    exit 12
}
finally {
    if ($null -ne $temporaryRoot -and (Test-Path $temporaryRoot)) {
        Remove-Item -Recurse -Force $temporaryRoot
    }
    if ($temporaryLog -and (Test-Path $Log)) {
        Remove-Item -Force $Log
    }
}
