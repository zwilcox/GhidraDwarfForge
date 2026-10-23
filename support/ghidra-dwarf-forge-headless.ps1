param(
    [string] $GhidraDirectory = $env:GHIDRA_INSTALL_DIR,
    [string] $Libdwarf,
    [string] $Libdwarfp,
    [Alias('Input')] [string] $OriginalElf,
    [string] $Output,
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
            $Libdwarf, $Libdwarfp, $headless, $PSCommandPath)) {
        Assert-LogNotAlias $protected
    }
    if (-not [string]::IsNullOrWhiteSpace($selectedOutput)) {
        Assert-LogNotAlias "$selectedOutput.c"
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
            '-import', $Import, '-analysisTimeoutPerFile', "$AnalysisTimeout",
            '-postScript', 'GhidraDwarfForge.java'
        ) + $exportOptions
    }
    else {
        if (-not (Test-Path -LiteralPath $ProjectDirectory -PathType Container)) {
            Exit-Usage "project directory does not exist: $ProjectDirectory"
        }
        $headlessArguments = @(
            $ProjectDirectory, $ProjectName, '-readOnly', '-noanalysis',
            '-process', $Program, '-postScript', 'GhidraDwarfForge.java'
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
