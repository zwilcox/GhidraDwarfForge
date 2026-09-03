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
    if (-not (Test-Path $required -PathType Leaf)) {
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
    $logParent = Split-Path -Parent ([IO.Path]::GetFullPath($Log))
    if (-not (Test-Path $logParent -PathType Container)) {
        Exit-Usage "log directory does not exist: $logParent"
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
        if (-not (Test-Path $Import -PathType Leaf)) {
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
        if (-not (Test-Path $ProjectDirectory -PathType Container)) {
            Exit-Usage "project directory does not exist: $ProjectDirectory"
        }
        $headlessArguments = @(
            $ProjectDirectory, $ProjectName, '-readOnly', '-noanalysis',
            '-process', $Program, '-postScript', 'GhidraDwarfForge.java'
        ) + $exportOptions
    }

    & $headless @headlessArguments 2>&1 | Tee-Object -FilePath $Log
    $headlessStatus = $LASTEXITCODE
    $reportLines = @(Get-Content $Log | Where-Object {
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
