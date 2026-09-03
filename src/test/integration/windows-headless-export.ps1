param(
    [Parameter(Mandatory = $true)] [string] $GhidraDirectory,
    [Parameter(Mandatory = $true)] [string] $ConsumerDll,
    [Parameter(Mandatory = $true)] [string] $ProducerDll,
    [Parameter(Mandatory = $true)] [string] $LinuxReferenceDirectory
)

$ErrorActionPreference = 'Stop'
$repositoryDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$resultDirectory = Join-Path $repositoryDirectory 'build\test-results\windows-host'
$workDirectory = Join-Path $resultDirectory 'work'
$scriptDirectory = Join-Path $repositoryDirectory 'src\test\integration\ghidra_scripts'
$headless = Join-Path $GhidraDirectory 'support\analyzeHeadless.bat'
$reference = Join-Path $LinuxReferenceDirectory 'semantic.exec.reference'
$linuxInput = Join-Path $LinuxReferenceDirectory 'semantic.exec.stripped'
$linuxSidecar = Join-Path $LinuxReferenceDirectory 'semantic.exec.ghidra-forge.dbg'
$linuxSource = "$linuxSidecar.c"

foreach ($required in @($headless, $ConsumerDll, $ProducerDll, $reference,
        $linuxInput, $linuxSidecar, $linuxSource)) {
    if (-not (Test-Path $required -PathType Leaf)) {
        throw "required Windows integration input is missing: $required"
    }
}

if (Test-Path $workDirectory) {
    Remove-Item -Recurse -Force $workDirectory
}
New-Item -ItemType Directory -Force $workDirectory | Out-Null
$fixtureInput = Join-Path $workDirectory 'semantic.exec.stripped'
$sidecar = Join-Path $workDirectory 'semantic.exec.ghidra-forge.dbg'
$source = "$sidecar.c"
Copy-Item $linuxInput $fixtureInput
$beforeInputHash = (Get-FileHash -Algorithm SHA256 $fixtureInput).Hash
$env:PATH = "$(Split-Path -Parent $ConsumerDll);$env:PATH"

function Invoke-NativeChecked {
    param([string] $Command, [string[]] $Arguments)
    $lines = @(& $Command @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE`n$($lines -join "`n")"
    }
    return $lines
}

function Get-ElfSymbolAddress {
    param([string] $Name)
    $lines = Invoke-NativeChecked 'readelf.exe' @('-Ws', $reference)
    $match = $lines | Where-Object { "$_" -match "\s$([regex]::Escape($Name))$" } |
        Select-Object -First 1
    if ($null -eq $match) {
        throw "ELF reference symbol is missing: $Name"
    }
    $fields = "$match".Trim() -split '\s+'
    return "0x$($fields[1])"
}

$addAddress = Get-ElfSymbolAddress 'recovered_add'
$variadicAddress = Get-ElfSymbolAddress 'recovered_variadic'
$noReturnAddress = Get-ElfSymbolAddress 'recovered_spin'
$compositeAddress = Get-ElfSymbolAddress 'recovered_composite'
$globalAddress = Get-ElfSymbolAddress 'fixture_sink'
$scopedGlobalAddress = Get-ElfSymbolAddress 'scoped_counter'
$projectDirectory = Join-Path $env:RUNNER_TEMP "ghidra-dwarf-forge-windows-$([guid]::NewGuid())"
$log = Join-Path $resultDirectory 'headless.log'
New-Item -ItemType Directory -Force $projectDirectory | Out-Null

try {
    $headlessArguments = @(
        $projectDirectory, 'GhidraDwarfForgeWindows', '-deleteProject',
        '-import', $fixtureInput,
        '-analysisTimeoutPerFile', '120',
        '-scriptPath', $scriptDirectory,
        '-postScript', 'RenameFixtureFunction.java',
        $addAddress, $variadicAddress, $noReturnAddress, 'recovered_add',
        $globalAddress, $compositeAddress, $scopedGlobalAddress,
        '-postScript', 'GhidraDwarfForge.java',
        '--libdwarf', $ConsumerDll, '--libdwarfp', $ProducerDll,
        '--output', $sidecar
    )
    & $headless @headlessArguments 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless.bat failed with exit code $LASTEXITCODE"
    }
}
finally {
    if (Test-Path $projectDirectory) {
        Remove-Item -Recurse -Force $projectDirectory
    }
}

$logText = Get-Content -Raw $log
foreach ($pattern in @(
        'GhidraDwarfForge symbol export PASS',
        'GhidraDwarfForge report: {"schemaVersion":1,"status":"PARTIAL"',
        '"validation":{"status":"NOT_RUN"}',
        '"native":{"libdwarfVersion":"2.3.2"}',
        'REPORT: Import succeeded',
        'Applied USER_DEFINED extern int external_counter declaration',
        'Applied USER_DEFINED int analyst_scope::scoped_counter at')) {
    if ($logText -notmatch [regex]::Escape($pattern)) {
        throw "headless log is missing: $pattern"
    }
}
if (-not (Test-Path $sidecar -PathType Leaf) -or
        -not (Test-Path $source -PathType Leaf)) {
    throw 'headless export did not publish both final artifacts'
}
if ((Get-ChildItem $workDirectory -Force | Where-Object Name -Match '\.stage\.').Count -ne 0) {
    throw 'headless export left a staging file behind'
}
$afterInputHash = (Get-FileHash -Algorithm SHA256 $fixtureInput).Hash
if ($beforeInputHash -ne $afterInputHash) {
    throw 'Windows-hosted export modified the original ELF input'
}
$sourceBytes = [System.IO.File]::ReadAllBytes($source)
if ($sourceBytes -contains 13) {
    throw 'Windows-hosted synthetic source contains a carriage return'
}
$windowsSourceHash = (Get-FileHash -Algorithm SHA256 $source).Hash
$linuxSourceHash = (Get-FileHash -Algorithm SHA256 $linuxSource).Hash
if ($windowsSourceHash -ne $linuxSourceHash) {
    throw "Windows/Linux synthetic source differs: $windowsSourceHash != $linuxSourceHash"
}

$header = Invoke-NativeChecked 'readelf.exe' @('-h', $sidecar)
$inputHeader = Invoke-NativeChecked 'readelf.exe' @('-h', $fixtureInput)
$sections = Invoke-NativeChecked 'readelf.exe' @('-S', $sidecar)
$notes = Invoke-NativeChecked 'readelf.exe' @('-n', $sidecar)
$inputNotes = Invoke-NativeChecked 'readelf.exe' @('-n', $fixtureInput)
$info = Invoke-NativeChecked 'readelf.exe' @('--debug-dump=info', $sidecar)
$abbrev = Invoke-NativeChecked 'readelf.exe' @('--debug-dump=abbrev', $sidecar)
$strings = Invoke-NativeChecked 'readelf.exe' @('--string-dump=.debug_str', $sidecar)
$line = Invoke-NativeChecked 'readelf.exe' @('--debug-dump=decodedline', $sidecar)
$verify = Invoke-NativeChecked 'llvm-dwarfdump.exe' @('--verify', $sidecar)
foreach ($validatorOutput in @($header, $inputHeader, $sections, $notes, $inputNotes,
        $info, $abbrev, $strings, $line, $verify)) {
    if (($validatorOutput -join "`n") -match '(?i)\b(?:warning|error):') {
        throw "validator reported a warning or error:`n$($validatorOutput -join "`n")"
    }
}
if (($sections -join "`n") -notmatch '[.]debug_str' -or
        ($abbrev -join "`n") -notmatch 'DW_FORM_strp' -or
        ($strings -join "`n") -notmatch 'GhidraDwarfForge') {
    throw 'DWARF string-table policy validation failed'
}

function Get-ReadelfHeaderField {
    param([string[]] $Lines, [string] $Name)
    $match = $Lines | Where-Object { "$_" -match "^\s*$([regex]::Escape($Name)):\s+" } |
        Select-Object -First 1
    if ($null -eq $match) {
        throw "readelf header field is missing: $Name"
    }
    return ("$match" -replace "^\s*$([regex]::Escape($Name)):\s+", '').Trim()
}

foreach ($field in @('Class', 'Data', 'OS/ABI', 'Machine', 'Flags')) {
    $inputValue = Get-ReadelfHeaderField $inputHeader $field
    $sidecarValue = Get-ReadelfHeaderField $header $field
    if ($inputValue -ne $sidecarValue) {
        throw "ELF identity field differs for ${field}: $inputValue != $sidecarValue"
    }
}
$inputBuildId = ($inputNotes | Where-Object { "$_" -match '^\s*Build ID:\s+' } |
    Select-Object -First 1)
$sidecarBuildId = ($notes | Where-Object { "$_" -match '^\s*Build ID:\s+' } |
    Select-Object -First 1)
if ($null -eq $inputBuildId -or $null -eq $sidecarBuildId -or
        "$inputBuildId".Trim() -ne "$sidecarBuildId".Trim()) {
    throw "ELF build identity differs: $inputBuildId != $sidecarBuildId"
}
$header | Set-Content -Path (Join-Path $resultDirectory 'readelf-header.txt') -Encoding utf8
$inputHeader | Set-Content -Path (Join-Path $resultDirectory 'readelf-input-header.txt') -Encoding utf8
$sections | Set-Content -Path (Join-Path $resultDirectory 'readelf-sections.txt') -Encoding utf8
$notes | Set-Content -Path (Join-Path $resultDirectory 'readelf-notes.txt') -Encoding utf8
$inputNotes | Set-Content -Path (Join-Path $resultDirectory 'readelf-input-notes.txt') -Encoding utf8
$info | Set-Content -Path (Join-Path $resultDirectory 'readelf-info.txt') -Encoding utf8
$abbrev | Set-Content -Path (Join-Path $resultDirectory 'readelf-abbrev.txt') -Encoding utf8
$line | Set-Content -Path (Join-Path $resultDirectory 'readelf-line.txt') -Encoding utf8
$verify | Set-Content -Path (Join-Path $resultDirectory 'llvm-verify.txt') -Encoding utf8

$infoText = $info -join "`n"
foreach ($pattern in @('DW_TAG_namespace', 'analyst_scope', 'scoped_counter',
        'external_counter', 'DW_AT_declaration', 'DW_AT_external',
        'DW_AT_calling_convention')) {
    if ($infoText -notmatch [regex]::Escape($pattern)) {
        throw "Windows DWARF is missing semantic marker: $pattern"
    }
}

$metadata = @(
    "input_sha256=$afterInputHash",
    "windows_sidecar_sha256=$((Get-FileHash -Algorithm SHA256 $sidecar).Hash)",
    "linux_sidecar_sha256=$((Get-FileHash -Algorithm SHA256 $linuxSidecar).Hash)",
    "source_sha256=$windowsSourceHash",
    'independent_dwarfdump=UNAVAILABLE_ON_WINDOWS_RUNNER',
    'windows_headless_export=PASS'
)
$metadata | Set-Content -Path (Join-Path $resultDirectory 'result.txt') -Encoding utf8
$metadata | ForEach-Object { Write-Host $_ }
