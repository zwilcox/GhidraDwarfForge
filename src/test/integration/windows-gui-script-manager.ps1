param(
    [Parameter(Mandatory = $true)] [string] $GhidraDirectory,
    [Parameter(Mandatory = $true)] [string] $ModuleDirectory,
    [Parameter(Mandatory = $true)] [string] $Fixture,
    [Parameter(Mandatory = $true)] [string] $Reference
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) {
    throw 'The Windows Script Manager journey requires native Windows execution.'
}
$ghidra = (Resolve-Path -LiteralPath $GhidraDirectory).ProviderPath
$module = (Resolve-Path -LiteralPath $ModuleDirectory).ProviderPath
$fixturePath = (Resolve-Path -LiteralPath $Fixture).ProviderPath
$referencePath = (Resolve-Path -LiteralPath $Reference).ProviderPath
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).ProviderPath
foreach ($tool in @('java', 'javac', 'readelf.exe', 'llvm-dwarfdump.exe')) {
    Get-Command $tool -ErrorAction Stop | Out-Null
}
foreach ($script in @('GhidraDwarfForge.java', 'ExportGhidraDwarfForge.java')) {
    if (-not (Test-Path -LiteralPath (Join-Path $module "ghidra_scripts\$script") -PathType Leaf)) {
        throw "installed script is missing: $script"
    }
}
$manifest = @(Get-Content -LiteralPath (Join-Path $module 'RELEASE-SHA256SUMS'))
if ($manifest.Count -eq 0) { throw 'installed release checksum manifest is empty' }
foreach ($entry in $manifest) {
    if ($entry -notmatch '^([0-9a-f]{64})  (.+)$') {
        throw "invalid release checksum record: $entry"
    }
    $expected = $Matches[1]
    $file = Join-Path $module $Matches[2]
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        throw "installed release checksum mismatch: $file"
    }
}
$root = Join-Path $repository 'build\test-results\windows-host\gui-script-manager'
$work = Join-Path $root ('run.' + [Guid]::NewGuid().ToString('N') + ' GUI paths')
foreach ($directory in @('', 'classes', 'settings', 'cache', 'tmp', 'user')) {
    New-Item -ItemType Directory -Force (Join-Path $work $directory) | Out-Null
}
Write-Output "windows-gui-script-manager-results=$work"
$before = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash

# Java argument files avoid Windows' command-line limit for the Ghidra classpath.
function Write-JavaArguments {
    param([string] $Path, [string[]] $Values)
    $quoted = foreach ($value in $Values) {
        '"' + $value.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    [System.IO.File]::WriteAllLines($Path, [string[]] $quoted,
        [System.Text.UTF8Encoding]::new($false))
}

function Invoke-Validator {
    param([string] $Command, [string[]] $Arguments, [string] $Name)
    $stdout = Join-Path $work "$Name.txt"
    $stderr = Join-Path $work "$Name.stderr"
    & $Command @Arguments 1> $stdout 2> $stderr
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE; see $stdout and $stderr"
    }
    if ((Get-Item -LiteralPath $stderr).Length -ne 0 -or
            (Get-Content -LiteralPath $stdout -Raw) -match '(?im)^\s*(warning|error):') {
        throw "$Command reported diagnostics; see $stdout and $stderr"
    }
}

$jars = @(Join-Path $module 'lib\GhidraDwarfForge.jar')
$jars += Get-ChildItem -LiteralPath (Join-Path $ghidra 'Ghidra') -Recurse -File -Filter '*.jar' |
    Where-Object { $_.FullName -notmatch '[/\\](Extensions|data)[/\\]' } |
    Sort-Object FullName | ForEach-Object FullName
$classpath = $jars -join [System.IO.Path]::PathSeparator
$classes = Join-Path $work 'classes'
$gui = Join-Path $PSScriptRoot 'gui'
$compileArgs = Join-Path $work 'javac.args'
Write-JavaArguments $compileArgs @('--release', '21', '-cp', $classpath, '-d', $classes,
    (Join-Path $gui 'GuiTestSupport.java'), (Join-Path $gui 'GuiTableClickSmoke.java'),
    (Join-Path $gui 'GuiScriptManagerSmoke.java'))
& javac "@$compileArgs" 2>&1 | Tee-Object -LiteralPath (Join-Path $work 'compile.log')
if ($LASTEXITCODE -ne 0) { throw "GUI driver compilation failed: $LASTEXITCODE" }

Invoke-Validator 'readelf.exe' @('-Ws', $referencePath) 'reference-symbols'
$symbol = Get-Content -LiteralPath (Join-Path $work 'reference-symbols.txt') |
    Where-Object { $_ -match '\srecovered_add$' } | Select-Object -First 1
if ($null -eq $symbol) { throw 'compiler reference has no recovered_add symbol' }
$functionAddress = ($symbol.Trim() -split '\s+')[1]
$runArgs = Join-Path $work 'java.args'
Write-JavaArguments $runArgs @('--enable-native-access=ALL-UNNAMED',
    '-Djava.awt.headless=false', '-Duser.language=en', '-Duser.country=US',
    "-Duser.home=$(Join-Path $work 'user')",
    "-Dapplication.settingsdir=$(Join-Path $work 'settings')",
    "-Dapplication.cachedir=$(Join-Path $work 'cache')",
    "-Dapplication.tempdir=$(Join-Path $work 'tmp')",
    "-Djava.io.tmpdir=$(Join-Path $work 'tmp')",
    '-cp', "$classes$([System.IO.Path]::PathSeparator)$classpath",
    'GuiScriptManagerSmoke', $ghidra, $module, $fixturePath, $work, $functionAddress)
& java "@$runArgs" 2>&1 | Tee-Object -LiteralPath (Join-Path $work 'gui.log')
if ($LASTEXITCODE -ne 0) { throw "Windows Script Manager journey failed: $LASTEXITCODE; see $work" }
if ((Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash -ne $before) {
    throw 'Windows GUI journey modified the source fixture'
}

$inputElf = Join-Path $work 'select\readonly\fixture'
$sidecar = Join-Path $work 'select\chosen\fixture.dbg'
Invoke-Validator 'readelf.exe' @('-h', '-S', '-n', $inputElf) 'input-elf'
Invoke-Validator 'readelf.exe' @('-h', '-S', '-n', $sidecar) 'sidecar-elf'
Invoke-Validator 'readelf.exe' @('--debug-dump=info', '--debug-dump=abbrev',
    '--debug-dump=aranges', '--debug-dump=decodedline', '--debug-dump=Ranges',
    '--debug-dump=loc', $sidecar) 'readelf-dwarf'
Invoke-Validator 'llvm-dwarfdump.exe' @('--verify', $sidecar) 'llvm-verify'
$inputMetadata = Get-Content -LiteralPath (Join-Path $work 'input-elf.txt')
$outputMetadata = Get-Content -LiteralPath (Join-Path $work 'sidecar-elf.txt')
foreach ($field in @('Class', 'Data', 'OS/ABI', 'Machine', 'Flags', 'Build ID')) {
    $pattern = '^\s*' + [regex]::Escape($field) + ':\s*(.+)$'
    $inputValue = @($inputMetadata | Where-Object { $_ -match $pattern } |
        ForEach-Object { $_.Trim() })
    $outputValue = @($outputMetadata | Where-Object { $_ -match $pattern } |
        ForEach-Object { $_.Trim() })
    if ($inputValue.Count -ne 1 -or $outputValue.Count -ne 1 -or
            $inputValue[0] -ne $outputValue[0]) {
        throw "Windows GUI sidecar ELF identity mismatch: $field"
    }
}
$independent = Get-Command dwarfdump.exe -ErrorAction SilentlyContinue
if ($null -eq $independent) {
    'independent-dwarfdump=UNAVAILABLE_ON_WINDOWS_RUNNER' |
        Add-Content -LiteralPath (Join-Path $work 'result.txt')
}
else {
    Invoke-Validator $independent.Source @($sidecar) 'dwarfdump'
    'independent-dwarfdump=PASS' | Add-Content -LiteralPath (Join-Path $work 'result.txt')
}
@('windows-script-manager-structural-validation=PASS',
    'gdb-linux-elf-runtime=NOT_RUN_ON_WINDOWS_HOST',
    "source-fixture-sha256=$before") | Add-Content -LiteralPath (Join-Path $work 'result.txt')
Write-Output 'windows-gui-script-manager-integration=PASS'
