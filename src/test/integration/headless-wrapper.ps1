$ErrorActionPreference = 'Stop'
$repositoryDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$wrapper = Join-Path $repositoryDirectory 'support\ghidra-dwarf-forge-headless.ps1'
$work = Join-Path ([IO.Path]::GetTempPath()) "ghidra-dwarf-forge-wrapper-test-$([guid]::NewGuid())"
$fakeGhidra = Join-Path $work 'fake-ghidra'
$fakeSupport = Join-Path $fakeGhidra 'support'
$launcher = Join-Path $fakeSupport 'analyzeHeadless.bat'
$argumentLog = Join-Path $work 'arguments.txt'
$locationRunner = Join-Path $work 'invoke-from-location.ps1'
$powershell = (Get-Process -Id $PID).Path
$oldArguments = $env:FAKE_ARGUMENT_LOG
$oldStatus = $env:FAKE_REPORT_STATUS
$oldExit = $env:FAKE_HEADLESS_EXIT
$protectedHashes = @{}

function Assert-Condition([bool] $Condition, [string] $Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Preserve-File([string] $Path) {
    [IO.File]::WriteAllText($Path, "preserve this file: $Path`n")
    $protectedHashes[$Path] = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Assert-Preserved {
    foreach ($path in $protectedHashes.Keys) {
        Assert-Condition ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq
            $protectedHashes[$path]) "protected file changed: $path"
    }
}

function Invoke-Wrapper([int] $Expected, [string[]] $Options, [string] $WorkingDirectory = '') {
    $wrapperArguments = @('-GhidraDirectory', $fakeGhidra,
        '-Libdwarf', $consumer, '-Libdwarfp', $producer) + $Options
    if ([string]::IsNullOrEmpty($WorkingDirectory)) {
        $arguments = @('-NoLogo', '-NoProfile', '-File', $wrapper) + $wrapperArguments
    }
    else {
        $argumentsFile = Join-Path $work 'location-options.clixml'
        Export-Clixml -InputObject $wrapperArguments -LiteralPath $argumentsFile
        $arguments = @('-NoLogo', '-NoProfile', '-File', $locationRunner,
            '-Wrapper', $wrapper, '-Directory', $WorkingDirectory, '-ArgumentsFile', $argumentsFile)
    }
    $transcript = @(& $powershell @arguments 2>&1)
    $actual = $LASTEXITCODE
    [IO.File]::WriteAllLines((Join-Path $work 'last-transcript.txt'), [string[]] $transcript)
    Assert-Condition ($actual -eq $Expected) "expected exit $Expected, got $actual : $($transcript -join ' ')"
    return $transcript
}

function Assert-RejectedLog([string] $LogPath, [string[]] $Options, [string] $WorkingDirectory = '') {
    Remove-Item -LiteralPath $argumentLog -Force -ErrorAction SilentlyContinue
    $transcript = Invoke-Wrapper 64 ($Options + @('-Log', $LogPath)) $WorkingDirectory
    Assert-Condition (-not (Test-Path -LiteralPath $argumentLog)) "colliding log launched Ghidra: $LogPath"
    Assert-Condition (($transcript -join "`n") -match 'log path (aliases|is inside)') "missing collision diagnostic for $LogPath : $($transcript -join ' ')"
    Assert-Preserved
}

try {
    New-Item -ItemType Directory -Path $fakeSupport -Force | Out-Null
    [IO.File]::WriteAllText($locationRunner, @'
param([string] $Wrapper, [string] $Directory, [string] $ArgumentsFile)
$ErrorActionPreference = 'Stop'
[Environment]::CurrentDirectory = [IO.Path]::GetDirectoryName($Directory)
Set-Location -LiteralPath $Directory
if ([Environment]::CurrentDirectory -eq (Get-Location).ProviderPath) {
    throw 'test requires different process and PowerShell current directories'
}
$options = Import-Clixml -LiteralPath $ArgumentsFile
$parameters = @{}
for ($index = 0; $index -lt $options.Count; $index += 2) {
    $parameters[$options[$index].TrimStart('-')] = $options[$index + 1]
}
& $Wrapper @parameters
exit $LASTEXITCODE
'@)
    if ($env:OS -eq 'Windows_NT') {
        [IO.File]::WriteAllText($launcher, @'
@echo off
> "%FAKE_ARGUMENT_LOG%" echo launched %*
echo INFO GhidraDwarfForge report: {"schemaVersion":1,"status":"%FAKE_REPORT_STATUS%"}
exit /b %FAKE_HEADLESS_EXIT%
'@)
    }
    else {
        Copy-Item (Join-Path $PSScriptRoot 'fixtures/fake-ghidra/support/analyzeHeadless') $launcher
        & chmod '+x' $launcher
        Assert-Condition ($LASTEXITCODE -eq 0) 'could not make fake launcher executable'
    }
    $env:FAKE_ARGUMENT_LOG = $argumentLog
    $env:FAKE_REPORT_STATUS = 'SUCCESS'
    $env:FAKE_HEADLESS_EXIT = '0'
    $consumer = Join-Path $work 'libdwarf.dll'
    $producer = Join-Path $work 'libdwarfp.dll'
    $inputElf = Join-Path $work 'fixture input.elf'
    $override = Join-Path $work 'override.elf'
    $output = Join-Path $work 'explicit.dbg'
    $selection = Join-Path $work 'formatter selection λ.json'
    $formatterHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFileName($output)))).ToLowerInvariant()
    $formatterOutput = Join-Path $work "forge_formatters_$formatterHash.py"
    $project = Join-Path $work 'projects'
    $databaseDirectory = Join-Path $project 'Existing.rep'
    $database = Join-Path $databaseDirectory 'db.1'
    $packagedDirectory = Join-Path $fakeGhidra 'Ghidra\Extensions\GhidraDwarfForge\os\win_x86_64'
    $packagedLibrary = Join-Path $packagedDirectory 'libdwarf.dll'
    New-Item -ItemType Directory -Path $databaseDirectory, $packagedDirectory -Force | Out-Null
    foreach ($path in @($consumer, $producer, $inputElf, $override, $output, $selection, $formatterOutput, "$output.c", "$output.gdb.py", "$output.unwind.json",
            "$inputElf.dbg", "$inputElf.dbg.c", "$inputElf.dbg.gdb.py", "$inputElf.dbg.unwind.json",
            "$override.dbg", "$override.dbg.c", "$override.dbg.gdb.py", "$override.dbg.unwind.json",
            (Join-Path $project 'Existing.gpr'), (Join-Path $project 'Existing.lock'),
            $database, $packagedLibrary)) {
        Preserve-File $path
    }
    $protectedHashes[$launcher] = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash
    $importOptions = @('-Import', $inputElf)
    $projectOptions = @('-ProjectDirectory', $project, '-ProjectName', 'Existing',
        '-Program', '/folder/program', '-OriginalElf', $inputElf)

    $null = Invoke-Wrapper 0 ($importOptions + @('-Log', (Join-Path $work 'success.log')))
    Assert-Condition (Test-Path -LiteralPath $argumentLog) 'valid log did not launch Ghidra'
    $launchedArguments = Get-Content -LiteralPath $argumentLog -Raw
    Assert-Condition ($launchedArguments -match '(?:^|\s)"?-loader"?\s+"?ElfLoader"?(?:\s|$)') `
        'import wrapper did not select the ELF loader'
    $null = Invoke-Wrapper 0 $importOptions
    Assert-Condition (-not (Get-Content -LiteralPath $argumentLog -Raw).Contains('--source-lines=')) 'default selected multiple sources'
    $null = Invoke-Wrapper 0 ($importOptions + @('-TargetProfile', 'cortex-m3'))
    Assert-Condition ((Get-Content -LiteralPath $argumentLog -Raw).Contains('--target-profile=cortex-m3')) 'target profile not forwarded'
    foreach ($profile in @('', 'cortex-m4', 'ARMv7')) {
        $null = Invoke-Wrapper 64 ($importOptions + @('-TargetProfile', $profile))
    }
    foreach ($target in @('1', '8', '1000', '2147483647')) {
        $null = Invoke-Wrapper 0 ($importOptions + @('-SourceLines', $target))
        Assert-Condition ((Get-Content -LiteralPath $argumentLog -Raw).Contains("--source-lines=$target")) 'source line target not forwarded'
    }
    foreach ($target in @('', '0', '-1', '+1', '01', ' 8', '1.5', '2147483648', '999999999999999999999999')) {
        Remove-Item -LiteralPath $argumentLog -Force -ErrorAction SilentlyContinue
        $transcript = Invoke-Wrapper 64 ($importOptions + @('-SourceLines', $target, '-Log', $inputElf))
        Assert-Condition (-not (Test-Path -LiteralPath $argumentLog)) 'invalid source target launched Ghidra'
        Assert-Condition (($transcript -join ' ') -match 'SourceLines must be') 'missing source target diagnostic'
        Assert-Preserved
    }
    $null = Invoke-Wrapper 0 ($importOptions + @('-Formatters', $selection))
    $launchedArguments = Get-Content -LiteralPath $argumentLog -Raw
    Assert-Condition ($launchedArguments.Contains("--formatters=$selection")) 'formatter selection was not forwarded'
    $null = Invoke-Wrapper 0 ($importOptions + @('-AnnotationRecordLimit', '123',
        '-AnnotationTextLimit', '456', '-AnnotationSourceLimit', '789'))
    $launchedArguments = Get-Content -LiteralPath $argumentLog -Raw
    foreach ($option in @('--annotation-record-limit=123', '--annotation-text-limit=456', '--annotation-source-limit=789')) {
        Assert-Condition ($launchedArguments.Contains($option)) "missing annotation option: $option"
    }
    $null = Invoke-Wrapper 0 $projectOptions
    $launchedArguments = Get-Content -LiteralPath $argumentLog -Raw
    Assert-Condition ($launchedArguments -notmatch '(?:^|\s)"?-loader"?(?:\s|$)') `
        'existing-project wrapper would select an import loader'

    Remove-Item -LiteralPath $argumentLog -Force
    $unknownProjectOptions = @('-ProjectDirectory', $project, '-ProjectName', 'Existing',
        '-Program', '/folder/program')
    $unknownTranscript = Invoke-Wrapper 64 ($unknownProjectOptions + @('-Log', $inputElf))
    Assert-Condition (-not (Test-Path -LiteralPath $argumentLog)) 'unknown project input launched Ghidra'
    Assert-Condition (($unknownTranscript -join ' ') -match 'requires -OriginalElf') 'missing unknown-input diagnostic'
    Assert-Preserved
    $null = Invoke-Wrapper 0 $unknownProjectOptions

    Assert-RejectedLog $inputElf $importOptions
    $sourceNames = @("forge-src-000001-$('0' * 64).c", "forge-src-$('0' * 64).json")
    foreach ($name in $sourceNames) {
        $part = Join-Path $work $name
        Preserve-File $part
        Assert-RejectedLog $part $importOptions
        $hard = Join-Path $work "$name-hard.log"
        New-Item -ItemType HardLink -Path $hard -Target $part | Out-Null
        Assert-RejectedLog $hard ($importOptions + @('-SourceLines', '8'))
    }
    $futureManifest = Join-Path $work "forge-src-$('1' * 64).json"
    Assert-RejectedLog $futureManifest ($importOptions + @('-SourceLines', '8'))
    Assert-Condition (-not (Test-Path -LiteralPath $futureManifest)) 'reserved future manifest became a log'
    $independentSources = Join-Path $work 'independent-sources'
    New-Item -ItemType Directory -Path $independentSources | Out-Null
    $null = Invoke-Wrapper 0 ($importOptions + @('-Log', (Join-Path $independentSources $sourceNames[0])))
    Assert-RejectedLog $selection ($importOptions + @('-Formatters', $selection))
    Assert-RejectedLog $formatterOutput ($importOptions + @('-Output', $output, '-Formatters', $selection))
    $selectionHardlink = Join-Path $work 'selection-hardlink.log'
    New-Item -ItemType HardLink -Path $selectionHardlink -Target $selection | Out-Null
    Assert-RejectedLog $selectionHardlink ($importOptions + @('-Formatters', $selection))
    Assert-RejectedLog (Join-Path $work './fixture input.elf') $importOptions
    $relativeInput = [IO.Path]::GetFileName($inputElf)
    Assert-RejectedLog $relativeInput $importOptions $work
    Assert-RejectedLog $inputElf @('-Import', $relativeInput) $work
    Assert-RejectedLog "$relativeInput.dbg" $importOptions $work
    Assert-RejectedLog "$relativeInput.dbg.c" $importOptions $work
    $null = Invoke-Wrapper 0 ($importOptions + @('-Log', 'relative-independent.log')) $work
    Assert-Condition (Test-Path -LiteralPath (Join-Path $work 'relative-independent.log')) 'relative log used the wrong directory'
    $literalLog = Join-Path $work 'fixture input.el[f]'
    $null = Invoke-Wrapper 0 ($importOptions + @('-Log', $literalLog))
    Assert-Condition (Test-Path -LiteralPath $literalLog) 'literal bracket log was not written'
    Assert-Preserved
    $protectedHashes[$literalLog] = (Get-FileHash -LiteralPath $literalLog -Algorithm SHA256).Hash
    Assert-RejectedLog $literalLog @('-Import', $literalLog)
    if ($env:OS -eq 'Windows_NT') {
        Assert-RejectedLog $inputElf.ToUpperInvariant() $importOptions
        # Preventive Windows coverage: the unnamed stream aliases the file.
        foreach ($streamLog in @(($inputElf + '::$DATA'), ($inputElf + ':transcript'))) {
            Remove-Item -LiteralPath $argumentLog -Force -ErrorAction SilentlyContinue
            $streamTranscript = Invoke-Wrapper 64 ($importOptions + @('-Log', $streamLog))
            Assert-Condition (-not (Test-Path -LiteralPath $argumentLog)) 'alternate-stream log launched Ghidra'
            Assert-Condition (($streamTranscript -join ' ') -match 'alternate data stream') 'missing alternate-stream diagnostic'
            Assert-Preserved
        }
    }
    Assert-RejectedLog $inputElf ($importOptions + @('-OriginalElf', $override))
    Assert-RejectedLog $override ($importOptions + @('-OriginalElf', $override))
    $null = Invoke-Wrapper 0 ($importOptions + @('-GdbLoader'))
    Assert-Condition ((Get-Content -LiteralPath $argumentLog -Raw) -match '--gdb-loader') 'loader flag was not forwarded'
    $null = Invoke-Wrapper 0 ($importOptions + @('-CompressDebugSections', 'zlib'))
    if ((Get-Content -LiteralPath $argumentLog -Raw) -notmatch
            '(?:^|\s)"?--compress-debug-sections=zlib"?(?:\s|$)') {
        throw 'compression option was not passed to the exporter'
    }
    $null = Invoke-Wrapper 0 ($importOptions + @('-CompressDebugSections', 'none'))
    if ((Get-Content -LiteralPath $argumentLog -Raw) -match '--compress-debug-sections=') {
        throw 'explicit none unexpectedly changed default exporter arguments'
    }
    $null = Invoke-Wrapper 64 ($importOptions + @('-CompressDebugSections', 'zstd'))
    Invoke-Wrapper 0 @('-Import', $inputElf, '-SynthesizeUnwind', 'conditioned',
        '-UnwindStackSeparation', '100:107', '-UnwindRelocatedPointers', 'fixed') | Out-Null
    foreach ($option in @('--synthesize-unwind=conditioned', '--unwind-stack-separation=100:107', '--unwind-relocated-pointers=fixed')) {
        Assert-Condition ((Get-Content -LiteralPath $argumentLog -Raw).Contains($option)) 'unwind option was not forwarded'
    }
    foreach ($mode in @('assembly', 'pcode', 'both')) {
        $null = Invoke-Wrapper 0 ($importOptions + @('-SourceContext', $mode))
        Assert-Condition ((Get-Content -LiteralPath $argumentLog -Raw).Contains("--source-context=$mode")) 'context option was not forwarded'
    }
    $null = Invoke-Wrapper 0 ($importOptions + @('-SourceContext', 'off'))
    Assert-Condition ((Get-Content -LiteralPath $argumentLog -Raw) -notmatch '--source-context=') 'off changed exporter arguments'
    $null = Invoke-Wrapper 64 ($importOptions + @('-SourceContext', 'invalid'))
    $null = Invoke-Wrapper 64 ($importOptions + @('-SourceContext', 'BOTH'))
    foreach ($log in @($output, "$output.c", "$output.gdb.py", "$output.unwind.json")) {
        Assert-RejectedLog $log ($importOptions + @('-Output', $output))
    }
    foreach ($log in @("$inputElf.dbg", "$inputElf.dbg.c", "$inputElf.dbg.gdb.py", "$inputElf.dbg.unwind.json")) {
        Assert-RejectedLog $log $importOptions
    }
    foreach ($log in @("$override.dbg", "$override.dbg.c", "$override.dbg.gdb.py", "$override.dbg.unwind.json")) {
        Assert-RejectedLog $log ($importOptions + @('-OriginalElf', $override))
    }
    $newOutput = Join-Path $work 'new.dbg'
    Assert-RejectedLog $newOutput ($importOptions + @('-Output', $newOutput))
    Assert-RejectedLog "$newOutput.c" ($importOptions + @('-Output', $newOutput))
    Assert-Condition (-not (Test-Path -LiteralPath $newOutput)) 'collision created output'
    Assert-Condition (-not (Test-Path -LiteralPath "$newOutput.c")) 'collision created source'
    foreach ($log in @($consumer, $producer, $launcher, $packagedLibrary)) {
        Assert-RejectedLog $log $importOptions
    }
    foreach ($log in @((Join-Path $project 'Existing.gpr'),
            (Join-Path $project 'Existing.lock'), $database,
            (Join-Path $databaseDirectory 'new-file'))) {
        Assert-RejectedLog $log $projectOptions
    }
    foreach ($path in @($inputElf, $output, "$output.c", $producer, $packagedLibrary, $database)) {
        $link = Join-Path $work "hardlink-$([guid]::NewGuid()).log"
        New-Item -ItemType HardLink -Path $link -Target $path | Out-Null
        $options = if ($path -eq $database) { $projectOptions } else {
            $importOptions + @('-Output', $output)
        }
        Assert-RejectedLog $link $options
    }

    $symlink = Join-Path $work 'input-symlink.log'
    $canSymlink = $true
    try {
        New-Item -ItemType SymbolicLink -Path $symlink -Target $inputElf | Out-Null
    }
    catch {
        if ($env:OS -ne 'Windows_NT') { throw }
        Write-Host 'SKIP file-symlink cases: Windows account lacks symlink permission'
        $canSymlink = $false
    }
    if ($canSymlink) {
        Assert-RejectedLog $symlink $importOptions
        foreach ($name in $sourceNames) {
            $alias = Join-Path $work "$name-symbolic.log"
            New-Item -ItemType SymbolicLink -Path $alias -Target (Join-Path $work $name) | Out-Null
            Assert-RejectedLog $alias $importOptions
        }
        $futureAlias = Join-Path $work 'future-source.log'
        New-Item -ItemType SymbolicLink -Path $futureAlias -Target $futureManifest | Out-Null
        Assert-RejectedLog $futureAlias $importOptions
        Assert-Condition (-not (Test-Path -LiteralPath $futureManifest)) 'dangling source log created manifest'
        $reverseLog = Join-Path $independentSources 'preserved.log'
        Preserve-File $reverseLog
        New-Item -ItemType SymbolicLink -Path (Join-Path $work "forge-src-000002-$('0' * 64).c") -Target $reverseLog | Out-Null
        Assert-RejectedLog $reverseLog $importOptions
        $reverseFuture = Join-Path $independentSources 'not-created.log'
        New-Item -ItemType SymbolicLink -Path (Join-Path $work "forge-src-000003-$('0' * 64).c") -Target $reverseFuture | Out-Null
        Assert-RejectedLog $reverseFuture $importOptions
        Assert-Condition (-not (Test-Path -LiteralPath $reverseFuture)) 'dangling source alias created log'
        $dangling = Join-Path $work 'dangling-output.log'
        New-Item -ItemType SymbolicLink -Path $dangling -Target $newOutput | Out-Null
        Assert-RejectedLog $dangling ($importOptions + @('-Output', $newOutput))
        Assert-Condition (-not (Test-Path -LiteralPath $newOutput)) 'dangling log created output'
        $directoryAlias = Join-Path $work 'directory-alias'
        New-Item -ItemType SymbolicLink -Path $directoryAlias -Target $databaseDirectory | Out-Null
        Assert-RejectedLog (Join-Path $directoryAlias 'db.1') $projectOptions

        $lexicalDirectory = Join-Path $work 'lexical'
        $physicalDirectory = Join-Path $work 'physical'
        $physicalChild = Join-Path $physicalDirectory 'child'
        New-Item -ItemType Directory -Path $lexicalDirectory, $physicalChild -Force | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $lexicalDirectory 'alias') -Target $physicalChild | Out-Null
        $lexicalInput = Join-Path $lexicalDirectory 'original.elf'
        $ambiguousInput = "$lexicalDirectory/alias/../original.elf"
        foreach ($path in @($lexicalInput, (Join-Path $physicalDirectory 'original.elf'),
                "$lexicalInput.dbg", "$lexicalInput.dbg.c")) {
            Preserve-File $path
        }
        Assert-RejectedLog $lexicalInput ($importOptions + @('-OriginalElf', $ambiguousInput))
        Assert-RejectedLog "$lexicalInput.dbg" ($importOptions + @('-OriginalElf', $ambiguousInput))
        Assert-RejectedLog "$lexicalInput.dbg.c" ($importOptions + @('-OriginalElf', $ambiguousInput))
        # Tee-Object and the Java exporter both normalize '..' lexically.
        Assert-RejectedLog $ambiguousInput @('-Import', $lexicalInput)
    }
    if ($env:OS -ne 'Windows_NT') {
        $specialDirectory = Join-Path $work "source-directory`n"
        New-Item -ItemType Directory -Path $specialDirectory | Out-Null
        foreach ($name in $sourceNames) {
            $part = Join-Path $specialDirectory $name
            Preserve-File $part
            foreach ($kind in @('HardLink', 'SymbolicLink')) {
                $alias = Join-Path $work "$name-newline-$kind.log"
                New-Item -ItemType $kind -Path $alias -Target $part | Out-Null
                Assert-RejectedLog $alias ($importOptions + @('-Output', (Join-Path $specialDirectory 'fixture.dbg')))
            }
        }
    }
    $independent = Join-Path $work 'independent.log'
    [IO.File]::WriteAllText($independent, 'independent log')
    $independentHardlink = Join-Path $work 'independent-hardlink.log'
    New-Item -ItemType HardLink -Path $independentHardlink -Target $independent | Out-Null
    $null = Invoke-Wrapper 0 ($importOptions + @('-Log', $independentHardlink))
    if ($canSymlink) {
        $independentSymlink = Join-Path $work 'independent-symlink.log'
        New-Item -ItemType SymbolicLink -Path $independentSymlink -Target $independent | Out-Null
        $null = Invoke-Wrapper 0 ($importOptions + @('-Log', $independentSymlink))
    }
    Assert-Preserved
    Write-Host 'headless-wrapper-powershell=PASS'
}
finally {
    $env:FAKE_ARGUMENT_LOG = $oldArguments
    $env:FAKE_REPORT_STATUS = $oldStatus
    $env:FAKE_HEADLESS_EXIT = $oldExit
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
