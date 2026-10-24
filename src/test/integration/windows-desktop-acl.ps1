param()
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) {
    throw 'This evidence probe must run on native Windows.'
}
$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$resultRoot = Join-Path $repository 'build\test-results\windows-desktop-acl'
$work = Join-Path $resultRoot ('run.' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $work 'classes'
New-Item -ItemType Directory -Force $classes | Out-Null
$gui = Join-Path $PSScriptRoot 'gui'
& javac --release 21 -d $classes (Join-Path $gui 'GuiTestSupport.java') `
    (Join-Path $gui 'WindowsDesktopAclProbe.java') 2>&1 |
    Tee-Object -LiteralPath (Join-Path $work 'compile.log')
if ($LASTEXITCODE -ne 0) {
    throw "Windows desktop probe compilation failed: $LASTEXITCODE"
}
& {
    "os=$([Environment]::OSVersion)"
    "user=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    "session=$((Get-Process -Id $PID).SessionId)"
    & java -version 2>&1
} | Set-Content -LiteralPath (Join-Path $work 'environment.txt')
& java '-Djava.awt.headless=false' -cp $classes WindowsDesktopAclProbe $work 2>&1 |
    Tee-Object -LiteralPath (Join-Path $work 'probe.log')
if ($LASTEXITCODE -ne 0) {
    throw "Native Windows desktop/ACL feasibility failed: $LASTEXITCODE; see $work"
}
Write-Output "Windows desktop/ACL evidence: $work"
