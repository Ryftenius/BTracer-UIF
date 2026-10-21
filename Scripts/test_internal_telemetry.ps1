param([string]$BinaryDirectory = (Join-Path $PSScriptRoot '..\bin\Release\x64'))
$ErrorActionPreference = 'Stop'
$exe = Join-Path $BinaryDirectory 'SkuggaRunner.exe'
$target = Join-Path $BinaryDirectory 'SkuggaTestTarget.exe'
$previousConsole = $env:SKUGGA_TEST_NO_NEW_CONSOLE
try {
    $env:SKUGGA_TEST_NO_NEW_CONSOLE = '1'
    foreach ($include in @($false,$true)) {
        $arguments = @('--cli','--api','NtQueryVirtualMemory,NtMapViewOfSection,NtProtectVirtualMemory',
            '--stack','--raw','--timeout','10s')
        if ($include) { $arguments += '/include-internals' }
        $arguments += @('--',$target,'--cli-probe-direct-syscall')
        $output = (& $exe @arguments 2>&1) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw "Owned probe failed: $output" }
        if ($output -notmatch 'direct-syscall source=') { throw 'Detection was lost' }
        if ($output -match 'auto-enabled protect folding') { throw 'Raw mode emitted folding notice' }
        $internalFrames = [regex]::Matches($output,'\[internal\]').Count
        if ((-not $include -and $internalFrames -ne 0) -or ($include -and $internalFrames -eq 0)) {
            throw "Unexpected internal-frame visibility: include=$include frames=$internalFrames"
        }
        Write-Output "Owned runtime probe passed: include-internals=$include internal-frames=$internalFrames"
    }
} finally { $env:SKUGGA_TEST_NO_NEW_CONSOLE = $previousConsole }
