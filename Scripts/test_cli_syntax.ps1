param([Parameter(Mandatory)][string]$BinaryPath)
$ErrorActionPreference = 'Stop'
$cases = @(
    @{ Args=@('--cli','--help'); Exit=0; Match='Observe' },
    @{ Args=@('--cli','/help'); Exit=0; Match='Observe' },
    @{ Args=@('--cli','run','--help'); Exit=0; Match='Observe' },
    @{ Args=@('/version'); Exit=0; Match='SPOOK' },
    @{ Args=@('--cli','--api'); Exit=2; Match='requires a hook' },
    @{ Args=@('--cli','/api'); Exit=2; Match='requires a hook' },
    @{ Args=@('--cli','--loader','bad'); Exit=2; Match='unknown loader' },
    @{ Args=@('--cli','/loader:bad'); Exit=2; Match='unknown loader' },
    @{ Args=@('--cli','--unknown'); Exit=2; Match='unknown option' }
)
# A deliberately missing target exercises parsing without executing a target.
foreach ($switches in @(
    @('--api','NtQueryInformationProcess','--stack'),
    @('/stack','/api:NtQueryInformationProcess'),
    @('/api','NtQueryInformationProcess','/registers'),
    @('--quiet','--api','NtQueryInformationProcess'),
    @('--deny','--api','NtQueryInformationProcess'),
    @('--group','memory'), @('/group:memory'),
    @('--lhook','NtQueryInformationProcess','--stack-trace'),
    @('--loader','standard','--api','NtQueryInformationProcess')
)) {
    $cases += @{ Args=@('--cli','run') + $switches + @('--','Z:\skugga-missing-cli-fixture.exe','/target-option'); Exit=2; Match='missing target: Z:' }
}
foreach ($case in $cases) {
    $arguments = $case.Args
    $output = (& $BinaryPath @arguments 2>&1) -join "`n"
    if ($LASTEXITCODE -ne $case.Exit -or $output -notmatch $case.Match) {
        throw "CLI case failed: $($arguments -join ' ')`n$output"
    }
    if ($output -match 'WATCH IT UNFOLD|SKUGGA - owned-process user-mode sensor runner') {
        throw 'Obsolete banner found'
    }
}
Write-Output "$($cases.Count) CLI syntax cases passed"
