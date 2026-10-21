param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9.+_-]+$')][string]$Version,
    [Parameter(Mandatory)][ValidateSet('x64','Win32')][string]$Platform
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$files = @(foreach ($directory in @('ABI','DLL','Injector','Mapper','SDK','VCXProj','Scripts')) {
    Get-ChildItem -LiteralPath (Join-Path $root $directory) -Recurse -File |
        Where-Object Extension -in '.cpp','.c','.h','.hpp','.asm','.vcxproj','.ps1'
}) | Sort-Object FullName
$records = foreach ($file in $files) {
    [IO.Path]::GetRelativePath($root,$file.FullName).Replace('\','/') + ':' + (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
}
$sha = [Security.Cryptography.SHA256]::Create()
try { $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($records -join "`n")))).Replace('-','').ToLowerInvariant() }
finally { $sha.Dispose() }
$arch = if ($Platform -eq 'x64') { 'x86_64' } else { 'x86' }
$content = "#pragma once`n#define SKUGGA_VERSION L`"$Version`"`n#define SKUGGA_BUILD_ID L`"skugga-$Version+$($digest.Substring(0,12)).windows-$arch`"`n"
[IO.Directory]::CreateDirectory((Split-Path -Parent $OutputPath)) | Out-Null
if (-not (Test-Path -LiteralPath $OutputPath) -or [IO.File]::ReadAllText($OutputPath) -ne $content) {
    [IO.File]::WriteAllText($OutputPath,$content)
}
