param(
    [switch]$KeepObj,
    [switch]$RemoveTaskEvidence
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Remove-WorkspacePath([string]$Path, [switch]$Recurse) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not $resolved.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to remove path outside workspace: $resolved"
    }

    if ($Recurse) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    else {
        Remove-Item -LiteralPath $resolved -Force
    }
}

if (-not $KeepObj) {
    Remove-WorkspacePath (Join-Path $Root "obj") -Recurse
}

if ($RemoveTaskEvidence) {
    Remove-WorkspacePath (Join-Path $Root ".evidence") -Recurse
    Remove-WorkspacePath (Join-Path $Root ".baseline") -Recurse
}

$diagnosticDirs = @(
    "bin\Debug\x64\SkuggaDiagnostics",
    "bin\Debug\Win32\SkuggaDiagnostics",
    "bin\Release\x64\SkuggaDiagnostics",
    "bin\Release\Win32\SkuggaDiagnostics",
    "bin\ReleaseStaged\x64\SkuggaDiagnostics",
    "bin\ReleaseStaged\Win32\SkuggaDiagnostics"
)

foreach ($relative in $diagnosticDirs) {
    Remove-WorkspacePath (Join-Path $Root $relative) -Recurse
}

$binRoot = Join-Path $Root "bin"
if (Test-Path -LiteralPath $binRoot) {
    Get-ChildItem -LiteralPath $binRoot -Recurse -Filter "skugga-runtime-*.log" -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-WorkspacePath $_.FullName
        }
}

Write-Host "[clean] removed obj, diagnostics bundles, and runtime logs"
if ($RemoveTaskEvidence) {
    Write-Host "[clean] removed task evidence and baseline copies"
}
