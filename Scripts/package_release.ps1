[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$Version = '1.0.1',
    [string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Choose a new release output directory' }
$certificates = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -eq 'CN=RYFTENIUS' -and $_.HasPrivateKey -and
    $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date)
})
if ($CertificateThumbprint) {
    $certificates = @($certificates | Where-Object Thumbprint -eq $CertificateThumbprint)
}
if ($certificates.Count -ne 1) { throw 'Select exactly one valid local RYFTENIUS code-signing identity' }
$certificate = $certificates[0]
if (-not ($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })) {
    throw 'Selected identity is not a code-signing certificate'
}
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signer = Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $signer) { throw 'Windows SDK signtool is required' }
[IO.Directory]::CreateDirectory($output) | Out-Null
$hashes = @()
foreach ($platform in @('x64','Win32')) {
    $stage = Join-Path $output $platform
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    foreach ($pair in @(@('SKUGGA.dll','SKUGGA.dll'), @('SkuggaRunner.exe','skugga.exe'))) {
        $source = Join-Path $root ('bin\Release\'+$platform+'\'+$pair[0])
        $destination = Join-Path $stage $pair[1]
        Copy-Item -LiteralPath $source -Destination $destination
        & $signer sign /s My /sha1 $certificate.Thumbprint /fd SHA256 /d 'RYFTENIUS SKUGGA' $destination
        if ($LASTEXITCODE) { throw ('Signing failed: '+$destination) }
        $signature = Get-AuthenticodeSignature -LiteralPath $destination
        if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
            throw ('Output signer mismatch: '+$destination)
        }
        $hashes += (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash+'  '+$platform+'/'+$pair[1]
    }
    Copy-Item -LiteralPath (Join-Path $stage 'skugga.exe') -Destination (Join-Path $stage 'sk.exe')
    $hashes += (Get-FileHash -LiteralPath (Join-Path $stage 'sk.exe') -Algorithm SHA256).Hash+'  '+$platform+'/sk.exe'
}
Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $output 'LICENSE')
[IO.File]::WriteAllLines((Join-Path $output 'SHA256SUMS.txt'),$hashes)
$archive = Join-Path $output ('SKUGGA-'+$Version+'-windows.zip')
Compress-Archive -LiteralPath @((Join-Path $output 'x64'),(Join-Path $output 'Win32'),
    (Join-Path $output 'LICENSE'),(Join-Path $output 'SHA256SUMS.txt')) -DestinationPath $archive
Write-Output ('Release archive: '+$archive)
Write-Output ('Signer: '+$certificate.Subject)
Write-Output ('Archive SHA256: '+(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash)
