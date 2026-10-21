param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$item = Get-Item -LiteralPath $Path
if ($item.Length -gt 64MB) { throw 'Signature audit is bounded to 64 MiB' }
$bytes = [IO.File]::ReadAllBytes($item.FullName)
function Read-Der([byte[]]$Buffer, [ref]$Position) {
    $cursor = [int]$Position.Value
    if ($cursor -lt 0 -or $cursor + 2 -gt $Buffer.Length) { throw 'Truncated DER' }
    $tag = $Buffer[$cursor++]; $length = [int]$Buffer[$cursor++]
    if ($length -band 0x80) {
        $count = $length -band 0x7f
        if ($count -lt 1 -or $count -gt 4 -or $cursor + $count -gt $Buffer.Length) { throw 'Invalid DER length' }
        $length = 0L
        for ($i=0; $i -lt $count; $i++) { $length = ($length -shl 8) -bor $Buffer[$cursor++] }
    }
    if ($length -gt $Buffer.Length - $cursor) { throw 'DER range outside buffer' }
    $Position.Value = $cursor + $length
    [pscustomobject]@{Tag=$tag;Start=$cursor;Length=$length}
}
if ($bytes.Length -lt 256 -or [BitConverter]::ToUInt16($bytes,0) -ne 0x5a4d) { throw 'Not a PE' }
$pe = [BitConverter]::ToInt32($bytes,0x3c)
if ($pe -lt 64 -or $pe + 264 -gt $bytes.Length -or [BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550) { throw 'Invalid PE header' }
$optional=$pe+24; $magic=[BitConverter]::ToUInt16($bytes,$optional)
$directory = switch ($magic) { 0x20b { $optional+112 } 0x10b { $optional+96 } default { throw 'Invalid PE optional header' } }
$security=$directory+32
$certificateOffset=[BitConverter]::ToUInt32($bytes,$security)
$certificateSize=[BitConverter]::ToUInt32($bytes,$security+4)
if ($certificateSize -lt 8 -or [long]$certificateOffset+$certificateSize -ne $bytes.Length) { throw 'Unexpected certificate extent' }
$certificateLength=[BitConverter]::ToUInt32($bytes,$certificateOffset)
if ($certificateLength -lt 8 -or $certificateLength -gt $certificateSize) { throw 'Invalid certificate length' }
$cmsBytes=[byte[]]::new($certificateLength-8)
[Array]::Copy($bytes,$certificateOffset+8,$cmsBytes,0,$cmsBytes.Length)
$cms=[Security.Cryptography.Pkcs.SignedCms]::new()
$cms.Decode($cmsBytes)
$cms.CheckSignature($true) # Mathematical signature verification; no trust-store mutation.
$content=$cms.ContentInfo.Content
$position=0; $root=Read-Der $content ([ref]$position)
if ($root.Tag -ne 0x30) { throw 'Invalid signed content' }
$position=$root.Start; $null=Read-Der $content ([ref]$position)
$digestInfo=Read-Der $content ([ref]$position)
$position=$digestInfo.Start; $algorithm=Read-Der $content ([ref]$position)
$digest=Read-Der $content ([ref]$position)
$position=$algorithm.Start; $oid=Read-Der $content ([ref]$position)
$oidBytes=$content[$oid.Start..($oid.Start+$oid.Length-1)]
if ($oid.Tag -ne 6 -or [Convert]::ToHexString([byte[]]$oidBytes) -ne '608648016503040201' -or $digest.Tag -ne 4 -or $digest.Length -ne 32) { throw 'Expected SHA-256 Authenticode digest' }
# The release linker produces contiguous raw sections. Refuse other layouts.
$cursor=[BitConverter]::ToUInt32($bytes,$optional+60)
$table=$optional+[BitConverter]::ToUInt16($bytes,$pe+20)
$count=[BitConverter]::ToUInt16($bytes,$pe+6)
if ($count -gt 96 -or $table+$count*40 -gt $bytes.Length) { throw 'Invalid section table' }
$sections=@(for($i=0;$i -lt $count;$i++){
    $header=$table+$i*40
    $size=[BitConverter]::ToUInt32($bytes,$header+16)
    if($size){[pscustomobject]@{Size=$size;Offset=[BitConverter]::ToUInt32($bytes,$header+20)}}
}) | Sort-Object Offset
foreach($section in $sections){
    if($section.Offset -ne $cursor){throw 'Unsupported noncontiguous raw sections'}
    $cursor += [long]$section.Size
}
if($cursor -gt $certificateOffset -or $certificateOffset -lt $security+8){throw 'Invalid raw file extent'}
$hash=[Security.Cryptography.SHA256]::Create()
try {
    $null=$hash.TransformBlock($bytes,0,$optional+64,$null,0)
    $null=$hash.TransformBlock($bytes,$optional+68,$security-($optional+68),$null,0)
    $null=$hash.TransformFinalBlock($bytes,$security+8,$certificateOffset-($security+8))
    $expected=[byte[]]$content[$digest.Start..($digest.Start+$digest.Length-1)]
    if([Convert]::ToHexString($hash.Hash) -ne [Convert]::ToHexString($expected)){throw 'Authenticode file digest mismatch'}
} finally {$hash.Dispose()}
Write-Output ('Authenticode signature and file digest verified: '+$item.Name)
