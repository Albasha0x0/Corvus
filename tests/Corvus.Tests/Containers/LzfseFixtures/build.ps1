# Rebuilds the LZFSE fixtures with Apple's lzfse command-line tool (lzfse 1.0, built from github.com/lzfse/lzfse):
#   $env:CORVUS_LZFSE = '<path to lzfse>'; pwsh -File build.ps1
# The encoder picks the block kind by input: text.lzfse is FSE-coded (bvx2, several blocks), small.lzfse is under the
# 4 KiB LZVN threshold (bvxn), random.lzfse is incompressible. The inputs are generated here; the tests check the
# decoded bytes by their SHA-256.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$tool = $env:CORVUS_LZFSE
if (-not $tool) { throw 'CORVUS_LZFSE names the lzfse program' }
$work = Join-Path ([IO.Path]::GetTempPath()) 'corvus-lzfse-inputs'
New-Item -ItemType Directory -Force $work | Out-Null

$text = [Text.StringBuilder]::new()
for ($i = 0; $text.Length -lt 300000; $i++) { [void]$text.Append("entry ${i}: ledger record $($i * 7 % 1000) balance $($i * 13 % 9973)`n") }
[IO.File]::WriteAllText((Join-Path $work 'text'), $text.ToString())
[IO.File]::WriteAllText((Join-Path $work 'small'), $text.ToString().Substring(0, 2000))
$random = [byte[]]::new(20000)
[Random]::new(20261025).NextBytes($random)
[IO.File]::WriteAllBytes((Join-Path $work 'random'), $random)

foreach ($name in 'text', 'small', 'random') {
    & $tool -encode -i (Join-Path $work $name) -o (Join-Path $here "$name.lzfse")
    if ($LASTEXITCODE -ne 0) { throw "lzfse failed on $name" }
    $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $work $name)).Hash.ToLowerInvariant()
    "$name $((Get-Item (Join-Path $work $name)).Length) $hash"
}
Remove-Item -Recurse -Force $work
