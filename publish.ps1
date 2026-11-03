# Builds a framework-dependent release into ./publish (requires the .NET 10 runtime on the target machine).
# Usage:  ./publish.ps1            -> ./publish/corvus.exe
#         ./publish.ps1 -SelfContained   -> single-folder build that does not need .NET installed
param([switch]$SelfContained)

$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'publish'
$project = Join-Path $PSScriptRoot 'src/Corvus/Corvus.csproj'
$marker = Join-Path $out '.build-complete'

# Relays copy the output folder at any time and hold its files while they do, so the build goes to a private folder.
$stage = Join-Path $PSScriptRoot 'obj/publish-stage'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }

$publishArgs = @('publish', $project, '-c', 'Release', '-o', $stage, '-r', 'win-x64', '--nologo')
if ($SelfContained) { $publishArgs += @('--self-contained', 'true') } else { $publishArgs += @('--self-contained', 'false') }

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

# A development relay (corvus relay) starts a new server only once the marker is back; it is written last.
if (Test-Path $marker) { Remove-Item $marker -Force }

# A file held open with delete sharing can be renamed aside; any other is retried for 60 s while a relay finishes copying it.
New-Item -ItemType Directory -Force $out | Out-Null
Get-ChildItem $out -Recurse -File -Filter '*.aside-*' | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
foreach ($file in Get-ChildItem $stage -Recurse -File) {
    $target = Join-Path $out $file.FullName.Substring($stage.Length + 1)
    New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
    for ($attempt = 1; ; $attempt++) {
        try { Copy-Item $file.FullName $target -Force; break }
        catch [System.IO.IOException] {
            if ($attempt -ge 120) { throw }
            if (Test-Path $target) { Rename-Item $target ((Split-Path $target -Leaf) + '.aside-' + [DateTime]::UtcNow.Ticks) -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 500
        }
    }
}
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

$commit = $null; $dirty = $null
try {
    $commit = git -C $PSScriptRoot rev-parse --short HEAD 2>$null
    $dirty = [bool](git -C $PSScriptRoot status --porcelain 2>$null)
} catch { }
$build = [ordered]@{
    buildId = '{0:yyyyMMddTHHmmssZ}-{1}' -f [DateTime]::UtcNow, [Guid]::NewGuid().ToString('N').Substring(0, 8)
    commit = $commit
    dirty = $dirty
}
$temp = "$marker.tmp"
Set-Content -Path $temp -Value ($build | ConvertTo-Json -Compress) -NoNewline
Move-Item $temp $marker -Force
Write-Host "Published to $out (build $($build.buildId))"
