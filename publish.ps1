# Builds a framework-dependent release into ./publish (requires the .NET 10 runtime on the target machine).
# Usage:  ./publish.ps1            -> ./publish/corvus.exe
#         ./publish.ps1 -SelfContained   -> single-folder build that does not need .NET installed
param([switch]$SelfContained)

$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'publish'
$project = Join-Path $PSScriptRoot 'src/Corvus/Corvus.csproj'
$marker = Join-Path $out '.build-complete'

# A development relay (corvus relay) starts a new server only once the marker is back; it is written last.
if (Test-Path $marker) { Remove-Item $marker -Force }

# A running server's files cannot be overwritten on Windows, but they can be renamed: move them aside, delete earlier ones once free.
if (Test-Path $out) {
    Get-ChildItem $out -Recurse -File -Filter '*.aside-*' | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
    foreach ($file in Get-ChildItem $out -Recurse -File | Where-Object { $_.Name -notlike '*.aside-*' }) {
        try { [IO.File]::Open($file.FullName, 'Open', 'ReadWrite', 'None').Dispose() }
        catch [System.IO.IOException] { Rename-Item $file.FullName ($file.Name + '.aside-' + [DateTime]::UtcNow.Ticks) }
    }
}

$publishArgs = @('publish', $project, '-c', 'Release', '-o', $out, '-r', 'win-x64', '--nologo')
if ($SelfContained) { $publishArgs += @('--self-contained', 'true') } else { $publishArgs += @('--self-contained', 'false') }

dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

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
