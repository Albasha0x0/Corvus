#!/usr/bin/env pwsh
# Rebuilds a release tag's .NET tool package and compares its managed DLLs with the published package's.
# Reports only: a differing DLL is listed, not failed; a failed rebuild or download fails the script.
#   ./tools/compare-rebuild.ps1 [-Tag v2.8.0] [-Repo owner/name] [-WorkDir folder]
# Needs git with the tag fetched, gh, and the .NET SDK the tag's global.json names. With GITHUB_STEP_SUMMARY set, the
# report is also appended there.
param(
    [string]$Tag,
    [string]$Repo = $(if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'Albasha0x0/Corvus' }),
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) 'corvus-rebuild')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
if (-not $Tag) { $Tag = git -C $root tag --list 'v*' --sort=-v:refname | Select-Object -First 1 }
if (-not $Tag) { throw 'No v* tag in this clone; fetch tags or pass -Tag.' }
$version = $Tag.TrimStart('v')

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
$source = Join-Path $WorkDir 'source'
$rebuilt = Join-Path $WorkDir 'rebuilt'
$published = Join-Path $WorkDir 'published'
New-Item -ItemType Directory -Force $rebuilt, $published | Out-Null

# The release packs with the same version property; ContinuousIntegrationBuild maps source paths as on the runner.
# The SDK is chosen by the working directory's global.json, so dotnet runs from the tag's tree.
git -C $root worktree add --detach $source $Tag 2>&1 | Out-Null
if ($LASTEXITCODE) { throw "git worktree add $Tag failed ($LASTEXITCODE)." }
try {
    Push-Location $source
    try {
        dotnet pack src/Corvus/Corvus.csproj -c Release "-p:Version=$version" -p:ContinuousIntegrationBuild=true -o $rebuilt --nologo
        if ($LASTEXITCODE) { throw "dotnet pack of $Tag failed ($LASTEXITCODE)." }
    }
    finally { Pop-Location }
}
finally { git -C $root worktree remove --force $source 2>&1 | Out-Null }

gh release download $Tag --repo $Repo --pattern 'CorvusRE.*.nupkg' --pattern SHA256SUMS --dir $published
if ($LASTEXITCODE) { throw "gh release download $Tag failed ($LASTEXITCODE)." }
$package = Get-ChildItem $published -Filter 'CorvusRE.*.nupkg' | Select-Object -First 1
$listed = Get-Content (Join-Path $published 'SHA256SUMS') | Where-Object { $_ -match "^([0-9a-f]{64}) [ *]$([regex]::Escape($package.Name))$" } | Select-Object -First 1
if (-not $listed -or $listed.Substring(0, 64) -ne (Get-FileHash $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw "$($package.Name) does not match the release's SHA256SUMS."
}

function Expand-Package([string]$nupkg, [string]$to) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($nupkg, $to)
    $to
}
$old = Expand-Package $package.FullName (Join-Path $WorkDir 'published-files')
$new = Expand-Package (Get-ChildItem $rebuilt -Filter 'CorvusRE.*.nupkg' | Select-Object -First 1).FullName (Join-Path $WorkDir 'rebuilt-files')

function Test-Managed([string]$path) {
    $stream = [IO.File]::OpenRead($path)
    try {
        $pe = [Reflection.PortableExecutable.PEReader]::new($stream)
        try { $pe.HasMetadata } catch [BadImageFormatException] { $false } finally { $pe.Dispose() }
    }
    finally { $stream.Dispose() }
}

$rows = foreach ($file in Get-ChildItem $old -Recurse -File -Include *.dll, *.exe | Sort-Object FullName) {
    if (-not (Test-Managed $file.FullName)) { continue }
    $relative = [IO.Path]::GetRelativePath($old, $file.FullName).Replace('\', '/')
    $other = Join-Path $new $relative
    $state = if (-not (Test-Path $other)) { 'not rebuilt' }
             elseif ((Get-FileHash $file.FullName).Hash -eq (Get-FileHash $other).Hash) { 'identical' }
             else { 'differs' }
    [pscustomobject]@{ File = $relative; State = $state }
}

$same = @($rows | Where-Object State -eq 'identical').Count
$lines = @("## Rebuild of $Tag", '', "$same of $(@($rows).Count) managed DLLs identical to the published package.", '',
    '| File | State |', '|---|---|') + @($rows | ForEach-Object { "| ``$($_.File)`` | $($_.State) |" })
$lines | Write-Output
if ($env:GITHUB_STEP_SUMMARY) { $lines | Add-Content $env:GITHUB_STEP_SUMMARY }
