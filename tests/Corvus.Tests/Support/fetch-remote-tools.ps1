# Downloads the tools remote-tools-assets.json pins for the offloaded test groups and the test host, checks each archive
# against its recorded SHA-256 and extracts it into -Destination (into its own folder when the archive has no top
# folder); a tool already extracted there is kept. Prints NAME=path lines for the variables the tests read, which a CI
# step appends to its environment. -Check downloads nothing and prints "missing <name> <version>" per absent tool.
# Runs on Windows PowerShell 5.1 too (a new test host has no PowerShell 7 yet).
# Usage:  pwsh tests/Corvus.Tests/Support/fetch-remote-tools.ps1 -Destination <folder> [-Name ghidra,jdk] [-Check]
param([Parameter(Mandatory)][string]$Destination, [string[]]$Name, [switch]$Check)
$ErrorActionPreference = 'Stop'
# The progress bar slows Invoke-WebRequest on Windows PowerShell several times over.
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$tar = if ($env:SystemRoot -and (Test-Path "$env:SystemRoot\System32\tar.exe")) { "$env:SystemRoot\System32\tar.exe" } else { 'tar' }
$table = Get-Content (Join-Path $PSScriptRoot 'remote-tools-assets.json') -Raw | ConvertFrom-Json
if (-not $Check) { New-Item -ItemType Directory -Force $Destination | Out-Null }
foreach ($tool in $table.tools | Where-Object { -not $Name -or $_.name -in $Name }) {
    $folder = Join-Path $Destination $tool.folder
    if (-not (Test-Path $folder)) {
        if ($Check) { "missing $($tool.name) $($tool.version)"; continue }
        $archive = Join-Path $Destination "$($tool.name)-$($tool.version)$(if ($tool.url -match '\.tar\.gz$') { '.tar.gz' } else { '.zip' })"
        Invoke-WebRequest -Uri $tool.url -OutFile $archive -UseBasicParsing
        $sha = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sha -ne $tool.sha256) { Remove-Item $archive -Force; throw "$($tool.name): SHA-256 $sha, expected $($tool.sha256)" }
        $into = if ($tool.into) { Join-Path $Destination $tool.into } else { $Destination }
        # Windows' own tar (bsdtar) reads zip files too, faster than Expand-Archive and past its path limits on 5.1; a
        # GNU tar earlier on PATH (Git's) reads no zip files.
        New-Item -ItemType Directory -Force $into | Out-Null
        & $tar -xf $archive -C $into
        if ($LASTEXITCODE -ne 0) { throw "tar failed on $archive" }
        Remove-Item $archive -Force
        if (-not (Test-Path $folder)) { throw "$($tool.name): the archive holds no $($tool.folder)" }
    }
    if ($tool.variable -and -not $Check) { "$($tool.variable)=$folder" }
}
