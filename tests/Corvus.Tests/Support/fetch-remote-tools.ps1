# Downloads the tools remote-tools-assets.json pins for the offloaded test groups, checks each archive against its
# recorded SHA-256 and extracts it into -Destination; a tool already extracted there is kept. Prints NAME=path lines
# for the variables the tests read, which a CI step appends to its environment.
# Usage:  pwsh tests/Corvus.Tests/Support/fetch-remote-tools.ps1 -Destination <folder> [-Name ghidra]
param([Parameter(Mandatory)][string]$Destination, [string[]]$Name)
$ErrorActionPreference = 'Stop'

$table = Get-Content (Join-Path $PSScriptRoot 'remote-tools-assets.json') -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force $Destination | Out-Null
foreach ($tool in $table.tools | Where-Object { -not $Name -or $_.name -in $Name }) {
    $folder = Join-Path $Destination $tool.folder
    if (-not (Test-Path $folder)) {
        $archive = Join-Path $Destination ([IO.Path]::GetFileName($tool.url))
        Invoke-WebRequest -Uri $tool.url -OutFile $archive
        $sha = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sha -ne $tool.sha256) { throw "$($tool.name): SHA-256 $sha, expected $($tool.sha256)" }
        if ($archive.EndsWith('.zip')) { Expand-Archive $archive -DestinationPath $Destination -Force }
        else { tar -xzf $archive -C $Destination; if ($LASTEXITCODE -ne 0) { throw "tar failed on $archive" } }
        Remove-Item $archive -Force
        if (-not (Test-Path $folder)) { throw "$($tool.name): the archive holds no $($tool.folder)" }
    }
    "$($tool.variable)=$folder"
}
