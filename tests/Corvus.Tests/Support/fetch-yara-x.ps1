# Downloads the YARA-X release assets for this machine's runtime identifier (yara-x-assets.json), checks each against
# its recorded SHA-256 and extracts the listed file into -Destination. The YARA tests read that folder from
# CORVUS_TEST_YARA_X; a platform with no upstream build gets no file, and its tests skip with the reason.
# -Part library or cli fetches that part only. Release packaging builds the library from "commit" where upstream
# publishes none.
# Usage:  pwsh tests/Corvus.Tests/Support/fetch-yara-x.ps1 -Destination <folder> [-Part library|cli]
param([Parameter(Mandatory)][string]$Destination, [ValidateSet('library', 'cli')][string]$Part)
$ErrorActionPreference = 'Stop'

$table = Get-Content (Join-Path $PSScriptRoot 'yara-x-assets.json') -Raw | ConvertFrom-Json
$rid = [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier
New-Item -ItemType Directory -Force $Destination | Out-Null
$assets = @($table.assets | Where-Object { $_.rid -eq $rid -and (-not $Part -or $_.part -eq $Part) })
if ($assets.Count -eq 0) { Write-Host "YARA-X $($table.version) publishes no build for $rid."; exit 0 }

foreach ($asset in $assets) {
    $archive = Join-Path $Destination $asset.file
    Invoke-WebRequest -Uri ($table.release + $asset.file) -OutFile $archive
    $sha = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -ne $asset.sha256) { throw "$($asset.file): SHA-256 $sha, expected $($asset.sha256)" }
    # Each archive goes to a folder of its own; only the listed file is kept.
    $unpacked = Join-Path $Destination "unpacked-$($asset.part)"
    New-Item -ItemType Directory -Force $unpacked | Out-Null
    if ($asset.file.EndsWith('.zip')) { Expand-Archive $archive -DestinationPath $unpacked -Force }
    else { tar -xzf $archive -C $unpacked; if ($LASTEXITCODE -ne 0) { throw "tar failed on $($asset.file)" } }
    $member = Get-ChildItem $unpacked -Recurse -File -Filter $asset.member | Select-Object -First 1
    if (-not $member) { throw "$($asset.file) holds no $($asset.member)" }
    Move-Item $member.FullName (Join-Path $Destination $asset.member) -Force
    Remove-Item $unpacked -Recurse -Force
    Remove-Item $archive -Force
    Write-Host "YARA-X $($table.version) $($asset.part) for ${rid}: $($asset.member) (SHA-256 checked)"
}
