# Downloads the tools remote-tools-assets.json pins for the offloaded test groups, checks each download
# against its recorded SHA-256 and unpacks it into -Destination (into its own folder when the archive has no top
# folder): a zip or tar.gz archive is extracted, a Windows Installer package is extracted by an administrative install
# (nothing is registered on the machine), and any other file (a jar) is kept as it is. A tool already there is kept.
# Prints NAME=path lines for the variables the tests read, which a CI step appends to its environment. -Check downloads
# nothing and prints "missing <name> <version>" per absent tool.
# Runs on Windows PowerShell 5.1 too.
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
        $leaf = ($tool.url -split '/')[-1]
        $download = Join-Path $Destination "$($tool.name)-$($tool.version)-$leaf"
        Invoke-WebRequest -Uri $tool.url -OutFile $download -UseBasicParsing
        $sha = (Get-FileHash $download -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sha -ne $tool.sha256) { Remove-Item $download -Force; throw "$($tool.name): SHA-256 $sha, expected $($tool.sha256)" }
        $into = if ($tool.into) { Join-Path $Destination $tool.into } else { $Destination }
        New-Item -ItemType Directory -Force $into | Out-Null
        if ($leaf -match '\.(zip|tar\.gz)$' -or $tool.url -match '/package/') {
            # Windows' own tar (bsdtar) reads zip files too, faster than Expand-Archive and past its path limits on 5.1;
            # a GNU tar earlier on PATH (Git's) reads no zip files.
            & $tar -xf $download -C $into
            if ($LASTEXITCODE -ne 0) { throw "tar failed on $download" }
            Remove-Item $download -Force
        }
        elseif ($leaf -match '\.msi$') {
            $process = Start-Process msiexec.exe -ArgumentList '/a', "`"$download`"", '/qn', "TARGETDIR=`"$into`"" -Wait -PassThru
            if ($process.ExitCode -ne 0) { throw "msiexec /a failed on $download (exit $($process.ExitCode))" }
            Remove-Item $download, (Join-Path $into $leaf) -Force -ErrorAction SilentlyContinue
        }
        else { Move-Item $download (Join-Path $into $leaf) -Force }
        if (-not (Test-Path $folder)) { throw "$($tool.name): the download holds no $($tool.folder)" }
    }
    if ($Check) { continue }
    if ($tool.variable) { "$($tool.variable)=$folder" }
    # Variables that name a file or folder of the tool, relative to -Destination.
    if ($tool.variables) { $tool.variables.PSObject.Properties | ForEach-Object { "$($_.Name)=$(Join-Path $Destination $_.Value)" } }
}
