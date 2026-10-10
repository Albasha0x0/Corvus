# Installs NetDecompilerMcp for the current user and registers it with every installed MCP client.
#   irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
# Uninstall (keeps your data; add -PurgeData to delete it too):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1))) -Uninstall
# Environment: NDM_REPO (owner/name), NDM_ARCHIVE (local release archive), GITHUB_TOKEN (private repositories).
param([switch]$Uninstall, [switch]$PurgeData)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = if ($env:NDM_REPO) { $env:NDM_REPO } else { 'Albasha0x0/Corvus' }
$root = Join-Path $env:LOCALAPPDATA 'NetDecompilerMcp'
$current = Join-Path $root 'current'
$exe = Join-Path $current 'NetDecompilerMcp.exe'

if ($Uninstall) {
    if (Test-Path $exe) { if ($PurgeData) { & $exe uninstall --purge-data } else { & $exe uninstall } } else { Write-Host 'NetDecompilerMcp is not installed.' }
    return
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
$rid = if ($arch -eq 'ARM64') { 'win-arm64' } else { 'win-x64' }
$asset = "NetDecompilerMcp-$rid.zip"
$archive = Join-Path ([IO.Path]::GetTempPath()) ("ndm-" + [guid]::NewGuid().ToString('N') + '.zip')

try {
    if ($env:NDM_ARCHIVE) {
        Copy-Item $env:NDM_ARCHIVE $archive
    } elseif ($env:GITHUB_TOKEN) {
        $headers = @{ Authorization = "Bearer $env:GITHUB_TOKEN"; 'User-Agent' = 'NetDecompilerMcp-installer' }
        $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers $headers
        $item = $release.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
        if (-not $item) { throw "Release $($release.tag_name) has no $asset." }
        $headers.Accept = 'application/octet-stream'
        Invoke-WebRequest $item.url -Headers $headers -OutFile $archive -UseBasicParsing
    } else {
        Write-Host "Downloading $asset..."
        Invoke-WebRequest "https://github.com/$repo/releases/latest/download/$asset" -OutFile $archive -UseBasicParsing
    }

    $versions = Join-Path $root 'versions'
    $staging = Join-Path $versions ('.new-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force $staging | Out-Null
    Expand-Archive $archive $staging -Force
    $version = (& (Join-Path $staging 'NetDecompilerMcp.exe') version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $version) { throw 'The downloaded build does not run on this machine.' }

    $target = Join-Path $versions $version
    if (Test-Path $target) {
        try { Remove-Item $target -Recurse -Force } catch { $target = "$target-" + [guid]::NewGuid().ToString('N').Substring(0, 6) }
    }
    Move-Item $staging $target

    if (Test-Path $current) { cmd /c rmdir "$current" | Out-Null }
    cmd /c mklink /J "$current" "$target" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create $current." }
    Get-ChildItem $versions -Directory | Where-Object { $_.FullName -ne $target } | ForEach-Object {
        try { Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop } catch { }
    }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $current)) {
        [Environment]::SetEnvironmentVariable('Path', (@($userPath, $current) | Where-Object { $_ }) -join ';', 'User')
        $env:Path = "$env:Path;$current"
    }

    Write-Host "Installed NetDecompilerMcp $version to $target"
    & $exe install
    if ($LASTEXITCODE -ne 0) { throw 'Registration reported a problem (see above).' }
    Write-Host ''
    Write-Host 'Done. Commands: NetDecompilerMcp status | update | uninstall (new terminals have it on PATH).'
} finally {
    Remove-Item $archive -Force -ErrorAction SilentlyContinue
}
