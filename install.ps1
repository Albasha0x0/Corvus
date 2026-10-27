# Installs Corvus for the current user and registers it with the MCP clients found.
# Existing registrations are refreshed; new clients are registered after one confirmation (Enter = yes).
#   irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1))) -Yes
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Albasha0x0/Corvus/main/install.ps1))) -Uninstall
# Options:
#   -Version X.Y.Z   install that release (pin or roll back)
#   -DryRun          show what would be installed and registered; change nothing
#   -Yes             register new clients without asking
#   -Client a,b      register only the named clients
#   -WithLive        install the tested Frida into a private Python environment and turn on --live-install-frida
#   -Uninstall       remove the program and registrations; data is kept unless -PurgeData is given
# Environment:
#   CORVUS_VERSION, CORVUS_YES=1   as -Version, -Yes
#   CORVUS_REPO                    owner/name
#   CORVUS_ARCHIVE                 local release archive
#   CORVUS_SHA256SUMS              manifest to verify CORVUS_ARCHIVE; without it a local archive is trusted
#   GITHUB_TOKEN                   optional; higher GitHub API rate limit
#   CORVUS_REQUIRE_ATTESTATION     1: refuse a build whose provenance was not checked; 0: skip the check (self-built)
# Downloads are verified against the release's SHA256SUMS; a missing manifest or a mismatch stops the install.
# With gh signed in, the build provenance must name this repository's release workflow.
param([switch]$Uninstall, [switch]$PurgeData, [string]$Version, [switch]$DryRun, [switch]$Yes, [string[]]$Client, [switch]$WithLive)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = if ($env:CORVUS_REPO) { $env:CORVUS_REPO } else { 'Albasha0x0/Corvus' }
$root = Join-Path $env:LOCALAPPDATA 'Corvus'
$current = Join-Path $root 'current'
$exe = Join-Path $current 'corvus.exe'
# Migration only: the install made before the rename; the program's install command moves its registrations and data.
$legacyExe = Join-Path $env:LOCALAPPDATA 'NetDecompilerMcp\current\NetDecompilerMcp.exe'
if (-not $Version) { $Version = $env:CORVUS_VERSION }
if ($Version) { $Version = $Version.TrimStart('v') }
if ($Version -and [version](($Version -split '[+-]')[0]) -lt [version]'1.2.0') { throw "Release $Version predates Corvus (1.2.0 is the first)." }

# Options passed on to the program's install (or uninstall) command.
$setupArgs = @()
if ($DryRun) { $setupArgs += '--dry-run' }
if ($Yes) { $setupArgs += '--yes' }
if ($WithLive) { $setupArgs += '--with-live' }
if ($Client) { $setupArgs += @('--client', ($Client -join ',')) }

if ($Uninstall) {
    $removeArgs = @($setupArgs | Where-Object { $_ -eq '--dry-run' })
    if ($PurgeData) { $removeArgs += '--purge-data' }
    if (Test-Path $exe) { & $exe uninstall @removeArgs }
    elseif (Test-Path $legacyExe) { & $legacyExe uninstall @removeArgs }
    else { Write-Host 'Corvus is not installed.' }
    return
}

$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
$rid = if ($arch -eq 'ARM64') { 'win-arm64' } else { 'win-x64' }
$asset = "corvus-$rid.zip"
$archive = Join-Path ([IO.Path]::GetTempPath()) ("corvus-" + [guid]::NewGuid().ToString('N') + '.zip')
$sums = "$archive.sha256sums"
$dryStaging = "$archive.staged"
$unverified = 'refusing to install an unverified build'
$release = if ($Version) { "v$Version" } else { 'the latest release' }
$tag = if ($Version) { "v$Version" } else { $null }

# The archive's SLSA build provenance through gh: the line to print, or a throw when gh finds the build was not made
# by this repository's release workflow. Exit 1 with words other than these refuses: unrecognised is not a pass.
function Test-Provenance([string]$file, [string]$tag) {
    $ErrorActionPreference = 'Continue'
    if ($env:CORVUS_REQUIRE_ATTESTATION -eq '0') { return 'Provenance not checked (CORVUS_REQUIRE_ATTESTATION=0).' }
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { $reason = 'gh is not on PATH' }
    else {
        $ghArgs = @('attestation', 'verify', $file, '--repo', $repo, '--signer-workflow', "$repo/.github/workflows/release.yml")
        if ($tag) { $ghArgs += @('--source-ref', "refs/tags/$tag") }
        # Windows PowerShell wraps each stderr line in an error record; an empty line's message is the type name.
        $out = (& gh @ghArgs 2>&1 | ForEach-Object { if ($_ -is [Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" } } |
            Where-Object { $_ -ne 'System.Management.Automation.RemoteException' }) -join "`n"
        $code = $LASTEXITCODE
        $first = @($out -split "`n" | ForEach-Object { $_.Trim() -replace '^Error: ' } | Where-Object { $_ }) | Select-Object -First 1
        if ($code -eq 0) { return "Provenance verified: $asset was built by $repo's release workflow." }
        # gh's exit code 4: authentication required.
        if ($code -eq 4) { $reason = 'gh is not signed in: gh auth login, or set GH_TOKEN' }
        elseif ($code -ne 1 -or $out -match 'unknown command|unknown flag|sigstore verifier|trusted root|dial tcp|no such host|connection refused|connection reset|i/o timeout|timed out|timeout exceeded|TLS handshake|proxyconnect|HTTP (401|403|429|5\d\d)') { $reason = "gh: $first" }
        else { throw "Provenance check failed for $asset against $repo's release workflow: $first" }
    }
    if ($env:CORVUS_REQUIRE_ATTESTATION -eq '1') { throw "Provenance not checked ($reason) and CORVUS_REQUIRE_ATTESTATION=1; refusing to install." }
    return "Provenance not checked ($reason)."
}

try {
    if ($env:CORVUS_ARCHIVE) {
        Copy-Item $env:CORVUS_ARCHIVE $archive
        if ($env:CORVUS_SHA256SUMS) { Copy-Item $env:CORVUS_SHA256SUMS $sums; $source = $env:CORVUS_SHA256SUMS } else { $sums = $null; $source = 'none (local archive)' }
        $release = $env:CORVUS_ARCHIVE
    } elseif ($env:GITHUB_TOKEN) {
        $headers = @{ Authorization = "Bearer $env:GITHUB_TOKEN"; 'User-Agent' = 'Corvus-installer' }
        $api = if ($Version) { "https://api.github.com/repos/$repo/releases/tags/v$Version" } else { "https://api.github.com/repos/$repo/releases/latest" }
        $info = Invoke-RestMethod $api -Headers $headers
        $item = $info.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
        if (-not $item) { throw "Release $($info.tag_name) has no $asset." }
        $sumsItem = $info.assets | Where-Object { $_.name -eq 'SHA256SUMS' } | Select-Object -First 1
        if (-not $sumsItem) { throw "Release $($info.tag_name) has no SHA256SUMS manifest; $unverified." }
        $headers.Accept = 'application/octet-stream'
        Invoke-WebRequest $item.url -Headers $headers -OutFile $archive -UseBasicParsing
        Invoke-WebRequest $sumsItem.url -Headers $headers -OutFile $sums -UseBasicParsing
        $release = $info.tag_name
        $tag = $info.tag_name
        $source = "SHA256SUMS of $($info.tag_name)"
    } else {
        $base = if ($Version) { "https://github.com/$repo/releases/download/v$Version" } else { "https://github.com/$repo/releases/latest/download" }
        Write-Host "Downloading $asset ($release)..."
        Invoke-WebRequest "$base/$asset" -OutFile $archive -UseBasicParsing
        try { Invoke-WebRequest "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing }
        catch { throw "$release has no SHA256SUMS manifest; $unverified." }
        $source = "$base/SHA256SUMS"
    }

    if ($sums) {
        $line = Get-Content $sums | Where-Object { $_ -match "^[0-9a-fA-F]{64} [ *]$([regex]::Escape($asset))$" } | Select-Object -First 1
        if (-not $line) { throw "SHA256SUMS lists no $asset; $unverified." }
        $expected = $line.Substring(0, 64)
        $actual = (Get-FileHash $archive -Algorithm SHA256).Hash
        if ($actual -ne $expected) { throw "Checksum mismatch for $asset (expected $expected, got $actual); the download is corrupt or was altered." }
    }
    Write-Host (Test-Provenance $archive $tag)

    if ($DryRun) {
        # A staged copy outside the install root plans the registration for the program that would be installed.
        Expand-Archive $archive $dryStaging -Force
        $staged = Join-Path $dryStaging 'corvus.exe'
        $version = (& $staged version).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $version) { throw 'The downloaded build does not run on this machine.' }
        Write-Host "Release: $release ($asset, Corvus $version)"
        Write-Host "Checksum: $source"
        Write-Host "Would install to: $(Join-Path $root "versions\$version"), linked as $current"
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not (($userPath -split ';') -contains $current)) { Write-Host "Would add to the user PATH: $current" }
        & $staged install --command $exe @setupArgs
        if ($LASTEXITCODE -ne 0) { throw 'The registration plan reported a problem (see above).' }
        return
    }

    $versions = Join-Path $root 'versions'
    $staging = Join-Path $versions ('.new-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force $staging | Out-Null
    Expand-Archive $archive $staging -Force
    $version = (& (Join-Path $staging 'corvus.exe') version).Trim()
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

    Write-Host "Installed Corvus $version to $target"
    & $exe install @setupArgs
    if ($LASTEXITCODE -ne 0) { throw 'Registration reported a problem (see above).' }
    Write-Host ''
    Write-Host 'Done. Commands: corvus status | update | uninstall (new terminals have it on PATH).'
} finally {
    Remove-Item $archive, "$archive.sha256sums" -Force -ErrorAction SilentlyContinue
    Remove-Item $dryStaging -Recurse -Force -ErrorAction SilentlyContinue
}
