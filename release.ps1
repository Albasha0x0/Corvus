# Cuts a release from a clean main: bumps the version, checks the release notes, regenerates the generated docs, runs the
# full suite, commits and tags. With -Push it pushes main and the tag, waits for release.yml, verifies every asset
# (archives, MCP bundles, the NuGet tool package) against SHA256SUMS, sets the GitHub release body from the notes and
# prints the manual channel checklist.
# Usage:  ./release.ps1 -Version 1.2.0              # check, test (full suite unless it passed on this tree; a patch
#                                                   #   release reruns only the changed families), bump, commit, tag
#         ./release.ps1 -Version 1.2.0 -Push        # ... then push, wait for the workflow and verify the release
#         ./release.ps1 -Version 1.2.0 -VerifyOnly  # verify an existing release and print the checklist
#         ./release.ps1 -Version 1.2.0 -Bundle DIR  # MCP bundles (.mcpb) from the archives in DIR (release.yml runs this)
# Needs PowerShell 7, git, the .NET SDK and, for -Push / -VerifyOnly, an authenticated gh.
#Requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$Version,
    [switch]$Push,
    [switch]$VerifyOnly,
    [switch]$SkipTests,
    [string]$Bundle,
    [string]$Repo = 'Albasha0x0/Corvus'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$Version = $Version.TrimStart('v')
$tag = "v$Version"
$project = Join-Path $root 'src/Corvus/Corvus.csproj'
$notes = Join-Path $root 'docs/release-notes.md'
$workflow = Join-Path $root '.github/workflows/release.yml'

function Fail([string]$message) { Write-Host "error: $message" -ForegroundColor Red; exit 1 }
function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { Fail "$exe $($arguments -join ' ') failed ($LASTEXITCODE)" }
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') { Fail "version '$Version' is not major.minor.patch" }

# The release targets are the release workflow's matrix; the archives and SHA256SUMS are what it attaches.
$rids = [regex]::Matches((Get-Content $workflow -Raw), 'rid: ([a-z0-9-]+)') | ForEach-Object { $_.Groups[1].Value }
if (-not $rids) { Fail "no rid entries in $workflow" }
$assets = @($rids | ForEach-Object { if ($_ -like 'win-*') { "corvus-$_.zip" } else { "corvus-$_.tar.gz" } }) + 'SHA256SUMS'

# MCP bundles for the targets marked bundle: true: the release archive under server/ plus mcpb/manifest.json for its platform.
$bundleRids = [regex]::Matches((Get-Content $workflow -Raw), 'rid: ([a-z0-9-]+)[^}\n]*bundle: true') | ForEach-Object { $_.Groups[1].Value }
$assets += $bundleRids | ForEach-Object { "corvus-$_.mcpb" }
# The NuGet .NET tool, attached for the nuget.org push once the repository is public.
$nupkg = "CorvusRE.$Version.nupkg"
$assets += $nupkg

function New-Bundles([string]$dir) {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    foreach ($rid in $bundleRids) {
        $windows = $rid -like 'win-*'
        $archive = Join-Path $dir ("corvus-$rid" + $(if ($windows) { '.zip' } else { '.tar.gz' }))
        if (-not (Test-Path $archive)) { Fail "no $archive" }
        $stage = Join-Path ([IO.Path]::GetTempPath()) "corvus-mcpb-$rid-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
        $server = Join-Path $stage 'server'
        New-Item -ItemType Directory $server | Out-Null
        try {
            if ($windows) { Expand-Archive $archive $server }
            else {
                # .NET's reader keeps the entries' Unix modes, and any OS can run it (a tar on PATH may not read drive paths).
                $gzip = [IO.Compression.GZipStream]::new([IO.File]::OpenRead($archive), [IO.Compression.CompressionMode]::Decompress)
                try { [Formats.Tar.TarFile]::ExtractToDirectory($gzip, $server, $false) } finally { $gzip.Dispose() }
            }
            $manifest = Get-Content (Join-Path $root 'mcpb/manifest.json') -Raw | ConvertFrom-Json -AsHashtable
            $entry = 'server/corvus' + $(if ($windows) { '.exe' } else { '' })
            $manifest.version = $Version
            $manifest.server.entry_point = $entry
            $manifest.server.mcp_config.command = '${__dirname}/' + $entry
            $manifest.compatibility.platforms = @(switch -Wildcard ($rid) { 'win-*' { 'win32' } 'osx-*' { 'darwin' } default { 'linux' } })
            [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'), ($manifest | ConvertTo-Json -Depth 10))

            $target = Join-Path $dir "corvus-$rid.mcpb"
            if (Test-Path $target) { Remove-Item $target }
            $zip = [IO.Compression.ZipFile]::Open($target, 'Create')
            try {
                foreach ($file in Get-ChildItem $stage -Recurse -File) {
                    $name = [IO.Path]::GetRelativePath($stage, $file.FullName).Replace('\', '/')
                    $item = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $name)
                    # Unix permissions in the high 16 bits, so the launcher stays executable when the client unpacks it.
                    if (-not $windows) {
                        $mode = if (-not $IsWindows) { [int]$file.UnixFileMode } elseif ($name -eq $entry) { 0x1ED } else { 0x1A4 }
                        $item.ExternalAttributes = (0x8000 -bor $mode) -shl 16
                    }
                }
            }
            finally { $zip.Dispose() }
            Write-Host "Bundled $target"
        }
        finally { Remove-Item $stage -Recurse -Force }
    }
}

if ($Bundle) {
    New-Bundles (Resolve-Path $Bundle).Path
    exit 0
}

# The notes section of this version: from its heading to the next version heading.
function Get-Notes {
    $text = (Get-Content $notes -Raw) -replace "`r`n", "`n"
    $match = [regex]::Match($text, "(?ms)^## $([regex]::Escape($Version))\s*\n(.*?)(?=^## \d|\z)")
    if (-not $match.Success) { Fail "docs/release-notes.md has no '## $Version' section; write the notes first" }
    $first = [regex]::Match($text, '(?m)^## (\d+\.\d+\.\d+)')
    if ($first.Groups[1].Value -ne $Version) { Fail "the first version in docs/release-notes.md is $($first.Groups[1].Value), not $Version" }
    return $match.Groups[1].Value.Trim()
}

if (-not $VerifyOnly) {
    Push-Location $root
    try {
        if ((git branch --show-current) -ne 'main') { Fail 'release from main' }
        if (git status --porcelain) { Fail 'the working tree is not clean' }
        if (git tag --list $tag) { Fail "tag $tag exists" }
        $null = Get-Notes

        # test.ps1 -Full -Exhaustive stamps the clean tree it passed on; the bump below changes only version strings and generated docs,
        # whose quick run follows, so a passed tree needs no second full run. A patch release (x.y.z, z > 0) takes a pass
        # made up partly of reused family passes; a minor release (x.y.0) wants the whole exhaustive suite, which also
        # catches what a family key cannot see, unless only documentation changed since its last whole pass.
        $gitDir = [IO.Path]::GetFullPath((git rev-parse --git-common-dir).Trim())
        $tree = (git rev-parse 'HEAD^{tree}').Trim()
        $stamp = Join-Path $gitDir 'corvus-full-suite.stamp'
        $have = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { '' }
        $whole = Join-Path $gitDir 'corvus-whole-suite.stamp'
        $whole = if (Test-Path $whole) { (Get-Content $whole -Raw).Trim() } else { $null }
        Import-Module (Join-Path $root 'test-reuse.psm1') -Force
        $docsOnly = $whole -and $whole -ne $tree -and (Test-DocsOnly @(git diff --name-only $whole $tree 2>$null))
        $reusable = [int]($Version -split '\.')[2] -gt 0 -or $docsOnly
        if ($docsOnly) { Write-Host "Only documentation changed since the last whole pass ($($whole.Substring(0, 8))): family passes are reused." }
        $passed = $have -eq "$tree exhaustive" -or ($reusable -and $have -eq "$tree exhaustive reused")
        if ($passed) { Write-Host "The full suite passed on this tree ($have); not run again." }
        # Before the bump, on the clean tree, so the run records its family passes.
        elseif (-not $SkipTests) {
            if ($reusable) { & (Join-Path $root 'test.ps1') -Full -Exhaustive -Reuse } else { & (Join-Path $root 'test.ps1') -Full -Exhaustive }
            if ($LASTEXITCODE -ne 0) { Fail 'the full suite failed' }
            $passed = $true
        }
        # A second Ghidra version (the oldest supported, say): the engine tests again with it, skipped when they passed on these inputs.
        if (-not $SkipTests) {
            & (Join-Path $root 'test.ps1') -SecondGhidra
            if ($LASTEXITCODE -ne 0) { Fail 'the engine tests on the second Ghidra failed' }
        }

        $csproj = Get-Content $project -Raw
        $bumped = [regex]::Replace($csproj, '<Version>[^<]+</Version>', "<Version>$Version</Version>")
        if ($bumped -eq $csproj -and $csproj -notmatch "<Version>$([regex]::Escape($Version))</Version>") { Fail "no <Version> in $project" }
        [IO.File]::WriteAllText($project, $bumped)
        # The MCP Registry entry packed into the .NET tool, the bundle manifest and the plugins name the same version
        # (their tests check); the plugins also run that version of the .NET tool.
        foreach ($file in 'src/Corvus/.mcp/server.json', 'mcpb/manifest.json', '.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', '.codex-plugin/plugin.json') {
            $path = Join-Path $root $file
            $text = [regex]::Replace((Get-Content $path -Raw), '"version": "[^"]+"', "`"version`": `"$Version`"")
            [IO.File]::WriteAllText($path, [regex]::Replace($text, '"CorvusRE@[^"]+"', "`"CorvusRE@$Version`""))
        }

        # Generated docs and the skill can name the version; regenerate them with a quick run.
        $env:CORVUS_UPDATE_DOCS = '1'
        try { Run 'dotnet' @('test', (Join-Path $root 'tests/Corvus.Tests'), '--nologo') }
        finally { Remove-Item Env:CORVUS_UPDATE_DOCS }

        Run 'git' @('add', '-A')
        Run 'git' @('commit', '-m', "release: $Version")
        Run 'git' @('tag', '-a', $tag, '-m', "Corvus $Version")
        Write-Host "Committed and tagged $tag."
        if (-not $Push) {
            Write-Host "Next: ./release.ps1 -Version $Version -VerifyOnly after 'git push origin main $tag', or run again with -Push."
            exit 0
        }
        Run 'git' @('push', 'origin', 'main')
        Run 'git' @('push', 'origin', $tag)
    }
    finally { Pop-Location }

    # The workflow run for the tag's commit (an earlier run of a re-pushed tag has the same branch): wait for it, then for its end.
    $commit = git -C $root rev-parse "$tag^{commit}"
    $run = $null
    for ($i = 0; $i -lt 30 -and -not $run; $i++) {
        $run = gh run list --repo $Repo --workflow release.yml --commit $commit --limit 1 --json databaseId --jq '.[0].databaseId'
        if (-not $run) { Start-Sleep -Seconds 10 }
    }
    if (-not $run) { Fail "no release.yml run for $tag" }
    Run 'gh' @('run', 'watch', $run, '--repo', $Repo, '--exit-status')
}

# Every expected asset is attached and matches SHA256SUMS.
$listed = gh release view $tag --repo $Repo --json assets --jq '.assets[].name'
if ($LASTEXITCODE -ne 0) { Fail "no release $tag" }
$missing = @($assets | Where-Object { $_ -notin $listed })
if ($missing) { Fail "release $tag lacks $($missing -join ', ')" }

$work = Join-Path ([IO.Path]::GetTempPath()) "corvus-release-$Version"
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory $work | Out-Null
Run 'gh' @('release', 'download', $tag, '--repo', $Repo, '--dir', $work)
$sums = @{}
foreach ($line in Get-Content (Join-Path $work 'SHA256SUMS')) {
    if ($line -match '^([0-9a-f]{64}) [ *](.+)$') { $sums[$Matches[2]] = $Matches[1] }
}
foreach ($asset in $assets | Where-Object { $_ -ne 'SHA256SUMS' }) {
    if (-not $sums.ContainsKey($asset)) { Fail "SHA256SUMS lists no $asset" }
    $hash = (Get-FileHash (Join-Path $work $asset) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $sums[$asset]) { Fail "$asset does not match SHA256SUMS" }
}
Write-Host "Verified $($assets.Count - 1) assets against SHA256SUMS."

# The release body is this version's notes.
$body = Join-Path $work 'notes.md'
[IO.File]::WriteAllText($body, (Get-Notes) + "`n")
Run 'gh' @('release', 'edit', $tag, '--repo', $Repo, '--notes-file', $body)

# Post-release update: the previous release installed by install.sh in WSL with a throwaway HOME, then 'corvus update' to this one.
$previous = git -C $root describe --tags --abbrev=0 "$tag^" 2>$null
$distro = if ($env:CORVUS_RELEASE_WSL) { $env:CORVUS_RELEASE_WSL } else { 'Ubuntu' }
if ($previous -and (Get-Command wsl -ErrorAction SilentlyContinue)) {
    $updateTest = Join-Path $work 'update-test.sh'
    [IO.File]::WriteAllText($updateTest, @'
set -eu
work=$(mktemp -d /tmp/corvus-update-XXXXXX)
trap 'rm -rf "$work"' EXIT
export HOME="$work/home" CORVUS_HOME="$work/home/Corvus" XDG_DATA_HOME="$work/home/.local/share" XDG_CONFIG_HOME="$work/home/.config"
mkdir -p "$HOME"
sh "$1" --version "$2" --yes >"$work/install.log" 2>&1 || { cat "$work/install.log"; exit 1; }
"$CORVUS_HOME/current/corvus" update --version "$3" >"$work/update.log" 2>&1 || { cat "$work/update.log"; exit 1; }
after=$("$CORVUS_HOME/current/corvus" version)
case "$after" in *"$3"*) echo "update $2 -> $after" ;; *) echo "update from $2 reports $after, not $3"; exit 1 ;; esac
'@.Replace("`r`n", "`n"))
    $wslPath = { param($p) (wsl -d $distro -- wslpath -a ($p -replace '\\', '/')) -join '' }
    wsl -d $distro -- sh (& $wslPath $updateTest) (& $wslPath (Join-Path $root 'install.sh')) $previous.TrimStart('v') $Version
    if ($LASTEXITCODE -ne 0) { Fail "update from $previous to $tag failed" }
}
else { Write-Host "Update check skipped: no previous tag or no WSL ($distro)." -ForegroundColor Yellow }

Write-Host ""
Write-Host "Release $tag is published. Manual channel steps:"
Write-Host "  [ ] Install check: run the install script on a clean machine or account (GITHUB_TOKEN while the repository is private),"
Write-Host "      then 'corvus version' (expect $Version) and 'corvus status'."
Write-Host "  [ ] MCP bundle: install corvus-<rid>.mcpb in a client that takes bundles (Claude Desktop); the server starts and lists its tools."
Write-Host "  [ ] .NET tool: 'dotnet tool install -g CorvusRE --add-source <folder with $nupkg>', then 'corvus version' (expect $Version)"
Write-Host "      and 'corvus status' (Installed as: dotnet-tool); 'dnx CorvusRE --add-source <folder> --yes version' likewise."
Write-Host "  [ ] Announce: the release notes link, https://github.com/$Repo/releases/tag/$tag"
Write-Host "  [ ] nuget.org: CorvusRE lists $Version (release.yml's publish job)."
Write-Host "  [ ] MCP Registry: io.github.Albasha0x0/corvus lists $Version (the same job, after nuget.org)."
Write-Host "  [ ] winget, Scoop, Homebrew: manifests in their own repositories, with the archive hashes below."
Write-Host "  [ ] Claude Code and Codex plugin marketplace: install corvus from $Repo in each; the server reports $Version."
Write-Host "  Archive hashes for package manifests:"
foreach ($asset in $assets | Where-Object { $_ -ne 'SHA256SUMS' }) { Write-Host ("    {0}  {1}" -f $sums[$asset], $asset) }
Remove-Item $work -Recurse -Force
