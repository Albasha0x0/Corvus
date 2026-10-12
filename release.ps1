# Cuts a release from a clean main: bumps the version, checks the release notes, regenerates the generated docs, runs the
# full suite, commits and tags. With -Push it pushes main and the tag, waits for release.yml, verifies every archive
# against SHA256SUMS, sets the GitHub release body from the notes and prints the manual channel checklist.
# Usage:  ./release.ps1 -Version 1.2.0              # bump, check, test, commit, tag (local only)
#         ./release.ps1 -Version 1.2.0 -Push        # ... then push, wait for the workflow and verify the release
#         ./release.ps1 -Version 1.2.0 -VerifyOnly  # verify an existing release and print the checklist
# Needs git, the .NET SDK and, for -Push / -VerifyOnly, an authenticated gh.
param(
    [Parameter(Mandatory)][string]$Version,
    [switch]$Push,
    [switch]$VerifyOnly,
    [switch]$SkipTests,
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
# Migration only: each archive also ships under its name from before the rename, for the update of installs made then.
$assets = @(foreach ($name in 'corvus', 'NetDecompilerMcp') { $rids | ForEach-Object { if ($_ -like 'win-*') { "$name-$_.zip" } else { "$name-$_.tar.gz" } } }) + 'SHA256SUMS'

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

        $csproj = Get-Content $project -Raw
        $bumped = [regex]::Replace($csproj, '<Version>[^<]+</Version>', "<Version>$Version</Version>")
        if ($bumped -eq $csproj -and $csproj -notmatch "<Version>$([regex]::Escape($Version))</Version>") { Fail "no <Version> in $project" }
        [IO.File]::WriteAllText($project, $bumped)
        # The MCP Registry entry packed into the .NET tool names the same version (ToolPackageTests).
        $server = Join-Path $root 'src/Corvus/.mcp/server.json'
        [IO.File]::WriteAllText($server, [regex]::Replace((Get-Content $server -Raw), '"version": "[^"]+"', "`"version`": `"$Version`""))

        # Generated docs and the skill can name the version; regenerate, then run the full suite on the result.
        $env:CORVUS_UPDATE_DOCS = '1'
        try { Run 'dotnet' @('test', (Join-Path $root 'tests/Corvus.Tests'), '--nologo') }
        finally { Remove-Item Env:CORVUS_UPDATE_DOCS }
        if (-not $SkipTests) { Run 'dotnet' @('test', (Join-Path $root 'tests/Corvus.Tests'), '--nologo', '-p:CORVUS_ALL_TESTS=1') }

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

    # The workflow run for the tag: wait for it to appear, then for it to finish.
    $run = $null
    for ($i = 0; $i -lt 30 -and -not $run; $i++) {
        $run = gh run list --repo $Repo --workflow release.yml --branch $tag --limit 1 --json databaseId --jq '.[0].databaseId'
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
Write-Host "Verified $($assets.Count - 1) archives against SHA256SUMS."

# The release body is this version's notes.
$body = Join-Path $work 'notes.md'
[IO.File]::WriteAllText($body, (Get-Notes) + "`n")
Run 'gh' @('release', 'edit', $tag, '--repo', $Repo, '--notes-file', $body)

Write-Host ""
Write-Host "Release $tag is published. Manual channel steps:"
Write-Host "  [ ] Install check: run the install script on a clean machine or account (GITHUB_TOKEN while the repository is private),"
Write-Host "      then 'corvus version' (expect $Version) and 'corvus status'."
Write-Host "  [ ] Update check: 'corvus update --dry-run' on an older install names $tag and SHA256SUMS."
Write-Host "  [ ] Announce: the release notes link, https://github.com/$Repo/releases/tag/$tag"
Write-Host "  Archive hashes for package manifests:"
foreach ($asset in $assets | Where-Object { $_ -ne 'SHA256SUMS' }) { Write-Host ("    {0}  {1}" -f $sums[$asset], $asset) }
Remove-Item $work -Recurse -Force
