# Cuts a release from a clean main: bumps the version, checks the notes, regenerates docs, runs the quick set, commits
# and tags. -Push then pushes, waits for release.yml, verifies every asset against SHA256SUMS, sets the release body
# from the notes and prints the manual channel checklist.
# Usage:  ./release.ps1 -Version 1.2.0              # check (a full run passed on this history, -MaxBehind 50),
#                                                   #   bump, quick set, commit, tag
#         ./release.ps1 -Version 1.2.0 -Push        # ... then push, wait for the workflow and verify the release
#         ./release.ps1 -Version 1.2.0 -VerifyOnly  # verify an existing release and print the checklist
#         ./release.ps1 -Version 1.2.0 -Bundle DIR  # MCP bundles (.mcpb) from the archives in DIR (release.yml runs this)
#         ./release.ps1 -Version 1.2.0 -Summary F   # write the test summary the release would carry to F
# Needs PowerShell 7, git, the .NET SDK and, for -Push / -VerifyOnly, an authenticated gh.
#Requires -Version 7.0
param(
    [Parameter(Mandatory)][string]$Version,
    [switch]$Push,
    [switch]$VerifyOnly,
    [switch]$SkipTests,
    # The most commits a release may be ahead of its last full pass.
    [int]$MaxBehind = 50,
    [string]$Bundle,
    [string]$Summary,
    # Where the test records are read from (default: the repository's git directory).
    [string]$Evidence,
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

# MCP bundles for targets marked bundle: true: the archive under server/ plus mcpb/manifest.json.
$bundleRids = [regex]::Matches((Get-Content $workflow -Raw), 'rid: ([a-z0-9-]+)[^}\n]*bundle: true') | ForEach-Object { $_.Groups[1].Value }
$assets += $bundleRids | ForEach-Object { "corvus-$_.mcpb" }
# The .NET tool package; release.yml pushes it to nuget.org.
$nupkg = "CorvusRE.$Version.nupkg"
$assets += $nupkg
# The full pass the release relies on: committed with the bump, attached and attested by release.yml.
$testSummary = 'release/tests.json'
$assets += 'corvus-tests.json'

# Summary of the full pass at $passedAt (null: none checked, $why says why) from test.ps1's records in $gitDir.
# A fact not recorded is 'unknown'; tool names only, no paths.
function Get-TestSummary([string]$gitDir, [string]$passedAt, [string]$why) {
    $unknown = 'unknown'
    $summary = [ordered]@{
        schema = 1; version = $Version; commit = $unknown; tree = $unknown; date = $unknown; strength = $unknown
        reusedEarlierPasses = $unknown; commitsBehind = $unknown; testsRun = $unknown; failed = $unknown
        families = $unknown; deferred = $unknown; engines = $unknown; tools = $unknown
        os = "$([Runtime.InteropServices.RuntimeInformation]::OSDescription) $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)".ToLowerInvariant()
        sdk = $unknown; environment = 'the machine that tagged the release; the run itself records no OS or SDK'
    }
    $sdk = (& dotnet --version 2>$null) -join ''
    if ($LASTEXITCODE -eq 0 -and $sdk) { $summary.sdk = $sdk.Trim() }
    if (-not $passedAt) { $summary.commit = "$unknown ($why)"; return $summary }
    $summary.commit = $passedAt
    $behind = git -C $root rev-list --count "$passedAt..HEAD" 2>$null
    if ($LASTEXITCODE -eq 0) { $summary.commitsBehind = [int]$behind }

    # Ledger line: <commit> <tree> <strength> [reused] <yyyy-MM-ddTHH:mm>.
    $ledger = Join-Path $gitDir 'corvus-full-passes.txt'
    $line = if (Test-Path $ledger) { Get-Content $ledger | Where-Object { ($_ -split ' ')[0] -eq $passedAt } | Select-Object -Last 1 }
    if ($line) {
        $fields = $line -split ' '
        $summary.tree = $fields[1]; $summary.strength = $fields[2]; $summary.date = $fields[-1]
        $summary.reusedEarlierPasses = $fields -contains 'reused'
    }

    # Runs matched by commit and end minute; their class records give test counts. A family's stamp may come from a
    # run that failed in another family.
    $history = Join-Path $gitDir 'corvus-test-history.jsonl'
    $runs = @(if (Test-Path $history) {
        Select-String -Path $history -SimpleMatch '"kind":"run"' | ForEach-Object { $_.Line | ConvertFrom-Json } |
            Where-Object { $_.mode -in 'push', 'full' -and $_.commit }
    })
    function Find-Run([string]$commit, [string]$at) { $runs | Where-Object { $commit.StartsWith($_.commit) -and $_.at -eq $at.Replace('T', ' ') } | Select-Object -Last 1 }
    $run = if ($line) { Find-Run $passedAt $summary.date }
    if (-not $run) { $run = $runs | Where-Object { $passedAt.StartsWith($_.commit) -and $_.code -eq 0 } | Select-Object -Last 1 }
    if ($run) {
        $summary.testsRun = $run.tests; $summary.failed = $run.failed
        if ($null -ne $run.permits) {
            $engines = @($run.permits.PSObject.Properties.Name -split ',')
            $summary.engines = [ordered]@{}
            foreach ($engine in 'ida', 'ghidra') { $summary.engines[$engine] = if ("engine-$engine" -in $engines) { 'ran' } else { 'not in this run (reused or not available)' } }
        }
    }

    # Newest recorded pass of each family, with its test count when the history has it.
    $stampsFile = Join-Path $gitDir 'corvus-family-stamps.json'
    if (Test-Path $stampsFile) {
        $stamps = Get-Content $stampsFile -Raw | ConvertFrom-Json -AsHashtable
        $classMap = Get-ClassMap (Join-Path $root 'tests/Corvus.Tests')
        $wanted = @{}
        foreach ($name in $stamps.Keys) { if ($r = Find-Run $stamps[$name].commit $stamps[$name].at) { $wanted[$name] = $r.run } }
        $counts = @{}
        if ($wanted.Count) {
            $ids = @($wanted.Values | Sort-Object -Unique)
            foreach ($record in Select-String -Path $history -SimpleMatch $ids | Where-Object Line -like '*"kind":"class"*' | ForEach-Object { $_.Line | ConvertFrom-Json }) {
                $counts["$($record.run) $(($record.name -split '\+')[0])"] += [int]$record.tests
            }
        }
        $summary.families = @($stamps.Keys | Sort-Object | ForEach-Object {
            $name = $_
            $tests = $unknown
            if ($wanted[$name] -and $classMap[$name]) {
                $sum = 0
                foreach ($class in $classMap[$name]) { $sum += [int]$counts["$($wanted[$name]) $class"] }
                if ($sum) { $tests = $sum }
            }
            [ordered]@{ name = $name; mode = $stamps[$name].mode; commit = $stamps[$name].commit; at = $stamps[$name].at; tests = $tests }
        })
    }

    # Classes the pass left to the nightly runs, when the last run is the pass.
    $lastRun = Join-Path $gitDir 'corvus-last-run.json'
    if ((Test-Path $lastRun) -and ($last = Get-Content $lastRun -Raw | ConvertFrom-Json) -and $last.commit -and $passedAt.StartsWith($last.commit)) {
        $summary.deferred = [ordered]@{ reason = 'left to the nightly whole run and the test host tier run'; classes = @($last.deferred | Sort-Object) }
    }

    # External tools the suite looks for; the tests that need a tool not found skip.
    $tools = @(Get-LocatedTools (Join-Path $root 'tests/Corvus.Tests'))
    if ($tools) {
        $summary.tools = [ordered]@{
            reason = 'not found on the machine that tagged the release; the tests that need them skip'
            notFound = @($tools | Where-Object { $_ -match '^tool ([^=]+)=$' } | ForEach-Object { $Matches[1] } | Sort-Object)
        }
    }
    return $summary
}

function Write-TestSummary([string]$path, $summary) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllText($path, (($summary | ConvertTo-Json -Depth 5) -replace "`r`n", "`n") + "`n")
}

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
                # .NET's reader keeps Unix modes on any OS; a tar on PATH may not read drive paths.
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

if ($Summary) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $gitDir = if ($Evidence) { $Evidence } else { [IO.Path]::GetFullPath((git -C $root rev-parse --git-common-dir).Trim(), $root) }
    $passedAt = Get-FullPass $root (Join-Path $gitDir 'corvus-full-passes.txt') (Join-Path $gitDir 'corvus-background.passed')
    Write-TestSummary ([IO.Path]::GetFullPath($Summary)) (Get-TestSummary $gitDir $passedAt 'no full pass on this history')
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
        # A bump committed and tagged without -Push is pushed by running again
        # with -Push.
        $resume = $Push -and (git tag --list $tag) -and (git rev-parse "$tag^{commit}") -eq (git rev-parse HEAD)
        if ((git tag --list $tag) -and -not $resume) { Fail "tag $tag exists" }
        if ($resume) { Write-Host "Pushing the existing $tag." }
        else {
            $null = Get-Notes

            # A release needs a full pass at most -MaxBehind commits back and no failure after it on this history.
            # Families not yet verified on these inputs are named.
            $gitDir = [IO.Path]::GetFullPath((git rev-parse --git-common-dir).Trim())
            $result = Join-Path $gitDir 'corvus-background.result'
            $last = if (Test-Path $result) { (Get-Content $result -Raw).Trim() } else { '' }
            if (-not $SkipTests) {
                Import-Module (Join-Path $root 'test-reuse.psm1') -Force
                $passedAt = Get-FullPass $root (Join-Path $gitDir 'corvus-full-passes.txt') (Join-Path $gitDir 'corvus-background.passed')
                if (-not $passedAt) { Fail 'no full run has passed on this history: push, or run ./test.ps1 -Full, and release once it passes' }
                $behind = [int](git rev-list --count "$passedAt..HEAD")
                if ($behind -gt $MaxBehind) { Fail "the last full pass on this history ($($passedAt.Substring(0, 8))) is $behind commits back, more than ${MaxBehind}: run ./test.ps1 -Full" }
                # A failed background run on a commit after the pass, on this history, is a known failure.
                if ($last -match '^(\w+) FAILED' -and ($failed = git rev-parse --verify --quiet "$($Matches[1])^{commit}")) {
                    git merge-base --is-ancestor $passedAt $failed 2>$null; $afterPass = $LASTEXITCODE -eq 0 -and $failed -ne $passedAt
                    git merge-base --is-ancestor $failed HEAD 2>$null; $onHistory = $LASTEXITCODE -eq 0
                    if ($afterPass -and $onHistory) { Fail "the last background run failed after the last pass ($last); fix it first (./test.ps1 -Status), or pass -SkipTests" }
                }
                $summaryData = Get-TestSummary $gitDir $passedAt $null
                Write-Host "The full suite passed on $($passedAt.Substring(0, 8))$(if ($behind) { ", $behind commits back" } else { ', this commit' })$(if ($last -match 'running') { "; a run is going: $last" })."
                $stampsFile = Join-Path $gitDir 'corvus-family-stamps.json'
                if (Test-Path $stampsFile) {
                    $tests = Join-Path $root 'tests/Corvus.Tests'
                    $classMap = Get-ClassMap $tests
                    $keys = Get-FamilyKeys @(git ls-tree -r HEAD) @($classMap.Keys) @(Get-RootReaders $tests) (Get-RunEnvironment -tools (Get-LocatedTools $tests)) (Read-CoverageMap (Join-Path $gitDir 'corvus-coverage-map.json'))
                    $stale = @(Get-StaleFamilies $keys (Get-Content $stampsFile -Raw | ConvertFrom-Json) $false | Where-Object { $_ -ne 'Contract' })
                    if ($stale) { Write-Host "Not yet verified on these inputs: $($stale -join ', ')." -ForegroundColor Yellow }
                }
            }

            $csproj = Get-Content $project -Raw
            $bumped = [regex]::Replace($csproj, '<Version>[^<]+</Version>', "<Version>$Version</Version>")
            if ($bumped -eq $csproj -and $csproj -notmatch "<Version>$([regex]::Escape($Version))</Version>") { Fail "no <Version> in $project" }
            [IO.File]::WriteAllText($project, $bumped)
            # The registry entry, bundle manifest and plugins name the same version; tests check.
            foreach ($file in 'src/Corvus/.mcp/server.json', 'mcpb/manifest.json', '.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', '.codex-plugin/plugin.json') {
                $path = Join-Path $root $file
                $text = [regex]::Replace((Get-Content $path -Raw), '"version": "[^"]+"', "`"version`": `"$Version`"")
                [IO.File]::WriteAllText($path, [regex]::Replace($text, '"CorvusRE@[^"]+"', "`"CorvusRE@$Version`""))
            }

            # Generated docs and the skill can name the version; regenerate them with a quick run.
            $env:CORVUS_UPDATE_DOCS = '1'
            try { Run 'dotnet' @('test', (Join-Path $root 'tests/Corvus.Tests'), '--nologo') }
            finally { Remove-Item Env:CORVUS_UPDATE_DOCS }

            if (-not $summaryData) { $summaryData = Get-TestSummary $gitDir $null 'released with -SkipTests' }
            Write-TestSummary (Join-Path $root $testSummary) $summaryData

            Run 'git' @('add', '-A')
            # The subject keeps the form the commit-msg hook checks.
            Run 'git' @('commit', '-m', "chore(release): version $Version")
            Run 'git' @('tag', '-a', $tag, '-m', "Corvus $Version")
            Write-Host "Committed and tagged $tag."
            if (-not $Push) {
                Write-Host "Next: ./release.ps1 -Version $Version -VerifyOnly after 'git push origin main $tag', or run again with -Push."
                exit 0
            }
        }
        Run 'git' @('push', 'origin', 'main')
        Run 'git' @('push', 'origin', $tag)
    }
    finally { Pop-Location }

    # Match the run by commit, not branch: a re-pushed tag has earlier runs on the same branch.
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

# The notes go on the release before the assets are checked, so a failed
# check leaves the release with its body.
$body = Join-Path $work 'notes.md'
[IO.File]::WriteAllText($body, (Get-Notes) + "`n")
Run 'gh' @('release', 'edit', $tag, '--repo', $Repo, '--notes-file', $body)

# A signed asset link can expire mid-download (2.7.2), so the download is
# tried 3 times from an empty folder.
$assetDir = Join-Path $work 'assets'
for ($attempt = 1; ; $attempt++) {
    if (Test-Path $assetDir) { Remove-Item $assetDir -Recurse -Force }
    gh release download $tag --repo $Repo --dir $assetDir
    if ($LASTEXITCODE -eq 0) { break }
    if ($attempt -eq 3) { Fail "gh release download $tag failed 3 times" }
    Start-Sleep -Seconds 10
}
$sums = @{}
foreach ($line in Get-Content (Join-Path $assetDir 'SHA256SUMS')) {
    if ($line -match '^([0-9a-f]{64}) [ *](.+)$') { $sums[$Matches[2]] = $Matches[1] }
}
foreach ($asset in $assets | Where-Object { $_ -ne 'SHA256SUMS' }) {
    if (-not $sums.ContainsKey($asset)) { Fail "SHA256SUMS lists no $asset" }
    $hash = (Get-FileHash (Join-Path $assetDir $asset) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $sums[$asset]) { Fail "$asset does not match SHA256SUMS" }
}
Write-Host "Verified $($assets.Count - 1) assets against SHA256SUMS."

# Update check: install the previous release in WSL with a throwaway HOME, then 'corvus update' to this one.
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
Write-Host "  [ ] Install check: run the install script on a clean machine or account,"
Write-Host "      then 'corvus version' (expect $Version) and 'corvus status'."
Write-Host "  [ ] MCP bundle: install corvus-<rid>.mcpb in a client that takes bundles (Claude Desktop); the server starts and lists its tools."
Write-Host "  [ ] .NET tool: 'dotnet tool install -g CorvusRE --version $Version', then 'corvus version' (expect $Version)"
Write-Host "      and 'corvus status' (Installed as: dotnet-tool); 'dnx CorvusRE --version $Version --yes version' likewise."
Write-Host "  [ ] Announce: the release notes link, https://github.com/$Repo/releases/tag/$tag"
Write-Host "  [ ] nuget.org: CorvusRE lists $Version (release.yml's publish job)."
Write-Host "  [ ] MCP Registry: io.github.Albasha0x0/corvus lists $Version (the same job, after nuget.org)."
Write-Host "      Either missing: gh workflow run release.yml --repo $Repo --ref $tag -f tag=$tag (publishes again from the tag)."
Write-Host "  [ ] winget, Scoop, Homebrew: manifests in their own repositories, with the archive hashes below."
Write-Host "  [ ] Claude Code and Codex plugin marketplace: install corvus from $Repo in each; the server reports $Version."
Write-Host "  Archive hashes for package manifests:"
foreach ($asset in $assets | Where-Object { $_ -ne 'SHA256SUMS' }) { Write-Host ("    {0}  {1}" -f $sums[$asset], $asset) }
Remove-Item $work -Recurse -Force
