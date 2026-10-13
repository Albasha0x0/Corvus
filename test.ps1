# Runs the tests. The quick set by default; -Full runs everything (slow, IDA and Ghidra tests; set CORVUS_GHIDRA_DIR for
# Ghidra) and, on a clean tree, stamps the tree it passed on, so a later -Full -IfChanged (or release.ps1) skips a repeat.
# Usage:  ./test.ps1                      # quick set (before each commit)
#         ./test.ps1 -Full                # full suite (before a release or a gate run)
#         ./test.ps1 -Full -IfChanged     # full suite unless it already passed on this exact tree
#         ./test.ps1 -Filter <expr>       # any dotnet test filter, quick or full
#Requires -Version 7.0
param(
    [switch]$Full,
    [switch]$IfChanged,
    [string]$Filter
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$tests = Join-Path $root 'tests/Corvus.Tests'

# The tree a full run passed on, kept in .git so it is never committed. Only a clean tree has a hash worth recording.
function Get-CleanTree {
    if (git -C $root status --porcelain) { return $null }
    return (git -C $root rev-parse 'HEAD^{tree}').Trim()
}
$stamp = Join-Path (git -C $root rev-parse --absolute-git-dir).Trim() 'corvus-full-suite.stamp'

if ($Full -and $IfChanged) {
    $tree = Get-CleanTree
    if ($tree -and (Test-Path $stamp) -and (Get-Content $stamp -Raw).Trim() -eq $tree) {
        Write-Host "The full suite already passed on tree $tree; skipped."
        exit 0
    }
}

$arguments = @('test', $tests, '--nologo')
if ($Filter) { $arguments += @('--filter', $Filter) }
$saved = $env:CORVUS_ALL_TESTS
try {
    if ($Full) { $env:CORVUS_ALL_TESTS = '1' }
    $tree = if ($Full -and -not $Filter) { Get-CleanTree } else { $null }
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($tree) { Set-Content -Path $stamp -Value $tree -NoNewline; Write-Host "Stamped tree $tree." }
}
finally { $env:CORVUS_ALL_TESTS = $saved }
