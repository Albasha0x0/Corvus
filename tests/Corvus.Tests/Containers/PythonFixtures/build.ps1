# Rebuilds the Python bytecode fixtures from constructs.py (3.x) and constructs-2.7.py with each interpreter named in
# CORVUS_FIXTURE_PYTHONS (paths separated by the path separator), compiled with a fixed hash seed.
$ErrorActionPreference = 'Stop'
if (-not $env:CORVUS_FIXTURE_PYTHONS) { throw 'set CORVUS_FIXTURE_PYTHONS to the Python interpreters, separated by the path separator' }
$env:PYTHONHASHSEED = '0'
foreach ($python in $env:CORVUS_FIXTURE_PYTHONS.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)) {
    & $python -E -s (Join-Path $PSScriptRoot 'build.py')
    if ($LASTEXITCODE -ne 0) { throw "$python failed" }
}
