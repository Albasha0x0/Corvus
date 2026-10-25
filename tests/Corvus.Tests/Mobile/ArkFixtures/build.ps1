# Rebuilds the Ark bytecode fixtures from features.ts and helper.ts with the OpenHarmony SDK's compiler.
# CORVUS_FIXTURE_ES2ABC: es2abc from the SDK (ets/build-tools/ets-loader/bin/ark/build-win/bin, or build/bin on Linux).
# features.abc merges both modules; features.txt is the SDK's ark_disasm listing of it (CORVUS_ARK_DISASSEMBLER), kept
# so the listing tests run without the SDK.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$compiler = $env:CORVUS_FIXTURE_ES2ABC
if (-not $compiler) { throw 'set CORVUS_FIXTURE_ES2ABC to the SDK es2abc' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-abc-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    Push-Location $here
    $list = Join-Path $tmp 'files.txt'
    # Each line: source;record name;module kind;source file;package name.
    @(
        "features.ts;features;esm;features.ts;fixtures"
        "helper.ts;helper;esm;helper.ts;fixtures"
    ) | Set-Content $list -Encoding ascii
    & $compiler --module --merge-abc --extension=ts --output (Join-Path $here 'features.abc') "@$list"
    if ($LASTEXITCODE -ne 0) { throw "es2abc exit $LASTEXITCODE" }
    if ($env:CORVUS_ARK_DISASSEMBLER) {
        & $env:CORVUS_ARK_DISASSEMBLER (Join-Path $here 'features.abc') (Join-Path $here 'features.txt')
        if ($LASTEXITCODE -ne 0) { throw "ark_disasm exit $LASTEXITCODE" }
    }
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $tmp
}
