# Rebuilds the CFI fixtures from frames.rs: shared objects with .eh_frame for targets the LLVM release build cannot
# compile (rustc's LLVM has every backend; ld.lld links them).
# Tools: CORVUS_FIXTURE_RUSTC (rustc), CORVUS_FIXTURE_LLVM (a folder with ld.lld and llvm-objcopy).
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$rustc = $env:CORVUS_FIXTURE_RUSTC ?? 'rustc'
$llvm = $env:CORVUS_FIXTURE_LLVM
function Tool($name) { if ($llvm) { Join-Path $llvm $name } else { $name } }
$env:RUSTC_BOOTSTRAP = '1' # no_core and lang items: no standard library is needed for these targets

$targets = @(
    @('ppc64le.so', 'powerpc64le-unknown-linux-gnu'),
    @('ppc64.so', 'powerpc64-unknown-linux-musl'),
    @('s390x.so', 's390x-unknown-linux-gnu'),
    @('riscv64.so', 'riscv64gc-unknown-linux-gnu')
)
$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-cfi-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    foreach ($t in $targets) {
        $obj = Join-Path $tmp "$($t[0]).o"
        $so = Join-Path $tmp $t[0]
        & $rustc "--target=$($t[1])" -C opt-level=2 -C panic=abort -C force-unwind-tables=yes -C relocation-model=pic --emit=obj -o $obj (Join-Path $here 'frames.rs')
        if ($LASTEXITCODE) { throw "rustc failed for $($t[1])" }
        & (Tool 'ld.lld') -shared --build-id=none --eh-frame-hdr -o $so $obj
        if ($LASTEXITCODE) { throw "ld.lld failed for $($t[1])" }
        & (Tool 'llvm-objcopy') --remove-section=.comment $so (Join-Path $here $t[0])
        if ($LASTEXITCODE) { throw "llvm-objcopy failed for $($t[1])" }
    }
}
finally { Remove-Item -Recurse -Force $tmp }
