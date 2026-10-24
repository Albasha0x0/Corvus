# Rebuilds the string form fixtures: literals.rs as static Linux x64 and ARM64 executables (core only, symbols kept),
# literals.swift as a Windows x64 executable that loads swiftCore.dll, and literals.swift as Linux x64 and ARM64 code
# linked alone (Swift runtime calls left unresolved).
# Tools: CORVUS_FIXTURE_RUSTC (rustc with the x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu targets),
# CORVUS_FIXTURE_LLVM (a folder with ld.lld), CORVUS_FIXTURE_SWIFT (swiftc; SDKROOT names the Windows SDK, and LIB the
# MSVC and Windows SDK x64 libraries, as a Visual Studio x64 developer prompt sets it), CORVUS_FIXTURE_SWIFT_STATIC_SDK
# (the musl-1.2.5.sdk folder of the Swift Static Linux SDK).
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$rustc = $env:CORVUS_FIXTURE_RUSTC ?? 'rustc'
$swiftc = $env:CORVUS_FIXTURE_SWIFT ?? 'swiftc'
$musl = $env:CORVUS_FIXTURE_SWIFT_STATIC_SDK ?? $(throw 'CORVUS_FIXTURE_SWIFT_STATIC_SDK is not set')
$llvm = $env:CORVUS_FIXTURE_LLVM
function Tool($name) { if ($llvm) { Join-Path $llvm $name } else { $name } }

$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-strings-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    foreach ($t in @(@('rust-x64.elf', 'x86_64-unknown-linux-gnu'), @('rust-arm64.elf', 'aarch64-unknown-linux-gnu'))) {
        $obj = Join-Path $tmp "$($t[0]).o"
        & $rustc "--target=$($t[1])" -C opt-level=2 -C panic=abort -C relocation-model=static --emit=obj -o $obj (Join-Path $here 'literals.rs')
        if ($LASTEXITCODE) { throw "rustc failed for $($t[1])" }
        & (Tool 'ld.lld') -e _start --build-id=none -static -o (Join-Path $here $t[0]) $obj
        if ($LASTEXITCODE) { throw "ld.lld failed for $($t[1])" }
    }
    $exe = Join-Path $tmp 'swift-x64.exe'
    & $swiftc -O -parse-as-library -sdk $env:SDKROOT -target x86_64-unknown-windows-msvc -o $exe (Join-Path $here 'literals.swift')
    if ($LASTEXITCODE) { throw 'swiftc failed for Windows' }
    Copy-Item $exe (Join-Path $here 'swift-x64.exe')
    # The static runtime adds 6 MB per image: the code alone keeps the literals as compiled.
    foreach ($t in @(@('swift-x64.elf', 'x86_64'), @('swift-arm64.elf', 'aarch64'))) {
        $sdk = Join-Path $musl $t[1]
        $obj = Join-Path $tmp "$($t[0]).o"
        & $swiftc -O -parse-as-library -target "$($t[1])-swift-linux-musl" -sdk $sdk -resource-dir (Join-Path $sdk 'usr/lib/swift_static') `
            -emit-object -o $obj (Join-Path $here 'literals.swift')
        if ($LASTEXITCODE) { throw "swiftc failed for $($t[1])" }
        & (Tool 'ld.lld') -static -e main --build-id=none --unresolved-symbols=ignore-all -o (Join-Path $here $t[0]) $obj
        if ($LASTEXITCODE) { throw "ld.lld failed for $($t[1])" }
    }
}
finally { Remove-Item -Recurse -Force $tmp }
