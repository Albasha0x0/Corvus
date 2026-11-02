# Rebuilds the compiler fixtures from translated_shapes.cpp with MSVC 19.44.35207 (x64: /Od, /O1, /O2).
# With CORVUS_FIXTURE_CLANG set it also builds clang x86-64 PE and x86-64 and
# AArch64 ELF images (-O0, -O1, -O2); requires clang with lld.
# Tools: CORVUS_FIXTURE_VCVARS (vcvars64.bat of Visual Studio 2022 Build Tools),
# CORVUS_FIXTURE_CLANG (the LLVM bin folder; the clang outputs are skipped when unset).
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$source = Join-Path $here 'translated_shapes.cpp'

# MSVC targets: output name, optimization option. No runtime library, no incremental thunks, no folding of equal functions.
$msvc = @(@('msvc-Od', '/Od'), @('msvc-O1', '/O1'), @('msvc-O2', '/O2'))
$vcvars = $env:CORVUS_FIXTURE_VCVARS
if ($vcvars) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-fx-$PID"
    New-Item -ItemType Directory -Force $tmp | Out-Null
    try {
        foreach ($t in $msvc) {
            $dll = Join-Path $here "shapes-$($t[0]).dll"
            $line = "`"$vcvars`" >nul && cl /nologo /LD $($t[1]) /GS- /Gy /Zl /Fo`"$tmp\$($t[0]).obj`" /Fe`"$dll`" `"$source`" /link /NODEFAULTLIB /NOENTRY /INCREMENTAL:NO /OPT:REF /OPT:NOICF /Brepro /DEBUG:NONE /MANIFEST:NO"
            cmd /c $line | Out-Null
            if ($LASTEXITCODE) { throw "cl failed for $($t[0])" }
            Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $here "shapes-$($t[0]).lib"), (Join-Path $here "shapes-$($t[0]).exp")
        }
    }
    finally { Remove-Item -Recurse -Force $tmp }
}

$llvm = $env:CORVUS_FIXTURE_CLANG
if ($llvm) {
    $clang = Join-Path $llvm 'clang'
    $common = @('-ffreestanding', '-fno-builtin', '-fno-exceptions', '-fno-rtti', '-fno-stack-protector', '-fasynchronous-unwind-tables', '-fvisibility=hidden')
    foreach ($o in @('O0', 'O1', 'O2')) {
        $obj = Join-Path ([IO.Path]::GetTempPath()) "corvus-fx-clang-$PID-$o.obj"
        try {
            & $clang --target=x86_64-pc-windows-msvc "-$o" -c @common -Xclang -fno-rtti-data -o $obj $source
            if ($LASTEXITCODE) { throw "clang failed for pe $o" }
            & (Join-Path $llvm 'lld-link') -dll -nodefaultlib -noentry -incremental:no -opt:ref -opt:noicf -Brepro -debug:none -manifest:no "-out:$(Join-Path $here "shapes-clang-$o-x64.dll")" $obj
            if ($LASTEXITCODE) { throw "lld-link failed for pe $o" }
        }
        finally { Remove-Item -Force -ErrorAction SilentlyContinue $obj, (Join-Path $here "shapes-clang-$o-x64.lib") }
        foreach ($t in @(@('x86_64-linux-gnu', 'x64'), @('aarch64-linux-gnu', 'arm64'))) {
            $out = Join-Path $here "shapes-clang-$o-$($t[1]).elf"
            & $clang "--target=$($t[0])" "-$o" -shared -fPIC -nostdlib @common -fuse-ld=lld '-Wl,--build-id=none' '-Wl,--no-rosegment' -o $out $source
            if ($LASTEXITCODE) { throw "clang failed for $($t[0]) $o" }
        }
    }
}
