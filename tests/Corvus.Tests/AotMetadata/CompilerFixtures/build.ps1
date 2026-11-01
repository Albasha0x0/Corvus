# Rebuilds the compiler fixtures from translated_shapes.cpp with MSVC 19.44.35207 (x64: /Od, /O1, /O2).
# With CORVUS_FIXTURE_CLANG set it also builds clang x86-64 and AArch64 ELF images (-O0, -O2); none is committed.
# Tools: CORVUS_FIXTURE_VCVARS (vcvars64.bat of Visual Studio 2022 Build Tools),
# CORVUS_FIXTURE_CLANG (a command prefix for clang and ld.lld; the clang outputs are skipped when unset).
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

$clang = ($env:CORVUS_FIXTURE_CLANG ?? '') -split ' ' | Where-Object { $_ }
if ($clang) {
    foreach ($t in @(@('x86_64-linux-gnu', 'x64'), @('aarch64-linux-gnu', 'arm64'))) {
        foreach ($o in @('-O0', '-O2')) {
            $out = Join-Path $here "shapes-clang$o-$($t[1]).elf"
            $c = @($clang) + @('clang', "--target=$($t[0])", $o, '-shared', '-nostdlib', '-ffreestanding', '-fno-builtin', '-fno-exceptions', '-fno-rtti',
                '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-fuse-ld=lld', '-Wl,--build-id=none', '-Wl,--no-rosegment', '-o', $out, $source)
            & $c[0] @($c[1..($c.Count)])
            if ($LASTEXITCODE) { throw "clang failed for $($t[0]) $o" }
        }
    }
}
