# Rebuilds the ISA fixtures from calls.rs (rustc's LLVM has every backend; ld.lld links them) and writes the 6502 image.
# Tools: CORVUS_FIXTURE_RUSTC (rustc), CORVUS_FIXTURE_LLVM (a folder with ld.lld, llvm-objcopy and llvm-nm),
# CORVUS_FIXTURE_M68K (a command prefix for GNU binutils m68k-linux-gnu-ld and -objcopy 2.38: ld.lld has no m68k),
# CORVUS_FIXTURE_CC65 (a command prefix for ca65 and ld65 2.19, which build nrom.nes from nrom.s and nrom.cfg),
# CORVUS_FIXTURE_CLANG (a command prefix for clang, ld.lld and llvm-objcopy 14, which build emu-*.elf from emu.c).
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$rustc = $env:CORVUS_FIXTURE_RUSTC ?? 'rustc'
$llvm = $env:CORVUS_FIXTURE_LLVM
function Tool($name) { if ($llvm) { Join-Path $llvm $name } else { $name } }
$env:RUSTC_BOOTSTRAP = '1' # no_core and lang items: no standard library is needed for these targets

# file, rustc target, extra linker arguments, kind (elf; cortex: vector table + .text at 0x8000000)
$targets = @(
    @('mips32be.elf', 'mips-unknown-linux-gnu', @(), 'elf'),
    @('mips32le.elf', 'mipsel-unknown-linux-gnu', @(), 'elf'),
    @('ppc32.elf', 'powerpc-unknown-linux-gnu', @(), 'elf'),
    # ELFv2 (musl), the ABI ld.lld links; ppc64v1.elf only feeds the .opd descriptor test: lld branches to v1 descriptors
    @('ppc64.elf', 'powerpc64-unknown-linux-musl', @(), 'elf'),
    @('ppc64v1.elf', 'powerpc64-unknown-linux-gnu', @(), 'elf'),
    @('riscv32.elf', 'riscv32imac-unknown-none-elf', @(), 'elf'),
    @('riscv64.elf', 'riscv64gc-unknown-none-elf', @(), 'elf'),
    @('armbe.elf', 'armebv7r-none-eabi', @(), 'elf'),
    @('cortexm.bin', 'thumbv7m-none-eabi', @('--image-base=0x08000000', '-Ttext=0x08000100'), 'cortex')
)
$tmp = Join-Path ([IO.Path]::GetTempPath()) "corvus-isa-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    foreach ($t in $targets) {
        $obj = Join-Path $tmp "$($t[0]).o"
        $elf = Join-Path $tmp "$($t[0]).elf"
        $out = Join-Path $here $t[0]
        & $rustc "--target=$($t[1])" -C opt-level=2 -C panic=abort -C relocation-model=static --emit=obj -o $obj (Join-Path $here 'calls.rs')
        if ($LASTEXITCODE) { throw "rustc failed for $($t[1])" }
        & (Tool 'ld.lld') -e _start --build-id=none -static @($t[2]) -o $elf $obj
        if ($LASTEXITCODE) { throw "ld.lld failed for $($t[1])" }
        if ($t[3] -eq 'elf') { & (Tool 'llvm-objcopy') --remove-section=.comment $elf $out; continue }
        # Cortex-M flash image: 64-word vector table (initial SP, reset = _start in Thumb state, the rest unused) then the code
        $code = Join-Path $tmp 'text.bin'
        & (Tool 'llvm-objcopy') -O binary -j .text $elf $code
        $start = (& (Tool 'llvm-nm') $elf | Where-Object { $_ -match ' T _start$' }) -replace ' .*', ''
        $table = [byte[]]::new(0x100)
        [BitConverter]::GetBytes([uint32]0x20002000).CopyTo($table, 0)
        [BitConverter]::GetBytes([uint32]([Convert]::ToUInt32($start, 16) -bor 1)).CopyTo($table, 4)
        [IO.File]::WriteAllBytes($out, [byte[]]($table + [IO.File]::ReadAllBytes($code)))
    }
}
finally { Remove-Item -Recurse -Force $tmp }

# m68k at 0: 256-vector table (initial SSP, reset = _start at 0x400, big-endian), then .text and .rodata.
$m68k = ($env:CORVUS_FIXTURE_M68K ?? '') -split ' ' | Where-Object { $_ }
function M68k($tool) { $c = @($m68k) + "m68k-linux-gnu-$tool"; & $c[0] @($c[1..($c.Count)] + $args); if ($LASTEXITCODE) { throw "$tool failed" } }
Push-Location $here
try {
    & $rustc --target=m68k-unknown-linux-gnu -C opt-level=2 -C panic=abort -C relocation-model=static --emit=obj -o m68k.o calls.rs
    if ($LASTEXITCODE) { throw 'rustc failed for m68k' }
    M68k ld -e _start --build-id=none -static -Ttext=0x400 -o m68k.elf m68k.o
    M68k objcopy -O binary -j .text -j .rodata m68k.elf m68k.text
    $table = [byte[]]::new(0x400)
    $table[1] = 0x10; $table[6] = 0x04
    [IO.File]::WriteAllBytes((Join-Path $here 'm68k.bin'), [byte[]]($table + [IO.File]::ReadAllBytes((Join-Path $here 'm68k.text'))))
    # Integer code for the built-in emulator: loops stay scalar, as the emulator models no vector arithmetic.
    $clang = ($env:CORVUS_FIXTURE_CLANG ?? '') -split ' ' | Where-Object { $_ }
    foreach ($t in @(@('x86_64-linux-gnu', 'x64'), @('i386-linux-gnu', 'x86'), @('aarch64-linux-gnu', 'arm64'))) {
        $steps = @(
            @('clang', "--target=$($t[0])", '-O2', '-fno-vectorize', '-fno-slp-vectorize', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                '-fno-pic', '-fno-asynchronous-unwind-tables', '-c', 'emu.c', '-o', 'emu.o'),
            @('ld.lld', '-e', '_start', '--build-id=none', '-static', '-o', 'emu.elf', 'emu.o'),
            @('llvm-objcopy', '--remove-section=.comment', 'emu.elf', "emu-$($t[1]).elf"))
        foreach ($step in $steps) {
            $c = @($clang) + $step
            & $c[0] @($c[1..($c.Count)])
            if ($LASTEXITCODE) { throw "$($step[0]) failed for $($t[0])" }
        }
    }
    $cc65 = ($env:CORVUS_FIXTURE_CC65 ?? '') -split ' ' | Where-Object { $_ }
    foreach ($step in @(@('ca65', '-o', 'nrom.o', 'nrom.s'), @('ld65', '-C', 'nrom.cfg', '-o', 'nrom.nes', 'nrom.o'))) {
        $c = @($cc65) + $step
        & $c[0] @($c[1..($c.Count)])
        if ($LASTEXITCODE) { throw "$($step[0]) failed" }
    }
}
finally { Remove-Item -Force m68k.o, m68k.elf, m68k.text, nrom.o, emu.o, emu.elf -ErrorAction SilentlyContinue; Pop-Location }

# 6502 at 0x8000, assembled by hand (no 6502 backend in LLVM):
#   8000 entry:  JSR middle ; RTS
#   8004 middle: JSR leaf ; JSR leaf ; RTS
#   800B leaf:   CLC ; ADC #7 ; RTS
[IO.File]::WriteAllBytes((Join-Path $here 'm6502.bin'), [byte[]](
    0x20, 0x04, 0x80, 0x60,
    0x20, 0x0B, 0x80, 0x20, 0x0B, 0x80, 0x60,
    0x18, 0x69, 0x07, 0x60))
