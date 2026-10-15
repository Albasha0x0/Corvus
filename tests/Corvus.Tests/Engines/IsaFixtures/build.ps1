# Rebuilds the ISA fixtures from calls.rs (rustc's LLVM has every backend; ld.lld links them) and writes the 6502 image.
# Tools: CORVUS_FIXTURE_RUSTC (rustc), CORVUS_FIXTURE_LLVM (a folder with ld.lld, llvm-objcopy and llvm-nm).
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

# 6502 at 0x8000, assembled by hand (no 6502 backend in LLVM):
#   8000 entry:  JSR middle ; RTS
#   8004 middle: JSR leaf ; JSR leaf ; RTS
#   800B leaf:   CLC ; ADC #7 ; RTS
[IO.File]::WriteAllBytes((Join-Path $here 'm6502.bin'), [byte[]](
    0x20, 0x04, 0x80, 0x60,
    0x20, 0x0B, 0x80, 0x20, 0x0B, 0x80, 0x60,
    0x18, 0x69, 0x07, 0x60))
