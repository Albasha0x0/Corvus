# Known issues

## Known limits

- `patch_asm` assembles x86 and x64 only.
- `live_timeline` and `live_console` run on Windows only.
- Nuitka standalone programs are detected, not extracted (their code is compiled to native code).
- Protobuf: message descriptors are recovered; messages are not decoded.
- Instruction sets other than x86, x64, ARM32 and ARM64 (MIPS, PowerPC, RISC-V and others) show declared functions only; IDA or Ghidra reads their code.
- No Rust v0 (`_R`) demangler; legacy Rust names are Itanium-mangled and read as such, with their hash suffix.
- No FLIRT engine; IDA's library function names are used when present.
- No YARA rules are bundled.

## .NET 10 JIT crash: a conditional branch to its own fall-through at nested try regions

**Status: worked around in simplify_methods; a runtime-level issue, not reported upstream yet.**

### What happens

A conditional branch whose target is its fall-through instruction, where that instruction starts two nested try
regions, crashes the JIT with an access violation (`0xC0000005`, "Fatal error") and ends the process. The IL is valid:
with one try region, or with an unconditional `br` after the conditional one, it JIT-compiles fine.

Seen with .NET runtime 10.0.11 (SDK 10.0.303) on Windows x64.

### Minimal repro

`static int M(int)`, compiled with `RuntimeHelpers.PrepareMethod`:

```
    ldarg.0
    ldc.i4.1
    blt L            // target == fall-through
L:  nop              // starts both try regions below
    leave LEAVE_OUTER
FIN:
    endfinally
LEAVE_OUTER:
    leave END
CATCH:
    pop
    leave END
END:
    ldc.i4.0
    ret

.try L to FIN finally handler FIN to LEAVE_OUTER
.try L to CATCH catch [System.Runtime]System.Exception handler CATCH to END
```

Variants: `br L` after `blt L`, or only the finally region: OK. `ldarg.0; conv.r8; ldc.r8 1.0; blt L`: same crash.

### How simplify_methods avoids it

Fuzz seed 468 produced the shape: folding a constant branch at the start of nested try regions and dropping the `br`
after it left `blt L; L:`. The cfg pass now turns a conditional branch to the next instruction into pops of its
operands, as a compiler would (`MethodSimplifier.DropBranchesToNext`). An original body with the shape is rewritten the
same way when the method has other simplifications; a method with nothing else to simplify keeps its original body.

Regression test: `SimplifyRegressionTests.ConditionalBranchToNextBecomesPops` checks the shape structurally before
JIT-compiling, so a regression fails the test instead of crashing the test process.
