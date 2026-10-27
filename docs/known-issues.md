# Known issues

## Known limits

- `patch_asm` assembles x86 and x64 only.
- `live_timeline` and `live_console` run on Windows only.
- Nuitka standalone programs are detected, not extracted (compiled to native code).
- Protobuf: message descriptors are recovered; messages are not decoded.
- Instruction sets other than x86, x64, ARM32 and ARM64 show declared functions only; IDA or Ghidra reads their code.
- No Rust v0 (`_R`) demangler; legacy Rust names read as Itanium names, with their hash suffix.
- No FLIRT engine; IDA's library function names are used when present.
- No YARA rules are bundled.

## .NET 10 JIT crash on a branch to its own fall-through

**Status: worked around in `simplify_methods`; not reported upstream yet.**

- A conditional branch whose target is its fall-through instruction, where that instruction starts two nested try
  regions, crashes the JIT (`0xC0000005`, "Fatal error") and ends the process.
- The IL is valid: with one try region, or an unconditional `br` after the branch, it compiles.
- Seen with .NET runtime 10.0.11 (SDK 10.0.303) on Windows x64.

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

- `br L` after `blt L`, or only the finally region: compiles.
- `ldarg.0; conv.r8; ldc.r8 1.0; blt L`: same crash.

### Workaround

- `simplify_methods` turns a conditional branch to the next instruction into pops of its operands, as a compiler does.
- An original body with the shape is rewritten the same way when the method has other simplifications; otherwise it
  keeps its original body.
- The regression test checks the shape before compiling, so a regression fails the test, not the test process.
