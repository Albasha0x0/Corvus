# Known issues

## .NET 10 JIT crash: a conditional branch to its own fall-through at nested try regions

**Status: worked around in simplify_methods; a runtime-level issue, not reported upstream yet.**

### What happens

A conditional branch whose target is also its fall-through instruction, where that instruction starts two nested try
regions, crashes the JIT with an access violation (`0xC0000005`, "Fatal error"), which ends the process. The IL is valid:
one try region instead of two, or an unconditional `br` after the conditional one, JIT-compiles fine.

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

Variants: with `br L` after `blt L`: OK. With only the finally region: OK. With `ldarg.0; conv.r8; ldc.r8 1.0; blt L`:
crashes the same way.

### How simplify_methods avoids it

The fuzz test (seed 468) produced this shape: folding a constant branch at the start of nested try regions and dropping
the `br` after it left `blt L; L:`. The cfg pass now turns a conditional branch to the next instruction into pops of
its operands, as a compiler would, so the shape is never produced
(`MethodSimplifier.DropBranchesToNext`). An original body that already contains the shape is rewritten the same way
when the method has other simplifications; a method with nothing else to simplify keeps its original body.

Regression fixture: `SimplifyRegressionTests.ConditionalBranchToNextBecomesPops`, which checks the shape structurally
before JIT-compiling the method, so a regression fails the test instead of crashing the test process.
