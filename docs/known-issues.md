# Known issues

## Saving re-encodes invalid original method bodies silently

**Status: resolved** (faithful saving with a report; the contract is in [saving.md](saving.md)).

### What happened

Once an assembly had an edit, `save_assembly` wrote the whole module again with dnlib (`LoadedAssembly.Write`), which
re-encodes every method body from its parsed instructions. Original bodies dnlib cannot represent came back different,
with its errors suppressed (`DummyLogger.NoThrowInstance`) and nothing in the save result:

- **Empty bodies** (an RVA, zero instructions) were written with no body at all.
- **Truncated bodies** (a branch past the end) had the branch written to offset 0.

Found by the simplify_methods library sweep in the .NET Framework 4.8 reference assemblies: `mscorlib.dll` (20,906
empty bodies, 5 truncated, e.g. `System.DefaultBinder::SelectProperty`) and `System.Xml.dll` (9,165 empty). No other
swept library had a body the writer changed.

### Outcome

- **Faithful by default.** Every method body no edit changed is written with its original bytes, including bodies dnlib
  cannot represent. Every signature no edit changed points at its original blob. Edits are encoded by dnlib as before.
  An unmodified assembly is still saved as its original bytes.
- **Checked and reported.** The written image is compared with the original, method by method and signature by
  signature. The save result lists anything that differs although no edit asked for it, and anything invalid in the
  original that was kept, one line per member with a reason code in the fallback-reason style. With dnlib's errors
  collected, a writer error on an edited or added member is listed too.
- **Strict mode.** `strict=true` refuses a save with any byte change it did not ask for, lists the members and writes
  nothing.
- **Result on the sweep.** The two reference assemblies now save their 20,921 (mscorlib) and 9,165 (System.Xml) invalid
  bodies byte-for-byte and list them as kept. Across all 24 sweep libraries (about 144,000 methods), a rewrite changes
  no body and no signature. `SaveFidelitySweepTests` keeps this as a permanent contract; `SaveFidelityTests` pins each
  invalid shape, edits next to them, strict mode, and damaged images.

What can still change on save is reported, never silent: a body whose header or code lies outside the image's
sections cannot be copied, and is written as dnlib decoded it (`unreadable-body`).

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
