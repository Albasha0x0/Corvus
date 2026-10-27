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
- The .NET 9 and 10 JIT crashes on a conditional branch to its fall-through that starts two nested try regions
  ([dotnet/runtime#136505](https://github.com/dotnet/runtime/issues/136505)).
- `simplify_methods` rewrites such a branch to pops of its operands; a method with no other simplification keeps its
  original body.
