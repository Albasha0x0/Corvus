# simplify_methods: engine contract

Generated from `SimplifyManifest` (src/NetDecompilerMcp/Services/Simplify/SimplifyManifest.cs); a test keeps the two in sync.

The engine rewrites copies of method bodies and keeps a rewrite only when the result passes the stack verifier. Every
evaluation that leaves the supported subset stops at that point and leaves the code as it was; every skipped rewrite and
every method left unchanged is reported with one of the reasons below.

## Interpreter instructions

| Group | Instructions | Notes |
|---|---|---|
| Constants and stack | `nop` `ldc.i4` `ldc.i4.s` `ldc.i4.m1` `ldc.i4.0` `ldc.i4.1` `ldc.i4.2` `ldc.i4.3` `ldc.i4.4` `ldc.i4.5` `ldc.i4.6` `ldc.i4.7` `ldc.i4.8` `ldc.i8` `ldc.r4` `ldc.r8` `ldnull` `ldstr` `dup` `pop` |  |
| Prefixes | `tail.` `volatile.` `unaligned.` `readonly.` | no effect on the evaluated result |
| Arguments and locals | `ldarg` `ldarg.s` `ldarg.0` `ldarg.1` `ldarg.2` `ldarg.3` `starg` `starg.s` `ldarga` `ldarga.s` `ldloc` `ldloc.s` `ldloc.0` `ldloc.1` `ldloc.2` `ldloc.3` `stloc` `stloc.s` `stloc.0` `stloc.1` `stloc.2` `stloc.3` `ldloca` `ldloca.s` | struct values are copied on load and store; ldarga / ldloca give managed pointers |
| Arithmetic and bit operations | `add` `sub` `mul` `div` `div.un` `rem` `rem.un` `and` `or` `xor` `shl` `shr` `shr.un` `add.ovf` `add.ovf.un` `sub.ovf` `sub.ovf.un` `mul.ovf` `mul.ovf.un` `neg` `not` `ckfinite` | int32, int64 and native int; native int results must be the same on 32- and 64-bit platforms; float32 operands are computed in single precision as the JIT does; division by zero and checked overflow stop evaluation |
| Comparisons | `ceq` `cgt` `cgt.un` `clt` `clt.un` | references compare by identity or against null |
| Conversions | `conv.i1` `conv.i2` `conv.i4` `conv.i8` `conv.u1` `conv.u2` `conv.u4` `conv.u8` `conv.i` `conv.u` `conv.r4` `conv.r8` `conv.r.un` `conv.ovf.i1` `conv.ovf.i2` `conv.ovf.i4` `conv.ovf.i8` `conv.ovf.u1` `conv.ovf.u2` `conv.ovf.u4` `conv.ovf.u8` `conv.ovf.i` `conv.ovf.u` `conv.ovf.i1.un` `conv.ovf.i2.un` `conv.ovf.i4.un` `conv.ovf.i8.un` `conv.ovf.u1.un` `conv.ovf.u2.un` `conv.ovf.u4.un` `conv.ovf.u8.un` `conv.ovf.i.un` `conv.ovf.u.un` | exact ECMA-335 semantics: truncation, sign / zero extension, overflow checks of conv.ovf; out-of-range float to integer conversion (undefined) stops evaluation |
| Branches | `br` `br.s` `brtrue` `brtrue.s` `brfalse` `brfalse.s` `beq` `beq.s` `bne.un` `bne.un.s` `bge` `bge.s` `bge.un` `bge.un.s` `bgt` `bgt.s` `bgt.un` `bgt.un.s` `ble` `ble.s` `ble.un` `ble.un.s` `blt` `blt.s` `blt.un` `blt.un.s` `switch` `ret` | loops run within the shared instruction budget |
| Arrays | `newarr` `ldlen` `ldelema` `ldelem.i1` `ldelem.u1` `ldelem.i2` `ldelem.u2` `ldelem.i4` `ldelem.u4` `ldelem.i8` `ldelem.i` `ldelem.r4` `ldelem.r8` `ldelem.ref` `ldelem` `stelem.i1` `stelem.i2` `stelem.i4` `stelem.i8` `stelem.i` `stelem.r4` `stelem.r8` `stelem.ref` `stelem` | one-dimensional arrays of primitives, strings and other references; at most 1M elements |
| Indirect access | `ldind.i1` `ldind.u1` `ldind.i2` `ldind.u2` `ldind.i4` `ldind.u4` `ldind.i8` `ldind.i` `ldind.r4` `ldind.r8` `ldind.ref` `stind.i1` `stind.i2` `stind.i4` `stind.i8` `stind.i` `stind.r4` `stind.r8` `stind.ref` | through managed pointers to arguments, locals, array elements and struct fields |
| Value types | `ldobj` `stobj` `initobj` `ldfld` `ldflda` `stfld` | structs defined in the same module (sequential or auto layout), enums and primitives |
| Static state | `ldsfld` `stsfld` `ldtoken` | readonly static fields of the same module, after evaluating the type's static constructor once; writes only inside static constructors |
| Type tests | `isinst` `castclass` | System.Object, System.String, System.Text.StringBuilder and System.Text.Encoding targets |
| Calls | `call` `callvirt` `newobj` | intrinsics (below), and static methods and struct methods with IL bodies in the same module (no exception handlers, not generic); newobj of strings, StringBuilder and module structs |

Every other instruction stops evaluation with `unsupported-instruction`.

## Intrinsics

Framework methods evaluated directly (deterministic and culture-independent for the values they accept):

- `System.Boolean System.String::Equals(System.String)`
- `System.Boolean System.String::Equals(System.String,System.String)`
- `System.Boolean System.String::IsNullOrEmpty(System.String)`
- `System.Boolean System.String::op_Equality(System.String,System.String)`
- `System.Boolean System.String::op_Inequality(System.String,System.String)`
- `System.Byte[] System.Convert::FromBase64String(System.String)`
- `System.Byte[] System.Text.Encoding::GetBytes(System.String)`
- `System.Char System.String::get_Chars(System.Int32)`
- `System.Char System.Text.StringBuilder::get_Chars(System.Int32)`
- `System.Char[] System.String::ToCharArray()`
- `System.Int32 System.Array::get_Length()`
- `System.Int32 System.Math::Abs(System.Int32)`
- `System.Int32 System.Math::Max(System.Int32,System.Int32)`
- `System.Int32 System.Math::Min(System.Int32,System.Int32)`
- `System.Int32 System.String::IndexOf(System.Char)`
- `System.Int32 System.String::get_Length()`
- `System.Int32 System.Text.StringBuilder::get_Length()`
- `System.String System.Char::ToString()`
- `System.String System.Char::ToString(System.Char)`
- `System.String System.Convert::ToBase64String(System.Byte[])`
- `System.String System.Int32::ToString()`
- `System.String System.Object::ToString()`
- `System.String System.String::Concat(System.Object,System.Object)`
- `System.String System.String::Concat(System.Object,System.Object,System.Object)`
- `System.String System.String::Concat(System.String,System.String)`
- `System.String System.String::Concat(System.String,System.String,System.String)`
- `System.String System.String::Concat(System.String,System.String,System.String,System.String)`
- `System.String System.String::Concat(System.String[])`
- `System.String System.String::Insert(System.Int32,System.String)`
- `System.String System.String::Join(System.String,System.String[])`
- `System.String System.String::Remove(System.Int32)`
- `System.String System.String::Remove(System.Int32,System.Int32)`
- `System.String System.String::Replace(System.Char,System.Char)`
- `System.String System.String::Replace(System.String,System.String)`
- `System.String System.String::Substring(System.Int32)`
- `System.String System.String::Substring(System.Int32,System.Int32)`
- `System.String System.String::ToLowerInvariant()`
- `System.String System.String::ToUpperInvariant()`
- `System.String System.String::Trim()`
- `System.String System.Text.Encoding::GetString(System.Byte[])`
- `System.String System.Text.Encoding::GetString(System.Byte[],System.Int32,System.Int32)`
- `System.String System.Text.StringBuilder::ToString()`
- `System.Text.Encoding System.Text.Encoding::get_ASCII()`
- `System.Text.Encoding System.Text.Encoding::get_BigEndianUnicode()`
- `System.Text.Encoding System.Text.Encoding::get_UTF8()`
- `System.Text.Encoding System.Text.Encoding::get_Unicode()`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.Char)`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.Char[])`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.Int32)`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.String)`
- `System.Text.StringBuilder System.Text.StringBuilder::Insert(System.Int32,System.String)`
- `System.Void System.Array::Copy(System.Array,System.Array,System.Int32)`
- `System.Void System.Array::Copy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)`
- `System.Void System.Array::Reverse(System.Array)`
- `System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)`
- `System.Void System.String::.ctor(System.Char,System.Int32)`
- `System.Void System.String::.ctor(System.Char[])`
- `System.Void System.String::.ctor(System.Char[],System.Int32,System.Int32)`
- `System.Void System.Text.StringBuilder::.ctor()`
- `System.Void System.Text.StringBuilder::.ctor(System.Int32)`
- `System.Void System.Text.StringBuilder::.ctor(System.String)`
- `System.Void System.Text.StringBuilder::set_Length(System.Int32)`

## Limits

| Limit | Default |
|---|---|
| maxDepth | 8 frames, the evaluated call included (tool parameter, 1-64) |
| budget | 100,000 instructions per evaluation, shared by nested calls and the static constructors they trigger (tool parameter) |
| method budget | 5,000,000 instructions across all evaluations of one method |
| memory | 16 MB of simulated allocations per evaluation, static state included |
| time | 5 s per method, all passes included |
| arrays and strings | 1M elements / characters |

## Fallback reasons

| Code | Meaning |
|---|---|
| `unsupported-instruction` | an IL instruction that is not in the instruction table below |
| `unsupported-call` | a call to a framework or other method that is neither an intrinsic nor IL of the same module (I/O, reflection, threading, ...) |
| `no-body` | the callee has no IL body: P/Invoke, internal call, runtime-implemented or abstract |
| `other-module` | the callee or a static field belongs to another module, whose code may differ at run time |
| `generic` | a generic method or a member of a generic type |
| `exception-handling` | the callee has exception handlers, or the code throws |
| `instance-object` | creates or uses an instance of a class other than the modelled string, array, StringBuilder and Encoding objects |
| `unsupported-value` | a value the interpreter does not model: boxing, unmanaged pointers, typed references, structs of other modules or with explicit layout, arrays of structs, type tokens |
| `mutable-static` | reads a static field that is not readonly, writes a static field outside a static constructor, or modifies an object held in a static field |
| `static-initializer` | the static constructor of a type the code needs cannot be evaluated, or the method being simplified is that static constructor |
| `runtime-error` | the code would throw at run time: division by zero, checked overflow, index out of range, null reference, invalid cast, invalid argument |
| `platform-dependent` | the result would differ between platforms or cultures: native int values outside the 32-bit range, out-of-range float to integer conversion, culture-sensitive formatting |
| `invalid-code` | the evaluated code is not valid IL: stack underflow, mismatched operand types, a branch outside the method, execution past its end |
| `call-depth` | nested calls exceed the depth limit (maxDepth) (resource limit) |
| `instruction-budget` | the evaluation, including nested calls and static constructors, executed more instructions than the budget allows, or the method's total budget ran out (resource limit) |
| `memory-limit` | the evaluation allocated more simulated memory (arrays, strings, builders) than the limit (resource limit) |
| `time-limit` | simplifying the method took longer than its time limit; the method is left unchanged (resource limit) |
| `flattened-shape` | flattened control flow (a loop over a switch on a state) whose dispatcher cannot be removed: run through per state, some way into it does not select the same case on every run (the state depends on arguments or other unknown values, or on the path taken), a case reads the state with a value that depends on the path taken, the state's address is taken, the dispatcher or a case is in another protected region, or the analysis exceeds its limits (1,024 states); the dispatcher is kept as it is and the other passes still apply to the method |
| `original-unverifiable` | the original body does not pass the stack verifier, so it is not rewritten |
| `result-unverifiable` | the rewritten body did not pass the stack verifier; the method is left unchanged |
| `unexpected` | an unexpected error while reading or rewriting the body (malformed metadata or a defect); the method is left unchanged |
