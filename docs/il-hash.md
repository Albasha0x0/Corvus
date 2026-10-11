# Normalized IL hash

`IlHash` (src/Corvus/Services/IlHash.cs) gives each method body a SHA-256 that does not depend on
metadata tokens, byte offsets or the short / long form the compiler picked for an instruction. Two builds of the
same code therefore give each method the same hash, even when adding members elsewhere shifted every token.
`get_il` prints it (`// IL hash: <first 16 hex digits>`, one line per method), `find_counterpart` compares it
(`body: unchanged` / `changed`), and `compare_assemblies` uses it to tell changed bodies from unchanged ones and
to pair renamed methods whose bodies are identical.

A method without a body (abstract, extern, runtime-implemented) or whose body is not valid IL (see
`get_assembly_info`) has no hash.

## Raw IL SHA-256

`get_il` also prints `raw IL SHA-256: <first 16 hex digits>`: the SHA-256 of the method's IL code bytes exactly as
stored in the file as loaded. The bytes start after the tiny (1-byte) or fat (12-byte) method header and run for the
header's code size; the header, the alignment padding and the extra data sections (exception clauses) are not
included. It changes whenever a token or an offset changes, so it identifies one exact build, where the normalized
hash identifies the code. For an assembly with unsaved edits it is still the file's value (`(file as loaded)`).
Methods without an IL body (abstract, extern, runtime-implemented, native) have none. `decompile_member` with
`provenance=true` prints both hashes in full.

## Encoding (version 1)

The hash is the lower-case hex SHA-256 of the UTF-8 bytes of a text. Each line ends with `\n` (also the last).

1. `ilhash 1`
2. `locals` followed by ` <type>` for each local variable, in slot order.
3. `initlocals 1` if the body header asks for zero-initialized locals and there is at least one local, else
   `initlocals 0`.
4. One line per instruction, in order: the opcode name, then, if the instruction has an operand, a space and the
   operand as `<kind>:<value>`:

   | Operand | Written as |
   |---|---|
   | int8 / int32 constant (`ldc.i4`, `ldc.i4.s`, `ldc.i4.<n>`, `unaligned.`) | `i:<decimal>` |
   | int64 constant | `l:<decimal>` |
   | float32 / float64 constant | `r4:<8 hex digits>` / `r8:<16 hex digits>` (IEEE bits) |
   | string | `s:"<text>"`, with `\` as `\\`, `"` as `\"`, and characters below U+0020, U+007F and UTF-16 surrogates as `\u<4 hex digits>` |
   | argument | `a:<number>` (argument 0 is `this` in instance methods) |
   | local | `v:<slot>` |
   | branch target | `@<instruction index>` (0-based); `switch` lists them comma-separated |
   | method (`MethodDef`, `MemberRef`, `MethodSpec`) | `m:<return type> <declaring type>::<name>[<<instantiation>>](<parameter types>)` |
   | field (`FieldDef`, `MemberRef`) | `f:<type> <declaring type>::<name>` |
   | type (`TypeDef`, `TypeRef`, `TypeSpec`) | `t:<type>` |
   | stand-alone signature (`calli`) | `sig:[instance ]<return type>(<parameter types>)` |
   | operand that does not resolve | `?` (a branch target that is not an instruction start: `@?`) |

   Opcodes are normalized to one form: short branches (`br.s`, `leave.s`, `beq.s`, ...) to the long form;
   `ldarg.s`, `ldarga.s`, `starg.s`, `ldloc.s`, `ldloca.s`, `stloc.s` to the long form; `ldarg.<n>`, `ldloc.<n>`,
   `stloc.<n>` to `ldarg` / `ldloc` / `stloc` with the number as operand; `ldc.i4.<n>`, `ldc.i4.m1`, `ldc.i4.s` to
   `ldc.i4`. Other opcodes are written with their ECMA-335 name.
5. One line per exception region, in metadata order: `catch`, `filter`, `finally` or `fault`, then the try start
   and end, then the handler start and end, as `@<instruction index>` (ends are exclusive; the end of the body is
   `@<instruction count>`); a filter region adds its filter start, a catch region adds `t:<catch type>`.

Types are written in signature notation without assembly names: `Namespace.Name` with `/` before nested type
names, generic instances as `Name`1<Arg>` with comma-separated arguments, type generic parameters as `!<n>` and
method generic parameters as `!!<n>`, `*` / `&` / `[]` / `[<rank>]` suffixes, ` pinned`, and
` modreq(<type>)` / ` modopt(<type>)`. Primitive types use their full names (`System.Int32`). Member references and
definitions are written alike, so a call to a method of the same assembly and a call through a member reference
give the same text.

Not part of the hash: metadata tokens, IL byte offsets and sizes, the max-stack value, the local signature's
token, the method's own name, signature, flags and custom attributes (`compare_assemblies` reports those as
signature or `metadata` changes).

## Test vector

`Lab.P::Parse(string)` built by `IlHashTests` (short forms; the same method with long forms and other tokens
gives the same hash):

```
.method public hidebysig static int32 Parse(string a0)
{
  .locals init (int32 V_0)
  .try
  {
    IL_0000: ldarg.0
    IL_0001: call int32 [mscorlib]System.Int32::Parse(string)
    IL_0006: stloc.0
    IL_0007: leave.s IL_000e
  }
  catch [mscorlib]System.FormatException
  {
    IL_0009: pop
    IL_000a: ldc.i4.m1
    IL_000b: stloc.0
    IL_000c: leave.s IL_000e
  }
  IL_000e: ldloc.0
  IL_000f: ldstr "done\n"
  IL_0014: pop
  IL_0015: ret
}
```

Canonical text:

```
ilhash 1
locals System.Int32
initlocals 1
ldarg a:0
call m:System.Int32 System.Int32::Parse(System.String)
stloc v:0
leave @8
pop
ldc.i4 i:-1
stloc v:0
leave @8
ldloc v:0
ldstr s:"done\u000a"
pop
ret
catch @0 @4 @4 @8 t:System.FormatException
```

SHA-256: `21807e13787c7f6e0a872a4b4d1741c054fc0de4727a67d8b55ea0dc0b26fffa` (shown by `get_il` as
`// IL hash: 21807e13787c7f6e`).
