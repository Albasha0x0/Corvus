# Normalized IL hash

A SHA-256 of each method body that ignores metadata tokens, byte offsets and short or long instruction forms. Two
builds of the same code give the same hash.

- `get_il` prints it: `// IL hash: <first 16 hex digits>`.
- `find_counterpart` reports `body: unchanged` or `changed`; `compare_assemblies` pairs renamed methods with identical
  bodies.
- A method without a body, or with invalid IL, has no hash.
- `get_il` also prints `raw IL SHA-256` over the IL code bytes in the file (`(file as loaded)` with unsaved edits).
  Any token or offset change changes it. `decompile_member provenance=true` prints both hashes in full.

## Encoding (version 1)

Lower-case hex SHA-256 of this UTF-8 text; each line ends with `\n`.

1. `ilhash 1`
2. `locals` and ` <type>` per local, in slot order.
3. `initlocals 1` if the header zeroes locals and there is at least one, else `initlocals 0`.
4. Per instruction: the opcode name, then ` <kind>:<value>` for an operand (table below).
5. Per exception region, in metadata order: `catch`, `filter`, `finally` or `fault`, try start and end, handler start and
   end, as `@<instruction index>`. Ends are exclusive; the body end is `@<instruction count>`. A filter adds its filter
   start; a catch adds `t:<type>`.

| Operand | Written as |
|---|---|
| int32 / int64 / float32 / float64 | `i:<decimal>` / `l:<decimal>` / `r4:<8 hex digits>` / `r8:<16 hex digits>` (IEEE bits) |
| string | `s:"<text>"`; `\` and `"` escaped; below U+0020, U+007F and surrogates as `\uXXXX` |
| argument / local | `a:<n>` (0 is `this`) / `v:<slot>` |
| branch target | `@<instruction index>` (0-based); `switch` lists them comma-separated |
| method / field / type | `m:<return> <declaring>::<name>[<<instantiation>>](<parameter types>)`, `f:<type> <declaring>::<name>`, `t:<type>` |
| `calli` | `sig:[instance ]<return>(<parameter types>)` |
| unresolved | `?` (a branch target that is not an instruction start: `@?`) |

Normalized opcodes: short branches and `*.s` forms take the long name; `ldarg.<n>`, `ldloc.<n>` and `stloc.<n>` become
`ldarg`, `ldloc` and `stloc` with the number as operand; `ldc.i4.<n>`, `ldc.i4.m1` and `ldc.i4.s` become `ldc.i4`. Other
opcodes keep their ECMA-335 name.

Types: signature notation without assembly names (`System.Int32`, `Outer/Inner`, ``Name`1<Arg>``, `!n`, `!!n`, `*`,
`&`, `[]`, `[<rank>]`, ` pinned`, ` modreq(<type>)`, ` modopt(<type>)`).

Not hashed: metadata tokens, IL offsets and sizes, max stack, the local signature token, and the method's name,
signature, flags and custom attributes.

## Test vector

Canonical text of a `Parse(string)` method with a catch region:

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

SHA-256: `21807e13787c7f6e0a872a4b4d1741c054fc0de4727a67d8b55ea0dc0b26fffa`
