# Showcase: IL with the source lines of its build

The question: which source line does each IL instruction come from, and where can that source be read? The assembly is
`Mono.Cecil.dll` from the public NuGet package [Mono.Cecil](https://www.nuget.org/packages/Mono.Cecil/0.11.3), read
from the NuGet packages folder after a restore. The package ships the Portable PDB beside the assembly.

Disassemble one method with `source=true`:

<!-- check: batch show=2 -->
```json
{"tool": "load_assembly", "args": {"path": "~/.nuget/packages/mono.cecil/0.11.3/lib/netstandard2.0/Mono.Cecil.dll"}}
{"tool": "get_il", "args": {"assembly": "Mono.Cecil", "symbol": "Mono.Cecil.ModuleDefinition::ReadModule(string, ReaderParameters)", "source": true}}
```

<!-- check: output -->
```text
=== [2/2] get_il
// [Mono.Cecil] Mono.Cecil.ModuleDefinition::ReadModule(string, ReaderParameters)
// Portable PDB: ~/.nuget/packages/mono.cecil/0.11.3/lib/netstandard2.0/Mono.Cecil.pdb (id matches the image); SourceLink maps 138 documents
// IL hash: 04385171cf6a5eae  raw IL SHA-256: 272d9277e549ddb8
.method /* 060006DE */ public hidebysig static
	class Mono.Cecil.ModuleDefinition ReadModule (
		string fileName,
		class Mono.Cecil.ReaderParameters parameters
	) cil managed
{
	// Method begins at RVA 0x16eb4
	// Header size: 12
	// Code size: 112 (0x70)
	.maxstack 4
	.locals /* 11000127 */ init (
		[0] class [netstandard]System.IO.Stream 'stream',
		[1] class [netstandard]System.IO.MemoryStream memory,
		[2] class [netstandard]System.IO.Stream,
		[3] class Mono.Cecil.ModuleDefinition
	)

	// line 1082:4-1082:136 in https://raw.githubusercontent.com/jbevain/cecil/e9a4815fdb102a3bc87a606c6e9ee5f61c00414a/Mono.Cecil/ModuleDefinition.cs
	IL_0000: ldarg.0
	IL_0001: ldc.i4.3
	IL_0002: ldarg.1
	IL_0003: callvirt instance bool Mono.Cecil.ReaderParameters::get_ReadWrite() /* 0600064A */
	IL_0008: brtrue.s IL_000d

	IL_000a: ldc.i4.1
	IL_000b: br.s IL_000e

	IL_000d: ldc.i4.3

	IL_000e: ldc.i4.1
	IL_000f: call class [netstandard]System.IO.Stream Mono.Cecil.ModuleDefinition::GetFileStream(string, valuetype [netstandard]System.IO.FileMode, valuetype [netstandard]System.IO.FileAccess, valuetype [netstandard]System.IO.FileShare) /* 060006DF */
	IL_0014: stloc.0
	// line 1084:4-1084:28
	IL_0015: ldarg.1
	IL_0016: callvirt instance bool Mono.Cecil.ReaderParameters::get_InMemory() /* 06000638 */
	IL_001b: brfalse.s IL_0054

	// line 1085:5-1085:78
	IL_001d: ldloc.0
	IL_001e: callvirt instance bool [netstandard]System.IO.Stream::get_CanSeek() /* 0A00009F */
	IL_0023: brtrue.s IL_0028

	IL_0025: ldc.i4.0
	IL_0026: br.s IL_002f

	IL_0028: ldloc.0
	IL_0029: callvirt instance int64 [netstandard]System.IO.Stream::get_Length() /* 0A0000A9 */
	IL_002e: conv.i4

	IL_002f: newobj instance void [netstandard]System.IO.MemoryStream::.ctor(int32) /* 0A0000AA */
	IL_0034: stloc.1
	// line 1086:5-1086:19
	IL_0035: ldloc.0
	IL_0036: stloc.2
	.try
	{
		// line 1087:6-1087:29
		IL_0037: ldloc.0
		IL_0038: ldloc.1
		IL_0039: callvirt instance void [netstandard]System.IO.Stream::CopyTo(class [netstandard]System.IO.Stream) /* 0A000198 */
		IL_003e: leave.s IL_004a
	} // end .try
	finally
	{
		// hidden
		IL_0040: ldloc.2
		IL_0041: brfalse.s IL_0049

		IL_0043: ldloc.2
		IL_0044: callvirt instance void [netstandard]System.IDisposable::Dispose() /* 0A000028 */

		// hidden
		IL_0049: endfinally
	} // end handler

	// line 1089:5-1089:25
	IL_004a: ldloc.1
	IL_004b: ldc.i4.0
	IL_004c: conv.i8
	IL_004d: callvirt instance void [netstandard]System.IO.Stream::set_Position(int64) /* 0A0000BF */
	// line 1090:5-1090:21
	IL_0052: ldloc.1
	IL_0053: stloc.0

	// hidden
	IL_0054: nop
	.try
	{
		// line 1094:5-1094:73
		IL_0055: ldloc.0
		IL_0056: call valuetype Mono.Disposable`1<!!0> Mono.Disposable::Owned<class [netstandard]System.IO.Stream>(!!0) /* 2B00008E */
		IL_005b: ldarg.0
		IL_005c: ldarg.1
		IL_005d: call class Mono.Cecil.ModuleDefinition Mono.Cecil.ModuleDefinition::ReadModule(valuetype Mono.Disposable`1<class [netstandard]System.IO.Stream>, string, class Mono.Cecil.ReaderParameters) /* 060006E2 */
		IL_0062: stloc.3
		IL_0063: leave.s IL_006e
	} // end .try
	catch [netstandard]System.Exception
	{
		// line 1095:6-1095:23
		IL_0065: pop
		// line 1096:5-1096:23
		IL_0066: ldloc.0
		IL_0067: callvirt instance void [netstandard]System.IO.Stream::Dispose() /* 0A000377 */
		// line 1097:5-1097:11
		IL_006c: rethrow
	} // end handler

	// line 1099:3-1099:4
	IL_006e: ldloc.3
	IL_006f: ret
} // end of method ModuleDefinition::ReadModule
```

The PDB is used only because its id equals the one the image records; a PDB of another build is named and refused
instead of putting wrong lines on the IL. Each sequence point stands at its IL offset as `// line start-end`, with the
document where it changes, given as its SourceLink URL (the source file of that exact commit) when the PDB carries
SourceLink. Hidden points (compiler-generated code such as the `finally` of a `using`) read `// hidden`, and the
locals take their source names (`stream`, `memory`) from the PDB's local scopes. An embedded Portable PDB is read the
same way.
