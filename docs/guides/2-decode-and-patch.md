# Guide 2: decode and patch

Code that ships transformed hides its strings behind decoder calls and its control flow behind a state-machine switch.
`PreviewGate` in the Notes sample ([source](../../samples/Notes/v1/PreviewGate.cs)) is written in that shape on
purpose. This guide turns it back into plain code, finds the valid code, makes the gate accept any code and saves a
patched copy. Build the sample first ([guide 1](1-first-session.md#build-the-sample)).

## Ask your agent

> Load samples/Notes/v1/bin/Notes.dll. Simplify PreviewGate.Verify and tell me which code it accepts. Then make it
> accept any code, name the string decoder Decode, and save a copy to samples/Notes/v1/bin/patched/Notes.dll.

The calls it makes, as a batch. The first `decompile_member` shows the method as compiled; `simplify_methods` runs each
decoder call with its constant arguments in a sandboxed IL interpreter (nothing from the file is executed) and replaces
it with the string it returns, then straightens the switch; the second `decompile_member` shows the result.

<!-- check: batch -->
```json
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/Notes.dll"}}
{"tool": "decompile_member", "args": {"member": "Notes.PreviewGate::Verify"}}
{"tool": "simplify_methods", "args": {"symbol": "Notes.PreviewGate::Verify", "dryRun": false}}
{"tool": "decompile_member", "args": {"member": "Notes.PreviewGate::Verify"}}
{"tool": "rename_symbol", "args": {"symbol": "Notes.Strings::D", "newName": "Decode", "dryRun": false}}
{"tool": "stub_method", "args": {"method": "Notes.PreviewGate::Verify", "value": "true", "dryRun": false}}
{"tool": "save_assembly", "args": {"assembly": "Notes", "outputPath": "samples/Notes/v1/bin/patched/Notes.dll", "overwrite": true}}
{"tool": "export_edits", "args": {"assembly": "Notes", "outputPath": "samples/Notes/v1/bin/patched/notes-v1.edits.json", "overwrite": true}}
```

<!-- check: output -->
```text
=== [1/8] load_assembly
Loaded Notes: Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
  samples/Notes/v1/bin/Notes.dll
  8 types, 2 namespaces
=== [2/8] decompile_member
// [Notes]
// Notes.PreviewGate::Verify(string)  [token 0x06000022]
using System;

public static bool Verify(string code)
{
	int num = 0;
	while (true)
	{
		switch (num)
		{
		case 0:
			num = ((code.Length == 14) ? 1 : 3);
			break;
		case 1:
			num = (code.StartsWith(Strings.D("\u0004\u0003\u0011\b\u001ck", 65), StringComparison.Ordinal) ? 2 : 3);
			break;
		case 2:
			if (code.Substring(6) == Strings.D("$R&W.)Z(", 19))
			{
				return true;
			}
			num = 3;
			break;
		default:
			Console.Error.WriteLine(Strings.D("CEZLBFT\u0011BAQC_RO\u0019YTXX", 42));
			return false;
		}
	}
}
=== [3/8] simplify_methods
[Notes] Simplified Notes.PreviewGate::Verify(string) (fold,cfg,inline): 1 of 1 method(s) changed.
Notes.PreviewGate::Verify(string)  [46 -> 24 instructions]
  folded Notes.Strings::D(string, int) -> "EARLY-" at IL_002F
  folded Notes.Strings::D(string, int) -> "7F3A91C2" at IL_0051
  folded Notes.Strings::D(string, int) -> "invalid preview code" at IL_006F
  collapsed 4 branch chain(s), normalized 1 switch dispatcher(s) (6 transition(s) go straight to their case), removed 5 unreachable block(s) (8 instructions)
Edit Notes#1. Unsaved edits in Notes: 1.
Digest 73a90c814517d45c.
=== [4/8] decompile_member
// [Notes]
// Notes.PreviewGate::Verify(string)  [token 0x06000022]
using System;

public static bool Verify(string code)
{
	if (code.Length == 14 && code.StartsWith("EARLY-", StringComparison.Ordinal) && code.Substring(6) == "7F3A91C2")
	{
		return true;
	}
	Console.Error.WriteLine("invalid preview code");
	return false;
}
=== [5/8] rename_symbol
[Notes] rename method Notes.Strings::D(string, int) -> Decode
Edit Notes#2. Unsaved edits in Notes: 2.
Digest 2597468d97f6c120.
=== [6/8] stub_method
[Notes] stub Notes.PreviewGate::Verify(string) => return true;
Edit Notes#3. Unsaved edits in Notes: 3.
Digest 2378754614672d06.
=== [7/8] save_assembly
Wrote samples/Notes/v1/bin/patched/Notes.dll (12,800 bytes, 3 edit(s); everything no edit touched is as in the original).
Edits written: Notes#1 (73a90c814517d45c), Notes#2 (2597468d97f6c120), Notes#3 (2378754614672d06).
=== [8/8] export_edits
Exported 3 edit(s) of Notes to samples/Notes/v1/bin/patched/notes-v1.edits.json.
Bound to the build: sha256 <sha256-1>, MVID <guid-1>, Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null. apply_edits refuses other builds unless targetBuild=other.
```

All three decoder calls fold, and the simplified method names the code: `EARLY-` followed by `7F3A91C2`.

## Check

The original accepts that code and refuses any other:

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/Notes.dll preview EARLY-7F3A91C2
```

<!-- check: output -->
```text
preview enabled
exit code 0
```

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/Notes.dll preview any-code
```

<!-- check: output -->
```text
preview unavailable
stderr: invalid preview code
exit code 1
```

The edited copy accepts any code:

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/patched/Notes.dll preview any-code
```

<!-- check: output -->
```text
preview enabled
exit code 0
```

The edits are also saved as an edit script (`export_edits`), which [guide 3](3-new-build.md) carries to a new build.
