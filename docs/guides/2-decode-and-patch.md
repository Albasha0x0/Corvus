# Guide 2: decode and patch

Code that ships obfuscated hides its strings behind decoder calls and its control flow behind a state-machine switch.
`LicenseCheck` in the Notes sample ([source](../../samples/Notes/v1/LicenseCheck.cs)) is written in that shape on
purpose. This guide turns it back into plain code, finds the valid key, makes the check accept any key and saves a
patched copy. Build the sample first ([guide 1](1-first-session.md#build-the-sample)).

## Ask your agent

> Load samples/Notes/v1/bin/Notes.dll. Simplify LicenseCheck.Verify and tell me which key it accepts. Then make it
> accept any key, name the string decoder Decode, and save a copy to samples/Notes/v1/bin/patched/Notes.dll.

The calls it makes, as a batch. The first `decompile_member` shows the method as compiled; `simplify_methods` runs each
decoder call with its constant arguments in a sandboxed IL interpreter (nothing from the file is executed) and replaces
it with the string it returns, then straightens the switch; the second `decompile_member` shows the result.

<!-- check: batch -->
```json
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/Notes.dll"}}
{"tool": "decompile_member", "args": {"member": "Notes.LicenseCheck::Verify"}}
{"tool": "simplify_methods", "args": {"symbol": "Notes.LicenseCheck::Verify"}}
{"tool": "decompile_member", "args": {"member": "Notes.LicenseCheck::Verify"}}
{"tool": "rename_symbol", "args": {"symbol": "Notes.Strings::D", "newName": "Decode"}}
{"tool": "stub_method", "args": {"method": "Notes.LicenseCheck::Verify", "value": "true"}}
{"tool": "save_assembly", "args": {"assembly": "Notes", "outputPath": "samples/Notes/v1/bin/patched/Notes.dll", "overwrite": true}}
{"tool": "export_edits", "args": {"assembly": "Notes", "path": "samples/Notes/v1/bin/patched/notes-v1.edits.json", "overwrite": true}}
```

<!-- check: output -->
```text
=== [1/8] load_assembly
Loaded Notes: Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
  samples/Notes/v1/bin/Notes.dll
  8 types, 2 namespaces
=== [2/8] decompile_member
// [Notes]
// Notes.LicenseCheck::Verify(string)  [token 0x06000022]
using System;

public static bool Verify(string key)
{
	int num = 0;
	while (true)
	{
		switch (num)
		{
		case 0:
			num = ((key.Length == 14) ? 1 : 3);
			break;
		case 1:
			num = (key.StartsWith(Strings.D("\u000f\r\u0017\u0001\u0016k", 65), StringComparison.Ordinal) ? 2 : 3);
			break;
		case 2:
			if (key.Substring(6) == Strings.D("$R&W.)Z(", 19))
			{
				return true;
			}
			num = 3;
			break;
		default:
			Console.Error.WriteLine(Strings.D("FBOH@\\U\u0011YVM\u0015DRR\\YOYY", 42));
			return false;
		}
	}
}
=== [3/8] simplify_methods
[Notes] Simplified Notes.LicenseCheck::Verify(string) (fold,cfg,inline): 1 of 1 method(s) changed.
Notes.LicenseCheck::Verify(string)  [46 -> 24 instructions]
  folded Notes.Strings::D(string, int) -> "NOTES-" at IL_002F
  folded Notes.Strings::D(string, int) -> "7F3A91C2" at IL_0051
  folded Notes.Strings::D(string, int) -> "license key rejected" at IL_006F
  collapsed 4 branch chain(s), normalized 1 switch dispatcher(s) (6 transition(s) go straight to their case), removed 5 unreachable block(s) (8 instructions)
Unsaved edits in Notes: 1.
=== [4/8] decompile_member
// [Notes]
// Notes.LicenseCheck::Verify(string)  [token 0x06000022]
using System;

public static bool Verify(string key)
{
	if (key.Length == 14 && key.StartsWith("NOTES-", StringComparison.Ordinal) && key.Substring(6) == "7F3A91C2")
	{
		return true;
	}
	Console.Error.WriteLine("license key rejected");
	return false;
}
=== [5/8] rename_symbol
[Notes] rename method Notes.Strings::D(string, int) -> Decode
Unsaved edits in Notes: 2.
=== [6/8] stub_method
[Notes] stub Notes.LicenseCheck::Verify(string) => return true;
Unsaved edits in Notes: 3.
=== [7/8] save_assembly
Wrote samples/Notes/v1/bin/patched/Notes.dll (12,800 bytes, 3 edit(s); everything no edit touched is as in the original).
=== [8/8] export_edits
Exported 3 edit(s) of Notes to samples/Notes/v1/bin/patched/notes-v1.edits.json.
Bound to the build: sha256 <sha256-1>, MVID <guid-1>, Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null. apply_edits refuses other builds unless targetBuild=other.
```

All three decoder calls fold, and the simplified method names the key: `NOTES-` followed by `7F3A91C2`.

## Check

The original accepts that key and refuses any other:

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/Notes.dll license NOTES-7F3A91C2
```

<!-- check: output -->
```text
licensed
exit code 0
```

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/Notes.dll license any-key
```

<!-- check: output -->
```text
not licensed
stderr: license key rejected
exit code 1
```

The patched copy accepts any key:

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/patched/Notes.dll license any-key
```

<!-- check: output -->
```text
licensed
exit code 0
```

The edits are also saved as an edit script (`export_edits`), which [guide 3](3-new-build.md) carries to a new build.
