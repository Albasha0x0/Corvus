# Guide 3: a new build

A new version of a program usually renames and moves some of what you had worked out. Notes 2.0
([source](../../samples/Notes/v2)) renames `CsvExporter.Quote` to `Escape` and `PreviewGate.Verify` to `Check`, and
moves the string decoder into `PreviewGate`. This guide finds those changes and carries the edits of
[guide 2](2-decode-and-patch.md) (simplify, rename, patch) to the new build. Run guide 2 first: it writes the edit
script used here.

## Ask your agent

> Load samples/Notes/v1/bin/Notes.dll and samples/Notes/v2/bin/Notes.dll. What changed? Then apply my edit script
> samples/Notes/v1/bin/patched/notes-v1.edits.json to the new build and save it to samples/Notes/v2/bin/patched/Notes.dll.

`compare_assemblies` matches members by content, so a renamed or moved method is found even under its new name.
`apply_edits` with `targetBuild=other` resolves each edit by name and follows the renames it finds.

<!-- check: batch -->
```json
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/Notes.dll"}}
{"tool": "load_assembly", "args": {"path": "samples/Notes/v2/bin/Notes.dll"}}
{"tool": "compare_assemblies", "args": {"oldAssembly": "Notes", "newAssembly": "Notes#2"}}
{"tool": "apply_edits", "args": {"path": "samples/Notes/v1/bin/patched/notes-v1.edits.json", "assembly": "Notes#2", "targetBuild": "other", "dryRun": false}}
{"tool": "save_assembly", "args": {"assembly": "Notes#2", "outputPath": "samples/Notes/v2/bin/patched/Notes.dll", "overwrite": true}}
```

<!-- check: output -->
```text
=== [1/5] load_assembly
Loaded Notes: Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
  samples/Notes/v1/bin/Notes.dll
  8 types, 2 namespaces
=== [2/5] load_assembly
Loaded Notes#2: Notes, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null
  samples/Notes/v2/bin/Notes.dll
  7 types, 2 namespaces
=== [3/5] compare_assemblies
Comparing Notes (samples/Notes/v1/bin/Notes.dll; SHA-256 <sha256-1>, MVID <guid-1>)
       -> Notes#2 (samples/Notes/v2/bin/Notes.dll; SHA-256 <sha256-2>, MVID <guid-2>)
Types: 0 renamed, 4 with member changes, 1 removed, 0 added (7 matched of 8 old).
Members (each change of a member counted): 2 renamed, 1 moved, 0 signature, 4 body, 0 metadata, 0 type, 0 offset, 0 address, 0 added, 0 removed, 0 ambiguous, 0 unknown
Member matches: 73 exact, 2 strong, 1 structural, 0 ambiguous (by tier: full name + signature 53, full name 20, body shape 1, IL hash 1, IL hash, other type 1).

7 changes (showing 1-7):
  Notes.CsvExporter
      body      method Write(IEnumerable<Note>, TextWriter): 47 -> 47 instructions
      renamed   method Quote(string) -> Escape(string)  (identical body (renamed); tier: IL hash, strong)
  Notes.PreviewGate
      renamed   method Verify(string) -> Check(string)  (identical body shape (renamed); tier: body shape, structural)  +body: 46 -> 46 instructions
  Notes.NoteStore
      body      method All(): 25 -> 32 instructions
  Notes.Program
      body      method Main(string[]): 90 -> 90 instructions
  Notes.Strings  (removed)
      moved     method D(string, int) -> Notes.PreviewGate::D(string, int)  (identical body (moved); tier: IL hash, other type, strong)
  Removed types (1):
      Notes.Strings
[End: 7 changes]
=== [4/5] apply_edits
Applying 3 edit(s) from notes-v1.edits.json to Notes#2 (different build: resolving symbols by name, renamed ones through Notes (the build the script was made from)):
Build check: different build, carried over (targetBuild=other): the script was made for sha256 <sha256-1>, MVID <guid-1>, Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null; Notes#2 is sha256 <sha256-2>, MVID <guid-2>, Notes, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null
  #1 ok      simplify Notes.PreviewGate::Verify(string) (fold,cfg,inline): 1 method(s)
      target renamed in this build: Notes.PreviewGate::Verify(string) -> Notes.PreviewGate::Check(string) (identical body shape (renamed))
  #2 ok      rename method Notes.Strings::D(string, int) -> Decode
      target renamed in this build: Notes.Strings::D(string, int) -> Notes.PreviewGate::D(string, int) (identical body (moved))
  #3 ok      stub Notes.PreviewGate::Verify(string) => return true;
      target renamed in this build: Notes.PreviewGate::Verify(string) -> Notes.PreviewGate::Check(string) (identical body shape (renamed))
3 applied, 0 failed.
Cross-build: 3 edit(s) resolved by name, 3 target(s) followed to a renamed counterpart.
=== [5/5] save_assembly
Wrote samples/Notes/v2/bin/patched/Notes.dll (12,800 bytes, 3 edit(s); everything no edit touched is as in the original).
```

The comparison finds the two renames and the move that the [source diff](../../samples/Notes) shows, and all three
edits apply to their renamed targets.

## Check

<!-- check: run -->
```sh
dotnet samples/Notes/v2/bin/Notes.dll preview any-code
```

<!-- check: output -->
```text
preview unavailable
stderr: invalid preview code
exit code 1
```

<!-- check: run -->
```sh
dotnet samples/Notes/v2/bin/patched/Notes.dll preview any-code
```

<!-- check: output -->
```text
preview enabled
exit code 0
```
