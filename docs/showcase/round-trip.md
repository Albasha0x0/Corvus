# Showcase: decompile, rebuild, run

`export_project` writes an assembly back out as a C# project. For the Notes sample the exported project builds
under this repository's warnings-as-errors settings, the rebuilt program prints the same export, and
`compare_assemblies` measures how close the rebuilt code is to the original. Build the sample first ([guide 1](../guides/1-first-session.md#build-the-sample)).

<!-- check: batch -->
```json
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/Notes.dll"}}
{"tool": "export_project", "args": {"assembly": "Notes", "outputDirectory": "samples/Notes/v1/bin/exported"}}
```

<!-- check: output -->
```text
=== [1/2] load_assembly
Loaded Notes: Notes, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
  samples/Notes/v1/bin/Notes.dll
  8 types, 2 namespaces
=== [2/2] export_project
Exported Notes to samples/Notes/v1/bin/exported: 9 files. Project: samples/Notes/v1/bin/exported/Notes.csproj
```

Build the exported project and run it:

<!-- check: setup -->
```sh
dotnet build samples/Notes/v1/bin/exported
```

<!-- check: run -->
```sh
dotnet samples/Notes/v1/bin/exported/bin/Notes.dll export
```

<!-- check: output -->
```text
id,title,created
1,Groceries,2026-01-05
2,"Hello, ""you""",2026-01-06
3,Plan,2026-01-07
exit code 0
```

The same four lines as the original ([guide 1](../guides/1-first-session.md#predict-then-check)). Original and
rebuilt program side by side:

<!-- check: batch show=3 -->
```json
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/Notes.dll"}}
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/exported/bin/Notes.dll"}}
{"tool": "compare_assemblies", "args": {"oldAssembly": "Notes", "newAssembly": "Notes#2"}}
```

<!-- check: output -->
```text
=== [3/3] compare_assemblies
Comparing Notes (samples/Notes/v1/bin/Notes.dll; SHA-256 <sha256-1>, MVID <guid-1>)
       -> Notes#2 (samples/Notes/v1/bin/exported/bin/Notes.dll; SHA-256 <sha256-2>, MVID <guid-2>)
Types: 0 renamed, 2 with member changes, 0 removed, 0 added (8 matched of 8 old).
Members (each change of a member counted): 0 renamed, 0 moved, 0 signature, 2 body, 0 metadata, 0 type, 0 offset, 0 address, 0 added, 0 removed, 0 ambiguous, 0 unknown
Member matches: 32 exact, 41 strong, 0 structural, 0 ambiguous (by tier: type match + name + signature 32, full name + signature 24, type match + name 9, full name 8).
Hidden: 1 compiler-generated type change(s) and 0 member change(s) (closures, state machines, backing fields, array data; includeCompilerGenerated=true shows them).

2 changes (showing 1-2):
  Notes.NoteStore
      body      method All(): 25 -> 25 instructions
  Notes.Program
      body      method Main(string[]): 90 -> 90 instructions
[End: 2 changes]
```

Every type and member of the original is matched in the rebuilt program under its own name; the body changes listed
are the compiler's choices for the decompiled source, with the same instruction counts.
