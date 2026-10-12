# Showcase: inside a single-file app

A .NET single-file app is a native executable with its assemblies bundled inside. `unpack_container` reads the
bundle without running it and extracts the assemblies byte for byte. Here the Notes sample is published twice for
Linux x64, as one file and as an ordinary folder, from any OS:

<!-- check: setup -->
```sh
dotnet publish samples/Notes/v1 -r linux-x64 --self-contained false -p:PublishSingleFile=true -o samples/Notes/v1/bin/single
dotnet publish samples/Notes/v1 -r linux-x64 --self-contained false -o samples/Notes/v1/bin/plain
```

Unpack the single file, then compare what came out of it with the ordinary build:

<!-- check: batch show=1,3 -->
```json
{"tool": "unpack_container", "args": {"path": "samples/Notes/v1/bin/single/Notes", "outputDirectory": "samples/Notes/v1/bin/unpacked"}}
{"tool": "load_assembly", "args": {"path": "samples/Notes/v1/bin/plain/Notes.dll"}}
{"tool": "compare_assemblies", "args": {"oldAssembly": "Notes", "newAssembly": "Notes#2"}}
```

<!-- check: output -->
```text
=== [1/3] unpack_container
{"source":"samples/Notes/v1/bin/single/Notes","container":".NET single-file bundle","outputDirectory":"samples/Notes/v1/bin/unpacked","files":[{"path":"samples/Notes/v1/bin/unpacked/Notes.dll","kind":".NET assembly","size":12288,"sha256":"<sha256-1>","origin":"bundle entry (assembly)","loadedAs":"Notes","readyToRun":false,"merged":null},{"path":"samples/Notes/v1/bin/unpacked/Notes.runtimeconfig.json","kind":"text","size":342,"sha256":"<sha256-2>","origin":"bundle entry (runtimeconfig.json)","loadedAs":null,"readyToRun":null,"merged":null},{"path":"samples/Notes/v1/bin/unpacked/Notes.deps.json","kind":"text","size":467,"sha256":"<sha256-3>","origin":"bundle entry (deps.json)","loadedAs":null,"readyToRun":null,"merged":null}],"notes":["Single-file bundle v6.0, id evp1zbx5CE9e, 3 files."]}
=== [3/3] compare_assemblies
Comparing Notes (samples/Notes/v1/bin/unpacked/Notes.dll; SHA-256 <sha256-1>, MVID <guid-1>)
       -> Notes#2 (samples/Notes/v1/bin/plain/Notes.dll; SHA-256 <sha256-1>, MVID <guid-1>)
Types: 0 renamed, 0 with member changes, 0 removed, 0 added (8 matched of 8 old).
Members (each change of a member counted): 0 renamed, 0 moved, 0 signature, 0 body, 0 metadata, 0 type, 0 offset, 0 address, 0 added, 0 removed, 0 ambiguous, 0 unknown
Member matches: 76 exact, 0 strong, 0 structural, 0 ambiguous (by tier: full name + signature 56, full name 20).
```

Both builds of `Notes.dll` carry the same SHA-256 label: the extracted assembly is identical to the one the publish
step left in the folder build, and the comparison finds no change.
