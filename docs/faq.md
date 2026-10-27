# FAQ

## Does it upload my files or use the network?

- No file is uploaded.
- Requests: .NET reference packs from nuget.org for an uninstalled .NET version; `load_pdb download=true` (symbol
  server, debuginfod); `open_minidump downloadDac=true`; the pinned Frida with `--live-install-frida`; release
  downloads by the install scripts and `update`.
- IDA and Ghidra follow their own settings.
- `CORVUS_OFFLINE=1` refuses Corvus's own requests except updates and installs, which run only when you start them.
- Full list: [SECURITY.md](../SECURITY.md#network).

## Does it run the program I analyze?

- Not by default: it reads bytes.
- `simplify_methods` and `emulate_native` emulate code; nothing runs natively.
- `inspect_process` reads a running process; it writes and suspends nothing.
- Only the session tools, off by default, start or attach to a program and patch its code in memory.
- External helpers (IDA, Ghidra, JADX, adb, TShark and others) run only on the calls that need them:
  [SECURITY.md](../SECURITY.md#worker-and-helper-processes).

## Do I need IDA or Ghidra?

- No. .NET decompilation, search, cross-references and patching are built in.
- Built-in native analysis: PE, ELF and Mach-O disassembly, functions, cross-references, CFGs, RTTI, PDBs, patching.
- IDA (with idalib) or Ghidra adds C pseudocode (`decompile_native`, `search_decompiled`), `emulate_native`, engine
  scripting and engine type and frame edits.
- WebAssembly decompiles without one.
- `corvus status --engine all` shows what is available.

## Which clients are supported?

- The [client table](installation.md#clients); `install` finds the installed ones.
- Any other MCP client works with the output of `corvus config`.

## How do I update?

`corvus update` installs the latest release and refreshes existing registrations; client settings need no change. `--version X` pins or rolls back.

## The tools do not show up

Restart the client, then run `corvus status`. Symptoms and fixes: [troubleshooting.md](troubleshooting.md).

## Can I use it without an agent?

Yes. `corvus decompile_member --load app.dll member=Ns.Type::Method`; `batch` runs several calls in one session
([cli.md](cli.md)).

## Can I install without internet access?

Yes: copy a release archive and `SHA256SUMS`, then run the install script with `CORVUS_ARCHIVE` and
`CORVUS_SHA256SUMS` ([installation.md](installation.md)).

## Does it read AOT builds with global-metadata.dat?

- Yes. `load_assembly` reads a build folder or its `global-metadata.dat`; nothing external is needed.
- `summarize_build` reports the build version, scripting backend and next calls.
- Metadata encrypted on disk is reported, not decrypted: load a decrypted copy saved from the running program's memory.

## Is the agent skill required?

No. The server sends its own guidance. `install --skill` adds an optional skill that tells an agent how to check the
registration and use the command line when the tools are not connected.

## Where is my data?

- Saved names, comments, notes, caches, symbols and reference packs: `%LOCALAPPDATA%\Corvus` on Windows, the local
  application data folder elsewhere.
- `uninstall` keeps them; `uninstall --purge-data` deletes them.

## May I use it on any program?

Use it on software you own or may analyze, under the license terms and laws that apply
([README](../README.md#responsible-use)).
