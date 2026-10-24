# FAQ

**Does it upload my files or send anything over the network?**
No file is uploaded. Requests: a .NET reference pack from nuget.org when code targets an uninstalled .NET version;
`load_pdb download=true` (symbol server, debuginfod) and `open_minidump downloadDac=true`; the pinned Frida with
`--live-install-frida`; release downloads by the install scripts and `update`; and IDA or Ghidra if their own settings
reach out. `CORVUS_OFFLINE=1` refuses Corvus's own requests except updates and installs, which run only when you
start them. Full list: [SECURITY.md](../SECURITY.md#network).

**Does it run the program I analyze?**
Not by default: it reads bytes. `simplify_methods` and `emulate_native` emulate code (never run natively).
`inspect_process` reads a running process, writing and suspending nothing. Only the session tools, off by default, run
or attach to a program and patch its code in memory. External helpers (IDA, Ghidra, JADX, adb, TShark and others) run
only on the calls that need them: [SECURITY.md](../SECURITY.md#worker-and-helper-processes).

**Do I need IDA or Ghidra?**
No. Decompilation, search, cross-references and patching of .NET code, and native analysis (PE, ELF, Mach-O
disassembly, functions, cross-references, CFGs, RTTI, PDBs, patching) are built in. IDA (with idalib) or Ghidra adds
C pseudocode (`decompile_native`, `search_decompiled`), emulation (`emulate_native`), engine scripting and the engine
type and frame edits. WebAssembly decompiles without one. `corvus status --engine all` shows what is available.

**Which clients are supported?**
The ones in the table of [installation.md](installation.md#clients); `install` finds the installed ones. Any other MCP
client works with the output of `corvus config`.

**How do I update?**
`corvus update` installs the latest release and refreshes existing registrations; client settings need no
change. `--version X` pins or rolls back.

**The tools do not show up. What now?**
Restart the client, then run `corvus status`. [troubleshooting.md](troubleshooting.md) goes by symptom.

**Can I use it without an agent?**
Yes. Every tool runs from a terminal: `corvus decompile_member --load app.dll member=Ns.Type::Method`, and
`batch` runs several calls in one session ([cli.md](cli.md)).

**Can I install without internet access on the target machine?**
Yes: copy a release archive and `SHA256SUMS`, then run the install script with `CORVUS_ARCHIVE` and `CORVUS_SHA256SUMS`
([installation.md](installation.md)).

**Does it handle Il2Cpp and Unity builds?**
Yes. `load_assembly` reads an Il2Cpp build folder or its `global-metadata.dat` with the built-in metadata reader; no
external dumper is needed. `unity_overview` reports the engine version, scripting backend and the next calls. Metadata
encrypted on disk is reported, not decrypted: dump the decrypted copy from the running program's memory and load
that.

**Is the agent skill required?**
No. The server sends its own guidance to every client. `install --skill` adds an optional skill for clients that read
skills; it lets an agent check the registration and use the command line when the tools are not connected.

**Where is my data, and how do I remove it?**
Saved names, comments, notes, code-index and engine caches, symbols and reference packs live under
`%LOCALAPPDATA%\Corvus` on Windows and the local application data folder elsewhere. `uninstall` keeps them;
`uninstall --purge-data` deletes them.

**May I use it on any program?**
Use it on software you own or are permitted to analyze, and follow the license terms and laws that apply to you
([README](../README.md#responsible-use)).
