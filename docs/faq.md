# FAQ

**Does it upload my files or send anything over the network?**
No file is uploaded. The server makes three kinds of requests: a .NET reference pack from nuget.org when code targets
a .NET version that is not installed (`NDM_OFFLINE=1` turns this off), a PDB from a symbol server when you call
`load_pdb download=true`, and the release download of the install scripts and `update`. Everything else runs locally.

**Does it run the program I analyze?**
No. It reads bytes. Two features execute something, both bounded: `simplify_methods` runs string-decoder methods in its
own sandboxed IL interpreter (no I/O, reflection or native code; such calls are kept and reported), and
`inspect_process` reads a running process you name with query and read handles only, writing and suspending nothing.

**Do I need IDA or Ghidra?**
No. Decompilation, search, cross-references and patching of .NET code, and native analysis (PE, ELF, Mach-O
disassembly, functions, cross-references, CFGs, RTTI, PDBs, patching) are built in. IDA (with idalib) or Ghidra adds
C pseudocode for native code (`decompile_native`) and the engine type and frame edits. `NetDecompilerMcp status
--engine all` shows what is available.

**Which clients are supported?**
The ones in the table of [installation.md](installation.md#clients); `install` finds the installed ones. Any other MCP
client works with the output of `NetDecompilerMcp config`.

**How do I update?**
`NetDecompilerMcp update` installs the latest release and refreshes existing registrations; client settings need no
change. `--version X` pins or rolls back.

**The tools do not show up. What now?**
Restart the client, then run `NetDecompilerMcp status`. [troubleshooting.md](troubleshooting.md) goes by symptom.

**Can I use it without an agent?**
Yes. Every tool runs from a terminal: `NetDecompilerMcp decompile_member --load app.dll member=Ns.Type::Method`, and
`batch` runs several calls in one session ([cli.md](cli.md)).

**Can I install without internet access on the target machine?**
Yes: copy a release archive and `SHA256SUMS`, then run the install script with `NDM_ARCHIVE` and `NDM_SHA256SUMS`
([installation.md](installation.md)).

**Does it handle Il2Cpp and Unity builds?**
Yes. `load_assembly` reads an Il2Cpp game folder or its `global-metadata.dat` with the built-in metadata reader (no
external dumper), and `unity_overview` reports the engine version, scripting backend and the next calls.

**Is the agent skill required?**
No. The server sends its own guidance to every client. `install --skill` adds an optional skill for clients that read
skills; it helps an agent check the registration and use the command line when the tools are not connected.

**Where is my data, and how do I remove it?**
Saved names, comments, notes, code-index and engine caches, symbols and reference packs live under
`%LOCALAPPDATA%\NetDecompilerMcp` on Windows and the local application data folder elsewhere. `uninstall` keeps them;
`uninstall --purge-data` deletes them.

**May I use it on any program?**
Use it on software you own or are permitted to analyze, and follow the license terms and laws that apply to you. See the
README's lawful-use note.
