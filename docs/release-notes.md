# Release notes

## 2.7.1

### Highlights

- Paths in call arguments and inside analyzed files open only files on this machine.
- Outputs are refused in the server's folders, start files, repositories, SSH and agent configuration.
- A worker crash fails only the call that caused it; the others run again.
- Package reviews name every file they did not read, and results report partial coverage.

### Breaking changes

- **Remote paths:** Before: a UNC path, `//host` path or network drive in a call argument was opened. After: refused with `invalid_argument`; `--allow-remote-paths` opens them again. [45a64473](https://github.com/Albasha0x0/Corvus/commit/45a64473)
- **Outputs:** Before: `outputPath=~/.ssh/x.dll` or an output in a `.git` folder was written. After: refused with `invalid_argument` naming the place. [d0495a18](https://github.com/Albasha0x0/Corvus/commit/d0495a18)
- **corvus.json:** Before: program, library and URL locators applied from any readable file. After: only from a file no other account can write; `CORVUS_REPO` is refused. [6fd22914](https://github.com/Albasha0x0/Corvus/commit/6fd22914)

### Changes

- **Native:** capa runs on a private copy of its input and requires capa 10. [f181d9b1](https://github.com/Albasha0x0/Corvus/commit/f181d9b1)
- **Native:** `load_pdb server=` accepts only configured symbol servers. [089d10b5](https://github.com/Albasha0x0/Corvus/commit/089d10b5)
- **Web:** `summarize_file view=package` lists files not read in `partial`; scan tools report coverage `unknown` unless complete. [c7f0e455](https://github.com/Albasha0x0/Corvus/commit/c7f0e455)
- **Recipes:** the Velociraptor recipe defaults to `C:\Program Files\Corvus\corvus.exe`, a folder only administrators can write. [7ff62c9a](https://github.com/Albasha0x0/Corvus/commit/7ff62c9a)

### Fixes

- **Session:** an evidence bundle re-runs read-only tools only. [34e90c5c](https://github.com/Albasha0x0/Corvus/commit/34e90c5c)
- **Session:** tag characters, variation selectors and unpaired surrogates are escaped in text and structured results. [65958ea6](https://github.com/Albasha0x0/Corvus/commit/65958ea6)
- **Mobile:** values passed to the device shell through adb are quoted. [2aff380a](https://github.com/Albasha0x0/Corvus/commit/2aff380a)
- **Engines:** programs are never started from the current folder. [5c1eccbf](https://github.com/Albasha0x0/Corvus/commit/5c1eccbf)
- **Engines:** a worker crash no longer fails the calls running beside it. [6b9ce07c](https://github.com/Albasha0x0/Corvus/commit/6b9ce07c)
- **Engines:** an external tool stopped at its limit leaves nothing in the temporary folder. [6f670613](https://github.com/Albasha0x0/Corvus/commit/6f670613)
- **Native:** paths named inside an analyzed file are reported "not opened" when remote or a device. [089d10b5](https://github.com/Albasha0x0/Corvus/commit/089d10b5)
- **Web:** package and config readers match file text in linear time. [22d8d6c5](https://github.com/Albasha0x0/Corvus/commit/22d8d6c5)
- **Containers:** `export_project` keeps input names out of project markup and paths. [8cf016a2](https://github.com/Albasha0x0/Corvus/commit/8cf016a2)
- **Native:** generated C headers escape input names in comments and strings. [2fd9c804](https://github.com/Albasha0x0/Corvus/commit/2fd9c804)

### In progress

- Name a job memory limit when Windows sends no limit notice.
- Set stop points and coverage on methods compiled before the JIT hook is in place.

## 2.7.0

### Highlights

- Live sessions on Android devices, Node and Electron (V8 inspector), JVMs (JDWP) and TTD recordings.
- Read LevelDB, LMDB, ESE, Berkeley DB and Realm databases, registry hives and event logs, deleted records included.
- Open Apple disk images, HFS+ and APFS volumes, Linux and HarmonyOS packages, ESP32 flash and model files.
- Emulate x86, x64 and ARM64 code without Ghidra.

### Breaking changes

Renamed, no aliases. [e6999955](https://github.com/Albasha0x0/Corvus/commit/e6999955)

- **Tools:** Before: `unity_overview`, `get_il2cpp_info`, `export_il2cpp_symbols`, `apply_il2cpp_names`. After: `summarize_build`, `get_method_addresses`, `export_method_symbols`, `apply_metadata_names`.
- **Parameters:** Before: `oldIl2Cpp`, `newIl2Cpp`. After: `oldMetadata`, `newMetadata`.
- **Name source and layer:** Before: `il2cpp`. After: `metadata`.
- **update_to_new_build:** Before: `il2cpp_names`, `il2cpp_mapping`. After: `metadata_names`, `method_mapping`.
- **Kinds and topics:** Before: frame, backend, session and toolset kind `il2cpp`; guide topic `il2cpp`. After: `aot`.
- **Views and formats:** Before: `summarize_file view=unity`, `symbolize_stack_text format=unity`. After: `view=assets`, `format=mono`.
- **Reasons:** Before: `not_a_unity_build`, `no_il2cpp_metadata`, `new_has_own_il2cpp_names`. After: `not_a_build`, `no_metadata`, `new_has_own_metadata_names`.
- **JSON fields:** Before: `il2Cpp`, `il2CppAddressedMethods`, `il2CppDummy`, `il2CppMapping`. After: `address`, `addressedMethods`, `dummy`, `methodMapping`.
- **Other values:** Before: `style=il2cpp`, type ids `il2cpp:`, container kind `unitywebdata`, batch step `unity`. After: `style=aot`, `metadata:`, `webdata`, `build`.
- **Setting:** Before: `CORVUS_IL2CPP_CACHE`. After: `CORVUS_AOT_CACHE`. [e6999955](https://github.com/Albasha0x0/Corvus/commit/e6999955)

### Changes

- **Live:** `live_session` opens Android devices through frida-server, `inspector:PORT`, `jdwp:PORT` and `ttd:PATH` (Android tested on an x86_64 emulator only). [ff3515e0](https://github.com/Albasha0x0/Corvus/commit/ff3515e0)
- **Emulation:** `emulate_native engine=ours` runs integer code in process; `auto` picks it without Ghidra. [30b900f3](https://github.com/Albasha0x0/Corvus/commit/30b900f3)
- **Process:** `inspect_process view=windows` lists a program's window tree. [62831bdf](https://github.com/Albasha0x0/Corvus/commit/62831bdf)
- **Dart:** Dart 3.0 to 3.13 and Flutter 3.10 to 3.47 AOT images are named, compressed pointers included. [5c4f08e8](https://github.com/Albasha0x0/Corvus/commit/5c4f08e8)
- **Native:** ELF MiniDebugInfo names, Mach-O code requirements, raw m68k code and iNES ROMs. [0a1ebcd1](https://github.com/Albasha0x0/Corvus/commit/0a1ebcd1)
- **Engines:** `decompile_native engine=all` returns IDA's and Ghidra's output in one call. [26247645](https://github.com/Albasha0x0/Corvus/commit/26247645)
- **Files:** `summarize_file` reads databases, registry hives, event logs, Process Monitor captures, certificates and model files. [9f3713ac](https://github.com/Albasha0x0/Corvus/commit/9f3713ac)
- **Containers:** Apple disk images, APFS, rpm, AppImage, snap, Unreal pak, Lua bytecode, Qt resources, SWF and ESP32 flash. [f7e891b8](https://github.com/Albasha0x0/Corvus/commit/f7e891b8)
- **Web:** `analyze_js` adds `beautify`, `react`, `jsx` and `flight` views; `view=wasm` shows a component's WIT world. [d27cda83](https://github.com/Albasha0x0/Corvus/commit/d27cda83)
- **Setup:** seven more MCP clients; `corvus.json` sets `CORVUS_` variables. [8da13d49](https://github.com/Albasha0x0/Corvus/commit/8da13d49)
- **Release:** container image on ghcr.io and the docs as a static site. [ff515342](https://github.com/Albasha0x0/Corvus/commit/ff515342)
- **Upgrade:** compiled metadata builds are read again once; the `il2cpp` folder in the data folder can be deleted. [e6999955](https://github.com/Albasha0x0/Corvus/commit/e6999955)

### Fixes

- **Engines:** a worker connection dropped under load no longer ends the server. [42fb7d84](https://github.com/Albasha0x0/Corvus/commit/42fb7d84)
- **Native:** `resolve_address` works while the code index builds. [0a3a2f27](https://github.com/Albasha0x0/Corvus/commit/0a3a2f27)
- **NativeAOT:** no false dispatch cells in win-x86 builds. [eaeb4649](https://github.com/Albasha0x0/Corvus/commit/eaeb4649)
- **Containers:** 64-bit NSIS installers and embedded Godot 3 packs open. [b0ba843e](https://github.com/Albasha0x0/Corvus/commit/b0ba843e)
- **Web:** source map positions in later sections resolve correctly. [57422e53](https://github.com/Albasha0x0/Corvus/commit/57422e53)
- **Status:** `server_status` stays within its size budget. [30b900f3](https://github.com/Albasha0x0/Corvus/commit/30b900f3)

### In progress

- Android arm64 devices and AOT-compiled managed code on a device.
- Browser page sessions over the Chrome DevTools Protocol.
- ARM64 emulation checked against hardware.

## 2.6.0

### Highlights

- Recover settings kept in serialized assets: typed URLs, hosts, keys and encoded values.
- Check a package before install: offline provenance, GuardDog rules and what a source folder runs.
- Scan a running program's memory with YARA rules and export findings as a STIX 2.1 bundle.

### Breaking changes

- **unity_overview, extract_strings:** an input with no build is refused with reason `not_a_unity_build`; `extract_strings` answers `unsupported`. Before: `unity_overview path=<folder>` → `unsupported`, `details.reason: not_a_unity_title`; `extract_strings` → `invalid_argument`. After: `unsupported`, `details.reason: not_a_unity_build`. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)

### Changes

- **License:** Apache License 2.0. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **IDA:** `CORVUS_IDA_CONNECT=1` reads and edits a database open in IDA 9 or newer that runs `corvus_connect.py`; Corvus never saves or closes it. [076cade3](https://github.com/Albasha0x0/Corvus/commit/076cade3)
- **Assets:** `extract_strings` reads serialized files, bundles and text assets; `summarize_file view=unity` shows script fields; a whole base64 or hex value is an `encoded` row. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Engines:** `compare_native_images engine=ida|ghidra` names each differing range: patch, fixup, relocation, zero fill or unknown (PE and ELF). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **YARA and STIX:** `live_read rules=` scans a session's writable memory; pinned rule packs are verified; findings export as STIX 2.1. [814968d7](https://github.com/Albasha0x0/Corvus/commit/814968d7)
- **Emulation:** `emulate_native engine=speakeasy` runs a whole PE with Windows API emulation. [97d330b8](https://github.com/Albasha0x0/Corvus/commit/97d330b8)
- **Package review:** `summarize_file` names what a source folder runs on open, checkout or build; GuardDog 3.2.0 (`CORVUS_GUARDDOG` or PATH) matches join the review on Linux and macOS; Sigstore, npm and PyPI provenance is checked offline. [86d3eb43](https://github.com/Albasha0x0/Corvus/commit/86d3eb43)
- **Upgrade:** saved native indexes are rebuilt once (format 18); cached dummy assemblies are read again once. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)

### Fixes

- **Assets:** script fields read from metadata without the binary are unknown with a reason, not empty. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Ghidra:** inferred indirect-call arguments carry `derived=true`, since decompiler processes can differ. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Status:** `server_status` stays within its budget with all engines installed; rule setup no longer counts against the 2 s capability survey. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **ELF:** MIPS64 relocations read their symbol and type correctly. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Recipes:** the GuardDog recipe fetches sdists by URL, since `pip download` runs an sdist's build backend. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Engines:** a killed worker's process tree is awaited; a Windows worker ends at its job memory limit; a held Ghidra project opens as a snapshot. [cc731176](https://github.com/Albasha0x0/Corvus/commit/cc731176)

## 2.5.1

### Breaking changes

None.

### Fixes

- **Native imports:** kernel-mode forwarders that name the kernel without an extension bind to `ntoskrnl.exe`. [a2a29687](https://github.com/Albasha0x0/Corvus/commit/a2a29687)
- **Native code:** an address in a block before its function's entry reads `name-0xB`, not `name+0xFFFFFFF5`. [b6468771](https://github.com/Albasha0x0/Corvus/commit/b6468771)

## 2.5.0

### Highlights

- Stop at a .NET method's first call by `Ns.Type::Method` and read its managed frames in a session, 32-bit programs included.
- Open sessions and save snapshots on macOS and Windows ARM64, and read macOS core dumps.
- List and extract installers and frozen Python programs, and write a CycloneDX SBOM with advisories checked offline.

### Breaking changes

- **live_watch:** a watch in a module not loaded yet is set as a deferred row; rows have `state`, and `address`, `prototype` and `decoding` can be null. Before: `live_watch session=live-1 action=set where=late.dll!Run` → `not_found`. After: the same call → `{"id":"w2","where":"late.dll!Run","address":null,"state":"deferred"}`. [82569e67](https://github.com/Albasha0x0/Corvus/commit/82569e67)
- **save_assembly, save_native:** `overwrite=true` no longer replaces the loaded file. Before: `save_assembly assembly=app.dll outputPath=<path of app.dll> overwrite=true`. After: `save_assembly assembly=app.dll replaceOriginal=true` (server started with `--allow-replace-original`). [1899d87a](https://github.com/Albasha0x0/Corvus/commit/1899d87a)
- **live_session:** attaching needs `--allow-live-attach`; `--allow-live` alone lists processes. Before: server `--allow-live`, then `live_session action=attach process=1234`. After: server `--allow-live-attach`, then the same call. [e63e805a](https://github.com/Albasha0x0/Corvus/commit/e63e805a)
- **live_read:** registers come only when asked; the result pages as bytes (`offset`, `nextOffset`). Before: `live_read session=live-1 memory=rsp` → registers and memory. After: `live_read session=live-1 memory=rsp registers=all` → the same; without `registers=` only memory. [9e871e40](https://github.com/Albasha0x0/Corvus/commit/9e871e40)
- **Frida:** Frida older than 17.0 is refused with `provider_unavailable`; outside 17.24.3 to 17.x a session opens with an error event. Before: any Frida with Python bindings started a session. After: `python -m pip install "frida>=17.24.3,<18"`, or start the server with `--live-install-frida`. [52679133](https://github.com/Albasha0x0/Corvus/commit/52679133)
- **File tools:** `summarize_file`, `list_assemblies path=`, `unpack_container`, `search_container` and dump reads parse untrusted files in a worker process; no silent fallback. Before: `summarize_file path=app.exe` parsed the file in the server process. After: the same call reads it in a worker; `--in-process-parsing` (`CORVUS_IN_PROCESS_PARSING=1`) restores in-process reads; `CORVUS_WORKER_HOST=0` turns every worker off. [5a6a7ee6](https://github.com/Albasha0x0/Corvus/commit/5a6a7ee6)
- **inspect_process:** a `live-N` id resolves only through its session. Before: `inspect_process process=live-1` after the session closed named whatever process reused the pid. After: the same call answers `not_found`; pass the process id. [eec4b54e](https://github.com/Albasha0x0/Corvus/commit/eec4b54e)

### Changes

- **Stop points:** points defer until a module loads or a method compiles; `name+0xN`; points follow jumps, rebound delay-load pointers and packed DLLs. [82569e67](https://github.com/Albasha0x0/Corvus/commit/82569e67)
- **Sessions, .NET:** stops name JIT and ReadyToRun frames; `live_break` and `live_watch` take `Ns.Type::Method` (.NET 10 x64 on Windows only). [0adca182](https://github.com/Albasha0x0/Corvus/commit/0adca182)
- **Program allow list:** `--live-allow <program or folder>` limits spawn, attach and `live_console` by final path. [e63e805a](https://github.com/Albasha0x0/Corvus/commit/e63e805a)
- **macOS and Windows ARM64:** `live_session` opens on macOS (snapshots through lldb) and Windows ARM64; macOS lacks child processes, .NET stops, `live_timeline` and `live_console`. [048992fe](https://github.com/Albasha0x0/Corvus/commit/048992fe)
- **Installers and Python programs:** NSIS, Inno Setup (5.5.0 to 7.1), WiX Burn, Squirrel and ClickOnce list and extract; PyInstaller, py2exe, cx_Freeze and Nuitka onefile list; `view=python` disassembles `.pyc` 2.7 to 3.14. [72efd8e5](https://github.com/Albasha0x0/Corvus/commit/72efd8e5)
- **Advisories:** `summarize_file view=dependencies` lists shipped components; `sbomPath` writes a CycloneDX 1.6 SBOM; osv-scanner 2 or newer (`CORVUS_OSV_SCANNER` or PATH) runs `--offline`. [b210a387](https://github.com/Albasha0x0/Corvus/commit/b210a387)
- **YARA rules:** `search_container kind=yara` runs YARA-X 1.22.0 rules on files, container members and dumps in a worker process; glibc 2.34 or newer; refused on musl. [f398695f](https://github.com/Albasha0x0/Corvus/commit/f398695f)
- **Upgrade:** the native code index is rebuilt once (format 17); builds read by the built-in metadata reader and cached `bucket_minidumps` signatures are read again once. [2a6b25dd](https://github.com/Albasha0x0/Corvus/commit/2a6b25dd)

### Fixes

- **Session exits:** a program's exit no longer hangs the session (frida/frida-gum#1192, #1194); a stuck exit is ended after 10 s. [73646c40](https://github.com/Albasha0x0/Corvus/commit/73646c40)
- **Coverage:** points count hits in the program, are set and cleared in batches of 256, and skip CET stubs; methods a run never read are unknown (`?`), not "not run". [0b3428ab](https://github.com/Albasha0x0/Corvus/commit/0b3428ab)
- **Session results:** pages no longer skip or double-count rows; `resultSha256` leaves out workspace notices. [df9d008f](https://github.com/Albasha0x0/Corvus/commit/df9d008f)
- **Dump stacks:** x86 walks pass hooked threads; scanned return address copies are not extra frames; a frame without a method start reads "(offset unknown)" (microsoft/clrmd#1520). [a029d53a](https://github.com/Albasha0x0/Corvus/commit/a029d53a)
- **Section reads:** whole-section readers stop at the file bytes, so damaged headers no longer cause huge scans. [c27ce974](https://github.com/Albasha0x0/Corvus/commit/c27ce974)
- **Shared records:** a second save over the original replaces this server's earlier save. [aeeb5026](https://github.com/Albasha0x0/Corvus/commit/aeeb5026)
- **Session opens on Linux:** no longer hang under load (frida/frida-gum#1196); a program in vfork is refused after 10 s. [e7c1a1b5](https://github.com/Albasha0x0/Corvus/commit/e7c1a1b5)
- **Session memory:** `live_read` reads addresses in an image's preferred range where the program has them. [c6bce07b](https://github.com/Albasha0x0/Corvus/commit/c6bce07b)

## 2.4.0

### Highlights

- Open a session on a local program: stop points, call recording, coverage, event traces, console control and snapshots.
- Read Office documents, PDFs, shortcuts, scripts and packages before opening or installing them.
- Read JavaScript and Electron apps: endpoints, secrets, data flow, bridge methods and Hermes bytecode.

### Breaking changes

- **inspect_instruction:** the walk pages as a list; `offset` counts rows.
- **get_native_type, resolve_call_targets:** records leave out false, zero and empty fields. Before: every field present. After: absent fields mean false, zero or empty.
- **load_assembly, reload_assembly, unload_assembly, add_search_directory:** return typed records. Before: a copy of the text. After: typed records.
- **Notes:** note files are written as `corvus-notes/3`. Before: `corvus-notes/2`. After: `corvus-notes/3`; version 2 still reads.

### Changes

- **Sessions:** nine `live_*` tools, off by default: `--allow-live`, `--allow-live-spawn` to start programs, `--live-scripting` for user scripts; snapshots save as standard dumps.
- **Scripts and packages:** `view=script` decodes PowerShell, VBScript, batch and JavaScript layers without running them; `view=package` reviews npm, PyPI, VS Code and browser extension packages.
- **Installers and firmware:** cabinets, Windows Installer, ISO 9660, UDF, VHD, VHDX, MBR / GPT, NTFS, squashfs, cramfs, ext2/3/4, FAT, JFFS2, UBI / UBIFS and TRX images open.
- **Captures:** pcap TCP reassembly and HTTP objects, TLS 1.2 / 1.3 with a key log, JA3 / JA4; `search_container kind=request` pages HAR, mitmproxy and `.saz`.
- **JavaScript and Electron:** `kind=electron`, `kind=feature`; `analyze_js` adds `endpoints`, `secrets`, `diff`, `runtime`, `flow` and `origins`; Hermes bytecode 59-96.
- **Engines:** Ghidra 12.0 support; `ghidra_script` in Python through PyGhidra (`CORVUS_GHIDRA_PYTHON`).
- **Large inputs:** APK, IPA, plist, mitmproxy, WebAssembly and native images over 64 MiB read as streams.
- **Upgrade:** the native code index is rebuilt once (format 16).

### Fixes

- **save_assembly:** a ReadyToRun image without header room for a new section is written as IL only, and says so.
- **CLI:** reads and writes UTF-8 when redirected.
- **Engines:** `engine=auto` answers from the built-in index when another session holds the saved analysis.
- **Update:** `corvus update` on Linux and macOS keeps the running version; after updating from 2.3.0 or older run `corvus install --refresh-only` once.

## 2.3.0

### Highlights

- Compare kept results without running anything again; what a side does not show is `unknown`.
- Edit struct layouts, argument storage and flow overrides in IDA and Ghidra.
- Load DWARF debug info for ELF and Mach-O, and WebAssembly modules as native images.

### Breaking changes

None.

### Changes

- **Comparisons:** `compare_assemblies`, `compare_native_images`, `compare_folders` and `diff_function` take `oldResult` / `newResult`.
- **Completeness:** function results name each facet as available or unavailable; truncated records have coverage `partial`.
- **Engine databases:** `load_assembly` opens a Ghidra project (`.gpr`) from a copy; import overrides apply before the first analysis.
- **Engine edits:** `declare_native_types` inserts fields; `set_native_local inferStruct=` and `storage=`; `define_native kind=flow` (Ghidra).
- **Debug info:** `load_pdb` reads DWARF 2-5 (sections, `.build-id`, `.gnu_debuglink`, dSYM, debuginfod on request).
- **WebAssembly:** `.wasm` loads as a native image; `summarize_file view=wasm` validates; `compare_native_images` compares builds.
- **Network:** `search_container kind=packet` with Wireshark display filters; `kind=endpoint` joins code endpoints with a capture; `view=protobuf`.
- **Upgrade:** engine output stored by 2.2.0 is computed again once.

## 2.2.0

### Highlights

- Every input schema fits the strictest model gateways.
- Read pcap captures, SQLite databases, Dart AOT snapshots and Rust dependency lists.
- Bundle kept results as evidence and verify them later.

### Breaking changes

None.

### Changes

- **Prompts:** `investigate_feature` and `check_reimplementation`.
- **Model gateways:** no `$ref` or combinators, one type, depth ≤ 10; `corvus status` names any tool outside the subset.
- **Untrusted content:** results that may quote the analyzed file carry `untrustedContent: true` and `source: analysis_target`.
- **Long engine opens:** an open past the deadline answers with `details.stage` and `details.seconds`; calling again resumes it.
- **Captures:** `summarize_file view=pcap`; `search_container kind=endpoint` reads pcap and `.saz`.
- **Crash dumps:** `open_minidump`, `dump_stack`, `read_dump_memory` and `bucket_minidumps` read ELF core files.
- **Formats:** `summarize_file` views `sqlite`, `flutter` and `rust`; `get_pe_info` reports ELF CET, BTI and PAC.
- **Evidence:** `read_result format=evidence` bundles results; `format=verify` reruns them and names changes.

## 2.1.0

### Highlights

- Load headerless code with `load_assembly format=raw`.
- Read JavaScript bundles and source maps with `analyze_js`.
- Open tar, 7z, RAR, xar and cpio archives, and Apple app bundles.

### Breaking changes

None.

### Changes

- **Raw images:** `format=raw arch= base= entry=`; x86, x64, ARM, Thumb, ARM64 built in, other processors through IDA and Ghidra; DOS `.COM` and MZ.
- **JavaScript:** `analyze_js` (new tool, `web` toolset) maps minified positions to source and lists bundle modules.
- **Electron:** `search_container kind=electron` lists preloads, contextBridge keys and IPC channels; `compare_folders` compares `.asar`.
- **Captures:** `search_container kind=endpoint` gives request templates.
- **Archives:** tar, 7z, RAR, gzip, bzip2, xz, xar and cpio open as containers with archive bomb limits; `view=wasm`, `view=firmware`.
- **Apple:** `summarize_file view=apple`, `plist` and `nib`; `verify_native_imports` resolves Mach-O load commands.
- **Ghidra:** `.gzf` archives load; `reanalyze_native background=true preset=`; `decompile_native view=pcode`.

### Fixes

- **server_status:** no longer walks the engine cache on every call.
- **Reference packs:** downloads time out instead of stalling.

## 2.0.2

### Breaking changes

None.

### Changes

- **Distribution:** first release on nuget.org and in the MCP Registry; metadata names the maintainer as Albasha0x0.

## 2.0.1

### Breaking changes

None.

### Changes

- **Security:** built with .NET SDK 10.0.402 (runtime and `System.Security.Cryptography.Pkcs` 10.0.13; CVE-2026-84008, CVE-2026-70162); framework-dependent installs need runtime 10.0.13.
- **Distribution:** `dotnet tool install -g CorvusRE` or `dnx CorvusRE --yes`; MCP Registry name `io.github.Albasha0x0/corvus`.
- **Release assets:** ship under the `corvus` name only.

### Fixes

- **Notices:** many abandoned edit sessions produce one notice line.

## 2.0.0

### Highlights

- One output contract on every tool: structured record, output schema, list envelope, token budget, `Next:` on errors.
- Edit tools preview by default (`dryRun=true`); applied edits get stable ids and undo in IDA and Ghidra too.
- Engine output is cached across processes; repeated decompiles answer in milliseconds.

### Breaking changes

- **Edits:** every .NET and native edit tool and `migrate_native_names` default to `dryRun=true`. Before: edits applied at once. After: pass `dryRun=false` to apply.
- **Removed tools:** `decompile_type`, `decompile_assembly_attributes`, `find_overrides`. Before: `decompile_type`; `decompile_assembly_attributes`; `find_overrides`. After: `decompile_member` with the type; `get_attributes format=csharp`; `find_references kind=overrides`.
- **Renamed parameters (no aliases):** before → after.
  - `maxChars` → `maxTokens` on every tool with a size limit.
  - `find_call_paths`: `maxPaths` → `limit` (with `offset`).
  - `diff_function`: `maxLines` → `offset`, `limit`, `maxTokens`.
  - `inspect_instruction`: `count` → `limit`.
  - `ida_python`: `maxOutput`, `file` → `maxTokens`, `scriptPath`.
  - `ghidra_script`: `timeout` → `timeoutSeconds`.
  - `find_virtual_calls`, `emulate_native`, `reanalyze_native`: `seconds` → `timeoutSeconds`.
  - `search_decompiled`: `cursor`, `seconds` → `offset`, `timeoutSeconds`.
  - `search_instructions`, `reanalyze_native`: `start`, `end` → `from`, `to`.
  - `list_imports`: `module` → `library`.
  - `load_pdb`: `force` → `allowMismatch`.
  - `patch_bytes`, `patch_asm`: `force` → `allowUnsafe`.
  - `export_engine_database`: `force` → `overwrite`.
  - `get_resource`, `get_android_resource`: `savePath` → `outputPath`.
  - `export_edits`, `save_session`: `path` → `outputPath` (parameter and record).
  - `undo_native_edit`: `number` → `editId`.
- **Booleans inverted to default false (omitting them behaves as before):** before → after.
  - `apply_edits`: `stopOnError=true` → `continueOnError=false`.
  - `compare_assemblies`: `listAddedRemovedTypes=true` → `typeCountsOnly=false`.
  - `decompile_java`: `smaliFallback=true` → `javaOnly=false`.
  - `disassemble`: `function=true` → `fromAddress=false`.
  - `dump_stack`: `exceptionContext=true` → `dumpTimeContext=false`.
  - `install_android_package`: `replace=true` → `keepInstalled=false`.
  - `read_dump_memory`: `imageFallback=true` → `dumpOnly=false`.
  - `trace_native_values`: `followGlobals=true` → `stopAtGlobals=false`.
  - `unpack_container`: `load=true` → `extractOnly=false`.
  - `comment_native`: `dedupe=true` → `repeatLine=false`.
  - `find_call_paths`: `includeVirtual=true` → `directOnly=false`.
  - `find_references`: `includeVirtualCalls=true` → `directOnly=false`.
  - `list_types`: `includeNested=true` → `topLevelOnly=false`.
  - `migrate_native_names`: `comments=true` → `namesOnly=false`.
  - Build tools: `useNames=true` → `codeOnly=false`.
- **New false defaults:** `set_native_type` `rename` defaults to false; `get_native_frame` needs `locals=true` for decompiler locals.
- **Lists take arrays:** note tags, `compare_folders exclude`, `extract_strings types`, `simplify_methods passes`, `compare_assemblies changes`, `migrate_native_names sources`, `search_code_pattern images`, `update_to_new_build include`, `oldIl2Cpp`, `newIl2Cpp`. Before: a separated string. After: an array.
- **Paging:** `offset` counts rows, nodes, blocks or bytes, never characters; `truncated` is removed. Before: `offset` in characters; `truncated`. After: continue with `nextOffset`; `hasMore` and `totalExact` say whether more exists.
- **Records:** row arrays are named `items`; many fields renamed or dropped; full schemas in [docs/schemas](schemas/). Before: the text part held the record's JSON. After: text is readable rows; `CORVUS_RESULT_MODE=json` restores a JSON copy.
- **Edit ids:** .NET edits are `<assembly>#<n>`, native edits `<image>#<n>`, stable across undo. Before: undo renumbered the remaining edits. After: `undo_edit` and `diff_edits` take the id in `number`; `undo_native_edit` takes `editId` (`image#n`, `#n`, `n` or a comma list).
- **compare_assemblies:** read-only; `tokenMapPath` and `overwrite` removed. Before: `tokenMapPath=<file>`. After: `tokenMap=true` returns `tokenMapResultId`; write it with `read_result outputPath=`.
- **extract_strings:** read-only; `savePath`, `format` and `overwrite` removed. Before: `savePath=<file>`. After: `read_result id=<valuesResultId> outputPath=<file>`.
- **apply_edits:** a rolled-back script is an error. Before: success. After: code `failed` with per-edit items in `partial`.
- **open_minidump, inspect_process:** per-section offset/limit pairs removed. Before: `modulesOffset`, `threadsLimit`, `sections`. After: `view=` with `offset` and `limit` (50).
- **Undecoded architectures:** code tools on MIPS, PowerPC, RISC-V and s390x refuse. Before: success with 0 rows. After: `unsupported` with `details.reason=instructions-not-decoded`.
- **unpack_container:** data that is not a container is refused. Before: success with no files. After: `unsupported`.
- **read_android_log:** `maxBytes` removed. Before: `maxBytes`. After: `buffer`, `offset` (lines back from the newest), `limit`.
- **map_java_dotnet, pull_android_file:** error codes changed. Before: `not_found` for an AOT package; `failed` for a missing remote file. After: `unsupported` (`details.reason=il2cpp`); `not_found`.
- **Note files:** format `corvus-notes/2`. Before: format 1. After: format 2; format 1 still reads.
- **Input schemas:** optional parameters have no `null` in `type`; booleans and `offset` no longer declare defaults. Before: `["string","null"]`. After: `"string"`; a null sent anyway counts as omitted.

### Changes

- **.NET read:** `decompile_member` decompiles whole types; `get_type_info` returns one `items` array with `section`; `get_assembly_info view=`.
- **.NET edits:** all 15 edit tools return records; `revert_edits` returns a `resultId` with the discarded edits; `simplify_methods passes` takes `fold`, `cfg`, `inline`.
- **Engines:** `engine=auto` picks IDA, then Ghidra, if it analyzed these bytes, else ours; `engine=ours` on engine-only tools is `invalid_argument`.
- **Errors:** always carry a `Next:` line; oversized errors keep the whole error under `details.resultId`.
- **Profiles:** `--toolsets core` (at most 100 tools) and `lean` (at most 40); clients that cap tool counts get `lean`.
- **Output budget:** set by the client profile (`--client`, `CORVUS_CLIENT`, `CORVUS_MAX_OUTPUT_TOKENS`); a call answers 5 s before the client's limit.
- **Results:** `read_result` ids are content ids (`r-` + 12 hex) kept 7 days (`CORVUS_RESULT_CACHE`, `_MB`, `_DAYS`).
- **Upgrade:** code index format 14; older indexes are rebuilt on first use.

## 1.3.0

### Highlights

- Find look-alike functions across loaded images with `find_similar_functions`.
- Run a function in Ghidra's p-code emulator with `emulate_native`.
- Read Electron, Objective-C, Swift and Go metadata.

### Breaking changes

- **Busy server:** leftover calls are capped (`CORVUS_MAX_LEFTOVER_CALLS`, default 2). Before: no cap. After: a new call at the cap is `provider_unavailable` with `retryAfterMs`.
- **Errors:** save tools report only IO faults as `io_error`; other faults are `internal`. Before: any save fault was `io_error`. After: `internal` with a Next; `decompile_java` without JADX or Java is not retryable (`not_configured`).
- **rename_symbol:** keeps a generic type's arity suffix. Before: a different arity was accepted. After: refused.
- **set_native_local (Ghidra):** a rename that did not take effect fails. Before: reported success. After: an error.

### Changes

- **Search:** `find_similar_functions` ranks look-alike functions and reports duplicate groups and clusters; `compare_folders` compares folders or zip-family archives by SHA-256, with moves and renames.
- **Emulation:** `emulate_native` runs a function or range with a private stack, call stubs and budgets.
- **update_to_new_build:** takes two .NET assemblies.
- **Busy server:** a lock timeout names the holders (`details.blockedBy`); `server_status` no longer takes the lock.
- **Electron and containers:** ASAR archives with integrity checks; `summarize_file` reports versions, fuses and `webPreferences`; WebGL data files and HAR / mitmproxy captures open as containers.
- **Mach-O and Go:** Objective-C and Swift metadata with a Swift demangler; build info, function sizes and noreturn runtime functions for PE, ELF and Mach-O.
- **Operations:** engine database cache bounded (`CORVUS_ANALYSIS_CACHE_MB` / `_DAYS`); `CORVUS_LOG_FORMAT=json`; `--trace-args` with secrets masked.
- **Upgrade:** code index format 11 and short IDA cache keys; older entries are rebuilt or migrated.

### Fixes

- **Engines:** workers end within a second of a killed server on Linux and macOS.
- **verify_native_imports:** no longer rebuilds stubs per call or hits dnlib's `LockException`.
- **Inputs:** paths over 259 characters fail up front with their length.
- **Blazor:** a boot manifest that lists none of the present assemblies is `not_found`.

## 1.2.0

### Highlights

- The project is named Corvus.
- Ghidra as a second decompiler engine.
- ELF and Mach-O images, built-in ARM64 and ARM32 / Thumb-2 analysis, and NativeAOT metadata.

### Breaking changes

- **Name:** the program is `corvus`, the MCP key `corvus`, variables `CORVUS_*`, resources `corvus://`. Data, client entries and skills move on first start; files saved earlier still read.
- **Exports:** export and save tools refuse to replace an existing file; links and device names are refused as targets. Before: files were replaced. After: pass `overwrite=true`.
- **save_assembly:** refuses an original that changed on disk since it loaded (`changed_on_disk`).
- **uninstall:** keeps annotations, caches and symbols. Before: removed with the program. After: `--purge-data` removes them.
- **Call deadline:** a tool not marked long-running ends with a timeout after twice `--timeout`; new codes `cancelled`, `changed_on_disk`.
- **Arguments:** closed values are enums checked before the tool runs; `limit < 1` is `invalid_argument` on paged native tools.
- **Native names:** a name on several addresses is an ambiguous error; hex-shaped names resolve as names before numbers.
- **Member labels:** carry generic parameters (`Method<T>(string)`); older edit scripts still resolve.
- **Native patches:** pad with the architecture's NOP; refused where none is defined.
- **IDA:** versions before 9.0 are refused.
- **Inputs:** FIFOs, sockets, devices and directories are refused as input files.

### Changes

- **Ghidra:** `engine=ghidra` on every engine tool; Ghidra 12.0 or newer via `CORVUS_GHIDRA_DIR` and a JDK; saved projects per file hash, with analysis budgets and partial saves that `reanalyze_native` completes; `ghidra_script` behind `--ghidra-scripting`; `export_engine_database` writes `.gzf`, `.h` or `.gdt`.
- **ELF and Mach-O:** load through every native tool, universal files by slice; Itanium demangler, RTTI and exception tables.
- **ARM64 and ARM32:** built-in decoders, function discovery, jump tables, call arguments and value traces.
- **NativeAOT:** `get_nativeaot_info` and a name layer for .NET 7 to 11 (PE, ELF, Mach-O; 32 and 64-bit).
- **AOT metadata:** Android, iOS, macOS and Linux builds from `.apk`, `.xapk`, `.apks`, `.aab` and `.ipa`; metadata up to v39.
- **Android and devices:** manifest, resources, APK signatures v1 to v4; `decompile_java` through JADX; adb read-only by default, install and uninstall behind `--allow-device-changes`.
- **Crash dumps:** managed exceptions, mixed frames, `dump_heap`, `dump_object`; DAC download opt-in; 32-bit dumps on Windows.
- **Setup:** `corvus install` edits client files in place (`--dry-run`, `--json`); `install --skill`; `SHA256SUMS` checked.

### Fixes

- **Reliability:** cross-process locks for annotations and notes; a deadlock between the edit journal and saves fixed.
- **read_bytes:** reports when cut short; bytes without file data show as `??`.
- **Regex searches:** a timeout reports what was not evaluated.

## 1.1.0

### Highlights

- Analyze native PE images: code index, IDA decompiler, PDB, patching, crash dumps and build migration.
- Persistent native code index and imported names across restarts.
- Carry names, patches and comments to a new build with `update_to_new_build`.

### Breaking changes

- **Arguments:** an undeclared parameter is `invalid_argument` with the closest names. Before: ignored; the tool ran with defaults. After: drop extra arguments.
- **load_pdb:** marked destructive; `clear=true` removes imported names and their saved copy.
- **engine=auto:** `list_functions`, `disassemble`, `get_cfg`, `find_xrefs` and `native_call_tree` answer from IDA once it has analyzed the image. Before: the built-in index. After: pass `engine=ours` for the built-in index only.

### Changes

- **Code index:** saved per file SHA-256 (8 GB, 30 days); `--index-cache <dir|off>`, `--index-cache-mb`, `--index-cache-days`.
- **Engines:** `engine=auto|ours|ida`, server default `--engine` / `CORVUS_ENGINE`; every result names its engine.
- **Virtual calls:** MSVC RTTI resolves virtual call edges; `find_virtual_calls`, `crossCheck=true`, `native_call_tree calls=`.
- **AOT metadata:** `load_assembly` reads metadata 24-31 from a build folder, `global-metadata.dat` or a memory dump of GameAssembly.dll.
- **inspect_process:** read-only view of a running local process on Windows; writes and suspends nothing.
- **Patch sites:** `patch_asm` / `patch_bytes extend=true` with `placement=auto|cave|section` and `stubMode=before|after`.
- **update_to_new_build:** carries names, comments, layers, patches and code patterns with one report.
- **Native PE:** own PE parser, x86 / x64 code index, MSVC demangler, RTTI, PDB reader with opt-in symbol download, ReadyToRun code.
