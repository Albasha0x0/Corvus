# Release notes

## 2.7.0

### Highlights

- Live sessions on Android devices, Node and Electron (V8 inspector), JVMs (JDWP) and TTD recordings.
- Read LevelDB, LMDB, ESE, Berkeley DB and Realm databases, registry hives and event logs, deleted records included.
- Open Apple disk images, HFS+ and APFS volumes, Linux and HarmonyOS packages, ESP32 flash and model files.
- Emulate x86, x64 and ARM64 code without Ghidra.

### Breaking changes

Renamed, no aliases. [3a711069](https://github.com/Albasha0x0/Corvus/commit/3a711069)

- **Tools:** Before: `unity_overview`, `get_il2cpp_info`, `export_il2cpp_symbols`, `apply_il2cpp_names`. After: `summarize_build`, `get_method_addresses`, `export_method_symbols`, `apply_metadata_names`.
- **Parameters:** Before: `oldIl2Cpp`, `newIl2Cpp`. After: `oldMetadata`, `newMetadata`.
- **Name source and layer:** Before: `il2cpp`. After: `metadata`.
- **update_to_new_build:** Before: `il2cpp_names`, `il2cpp_mapping`. After: `metadata_names`, `method_mapping`.
- **Kinds and topics:** Before: frame, backend, session and toolset kind `il2cpp`; guide topic `il2cpp`. After: `aot`.
- **Views and formats:** Before: `summarize_file view=unity`, `symbolize_stack_text format=unity`. After: `view=assets`, `format=mono`.
- **Reasons:** Before: `not_a_unity_build`, `no_il2cpp_metadata`, `new_has_own_il2cpp_names`. After: `not_a_build`, `no_metadata`, `new_has_own_metadata_names`.
- **JSON fields:** Before: `il2Cpp`, `il2CppAddressedMethods`, `il2CppDummy`, `il2CppMapping`. After: `address`, `addressedMethods`, `dummy`, `methodMapping`.
- **Other values:** Before: `style=il2cpp`, type ids `il2cpp:`, container kind `unitywebdata`, batch step `unity`. After: `style=aot`, `metadata:`, `webdata`, `build`.
- **Setting:** Before: `CORVUS_IL2CPP_CACHE`. After: `CORVUS_AOT_CACHE`. [a39ce929](https://github.com/Albasha0x0/Corvus/commit/a39ce929)

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
- **Upgrade:** compiled metadata builds are read again once; the `il2cpp` folder in the data folder can be deleted. [a39ce929](https://github.com/Albasha0x0/Corvus/commit/a39ce929)

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

- Recover settings kept in serialized assets: typed URLs, hosts, keys and encoded values, located by file, asset and field.
- Compare a binary's file bytes with IDA's or Ghidra's memory and see what the loader, a fixup or a patch changed.
- Check a package before install: offline provenance, GuardDog rules, what a source folder runs, what an update changes.
- Scan a running program's memory with YARA rules and export findings as a STIX 2.1 bundle.

### Breaking changes

- **unity_overview, extract_strings:** an input with no build is refused with reason `not_a_unity_build`; `extract_strings` answers `unsupported`. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
  - Before: `unity_overview path=<folder>` → `unsupported`, `details.reason: not_a_unity_title`; `extract_strings` → `invalid_argument`.
  - After: `unsupported`, `details.reason: not_a_unity_build`.

### Changes

- **License:** Apache License 2.0. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **IDA:** `CORVUS_IDA_CONNECT=1` reads and edits a database open in IDA 9 or newer that runs `corvus_connect.py` (`corvus ida-script`), without a local install; Corvus never saves or closes it (IDA Pro 9.3 on Windows checked). [076cade3](https://github.com/Albasha0x0/Corvus/commit/076cade3)
- **Dart:** Dart 3.13 AOT images name their code as the `dart` layer; compressed pointers and earlier Dart are reported as not read. [3ebac8c6](https://github.com/Albasha0x0/Corvus/commit/3ebac8c6)
- **Native names:** `migrate_native_names` takes a static library (.lib, .a) or object file (COFF, ELF) as its old side (MSVC x64 CRT, glibc and musl x64 checked). [d7e2d18b](https://github.com/Albasha0x0/Corvus/commit/d7e2d18b)
- **Assets:** `extract_strings` reads serialized files, bundles and JSON, XML and INI text assets; `summarize_file view=unity` shows script fields. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Values:** a whole base64 or hex value is an `encoded` row with its decoded length. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Engines:** `compare_native_images engine=ida|ghidra` names each differing range: patch, fixup, relocation, zero fill or unknown (IDA 9.3, Ghidra 12.1.4; PE and ELF). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Native strings:** Rust literals and Swift small strings are read with their lengths (PE and ELF, x86-64 and ARM64). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Mobile:** DEX string decoder calls show their returned strings in `disassemble_dex`, `search_dex` and `survey_features`. [7663ae6c](https://github.com/Albasha0x0/Corvus/commit/7663ae6c)
- **Capabilities:** capa rule names label PE, ELF and .NET binaries; build comparisons report capabilities added or removed. [34266e8d](https://github.com/Albasha0x0/Corvus/commit/34266e8d)
- **YARA and STIX:** `live_read rules=` scans a session's writable memory; pinned rule packs are verified; findings export as STIX 2.1. [814968d7](https://github.com/Albasha0x0/Corvus/commit/814968d7)
- **Emulation:** `emulate_native engine=speakeasy` runs a whole PE with Windows API emulation. [97d330b8](https://github.com/Albasha0x0/Corvus/commit/97d330b8)
- **Containers:** `extract_strings` reads a container's own assemblies; `batch --file` pages each step to its limit. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Package review:** `summarize_file` names what a source folder runs on open, checkout or build; `compare_folders` leads with a policy line. [86d3eb43](https://github.com/Albasha0x0/Corvus/commit/86d3eb43)
- **Provenance:** Sigstore bundles, npm attestations and PyPI provenance are checked offline; revocation and Ed25519 logs are not checked. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **GuardDog:** GuardDog 3.2.0 (`CORVUS_GUARDDOG` or PATH) matches join the package review; Linux and macOS only. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Comparisons:** with the malcontent rule pack, `compare_assemblies` and `compare_native_images` list behaviours added or removed. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Raw code:** `summarize_file view=raw` names likely instruction sets and load bases of an unknown file. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **.NET:** `get_assembly_info view=transforms` lists transformation layers and the tool identified behind each. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **.NET:** compiled XAML (XBF) reads as XAML. [0bd7ab85](https://github.com/Albasha0x0/Corvus/commit/0bd7ab85)
- **Supply chain:** releases ship with build provenance; reference packs and the dump DAC are verified against their publishers. [82917b7a](https://github.com/Albasha0x0/Corvus/commit/82917b7a)
- **Upgrade:** saved native indexes are rebuilt once (format 18); cached dummy assemblies are read again once (cache format 4). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)

### Fixes

- **Assets:** script fields read from metadata without the binary are reported as unknown with a reason, not empty. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Ghidra:** inferred indirect-call arguments carry `derived=true`, since decompiler processes can differ. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Comparisons:** rule setup no longer counts against the 2 s capability survey budget. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **ELF:** MIPS64 relocations read their symbol and type correctly. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Status:** `server_status` stays within its budget with all engines installed. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
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
- Hold, list and open the child processes a program starts, and read a running .NET program's heap without stopping it.
- List and extract installers and frozen Python programs, and write a CycloneDX SBOM with advisories checked offline.

### Breaking changes

- **live_watch:** a watch in a module not loaded yet is set as a deferred row; rows have `state`, and `address`, `prototype` and `decoding` can be null. [82569e67](https://github.com/Albasha0x0/Corvus/commit/82569e67)
  - Before: `live_watch session=live-1 action=set where=late.dll!Run` → `not_found`
  - After: the same call → `{"id":"w2","where":"late.dll!Run","address":null,"state":"deferred"}`
- **save_assembly, save_native:** `overwrite=true` no longer replaces the loaded file. [1899d87a](https://github.com/Albasha0x0/Corvus/commit/1899d87a)
  - Before: `save_assembly assembly=app.dll outputPath=<path of app.dll> overwrite=true`
  - After: `save_assembly assembly=app.dll replaceOriginal=true` (server started with `--allow-replace-original`)
- **live_session:** attaching needs `--allow-live-attach`; `--allow-live` alone lists processes. [e63e805a](https://github.com/Albasha0x0/Corvus/commit/e63e805a)
  - Before: server `--allow-live`, then `live_session action=attach process=1234`
  - After: server `--allow-live-attach`, then the same call
- **live_read:** registers come only when asked; the result pages as bytes (`offset`, `nextOffset`). [9e871e40](https://github.com/Albasha0x0/Corvus/commit/9e871e40)
  - Before: `live_read session=live-1 memory=rsp` → registers and memory
  - After: `live_read session=live-1 memory=rsp registers=all` → the same; without `registers=` only memory
- **Frida:** Frida older than 17.0 is refused with `provider_unavailable`; outside 17.24.3 to 17.x a session opens with an error event. [52679133](https://github.com/Albasha0x0/Corvus/commit/52679133)
  - Before: any Frida with Python bindings started a session
  - After: `python -m pip install "frida>=17.24.3,<18"`, or start the server with `--live-install-frida`
- **File tools:** `summarize_file`, `list_assemblies path=`, `unpack_container`, `search_container` and dump reads parse untrusted files in a worker process; no silent fallback. [5a6a7ee6](https://github.com/Albasha0x0/Corvus/commit/5a6a7ee6)
  - Before: `summarize_file path=app.exe` parsed the file in the server process
  - After: the same call reads it in a worker; `--in-process-parsing` (`CORVUS_IN_PROCESS_PARSING=1`) restores in-process reads; `CORVUS_WORKER_HOST=0` turns every worker off
- **inspect_process:** a `live-N` id resolves only through its session. [eec4b54e](https://github.com/Albasha0x0/Corvus/commit/eec4b54e)
  - Before: `inspect_process process=live-1` after the session closed named whatever process reused the pid
  - After: the same call answers `not_found`; pass the process id

### Changes

- **Upgrade:** the native code index is rebuilt once (format 17); builds read by the built-in metadata reader and cached `bucket_minidumps` signatures are read again once. [2a6b25dd](https://github.com/Albasha0x0/Corvus/commit/2a6b25dd)
- **Sessions, .NET:** stops name JIT and ReadyToRun frames; `live_break` and `live_watch` take `Ns.Type::Method` (.NET 10 x64 on Windows; not Linux targets). [0adca182](https://github.com/Albasha0x0/Corvus/commit/0adca182)
- **Started .NET programs:** run with `DOTNET_EnableWriteXorExecute=0`; single-file ReadyToRun code takes stop points; a point in a shared view of the code heap is refused. [73daeb57](https://github.com/Albasha0x0/Corvus/commit/73daeb57)
- **live_session:** `environment=["NAME=value"]` adds variables to a minimal set (server variables are not passed on); attach refuses the server and its parent processes. [959be663](https://github.com/Albasha0x0/Corvus/commit/959be663)
- **Sessions, 32-bit .NET:** a 32-bit decoder process reads frames, coverage and heap (.NET Framework 4.8 x86). [7260b18f](https://github.com/Albasha0x0/Corvus/commit/7260b18f)
- **Sessions, single-file and Framework apps:** stop points in bundles and native images; `downloadDac=true` fetches a missing DAC (off by default, refused under `CORVUS_OFFLINE=1`). [a82f007a](https://github.com/Albasha0x0/Corvus/commit/a82f007a)
- **Heap of a running program:** `dump_heap` and `dump_object` take a session id (Windows x64 and x86). [3652cf43](https://github.com/Albasha0x0/Corvus/commit/3652cf43)
- **Child processes:** `childNames` holds matching children at start; `action=children`, `attach_child` and `release_child` list and open them (Windows and Linux). [957d6fb1](https://github.com/Albasha0x0/Corvus/commit/957d6fb1)
- **Child processes on Linux:** a child session closed before its first continue leaves the child held, as on Windows. [f77c615c](https://github.com/Albasha0x0/Corvus/commit/f77c615c)
- **Sandboxed processes:** children under a restricted token or AppContainer load the agent. [cc0c3501](https://github.com/Albasha0x0/Corvus/commit/cc0c3501)
- **Stop points:** points defer until a module loads or a method compiles; `name+0xN`; points follow jumps, rebound delay-load pointers and packed DLLs. [82569e67](https://github.com/Albasha0x0/Corvus/commit/82569e67)
- **Watches:** functions without a prototype record raw values; DWARF prototypes decode System V float and aggregate parameters. [fc8e83d9](https://github.com/Albasha0x0/Corvus/commit/fc8e83d9)
- **live_read:** any address, modules by name, `cstring` / `utf16`, C-style arrays, `registers=all`. [9e871e40](https://github.com/Albasha0x0/Corvus/commit/9e871e40)
- **live_coverage:** waits for late modules, covers managed assemblies, caps at 5,000 functions with narrower suggestions. [096e5567](https://github.com/Albasha0x0/Corvus/commit/096e5567)
- **live_timeline:** leaves out the session's own files and keeps a short program's last events (Windows only). [0b819d2f](https://github.com/Albasha0x0/Corvus/commit/0b819d2f)
- **Session defaults:** `live_coverage`, `live_timeline` and `live_console` without `run` use the only run; `live_events` refuses unknown kinds. [b8b6cd62](https://github.com/Albasha0x0/Corvus/commit/b8b6cd62)
- **macOS and Windows ARM64:** `live_session` opens on macOS (snapshots through lldb) and Windows ARM64; macOS lacks child processes, .NET stops, `live_timeline` and `live_console`. [048992fe](https://github.com/Albasha0x0/Corvus/commit/048992fe)
- **live_events:** call events have their own 10,000-entry ring; pages report what each ring dropped. [60df8c18](https://github.com/Albasha0x0/Corvus/commit/60df8c18)
- **Sessions on Linux:** `file:line` from DWARF, CFI unwinding, exit status; statically linked programs refused (frida/frida#2533); musl attach only. [fda1fd00](https://github.com/Albasha0x0/Corvus/commit/fda1fd00)
- **Snapshots at a stop:** the stop is the dump's exception or the core's signal with the stop's registers. [02a58f2b](https://github.com/Albasha0x0/Corvus/commit/02a58f2b)
- **AOT stacks:** session frames of AOT-compiled managed code are named by method. [ce09a2a9](https://github.com/Albasha0x0/Corvus/commit/ce09a2a9)
- **Program allow list:** `--live-allow <program or folder>` limits spawn, attach and `live_console` by final path. [e63e805a](https://github.com/Albasha0x0/Corvus/commit/e63e805a)
- **Pinned Frida:** `--live-install-frida` (off by default) installs Frida 17.24.3 from hash-checked wheels into a private environment. [0700c27c](https://github.com/Albasha0x0/Corvus/commit/0700c27c)
- **Installers:** NSIS, Inno Setup (5.5.0 to 7.1), WiX Burn, Squirrel and ClickOnce list and extract. [72efd8e5](https://github.com/Albasha0x0/Corvus/commit/72efd8e5)
- **Python programs:** PyInstaller, py2exe, cx_Freeze and Nuitka onefile list; `view=python` disassembles `.pyc` 2.7 to 3.14; `CORVUS_PY_DECOMPILER` adds source. [3b3fdd3a](https://github.com/Albasha0x0/Corvus/commit/3b3fdd3a)
- **Packages:** Godot packs, Flatpak, apk v3, Debian packages, ar libraries, JMOD and WebAssembly components. [4fa10d46](https://github.com/Albasha0x0/Corvus/commit/4fa10d46)
- **Firmware:** permission bits on filesystem entries, carved zips, Sercomm headers, empty UBI volumes. [29131322](https://github.com/Albasha0x0/Corvus/commit/29131322)
- **Captures:** TLS 1.3 early data decrypts; HTTP/1.x request bodies export. [9f2d35ac](https://github.com/Albasha0x0/Corvus/commit/9f2d35ac)
- **Security:** untrusted-file workers share calls; a crash, memory limit or deadline ends the worker, not the server; SECURITY.md lists in-server reads. [69a32b6d](https://github.com/Albasha0x0/Corvus/commit/69a32b6d)
- **Dependencies:** `summarize_file view=dependencies` lists shipped components; `sbomPath` writes a CycloneDX 1.6 SBOM. [b210a387](https://github.com/Albasha0x0/Corvus/commit/b210a387)
- **Advisories:** osv-scanner 2 or newer (`CORVUS_OSV_SCANNER` or PATH) runs `--offline`; Corvus makes no network request. [c58e3b55](https://github.com/Albasha0x0/Corvus/commit/c58e3b55)
- **YARA rules:** `search_container kind=yara` runs YARA-X 1.22.0 rules on files, container members and dumps in a worker process; glibc 2.34 or newer; refused on musl. [f398695f](https://github.com/Albasha0x0/Corvus/commit/f398695f)
- **Region-set dumps:** a JSON manifest of memory region files opens in `open_minidump` and `read_dump_memory`. [97580469](https://github.com/Albasha0x0/Corvus/commit/97580469)
- **macOS and ARM64 dumps:** Mach-O core dumps open; ARM64 minidumps walk past the first frame. [5b9e7ab3](https://github.com/Albasha0x0/Corvus/commit/5b9e7ab3)
- **x86 dump stacks:** walks use PDB frame data and exception context records. [18e8f15b](https://github.com/Albasha0x0/Corvus/commit/18e8f15b)
- **Linux cores of .NET processes:** `dump_heap` and `dump_object` read them (server on Windows only). [65342d36](https://github.com/Albasha0x0/Corvus/commit/65342d36)
- **Dump frames:** single-file runtimes found, Mono frames named, COFF symbols name frames, managed frames walked from the exception context. [d1d5c0f4](https://github.com/Albasha0x0/Corvus/commit/d1d5c0f4)
- **Native:** Delphi and Free Pascal VMTs, MIPS GOT imports, ARM64 exception handlers, Rust crates from panic paths. [551ad882](https://github.com/Albasha0x0/Corvus/commit/551ad882)
- **Metadata:** builds that fill the code registration at run time map their generic method bodies. [c1a2a07e](https://github.com/Albasha0x0/Corvus/commit/c1a2a07e)
- **Engine opens:** IDA saves a partial analysis within a budget; the next open or `reanalyze_native` continues it, nothing unasked. [ea0fb99c](https://github.com/Albasha0x0/Corvus/commit/ea0fb99c)
- **reanalyze_native:** Ghidra's `analyzers=true` lists every analyzer of a reopened program. [4a533d52](https://github.com/Albasha0x0/Corvus/commit/4a533d52)
- **Ghidra time limits:** a stopped worker reports heap and busy threads; dumps go to `ghidra/stalls` or `CORVUS_STALL_DIR`. [08f2735f](https://github.com/Albasha0x0/Corvus/commit/08f2735f)
- **Package review:** `view=package` reads more install-time behaviour. [6c57bdd6](https://github.com/Albasha0x0/Corvus/commit/6c57bdd6)
- **Edits:** every edit carries a content digest; saves list the edits they wrote. [14d22758](https://github.com/Albasha0x0/Corvus/commit/14d22758)
- **Comparisons:** `compare_folders noDiffs=true`; `diff_function` compares a kept result with a loaded image. [1545f272](https://github.com/Albasha0x0/Corvus/commit/1545f272)
- **Catalog:** shorter tool and parameter descriptions. [be75e4c1](https://github.com/Albasha0x0/Corvus/commit/be75e4c1)
- **Batch scans:** `corvus batch --file <path> --json` writes one `corvus.batch/1` document; `--time-limit` (default 120 s, exit 124) and `--rules`. [3ce1d488](https://github.com/Albasha0x0/Corvus/commit/3ce1d488)
- **server_status:** the first call runs its checks in parallel. [b40bcf0a](https://github.com/Albasha0x0/Corvus/commit/b40bcf0a)
- **Generated assemblies:** dummy assemblies and reference stubs are reproducible. [9c73d883](https://github.com/Albasha0x0/Corvus/commit/9c73d883)
- **PDB names on x86:** decorated publics show undecorated, as DbgHelp does; decorated input names resolve. [171f342d](https://github.com/Albasha0x0/Corvus/commit/171f342d)
- **Text output:** control characters in file text are written as `\uXXXX`. [6ae387b8](https://github.com/Albasha0x0/Corvus/commit/6ae387b8)

### Fixes

- **Dump stacks:** x86 walks pass hooked threads; scanned return address copies are not extra frames. [a029d53a](https://github.com/Albasha0x0/Corvus/commit/a029d53a)
- **Engine analysis:** oversized functions report `limit_exceeded`; duplicate RTTI names and rejected file names no longer fail. [ca4c91ec](https://github.com/Albasha0x0/Corvus/commit/ca4c91ec)
- **Engine workers:** exits and crashes name the exit code and stderr; timeouts name the last stage. [1e1c3d5e](https://github.com/Albasha0x0/Corvus/commit/1e1c3d5e)
- **Decompiler failures:** a Hex-Rays failure suggests `engine=ghidra`; a Ghidra crash suggests `engine=ida`. [93f5af6b](https://github.com/Albasha0x0/Corvus/commit/93f5af6b)
- **IDA Python search:** a slow Python version check no longer marks IDA unavailable. [3fc786cb](https://github.com/Albasha0x0/Corvus/commit/3fc786cb)
- **Engine timeouts:** errors name request progress and the worker's last log line. [d055446d](https://github.com/Albasha0x0/Corvus/commit/d055446d)
- **32-bit .NET sessions:** one failed runtime read no longer stops the decoder. [390a88ad](https://github.com/Albasha0x0/Corvus/commit/390a88ad)
- **Linux snapshots:** a program in vfork is refused after 10 s. [6999b5af](https://github.com/Albasha0x0/Corvus/commit/6999b5af)
- **live_coverage:** points count hits in the program, are set in batches of 256, and skip CET stubs. [0b3428ab](https://github.com/Albasha0x0/Corvus/commit/0b3428ab)
- **Managed coverage:** methods a run never read are unknown (`?`), not "not run". [dc2d3ba4](https://github.com/Albasha0x0/Corvus/commit/dc2d3ba4)
- **IDA opens:** fatal errors are named; "Fatal registry error" retries up to twice. [c91989fb](https://github.com/Albasha0x0/Corvus/commit/c91989fb)
- **Snapshots of a starting program:** wait up to 10 s for the loader. [51e5cc1c](https://github.com/Albasha0x0/Corvus/commit/51e5cc1c)
- **Session starts on macOS:** a Frida start timeout is retried once. [ccc4abd8](https://github.com/Albasha0x0/Corvus/commit/ccc4abd8)
- **get_pe_info:** the PDB line waits up to 30 s for the search. [637cb40e](https://github.com/Albasha0x0/Corvus/commit/637cb40e)
- **Workspace shutdown:** closing during background indexing no longer crashes the server. [c79fabb0](https://github.com/Albasha0x0/Corvus/commit/c79fabb0)
- **Pattern matching:** built-in patterns have no match timeout; caller patterns report a timeout as partial. [80ef98c1](https://github.com/Albasha0x0/Corvus/commit/80ef98c1)
- **Long patterns:** wildcard arguments of any length match without a regex. [678a26dc](https://github.com/Albasha0x0/Corvus/commit/678a26dc)
- **External tools:** a version check over 15 s leaves the tool usable with an unknown version. [eaf5e2fe](https://github.com/Albasha0x0/Corvus/commit/eaf5e2fe)
- **PyGhidra workers:** each worker has its own temporary folder (NationalSecurityAgency/ghidra#9988). [ea53b9a0](https://github.com/Albasha0x0/Corvus/commit/ea53b9a0)
- **Managed frames:** a frame without a method start reads "(offset unknown)" (microsoft/clrmd#1520). [7c568d52](https://github.com/Albasha0x0/Corvus/commit/7c568d52)
- **Section reads:** whole-section readers stop at the file bytes, so damaged headers no longer cause huge scans. [c27ce974](https://github.com/Albasha0x0/Corvus/commit/c27ce974)
- **Path arguments:** invalid paths are `invalid_argument` naming the parameter, without echoing the path. [7da411d0](https://github.com/Albasha0x0/Corvus/commit/7da411d0)
- **inspect_process:** process 0 is refused. [4760f864](https://github.com/Albasha0x0/Corvus/commit/4760f864)
- **Shared records:** saves wait up to 30 s for another writer. [a10363c5](https://github.com/Albasha0x0/Corvus/commit/a10363c5)
- **unload_assembly:** closes an open dump id. [cdd47b37](https://github.com/Albasha0x0/Corvus/commit/cdd47b37)
- **save_assembly, save_native:** a second save over the original replaces this server's earlier save. [aeeb5026](https://github.com/Albasha0x0/Corvus/commit/aeeb5026)
- **Paged session results:** pages no longer skip rows cut by the budget. [df9d008f](https://github.com/Albasha0x0/Corvus/commit/df9d008f)
- **Sessions on Windows:** a program's exit no longer hangs the session (frida/frida-gum#1192). [0dde7bac](https://github.com/Albasha0x0/Corvus/commit/0dde7bac)
- **Stuck exits:** a program held in its exit is ended. [ab58b956](https://github.com/Albasha0x0/Corvus/commit/ab58b956)
- **attach_child on Linux:** attaching under load no longer leaves the child running. [f77c615c](https://github.com/Albasha0x0/Corvus/commit/f77c615c)
- **Results:** rows outside `items` are no longer counted twice. [6805b45a](https://github.com/Albasha0x0/Corvus/commit/6805b45a)
- **Session close:** status names why a session closed; a stuck exit is ended after 10 s. [25a8c92e](https://github.com/Albasha0x0/Corvus/commit/25a8c92e)
- **Session exit records:** the last watch batches, exit status and crashes are recorded. [d6887793](https://github.com/Albasha0x0/Corvus/commit/d6887793)
- **Close during an exit:** no longer leaves the exit stuck (frida/frida-gum#1192, #1194). [73646c40](https://github.com/Albasha0x0/Corvus/commit/73646c40)
- **Stops on 32-bit Linux:** the first frame is the stop point's own address. [91daec47](https://github.com/Albasha0x0/Corvus/commit/91daec47)
- **Session opens on Linux:** no longer hang under load (frida/frida-gum#1196). [e7c1a1b5](https://github.com/Albasha0x0/Corvus/commit/e7c1a1b5)
- **Script loads:** `live_script action=load` reports a script's top-level exception. [b452e1c2](https://github.com/Albasha0x0/Corvus/commit/b452e1c2)
- **Session timeouts:** a Frida D-Bus timeout is a retryable `timeout`. [ae992e95](https://github.com/Albasha0x0/Corvus/commit/ae992e95)
- **Session process handles:** a process id that is not a multiple of 4 no longer holds an unrelated process. [b606be33](https://github.com/Albasha0x0/Corvus/commit/b606be33)
- **Session stops:** stop points use probe hooks; overlapping hooks are refused; cleared points release threads. [81b06731](https://github.com/Albasha0x0/Corvus/commit/81b06731)
- **Session frames:** WoW64 system modules, late DLLs and `name-0xN` addresses are named as in snapshots. [9b2cb02a](https://github.com/Albasha0x0/Corvus/commit/9b2cb02a)
- **Containers:** squashfs inodes across blocks, module-info `provides`, smali array data and cache trimming fixed. [cf6152a3](https://github.com/Albasha0x0/Corvus/commit/cf6152a3)
- **server_status:** fits its budget with every tool configured; waits at most 5 s for checks. [f6085507](https://github.com/Albasha0x0/Corvus/commit/f6085507)
- **Result hashes:** `resultSha256` leaves out workspace notices. [b4715960](https://github.com/Albasha0x0/Corvus/commit/b4715960)
- **Kept results:** a folder past its limit is trimmed to 75%. [276b5687](https://github.com/Albasha0x0/Corvus/commit/276b5687)
- **Call log:** URL password masking is linear in the text. [70e4fc70](https://github.com/Albasha0x0/Corvus/commit/70e4fc70)
- **IDA starts:** stopped after 60 s without worker progress. [c72de6da](https://github.com/Albasha0x0/Corvus/commit/c72de6da)
- **Session memory reads:** `live_read` reads addresses in an image's preferred range where the program has them. [c6bce07b](https://github.com/Albasha0x0/Corvus/commit/c6bce07b)
- **Code coverage:** points are cleared in batches of 256, so programs exit sooner. [15da2f05](https://github.com/Albasha0x0/Corvus/commit/15da2f05)
- **Call deadlines:** count from when the request reaches the server. [46dd5e3b](https://github.com/Albasha0x0/Corvus/commit/46dd5e3b)
- **Script readings:** time limits tripled (12 s; 4.5 s overview; 2.25 s per block); 4,000,000-step budget kept. [a10c24d6](https://github.com/Albasha0x0/Corvus/commit/a10c24d6)
- **Worker starts:** Ghidra, pooled workers and Python probes stop on idle CPU time, not wall time. [8a378f59](https://github.com/Albasha0x0/Corvus/commit/8a378f59)
- **server_status tool checks:** JADX, Java and adb checks run in parallel. [cf70a298](https://github.com/Albasha0x0/Corvus/commit/cf70a298)
- **Worker request limits:** a quiet-limit stop is named as such. [5678530f](https://github.com/Albasha0x0/Corvus/commit/5678530f)
- **Frida install:** `--live-install-frida` creates its environment in seconds. [dae54009](https://github.com/Albasha0x0/Corvus/commit/dae54009)
- **Device calls:** adb runs without a prior version check. [5fe21a55](https://github.com/Albasha0x0/Corvus/commit/5fe21a55)
- **Call answers:** finished calls answer without retaking the workspace lock. [42a3440e](https://github.com/Albasha0x0/Corvus/commit/42a3440e)
- **.NET decompiles:** XML doc files are no longer opened (icsharpcode/ILSpy#4275). [22ec63c5](https://github.com/Albasha0x0/Corvus/commit/22ec63c5)
- **Process launches (Windows):** concurrent launches no longer queue. [6ba784e3](https://github.com/Albasha0x0/Corvus/commit/6ba784e3)
- **simplify_methods time limits:** count CPU time (5 s per method, 30 s per type initializer). [aadaf6d6](https://github.com/Albasha0x0/Corvus/commit/aadaf6d6)
- **Virtual call checks:** a slow engine decompilation no longer stops the engine. [a4f6aa25](https://github.com/Albasha0x0/Corvus/commit/a4f6aa25)
- **IDA decompiler licenses:** a missing Hex-Rays decompiler is `unsupported` and suggests `engine=ghidra`. [b5a5c246](https://github.com/Albasha0x0/Corvus/commit/b5a5c246)
- **Session tool details:** early stops kept; exits and missing files named; `live_read` array syntax relaxed. [24c47f48](https://github.com/Albasha0x0/Corvus/commit/24c47f48)
- **Managed names at a stop:** an unreadable .NET runtime is retried every 5 s. [a21afade](https://github.com/Albasha0x0/Corvus/commit/a21afade)

## 2.4.0

### Highlights

- Open a session on a local program: stop points, call recording, coverage, event traces, console control and snapshots.
- Read Office documents, PDFs, shortcuts, scripts and packages before opening or installing them.
- Extract installers, disk images, firmware filesystems and network captures in process on every OS.
- Read JavaScript and Electron apps: endpoints, secrets, data flow, bridge methods and Hermes bytecode.

### Breaking changes

- **inspect_instruction:** the walk pages as a list; `offset` counts rows.
- **get_native_type, resolve_call_targets:** records leave out false, zero and empty fields.
  - Before: every field present.
  - After: absent fields mean false, zero or empty.
- **load_assembly, reload_assembly, unload_assembly, add_search_directory:** return typed records.
  - Before: a copy of the text.
  - After: typed records.
- **Notes:** note files are written as `corvus-notes/3`.
  - Before: `corvus-notes/2`.
  - After: `corvus-notes/3`; version 2 still reads.

### Changes

- **Sessions:** nine `live_*` tools, off by default: `--allow-live`, `--allow-live-spawn` to start programs, `--live-scripting` for user scripts.
- **Sessions:** `live_session`, `live_break`, `live_read`, `live_events`, `live_watch`, `live_coverage`, `live_timeline` (ETW), `live_console`, `live_script`.
- **Sessions:** snapshots save as standard dumps; `inspect_process` takes a session id.
- **Notes:** note evidence links kept results; `update_note verify=true` marks a hypothesis confirmed, refuted or open.
- **Documents:** `summarize_file view=office`, `view=pdf`, `view=lnk` and OneNote embedded files.
- **Installers and disk images:** cabinets, Windows Installer, ISO 9660, UDF, VHD, VHDX, MBR / GPT and NTFS; `view=installer`.
- **Scripts and packages:** `view=script` decodes PowerShell, VBScript, batch and JavaScript layers without running them; `view=package` reviews npm, PyPI, VS Code and browser extension packages.
- **Firmware:** squashfs, cramfs, ext2/3/4, FAT, cpio, JFFS2, UBI / UBIFS, uImage, FIT, Android boot and TRX images extract.
- **Captures:** pcap TCP reassembly and HTTP objects, TLS 1.2 / 1.3 with a key log, JA3 / JA4; `search_container kind=request` pages HAR, mitmproxy and `.saz`.
- **JavaScript and Electron:** `kind=electron`, `kind=feature`; `analyze_js` adds `endpoints`, `secrets`, `diff`, `runtime`, `flow` and `origins`; Hermes bytecode 59-96.
- **Mobile and managed:** `survey_features` lists platform security findings; `view=layers` joins an APK's layers; `decompile_java` applies R8 / ProGuard names; WPF `.baml` handlers.
- **Debug info:** PDB line tables in `resolve_address` and `file:line` stop points; DWARF split units, dwz, Mach-O debug maps, locals in scope.
- **Engines:** Ghidra 12.0 support, `ghidra_script` in Python through PyGhidra (`CORVUS_GHIDRA_PYTHON`), better x86, ARM32 and ARM64 code discovery.
- **Large inputs:** APK, IPA, plist, mitmproxy, WebAssembly and native images over 64 MiB read as streams.
- **List tools:** the 15 list tools that lacked it take `maxTokens`.
- **Upgrade:** the native code index is rebuilt once (format 16).

### Fixes

- **save_assembly:** a ReadyToRun image without header room for a new section is written as IL only, and says so.
- **CLI:** reads and writes UTF-8 when redirected.
- **Engines:** `engine=auto` answers from the built-in index when another session holds the saved analysis.
- **server_status:** no longer walks cache folders on its own time.
- **Update:** `corvus update` on Linux and macOS keeps the running version; after updating from 2.3.0 or older run `corvus install --refresh-only` once.

## 2.3.0

### Highlights

- Compare kept results without running anything again; what a side does not show is `unknown`.
- Edit struct layouts, argument storage and flow overrides in IDA and Ghidra.
- Load DWARF debug info for ELF and Mach-O, and WebAssembly modules as native images.
- Filter captures with Wireshark display filters without TShark.

### Breaking changes

None.

### Changes

- **Comparisons:** `compare_assemblies`, `compare_native_images`, `compare_folders` and `diff_function` take `oldResult` / `newResult`.
- **Completeness:** function results name each facet as available or unavailable; truncated records have coverage `partial`.
- **Engine databases:** `load_assembly` opens a Ghidra project (`.gpr`) from a copy; import overrides apply before the first analysis.
- **Engine edits:** `declare_native_types` inserts fields; `set_native_local inferStruct=` and `storage=`; `define_native kind=flow` (Ghidra).
- **Engine output cache:** renaming a local makes only that function's answers stale.
- **Emulation:** `emulate_native candidates=` runs many argument sets in one request.
- **Debug info:** `load_pdb` reads DWARF 2-5 (sections, `.build-id`, `.gnu_debuglink`, dSYM, debuginfod on request).
- **WebAssembly:** `.wasm` loads as a native image; `summarize_file view=wasm` validates; `compare_native_images` compares builds.
- **Network:** `search_container kind=packet` with Wireshark display filters; `kind=endpoint` joins code endpoints with a capture; `view=protobuf`.
- **Formats:** `get_il source=true`, typed attribute arguments, FieldRVA data, metadata without the binary, `view=sqlite` recovery, `search_bytes` masks.
- **Upgrade:** engine output stored by 2.2.0 is computed again once.

## 2.2.0

### Highlights

- Every input schema fits the strictest model gateways.
- Read pcap captures, SQLite databases, Dart AOT snapshots and Rust dependency lists.
- Read Linux and Android ELF core dumps.
- Bundle kept results as evidence and verify them later.

### Breaking changes

None.

### Changes

- **Prompts:** `investigate_feature` and `check_reimplementation`.
- **Model gateways:** no `$ref` or combinators, one type, depth ≤ 10; `corvus status` names any tool outside the subset.
- **Untrusted content:** results that may quote the analyzed file carry `untrustedContent: true` and `source: analysis_target`.
- **Long engine opens:** an open past the deadline answers with `details.stage` and `details.seconds`; calling again resumes it.
- **Captures:** `summarize_file view=pcap`; `search_container kind=endpoint` reads pcap and `.saz`.
- **Formats:** `summarize_file` views `sqlite`, `flutter` and `rust`; `get_pe_info` reports ELF CET, BTI and PAC.
- **Crash dumps:** `open_minidump`, `dump_stack`, `read_dump_memory` and `bucket_minidumps` read ELF core files.
- **Native:** `survey_features` finds crypto and hash constants; `search_instructions value=min..max`.
- **Engines:** no-return prototypes stop caller flow; `ghidra_script` runs installed scripts by `name=`; `get_engine_status` lists Ghidra analysis errors.
- **Evidence:** `read_result format=evidence` bundles results; `format=verify` reruns them and names changes.
- **Android:** `get_android_device_info view=processes|features|services|settings|files`.
- **Builds:** `unity_overview` reads Mono APKs, zipped Windows and Linux builds and WebGL builds.

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

- **Security:** built with .NET SDK 10.0.402 (runtime 10.0.13, `System.Security.Cryptography.Pkcs` 10.0.13; CVE-2026-84008, CVE-2026-70162); framework-dependent installs need runtime 10.0.13.
- **Distribution:** `dotnet tool install -g CorvusRE` or `dnx CorvusRE --yes`; MCP Registry name `io.github.Albasha0x0/corvus`.
- **Release assets:** ship under the `corvus` name only.

### Fixes

- **Notices:** many abandoned edit sessions produce one notice line.

## 2.0.0

### Highlights

- One output contract on every tool: structured record, output schema, list envelope, token budget, `Next:` on errors.
- Edit tools preview by default (`dryRun=true`); applied edits get stable ids and undo in IDA and Ghidra too.
- Engine output is cached across processes; repeated decompiles answer in milliseconds.
- `--toolsets core` and `lean` profiles for clients that cap tool counts.

### Breaking changes

- **Edits:** every .NET and native edit tool and `migrate_native_names` default to `dryRun=true`.
  - Before: edits applied at once.
  - After: pass `dryRun=false` to apply.
- **Removed tools:** `decompile_type`, `decompile_assembly_attributes`, `find_overrides`.
  - Before: `decompile_type`; `decompile_assembly_attributes`; `find_overrides`.
  - After: `decompile_member` with the type; `get_attributes format=csharp`; `find_references kind=overrides`.
- **Renamed parameters (no aliases):**
  - Every tool with a size limit: Before: `maxChars`. After: `maxTokens`.
  - `find_call_paths`: Before: `maxPaths`. After: `limit` (with `offset`).
  - `diff_function`: Before: `maxLines`. After: `offset`, `limit`, `maxTokens`.
  - `inspect_instruction`: Before: `count`. After: `limit`.
  - `ida_python`: Before: `maxOutput`, `file`. After: `maxTokens`, `scriptPath`.
  - `ghidra_script`: Before: `timeout`. After: `timeoutSeconds`.
  - `find_virtual_calls`, `emulate_native`, `reanalyze_native`: Before: `seconds`. After: `timeoutSeconds`.
  - `search_decompiled`: Before: `cursor`, `seconds`. After: `offset`, `timeoutSeconds`.
  - `search_instructions`, `reanalyze_native`: Before: `start`, `end`. After: `from`, `to`.
  - `list_imports`: Before: `module`. After: `library`.
  - `load_pdb`: Before: `force`. After: `allowMismatch`.
  - `patch_bytes`, `patch_asm`: Before: `force`. After: `allowUnsafe`.
  - `export_engine_database`: Before: `force`. After: `overwrite`.
  - `get_resource`, `get_android_resource`: Before: `savePath`. After: `outputPath`.
  - `export_edits`, `save_session`: Before: `path`. After: `outputPath` (parameter and record).
  - `undo_native_edit`: Before: `number`. After: `editId`.
- **Booleans inverted to default false (omitting them behaves as before):**
  - `apply_edits`: Before: `stopOnError=true`. After: `continueOnError=false`.
  - `compare_assemblies`: Before: `listAddedRemovedTypes=true`. After: `typeCountsOnly=false`.
  - `decompile_java`: Before: `smaliFallback=true`. After: `javaOnly=false`.
  - `disassemble`: Before: `function=true`. After: `fromAddress=false`.
  - `dump_stack`: Before: `exceptionContext=true`. After: `dumpTimeContext=false`.
  - `install_android_package`: Before: `replace=true`. After: `keepInstalled=false`.
  - `read_dump_memory`: Before: `imageFallback=true`. After: `dumpOnly=false`.
  - `trace_native_values`: Before: `followGlobals=true`. After: `stopAtGlobals=false`.
  - `unpack_container`: Before: `load=true`. After: `extractOnly=false`.
  - `comment_native`: Before: `dedupe=true`. After: `repeatLine=false`.
  - `find_call_paths`: Before: `includeVirtual=true`. After: `directOnly=false`.
  - `find_references`: Before: `includeVirtualCalls=true`. After: `directOnly=false`.
  - `list_types`: Before: `includeNested=true`. After: `topLevelOnly=false`.
  - `migrate_native_names`: Before: `comments=true`. After: `namesOnly=false`.
  - Build tools: Before: `useNames=true`. After: `codeOnly=false`.
- **New false defaults:** `set_native_type` `rename` defaults to false; `get_native_frame` needs `locals=true` for decompiler locals.
- **Lists take arrays:** note tags, `compare_folders exclude`, `extract_strings types`, `simplify_methods passes`, `compare_assemblies changes`, `migrate_native_names sources`, `search_code_pattern images`, `update_to_new_build include`, `oldIl2Cpp`, `newIl2Cpp`.
  - Before: a separated string.
  - After: an array.
- **Paging:** `offset` counts rows, nodes, blocks or bytes, never characters; `truncated` is removed; most default page sizes are smaller.
  - Before: `offset` in characters; `truncated`.
  - After: continue with `nextOffset`; `hasMore` and `totalExact` say whether more exists.
- **Records:** row arrays are named `items`; many fields renamed or dropped; full schemas in [docs/schemas](schemas/).
  - Before: the text part held the record's JSON.
  - After: text is readable rows; `CORVUS_RESULT_MODE=json` restores a JSON copy.
- **Edit ids:** .NET edits are `<assembly>#<n>`, native edits `<image>#<n>`, stable across undo.
  - Before: undo renumbered the remaining edits.
  - After: `undo_edit` and `diff_edits` take the id in `number`; `undo_native_edit` takes `editId` (`image#n`, `#n`, `n` or a comma list).
- **compare_assemblies:** read-only; `tokenMapPath` and `overwrite` removed.
  - Before: `tokenMapPath=<file>`.
  - After: `tokenMap=true` returns `tokenMapResultId`; write it with `read_result outputPath=`.
- **extract_strings:** read-only; `savePath`, `format` and `overwrite` removed.
  - Before: `savePath=<file>`.
  - After: `read_result id=<valuesResultId> outputPath=<file>`.
- **apply_edits:** a rolled-back script is an error.
  - Before: success.
  - After: code `failed` with per-edit items in `partial`.
- **open_minidump, inspect_process:** per-section offset/limit pairs removed.
  - Before: `modulesOffset`, `threadsLimit`, `sections`.
  - After: `view=` with `offset` and `limit` (50).
- **Undecoded architectures:** code tools on MIPS, PowerPC, RISC-V and s390x refuse.
  - Before: success with 0 rows.
  - After: `unsupported` with `details.reason=instructions-not-decoded`.
- **unpack_container:** data that is not a container is refused.
  - Before: success with no files.
  - After: `unsupported`.
- **read_android_log:** `maxBytes` removed.
  - Before: `maxBytes`.
  - After: `buffer`, `offset` (lines back from the newest), `limit`.
- **map_java_dotnet, pull_android_file:** error codes changed.
  - Before: `not_found` for an AOT package; `failed` for a missing remote file.
  - After: `unsupported` (`details.reason=il2cpp`); `not_found`.
- **Note files:** format `corvus-notes/2`.
  - Before: format 1.
  - After: format 2; format 1 still reads.
- **Input schemas:** optional parameters have no `null` in `type`; booleans and `offset` no longer declare defaults.
  - Before: `["string","null"]`.
  - After: `"string"`; a null sent anyway counts as omitted.

### Changes

- **.NET read:** `decompile_member` decompiles whole types; `get_type_info` returns one `items` array with `section`; `get_assembly_info view=`.
- **.NET read:** smaller default limits: `list_namespaces` 200, `list_types` 150, `find_references` 150, `find_callees` 200, `search_strings` 100.
- **.NET edits:** all 15 edit tools return records; `revert_edits` returns a `resultId` with the discarded edits.
- **.NET edits:** `simplify_methods passes` takes `fold`, `cfg`, `inline`; `find_counterpart symbols[]` takes up to 100.
- **export_project:** decompiles a private snapshot, writes through a staging folder; `overwrite=true` replaces an export.
- **Native:** smaller default limits for import, export, function, string and xref lists; 17 native list tools take `maxTokens`.
- **Native:** `native_call_tree`, `get_cfg`, `read_bytes`, `list_cpp_classes` page by nodes, blocks, bytes and classes.
- **Native:** `find_xrefs kind=metadata`; `get_pe_info view=code`; `search_native_strings maxLength` (200); `get_native_type` takes a glob.
- **Native edits:** every applied edit returns an `editId`; `undo_native_edit` undoes bytes, names, comments and engine edits.
- **Engines:** `engine=auto` picks IDA, then Ghidra, if it analyzed these bytes, else ours; `engine=ours` on engine-only tools is `invalid_argument`.
- **Engines:** script exceptions in `ida_python` and `ghidra_script` are errors unless `allowError=true`.
- **Builds:** one reason vocabulary ([docs/migration-reasons.md](migration-reasons.md)); `migrate_native_names` and `update_to_new_build` agree.
- **Builds:** `map_address_between_builds` and `make_code_pattern` take `addresses[]`; `compare_native_images` returns one row type.
- **Containers:** `summarize_file view=` (default `overview`); `survey_features category=` adds evidence; `search_container kind=file`.
- **Containers:** `--load` of a .vsix, .nupkg or .zip loads the assemblies inside.
- **Android:** list tools use the list envelope with smaller defaults; `get_android_manifest view=`; `get_dex_class` pages members.
- **Dumps:** `open_minidump view=summary|modules|threads|memory|unloaded`; `symbolize_stack_text` folds repeated frames (`allFrames=true`).
- **Results:** `read_result` ids are content ids (`r-` + 12 hex) kept 7 days (`CORVUS_RESULT_CACHE`, `_MB`, `_DAYS`).
- **Output budget:** set by the client profile (`--client`, `CORVUS_CLIENT`, `CORVUS_MAX_OUTPUT_TOKENS`); a call answers 5 s before the client's limit.
- **Errors:** always carry a `Next:` line; oversized errors keep the whole error under `details.resultId`.
- **Profiles:** `--toolsets core` (at most 100 tools) and `lean` (at most 40); clients that cap tool counts get `lean`.
- **server_status:** `unavailableTools` rows are `{tools[], reason, remediation}`; new budget, cache and worker sections.
- **Engine output cache:** pseudocode and frames are kept across processes (`CORVUS_ENGINE_OUTPUT_MB`, default 1024).
- **Speed:** faster .NET edits, constructor decompiles, startup and record fitting.
- **Accuracy:** built-in x86, x64, ARM32, ARM64 and NativeAOT function and reference discovery closer to IDA.
- **Reliability:** `CORVUS_LOCK_CHECK=1` fails calls that read modules without the workspace lock; engine opens report progress every 4 s.
- **Android:** `decompile_java` finds nested and lambda classes and reads jars of `.class` files.
- **Upgrade:** code index format 14; older indexes are rebuilt on first use.

### Fixes

- **map_java_dotnet:** a parallel edit or reload no longer disposes modules mid-walk.
- **export_project:** works on an .apk.
- **find_method_by_address, get_il2cpp_info:** no negative `[More: offset=]` on overflow.
- **Linux and macOS:** percentages print as "0%"; PDB object names with Windows paths lose their folders.
- **patch_asm:** names the machine for images it cannot assemble.
- **C# edits:** enclosing namespace types bind first (CS0115 / CS1503); newer references are kept (CS1705).
- **export_native_patches:** `format=ida` works in IDA 9 for an appended segment.
- **Native undo:** restores the export name and the engine's own prototype.
- **Text output:** `get_call_tree` marks native-to-managed transitions; `dump_stack` shows `token` and `ilOffset`.
- **Budget:** token estimates count packed strings, UTF-16 and hex correctly.
- **POSIX engine workers:** end with a killed server under `dash` too.
- **analyze_native_function:** cached answers keep their warnings.
- **search_instructions:** a page stopped by the scan budget continues.
- **list_assemblies:** container pages no longer overlap.
- **diff_edits:** `totalChars` is stable across pages.
- **Containers:** AOT-compiled APKs are no longer labelled Mono.
- **find_similar_functions:** duplicates and clusters show their rows.

## 1.3.0

### Highlights

- Find look-alike functions across loaded images with `find_similar_functions`.
- Run a function in Ghidra's p-code emulator with `emulate_native`.
- Compare two folders or archives entry by entry with `compare_folders`.
- Read Electron, Objective-C, Swift and Go metadata.

### Breaking changes

- **Busy server:** leftover calls are capped (`CORVUS_MAX_LEFTOVER_CALLS`, default 2).
  - Before: no cap.
  - After: a new call at the cap is `provider_unavailable` with `retryAfterMs`.
- **Errors:** save tools report only IO faults as `io_error`; other faults are `internal`.
  - Before: any save fault was `io_error`.
  - After: `internal` with a Next; `decompile_java` without JADX or Java is not retryable (`not_configured`).
- **rename_symbol:** keeps a generic type's arity suffix.
  - Before: a different arity was accepted.
  - After: refused.
- **set_native_local (Ghidra):** a rename that did not take effect fails.
  - Before: reported success.
  - After: an error.

### Changes

- **find_similar_functions:** ranks look-alike functions and reports duplicate groups and clusters.
- **emulate_native:** runs a function or range with a private stack, call stubs and budgets.
- **compare_folders:** compares folders or zip-family archives by SHA-256, with moves and renames.
- **update_to_new_build:** takes two .NET assemblies.
- **Busy server:** a lock timeout names the holders (`details.blockedBy`); `server_status` no longer takes the lock.
- **Deterministic records:** `unity_overview`, `compare_native_images`, `update_to_new_build` and `find_similar_functions` drop elapsed time.
- **Electron:** ASAR archives with integrity checks; `summarize_file` reports versions, fuses and `webPreferences`.
- **Containers:** WebGL data files and HAR / mitmproxy captures open as containers.
- **Mach-O:** Objective-C and Swift metadata and a Swift demangler in `list_cpp_classes` and `get_native_type`.
- **Go:** build info, function sizes and noreturn runtime functions for PE, ELF and Mach-O.
- **ELF and Mach-O:** `patch_asm` extends patch sites beyond their size.
- **ARM:** gap discovery, `.ARM.exidx`, ARM64X / ARM64EC, JNIEnv calls named, floating-point call arguments.
- **Index speed:** the code index runs on several threads with the same results.
- **IDA:** cached function and string lists; batched `find_xrefs`, `resolve_address` and `search_bytes`; a user's `.i64` is never written.
- **Operations:** engine database cache bounded (`CORVUS_ANALYSIS_CACHE_MB` / `_DAYS`); `CORVUS_LOG_FORMAT=json`; `--trace-args` with secrets masked.
- **Distribution:** CorvusRE NuGet .NET tool package and MCP bundles (`.mcpb`).
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
- Android packages and devices, and deeper .NET crash dump decoding.

### Breaking changes

- **Name:** the program is `corvus`, the MCP key `corvus`, variables `CORVUS_*`, resources `corvus://`.
  - Data, client entries and skills move on first start; files saved earlier still read.
- **Exports:** export and save tools refuse to replace an existing file; links and device names are refused as targets.
  - Before: files were replaced.
  - After: pass `overwrite=true`.
- **save_assembly:** refuses an original that changed on disk since it loaded (`changed_on_disk`).
- **uninstall:** keeps annotations, caches and symbols.
  - Before: removed with the program.
  - After: `--purge-data` removes them.
- **Call deadline:** a tool not marked long-running ends with a timeout after twice `--timeout`; new codes `cancelled`, `changed_on_disk`.
- **Arguments:** closed values are enums checked before the tool runs; `limit < 1` is `invalid_argument` on paged native tools.
- **Native names:** a name on several addresses is an ambiguous error; hex-shaped names resolve as names before numbers.
- **Member labels:** carry generic parameters (`Method<T>(string)`); older edit scripts still resolve.
- **Native patches:** pad with the architecture's NOP; refused where none is defined.
- **IDA:** versions before 9.0 are refused.
- **Inputs:** FIFOs, sockets, devices and directories are refused as input files.

### Changes

- **Ghidra:** `engine=ghidra` on every engine tool; Ghidra 12.0 or newer via `CORVUS_GHIDRA_DIR` and a JDK.
- **Ghidra:** saved projects per file hash, analysis budgets with partial saves that `reanalyze_native` completes.
- **Ghidra:** `ghidra_script` behind `--ghidra-scripting`; `export_engine_database` writes `.gzf`, `.h` or `.gdt`.
- **Engine edits:** `define_native`, `set_native_operand`, `reanalyze_native`; type and stack member edits replayed on new builds.
- **Engine views:** `list_globals`, `search_instructions`, `convert_number`, `get_engine_status`, `search_decompiled`, `make_code_pattern`.
- **Engine control:** `CORVUS_ENGINE_REQUEST_TIMEOUT`, `CORVUS_ENGINE_OPEN_TIMEOUT`, `CORVUS_ENGINE_ANALYSIS=none`; read-only snapshot when another server holds a database.
- **ELF and Mach-O:** load through every native tool, universal files by slice; Itanium demangler, RTTI and exception tables.
- **ARM64 and ARM32:** built-in decoders, function discovery, jump tables, call arguments and value traces.
- **Go:** function tables (Go 1.2 to 1.24) as a function and name source.
- **Patching:** `patch_bytes`, `patch_asm` and `save_native` on ELF and Mach-O.
- **Native analysis:** `inspect_instruction`, `get_native_type`, `trace_native_values`, `resolve_call_targets`, `analyze_native_function`, `trace_native_feature`, `diff_function`.
- **NativeAOT:** `get_nativeaot_info` and a name layer for .NET 7 to 11 (PE, ELF, Mach-O; 32 and 64-bit).
- **AOT metadata:** Android, iOS, macOS and Linux builds from `.apk`, `.xapk`, `.apks`, `.aab` and `.ipa`; metadata up to v39.
- **Android:** manifest, resources, APK signatures v1 to v4; DEX tools; `decompile_java` through JADX; `map_java_dotnet`.
- **Devices:** adb read-only by default; install and uninstall behind `--allow-device-changes`.
- **Crash dumps:** managed exceptions, mixed frames, `dump_heap`, `dump_object`; DAC download opt-in; 32-bit dumps on Windows.
- **Stacks:** `symbolize_stack_text` and `bucket_minidumps`.
- **.NET builds:** `compare_assemblies` and `find_counterpart` report every member change, with optional C# or IL diffs.
- **Sessions and notes:** `save_session`, `load_session`, `record_note`, `update_note`, `list_notes`.
- **Setup:** `corvus install` edits client files in place (`--dry-run`, `--json`); `install --skill`; `SHA256SUMS` checked.
- **CLI:** `corvus call`, `describe`, `batch`, shell completions.
- **Server:** `--toolsets`, `--tools-file`, `--trace`, `--log-level`, resource subscriptions.

### Fixes

- **Reliability:** cross-process locks for annotations and notes; a deadlock between the edit journal and saves fixed.
- **read_bytes:** reports when cut short; bytes without file data show as `??`.
- **Regex searches:** a timeout reports what was not evaluated.

## 1.1.0

### Highlights

- Analyze native PE images: code index, IDA decompiler, PDB, patching, crash dumps and build migration.
- Persistent native code index and imported names across restarts.
- Read metadata of AOT-compiled managed code with the built-in reader.
- Carry names, patches and comments to a new build with `update_to_new_build`.

### Breaking changes

- **Arguments:** an undeclared parameter is `invalid_argument` with the closest names.
  - Before: ignored; the tool ran with defaults.
  - After: drop extra arguments.
- **load_pdb:** marked destructive; `clear=true` removes imported names and their saved copy.
- **engine=auto:** `list_functions`, `disassemble`, `get_cfg`, `find_xrefs` and `native_call_tree` answer from IDA once it has analyzed the image.
  - Before: the built-in index.
  - After: pass `engine=ours` for the built-in index only.

### Changes

- **Code index:** saved per file SHA-256 (8 GB, 30 days); `--index-cache <dir|off>`, `--index-cache-mb`, `--index-cache-days`.
- **Imported names:** `load_pdb` and `apply_il2cpp_names` names are reapplied on reload; `list_native_edits` lists each layer.
- **Engines:** `engine=auto|ours|ida`, server default `--engine` / `CORVUS_ENGINE`; every result names its engine.
- **IDA:** `decompile_native` loads PDB types into the database.
- **Virtual calls:** MSVC RTTI resolves virtual call edges; `find_virtual_calls`, `crossCheck=true`, `native_call_tree calls=`.
- **AOT metadata:** `load_assembly` reads metadata 24-31 from a build folder, `global-metadata.dat` or a memory dump of GameAssembly.dll.
- **unity_overview:** build version, runtime kind with evidence, metadata state and next calls.
- **inspect_process:** read-only view of a running local process on Windows; writes and suspends nothing.
- **Patch sites:** `patch_asm` / `patch_bytes extend=true` with `placement=auto|cave|section` and `stubMode=before|after`.
- **update_to_new_build:** carries names, comments, layers, patches and code patterns with one report.
- **Native PE:** own PE parser, x86 / x64 code index, MSVC demangler, RTTI, PDB reader with opt-in symbol download, ReadyToRun code.
- **IDA (idalib):** `decompile_native`, cached analysis, pushed names, patches and types; `--ida-prewarm`.
- **Native editing:** renames and comments per file hash, `patch_bytes`, `patch_asm`, undo, `save_native`, patch export and migration.
- **Builds and dumps:** `compare_native_images`, address and name migration, code patterns, `open_minidump`, `dump_stack`, `read_dump_memory`.
- **AOT metadata:** string literals, metadata to native navigation, struct layouts, prototypes and C++ bindings.
- **Protocol:** typed errors, structured output, `read_result` for large responses, `server_status` with a catalog digest.
- **.NET:** normalized IL hashes, member matching, more `simplify_methods` passes.
