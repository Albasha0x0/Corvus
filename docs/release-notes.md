# Release notes

## 2.7.0

165 tools and 15 prompts, as in 2.6.0: everything new is a parameter, an action, a view or a kind of an existing tool.

### Highlights

- Open a session on a program on an Android device, a Node or Electron program through its V8 inspector, a JVM
  through JDWP, or a TTD recording, and stop at original source lines.
- Read databases and logs without their libraries, with deleted records recovered: LevelDB, LMDB, ESE, Berkeley DB,
  Realm, registry hives, Windows event logs and Process Monitor captures.
- Open Apple disk images, HFS+ and APFS volumes, asset catalogs, rpm, AppImage, snap and HarmonyOS packages, Java
  runtime images, ESP32 flash images and model files on any OS.
- Name the code of Dart AOT images from Dart 3.0 to 3.13, compressed pointers included, and emulate x86, x64 and ARM64
  code without Ghidra.

### Breaking changes

None.

### Changes

- **Live, Android:** `live_session device=SERIAL` spawns or attaches through the device's frida-server; a stop adds
  the held thread's Java frames, joined to their DEX methods (Android 14 x86_64 emulator, Frida 17.24.3; arm64 devices
  not checked). [ff3515e0](https://github.com/Albasha0x0/Corvus/commit/ff3515e0) [6a2d4aed](https://github.com/Albasha0x0/Corvus/commit/6a2d4aed) [70e6be17](https://github.com/Albasha0x0/Corvus/commit/70e6be17)
- **Live, V8:** `program=inspector:PORT` opens a session over the Chrome DevTools Protocol; `live_break at=FILE:LINE`
  takes original source positions, and `action=ipc` counts an Electron app's IPC routes joined to their code (node
  22.17.0, Electron 33.2.0; loopback only). [a9716f6a](https://github.com/Albasha0x0/Corvus/commit/a9716f6a) [5d29e5f2](https://github.com/Albasha0x0/Corvus/commit/5d29e5f2)
- **Live, JVM:** `program=jdwp:PORT` lists threads and stacks and stops at `File.java:LINE` (HotSpot JDK 11, 22 and
  24 on Windows x64; Linux not checked). [9cdde5ba](https://github.com/Albasha0x0/Corvus/commit/9cdde5ba)
- **Live, TTD:** `program=ttd:PATH` replays a TTD recording forward with stop points, call recording and reads (x64
  recordings, TTD 1.11.617; rr recordings not read). [b266b59d](https://github.com/Albasha0x0/Corvus/commit/b266b59d)
- **Process:** `inspect_process view=windows` lists a program's UI Automation tree with each window's class procedure
  and a PNG of its first window (Windows). [62831bdf](https://github.com/Albasha0x0/Corvus/commit/62831bdf)
- **Emulation:** `emulate_native engine=ours` runs x86, x64 and ARM64 integer code in process with the Ghidra
  worker's memory layout; `auto` picks it without Ghidra. Floating point, vector arithmetic and system calls stop the
  run by name (ARM64 not checked on hardware). [30b900f3](https://github.com/Albasha0x0/Corvus/commit/30b900f3)
- **Dart:** Dart AOT images name their code for Dart 3.0 to 3.13 and Flutter 3.10 to 3.47, compressed pointers
  included; 99.5% or more of names equal the debug symbols. [5c4f08e8](https://github.com/Albasha0x0/Corvus/commit/5c4f08e8) [f0f42c29](https://github.com/Albasha0x0/Corvus/commit/f0f42c29) [cf9569a6](https://github.com/Albasha0x0/Corvus/commit/cf9569a6) [2e9be512](https://github.com/Albasha0x0/Corvus/commit/2e9be512) [bdaf59ea](https://github.com/Albasha0x0/Corvus/commit/bdaf59ea) [2472c621](https://github.com/Albasha0x0/Corvus/commit/2472c621)
- **ELF:** function names are read from MiniDebugInfo (`.gnu_debugdata`). [0a1ebcd1](https://github.com/Albasha0x0/Corvus/commit/0a1ebcd1)
- **Mach-O:** a signature's code requirements show as `codesign -d -r-` prints them. [94521155](https://github.com/Albasha0x0/Corvus/commit/94521155)
- **Raw code:** `format=raw arch=m68k` loads 68000 code; an iNES or NES 2.0 ROM unpacks to the CPU's view at power-on.
  [752d8b12](https://github.com/Albasha0x0/Corvus/commit/752d8b12)
- **Engines:** `decompile_native engine=all` returns IDA's and Ghidra's text for one address in one call.
  [26247645](https://github.com/Albasha0x0/Corvus/commit/26247645)
- **Apple images:** UDIF disk images (every chunk method, LZFSE included), HFS+ and APFS volumes, decmpfs files and
  compiled asset catalogs open as containers (compared with 7-Zip 26.04 and carfile-go 0.8.0; sealed and encrypted
  volumes not read). [f7e891b8](https://github.com/Albasha0x0/Corvus/commit/f7e891b8) [0720a0f0](https://github.com/Albasha0x0/Corvus/commit/0720a0f0) [147fba90](https://github.com/Albasha0x0/Corvus/commit/147fba90) [66af06a6](https://github.com/Albasha0x0/Corvus/commit/66af06a6)
- **Databases:** `summarize_file` views `leveldb`, `lmdb`, `ese`, `berkeleydb` and `realm` page records and recover
  deleted ones, each compared with its reference library. [9f3713ac](https://github.com/Albasha0x0/Corvus/commit/9f3713ac) [270c1082](https://github.com/Albasha0x0/Corvus/commit/270c1082) [b34b2606](https://github.com/Albasha0x0/Corvus/commit/b34b2606) [be786125](https://github.com/Albasha0x0/Corvus/commit/be786125) [9b89cdf1](https://github.com/Albasha0x0/Corvus/commit/9b89cdf1)
- **Windows files:** views `registry` (hives, deleted keys), `evtx` (event logs, records in free space), `procmon`
  (Process Monitor captures) and `pri` (package resource indexes). [1d77b83a](https://github.com/Albasha0x0/Corvus/commit/1d77b83a) [46fa138e](https://github.com/Albasha0x0/Corvus/commit/46fa138e) [28293642](https://github.com/Albasha0x0/Corvus/commit/28293642) [3bddd78c](https://github.com/Albasha0x0/Corvus/commit/3bddd78c)
- **Packages:** rpm, AppImage and snap packages, Java runtime images (`lib/modules`) and HarmonyOS packages with Ark
  bytecode (OpenHarmony 5.1.0 SDK). [cf368dde](https://github.com/Albasha0x0/Corvus/commit/cf368dde) [59dbc850](https://github.com/Albasha0x0/Corvus/commit/59dbc850) [c4c22c0a](https://github.com/Albasha0x0/Corvus/commit/c4c22c0a) [2836b6f8](https://github.com/Albasha0x0/Corvus/commit/2836b6f8)
- **Containers:** Unreal pak and IoStore, GameMaker data, Lua and LuaJIT bytecode, compiled AutoIt scripts, Qt
  resource collections (compiled-in ones too), SWF files, and ESP32 flash images, partition tables and NVS.
  [d826ba28](https://github.com/Albasha0x0/Corvus/commit/d826ba28) [de0f101b](https://github.com/Albasha0x0/Corvus/commit/de0f101b) [75a819b0](https://github.com/Albasha0x0/Corvus/commit/75a819b0) [a0b23874](https://github.com/Albasha0x0/Corvus/commit/a0b23874) [a489d2bb](https://github.com/Albasha0x0/Corvus/commit/a489d2bb) [0b91da28](https://github.com/Albasha0x0/Corvus/commit/0b91da28)
- **Models:** `summarize_file view=model` reads safetensors, GGUF, ONNX and PyTorch files and walks pickles on a
  symbolic stack, so nothing is imported or run. [687f52f3](https://github.com/Albasha0x0/Corvus/commit/687f52f3)
- **Certificates:** `summarize_file view=certificate` reads PEM, DER, PKCS #7 and PKCS #12 files and builds their
  chains; APK pins name the bundled certificate they match. [ba7cf5c8](https://github.com/Albasha0x0/Corvus/commit/ba7cf5c8)
- **Captures:** HTTP/3 objects export from QUIC v1 and v2 captures, and `view=qlog` reads qlog event logs.
  [4cafc0e1](https://github.com/Albasha0x0/Corvus/commit/4cafc0e1)
- **Web:** `view=page` checks a saved page's scripts, Subresource Integrity, import maps and meta CSP; `analyze_js`
  gains `view=beautify` with renames by scope, `view=react` and `view=jsx`; `view=flight` reads React Server Components
  payloads; `view=wasm` shows a component's world in WIT. [da7fe193](https://github.com/Albasha0x0/Corvus/commit/da7fe193) [651f325c](https://github.com/Albasha0x0/Corvus/commit/651f325c) [d27cda83](https://github.com/Albasha0x0/Corvus/commit/d27cda83) [8548d808](https://github.com/Albasha0x0/Corvus/commit/8548d808) [6d69475f](https://github.com/Albasha0x0/Corvus/commit/6d69475f) [d6c40cfc](https://github.com/Albasha0x0/Corvus/commit/d6c40cfc)
- **Mobile:** the layers view joins Cordova and Capacitor calls to their plugin classes. [36285815](https://github.com/Albasha0x0/Corvus/commit/36285815)
- **Setup:** install, config and status register Kimi Code, Qoder, Droid, Trae, CodeBuddy, Hermes and DeepSeek
  Harness; `corvus.json` in the data folder sets `CORVUS_` variables. [8da13d49](https://github.com/Albasha0x0/Corvus/commit/8da13d49) [84a9f748](https://github.com/Albasha0x0/Corvus/commit/84a9f748) [f5fc9b46](https://github.com/Albasha0x0/Corvus/commit/f5fc9b46)
- **Status:** `server_status` lists running and finished calls, and the external programs not found share one row.
  [00f871c9](https://github.com/Albasha0x0/Corvus/commit/00f871c9) [30b900f3](https://github.com/Albasha0x0/Corvus/commit/30b900f3)
- **Release:** a container image with a read-only root is pushed to ghcr.io (linux-x64, linux-arm64), and the
  documentation is attached as a static HTML site. [ff515342](https://github.com/Albasha0x0/Corvus/commit/ff515342) [395a189c](https://github.com/Albasha0x0/Corvus/commit/395a189c)
- **Docs:** Simplified Chinese and Japanese README translations. [58741f97](https://github.com/Albasha0x0/Corvus/commit/58741f97)

### Fixes

- **Engines:** worker folders are closed to other user accounts, and a worker connection disposed under load no
  longer ends the server. [2d7e3a56](https://github.com/Albasha0x0/Corvus/commit/2d7e3a56) [42fb7d84](https://github.com/Albasha0x0/Corvus/commit/42fb7d84)
- **Native:** `resolve_address` resolves a name while the code index is still building. [0a3a2f27](https://github.com/Albasha0x0/Corvus/commit/0a3a2f27)
- **NativeAOT:** interface dispatch cells are read from the cell section only; a win-x86 build's metadata no longer
  adds false cells. [eaeb4649](https://github.com/Albasha0x0/Corvus/commit/eaeb4649)
- **Containers:** 64-bit NSIS installers list their files, Godot 3 packs embedded in executables read, and every
  `summarize_file` view that pages takes its paging parameters. [b0ba843e](https://github.com/Albasha0x0/Corvus/commit/b0ba843e) [2393b92c](https://github.com/Albasha0x0/Corvus/commit/2393b92c) [de1509ab](https://github.com/Albasha0x0/Corvus/commit/de1509ab)
- **Web:** positions in later sections of an indexed source map name the right source, and `analyze_js view=beautify`
  is accepted through the server. [57422e53](https://github.com/Albasha0x0/Corvus/commit/57422e53) [c1cbd3ef](https://github.com/Albasha0x0/Corvus/commit/c1cbd3ef)
- **Status:** `server_status` stays within its report budget on a busy server and on a machine without the external
  programs; a jar tool is never reported as a running check. [501b3294](https://github.com/Albasha0x0/Corvus/commit/501b3294) [27dfb735](https://github.com/Albasha0x0/Corvus/commit/27dfb735) [255ec779](https://github.com/Albasha0x0/Corvus/commit/255ec779) [30b900f3](https://github.com/Albasha0x0/Corvus/commit/30b900f3)
- **Setup:** a server check keeps the server's exit message when its stdout ends first. [01d21b2c](https://github.com/Albasha0x0/Corvus/commit/01d21b2c)
- **Mobile:** a device wait requires the device's shell to answer, so a device listed as ready that stopped answering
  is named. [30b900f3](https://github.com/Albasha0x0/Corvus/commit/30b900f3)

### In progress

- **Live, Frida:** a module loaded inside `SHGetKnownFolderPath` is missing from Frida's module registry; Corvus keeps
  its workaround until a Frida release ships the fix (frida/frida-gum#1190).
- **Live, browser:** sessions on a browser page over the Chrome DevTools Protocol.
- **Live, Android:** arm64 devices and Il2Cpp programs on a device.
- **Emulation:** ARM64 checked against hardware.
- **Tests:** push runs within 15 minutes.

## 2.6.0

165 tools and 15 prompts, as in 2.5.1: everything new is a parameter, an action, a view or a kind of an existing tool.
Corvus is now licensed under the Apache License 2.0. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)

### Highlights

- Recover settings a Unity build keeps in its serialized assets: typed URLs, hosts, keys and encoded values from
  MonoBehaviour fields and config TextAssets, located by file, asset and field.
- Compare a binary's file bytes with IDA's or Ghidra's memory and see what the loader, a fixup or a patch changed.
- Gate a package before it is installed: signed provenance checked offline, GuardDog's rules, what a source folder
  runs on open, checkout or build, and what an update changes by policy group.
- Scan a running program's memory with YARA rules, fetch pinned rule packs, and write findings as a STIX 2.1 bundle.

### Breaking changes

- **unity_overview, extract_strings:** an input that holds no Unity build is refused with reason `not_a_unity_build`
  (was `not_a_unity_title`); `extract_strings` on such a folder answers `unsupported` instead of `invalid_argument`. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
  - Before: `unity_overview path=<folder>` → `unsupported`, `details.reason: not_a_unity_title`
  - After: the same call → `unsupported`, `details.reason: not_a_unity_build`

### Changes

- **IDA:** with `CORVUS_IDA_CONNECT=1`, a database open in IDA 9 or newer that runs `corvus_connect.py`
  (`corvus ida-script`) is read and edited in place, without a local install; Corvus never saves, rebases or closes it
  (IDA Pro 9.3 on Windows; Linux and macOS not checked). [076cade3](https://github.com/Albasha0x0/Corvus/commit/076cade3)
- **Dart:** Dart AOT images name their code from the snapshot's Function and Class objects, as the VM's stack traces
  print it, as the `dart` layer; `summarize_file view=flutter` reports the count (Dart 3.13 program snapshots: product,
  64-bit, uncompressed pointers; compressed pointers, as Flutter's mobile builds use, and earlier Dart are reported as
  not read). [3ebac8c6](https://github.com/Albasha0x0/Corvus/commit/3ebac8c6)
- **Native names:** `migrate_native_names` takes a static library (.lib, .a) or object file (COFF, ELF) as its
  old side: each function names the start holding its bytes, and a call reaching another name refuses it (MSVC
  14.29 x64 CRT, glibc and musl x64; x86 and AArch64 objects read, not checked on a real program).
  [d7e2d18b](https://github.com/Albasha0x0/Corvus/commit/d7e2d18b) [52a140cc](https://github.com/Albasha0x0/Corvus/commit/52a140cc)
- **Unity:** `extract_strings` reads serialized files, bundles, build folders and the packages that hold them, lays out
  Il2Cpp scripts without an earlier load, and reads JSON, XML and INI TextAssets; `summarize_file view=unity` shows
  MonoBehaviour script fields. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476) [460c434c](https://github.com/Albasha0x0/Corvus/commit/460c434c)
- **Values:** a whole base64 or hex value is an `encoded` row with its decoded length, in assets and string literals. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Engines:** `compare_native_images engine=ida|ghidra` names each differing range patched, engine fixup, relocation
  applied, zero fill or unknown (IDA 9.3, Ghidra 12.1.4; PE and ELF). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Native strings:** Rust literals take their length from the code or the pointer and length pair; Swift small strings
  are read from their immediates (PE and ELF, x86-64 and ARM64). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Mobile:** DEX string decoder calls show their returned strings in `disassemble_dex` and `search_dex`, and
  `survey_features` rules match them. [7663ae6c](https://github.com/Albasha0x0/Corvus/commit/7663ae6c) [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Capabilities:** capa rule names label PE, ELF, .NET and Il2Cpp binaries, and a build comparison reports
  capabilities an update adds or removes. [34266e8d](https://github.com/Albasha0x0/Corvus/commit/34266e8d) [f6b3193c](https://github.com/Albasha0x0/Corvus/commit/f6b3193c) [a70f82ec](https://github.com/Albasha0x0/Corvus/commit/a70f82ec)
- **YARA and STIX:** `live_read rules=` scans a session's writable memory; pinned rule packs are fetched and verified;
  findings export as STIX 2.1. [814968d7](https://github.com/Albasha0x0/Corvus/commit/814968d7) [5ae2fb2e](https://github.com/Albasha0x0/Corvus/commit/5ae2fb2e) [06cf329d](https://github.com/Albasha0x0/Corvus/commit/06cf329d)
- **Emulation:** `emulate_native engine=speakeasy` runs a whole PE with Windows API emulation. [97d330b8](https://github.com/Albasha0x0/Corvus/commit/97d330b8)
- **Containers:** `extract_strings` reads a container's own assemblies, `unity_overview` counts Il2Cpp images, types
  and methods from the header, and `batch --file` pages each step to its limit and adds a `unity` section. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Package review:** the package view reviews agent configuration files; `summarize_file` takes a source folder and
  names what runs on open, checkout or build (git hooks and config, dev container commands, `.envrc`, MSBuild, Cargo,
  Gradle and CMake steps); `compare_folders` leads with a policy line counting install scripts, endpoints, native files,
  permissions and findings an update adds or removes. [86d3eb43](https://github.com/Albasha0x0/Corvus/commit/86d3eb43) [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Provenance:** a Sigstore bundle, npm's attestations or PyPI's provenance beside a package file is checked offline:
  subject digest, signature, certificate chain to the pinned Sigstore trust root and the log's signed entry timestamp,
  with the source repository, commit and workflow; npm's publish attestation against npm's keys. Revocation and Ed25519
  logs are not checked. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **GuardDog:** with GuardDog 3.2.0 (`CORVUS_GUARDDOG` or PATH), its rule matches join the package review at file and
  line. Linux and macOS; GuardDog does not build on Windows. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Comparisons:** with the malcontent rule pack installed, `compare_assemblies` and `compare_native_images` list the
  malcontent behaviours an update adds or removes, highest risk first. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Raw code:** `summarize_file view=raw` names the instruction sets an unknown file reads as and the load bases its
  pointers imply, each with its `load_assembly` call; `format=raw` without `arch` names them. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **.NET:** `get_assembly_info view=transforms` lists the transformation layers (constants, proxies, control flow) from
  a `simplify_methods` dry run, counts encoded bodies and assemblies loaded from bytes, and names the identified tool
  behind each layer. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **.NET:** compiled XAML (XBF) reads as XAML. [0bd7ab85](https://github.com/Albasha0x0/Corvus/commit/0bd7ab85)
- **Supply chain:** releases ship with build provenance, checked before install; reference packs and the dump DAC are
  verified against their publishers; actions are pinned by commit and CodeQL and Scorecard run on every push.
  [82917b7a](https://github.com/Albasha0x0/Corvus/commit/82917b7a) [7efad8c1](https://github.com/Albasha0x0/Corvus/commit/7efad8c1) [30f5568b](https://github.com/Albasha0x0/Corvus/commit/30f5568b) [0b853057](https://github.com/Albasha0x0/Corvus/commit/0b853057) [23b7b472](https://github.com/Albasha0x0/Corvus/commit/23b7b472)
- **Upgrade:** saved native indexes are rebuilt once (format 18), cached Il2Cpp dummy assemblies are read again once
  (cache format 4), and reference packs cached before keep their documentation files. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476) [df1323db](https://github.com/Albasha0x0/Corvus/commit/df1323db) [d2f80da7](https://github.com/Albasha0x0/Corvus/commit/d2f80da7)

### Fixes

- **Unity:** Il2Cpp scripts read from metadata without the binary no longer lay out with no fields; such fields are
  unknown with a reason. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Ghidra:** indirect-call arguments the decompiler infers carry `derived=true`, since they can differ between
  decompiler processes. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Comparisons:** rule pattern setup no longer counts against the 2 s capability survey budget. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **ELF:** MIPS64 relocations read their symbol and type from the split `r_info` layout. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Status:** `server_status` keeps every capability row within its budget with all engines installed and on a busy
  server (child programs and lock users bounded). [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Recipes:** the GuardDog recipe fetches sdists by URL; `pip download` of an sdist runs its build backend. [d11df476](https://github.com/Albasha0x0/Corvus/commit/d11df476)
- **Engines:** a killed worker's process tree is awaited, a Windows worker ends at its job memory limit, and a Ghidra
  project another server holds opens as a snapshot. [cc731176](https://github.com/Albasha0x0/Corvus/commit/cc731176) [f6d74f0b](https://github.com/Albasha0x0/Corvus/commit/f6d74f0b) [64f1436c](https://github.com/Albasha0x0/Corvus/commit/64f1436c)

## 2.5.1

165 tools and 15 prompts, as in 2.5.0.

### Fixes

- **Native imports:** a forwarder in a kernel-mode image that names the kernel without an extension
  (`hal.dll`: `ntoskrnl.KeStallExecutionProcessor`) binds to `ntoskrnl.exe` instead of reading as `forwarder_broken`;
  user-mode forwarders still name DLLs only. [a2a29687](https://github.com/Albasha0x0/Corvus/commit/a2a29687)
- **Native code:** an address in a block placed before its function's entry reads `name-0xB` in `inspect_instruction`,
  call sites, call target sites, native link rows and traces, as stop stacks already showed it, instead of
  `name+0xFFFFFFF5`. [b6468771](https://github.com/Albasha0x0/Corvus/commit/b6468771)

## 2.5.0

165 tools and 15 prompts, as in 2.4.0: everything new is a parameter, an action, a view or a kind of an existing tool.

### Highlights

- Stop at a .NET method's first call by `Ns.Type::Method` and read its managed frames in a session, 32-bit programs included.
- Open sessions and save snapshots on macOS and Windows ARM64, and read macOS core dumps.
- Hold, list and open the child processes a program starts, and read a running .NET program's heap without stopping it.
- List and extract installers and frozen Python programs, and write a CycloneDX SBOM with advisories checked offline.

### Breaking changes

- **live_watch:** a watch in a module not loaded yet is set as a deferred row instead of refused; every row has `state`
  (set, deferred, failed), and `address`, `prototype` and `decoding` can be null. `live_break` rows carry `state` too.
  [82569e67](https://github.com/Albasha0x0/Corvus/commit/82569e67) [3de6df7e](https://github.com/Albasha0x0/Corvus/commit/3de6df7e)
  - Before: `live_watch session=live-1 action=set where=late.dll!Run` → `not_found` (address, prototype and decoding were
    required)
  - After: the same call → `{"id":"w2","where":"late.dll!Run","address":null,"state":"deferred"}`
- **save_assembly, save_native:** `overwrite=true` no longer replaces the loaded file; that takes `replaceOriginal=true`
  and the server switch `--allow-replace-original`. [1899d87a](https://github.com/Albasha0x0/Corvus/commit/1899d87a) [f37e24ff](https://github.com/Albasha0x0/Corvus/commit/f37e24ff)
  - Before: `save_assembly assembly=app.dll outputPath=<path of app.dll> overwrite=true`
  - After: `save_assembly assembly=app.dll replaceOriginal=true` (server started with `--allow-replace-original`)
- **live_session:** attaching needs `--allow-live-attach`; `--allow-live` alone lists processes. [e63e805a](https://github.com/Albasha0x0/Corvus/commit/e63e805a)
  - Before: server `--allow-live`, then `live_session action=attach process=1234`
  - After: server `--allow-live-attach`, then `live_session action=attach process=1234`
- **live_read:** registers come only when asked, and the result pages as bytes (`offset`, `nextOffset`). [9e871e40](https://github.com/Albasha0x0/Corvus/commit/9e871e40) [71bec8e7](https://github.com/Albasha0x0/Corvus/commit/71bec8e7)
  - Before: `live_read session=live-1 memory=rsp` → registers of the held thread and the memory
  - After: `live_read session=live-1 memory=rsp registers=all` → the same; without `registers=` only the memory
- **Frida:** a Frida older than 17.0 is refused with `provider_unavailable`; one outside 17.24.3 to 17.x opens with an
  error event naming both versions. [52679133](https://github.com/Albasha0x0/Corvus/commit/52679133)
  - Before: any Frida with Python bindings started a session
  - After: `python -m pip install "frida>=17.24.3,<18"`, or start the server with `--live-install-frida`
- **File tools:** `summarize_file`, `list_assemblies path=`, `unpack_container`, `search_container` and the dump reads
  read untrusted files in a corvus worker process with its memory capped; a worker that cannot start is refused as
  `provider_unavailable`, with no silent fallback to the server process. [5a6a7ee6](https://github.com/Albasha0x0/Corvus/commit/5a6a7ee6)
  - Before: `summarize_file path=app.exe` parsed the file in the server process
  - After: the same call reads it in a worker; start the server with `--in-process-parsing` (or
    `CORVUS_IN_PROCESS_PARSING=1`) to read in the server process, or `CORVUS_WORKER_HOST=0` to turn every worker off
- **inspect_process:** a `live-N` id resolves only through its session; an ended session's id is refused. [eec4b54e](https://github.com/Albasha0x0/Corvus/commit/eec4b54e)
  - Before: `inspect_process process=live-1` after the session closed named whatever process reused the pid
  - After: the same call answers `not_found`; pass the process id

### Changes

- **Upgrade:** the native code index is built again once (persist format 17), Il2Cpp builds read by the built-in reader are
  read again once, and `bucket_minidumps` computes cached signatures again once. [2a6b25dd](https://github.com/Albasha0x0/Corvus/commit/2a6b25dd) [35de67ea](https://github.com/Albasha0x0/Corvus/commit/35de67ea) [99e838dc](https://github.com/Albasha0x0/Corvus/commit/99e838dc)
- **Sessions, .NET:** stops name JIT-compiled and ReadyToRun frames through the runtime's DAC, `live_break` and
  `live_watch` take `Ns.Type::Method`, stopping at the first call (`Main` included) and following tiered recompiles, a
  managed name in an assembly not loaded yet is resolved when set, so an unknown name fails then, and the module list
  matches the assemblies loaded with `load_assembly` and names them. Verified on .NET 10 x64 on Windows 11 x64; not
  supported on Linux targets.
  [0adca182](https://github.com/Albasha0x0/Corvus/commit/0adca182) [e874ead6](https://github.com/Albasha0x0/Corvus/commit/e874ead6) [ed100102](https://github.com/Albasha0x0/Corvus/commit/ed100102)
  [f9c68865](https://github.com/Albasha0x0/Corvus/commit/f9c68865)
- **Started .NET programs:** a program `live_session` starts runs with `DOTNET_EnableWriteXorExecute=0`; a point on
  code in a shared view of the runtime's code heap is refused, and a point on ReadyToRun code a single-file app maps
  from its bundle hooks a stub near the code.
  [73daeb57](https://github.com/Albasha0x0/Corvus/commit/73daeb57) [2ba87891](https://github.com/Albasha0x0/Corvus/commit/2ba87891)
- **live_session spawn and attach:** `environment=["NAME=value"]` adds variables to the started program's minimal set
  (other server variables are not passed on); a started program runs in its own folder; attach refuses the server's own
  process and the processes it runs under (MCP client, terminal, editor). [959be663](https://github.com/Albasha0x0/Corvus/commit/959be663) [2ee05dce](https://github.com/Albasha0x0/Corvus/commit/2ee05dce) [8dd197b4](https://github.com/Albasha0x0/Corvus/commit/8dd197b4)
- **Sessions, 32-bit .NET:** the 32-bit decoder process reads a 32-bit runtime under the 64-bit server for frames, coverage
  and heap reads, each read within 15 s. `live_coverage` reads the runtime's record through it, so methods compiled
  before the run and precompiled code count; without the decoder it counts the JIT's compiles, and a run stopped during
  a read waits for that read. Verified on .NET Framework 4.8 x86 on Windows 11 x64. [7260b18f](https://github.com/Albasha0x0/Corvus/commit/7260b18f) [6c777c9a](https://github.com/Albasha0x0/Corvus/commit/6c777c9a)
  [21951b28](https://github.com/Albasha0x0/Corvus/commit/21951b28) [590fff31](https://github.com/Albasha0x0/Corvus/commit/590fff31) [4957da98](https://github.com/Albasha0x0/Corvus/commit/4957da98)
- **Sessions, single-file and Framework apps:** methods of a single-file bundle and of a Framework assembly loaded as
  its native image take stop points; `live_session downloadDac=true` fetches a missing DAC (off by default, refused
  under `CORVUS_OFFLINE=1`). Verified on Windows 11 x64 with single-file apps and .NET Framework 4.8 native images.
  [a82f007a](https://github.com/Albasha0x0/Corvus/commit/a82f007a) [5eee839d](https://github.com/Albasha0x0/Corvus/commit/5eee839d) [719ecde0](https://github.com/Albasha0x0/Corvus/commit/719ecde0)
- **Heap of a running program:** `dump_heap` and `dump_object` take a session id (x64, and x86 through the decoder
  process). Verified with .NET 10 x64 and .NET Framework 4.8 x86 programs on Windows 11 x64; not verified on Linux or
  macOS targets. [3652cf43](https://github.com/Albasha0x0/Corvus/commit/3652cf43)
- **Child processes:** `live_session childNames` alone turns following on and holds matching children at their start
  (`["*"]` holds every child); `action=children` lists them as process rows with a state, together with processes that
  name the program as their parent without passing a hold (a browser process its runtime starts for it, WebView2 for
  example), and `action=attach_child` / `release_child` open or release one. Verified on Windows 11 x64 and Ubuntu
  24.04 x64 (fork and exec, `posix_spawn`, `/proc/self/exe`).
  [957d6fb1](https://github.com/Albasha0x0/Corvus/commit/957d6fb1) [49e33e73](https://github.com/Albasha0x0/Corvus/commit/49e33e73) [c6efa8b5](https://github.com/Albasha0x0/Corvus/commit/c6efa8b5)
  [72c84bc9](https://github.com/Albasha0x0/Corvus/commit/72c84bc9) [11b64a3d](https://github.com/Albasha0x0/Corvus/commit/11b64a3d)
- **Child processes on Linux:** a child session closed before its first continue leaves the child held again, as on
  Windows (it used to run), and a parent session closed first keeps its worker until the child sessions it handed over
  close. Verified on Ubuntu 22.04 and 24.04 with Frida 17.24.3. [f77c615c](https://github.com/Albasha0x0/Corvus/commit/f77c615c)
- **Sandboxed processes:** children under a restricted token or AppContainer load the agent; a refusal names the token.
  Verified with Chromium child processes on Windows 11 x64. [cc0c3501](https://github.com/Albasha0x0/Corvus/commit/cc0c3501) [5480446f](https://github.com/Albasha0x0/Corvus/commit/5480446f)
- **Stop points and watches:** points defer until a module loads or a method compiles and report `state`; `name+0xN`;
  points on a jump follow it; points through a delay-load pointer move when it is rebound; a point in a packed DLL is
  set once its entry point returns. Verified with Frida 17.24.3 on Windows 11 x64 and Ubuntu 24.04.
  [82569e67](https://github.com/Albasha0x0/Corvus/commit/82569e67) [3de6df7e](https://github.com/Albasha0x0/Corvus/commit/3de6df7e) [0747b876](https://github.com/Albasha0x0/Corvus/commit/0747b876)
  [4329023d](https://github.com/Albasha0x0/Corvus/commit/4329023d)
- **Watches:** a function with no prototype records raw argument and return values; DWARF prototypes decode System V
  x64 float and aggregate parameters. Verified on Windows 11 x64 and Ubuntu 24.04 (DWARF on x64).
  [fc8e83d9](https://github.com/Albasha0x0/Corvus/commit/fc8e83d9) [c6481ed9](https://github.com/Albasha0x0/Corvus/commit/c6481ed9)
- **live_read:** any address, a module by name, 256-byte rows, `cstring` / `utf16` to the terminator, C-style arrays,
  `registers=all`. [9e871e40](https://github.com/Albasha0x0/Corvus/commit/9e871e40) [3013c8a6](https://github.com/Albasha0x0/Corvus/commit/3013c8a6) [e47f744f](https://github.com/Albasha0x0/Corvus/commit/e47f744f)
- **live_coverage:** waits for a module loaded later, covers managed assemblies from the runtime's record, suggests narrower
  matches over its 5,000-function cap, and sets bare points (a program under coverage starts and exits several times
  faster). [096e5567](https://github.com/Albasha0x0/Corvus/commit/096e5567) [058e28cd](https://github.com/Albasha0x0/Corvus/commit/058e28cd) [330e75b2](https://github.com/Albasha0x0/Corvus/commit/330e75b2) [652e6244](https://github.com/Albasha0x0/Corvus/commit/652e6244)
- **live_timeline:** leaves out the session's own helper files (also when the data root is relative or reached through
  a link or a short name) and records a started program's process id; a trace stopped after its program ended waits up
  to 10 s for the program's stop event, so a short program's trace keeps its last events. Windows only: it reads an
  event trace.
  [0b819d2f](https://github.com/Albasha0x0/Corvus/commit/0b819d2f) [1d970f15](https://github.com/Albasha0x0/Corvus/commit/1d970f15) [68596ec5](https://github.com/Albasha0x0/Corvus/commit/68596ec5)
  [b82dcea5](https://github.com/Albasha0x0/Corvus/commit/b82dcea5)
- **Session tool defaults:** `live_coverage`, `live_timeline` and `live_console` calls without `run` use the only run
  (with several, the error lists them); `live_events` refuses an unknown kind with the kinds and a `from` the session did
  not give out; a filtered `live_events` or `live_timeline` page that holds every match ends the list, with its poll
  cursor past the entries it scanned. [b8b6cd62](https://github.com/Albasha0x0/Corvus/commit/b8b6cd62) [cd035783](https://github.com/Albasha0x0/Corvus/commit/cd035783) [34fcfc1c](https://github.com/Albasha0x0/Corvus/commit/34fcfc1c) [8526cf1c](https://github.com/Albasha0x0/Corvus/commit/8526cf1c)
  [f745de6c](https://github.com/Albasha0x0/Corvus/commit/f745de6c) [4ff2c83e](https://github.com/Albasha0x0/Corvus/commit/4ff2c83e)
- **Sessions on macOS and Windows ARM64:** `live_session` opens on macOS and saves snapshots through lldb; `module!export`
  resolves as the program's loader does (the dyld shared cache, the x64 or x86 view of ARM64X and CHPE system DLLs); a
  Mach-O symbol is found by its C name (`open` for `_open`); an ARM64 program's exit status is read from x0, and a stop at
  a function's first instruction names its caller. Programs emulated on ARM64: a snapshot is refused (it would hold the
  emulator's threads), and a deferred point in a DLL whose entry point writes its code fails with the reason. Verified in
  the live CI job on Windows x64, Windows ARM64, Ubuntu and macOS ARM64 (lldb-2100.0.17.203). [048992fe](https://github.com/Albasha0x0/Corvus/commit/048992fe)
  [5a4c6079](https://github.com/Albasha0x0/Corvus/commit/5a4c6079) [a9fa6e6e](https://github.com/Albasha0x0/Corvus/commit/a9fa6e6e) [d81bb276](https://github.com/Albasha0x0/Corvus/commit/d81bb276) [a5dd8851](https://github.com/Albasha0x0/Corvus/commit/a5dd8851) [7438fcc2](https://github.com/Albasha0x0/Corvus/commit/7438fcc2) [95b06f04](https://github.com/Albasha0x0/Corvus/commit/95b06f04) [953f42cd](https://github.com/Albasha0x0/Corvus/commit/953f42cd) [d2c2ed27](https://github.com/Albasha0x0/Corvus/commit/d2c2ed27)
  - On macOS ARM64, supported: spawn and attach, stop points by name, address and line, deferred points, watches with raw
    values, `live_read`, scripts, `live_coverage`, snapshots through lldb (the core keeps lldb's registers; the stop is
    not recorded as an exception), session deadlines and two sessions at once.
  - On macOS, not supported: following child processes (`childNames` refused: Frida's child gating misses a fork there),
    .NET method stops and managed frame names (the runtime decoder runs on Windows only), `live_timeline` (no activity
    trace reader off Windows) and `live_console` (the console host is the Windows pseudoconsole).
- **live_events:** call events have a ring of their own (10,000) beside the other events (10,000), so output, stops and
  exits survive a flood of calls; a page marks what each ring dropped ("N call events dropped (ring capacity 10,000)"),
  and `dropped` is that total between the cursor and the end of the page. [60df8c18](https://github.com/Albasha0x0/Corvus/commit/60df8c18)
- **Sessions on Linux:** `file:line` from DWARF, CFI-unwound stops, exit status from `_exit`, thread starts, `ptrace_scope`
  refusals named, statically linked programs refused before a worker starts (Frida cannot load into them,
  frida/frida#2533). Verified on Ubuntu 24.04 x64 and x86 (glibc 2.39), an ARM64 Linux smoke test in an emulated
  VM; musl: attach only. [fda1fd00](https://github.com/Albasha0x0/Corvus/commit/fda1fd00) [bdef2e19](https://github.com/Albasha0x0/Corvus/commit/bdef2e19) [483a1bb0](https://github.com/Albasha0x0/Corvus/commit/483a1bb0) [635708e5](https://github.com/Albasha0x0/Corvus/commit/635708e5) [d451d936](https://github.com/Albasha0x0/Corvus/commit/d451d936) [a9a2a00b](https://github.com/Albasha0x0/Corvus/commit/a9a2a00b) [053f382e](https://github.com/Albasha0x0/Corvus/commit/053f382e)
- **Snapshots at a stop:** the stop is the dump's exception (x64, x86 under WoW64) or the core's signal with the stop's
  registers (Linux); a snapshot of a program changing during the read is retried. Verified on Windows 11 x64 (64-bit
  and 32-bit programs), Windows 11 ARM64 and Ubuntu 24.04 (x64 and x86 programs). [02a58f2b](https://github.com/Albasha0x0/Corvus/commit/02a58f2b) [8b242284](https://github.com/Albasha0x0/Corvus/commit/8b242284)
  [7737ae1e](https://github.com/Albasha0x0/Corvus/commit/7737ae1e) [f1c9f16b](https://github.com/Albasha0x0/Corvus/commit/f1c9f16b)
- **Il2Cpp and NativeAOT stacks:** session frames named by method from the code index. Verified on Windows 11 x64.
  [ce09a2a9](https://github.com/Albasha0x0/Corvus/commit/ce09a2a9)
- **Program allow list:** `--live-allow <program or folder>` limits spawn, attach and `live_console`, compared by
  final path, a link whose target passes through another link included (macOS `/var`). Verified on Windows 11 x64 and
  the macos-latest CI image (macOS ARM64).
  [e63e805a](https://github.com/Albasha0x0/Corvus/commit/e63e805a) [e27efe55](https://github.com/Albasha0x0/Corvus/commit/e27efe55) [3a1b279e](https://github.com/Albasha0x0/Corvus/commit/3a1b279e)
- **Pinned Frida:** `--live-install-frida` (off by default) installs Frida 17.24.3 from hash-checked wheels into a private
  Python environment; `server_status` shows the version against the tested range 17.24.3 to 17.x. [0700c27c](https://github.com/Albasha0x0/Corvus/commit/0700c27c)
  [52679133](https://github.com/Albasha0x0/Corvus/commit/52679133)
- **Installers:** NSIS, Inno Setup (data formats 5.5.0 to 7.1), WiX Burn, Squirrel and ClickOnce list and extract under
  their install paths; LZX decodes faster (a 14.1 s cabinet listing in 11.2 s). Compared with 7-Zip, innounp 2.71.2,
  lessmsi 2.x and wix burn extract 5.0.2. [72efd8e5](https://github.com/Albasha0x0/Corvus/commit/72efd8e5) [f6ec02d4](https://github.com/Albasha0x0/Corvus/commit/f6ec02d4) [65b572ac](https://github.com/Albasha0x0/Corvus/commit/65b572ac) [7fb9c460](https://github.com/Albasha0x0/Corvus/commit/7fb9c460) [83fcd283](https://github.com/Albasha0x0/Corvus/commit/83fcd283)
  [ee8ce050](https://github.com/Albasha0x0/Corvus/commit/ee8ce050) [a8ceb8ec](https://github.com/Albasha0x0/Corvus/commit/a8ceb8ec)
- **Python programs:** PyInstaller, py2exe, cx_Freeze, Nuitka onefile and library zips list every file with its role and
  Python version; `summarize_file view=python` disassembles `.pyc` as `dis` of its version prints it (2.7, 3.0 to
  3.14); `CORVUS_PY_DECOMPILER` adds the source, with the decompiler named and its warnings kept as a note (an exit
  other than 0 marks the source as possibly partial). [3b3fdd3a](https://github.com/Albasha0x0/Corvus/commit/3b3fdd3a) [2ca14eb5](https://github.com/Albasha0x0/Corvus/commit/2ca14eb5) [00eea165](https://github.com/Albasha0x0/Corvus/commit/00eea165) [a378c054](https://github.com/Albasha0x0/Corvus/commit/a378c054)
- **Packages and images:** Godot packs, Flatpak bundles, apk v3, Debian packages, ar libraries and JMOD files list and
  extract; WebAssembly components open as their core modules. [4fa10d46](https://github.com/Albasha0x0/Corvus/commit/4fa10d46) [34f5043a](https://github.com/Albasha0x0/Corvus/commit/34f5043a) [8f3c4b3d](https://github.com/Albasha0x0/Corvus/commit/8f3c4b3d) [709e895b](https://github.com/Albasha0x0/Corvus/commit/709e895b)
  [cd5c13fa](https://github.com/Albasha0x0/Corvus/commit/cd5c13fa) [18180675](https://github.com/Albasha0x0/Corvus/commit/18180675)
- **Firmware:** permission bits on every filesystem entry, a zip after a vendor header carved at the image's level,
  Sercomm headers sized, empty UBI volumes listed. [29131322](https://github.com/Albasha0x0/Corvus/commit/29131322) [68e215c3](https://github.com/Albasha0x0/Corvus/commit/68e215c3) [4ef64f85](https://github.com/Albasha0x0/Corvus/commit/4ef64f85) [abbec909](https://github.com/Albasha0x0/Corvus/commit/abbec909)
- **Captures:** TLS 1.3 early data decrypts; HTTP/1.x request bodies export under `requests/`; acknowledged TCP holes become
  gaps at once. Compared with `tshark --export-objects http`. [9f2d35ac](https://github.com/Albasha0x0/Corvus/commit/9f2d35ac) [ba43bbf5](https://github.com/Albasha0x0/Corvus/commit/ba43bbf5) [86917711](https://github.com/Albasha0x0/Corvus/commit/86917711) [4e5ea498](https://github.com/Albasha0x0/Corvus/commit/4e5ea498)
- **Security:** a worker that reads untrusted files shares concurrent calls, and a crash, memory limit or deadline
  ends the worker, not the server, with the same text and structured output as in process; a request whose shared
  worker was stopped for another request runs again on a fresh worker, and the reads that stay in the server are
  listed in SECURITY.md. Verified on Windows 11 x64 (0.2 ms per warm read, 485 ms for a worker's start and first
  read).
  [69a32b6d](https://github.com/Albasha0x0/Corvus/commit/69a32b6d) [c74f0cb5](https://github.com/Albasha0x0/Corvus/commit/c74f0cb5) [bd40b2dd](https://github.com/Albasha0x0/Corvus/commit/bd40b2dd)
  [02991ccf](https://github.com/Albasha0x0/Corvus/commit/02991ccf) [5a6a7ee6](https://github.com/Albasha0x0/Corvus/commit/5a6a7ee6) [9fe4bb04](https://github.com/Albasha0x0/Corvus/commit/9fe4bb04)
  [a4e073c6](https://github.com/Albasha0x0/Corvus/commit/a4e073c6)
- **Dependencies:** `summarize_file view=dependencies` lists the components a file ships with their evidence, and
  `sbomPath` writes them as a CycloneDX 1.6 SBOM, with package URLs only from package-level evidence: deps.json
  (`pkg:nuget` with the package SHA-512 and dependency edges), informational versions, Go build information, Rust
  crates, the Unity version and assemblies of an Il2Cpp build, a frozen Python program's interpreter and distributions
  (`pkg:pypi`), and an APK's Maven libraries (`pkg:maven`), AndroidX version files and native libraries with the
  OpenSSL, zlib, libpng, libcurl and libjpeg-turbo versions compiled into them (a split set read as one app); an
  assembly version alone leaves the package version unknown. SBOMs validated with CycloneDX.Core 12.1.2.
  [b210a387](https://github.com/Albasha0x0/Corvus/commit/b210a387) [3a57d562](https://github.com/Albasha0x0/Corvus/commit/3a57d562) [00b0df27](https://github.com/Albasha0x0/Corvus/commit/00b0df27)
  [674577d6](https://github.com/Albasha0x0/Corvus/commit/674577d6) [07a4ca34](https://github.com/Albasha0x0/Corvus/commit/07a4ca34)
- **Advisories:** with osv-scanner 2 or newer (`CORVUS_OSV_SCANNER` or PATH), `view=dependencies` reports each
  component's advisories from the databases the user downloaded, run with `--offline`, and without it reads "not
  checked" with the reason; Corvus makes no network request. Compared with osv-scanner 2.7.0.
  [c58e3b55](https://github.com/Albasha0x0/Corvus/commit/c58e3b55)
- **YARA rules:** `search_container kind=yara` runs YARA-X 1.22.0 rules (a file, a folder of `.yar` / `.yara` files,
  or rule text in `query`) against a file, every member its container walk reads, or a dump's captured memory at
  virtual addresses, in a corvus worker process (`CORVUS_WORKER_HOST=0` turns it off), naming a rule that does not
  compile with its line while the rest run. The library ships for win-x64, win-arm64, linux-x64, linux-arm64 (glibc
  2.34 or newer), osx-x64 and osx-arm64; on musl the scan is refused naming the platform. Matches equal the `yr`
  1.22.0 command line on the test rules (Windows 11 x64).
  [f398695f](https://github.com/Albasha0x0/Corvus/commit/f398695f) [668d271b](https://github.com/Albasha0x0/Corvus/commit/668d271b) [76e4dd95](https://github.com/Albasha0x0/Corvus/commit/76e4dd95)
  [84e9ea57](https://github.com/Albasha0x0/Corvus/commit/84e9ea57) [6449ae46](https://github.com/Albasha0x0/Corvus/commit/6449ae46)
- **Region-set dumps:** a JSON manifest of memory region files (base address, size, protection, optional modules) saved
  by any tool opens through `open_minidump` and `read_dump_memory` at its real addresses; modules are rebuilt from the
  memory, views that need threads report them as unknown, and a missing region file reads as unknown. [97580469](https://github.com/Albasha0x0/Corvus/commit/97580469)
- **macOS and ARM64 dumps:** macOS Mach-O core dumps (ARM64, x86_64) open in the dump tools; ARM64 minidumps walk past
  the first frame, and a snapshot at an ARM64 stop records the stop. Verified on macOS ARM64
  (lldb-2100.0.17.203) and Windows 11 ARM64. [5b9e7ab3](https://github.com/Albasha0x0/Corvus/commit/5b9e7ab3) [4a3c4bc1](https://github.com/Albasha0x0/Corvus/commit/4a3c4bc1)
- **x86 dump stacks:** walks use the module PDB's frame data, continue at an exception's context record, match import
  calls read from a rebased module file, follow tail jumps through an import slot and find the caller of a thread stopped
  at a block entry; frames chained from a scan's guess are marked inferred. Compared with cdb 10.0.26100.6584 (x86).
  [18e8f15b](https://github.com/Albasha0x0/Corvus/commit/18e8f15b) [6506e5ef](https://github.com/Albasha0x0/Corvus/commit/6506e5ef) [de228012](https://github.com/Albasha0x0/Corvus/commit/de228012)
  [034cb6d1](https://github.com/Albasha0x0/Corvus/commit/034cb6d1) [9881013b](https://github.com/Albasha0x0/Corvus/commit/9881013b) [c8e0230b](https://github.com/Albasha0x0/Corvus/commit/c8e0230b)
- **Linux cores of .NET processes:** `dump_heap` and `dump_object` read them with the Windows-hosted DAC for Linux
  targets (server on Windows only), the decoder is reopened when a later `open_minidump` names `imageDirectories` that
  find libcoreclr.so, and `heap_not_captured` names `createdump --withheap` and `dotnet-dump collect --type Heap`.
  Verified with the core of a .NET 10 program written under WSL; other runtime versions not verified.
  [65342d36](https://github.com/Albasha0x0/Corvus/commit/65342d36) [71b2a1dd](https://github.com/Albasha0x0/Corvus/commit/71b2a1dd) [b1f51f14](https://github.com/Albasha0x0/Corvus/commit/b1f51f14)
- **Dump runtimes and frames:** a single-file app's runtime is found, Mono frames name Mono's own report, and a
  managed library named Mono.* no longer marks a CoreCLR process as Mono; COFF symbols name frames, and a frame named
  from the image's symbol table reads "source symbol", not "export"; an image listed twice (a 32-bit program dumped by
  a 64-bit writer) reads once; `dump_stack` walks managed frames from the exception context, so a snapshot at a stop
  names them; code between Il2Cpp methods is named by the code index's function; an x64 unwind that reads a return
  address that is not code scans on; and a session frame in a module without a loaded image is named after the export
  below only where the unwind data allows.
  [d1d5c0f4](https://github.com/Albasha0x0/Corvus/commit/d1d5c0f4) [dfeb86b3](https://github.com/Albasha0x0/Corvus/commit/dfeb86b3) [9e2e7333](https://github.com/Albasha0x0/Corvus/commit/9e2e7333)
  [863903cc](https://github.com/Albasha0x0/Corvus/commit/863903cc) [86d8c159](https://github.com/Albasha0x0/Corvus/commit/86d8c159) [675fe7f8](https://github.com/Albasha0x0/Corvus/commit/675fe7f8)
  [e0afcfe5](https://github.com/Albasha0x0/Corvus/commit/e0afcfe5) [15213c3a](https://github.com/Albasha0x0/Corvus/commit/15213c3a) [1c4b87c5](https://github.com/Albasha0x0/Corvus/commit/1c4b87c5)
  [fda920c7](https://github.com/Albasha0x0/Corvus/commit/fda920c7)
- **Native:** `list_cpp_classes` reads Delphi and Free Pascal VMTs, Delphi VMTs with the CPP_ABI slots included; MIPS
  imports from the global GOT, with MIPS relocation types classified so a non-PIC executable's PLT slots are imports;
  ARM64 `.pdata` / `.xdata` handlers in `get_exception_info`; the JNI table scan reads data sections only;
  `summarize_file view=rust` without a cargo-auditable list names the rustc commit and the crates its panic locations'
  source paths name. [551ad882](https://github.com/Albasha0x0/Corvus/commit/551ad882) [81fd2e59](https://github.com/Albasha0x0/Corvus/commit/81fd2e59) [ecf87e7c](https://github.com/Albasha0x0/Corvus/commit/ecf87e7c)
  [5482d274](https://github.com/Albasha0x0/Corvus/commit/5482d274) [34ddbddd](https://github.com/Albasha0x0/Corvus/commit/34ddbddd) [5cd6f0e3](https://github.com/Albasha0x0/Corvus/commit/5cd6f0e3) [17f9dc8b](https://github.com/Albasha0x0/Corvus/commit/17f9dc8b)
- **Il2Cpp:** builds that fill the code registration at run time map their generic method bodies, builds before
  metadata 27 among them (read through their module array); the known limit "generic method bodies with
  runtime-filled registration are not mapped" is removed. Verified with constructed 32-bit ARM libraries and a Windows
  build copied with its registration cleared; builds before metadata 27 not verified by a test.
  [c1a2a07e](https://github.com/Albasha0x0/Corvus/commit/c1a2a07e) [7f8ef5ba](https://github.com/Albasha0x0/Corvus/commit/7f8ef5ba)
- **Engine opens:** IDA analyses an open within a budget and saves a partial analysis that the next open or
  `reanalyze_native` continues, a saved analysis an open's time limit cut short reads "partial" and names
  `reanalyze_native` (nothing completes it unasked), and timeouts name the limit that ran out. Verified on IDA 9.3 and
  Ghidra 12.1.4 on Windows 11 x64.
  [ea0fb99c](https://github.com/Albasha0x0/Corvus/commit/ea0fb99c) [6075deb2](https://github.com/Albasha0x0/Corvus/commit/6075deb2) [31037bcc](https://github.com/Albasha0x0/Corvus/commit/31037bcc) [1384d85d](https://github.com/Albasha0x0/Corvus/commit/1384d85d) [ddc6e532](https://github.com/Albasha0x0/Corvus/commit/ddc6e532) [3f77e47d](https://github.com/Albasha0x0/Corvus/commit/3f77e47d)
- **reanalyze_native:** Ghidra's `analyzers=true` lists every analyzer of a program reopened from its project.
  Verified with Ghidra 12.1.4 on Windows 11 x64. [4a533d52](https://github.com/Albasha0x0/Corvus/commit/4a533d52)
- **Ghidra time limits:** a worker stopped for time reports its heap and up to three busy Ghidra threads, read by the
  JDK's jcmd, or jhsdb when jcmd gets no answer, from the process of the worker tree that hosts the JVM (a PyGhidra
  worker included); a report that reads nothing says "worker state unknown" with the reason. The full thread dump is
  saved under the analysis cache's `ghidra/stalls`, or in `CORVUS_STALL_DIR` when set. Verified with Ghidra 12.1.4 on
  JDK 24.0.1.
  [08f2735f](https://github.com/Albasha0x0/Corvus/commit/08f2735f) [0206cd6e](https://github.com/Albasha0x0/Corvus/commit/0206cd6e) [40f45445](https://github.com/Albasha0x0/Corvus/commit/40f45445)
  [cbdbf18f](https://github.com/Albasha0x0/Corvus/commit/cbdbf18f) [c400d8af](https://github.com/Albasha0x0/Corvus/commit/c400d8af)
- **Package review:** `view=package` reads more install-time behaviour (downloads run, shells connected to a remote
  host, detached processes, decoded commands, secrets posted to a chat webhook URL, zero-width display names). [6c57bdd6](https://github.com/Albasha0x0/Corvus/commit/6c57bdd6) [44f62a27](https://github.com/Albasha0x0/Corvus/commit/44f62a27) [023a1f0e](https://github.com/Albasha0x0/Corvus/commit/023a1f0e) [f2cd9d21](https://github.com/Albasha0x0/Corvus/commit/f2cd9d21)
- **Edits:** every edit carries a content digest, the same in its dry run, the applied edit and `list_edits`; saves list
  the edits they wrote. [14d22758](https://github.com/Albasha0x0/Corvus/commit/14d22758)
- **Comparisons:** `compare_folders noDiffs=true`; `diff_function` compares a kept result with a loaded image.
  [1545f272](https://github.com/Albasha0x0/Corvus/commit/1545f272) [942166ea](https://github.com/Albasha0x0/Corvus/commit/942166ea)
- **Catalog:** shorter tool and parameter descriptions: model-facing catalog 151,871 bytes, tools/list 308,482, lean
  37,369, core 88,559. [be75e4c1](https://github.com/Albasha0x0/Corvus/commit/be75e4c1) [7513ca65](https://github.com/Albasha0x0/Corvus/commit/7513ca65) [a5939cda](https://github.com/Albasha0x0/Corvus/commit/a5939cda)
- **Batch scans:** `corvus batch --file <path> --json` runs a fixed set of read-only steps (`summarize_file`, the
  container listing when the file is one, strings of a .NET assembly) and prints one `corvus.batch/1` document with the
  file's hashes, the limits used and a status per section (complete, partial with the limit reached, not_applicable,
  unavailable, error, timeout). `--time-limit` (default 120 s) ends the run with exit code 124 and the document still
  written, and `--rules <file|folder>` adds YARA rule matches (`--limit yaraMatches=N`, default 500). [3ce1d488](https://github.com/Albasha0x0/Corvus/commit/3ce1d488) [ce4908b9](https://github.com/Albasha0x0/Corvus/commit/ce4908b9)
- **server_status:** the first call checks the engines and the external programs side by side, and reads its status
  sections beside them, so it waits for the slowest check rather than their sum: under load 9.1-14.2 s before,
  3.0-3.7 s now (1.4-3.8 s and 1.0-1.7 s on a quiet machine). [b40bcf0a](https://github.com/Albasha0x0/Corvus/commit/b40bcf0a) [396d164c](https://github.com/Albasha0x0/Corvus/commit/396d164c)
- **Repository tests:** `./test.ps1 -Perf` runs the timing tests alone, `./nightly.ps1 -Register` runs a whole run and
  the perf run each night, push runs send the heavy test classes (Ghidra and live groups included) to GitHub-hosted
  runners or to a second machine over ssh (`CORVUS_TEST_REMOTE`) and join their results, keeping IDA, real-data and
  perf classes local (`CORVUS_TEST_OFFLOAD=0` runs everything here), and `release.ps1` ships on a whole-suite pass at
  most 50 commits back; docs/testing.md has the details.
  [bc1a1888](https://github.com/Albasha0x0/Corvus/commit/bc1a1888) [25c2773d](https://github.com/Albasha0x0/Corvus/commit/25c2773d) [23af2523](https://github.com/Albasha0x0/Corvus/commit/23af2523)
  [fa39d88b](https://github.com/Albasha0x0/Corvus/commit/fa39d88b) [002d29b4](https://github.com/Albasha0x0/Corvus/commit/002d29b4) [63e0d3ad](https://github.com/Albasha0x0/Corvus/commit/63e0d3ad)
  [70a35f6e](https://github.com/Albasha0x0/Corvus/commit/70a35f6e) [b08ef2b2](https://github.com/Albasha0x0/Corvus/commit/b08ef2b2) [5f1e7707](https://github.com/Albasha0x0/Corvus/commit/5f1e7707)
  [59f73928](https://github.com/Albasha0x0/Corvus/commit/59f73928) [59d6ead5](https://github.com/Albasha0x0/Corvus/commit/59d6ead5) [23bd58ec](https://github.com/Albasha0x0/Corvus/commit/23bd58ec)
  [a9e8e2eb](https://github.com/Albasha0x0/Corvus/commit/a9e8e2eb) [099d7890](https://github.com/Albasha0x0/Corvus/commit/099d7890) [3d4cf68d](https://github.com/Albasha0x0/Corvus/commit/3d4cf68d)
  [778fd17a](https://github.com/Albasha0x0/Corvus/commit/778fd17a)
- **Generated assemblies:** Il2Cpp dummies and reference stubs take MVID and PE timestamp from their content, so a rebuild
  gives the same bytes. [9c73d883](https://github.com/Albasha0x0/Corvus/commit/9c73d883)
- **PDB names on x86:** a public in the `__stdcall`, `__fastcall` or `__vectorcall` form is shown undecorated, as
  DbgHelp shows it, with the decorated name kept beside it: a stop at CreateFileW reads `KERNELBASE.dll!CreateFileW`,
  not `_CreateFileW@28`. A decorated x86 name given as input (`_CreateFileW@28`) resolves to the public a PDB shows
  undecorated.
  [171f342d](https://github.com/Albasha0x0/Corvus/commit/171f342d) [f552240e](https://github.com/Albasha0x0/Corvus/commit/f552240e)
- **Text output:** control characters in file text are written as `\uXXXX`, and list rows cannot start a marker line.
  [6ae387b8](https://github.com/Albasha0x0/Corvus/commit/6ae387b8)

### Fixes

- **Dump stacks:** x86 walks reach the program's frames past a thread held in a hook; a scanned copy of a return address is
  not a second frame. [a029d53a](https://github.com/Albasha0x0/Corvus/commit/a029d53a) [012b765d](https://github.com/Albasha0x0/Corvus/commit/012b765d) [c10acba8](https://github.com/Albasha0x0/Corvus/commit/c10acba8)
- **Engine analysis:** a function over Hex-Rays' MAX_FUNCSIZE is `limit_exceeded`, Itanium RTTI duplicate names no
  longer fail the class analysis, IDA's extern segment is left out of function lists, and Ghidra opens files whose
  names it rejects. Verified on IDA 9.3 and Ghidra 12.1.4 on Windows 11 x64.
  [ca4c91ec](https://github.com/Albasha0x0/Corvus/commit/ca4c91ec) [6264eb3e](https://github.com/Albasha0x0/Corvus/commit/6264eb3e) [2aebf983](https://github.com/Albasha0x0/Corvus/commit/2aebf983) [15520dff](https://github.com/Albasha0x0/Corvus/commit/15520dff)
- **Engine workers:** an open reports "start" before the engine's open call returns, a worker that exits or crashes is
  named with its exit code and stderr tail on every path that sees it (macOS and Linux included), and a timed-out
  request names its last stage and how long the worker had been quiet. Verified on IDA 9.3 and Ghidra 12.1.4 on
  Windows 11 x64. [1e1c3d5e](https://github.com/Albasha0x0/Corvus/commit/1e1c3d5e) [30707e76](https://github.com/Albasha0x0/Corvus/commit/30707e76) [2f2088b5](https://github.com/Albasha0x0/Corvus/commit/2f2088b5) [c1852fa5](https://github.com/Albasha0x0/Corvus/commit/c1852fa5) [c75aa025](https://github.com/Albasha0x0/Corvus/commit/c75aa025)
- **Decompiler failures:** any Hex-Rays failure names `engine=ghidra` and `disassemble` as the next step, and a crash
  of Ghidra's decompiler process names `engine=ida` and `disassemble`. Verified on IDA 9.3 and Ghidra 12.1.4 on Windows
  11 x64. [93f5af6b](https://github.com/Albasha0x0/Corvus/commit/93f5af6b) [a9c46dc5](https://github.com/Albasha0x0/Corvus/commit/a9c46dc5)
- **IDA Python search:** a Python that answers its version check late is reported unknown and searched again within
  the open's own time limit, instead of IDA being cached as unavailable; when no Python answers even then, the open
  fails with a retryable timeout. Verified with a fake interpreter on Windows 11 x64; an IDA open against a slow
  Python is not verified. [3fc786cb](https://github.com/Albasha0x0/Corvus/commit/3fc786cb)
- **Engine timeouts:** a request that runs out of time is read before it is cancelled, and its error names whether the
  request was written, how many progress events the worker sent for it and the worker's last log line for it. Verified
  with Ghidra 12.1.4 on Windows 11 x64.
  [d055446d](https://github.com/Albasha0x0/Corvus/commit/d055446d)
- **32-bit .NET sessions:** one failed read of the runtime no longer stops the decoder for the session; the note that
  coverage counts first compiles comes once that counting is armed. [390a88ad](https://github.com/Albasha0x0/Corvus/commit/390a88ad) [1f857b4b](https://github.com/Albasha0x0/Corvus/commit/1f857b4b)
- **Linux snapshots:** a program waiting in vfork is refused after 10 s instead of hanging gcore, and is left running.
  [6999b5af](https://github.com/Albasha0x0/Corvus/commit/6999b5af)
- **live_coverage:** a function's point counts its hits in the program and clears itself at the hit limit, without
  holding the thread for the server, so a covered program keeps its speed when the server is busy; points are set in
  batches of up to 256, so a run that waits for its module no longer times out on a busy machine, and a refused point
  is reported while the rest are set; a leading endbr64 or endbr32 does not count toward a hook's 5 bytes of room, so
  CET stubs are left out before any point is set, with the instructions named. Verified with Frida 17.24.3 on Windows
  11 x64.
  [0b3428ab](https://github.com/Albasha0x0/Corvus/commit/0b3428ab) [178ab701](https://github.com/Albasha0x0/Corvus/commit/178ab701) [b8f374e0](https://github.com/Albasha0x0/Corvus/commit/b8f374e0)
- **Managed coverage runs:** a run that never read the program's runtime (the program ended first, or every 32-bit
  decoder read failed) reports the methods it did not see run as unknown, marked `?`, instead of not run; the summary
  has an `unread` field. Verified on Windows 11 x64. [dc2d3ba4](https://github.com/Albasha0x0/Corvus/commit/dc2d3ba4)
- **IDA opens:** a fatal IDA error that ends the worker is named in the error, and an open that loses IDA's registry race
  ("Fatal registry error") starts a new worker, at most twice, a workaround with no upstream report yet.
  Verified on IDA 9.3. [c91989fb](https://github.com/Albasha0x0/Corvus/commit/c91989fb) [aba393c4](https://github.com/Albasha0x0/Corvus/commit/aba393c4)
- **Snapshots of a starting program:** a snapshot waits up to 10 s for the program's loader instead of failing with
  "the program changed while it was read"; a program held at its start is refused with a timeout naming
  `live_break action=continue`. Verified on Windows 11 x64 with 64-bit and 32-bit programs. [51e5cc1c](https://github.com/Albasha0x0/Corvus/commit/51e5cc1c)
- **Session starts on macOS:** a start Frida 17.24.3 times out on ("unexpectedly timed out while initializing suspended
  process") is ended and tried once more; the session names what it ended. A workaround: the 10 s limit is
  source-derived (frida-core 17.24.3, the darwin helper's target preparation), and no upstream report is filed because
  400 standalone starts on macOS, idle and loaded, did not reproduce it; not on Windows, where this timeout has not
  been seen. Verified on the macos-latest and ubuntu-latest CI images. [ccc4abd8](https://github.com/Albasha0x0/Corvus/commit/ccc4abd8)
- **get_pe_info:** the PDB line reports the finished automatic search (waiting up to 30 s, else "PDB search pending").
  [637cb40e](https://github.com/Albasha0x0/Corvus/commit/637cb40e)
- **Workspace shutdown:** waits up to 10 s for calls holding or queued for the workspace lock, and a call still in the
  lock after that keeps the assemblies until it leaves, so closing a workspace while background indexing reads an
  assembly no longer ends the server with an access violation. Verified on Windows 11 x64.
  [c79fabb0](https://github.com/Albasha0x0/Corvus/commit/c79fabb0) [6ab1239e](https://github.com/Albasha0x0/Corvus/commit/6ab1239e)
- **Pattern matching:** the built-in patterns (endpoint scans, package review rules, script tokens, stack text formats,
  values and member names, documents and databases, feature rules, package and class wildcards) have no match timeout,
  so a loaded machine no longer loses rows. A pattern from a caller or an analyzed script runs without backtracking
  where it allows; otherwise a timeout is reported as a partial result or as a timeout error naming the pattern.
  [80ef98c1](https://github.com/Albasha0x0/Corvus/commit/80ef98c1) [f38ff5f5](https://github.com/Albasha0x0/Corvus/commit/f38ff5f5) [a359a15d](https://github.com/Albasha0x0/Corvus/commit/a359a15d) [9bdcb230](https://github.com/Albasha0x0/Corvus/commit/9bdcb230) [818a1e60](https://github.com/Albasha0x0/Corvus/commit/818a1e60) [1333603c](https://github.com/Albasha0x0/Corvus/commit/1333603c) [a43e61e7](https://github.com/Albasha0x0/Corvus/commit/a43e61e7) [bbd950ac](https://github.com/Albasha0x0/Corvus/commit/bbd950ac)
  [440c9c06](https://github.com/Albasha0x0/Corvus/commit/440c9c06) [795abf97](https://github.com/Albasha0x0/Corvus/commit/795abf97)
- **Long patterns:** wildcard and substring arguments of `list_android_resources`, `list_dex_classes`, `search_dex` and
  `search_il` of any length match without a regex; a 100,000-character argument no longer fails as an internal error.
  [678a26dc](https://github.com/Albasha0x0/Corvus/commit/678a26dc)
- **External tools:** callers probing one tool at once share one version check, and a version check slower than 15 s
  leaves the tool usable with its version unknown ("its version check timed out after 15 s"), checked again on the next
  call, instead of unavailable for the server's life. [eaf5e2fe](https://github.com/Albasha0x0/Corvus/commit/eaf5e2fe) [eef57b52](https://github.com/Albasha0x0/Corvus/commit/eef57b52)
- **PyGhidra workers:** each Ghidra worker keeps its temporary files, and so PyGhidra's start lock, in its own folder, so
  workers on one machine no longer queue behind one lock and miss the 2 min start limit. A workaround for
  NationalSecurityAgency/ghidra#9988; verified with Ghidra 12.1.4 and PyGhidra 3.1.0. [ea53b9a0](https://github.com/Albasha0x0/Corvus/commit/ea53b9a0) [b25bb7c0](https://github.com/Albasha0x0/Corvus/commit/b25bb7c0)
- **Managed frames:** a frame whose method start ClrMD does not give falls back to the method's native code or its IL
  map, else reads "(offset unknown)" instead of claiming the method's entry; a hot or cold start counts only when its
  range holds the address, so a frame in code a JIT tier replaced is named from the code that holds it. ClrMD gives no
  start for the code that holds an address (microsoft/clrmd#1520, ClrMD 3.1.512801, no fix yet).
  [7c568d52](https://github.com/Albasha0x0/Corvus/commit/7c568d52) [e10ba1e9](https://github.com/Albasha0x0/Corvus/commit/e10ba1e9) [0810704b](https://github.com/Albasha0x0/Corvus/commit/0810704b)
- **Section reads:** readers that read a whole section (x86 exception frames, constant search, Itanium RTTI and unwind
  tables, Il2Cpp registration and strings, code patterns, JNI tables, NativeAOT dispatch cells) stop at its file bytes
  within SizeOfImage, so a damaged header no longer makes them allocate and scan hundreds of megabytes of zero fill
  (two readers had no cap) and slow `list_functions`; the results are the same.
  [c27ce974](https://github.com/Albasha0x0/Corvus/commit/c27ce974) [7b40138b](https://github.com/Albasha0x0/Corvus/commit/7b40138b)
- **Path arguments:** every path parameter is checked before the tool runs, so a path the host rejects (a control
  character, a reserved character on Windows, a name over 255 characters) is `invalid_argument` naming the parameter,
  and file errors are classified by type rather than by stack frames, which a Release build can inline away; every
  check names a malformed path the same way, with one hint and without echoing the path.
  [7da411d0](https://github.com/Albasha0x0/Corvus/commit/7da411d0) [23e36665](https://github.com/Albasha0x0/Corvus/commit/23e36665)
- **inspect_process:** process 0, by id or by the name Idle, is refused as the System Idle Process, and `live_session`
  neither lists it nor attaches to it. [4760f864](https://github.com/Albasha0x0/Corvus/commit/4760f864)
- **Shared records:** a note, a name or another shared record saved while another writer of the same file runs waits
  up to 30 s for it instead of 2 s, so a save on a loaded machine is no longer reported as not made. Verified on
  Windows 11 x64. [a10363c5](https://github.com/Albasha0x0/Corvus/commit/a10363c5)
- **unload_assembly:** closes an open dump id. [cdd47b37](https://github.com/Albasha0x0/Corvus/commit/cdd47b37)
- **save_assembly, save_native:** a second save over the original replaces this server's own earlier save. [aeeb5026](https://github.com/Albasha0x0/Corvus/commit/aeeb5026)
- **Paged session results:** `live_events`, `live_console` and `live_timeline` pages no longer skip rows the output budget
  cut. [df9d008f](https://github.com/Albasha0x0/Corvus/commit/df9d008f)
- **Sessions on Windows:** a program's exit no longer hangs the session after a watch burst or a close during the
  exit; the agent lets Frida's threads settle for 0.3 s first, a workaround for frida/frida-gum#1192 (Frida 17.24.0 to
  17.24.3). Verified on Windows 11 x64 with 64-bit and 32-bit programs.
  [0dde7bac](https://github.com/Albasha0x0/Corvus/commit/0dde7bac) [03aa5b70](https://github.com/Albasha0x0/Corvus/commit/03aa5b70)
- **Stuck exits:** a program held in its exit is ended by the stuck exit check even when Frida reports it terminated
  before the exit finished, including a report that comes before the agent's exit status. Verified with Frida 17.24.3
  on Windows 11 x64. [ab58b956](https://github.com/Albasha0x0/Corvus/commit/ab58b956) [7519c6cd](https://github.com/Albasha0x0/Corvus/commit/7519c6cd) [914ca460](https://github.com/Albasha0x0/Corvus/commit/914ca460)
- **attach_child on Linux:** the child is held at the first thread that runs its main module's code and its session
  attaches to the running process, so an attach under load no longer fails and leaves the child running; a child that
  reaches none of its code within 5 s runs unheld and its session says so. Verified on Ubuntu 22.04 and 24.04
  (x64 and x86 programs) with Frida 17.24.3. [f77c615c](https://github.com/Albasha0x0/Corvus/commit/f77c615c)
- **Results:** a list whose rows sit outside `items` (a timeline report) is no longer counted twice and cut short, and
  a cut record names the shortened string in its warning.
  [6805b45a](https://github.com/Albasha0x0/Corvus/commit/6805b45a) [53b82556](https://github.com/Albasha0x0/Corvus/commit/53b82556)
- **Session close:** status and the exit event name why a session closed (deadline, close, server exit) from the
  moment the close starts; a program whose exit does not finish within 10 s is ended with the exit code it chose, also
  for 20 s after a close; a close posts every awaited reply before the unload and does not unload from an exiting
  program; and two closes that meet record one close event. Verified with Frida 17.24.3 on Windows 11 x64.
  [25a8c92e](https://github.com/Albasha0x0/Corvus/commit/25a8c92e) [4de31e6c](https://github.com/Albasha0x0/Corvus/commit/4de31e6c) [0b647ef4](https://github.com/Albasha0x0/Corvus/commit/0b647ef4) [22cb80df](https://github.com/Albasha0x0/Corvus/commit/22cb80df) [3c33a59d](https://github.com/Albasha0x0/Corvus/commit/3c33a59d) [a8743b28](https://github.com/Albasha0x0/Corvus/commit/a8743b28)
- **Session exit records:** the last watch batches and the exit status are sent when the program starts to exit; a
  fatal exception sends the calls recorded before it; a start that fails after the program runs ends the program; a
  crash whose exception event was lost is recorded from the exit code; and the exit event is recorded as the state
  turns exited or failed, so a caller that waits for the state finds it. Verified with Frida 17.24.3 on Windows 11
  x64. [d6887793](https://github.com/Albasha0x0/Corvus/commit/d6887793) [5568313c](https://github.com/Albasha0x0/Corvus/commit/5568313c) [34555623](https://github.com/Albasha0x0/Corvus/commit/34555623) [fcef82ca](https://github.com/Albasha0x0/Corvus/commit/fcef82ca) [9ca10c3f](https://github.com/Albasha0x0/Corvus/commit/9ca10c3f)
- **Close during an exit:** a close that lets held threads go waits up to 1 s for the program to begin its exit and
  detaches the agent's thread and module observers first, so a close during the exit no longer leaves the exit stuck or
  crashes the program in the script runtime; the wait comes only after a resume let threads go from their stops, and a
  start or an empty resume closes at once. A workaround for frida/frida-gum#1192 and frida/frida-gum#1194. Verified
  with Frida 17.24.3 on Windows 11 x64 with 64-bit and 32-bit programs and on Ubuntu 24.04.
  [73646c40](https://github.com/Albasha0x0/Corvus/commit/73646c40) [4169abff](https://github.com/Albasha0x0/Corvus/commit/4169abff)
- **Stops on 32-bit Linux:** a stop reports the stop point's own address as its first frame and as pc and eip, so a
  stop in a child session (where the parent's agent stays loaded) no longer names an address no module covers. Verified
  on Ubuntu 24.04 (glibc 2.39) with Frida 17.24.3. [91daec47](https://github.com/Albasha0x0/Corvus/commit/91daec47)
- **Session opens on Linux:** the agent reads thread ids from `/proc` and scans it for thread ends instead of a Frida
  helper process inside the program, so a session open no longer hangs under load. It works around
  frida/frida-gum#1196. Verified on Ubuntu 24.04 x64 and x86 with Frida 17.24.3. [e7c1a1b5](https://github.com/Albasha0x0/Corvus/commit/e7c1a1b5)
- **Script loads:** `live_script action=load` names a user script's top-level exception in its reply, settled by the
  worker before it replies, so a busy machine no longer reports the script loaded without it. Verified with Frida
  17.24.3 on Windows 11 x64 with 64-bit and 32-bit programs. [b452e1c2](https://github.com/Albasha0x0/Corvus/commit/b452e1c2)
- **Session timeouts:** a call Frida gave up waiting on (its 25 s D-Bus limit, reported as `TransportError: timeout was
  reached`) is a retryable `timeout` whose Next line says to call again, not `failed`; a program the session started is
  still ended. Verified with Frida 17.24.3 on Windows 11 x64. [ae992e95](https://github.com/Albasha0x0/Corvus/commit/ae992e95)
- **Session process handles (Windows):** a session keeps a process handle only when it names the process asked for;
  Windows ignores a process id's low two bits, so an id that is not a multiple of 4 could hold an unrelated process's
  handle and delay the exit report up to 25 s. Verified on Windows 11 x64.
  [b606be33](https://github.com/Albasha0x0/Corvus/commit/b606be33)
- **Session stops:** stop points use Frida probe hooks (the listener form corrupted the caller's frame); points whose
  hooks overlap, watches past a function's start and points in a counted function's first 16 bytes are refused, and
  coverage leaves out functions that are a single jump; a thread that reaches a point after it was cleared is
  released, so the program runs on and exits; a failed deferred point always names its next step; and a process
  already in a session is refused naming it. Verified with Frida 17.24.3 on Windows 11 x64 and Ubuntu 24.04.
  [81b06731](https://github.com/Albasha0x0/Corvus/commit/81b06731) [d7a211c0](https://github.com/Albasha0x0/Corvus/commit/d7a211c0) [200faba0](https://github.com/Albasha0x0/Corvus/commit/200faba0)
  [2ea9c26d](https://github.com/Albasha0x0/Corvus/commit/2ea9c26d) [eaca5845](https://github.com/Albasha0x0/Corvus/commit/eaca5845) [5439d509](https://github.com/Albasha0x0/Corvus/commit/5439d509)
  [8d9d8b3f](https://github.com/Albasha0x0/Corvus/commit/8d9d8b3f)
- **Session frames:** a 32-bit program's system modules are read from SysWOW64; frames in a DLL with no load event yet
  are named, and status lists a DLL mapped through a delay-load import before its event arrives; a return address is
  named by its call, a library with no loaded image by its symbol table (`.symtab`, `.dynsym`), and an address before
  a function's entry reads `name-0xN`, so a stop reads the same live and in its snapshot; x86 stops no longer show the
  stopped address or its caller twice, and x86 caller searches keep a slot budget of their own; and Linux stops in
  generated code find their caller by a stack scan checked by CFI. Verified with Frida 17.24.3 on Windows 11 x64 and
  Ubuntu 24.04.
  [9b2cb02a](https://github.com/Albasha0x0/Corvus/commit/9b2cb02a) [90bc92ce](https://github.com/Albasha0x0/Corvus/commit/90bc92ce) [1fe7f090](https://github.com/Albasha0x0/Corvus/commit/1fe7f090)
  [9038ff64](https://github.com/Albasha0x0/Corvus/commit/9038ff64) [0f52adbe](https://github.com/Albasha0x0/Corvus/commit/0f52adbe) [e0e2ff0d](https://github.com/Albasha0x0/Corvus/commit/e0e2ff0d)
  [7fba2d2e](https://github.com/Albasha0x0/Corvus/commit/7fba2d2e) [d1db038f](https://github.com/Albasha0x0/Corvus/commit/d1db038f) [0dabe008](https://github.com/Albasha0x0/Corvus/commit/0dabe008)
- **Containers:** a squashfs inode whose header ends in the next metadata block is read; a second module-info `provides`
  entry reads its own class; the hint for a file that is no container no longer calls tar, gzip and xz unread; an
  8-byte array-data element in int range is written without the `L` suffix, as baksmali writes it; Il2Cpp cache entries
  used within 10 minutes, or held by a workspace or server that has files loaded from them, are not trimmed, so another
  reader keeps its binary. [cf6152a3](https://github.com/Albasha0x0/Corvus/commit/cf6152a3) [e663fd5c](https://github.com/Albasha0x0/Corvus/commit/e663fd5c)
  [69e94bb0](https://github.com/Albasha0x0/Corvus/commit/69e94bb0) [1a2c97dc](https://github.com/Albasha0x0/Corvus/commit/1a2c97dc) [ee07ed25](https://github.com/Albasha0x0/Corvus/commit/ee07ed25) [3bb26142](https://github.com/Albasha0x0/Corvus/commit/3bb26142) [18937632](https://github.com/Albasha0x0/Corvus/commit/18937632)
- **server_status:** fits its report budget again with every external tool configured. A tool set in its variable is
  named by that variable, the workers section lists at most 3 processes per program, and a fix already given in
  unavailableTools is not repeated. [f6085507](https://github.com/Albasha0x0/Corvus/commit/f6085507)
- **server_status wait:** status waits at most 5 s for the engine and external program checks; a version check still
  running reports the program usable with its version unknown, an engine check still running keeps the engine's tools
  listed, and the next call reads the finished result; a cache folder's first count runs on a thread of its own, so a
  small folder answers within its 2 s wait on a busy machine. Verified on Windows 11 x64, including a contract sweep
  limited to two cores. [2efbd420](https://github.com/Albasha0x0/Corvus/commit/2efbd420) [91f7a047](https://github.com/Albasha0x0/Corvus/commit/91f7a047)
- **Result hashes:** a result's `resultSha256` leaves out workspace notices, so a recorded note call reruns to the
  same hash when a one-time notice (such as one about unsaved edits a stopped session left) is attached; results
  without a notice hash as in 2.4.0. [b4715960](https://github.com/Albasha0x0/Corvus/commit/b4715960) [d1cfc7d3](https://github.com/Albasha0x0/Corvus/commit/d1cfc7d3)
- **Kept results:** a kept-result folder past its size limit is trimmed to 75% of it, so writes walk the folder at most
  once per quarter of the limit instead of on every write; a 100,000-character `comment_native` on a folder of 48,000
  files took 2.2-6.0 s per call before and about 0.5 s now. [276b5687](https://github.com/Albasha0x0/Corvus/commit/276b5687)
- **Call log:** passwords in URLs are masked in time linear in the text, so a long string argument (a comment, a
  script, a pattern) no longer takes seconds to log; 400,000 letters took 4.3 s before, and the 100,000-character
  `comment_native` call takes 0.12 s with both fixes. [70e4fc70](https://github.com/Albasha0x0/Corvus/commit/70e4fc70)
- **IDA starts:** an open's start (loading idalib) is stopped after 60 s without progress from the worker, within the
  open's own limit, instead of after 60 s in all; the error names the quiet limit. Verified with IDA 9.3 on
  Windows 11 x64; the stop under a slow start was not reproduced on demand. [c72de6da](https://github.com/Albasha0x0/Corvus/commit/c72de6da)
- **Session memory reads:** `live_read` reads a stack or heap address that falls in an image's preferred range
  (ImageBase to ImageBase+SizeOfImage) where the program has it, instead of in the image ASLR loaded elsewhere; stop
  point addresses keep the image translation. Verified with 32-bit and 64-bit programs on Windows 11 x64. [c6bce07b](https://github.com/Albasha0x0/Corvus/commit/c6bce07b)
- **Code coverage:** a coverage run's points are cleared in requests of up to 256 instead of one request each, so a
  run over a whole image releases its program at exit sooner (a 2,959-function run: 53 s before, 11-14 s now, and
  minutes under load before); a backend without batches clears each point alone as before. Verified with Frida
  17.24.3 on Windows 11 x64. [15da2f05](https://github.com/Albasha0x0/Corvus/commit/15da2f05)
- **Call deadlines:** a client's call deadline counts from when the request reaches the server, so setup before the
  call runs (up to 0.3 s on a fresh server under load) no longer extends the answer past the client's wait. [46dd5e3b](https://github.com/Albasha0x0/Corvus/commit/46dd5e3b)
- **Script readings:** `summarize_file`'s script view and package review keep the 2.4.0 step budget of 4,000,000 steps
  and triple the time limits (12 s, 4.5 s for the overview and package review, 2.25 s per script block), so a reading
  on a busy machine is no longer cut short at the 2.4.0 limits; a note names the limit that stops a reading, time or
  JavaScript steps, and marks it partial. [a10c24d6](https://github.com/Albasha0x0/Corvus/commit/a10c24d6)
- **Ghidra starts:** a Ghidra worker's start is stopped only after its processes use less than 1% of a core for 2 min,
  within the open's 20 min limit, instead of after 2 min of wall time whatever it was doing, so a JVM start starved of
  CPU on a busy machine finishes; the error names the limit that stopped it, and where CPU time cannot be read a start
  stops after 2 min as before. Verified with Ghidra 12.1.4 on Windows 11 x64. [8a378f59](https://github.com/Albasha0x0/Corvus/commit/8a378f59)
- **server_status tool checks:** the checks of JADX, Java and adb for the tool availability list run side by side
  within what is left of the status deadline, instead of one after another with 5 s each, which added up to more than
  20 s under load. [cf70a298](https://github.com/Albasha0x0/Corvus/commit/cf70a298)
- **Worker request limits:** a silent worker request stopped by its quiet limit is named as such; it could be reported
  as stopped by its overall limit (once in 3,200 requests under load), so a worker that went silent read like one that
  ran out of time. [5678530f](https://github.com/Albasha0x0/Corvus/commit/5678530f)
- **Frida install:** `--live-install-frida` makes its private Python environment without copying pip into it when the
  base Python's pip is 22.3 or later, so the environment is ready in seconds (4.4-18.9 s) instead of running past its
  2-minute limit on a loaded machine. Verified with Frida 17.24.3 on Windows Server 2025 x64, Windows 11 arm64,
  Ubuntu 24.04 x64 and macOS 26 arm64. [dae54009](https://github.com/Albasha0x0/Corvus/commit/dae54009)
- **Device calls:** a device tool runs adb as soon as it finds it, without first waiting for an `adb version` check, so
  the first device calls of a server no longer wait on that extra program run under load; a missing adb is still named
  with the reason. [5fe21a55](https://github.com/Albasha0x0/Corvus/commit/5fe21a55)
- **Call answers:** a finished call answers without taking the workspace lock again: provenance and recent-call inputs
  read the last published set of loaded targets, and a call that changed nothing skips the edit journal sync, so a long
  exclusive holder (a cold C# compile) no longer holds back other answers past their deadline. [42a3440e](https://github.com/Albasha0x0/Corvus/commit/42a3440e)
- **.NET decompiles:** decompiles no longer open the assembly's XML doc file, which Corvus never shows: it cost 10-15% of
  a large type's first decompile, and a doc file another process held open turned a whole-type decompile into
  member-by-member output. A workaround for icsharpcode/ILSpy#4275, verified with ICSharpCode.Decompiler 11.1.0.9782. [22ec63c5](https://github.com/Albasha0x0/Corvus/commit/22ec63c5)
- **Process launches (Windows):** a child's launch holds the process creation lock only while its pipe ends are
  inheritable and starts its exit thread after releasing it, so concurrent launches no longer queue behind each other
  (lock held 34 ms at the median and 199 ms at p90 before, 3.9 ms and 29.6 ms now, under load). [6ba784e3](https://github.com/Albasha0x0/Corvus/commit/6ba784e3)
- **simplify_methods time limits:** the 5 s per-method limit and the 30 s limit per type initializer run count the
  thread's CPU time instead of wall time, so a loaded machine folds the same methods as a quiet one; a method also stops
  at 3 times its limit of wall time, and wall time is used where the CPU time cannot be read. [aadaf6d6](https://github.com/Albasha0x0/Corvus/commit/aadaf6d6)
- **Virtual call checks:** a virtual call cross-check against IDA or Ghidra no longer stops the engine when one
  decompilation runs past its batch's budget on a loaded machine: that decompilation now gets a full request limit, so
  a batch can take one request limit (2 min by default) longer, and the check's overall deadline still bounds it.
  Verified with IDA Pro 9.3 and Ghidra 12.1.4 on Windows 11 x64. [a4f6aa25](https://github.com/Albasha0x0/Corvus/commit/a4f6aa25)
- **Worker starts:** a pooled worker's start, the files worker's among them, is stopped only after it uses less than 1%
  of a core for 30 s, within three times that (90 s by default), instead of after 30 s of wall time, so a cold start on
  a busy machine finishes and a Yara scan or container search no longer fails with a start timeout; where CPU time
  cannot be read a start stops after 30 s as before. [aa7a35cd](https://github.com/Albasha0x0/Corvus/commit/aa7a35cd)
- **Python searches:** each candidate interpreter's probe (for the IDA and Frida workers, doctor and setup) is stopped
  only after it spends 15 s under 0.1% of a core, within 45 s overall, instead of after 15 s of wall time, so a loaded
  machine no longer reads IDA as unavailable or finds no Python 3; the candidate log names the limit that stopped a
  probe. [f0035bbb](https://github.com/Albasha0x0/Corvus/commit/f0035bbb)
- **IDA decompiler licenses:** a native decompile the IDA license cannot run, because it lacks the Hex-Rays decompiler
  for that processor, fails as `unsupported`, names the missing decompiler and its bitness, and suggests `engine=ghidra`
  or `disassemble`, instead of a failure whose Next: line asked to start IDA and accept the license terms. Verified with
  IDA 9.3 on Windows 11 x64. [b5a5c246](https://github.com/Albasha0x0/Corvus/commit/b5a5c246)
- **Session tool details:** a stop that arrives before the resume reply is kept, and the program's own module is
  found by the path the OS reports; `live_break` wait ended by the program's exit says it ended and how, and `continue`
  with a thread on a suspended program that holds nothing says it is still suspended; a spawn of a missing file is
  refused before a worker starts; an open that times out says the program did not load the agent in time; a script
  load checks once more for a first error when its wait ends; `live_coverage` reads a loaded module's code from its
  file when its image is not loaded, and a run whose program ends first stays ended; `live_read` takes `uint32 [4]`
  and `uint32[ 4 ]` as array types; `live_timeline` diff keeps a side's later lines at its first line's column; and on
  Windows the stop handler looks up symbols in the agent's folder only, so stops add no symbol file lookups to the
  program's activity.
  [24c47f48](https://github.com/Albasha0x0/Corvus/commit/24c47f48) [811104d1](https://github.com/Albasha0x0/Corvus/commit/811104d1) [88351ba8](https://github.com/Albasha0x0/Corvus/commit/88351ba8) [9ad90796](https://github.com/Albasha0x0/Corvus/commit/9ad90796) [91b92c54](https://github.com/Albasha0x0/Corvus/commit/91b92c54) [82e7f346](https://github.com/Albasha0x0/Corvus/commit/82e7f346) [680bfe02](https://github.com/Albasha0x0/Corvus/commit/680bfe02) [bbb845e9](https://github.com/Albasha0x0/Corvus/commit/bbb845e9) [dfb00783](https://github.com/Albasha0x0/Corvus/commit/dfb00783) [82557323](https://github.com/Albasha0x0/Corvus/commit/82557323) [f2afc731](https://github.com/Albasha0x0/Corvus/commit/f2afc731) [e46ae343](https://github.com/Albasha0x0/Corvus/commit/e46ae343) [1d551ef5](https://github.com/Albasha0x0/Corvus/commit/1d551ef5)
- **Managed names at a stop:** a session's .NET runtime that could not be read is tried again 5 s after the last try
  as well as when the program loads a module, so a stop whose thread is held no longer keeps its managed frames
  unnamed; the first failed read is named once in the session's events. [a21afade](https://github.com/Albasha0x0/Corvus/commit/a21afade)

## 2.4.0

165 tools and 15 prompts (2.3.0 had 156): nine session tools are new, in the `live` family and off by default. Record
changes are listed under **Changed**; the native code index is built again once (persist format 16).

- **Session tools** (behind `--allow-live`; starting a program also needs `--allow-live-spawn`, user scripts
  `--live-scripting`). `live_session` opens a session on a local program (open, spawn, list processes, save a
  snapshot as a standard dump that the dump tools open); `live_break` sets stop points by name, `module!export`,
  `file:line` or address and reads named stacks, typed registers and memory (`live_read`); `live_events` pages a
  session's events with a cursor. `live_watch` records each call of a function with its arguments and return value,
  decoded from the known-API table, PDB prototypes or DWARF parameter names. `live_coverage` collects function coverage
  of an image, draws it on the static call graph and compares two runs. `live_timeline` records the files, registry keys,
  endpoints and child processes a run touches from the OS event trace (ETW on Windows) and compares two runs.
  `live_console` drives a console program through a console host (send, wait, resize) with a paged transcript.
  `live_script` loads a user-supplied script. Saved session records verify through `read_result format=verify` by
  their named addresses; `inspect_process` takes a session id.
- **Notes as a hypothesis ledger.** Note evidence links a kept result or `last:N` that supports or refutes it;
  `update_note verify=true` re-checks each record and marks the hypothesis confirmed, refuted or open.
- **Documents.** `summarize_file view=office` (OLE and OOXML documents, VBA modules, Excel 4.0 macro sheets, embedded
  packages, encrypted OOXML under well-known default passwords), `view=pdf` (objects, streams and scripts as pdf-parser lists
  them; keyword counts as pdfid), `view=lnk` (a shortcut's target as the shell resolves it) and OneNote embedded files.
- **Installers and disk images.** Cabinets (MSZIP, LZX) and Windows Installer packages extract and list;
  `summarize_file view=installer` shows custom actions, registry, services and shortcuts. ISO 9660 (Joliet, Rock Ridge,
  El Torito), UDF, VHD, VHDX, MBR / GPT and NTFS images list and extract.
- **Scripts and packages.** `summarize_file view=script` reads PowerShell, VBScript / VBA, batch and JavaScript with
  their transformation layers decoded to plain text by bounded evaluators, nothing run. `view=package` reviews npm,
  PyPI, VS Code and browser extension packages before installing: install-time scripts, entry points, permissions,
  native binaries, signature and hash checks, names close to popular packages.
- **Firmware.** squashfs 4.0, cramfs, ext2/3/4, FAT, cpio, JFFS2, UBI / UBIFS, uImage, FIT, Android boot and TRX
  images read and extract in-process on every OS; `view=firmware` validates 143 header signatures.
- **Captures.** `unpack_container` on a pcap reassembles TCP and writes HTTP/1.x and HTTP/2 objects, decrypting TLS
  1.2 / 1.3 with a key log; JA3 / JA4 fingerprints. `search_container kind=request` pages a HAR, mitmproxy or `.saz`
  capture's requests as a stream; two captures compare as API diffs. Source maps unpack to their original tree.
- **JavaScript and Electron.** `search_container kind=electron` reads windows, preloads, bridge methods and IPC
  channels from the syntax tree; `kind=feature` follows a UI or log text to its handler. `analyze_js` adds
  `view=endpoints`, `secrets`, `diff` (two builds module by module), `runtime` (the webpack runtime), `flow` and
  `origins` (data flow through assignments, calls and the Electron bridge). `unpack_container` writes a bundle's
  modules as files. Hermes bytecode 59-96 reads, disassembles and decompiles through `analyze_js` and
  `summarize_file view=hermes`.
- **Mobile and managed.** `survey_features` on Android and Apple apps lists platform security findings (WebView bridges,
  TLS trust, cleartext, pinning, dynamic loading, embedded keys) at their method and offset. `summarize_file
  view=layers` joins an APK's DEX, native, .NET, Il2Cpp and JS layers. `decompile_java` keeps output on disk and puts
  R8 / ProGuard names into the Java text; jars and `.class` files disassemble as `javap -c -p` does. WPF `.baml`
  resources show event handlers joined to their methods. NativeAOT static fields get names in the name layer.
- **Debug info.** PDB line tables: `resolve_address` shows file and line, stop points take `file:line`. DWARF adds
  split units (`.dwo`, `.dwp`), dwz supplementary files, relocatable objects, Mach-O debug maps, and the parameters and
  locals in scope at an address. ELF core stacks unwind through DWARF CFI expressions (ppc64, s390x, riscv64).
- **Engines.** Ghidra's standard profile answers sooner (libSkiaSharp first answer 434 s to 348 s), reads DOS jump
  tables, takes C++ enum bases and default calling conventions, runs `ghidra_script` in Python through PyGhidra
  (`CORVUS_GHIDRA_PYTHON`), and works on Ghidra 12.0. A WebAssembly module for Ghidra answers unsupported at once when
  no loader is installed. Native accuracy: x86 switch bounds, ARM32 literal pools and no-return calls, ARM64 jump
  tables (recall 100); ARM32 discovery runs in parallel.
- **Large inputs.** APK, IPA, plist, mitmproxy flows, WebAssembly and native images over 64 MiB read in ranges or as
  streams (a 1 GiB APK summary from +1 GB to +15 MB of memory). SQLite reads `ADD COLUMN` defaults and carves
  `WITHOUT ROWID` tables.
- **Changed.** `inspect_instruction` pages its walk as a list; `offset` is a row offset. `get_native_type` and
  `resolve_call_targets` records leave out false, zero and empty fields. `load_assembly`, `reload_assembly`,
  `unload_assembly` and `add_search_directory` return typed records instead of a copy of the text. Note files are
  written as `corvus-notes/3` (version 2 still reads). The 15 list tools that lacked it take `maxTokens`.
- **Fixes.** `save_assembly` writes a ReadyToRun image with no header room for a new section as IL only and says so.
  The command line reads and writes UTF-8 when redirected. `engine=auto` answers from the built-in index when another
  session holds the saved analysis. `server_status` no longer walks cache folders on its own time.
  `corvus update` on Linux and macOS deleted the version it was running from and then failed while refreshing
  client registrations (the update itself was installed); it now keeps that version until the next update. Updating
  from 2.3.0 or older still shows the failure once: run `corvus install --refresh-only` afterwards.

## 2.3.0

156 tools and 15 prompts, as in 2.2.0: everything new is a parameter, a view or a kind of an existing tool. No breaking
changes; engine output stored by 2.2.0 is computed again once (the cache layout changed).

- **Evidence as input.** `compare_assemblies`, `compare_native_images`, `compare_folders` and `diff_function` take
  `oldResult` / `newResult` (a kept result, `last:N` or a bundle entry) and compare them without running anything;
  `read_result format=verify` takes one bundle entry and `against=`. What a side does not show is `unknown`, never
  removed, added or equal: a page of a longer result, a result that is not complete, or a facet either side lacks.
- **Completeness per facet.** Function results name `pseudocode`, `callers`, `callees`, `xrefs`, `strings` and `cfg` as
  available or unavailable (with the reason) in the provenance and in `coverage.facets`; a record that says it stopped
  early (`truncated`, `cut`, `incomplete`, `partial`) has coverage `partial`.
- **Engine databases.** `docs/engine-databases.md` states the contract (identity, reuse across sessions and command-line
  calls, invalidation, the user's own databases) with measured cold and warm times. `load_assembly` opens a Ghidra
  project (`.gpr`, `program=`) from a copy, leaving the original untouched. Import overrides (processor, language,
  compiler spec, seeds, disabled analyzers) apply before the first analysis in both engines.
- **Engine edits.** `declare_native_types` inserts fields with the later ones moved down, resizes a struct and names its
  gaps; `set_native_local inferStruct=` (Ghidra) declares a struct from a pointer's loads and stores and types the local,
  `storage=` moves an argument to a register (IDA `__usercall`, Ghidra custom storage); `define_native kind=flow`
  (Ghidra) sets or clears a flow override and repairs the function. `set_native_stack_var` and `set_native_operand`
  take `items=` batches, and `get_native_frame` reads several functions in one request. Stack edits carry their offset
  from the return address, so a member made in IDA lands in the same slot in Ghidra. Ghidra refuses a calling
  convention its compiler spec lacks and names the ones it has.
- **Engine output cache.** Renaming a local or a stack member makes only that function's stored answers stale.
- **Emulation.** `emulate_native candidates=` runs many argument sets on one emulator in one request.
- **Debug info.** `load_pdb` reads DWARF 2–5 for ELF and Mach-O (the image's sections, `.build-id` and `.gnu_debuglink`
  files, dSYM bundles, debuginfod on request) into names, types, prototypes with parameter names, source lines and
  inlined frames, pushed into IDA and Ghidra.
- **WebAssembly.** A `.wasm` file loads as a native image: WAT byte-equal to `wasm2wat`, a lifted view, calls, xrefs,
  CFG and strings; `summarize_file view=wasm` validates in-process (verdicts equal to `wasm-validate`) and joins the
  imports to their JS glue; `compare_native_images` compares two builds' interfaces and function bodies.
- **Network.** `search_container kind=packet` filters pcap / pcapng captures with Wireshark display filters, no TShark
  needed (HTTP/2, QUIC Initial server names, SMB2, NTLMSSP and Kerberos names too; other fields through TShark).
  `kind=endpoint` lists the endpoints an APK, .NET or Mach-O app's code names (Retrofit, OkHttp, Ktor, HttpClient,
  Refit, gRPC) and joins them with a capture. `summarize_file view=protobuf` rebuilds embedded descriptors as `.proto`.
- **Formats and managed code.** `get_il source=true` (Portable PDB sequence points, local names, SourceLink),
  `get_attributes` typed arguments and `[Flags]` members, FieldRVA data in `get_type_info`, Il2Cpp metadata without the
  binary, protection product identification with evidence, `view=sqlite` paging and recovery, streamed reads of files over
  64 MiB, Win32 resource details, `search_bytes` nibble and bit masks, R8 / ProGuard mappings for DEX, Flutter string
  pools, an Objective-C header export and Android screen and bugreport views.

## 2.2.0

156 tools and 15 prompts (2.1.0 had 13): `investigate_feature` and `check_reimplementation` are new prompts. No
breaking changes.

- **Model gateways.** Every tool's input schema stays inside the subset the strictest model gateways accept (no `$ref`
  or combinators, one declared type, typed array items, depth ≤ 10); `corvus status` names any tool outside it.
- **Untrusted-content marker.** Every result that may quote the analyzed file, errors included, carries
  `untrustedContent: true` and `source: analysis_target` in its provenance.
- **Long engine opens.** An open that outlasts the call's deadline answers with its stage and seconds so far
  (`details.stage`, `details.seconds`); calling again picks up the same open.
- **Captures.** `summarize_file view=pcap` reads pcap and pcapng as a stream: flows, DNS names and answers, TLS server
  names and ALPN (split ClientHellos joined) and HTTP/1.x requests, with every cap stated. `search_container
  kind=endpoint` also reads pcap captures and Fiddler `.saz` sessions.
- **Formats.** New `summarize_file` views: `sqlite` (own B-tree reader: schema, row counts, sample rows), `flutter`
  (Dart AOT snapshot version, features and engine build id) and `rust` (cargo-auditable dependency lists in ELF, PE
  and Mach-O). `get_pe_info` reports ELF CET, BTI and PAC from the GNU property note, and reads 8-byte aligned notes
  correctly.
- **Linux and Android crash dumps.** `open_minidump`, `dump_stack`, `read_dump_memory` and `bucket_minidumps` read ELF
  core files: threads, registers, the signal, modules matched by build id, and stacks unwound through `.eh_frame`.
- **Native.** `survey_features` finds crypto and hash constants (AES, SHA-2, MD5, SHA-1, CRC-32, Blowfish, ChaCha,
  TEA, FNV, MurmurHash3) and more environment-check checks (hypervisor ids, analysis-tool names).
  `search_instructions value=min..max` searches a constant range. NativeAOT frozen strings name their MethodTable.
- **Engines.** `set_native_type` with a no-return prototype stops the callers' flow at the call in IDA and Ghidra.
  `ghidra_script` compiles a script once per source and runs installed scripts by `name=` with arguments.
  `get_engine_status` lists Ghidra's analysis errors and warnings.
- **Evidence.** `read_result format=evidence` bundles kept results or the latest calls with their provenance;
  `format=verify` runs them again and names what changed. The new prompts walk from a behaviour to the code behind it
  and check a reimplementation by emulation.
- **Android and Unity.** `get_android_device_info` gains `view=processes|features|services|settings|files`.
  `unity_overview` reads Mono APKs, zipped Windows and Linux builds in place, and WebGL builds.
- **Release testing.** `test.ps1 -Full -Reuse` reruns only the test families whose inputs changed since their last
  pass; patch releases gate on it, minor releases still run the whole exhaustive suite.

## 2.1.0

156 tools (2.0.2 had 155): `analyze_js` is new, in the `web` toolset. No breaking changes.

- **Raw images.** `load_assembly format=raw arch= base= entry=` maps headerless code (firmware, ROM dumps, raw blobs).
  Our index decodes x86, x64, ARM, Thumb and ARM64; MIPS, PowerPC, RISC-V and 6502 go to IDA and Ghidra, which set
  the processor, bitness, base and entry before analysis. DOS `.COM` (`x86-16`) and MZ (`dos-mz`) images load too.
  Each layout gets its own id (`name[x64@0x400000]`), database and project.
- **JavaScript bundles.** `analyze_js` reads bundlers and source maps (a minified `line:column` maps to the original
  source and name), module tables (webpack, esbuild, Browserify, Parcel, Metro, AMD, SystemJS, Rollup/Vite chunks),
  each module's requires and dependents, and strings and names with their original positions. It also identifies
  Hermes bytecode.
- **Electron.** `search_container kind=electron` lists preload scripts, contextBridge keys, IPC channels, process
  and shell sinks and native add-ons (with their N-API registrations), each with `file:line:column`.
  `compare_folders` compares `.asar` archives entry by entry.
- **Captures.** `search_container kind=endpoint` gives a capture's request templates, with id segments folded and
  query values hidden.
- **Archives and formats.** tar (plain, gz, bz2, xz), 7z, RAR, single gzip/bzip2/xz files, xar (macOS `.pkg`) and
  cpio open as containers, with limits that stop archive bombs. New `summarize_file` views: `wasm` (imports,
  exports, toolchain, names) and `firmware` (formats found at their offsets inside an opaque image).
- **Apple.** New `summarize_file` views: `apple` (an `.ipa` or `.app`: Info.plist, each Mach-O's role and signature
  verdict, entitlements, provisioning profile), `plist` (keyed archives decoded) and `nib` (classes, outlets and
  actions, with each action resolved to its implementation). `verify_native_imports` resolves Mach-O load commands
  as dyld does.
- **Ghidra.** Ghidra archives (`.gzf`) load directly. A completion pass after the standard analysis finds more
  references while the image stays usable. `reanalyze_native` takes `background=true` and `preset=`.
  `decompile_native view=pcode` shows high p-code. Warm cross-reference queries are 2–30× faster.
- **Fixes.** `server_status` no longer walks the engine cache on every call (about 950 ms down to 20 ms), and
  reference-pack downloads time out instead of stalling a search.

## 2.0.2

- **Package metadata.** The NuGet package, the MCP bundles and the license name the maintainer as Albasha0x0. This is
  the first release published on nuget.org and in the MCP Registry.
- **Release script.** `release.ps1` waits for the release run of the tag's commit.

## 2.0.1

- **Security.** Built with .NET SDK 10.0.402: the self-contained builds carry runtime 10.0.13 (the October 2026 .NET
  security release), and `System.Security.Cryptography.Pkcs` is 10.0.13 (CVE-2026-84008, CVE-2026-70162). Update
  framework-dependent installs (`dotnet tool`, `dnx`) to a 10.0.13 runtime.
- **nuget.org and the MCP Registry.** The `CorvusRE` .NET tool package carries a README (with the registry's ownership
  line), so it is published on nuget.org (`dotnet tool install -g CorvusRE`, or `dnx CorvusRE --yes`) and listed in the
  MCP Registry as `io.github.Albasha0x0/corvus`.
- **Unsaved-session notice stays one line.** Loading an image with many abandoned edit or patch sessions names the
  newest one with its replay command and counts the older ones, instead of one line per session.
- **Release assets** ship under the `corvus` name only.
- **Docs.** A shorter README; feature detail in [features.md](features.md), server options in
  [configuration.md](configuration.md#server-options).

## 2.0.0

155 tools (1.3.0 had 158): `decompile_type`, `decompile_assembly_attributes` and `find_overrides` are folded into other
tools. This is the breaking release. Every tool now follows one output contract: a structured record with an output
schema on every tool, a list envelope `{items, offset, limit, total, totalExact, hasMore, nextOffset}` on every list,
a token budget per part (text and structured content are each fitted to it), errors with a `Next:` line, and long or
cut results kept under an id that `read_result` pages. Edit tools preview by default (`dryRun=true`). Parameter names,
paging units and record shapes changed across every family; the checklist below covers what a 1.x caller must change.

### Upgrading from 1.x

- **Edits preview by default.** Every .NET and native edit tool, and `migrate_native_names`, defaults to `dryRun=true`
  and ends with "Nothing changed (dry run); pass dryRun=false to apply". Pass `dryRun=false` to apply.
- **Removed tools.**

  | Removed | Use instead |
  |---|---|
  | `decompile_type` | `decompile_member` with the type |
  | `decompile_assembly_attributes` | `get_attributes format=csharp` |
  | `find_overrides` | `find_references kind=overrides` |

- **Renamed parameters** (no aliases):

  | Tool | 1.x | 2.0 |
  |---|---|---|
  | every tool with a size limit | `maxChars` | `maxTokens` |
  | `find_call_paths` | `maxPaths` | `limit` (with `offset`) |
  | `diff_function` | `maxLines` | `offset`, `limit`, `maxTokens` |
  | `inspect_instruction` | `count` | `limit` |
  | `ida_python` | `maxOutput`, `file` | `maxTokens`, `scriptPath` |
  | `ghidra_script` | `timeout` | `timeoutSeconds` |
  | `find_virtual_calls`, `emulate_native`, `reanalyze_native` | `seconds` | `timeoutSeconds` |
  | `search_decompiled` | `cursor`, `seconds` | `offset`, `timeoutSeconds` |
  | `search_instructions`, `reanalyze_native` | `start`, `end` | `from`, `to` |
  | `list_imports` | `module` | `library` |
  | `load_pdb` | `force` | `allowMismatch` |
  | `patch_bytes`, `patch_asm` | `force` | `allowUnsafe` |
  | `export_engine_database` | `force` | `overwrite` |
  | `get_resource`, `get_android_resource` | `savePath` | `outputPath` |
  | `export_edits`, `save_session` | `path` | `outputPath` (parameter and record) |
  | `undo_native_edit` | `number` | `editId` |

- **Booleans that now default to false**, under a new name with the opposite sense. Omitting them behaves as before.

  | Tool | 1.x | 2.0 |
  |---|---|---|
  | `apply_edits` | `stopOnError=true` | `continueOnError=false` |
  | `compare_assemblies` | `listAddedRemovedTypes=true` | `typeCountsOnly=false` |
  | `decompile_java` | `smaliFallback=true` | `javaOnly=false` |
  | `disassemble` | `function=true` | `fromAddress=false` |
  | `dump_stack` | `exceptionContext=true` | `dumpTimeContext=false` |
  | `install_android_package` | `replace=true` | `keepInstalled=false` |
  | `read_dump_memory` | `imageFallback=true` | `dumpOnly=false` |
  | `trace_native_values` | `followGlobals=true` | `stopAtGlobals=false` |
  | `unpack_container` | `load=true` | `extractOnly=false` |
  | `comment_native` | `dedupe=true` | `repeatLine=false` |
  | `find_call_paths` | `includeVirtual=true` | `directOnly=false` |
  | `find_references` | `includeVirtualCalls=true` | `directOnly=false` |
  | `list_types` | `includeNested=true` | `topLevelOnly=false` |
  | `migrate_native_names` | `comments=true` | `namesOnly=false` |
  | build tools | `useNames=true` | `codeOnly=false` |

  `set_native_type` now defaults `rename` to false, and `get_native_frame` needs `locals=true` for decompiler locals.
- **Lists take arrays.** Parameters that took a separated string are arrays: `record_note` / `update_note` tags,
  `compare_folders` `exclude` (globs), `extract_strings` `types`, `simplify_methods` `passes`, `compare_assemblies`
  `changes`, `migrate_native_names` `sources`, `search_code_pattern` `images`, `update_to_new_build` `include`,
  `oldIl2Cpp` and `newIl2Cpp`.
- **Paging counts rows.** `offset` counts rows, nodes, blocks or bytes as each tool states, never characters; continue
  with the `nextOffset` the result gives. `truncated` is gone from every record: `hasMore`, `nextOffset` and
  `totalExact` say it. Most default page sizes are smaller (listed per family below); `maxTokens` raises a page.
- **Records changed.** Row arrays are named `items` almost everywhere, and many fields were renamed or dropped. The
  full described schema of every tool is in [docs/schemas](schemas/). By default the text part is readable rows, not
  the record's JSON: read values from the structured content (`CORVUS_RESULT_MODE=json` restores a JSON copy in the
  text).
- **Edit ids.** .NET edits are numbered `<assembly>#<n>` and native edits `<image>#<n>`. The ids are stable: undoing
  an edit no longer renumbers the others. `undo_edit` and `diff_edits` take the id in `number`; `undo_native_edit`
  takes `editId` (`image#n`, `#n` or `n`, or a comma list).

### Changes in behaviour

#### .NET read

- **Consolidated tools.** `decompile_member` decompiles a whole type, `get_attributes format=csharp` gives assembly
  attributes as C#, and `find_references kind=overrides` lists overrides.
- **List contract.** Every .NET list tool returns the list envelope, pages by rows with `[More: offset=N]` /
  `[End: …]` footers ("N things (showing a-b)") and takes `maxTokens`. `get_call_tree` and `compare_assemblies` page
  by rows (was characters), `get_call_tree` loses `maxNodes`, and `list_resources` gains `offset` and `limit`.
- **New parameters.** `get_type_info` `section`, `offset`, `limit`; `get_assembly_info` `view` (default `summary`;
  references, tables and heaps only in their views); `get_attributes` `format`, `offset`, `limit`, `maxTokens`;
  `get_type_hierarchy` and `resolve_symbol` `offset`, `limit`; `search_il` `context`; `export_project` `overwrite`.
- **Default limits.** `list_namespaces` 2000 → 200, `list_types` 300 → 150, `find_references` 300 → 150,
  `find_callees` 2000 → 200, `search_strings` and `search_constants` 200 → 100, `get_r2r_code` `maxInstructions`
  5000 → 1500.
- **Records.** `TypeEntry.fullName` → `name`, and `kind` is absent for a plain class; `MemberEntry.ilInstructions` →
  `il`. Member references are flat (`label`, `token`, `assembly`); `find_references` shows the member only where it
  changes and `get_call_tree` rows lose `id`/`parent` and show `depth` only where it changes; `basis` appears only when
  derived. New records for `get_attributes`, `get_type_hierarchy`, `decompile_member`, `get_il`, `get_resource`,
  `get_r2r_code` and `find_r2r_method`.
- **`get_type_info`.** `nestedTypes`, `fields`, `properties`, `events` and `methods` become one `items` array with
  `kind`, plus `counts`. The default `section=summary` lists the first 8 of each kind. The top-level `fullName` moves to
  `type.label`; member rows drop `name` (they carry `token`, `signature`, `kind`, `il`; a constructor shows the type
  name).
- **`export_project`** is annotated destructive. It decompiles a private snapshot outside the workspace lock, writes
  through a staging folder (whole or not at all), replaces a previous export with `overwrite=true` and returns a
  record.

#### .NET edits

- **Preview by default** on `rename_symbol`, `rename_namespace`, `stub_method`, `patch_method_csharp`,
  `patch_method_il`, `add_members_csharp`, `add_types_csharp`, `simplify_methods` and `apply_edits`.
  `patch_method_csharp`, `add_members_csharp`, `add_types_csharp`, `undo_edit` and `apply_edits` are marked
  long-running and report progress.
- **Records.** All 15 edit tools return records. A single edit gives `{applied, dryRun, changes[{kind, target}],
  editIds}`, and its text ends "Edit <id>. Unsaved edits in …". `list_edits` pages rows (`offset`, `limit`,
  `maxTokens`) of `{number, editId, tool, description}`.
- **`apply_edits`.** A rolled-back script, or one where every edit failed, is now an error with code `failed` and
  per-edit items in `partial` (was success); items carry `code` and `basis`.
- **`revert_edits`** returns a `resultId` holding the discarded edits as a script.
- **`simplify_methods`.** `passes` is an array of `fold`, `cfg`, `inline` (omit for all three); `maxDepth` and
  `budget` are plain integers (8 and 100000); the totals line follows the header.
- **`compare_assemblies`** is read-only and in the `readonly` tool list: `tokenMapPath` and `overwrite` are removed and
  `tokenMap=true` returns a `tokenMapResultId` (write it with `read_result outputPath=`). Default page 200 → 100.
- **`find_counterpart`.** `symbol` is optional, `symbols[]` takes up to 100, with `offset`/`limit` and a
  `CounterpartList` record.
- **`patch_method_il`** operand syntax moved from the tool description to the edits guide.
- **`diff_edits`** gives an exact `totalChars` on every page (the "+" after the total in `[More: …]` is gone); a diff
  stops at 200 members with a closing note line.

#### Native analysis

- **Default limits.** `list_imports` 500 → 200, `list_exports` 500 → 300, `list_functions` 300 → 150,
  `list_globals` 300 → 200, `search_native_strings` 300 → 100, `resolve_call_targets` 100 → 75,
  `search_pdb_symbols` 200 → 150, `find_xrefs` 500 → 200, `verify_native_imports` 500 → 100,
  `get_call_arguments` 100 → 50. 17 native list tools take `maxTokens` as their last parameter.
- **`native_call_tree`** returns `NativeTreeNode` rows with a per-page `frontier` of unexpanded nodes. `offset` counts
  nodes (was characters), a new `limit` (200) sets the page and `maxNodes` drops from 500 to 250. `direction=both` is
  caller/callee rows by call site (was two sections).
- **`get_cfg`.** Record `blocks` → `items` with `offset`, `total` and a whole-function `summary`; `truncated` → `cut`;
  `offset` counts blocks, new `limit` (150).
- **`read_bytes`.** `offset` is a byte offset from `address`; the record is a `ByteDump` with `nextOffset` and
  `nextAddress`, paged by whole 16-byte lines within the budget.
- **`disassemble`** returns a body record. **`search_instructions`** has a new list record, `start`/`end` →
  `from`/`to`, and its count reads "N matching instructions" (was "N match(es)"). A page stopped by the scan budget
  has `hasMore=true`, `totalExact=false` and a `nextOffset` that resumes there; `maxInstructions` counts per page, and
  a page scans on to one new match (up to 5,000,000 instructions, then it names `from=`). The stop line reads "Scan
  budget of N instructions reached at X: the next page goes on from there" and `coverage.reason` "the scan budget
  stopped at X; total is a lower bound".
- **Batches.** `resolve_address` drops `more` and `lines`; its batch is `results` (`BatchItem`) with `failed`.
  `search_bytes` `patterns[]` is `BatchItem<{total, items}>` with `failed`. `find_xrefs` batch errors go into
  `targets` / `failed`. When every item fails the call is an error.
- **`find_xrefs`** gains `kind=metadata`: format tables naming an address (`.pdata`, CFG tables, export address
  table).
- **`get_call_arguments`.** `calls` → `items`, `display` dropped. **`get_exception_info`** has a new record.
  **`list_cpp_classes`** returns class rows, `offset` counts classes, new `limit` (100). **`load_pdb`** returns the
  shared edit result.
- **`find_similar_functions`** text is rows, and every view puts its rows in `items`: match rows (was `matches`) in
  `similar`, groups in `duplicates` and `clusters` (`groups` is removed). The list envelope describes those rows.
- **`verify_native_imports`** text is rows; its record keeps the first 20 run-time loads (was 100).
- **New parameters.** `get_pe_info` `view` (`view=code`: function statistics, capabilities, dynamic imports);
  `trace_native_feature` `engine`; `search_native_strings` `maxLength` (default 200); `get_native_type` takes a glob
  and lists every match.
- **Undecoded architectures.** On MIPS, PowerPC, RISC-V and s390x, `find_xrefs`, `native_call_tree` and the other code
  tools refuse with `unsupported` (`details.reason=instructions-not-decoded`, `arch`), instead of succeeding with 0
  rows.
- **`trace_native_feature`** record loses `truncated` (`nextOffset` says it).

#### Native edits and journal

- **Preview by default** on `rename_native`, `comment_native`, `patch_bytes` and `patch_asm`.
- **Journal.** Every applied native edit (bytes, names, comments, engine edits) returns an `editId`. `undo_native_edit`
  takes `editId` and undoes all of them, pushing the undo into an open IDA or Ghidra session. `list_native_edits` shows
  journal rows with `offset`/`limit` (100) and search pages.
- **Records.** The 8 native edit tools return structured records; texts read "Recorded as image#n" and "Dry run: …".
- **`patch_bytes` / `patch_asm`:** `force` → `allowUnsafe`. `patch_asm` on a non-x86 image is `unsupported`.
  **`comment_native`:** `dedupe` → `repeatLine` (default false). **`rename_native`:** `showDecompile` needs
  `dryRun=false`.
- **`export_native_annotations`** takes `format` in lower case. Session files gain `native[].journal`, so restored
  names, comments and engine edits stay undoable on the same build.
- **`export_native_patches`** text is one readable line (was the record's JSON).

#### Engines (IDA and Ghidra)

- **`engine=auto`** follows one rule: the preferred installed engine (IDA, then Ghidra) that has analyzed these bytes,
  live or saved, else ours. It never depends on earlier calls and may open a saved analysis. Engine-only tools use the
  same rule, else the first installed engine; `engine=ours` on an engine-only tool is `invalid_argument`. Note texts
  changed.
- **`decompile_native`.** The text is deterministic: push banners, open time and saved-analysis state moved to
  `_meta`, and the header loses "analyzed in" / "saved analysis". Record `Total` → `Inputs`, `Next` → `NextInput`. With
  `functions` or `callersOf`, `offset` is an input index; unreached inputs are counted, not listed.
- **`emulate_native`**, **`reanalyze_native`**, **`search_decompiled`**: `seconds` → `timeoutSeconds` (out of range is
  an error), new records, elapsed time only in `_meta`. `search_decompiled` `cursor` → `offset`, record fields renamed
  (`FunctionsTotal`, `Offset`, `FunctionsSearched`, `NextOffset`, `HasMore`, `TotalExact`) and `hits` → `items`
  (`offset` still counts functions searched). `reanalyze_native` `start`/`end` → `from`/`to`, and `analyzers=true`
  pages its options by `offset`/`limit` (200) with the list envelope.
- **`ida_python`**: `maxOutput` → `maxTokens`, `file` → `scriptPath`. **`ghidra_script`**: `timeout` →
  `timeoutSeconds`, plus `maxTokens`. In both, a script exception is an error unless `allowError=true`, and output past
  the page is kept under a `resultId`.
- **`get_native_frame`** is structured and row-paged; decompiler locals need `locals=true`, and the text has no
  "Decompiler locals" section. **`list_native_types`** is structured and sorted by name. **`set_native_type`**
  `rename` defaults to false.
- **`export_engine_database`** `force` → `overwrite`; it returns text plus a record.
- **Engine edits** return the shared edit result with `editIds` and are undone with `undo_native_edit`.
- Engine-backed code tools put the engine's version, build and profile in `_meta`; `get_engine_status` reports each
  engine's analysis profile and limitations.

#### Builds

- **`migrate_native_names`** previews by default; `sources` is an array (`user`, `pdb`, `il2cpp`); `comments` →
  `namesOnly`; record `entries` → `items`, `considered` and `truncated` removed, `applied` and `editIds` added. Default
  limit 200 → 100.
- **All build tools:** `useNames` → `codeOnly` (default false). One reason vocabulary
  ([docs/migration-reasons.md](migration-reasons.md)) and one build match on the original bytes, so
  `migrate_native_names` and `update_to_new_build` agree.
- **`compare_native_images`.** One row type in `items` replaces `pairs`, `unmatched` and `ambiguousFunctions`; the
  per-pair `changes` string is gone; default limit 100 → 40; takes `maxTokens`.
- **`map_address_between_builds`** and **`make_code_pattern`**: `address` is optional and `addresses[]` is added;
  records are `{oldImage, newImage, results[], failed}` and `{image, format, results[], failed}`.
- **`diff_function`.** `maxLines` → `offset`/`limit`/`maxTokens`; rows (pseudocode lines too) in `items`, `unified` and
  `truncated` removed; `addresses[]` gives `functions[]` summaries.
- **`search_code_pattern`.** `images` is an array; `hits` → `items` with `offset`; `failed[]`; `length`, `images`
  (count) and `truncated` removed. Default limit 200 → 100.
- **`migrate_native_patches`.** `entries` → `items`; the applied / would-apply counts become `carried`; `applied` is a
  boolean; `editIds` added; `truncated` removed. Default limit 200 → 100.
- **`update_to_new_build`.** `include` (an enum array), `oldIl2Cpp` and `newIl2Cpp` are arrays; categories lose
  `notCarriedBy`; the record loses `category`, `outcome` and `truncated` and gains `editIds` and `maxTokens`.
- `compare_native_images` `view`, `diff_function` `view` and `side`, and `make_code_pattern` `anchor` and `format` are
  no longer nullable in the schema; their defaults (`pairs`, `asm`, `old`, `auto`, `ida`) are stated.

#### Containers

- **`summarize_file`** takes `view` (default `overview`). The record is `{path, size, type, sha256, container, view,
  views, md5, sha1, entropy, signature, assemblies, highlights, highlightTotal, entryPoints, values, detail, notes}`:
  the signature is one line, highlights are the first 25, and the typed sections (NativeAOT, native image, packaging tools,
  Android, triage, Electron, Go, full assembly lists) move into `detail` under their view.
- **`survey_features`** default rows are `{name, category, matches, attack?, basis?}` without evidence; `category=` (a
  category, technique prefix or `all`) adds `evidence[]` and `attackName`. Evidence from a string or argument constant
  is `basis=derived`. `image` accepts an unloaded path.
- **`extract_strings`** is read-only: `savePath`, `format` and `overwrite` are removed; `types` is an enum array (was a
  comma string); rows page by `offset`/`limit` (100). The record holds `items`, `byType`, `valuesResultId` and `notes`
  (`values` and `savedTo` are gone); export with `read_result id=<valuesResultId> outputPath=…`.
- **`extract_embedded`.** `contents` → `items` with the list envelope, `offset`/`limit` (100), `basis=inferred`;
  accepts a container path, with sources prefixed by the inner path.
- **`search_container`.** `matches` → `items` `{path, name, kind, assembly?, detail?}`, `assembliesSearched` →
  `searched`, `truncated` removed, `offset`/`nextOffset`, default limit 200 → 100, new `kind=file`.
- **`unpack_container`.** `files` → `items` paged by `offset`/`limit` (100) with paths relative to the output
  directory; host and apphost rows read `extracted:false`; a `next {tool, arguments, reason}` when nothing was
  extracted; data that is not a container is `unsupported` (was success with no files). Text is readable rows (was a
  table) and the "N files written; 100 listed" note is gone. `load=true` → `extractOnly=false`.
- **`unity_overview`**: the not-Unity message changed (same code; the looked-for list is in `details`).
- **Unity Il2Cpp packages.** `list_assemblies path=` and `summarize_file` read a Unity Il2Cpp APK or AAB as "Android
  package (Unity Il2Cpp)" (was "(Unity Mono)"). The first page of `list_assemblies path=` is always in list order (app
  first, translations last).
- **`--load`** of a .vsix, .nupkg or .zip extracts it and loads the assemblies inside (was refused).

#### Android

- **List tools** (`list_dex_classes`, `list_android_resources`, `search_dex`, `find_dex_references`,
  `list_jni_bindings`, `list_android_packages`, `get_android_device_info`) use the list envelope, `truncated` removed,
  and their text is rows, not JSON. Default limits: classes, resources, hits and references 100 (was 500 or 200), JNI
  bindings 75 (200), device packages 150 (500), properties 100 (200).
- **`list_dex_classes`** rows show descriptors only (`javaName` removed); `interfaces` is capped at 3 with
  `interfacesTotal`; R8 map-id source files move to a note; the record gains `packages`.
- **`list_android_resources`** rows: `id` is a hex string (was a number), `isPublic` → `public` (only when true),
  values cut at 200 characters with `valueTruncated`.
- **`get_dex_class`** pages its members as `items` (`kind`, `id`, `declaration`, …) instead of `fields[]` /
  `methods[]`, which are now counts; new `members`, `query`, `offset`, `limit` (150). **`disassemble_dex`** starts a
  class with its method index.
- **`get_android_resource`**: `savePath` → `outputPath`; record `{entry, outputPath, bytes, sha256}` plus page fields.
- **`get_android_manifest`** takes `view`, `offset`, `limit`. The summary has `componentCounts`, `exported` (strings)
  and `exportedTotal` instead of `components`; permissions, declared permissions, queries and meta-data are strings;
  `view=components` gives rows.
- **`read_android_log`**: `maxBytes` removed; `buffer`, `offset` (lines back from the newest) and `limit`; structured
  lines, newest first.
- **`map_java_dotnet`**: an Il2Cpp package is `unsupported` (`details.reason=il2cpp`, with the Il2Cpp route), not
  `not_found`; `offset`/`limit` and the list envelope; `*` / `?` symbols list pairs (`direction=pattern`).
- **`install_android_package`** / **`uninstall_android_package`** return an edit outcome; `replace=true` →
  `keepInstalled=false`. **`decompile_java`** and **`disassemble_dex`** return structured page records;
  `smaliFallback=true` → `javaOnly=false`. **`pull_android_file`** of a missing remote file is `not_found` (was
  `failed`).

#### Dumps, Il2Cpp and NativeAOT

- **`open_minidump`** takes `view=summary|modules|threads|memory|unloaded` with `offset`/`limit` (50);
  `modulesOffset`, `modulesLimit`, `threadsOffset`, `threadsLimit` are removed. The record `DumpSummary` becomes
  `DumpReport {id, view, summary fields, counts, faultingModule, faultingThread | items, offset, total}`; the streams
  list is removed, handle types are strings and comments move to `notes`; `system` is `{architecture, os, processors,
  buildString}`; the exception instruction carries its bytes and `instructionBytes`, `moduleOffset`, `threadName`,
  `nestedRecord` are removed; module rows lose `end` and `checkSum`.
- **`inspect_process`** takes `view=summary|modules|regions|threads|stacks`, `offset`/`limit` (50) and `thread` for
  the stacks view; `sections` and the per-section offset/limit pairs are removed; `maxFrames` defaults to 64; thread
  rows lose `frames`, `registers` and `basePriority` (registers are in `view=stacks`).
- **`dump_stack`**: `frames` → `items`; `heuristic` → `basis` (`derived` or `inferred`, absent when observed);
  `heuristicFrames` → `scannedFrames`; `truncated` removed. `exceptionContext=true` → `dumpTimeContext=false`.
- **`dump_heap`**: `types` / `objects` → `items` (`HeapRow {type, size, count?, address?, value?, assembly?,
  token?}`); `walkStopped` → `totalExact=false`; `truncated` removed. `dump_heap` and `dump_object` leave `token` out
  for a type without a TypeDef (was `0x02000000`).
- **`symbolize_stack_text`**: `frames` → `items`; default limit 200 → 50; three or more matching native frames of one
  image fold into one row (`folded[]`; `allFrames=true` lists each); `frames` is the input frame count and `total` the
  row count.
- **`bucket_minidumps`**: `buckets` → `items`; `truncated` removed.
- **`read_dump_memory`**: record `{code, offset, nextOffset, nextAddress}` holding the page as hex; `hex` and `bytes`
  removed; new `offset` in bytes; 32 bytes per line in 4-byte groups, 64-bit addresses without the backtick.
  `imageFallback=true` → `dumpOnly=false`.
- **`get_il2cpp_info`**, **`find_method_by_address`**, **`export_il2cpp_symbols`** and **`apply_il2cpp_names`** return
  structured records; `apply_il2cpp_names` no longer shows timings in its text.
- **`get_nativeaot_info`**: `offset` counts rows in every view (was characters for summary and type); limit 200 → 75;
  the type view lists slots as rows; `truncated` removed. NativeAOT statics without field metadata read as
  `Owner::field_0xN`.
- `maxTokens` on every list tool of the family. The `generate_cpp_binding` host-API function-table details moved from
  the tool description to the Il2Cpp guide.

#### Session and notes

- **`load_assembly`**, **`unload_assembly`**, **`reload_assembly`**, **`add_search_directory`** return a record
  `{ids, text}`.
- **`list_assemblies`** returns `{items, offset, total, searchDirectories, backgroundIndexing, container?}` with the
  list envelope. `assemblies` and `nativeImages` merge into `items` with `kind` (`assembly`, `native`, `contained`,
  `file`); inapplicable fields are absent (`readyToRun` and `il2CppDummy` only when true, `unsavedEdits` only when some).
  With `path`, the container's assemblies or files are the rows (`container.files` and `fileTotal` removed). The count
  reads "assemblies", or "images" when native images are loaded (was "files").
- **`save_session`**: `path` → `outputPath` (parameter and record); returns a summary line plus the record.
  **`load_session`**: text rows with a header, the list envelope instead of `truncated`, progress notifications.
- **`record_note`** / **`update_note`**: `tags`, `addTags`, `removeTags` are string arrays; `evidence` / `addEvidence`
  are arrays of `{tool, args, resultSha256}` or `{text}`; a missing `resultSha256` is filled from the latest identical
  call in this process; one entry is at most 1,000 characters of JSON.
- **Note files** use format `corvus-notes/2`; format 1 is still read, with evidence strings becoming `{text}`.
- **`list_notes`**: text rows with the list envelope; `truncated` removed.
- **`read_result`** ids are content ids (`r-` + 12 hex), kept in memory and on disk for 7 days across restarts
  (`CORVUS_RESULT_CACHE`, `_MB`, `_DAYS`). It pages by `maxTokens`, searches with `query` and writes the whole result
  with `outputPath`. Its output class is bytes (the record gains `code` on query and outputPath results) and the record
  `format` field is removed.

#### Server and catalog

- **Output budget per part.** Text and structured content are each fitted to a token budget set by the client's
  profile (`--client`, `CORVUS_CLIENT`, `CORVUS_MAX_OUTPUT_TOKENS`); `maxTokens` asks for more up to that ceiling. A
  call answers 5 s before the client's own limit with a `timeout` whose `details.stillRunning` says the work goes on,
  and the same read-only call made again picks up the running work.
- **Cut warnings.** A record cut to fit carries one warning per cut array: "Cut to fit: <path> <kept> of <total> kept;
  read_result id=…". The cut trims the outermost arrays toward a common size in a few passes, so kept counts per array
  can differ from 1.x's one-row-at-a-time cut.
- **Errors** always carry a `Next:` line; an error over the budget sends its head and keeps the whole error under
  `details.resultId`. Every missing input path gives the same `not_found` text with its Next. Errors carry
  `_meta["corvus/provenance"]` too.
- **Output schemas on every tool** (the CLI's `--structured` refusal is unreachable). In `tools/list`, output schemas
  are compact: no `required` lists and objects below the rows are `{"type":"object"}` (depth 2, was 3).
  [docs/schemas](schemas/) keeps the full described form, and the tests validate results against both.
- **Input schemas.** Optional parameters have no `null` in `type` or `enum` (`"type":"string"`, was
  `["string","null"]`); a null sent anyway is treated as omitted. Booleans no longer declare `"default": false` (absent
  means false) and `offset` no longer declares `"default": 0`; other defaults stay.
- **Annotations.** No `annotations.title` (the top-level `title` stays); read-only tools omit `destructiveHint` and
  `idempotentHint`.
- **Descriptions.** The long-running suffix is " [Long-running.]" (was " [Long-running: can exceed 10 s.]"). The native
  `image` parameter reads "Native image id, file name or path." and `engine` "auto (default): IDA, else Ghidra, if it
  has analyzed these bytes, else ours. ida / ghidra: that engine, started when needed." Behaviour is unchanged.
- **Paging texts.** Character-paged text counts the LF-normalized text in "offset … past the end of the output (N
  chars)", as `totalChars` does. Generic record text reads "1 row (showing 1-1)" (was "1 rows").
- **Profiles.** `--toolsets core` (at most 100 tools) and `lean` (at most 40) sit beside `full`, and combine with
  families (`lean,dumps`). Clients that cap tool counts get `lean` by default. The MCP bundle offers the profile as a
  setting.
- **Catalog size.** `tools/list` fell from 349,663 to 297,064 bytes and the model-facing catalog from 167,541 to
  157,565 bytes; output schemas total 102,990 bytes.
- **`server_status`.** `unavailableTools` rows are `{tools[], reason, remediation}`; paths under the data folder read
  `<dataDir>\…`, with `run.dataDir` added. New sections for the budget, kept results, caches, leftover calls and lock
  holders, worker processes and the run id.
- **Token estimate.** A hex word counts 0.6 tokens per character (was 0.67), so `read_bytes`, `read_dump_memory` and
  other hex records carry about 10% more bytes per page.

### Improvements

#### Speed

- **Engine output cache.** Pseudocode and frames with decompiler locals are kept across processes, keyed by the engine
  build, the input and the database state. A decompile that took 169.7 s answers in 87 ms from a fresh process,
  byte-identical (`CORVUS_ENGINE_OUTPUT_MB`, default 1024).
- **Record cut.** Fitting a 20,000-node record took over 10 minutes; now 0.7 s.
- **`get_pe_info`** computes its record once per image: 38 → 7 ms warm.
- **.NET edits.** Each tree compiles once per edit. On a large assembly a warm `patch_method_csharp` drops from 7 s to
  2–4 s, `add_members_csharp` from 19–34 s to 3–7 s and `undo_edit` from 36 s to 5–10 s. A no-op write keeps the
  decompiler caches.
- **Constructors.** The constructors of one type share one decompile: 12.7 → 6.1 s for a batch, 0.06–0.6 s each.
- **Startup.** Tools are built on all cores: `initialize` takes about 0.8 s and the first `tools/list` about 8 ms
  (was 85 ms).
- **ARM64 late-bound imports.** Each function's call sites are analyzed once: 10–16 s → 3 s on a single-file host.
- **Smaller default pages.** `summarize_file` 8,094 → 1,881 tokens, `survey_features` 5,155 → 470, `open_minidump`
  summary 1,113, `inspect_process` summary 576.

#### Accuracy (our engine against IDA)

- **x86 / x64.** x86 call and jump references 76.1 / 87.7% → 100%; x64 calls, jumps and data 100%; x64 function-start
  F1 100 (IDA 99.3). Retpolines, return thunks and i386 PIC PLT stubs no longer mark functions no-return; i386 PIC and
  x64 relative switch tables resolve through tracked registers and stack slots.
- **ARM32.** Function starts on Debian armhf F1 86.9 → 97.8 (IDA 96.1); calls 100%; tail-jump-only targets become
  functions when their frame balances (misses 243 → 136).
- **ARM64.** `.pdata` fragments join their function (start F1 96.7 → 98.9); calls, jumps and data 98.3 / 98.3 / 96.1%
  → 99.99 / 99.91 / 99.67%.
- **NativeAOT.** Handler and filter funclets join their method and nop/int3 padding is not a function: 6,771 → 5,429
  functions on the reference app (PDB: 4,990 plus 87 helpers).
- **ELF.** A GNU hash table that names no symbol no longer reads as one symbol and no imports.
- **Ghidra** creates a function on request where our index starts one and its analysis does not.
- Code index persist format 14; older indexes are rebuilt on first use.

#### Reliability

- **`export_project`** works on a private snapshot outside the workspace lock, so edits, reloads and unloads no longer
  wait for it; a client deadline leaves a partial result.
- **Lock-scope check.** `CORVUS_LOCK_CHECK=1` fails a call that reads a module or decompiler reader without the
  workspace lock; the test suite runs with it on, and the call-graph build and indexing were fixed under it.
- **Cancellable waits.** Build-once caches (ReadyToRun, DEX code index, JADX sessions, minidump name tables, Il2Cpp
  string indexes, PDB type models, provider probes) and the edit journal sync stop waiting when their call is
  cancelled.
- **Engine opens** report progress every 4 s; a deadline during an open is a `timeout` with `stillRunning` and
  `retryAfterMs`, and the retry joins the same open.
- **Temporary files.** Dump decoders, the 32-bit CLR helper, engine patched-image and Mach-O slice folders, and ClrMD's
  `%TEMP%\symbols` are cleaned up.

#### Android

- **`decompile_java`** finds member, anonymous, local and lambda classes where JADX writes them, reads jars of
  `.class` files, and reports progress while JADX starts.
- **Il2Cpp builds** are recognized and routed to the Il2Cpp tools; dotted Java names and crc64 wrappers map between
  Java and .NET.

#### Containers

- **`summarize_file`** views and **`--load`** of .vsix, .nupkg and .zip (see Changes in behaviour);
  **`extract_embedded`** searches every assembly in an .apk or package.

### Fixes

- `map_java_dotnet` walked modules after releasing the workspace lock; a parallel edit or reload could dispose them
  (`NullReferenceException`).
- `export_project` on an .apk failed before the tool ran.
- `find_method_by_address` and `get_il2cpp_info` printed a negative `[More: offset=]` when `offset + limit` overflowed.
- `pull_android_file` reported a missing remote file as `failed`.
- On Linux and macOS, percentages printed as "0 %" (culture-dependent); every host now prints "0%". PDB object names
  recorded as Windows paths kept their folders on Linux and macOS.
- `server_status` on a server without IDA or Ghidra was cut to fit; an engine value missing on many tools is now one entry.
- `patch_asm` on an image it cannot assemble named the architecture "Other" (s390x); it now names the machine and
  carries `details.arch`.
- C# edits: enclosing namespaces' types bind first again (CS0115 / CS1503), and a reference newer than the runtime's
  assembly of the same name is kept (CS1705).
- `export_native_patches format=ida` failed in IDA 9 for an appended segment.
- Undoing a native edit in an engine restores the export name (not `sub_`) and the engine's own prototype.
- `get_call_tree` text marks native-to-managed transitions again; `dump_stack` text was missing `token` and
  `ilOffset`.
- Budget overruns: the token estimate undercounted packed strings, UTF-16 and hex; parts are now fitted 5% under the
  budget.
- POSIX engine workers lead their own process group, so a killed server ends them under `dash` too.
- `analyze_native_function` answered a repeated call from its cache without the "body may be cut" warning and, on
  undecoded architectures, without the partial-coverage note.
- `search_instructions` gave no continuation for a page stopped by the scan budget.
- `list_assemblies` on a container gave overlapping pages: 16 of 69 assemblies in a .vsix were never listed.
- `diff_edits` `totalChars` changed from page to page.
- Unity Il2Cpp APKs were labelled Unity Mono.
- `find_similar_functions` duplicates and clusters showed 0 rows to a client reading the list envelope.

### Known limitations

- Android list tools do not take `maxTokens` yet.
- The engine output cache drops a whole database's entries on any change, and misses across processes when IDA
  downloaded a PDB during the first open.
- `undo_edit` and `apply_edits` can still take 8–30 s on a large assembly, since each replayed C# edit writes the image.
- Code tools on MIPS, PowerPC, RISC-V and s390x refuse with `unsupported`; `patch_asm` there gives no Next.
- Three x86 switch patterns (index bounded in another block, constant slots) stay unresolved; hand-written ARM32
  runtime routines with computed jumps can split into several functions.
- tar, gzip and xz archives are not read as containers.
- Il2Cpp generic method bodies with runtime-filled registration are not mapped, and NativeAOT field names are not in
  the name layer.
- Token estimates are calibrated against the o200k tokenizer only.

## 1.3.0

158 tools (1.2.0 had 155). New are look-alike function search, p-code emulation and folder comparison. The release
also adds Electron, Objective-C / Swift and Go metadata, a faster and parallel code index (results are the same at any
thread count), faster IDA sessions, and reliability work across the server: calls that hold or wait on the workspace,
leftover calls, worker lifetime and logs.

### Changes in behaviour

- **Busy server.** Calls cancelled or past their deadline that keep running are capped (`CORVUS_MAX_LEFTOVER_CALLS`,
  default 2). At the cap a new call is refused as `provider_unavailable` with `retryAfterMs`. A call that times out
  waiting for the workspace lock names the calls holding it (`details.blockedBy`). `server_status` lists both and no
  longer takes the lock.
- **Errors.** Save tools report only IO faults as `io_error`; unclassified faults are `internal` with a Next (also per
  item in `apply_edits`). `decompile_java` without JADX or Java is not retryable (`details.reason` `not_configured`).
  A Blazor folder whose boot manifest lists none of the present assemblies is `not_found`.
- **`rename_symbol`** keeps a generic type's arity suffix and refuses a different arity.
- **`set_native_local` (Ghidra)** checks that the rename took effect: a local without storage in use, or a name the
  decompiler kept, fails instead of succeeding.
- **Deterministic records.** `unity_overview`, `compare_native_images`, `update_to_new_build` and
  `find_similar_functions` no longer carry elapsed time, so two identical calls give identical bytes.
- **Code index** persist format 11. Older indexes are rebuilt on first use.
- **IDA cache keys** are short (16 hex characters). Existing entries migrate. Input paths over 259 characters fail up
  front and give their length.

### New tools

- **`find_similar_functions`** ranks look-alike functions using MinHash sketches of instruction shapes, then rescores
  them exactly. It searches across all loaded images and also reports duplicate groups and near-duplicate clusters.
- **`emulate_native`** runs a function or range in Ghidra's p-code emulator over the program's bytes, with a private
  stack, arguments by calling convention, stubs for calls, and instruction and time budgets.
- **`compare_folders`** compares two folders or zip-family archives entry by entry by streaming SHA-256. It reports
  moves and case-only renames, and gives a next call per changed binary and inline diffs of small text files.
- **`update_to_new_build`** now also takes two .NET assemblies: member notes follow their `find_counterpart` match and
  file notes move to the new build.

### Formats and metadata

- **Electron:** ASAR archives with integrity checks, extracted entries and links; `summarize_file` reports Electron,
  Chromium and Node versions, fuses, the entry point and `webPreferences` values. Node-API add-on callbacks are named
  after their JavaScript names.
- **Unity WebGL** data files and **HAR / mitmproxy** captures open as containers.
- **Mach-O:** Objective-C and Swift metadata readers and a Swift demangler; `list_cpp_classes` and `get_native_type` list
  Objective-C classes, categories and protocols and Swift types.
- **Go:** build info for PE, ELF and Mach-O; function sizes from each function's own tables; noreturn runtime functions.
- **ELF and Mach-O** patch-site extension stubs (`patch_asm` beyond a site's size).

### Native analysis

- **ARM:** functions found in gaps from ARM32 and ARM64 prologues; `.ARM.exidx` / `.ARM.extab` exception data; ARM64X
  and ARM64EC images decoded in both instruction sets; ARM32 crypto instructions; JNIEnv / JavaVM calls named with their
  parameters; floating-point and System V call arguments (struct return, variadic vector count, 16-byte structs).
- **Index speed:** discovery, sorting, noreturn propagation, RTTI, `.pdata` and virtual call resolution run on several
  threads. Allocation on a 130 MB NativeAOT image drops from 3.1 GB to 0.32 GB.
- **IDA:** function and string lists are kept per session. Rename pushes are journaled and re-decompile only the
  affected functions. A first decompile on a large ELF drops from 7–10 s to 0.6 s. `find_xrefs`, `resolve_address` and
  `search_bytes` take lists of targets. An `.i64` beside the input starts the cache as a copy, and the user's file is
  never written. A script loop is interrupted in place at its cancel or deadline.

### Operations

- Engine workers end within a second of a killed server on Linux and macOS.
- The engine database cache is bounded (`CORVUS_ANALYSIS_CACHE_MB` / `_DAYS`).
- Each call writes one info log line (`CORVUS_LOG_FORMAT=json`). `--trace` records argument values only with
  `--trace-args`, with secrets masked.
- Per-RID publishes are ReadyToRun, so each cold CLI call is about 0.4 s faster.
- `verify_native_imports` reports progress, never rebuilds stubs per call (300 s to 7 s cold on a large app) and no
  longer hits dnlib's `LockException`.
- `export_project` decompiles outside the workspace lock.
- New: a CorvusRE NuGet .NET tool package, MCP bundles (`.mcpb`) per desktop target, and an updated SECURITY.md.

## 1.2.0

155 tools (1.1.0 had 101) and 13 prompts (9). The project takes its current name, **Corvus**. This
release adds a second decompiler engine (Ghidra), ELF and Mach-O images, our own ARM64 and ARM32 / Thumb-2 analysis,
NativeAOT and mobile Il2Cpp builds, Android packages and devices, deeper crash-dump decoding, and a round of reliability
work across the server and its engine workers.

### Renamed to Corvus

- **Program and registration.** The program is `corvus` (`corvus.exe`), installed under `Corvus`, and registers with
  clients under the MCP key `corvus`. Release archives are `corvus-<rid>` from the `Albasha0x0/Corvus` repository.
- **Names.** Environment variables are `CORVUS_*` and resources use the `corvus://` scheme.
- **Earlier installs.** On first start, data, client entries and skill folders of an earlier install move to the new
  names; files saved by earlier versions (sessions, edit scripts, patch sets, notes, engine databases) are still read.

### Changes in behaviour

- **Exports never overwrite by default.** Files written by export and save tools are written atomically and refuse to
  replace an existing file unless `overwrite=true`; links and device names are refused as targets. `save_assembly`
  recognizes the original through links and hard links, refuses an original that changed on disk since it loaded, and
  `save_native` verifies the written file before renaming it into place.
- **`uninstall` keeps user data.** Annotations, caches and symbols stay; `--purge-data` removes them.
- **Call deadline.** A tool not marked long-running ends with a timeout error after twice `--timeout`; cancelled calls
  stop waiting for the workspace lock. New error codes `cancelled` and `changed_on_disk` ([docs/errors.md](errors.md)).
- **Closed argument values** are advertised as enums and checked before the tool runs, with aliases and a
  did-you-mean suggestion; `limit < 1` is `invalid_argument` on every paged native tool.
- **Native names.** A name on several addresses is an ambiguous error listing them; hex-shaped names (`Bach`, `...h`)
  resolve as names before MASM numbers; a name on a jump thunk and on its body resolves to the body.
- **Incomplete results say so.** Regex searches that time out report what was not evaluated; a cut-short `read_bytes`
  says so; `read_bytes` shows bytes with no file data (`.bss`, virtual size past raw size) as `??` with a gap list.
- **Member labels carry generic parameters** (`Method<T>(string)`), so generic and non-generic overloads differ in
  diffs and replays; older edit scripts resolve their bare labels as before.
- **Native patches** pad with the architecture's NOP (whole NOPs on ARM64) and are refused where none is defined.
- **IDA before 9.0 is refused** with the reason; the reported idalib version shows in `server_status`.
- **Inputs:** FIFOs, sockets, devices and directories are refused as input files.

### Second engine: Ghidra

- **`engine=ghidra` everywhere an engine is used:** `decompile_native`, the code tools (`list_functions`, `disassemble`,
  `get_cfg`, `find_xrefs`, `native_call_tree`, `resolve_call_targets`, `trace_native_values`, `inspect_instruction`),
  the type, frame and local edit tools, `crossCheck` and `find_xrefs Type::member`. A session per engine and image;
  `auto` takes a complete IDA analysis, then Ghidra's, else ours. Ghidra 12.0 or newer through `CORVUS_GHIDRA_DIR` and a
  JDK; the worker is built on first use.
- **Saved projects** per file SHA-256 and profile key, warm reopen, rebase, damaged-project rebuild, an analysis budget
  with a partial save that `reanalyze_native` completes, and a background function pass after the open.
- **Large functions decompile:** 200 MB decompiler data, one retry with four times the time on a fresh decompiler,
  `timeoutSeconds` per call.
- **Ghidra's names** (loader and analysis names, function identification included) form a name layer below the others;
  `FUN_` / `LAB_` / `DAT_` and IDA default names resolve as addresses.
- **`ghidra_script`** runs a Java GhidraScript in the worker in one transaction, rolled back on failure (opt-in,
  `--ghidra-scripting`). `export_engine_database` writes a `.gzf` archive, or Ghidra's own types as `.h` / `.gdt`.

### IDA and engine depth

- **New edit tools:** `define_native` (code, functions, data, undefined bytes), `set_native_operand` (number base, char,
  offset, stack variable, enum member, struct offset), `reanalyze_native`; enum, struct and union member upsert,
  type delete and rename (followed into the other edits), stack member delete, `clear=true` to restore the engine's
  own local. All kept per file hash, replayed on a new database, exported and carried to new builds.
- **Comments:** kinds `eol`, `pre`, `plate` and pseudocode comments placed on the statement, with append and dedupe;
  `rename_native` and `comment_native` take batches with `dryRun`, `stopOnError` and per-item results;
  `showDecompile=after|diff` on the type and name edits.
- **Views:** `list_globals`, `search_instructions`, `convert_number`, `get_engine_status`, `search_decompiled` (regex
  over every function's pseudocode, resumable by cursor), `decompile_native functions=[...]` and `callersOf=`,
  `list_functions view=candidates`, `find_xrefs direction=from|both` and `kind=`, `list_native_types` filters,
  `related=true` and members, `list_cpp_classes engine=ida|ghidra`, typed reads (`get_native_type read=true`,
  `read_bytes type=`), `export_engine_database` (`.i64` copy), `make_code_pattern` in IDA / x64dbg / mask formats.
- **Worker control:** cancel and deadlines inside the IDA and Ghidra workers (partial results with a cursor; the worker
  is killed only past a grace period), `CORVUS_ENGINE_REQUEST_TIMEOUT` / `CORVUS_ENGINE_OPEN_TIMEOUT`,
  `CORVUS_ENGINE_ANALYSIS=none` for very large or malformed inputs, a read-only snapshot when another server holds the
  database, batch mode so no dialog waits, engine sessions and open-stage timings in `server_status`.

### Own engine: ELF, Mach-O, ARM64 and ARM32

- **ELF and Mach-O images** load beside PE (universal files by slice) through every native tool: relocations, PLT and
  GOT, symbol versions, chained fixups, exports trie, function starts, compact unwind, code signature and encryption.
  IDA and Ghidra open them too. Itanium C++ demangler, Itanium RTTI (single, multiple and virtual bases) for classes,
  type push and virtual calls, Itanium exception tables in `get_exception_info`, System V x64 calling convention.
- **ARM64** decoder, function discovery, jump tables, call arguments (integer and floating-point), value tracing and
  call targets; `inspect_instruction` on the built-in decoder; ARM64X / ARM64EC images from their CHPE metadata.
- **ARM32 / Thumb-2:** own A32 / T32 decoder (VFP and NEON included) with per-function state, cross-references through
  literal pools and MOVW / MOVT, TBB / TBH and PC-relative jump tables, IT blocks, AAPCS call arguments and value
  traces, fixed-address executables.
- **Discovery:** Go function tables (Go 1.2 to 1.24, ELF / PE / Mach-O) as a function and name source; static and
  fixed-address ELF (a static x86-64 Linux executable: 194 to 3,112 functions; its i386 build: 19 to 3,173); x64
  absolute switch tables; jump thunks named `j_<target>`. Image-scope `resolve_call_targets` on a 3.8 MB library:
  1,474 s to 12 s (ARM32), over 900 s to 7 s (ARM64).
- **Patching ELF and Mach-O:** `patch_bytes`, `patch_asm`, undo and `save_native` (universal files keep their other
  slices); bytes the loader rewrites are refused unless forced, encrypted bytes refused.
- **Packaging and hardening tools** reported with evidence in `summarize_file` and `get_pe_info` (detection only).

### Native analysis

- **`inspect_instruction`**, **`get_native_type`** (PDB, RTTI, Il2Cpp and engine types; field paths at an offset),
  **`trace_native_values`** (interprocedural value slices across functions and loaded images, struct fields, switch
  case selection) and **`resolve_call_targets`** (targets with basis and confidence).
- **`analyze_native_function`** (a function dossier in bounded sections, up to 16 at once, `component=true`),
  **`trace_native_feature`** (from a text to the ranked functions behind it), native goals in **`find_call_paths`**,
  **`diff_function`** (aligned instruction and pseudocode diff of a matched pair), `get_cfg` switch cases,
  `native_call_tree direction=both`, `summarize_file` triage for native images.

### NativeAOT

- **`get_nativeaot_info`** and a nativeaot name layer from the image's own metadata: method bodies, MethodTables,
  vtable slots, frozen strings, statics and interface dispatch cells, ranked below PDB names, pushed to IDA and Ghidra
  and exported. .NET 7 to 11 layouts, PE, ELF and Mach-O, 64- and 32-bit.

### Il2Cpp and Unity

- **Mobile and desktop layouts:** Android, iOS, macOS and Linux builds, read from `.apk` / `.xapk` / `.apks` / `.aab` /
  `.ipa`; ELF and Mach-O binaries; metadata up to v39; builds that fill the code registration at run time.
- 32-bit builds get headers and prototypes pushed to IDA and Ghidra; Il2Cpp builds and minidumps are kept in sessions;
  `unity_overview` reads packages and iOS layouts.

### Android

- **Packages:** manifest and resources (binary XML, `resources.arsc`, app bundle protobuf), APK signature verification
  (v1 to v4 with rotation and several signers, content digests recomputed), .NET for Android assembly stores.
- **Code:** DEX reader and Dalvik disassembler (`list_dex_classes`, `get_dex_class`, `disassemble_dex`, `search_dex`,
  `find_dex_references`), `decompile_java` through JADX, `map_java_dotnet` (also Unity Mono C# to Java),
  `list_jni_bindings`, `export_project` to a Gradle project skeleton.
- **Devices** through adb: read-only by default; install and uninstall behind `--allow-device-changes`.

### Crash dumps

- **.NET decoding:** managed exception, mixed frames, `dump_heap` and `dump_object`; DAC lookup with signature check and
  opt-in download; .NET Framework and 32-bit dumps through a bundled 32-bit decoder (Windows); IL offsets mapped to the
  C# statement.
- **`symbolize_stack_text`** (Unity, Mono, Il2Cpp, .NET, WER, Event Log, debugger, Android tombstone and logcat stacks,
  with build checks) and **`bucket_minidumps`**; WoW64 32-bit side, frame-pointer-less x86 frames, modules found by
  timestamp and size.

### Also since 1.1.0

- **.NET builds:** `compare_assemblies` / `find_counterpart` report every change of a matched member, members moved
  between types, and optional C# or IL diffs; provenance (file SHA-256, MVID, IL hashes); metadata and exception-clause
  health in `get_assembly_info`.
- **.NET export and patching:** `export_project` builds more real projects (framework inference, package references, preserialized resources);
  Blazor WebAssembly Webcil modules load and extract; many C# patch compile fixes; `diff_edits` first page of a
  whole-assembly simplify 27 s to 4 s.
- **Sessions and notes:** `save_session` / `load_session` (files by SHA-256, edits, patches, names, notes), an edit
  journal that offers unsaved work for replay, `record_note` / `update_note` / `list_notes`, shown in IDA and Ghidra.
- **Setup:** `corvus install` plans and edits client files in place (comments kept, `--dry-run`, `--json`), more
  clients and config homes, `corvus status` checks each registration with its own args and env; the agent skill
  (`install --skill`); `SHA256SUMS` checked by the installers and `update`.
- **CLI:** a generic tool runner (`corvus call`, `describe`), `batch`, prompts and resources, shell completions.
- **Server:** `--toolsets` and `--tools-file` to register fewer tools (`core`, `readonly`, `triage`), `--trace` JSONL
  call trace, `--log-level`, resource subscriptions, a development reload relay that also serves 2026-07-28 clients.
  Tool descriptions and schemas were trimmed from 225,472 to 165,631 bytes (-26.5%) at 155 tools.
- **Reliability:** cross-process locks and merges for annotation sidecars and notes; one ordered writer per engine
  worker; child-process output and exits read off the thread pool; a deadlock between the edit journal and saves fixed.

## 1.1.0

101 tools (1.0.1 had 54). This release adds the native PE track (analysis, IDA engine, PDB, patching, crash dumps,
build migration) and a batch of usability and analysis-depth work on top of it.

### Changes in behaviour

- **Unknown argument names are errors.** A parameter a tool does not declare is `invalid_argument` with the closest
  declared names ("unknown parameter 'max_chars'. Did you mean 'maxChars'?"; `details.suggestions`), instead of being
  ignored while the tool ran with its defaults. Clients that sent extra arguments must drop them.
- `load_pdb` is marked destructive: `clear=true` removes imported PDB names and their saved copy.
- With `engine=auto` (the default), `list_functions`, `disassemble`, `get_cfg`, `find_xrefs` and `native_call_tree`
  answer from IDA for an image once IDA has finished analyzing it in the session; pass `engine=ours` for the built-in
  index only.

### New in this batch

- **Persistent native code index.** Each image's code index is saved per user, keyed by the file's SHA-256 and the build
  options; reopening the same bytes loads it (msedge.dll, 334 MB: 2.6 s instead of 36 s; GameAssembly.dll, 206 MB:
  1.8 s instead of 54 s). Changed, damaged or older-format entries are rebuilt; bounded by size (8 GB) and age (30 days),
  least recently used first. `--index-cache <dir|off>`, `--index-cache-mb`, `--index-cache-days`; shown in `server_status`.
- **Imported names survive restarts.** Names from `load_pdb` and `apply_il2cpp_names` are saved beside user renames and
  reapplied when the same file loads again, also with the PDB moved or deleted (434,680 names on an Il2Cpp build restored in 0.8 s).
  `list_native_edits` lists each layer and whether it was restored; `clear=true` removes a layer.
- **Engine preference** `engine=auto|ours|ida` (server default `--engine` / `CORVUS_ENGINE`): see above; `auto` never starts
  IDA and costs about 0.1 µs per call. With IDA, our names still win and RTTI virtual-call edges IDA lacks are added.
  Every result names its engine.
- **PDB types in IDA.** `decompile_native` loads the PDB's structs, enums, typedefs and prototypes into the IDA database
  once per PDB, through IDA's PDB loader or the server's own PDB type reader, so pseudocode uses real struct and member
  names (`return source->flags;` instead of `return *(unsigned int *)(a1 + 712);`).
- **Virtual calls through RTTI.** `obj->vfunc()` sites are resolved from MSVC RTTI class hierarchies into
  `virtual_exact` / `virtual_possible` call-graph edges (+11,041 edges on Qt6Widgets.dll, +15,026 on Acrobat.dll).
  `find_virtual_calls` lists the sites; `crossCheck=true` compares with IDA (98-100% agreement on Qt6Widgets and
  a second large C++ DLL). `native_call_tree calls=direct|virtual`.
- **Built-in Il2Cpp metadata reader.** `load_assembly` on an Il2Cpp build folder or `global-metadata.dat` reads metadata
  versions 24-31, also from a memory dump of GameAssembly.dll; no external dumper. On a v31 build every method, RVA,
  vtable slot, field and field offset matches a reference dump. Unreadable metadata is an error with a reason;
  unreadable items are listed by reason.
- **`unity_overview`.** One call on a Unity build: engine version per source, Mono or Il2Cpp with evidence and metadata
  state (readable, encrypted, header modified), toolchain and middleware markers (optional Detect
  It Easy), and the next tool calls. Under 0.2 s on the builds tested.
- **`inspect_process`.** Read-only view of a running local process (Windows): modules, memory regions, threads and
  stacks, named through PE, PDB, Il2Cpp and user names. Opens only query and read handles, writes and suspends nothing,
  closes every handle before returning (docs/live-inspection.md).
- **Patch-site extension.** `patch_asm` / `patch_bytes` `extend=true` turn a site that is too small into a jump to a
  relocation stub that runs the new code (and the displaced instructions, `stubMode=before|after`) and returns after the
  site. `placement=auto|cave|section`: a code cave when one fits, else a new executable section (undo removes it byte
  for byte). Exports describe grown files (JSON v2, IDAPython, IPS / IPS32; `.dif` refuses them with `grown_file`).
- **`update_to_new_build`.** One call carries names, comments, PDB / Il2Cpp layers, patches (stubs re-created), code
  patterns with drift and the Il2Cpp method mapping to a new build, with one report: what carried, what did not and why.

### Also since 1.0.1

- **Native PE images:** own PE parser; x86 / x64 code index (functions, xrefs, CFGs, strings); MSVC demangler, RTTI and
  exception metadata; PDB reader with opt-in symbol download; Win32 resources; ReadyToRun code; P/Invoke verification
  with verdicts; late-bound imports and call-site arguments; navigation across loaded images and between managed and
  native code; ARM / ARM64 through IDA.
- **IDA (idalib) engine:** `decompile_native`, analysis cached per file hash, names, patches and types pushed in,
  library-function names, optional background analysis (`--ida-prewarm`).
- **Native editing:** renames and comments kept per file hash, `patch_bytes` / `patch_asm` (full MASM assembler,
  relocation-correct under ASLR), undo, `save_native`, `export_native_patches`, `migrate_native_patches`.
- **Builds and dumps:** `compare_native_images`, address and name migration, rebuild-stable code patterns; minidumps
  (`open_minidump`, `dump_stack`, `read_dump_memory`).
- **Il2Cpp:** string literals, metadata <-> native navigation both ways, complete struct layouts and prototypes, C++
  bindings in Il2Cpp style with generic templates.
- **Protocol:** typed errors with a JSON copy, structured output for list / search / info tools, response-size guard with
  `read_result`, `server_status` with a tool-catalog digest, one audited annotations table.
- **.NET:** normalized IL hash, tiered unique-only member matching, many `simplify_methods` readability passes.
