# Configuration

Every server option, environment variable and security switch.

- Options go in the client entry's `args`, variables in its `env`.
- An option wins over its variable; an environment variable wins over [corvus.json](#config-file).
- Switch variables take `1`, `true` or `on`.
- `server_status` shows each value in effect and its source.
- Setup: [installation.md](installation.md). Command line: [cli.md](cli.md). Tool arguments: [tools.md](tools.md).

```json
"corvus": { "command": "corvus", "args": ["--allow-live-attach"], "env": { "CORVUS_OFFLINE": "1" } }
```

| Section | Covers |
|---|---|
| [Security switches](#security-switches) | What can run, attach, change a device or replace the loaded file |
| [Claude Code](#claude-code) | Turning switches on for every project or one, and checking them |
| [Server options](#server-options) | Loading, limits, engines, tool profiles, logging |
| [Config file](#config-file) | Variables for every server and command of this user |
| [Environment variables](#environment-variables) | Folders and caches, engines, external programs, network, install |

## Security switches

- By default the server reads files and runs nothing from them; each switch widens that and is off by default.
- Turn one on with `corvus install --set <switch>` ([examples](#claude-code)) or in the entry's `args`.
- `inspect_process` needs no switch. The session tools refuse every call until a `--allow-live*` switch is on.
- Trust model: [SECURITY.md](../SECURITY.md).

| Option | Variable | Allows |
|---|---|---|
| `--allow-live-attach` | `CORVUS_ALLOW_LIVE_ATTACH` | the session tools and `live_session action=attach` |
| `--allow-live-spawn` | `CORVUS_ALLOW_LIVE_SPAWN` | the session tools, `live_session action=spawn` and `live_console action=start`, which run a program with your rights |
| `--allow-live` | `CORVUS_ALLOW_LIVE` | the session tools without opening a program (lists processes); implied by the other live switches |
| `--live-allow <path>` | `CORVUS_LIVE_ALLOW` | limits attach and start to these programs or folders (repeatable; a path list) |
| `--live-scripting` | `CORVUS_LIVE_SCRIPTING` | the session tools and `live_script`: your script runs with the program's rights |
| `--live-install-frida` | `CORVUS_LIVE_INSTALL_FRIDA` | without a tested Frida, the first session installs Frida 17.24.3 from hash-checked wheels ([Frida](live-inspection.md#frida)); refused offline |
| `--ida-scripting` | `CORVUS_IDA_SCRIPTING` | `ida_python`: any Python in the IDA worker, with the server's rights |
| `--ghidra-scripting` | `CORVUS_GHIDRA_SCRIPTING` | `ghidra_script`: any Java or Python in the Ghidra worker, with the server's rights |
| `--allow-replace-original` | `CORVUS_ALLOW_REPLACE_ORIGINAL` | `save_assembly` and `save_native` with `replaceOriginal=true`; without it they write new files only |
| `--allow-device-changes` | `CORVUS_ALLOW_DEVICE_CHANGES` | `install_android_package`, `uninstall_android_package`; the other device tools only read |
| `--trace-args` | `CORVUS_TRACE_ARGS` | argument values in the `--trace` file; secrets masked, best effort |
| `--in-process-parsing` | `CORVUS_IN_PROCESS_PARSING` | file and dump reads in the server process instead of a worker |
| | `CORVUS_LIVE_MAX_MINUTES` | minutes a session stays open (default 30) |

- `--live-allow`: links are resolved first; list only folders only you can write to.
- `--in-process-parsing` covers `summarize_file`, `list_assemblies path=`, `search_container`, `unpack_container`,
  `open_minidump`, `read_dump_memory`, `dump_heap` and `dump_object`. A file that crashes a reader then ends the
  server. By default a worker that cannot start refuses the call.

### Writing files

Edits stay in memory until a save. Every save is atomic (a temporary file, then a move).

| Argument (`save_assembly`, `save_native`) | Effect |
|---|---|
| none | `save_assembly` writes `<name>.patched.dll`; `save_native` needs `outputPath`; existing files refused |
| `overwrite=true` | replaces an existing file, never the loaded file |
| `replaceOriginal=true` | replaces the loaded file; needs `--allow-replace-original` |
| `versioned=true` | writes the first free `<name>.1.dll`, `<name>.2.dll`, ... |

- `replaceOriginal=true` writes the `.bak` once and refuses a file changed on disk since load.
- To also approve each save, add the save tools to the client's approval list (Claude Code:
  `"permissions": { "ask": ["mcp__corvus__save_assembly", "mcp__corvus__save_native"] }` in `~/.claude/settings.json`).
  Modes that skip approval skip this; the server switch holds in every mode.

## Claude Code

- Claude Code reads a global `corvus` entry and, per folder, an optional local one that replaces it (`~/.claude.json`).
- `corvus install` edits both; then restart Claude Code or reconnect `corvus` in `/mcp`.

Every project (every registered client's global entry):

```sh
corvus install --set allow-live-attach
```

One project, from its folder (`--project` also takes a path). A missing local entry is copied from the global one;
an existing one keeps its arguments:

```sh
corvus install --set allow-live-spawn --project .
```

```text
  ok  Claude Code, project <folder>: added a local entry (copied from the global one)  ~\.claude.json
```

Preview, turn off, several at once:

```sh
corvus install --dry-run --set allow-live-spawn --project .
corvus install --unset allow-live-spawn --project .
corvus install --set allow-live-attach,allow-replace-original --project .
```

`--unset` removes the option only: a variable in the entry's `env` keeps the switch on, and install names it.

Check what a folder uses, from that folder:

```sh
claude mcp get corvus
```

```text
corvus:
  Scope: Local config (private to you in this project)
  Status: ✔ Connected
  Args: --client claude-code --allow-live-spawn
```

`server_status` lists switches that are off under `unavailableTools`, each with the option that turns it on.

Limit which programs a session may start or attach to:

```json
"env": { "CORVUS_ALLOW_LIVE_SPAWN": "1", "CORVUS_LIVE_ALLOW": "<program or folder>" }
```

## Server options

| Option | Variable | Default | Effect |
|---|---|---|---|
| `--load <path>` | `CORVUS_LOAD` (`;`-separated) | | load a file or folder at startup (repeatable) |
| `--search-dir <dir>` | | | extra folder for resolving references (repeatable) |
| `--max-output <chars>` | | 60000 | page size of long results (minimum 2000) |
| `--timeout <s>` | | 180 | per-call decompilation limit (minimum 5) |
| `--no-index` | | | no background method index or call graph after loading |
| `--no-watch` | | | no reload when loaded files change on disk |
| `--client <id>` | `CORVUS_CLIENT` | detected | the client's limits ([client table](installation.md#clients)); written by `corvus install` |
| `--client-timeout <s>` | `CORVUS_CLIENT_TIMEOUT` | client's | the client's per-call limit, when raised from its default |
| | `CORVUS_MAX_OUTPUT_TOKENS` | client's | output ceiling in tokens (500 or more) |
| `--toolsets <list>` | `CORVUS_TOOLSETS` | every tool | register a profile or families (below) |
| `--tools-file <file\|readonly\|triage>` | `CORVUS_TOOLS_FILE` | | register only the listed tools, after `--toolsets` |
| `--engine <auto\|ours\|ida\|ghidra>` | `CORVUS_ENGINE` | `auto` | default engine of the native function, reference and CFG tools |
| `--prewarm <ida\|ghidra\|auto\|off>` | `CORVUS_PREWARM` | off | analyze each native image in that engine as it loads |
| `--ida-prewarm` | `CORVUS_IDA_PREWARM` | off | same as `--prewarm ida` |
| `--index-cache <dir\|off>` | `CORVUS_CODE_INDEX_CACHE` | `code-index` in the data folder | saved native code indexes, keyed by file SHA-256 |
| `--index-cache-mb <n>` | `CORVUS_CODE_INDEX_CACHE_MB` | 8192 | size bound of that cache |
| `--index-cache-days <n>` | `CORVUS_CODE_INDEX_CACHE_DAYS` | 30 | entries unused this long are deleted |
| `--binding-style <mono\|hostapi\|aot>` | | `mono` | `generate_cpp_binding` style when a call names none |
| `--binding-project <dir>` | | | project folder `generate_cpp_binding` scans for a host table |
| `--log-level <level>` | `CORVUS_LOG_LEVEL` | `information` | stderr log: `trace`, `debug`, `information`, `warning`, `error`, `none` |
| | `CORVUS_LOG_FORMAT` | text | `json`: log lines as JSON |
| `--trace <file>` | `CORVUS_TRACE` | off | one JSON line per call: time, tool, argument names, ms, error code, size |
| `--trace-args` | `CORVUS_TRACE_ARGS` | off | see [Security switches](#security-switches) |

- `--timeout`: `export_project` gets 10 times as long; tools not marked long-running end after twice the value.
- `--toolsets` profiles: `full`, `core` (at most 100 tools), `lean` (at most 40).
- `--toolsets` families: `session`, `dotnet`, `containers`, `edit`, `aot`, `native`, `native-edit`, `builds`, `notes`,
  `engine`, `android`, `dumps`, `live`, `web`. `session` is always included; combine as `lean,dumps`.
- A tool left out by `--toolsets` is not registered; naming its family brings it back. Without `--toolsets`, a client's default profile only hides tools from the
  listing; they still answer a direct call.
- `--tools-file`: names separated by spaces, commas or lines, `#` comments; an unknown name stops startup. `readonly`:
  tools that change nothing and write no file; `triage`: a first-look set. The `session` tools stay.
- `--engine auto`: IDA, then Ghidra, when either has analyzed the image, else built in.
- At `information` and below, the log has one line per call (tool, outcome, ms, sizes, engine), never argument values.
- `--trace` refuses an engine database path.
- Logs go to stderr; stdout carries only the protocol.

## Config file

`corvus.json` in the data folder (`CORVUS_DATA_DIR`, default `<LocalAppData>/Corvus`), or the file `CORVUS_CONFIG`
names, sets variables for every server and command this user starts. It is read once at startup; workers inherit it.

```json
{
  // Comments and trailing commas are allowed.
  "CORVUS_OFFLINE": true,
  "CORVUS_ANALYSIS_CACHE_MB": 65536,
  "CORVUS_GHIDRA_DIR": "D:/tools/ghidra"
}
```

- Keys are `CORVUS_` variables; values are strings, numbers or `true`/`false` (`1`/`0`).
- A variable already set in the environment wins over the file, and an option wins over both.
- Refused there, with a warning: the [security switches](#security-switches) (they stay in the client entry, where the client shows them),
  `CORVUS_DATA_DIR` and `CORVUS_CONFIG`.
- A file that is not valid JSON applies nothing.
- `server_status` (`run.config`) names the file and the variables it set, lost to the environment or refused.

## Environment variables

Variables of the options above are listed with them. A program variable takes the file or its folder.

### Folders and caches

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_DATA_DIR` | `<LocalAppData>/Corvus` | per-user data folder; the folders below default to entries in it |
| `CORVUS_ANNOTATIONS_DIR` | | saved native names, comments and imported name layers |
| `CORVUS_ANALYSIS_CACHE` | | saved IDA and Ghidra databases, keyed by file hash |
| `CORVUS_ANALYSIS_CACHE_MB`, `CORVUS_ANALYSIS_CACHE_DAYS` | 32768, 60 | bounds of that folder; entries open in a server are kept |
| `CORVUS_ENGINE_OUTPUT_MB` | 1024 | saved engine output, answered without starting the engine; `0`: off |
| `CORVUS_RESULT_CACHE` | `results` | kept results for `read_result`, holding analyzed-file content; `off`: memory only |
| `CORVUS_RESULT_CACHE_MB`, `CORVUS_RESULT_CACHE_DAYS` | 512, 7 | bounds of that folder |
| `CORVUS_JAVA_CACHE` | `java-sources` | saved `decompile_java` output; `off`: none |
| `CORVUS_AOT_CACHE` | | assemblies made by the compiled-metadata reader |
| `CORVUS_SYMBOL_CACHE` | | downloaded PDBs and runtime DACs |
| `CORVUS_DUMP_BUCKET_CACHE` | | per-dump signatures of `bucket_minidumps`; a rerun parses only new dumps |
| `CORVUS_DEBUG_DIRS` | | path list searched for separate DWARF files of ELF and Mach-O images |

### IDA and Ghidra

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_IDA_DIR`, `CORVUS_IDA_PYTHON` | found | IDA folder and the Python for idalib |
| `CORVUS_IDA_CONNECT` | off | `1`: use a database open in IDA and served by `corvus_connect.py` |
| `CORVUS_GHIDRA_DIR` | `GHIDRA_INSTALL_DIR` | Ghidra 12.0 or newer |
| `CORVUS_GHIDRA_JAVA` | `JAVA_HOME`, `PATH` | JDK for Ghidra |
| `CORVUS_GHIDRA_PYTHON` | | Python 3.9+ with PyGhidra; enables Python in `ghidra_script` |
| `CORVUS_GHIDRA_ANALYSIS` | `standard` | analysis profile: `standard`, `full`, `minimal` |
| `CORVUS_GHIDRA_COMPLETION` | on | `off`: no background pass completing a `standard` analysis |
| `CORVUS_GHIDRA_MAXMEM` | | JVM heap of each Ghidra worker |
| `CORVUS_GHIDRA_WORKER_DIR` | `<analysis cache>/ghidra` | Ghidra workers' settings, temporary files and build |
| `CORVUS_GHIDRA_SPARE_WORKER` | off | `on`: keep one idle Ghidra worker ready (1-2 GB) |
| `CORVUS_GHIDRA_OPTIONS` | | extra analyzer options, `Name=value;...` |
| `CORVUS_GHIDRA_EXTENSIONS` | | folder of Ghidra extension zips installed into the workers; nothing is downloaded |
| `CORVUS_GHIDRA_DECOMPILE_TIMEOUT` | 60 | seconds per decompiled function (1-600) |
| `CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB` | 200 | decompiler response limit (16-2048) |
| `CORVUS_ENGINE_ANALYSIS` | `full` | `none`: open images without auto-analysis, for huge or hostile inputs |
| `CORVUS_ENGINE_MEMORY_MB` | ¾ of available | memory limit of each IDA or Ghidra worker (Windows job object); a worker at it is ended; `0`: none |
| `CORVUS_ENGINE_REQUEST_TIMEOUT` | 120 | seconds per engine request; a stopped request returns what it found |
| `CORVUS_ENGINE_OPEN_TIMEOUT` | 1200 | seconds for an engine's start plus auto-analysis |
| `CORVUS_STALL_DIR` | `<analysis cache>/ghidra/stalls` | thread dumps of Ghidra workers stopped for time |

- `CORVUS_IDA_CONNECT`: the image's SHA-256 must match IDA's input. Reads and edits reach that database at once; IDA
  alone saves it; Corvus never rebases, closes or deletes it. No local IDA install is needed.
- PyGhidra offline install: `python -m pip install --no-index -f <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`.

### External programs

Optional. `server_status` shows where each was found, its version, or the fix.

| Variable | Program | Used for |
|---|---|---|
| `CORVUS_FRIDA_PYTHON` | Python with Frida's bindings (17.0+; tested 17.24.3 to 17.x) | the session tools' worker |
| `CORVUS_TTD` | folder with `TTDReplay.dll` and `TTDReplayCPU.dll` from WinDbg's `amd64\ttd` (tested TTD 1.11.617) | sessions on TTD recordings (`program=ttd:PATH`) |
| `CORVUS_JAVA` | JDK 17+ (`JAVA_HOME`, `PATH`) | the Java decompilers |
| `CORVUS_JAVA_DECOMPILER` | [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp) jar | `decompile_java` |
| `CORVUS_JAVA_DECOMPILER2` | [Vineflower](https://github.com/Vineflower/vineflower) jar | `decompile_java engine=vineflower` |
| `CORVUS_PY_DECOMPILER` | [pycdc](https://github.com/zrax/pycdc) or a program that prints a `.pyc`'s source | source in `summarize_file view=python` |
| `CORVUS_ADB` | `adb` (`PATH`, Android SDK) | the Android device tools |
| `CORVUS_TSHARK` | `tshark` 3+ (`PATH`, Wireshark folder) | packet filters on fields not decoded in process |
| `CORVUS_OSV_SCANNER` | [osv-scanner](https://github.com/google/osv-scanner) 2+ with offline databases | advisories in `summarize_file view=dependencies` |
| `CORVUS_GUARDDOG` | [GuardDog](https://github.com/DataDog/guarddog) 3.2.0; Linux and macOS only | rule matches in `summarize_file view=package` |
| `CORVUS_CAPA` | standalone [capa](https://github.com/mandiant/capa) 10.0.0 | `survey_features` capa labels |
| `CORVUS_EMULATOR` | [speakeasy](https://github.com/mandiant/speakeasy) 2.0.0b9 (report format 5) | `emulate_native engine=speakeasy` |
| `CORVUS_DIE` | Detect It Easy `diec` | `summarize_build detectItEasy=true` |
| `CORVUS_CLR32` | `Corvus.Clr32.exe` (`clr32/` beside the server) | decoding 32-bit .NET dumps |
| `CORVUS_AAPT2`, `CORVUS_APKSIGNER`, `CORVUS_DEX_DISASSEMBLER`, `CORVUS_PROTO_COMPILER`, `CORVUS_WASM_TO_TEXT`, `CORVUS_WASM_VALIDATOR`, `CORVUS_HBC_DISASSEMBLER`, `CORVUS_DEPENDENCY_LISTER`, `CORVUS_DART`, `CORVUS_FLUTTER`, `CORVUS_RCODESIGN`, `CORVUS_ARCHIVE_LISTER`, `CORVUS_LZFSE`, `CORVUS_ASSET_CATALOG_READER`, `CORVUS_ARK_DISASSEMBLER`, `CORVUS_PAK_TOOL`, `CORVUS_GAMEMAKER_TOOL` | aapt2, apksigner, baksmali, protoc, wasm2wat, wasm-validate, hbcdump, syft, Dart SDK, Flutter SDK, rcodesign, 7-Zip, lzfse, carfile-go, ark_disasm, repak, UndertaleModCli | test oracles only |

- osv-scanner: download its databases first (`osv-scanner scan source --offline-vulnerabilities
  --download-offline-databases`); `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` is passed on. Without it, advisories are
  reported not checked.
- GuardDog: `pip install guarddog==3.2.0`; `threat-*` rules are noteworthy; it does not build on Windows.
- capa: on compiled-metadata builds, from a freeze file of the calls the metadata names (format tested with 10.0.0);
  with `category=capa`, labels of PE, ELF and .NET files with ATT&CK and MBC entries, run in the worker host and kept
  per file. Without capa the labels are reported not checked.
- speakeasy: `pip install speakeasy-emulator==2.0.0b9`; another report format is refused by name.
- `CORVUS_PY_DECOMPILER` is used only when set; `CORVUS_GUARDDOG` only when found.

### Network

The server goes online only when a call or command asks for it ([SECURITY.md](../SECURITY.md#network)):

| What | Goes to | Turned off by |
|---|---|---|
| Reference packs for an uninstalled .NET version | nuget.org; SHA-512 checked against its catalog | `CORVUS_OFFLINE` |
| `load_pdb download=true` | symbol server (default `https://msdl.microsoft.com/download/symbols`); debuginfod for ELF | `CORVUS_OFFLINE` |
| `open_minidump downloadDac=true` | symbol server; the DAC is signature-checked | `CORVUS_OFFLINE` |
| Loading a DAC | revocation servers of the DAC's signer; cached data only when offline | `CORVUS_OFFLINE` |
| `--live-install-frida` | pip; hash-checked wheels | `CORVUS_OFFLINE` |
| `corvus rules fetch <pack>` | GitHub; SHA-256 must match the pinned value | `CORVUS_OFFLINE`, or not running it |
| `corvus update`, install scripts | GitHub | not running them |

| Variable | Effect |
|---|---|
| `CORVUS_OFFLINE` | `1`: no downloads of reference packs, symbols, DACs, revocation lists, rule packs or Frida |
| `CORVUS_DEBUGINFOD_URLS` | debuginfod servers for `load_pdb download=true` on ELF (else `DEBUGINFOD_URLS`; none by default) |
| `GITHUB_TOKEN` | optional token for `corvus update` and the install scripts (higher API rate limit); sent to GitHub hosts over HTTPS only |

### Automatic naming

| Variable | Effect |
|---|---|
| `CORVUS_AUTO_PDB` | `0`: do not read a matching local PDB or DWARF automatically |
| `CORVUS_AUTO_NATIVEAOT` | `0`: do not name NativeAOT images from their metadata |
| `CORVUS_AUTO_APPLE_NAMES` | `0`: do not name Mach-O images from Objective-C and Swift metadata |
| `CORVUS_AUTO_DART_NAMES` | `0`: do not name Dart AOT images from their snapshot |

### Output and limits

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_RESULT_MODE` | text | `json`: a structured result's text block is its compact JSON |
| `CORVUS_MAX_LEFTOVER_CALLS` | 2 | cancelled or timed-out calls still running; past it new calls wait, then are refused |

### Worker processes

Untrusted file reads run in `corvus worker` child processes; a crash or memory limit ends the worker and fails the
call, and the server keeps answering.

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_WORKER_HOST` | on | `0`: no workers; files read in the server; `search_container kind=yara` refused |
| `CORVUS_WORKER_MEMORY_MB` | ½ of available | memory limit per worker, at least 256; `0`: none |
| `CORVUS_WORKER_FIXTURE_OPS` | off | `1`: a worker also answers the tests' fixture ops |
| `CORVUS_YARA_LIBRARY` | shipped build | path of a libyara_x_capi 1.22.0 build for an unsupported platform |
| `CORVUS_CHILD_DATA_KB` | — | set by Corvus for a capped Linux child; becomes its RLIMIT_DATA |

- The worker memory limit uses a Windows job object, Linux RLIMIT_DATA or a macOS footprint watchdog. A worker that
  reaches it fails its call with `limit_exceeded` and is replaced.

### Install and update

| Variable | Effect |
|---|---|
| `CORVUS_YES` | `1`: `install` and the install scripts add new clients without asking |
| `CORVUS_REPO` | repository releases come from (`owner/name`) |
| `CORVUS_VERSION`, `CORVUS_HOME`, `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | install-script options ([installation.md](installation.md#install-script)) |
| `CORVUS_REQUIRE_ATTESTATION` | `1`: the install scripts and `update` refuse a build whose provenance `gh` could not check; `0`: skip the check (self-built archive) |
| `CORVUS_RELAY_DIR` | staged copies of the [development reload](installation.md#development-reload) relay |

### Diagnostics

| Variable | Effect |
|---|---|
| `CORVUS_LOCK_CHECK` | `1`: a read without the workspace lock fails (development check) |
| `CORVUS_CLEANUP_LOG` | set: record the decompiler cleanup's rewrite decisions |
