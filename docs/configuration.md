# Configuration

Server options, environment variables and security switches. Setup: [installation.md](installation.md). Command line:
[cli.md](cli.md). Tool arguments: [tools.md](tools.md).

- Options go in the client entry's `args`; variables go in its `env`. An option wins over its variable.
- An environment variable wins over [corvus.json](#config-file). Switch variables take `1`, `true` or `on`.
- `server_status` shows each value in effect and its source.

```json
"corvus": { "command": "corvus", "args": ["--allow-live-attach"], "env": { "CORVUS_OFFLINE": "1" } }
```

## Security switches

- Off by default: the server reads files and runs nothing from them. Each switch widens that.
- Turn one on with `corvus install --set <switch>` ([Claude Code](#claude-code)) or in the entry's `args`.
- `inspect_process` needs no switch. Session tools refuse every call until a `--allow-live*` switch is on.
- Trust model: [SECURITY.md](../SECURITY.md).

| Option | Variable | Allows |
|---|---|---|
| `--allow-live-attach` | `CORVUS_ALLOW_LIVE_ATTACH` | session tools; `live_session action=attach` |
| `--allow-live-spawn` | `CORVUS_ALLOW_LIVE_SPAWN` | session tools; `live_session action=spawn` and `live_console action=start`, which run a program with your rights |
| `--allow-live` | `CORVUS_ALLOW_LIVE` | session tools without opening a program (lists processes); implied by the other live switches |
| `--live-allow <path>` | `CORVUS_LIVE_ALLOW` | limits attach and start to these programs or folders (repeatable; a path list) |
| `--live-scripting` | `CORVUS_LIVE_SCRIPTING` | `live_script`: your script runs with the program's rights |
| `--live-install-frida` | `CORVUS_LIVE_INSTALL_FRIDA` | without a usable Frida, the first session installs 17.24.3 from hash-checked wheels ([Frida](live-inspection.md#frida)); refused offline |
| `--ida-scripting` | `CORVUS_IDA_SCRIPTING` | `ida_python`: any Python in the IDA worker, with the server's rights |
| `--ghidra-scripting` | `CORVUS_GHIDRA_SCRIPTING` | `ghidra_script`: any Java or Python in the Ghidra worker, with the server's rights |
| `--allow-replace-original` | `CORVUS_ALLOW_REPLACE_ORIGINAL` | `save_assembly` and `save_native` with `replaceOriginal=true`; without it they write new files only |
| `--allow-remote-paths` | `CORVUS_ALLOW_REMOTE_PATHS` | UNC paths and network drives in call arguments; paths named inside a file stay local; off under `CORVUS_OFFLINE` |
| `--allow-device-changes` | `CORVUS_ALLOW_DEVICE_CHANGES` | `install_android_package`, `uninstall_android_package`; other device tools only read |
| `--trace-args` | `CORVUS_TRACE_ARGS` | argument values in the `--trace` file; secrets masked, best effort |
| `--in-process-parsing` | `CORVUS_IN_PROCESS_PARSING` | file and dump reads in the server process, not a worker |
| | `CORVUS_LIVE_MAX_MINUTES` | minutes a session stays open (default 30) |

- `--live-allow`: links are resolved first. List only folders that only you can write to.
- `--in-process-parsing` covers `summarize_file`, `list_assemblies path=`, `search_container`, `unpack_container`,
  `open_minidump`, `read_dump_memory`, `dump_heap` and `dump_object`. A file that crashes a reader ends the server.
  By default, a worker that cannot start refuses the call.

### Writing files

Edits stay in memory until a save. Each save is atomic: a temporary file, then a move.

| Argument (`save_assembly`, `save_native`) | Effect |
|---|---|
| none | `save_assembly` writes `<name>.patched.dll`; `save_native` needs `outputPath`; existing files refused |
| `overwrite=true` | replaces an existing file, never the loaded file |
| `replaceOriginal=true` | replaces the loaded file; needs `--allow-replace-original` |
| `versioned=true` | writes the first free `<name>.1.dll`, `<name>.2.dll`, ... |

- `replaceOriginal=true` writes the `.bak` once and refuses a file changed on disk since load.
- `replaceOriginal=true` writes the loaded file and its `.bak` outside the roots; the refused places still apply.
- `CORVUS_OUTPUT_DIRS`: folders a client's tool calls write outputs under (a path list); default: the temporary folder and the client's roots. `<data>/exports` is always one.
- The loaded file's folder is not a root unless it lies inside one: a default output beside it goes to `<data>/exports/<file name>/` and the result says so.
- An explicit path outside the roots is refused; add its folder, or set `CORVUS_OUTPUT_DIRS=*` for the 2.7 behaviour.
- Refused places (`.ssh/`, `.claude/`, PATH folders) stay refused inside every root. The command line and file batches are not held to roots.
- To approve each save in Claude Code, add `"ask": ["mcp__corvus__save_assembly", "mcp__corvus__save_native"]` under `permissions` in `~/.claude/settings.json`.
- Modes that skip approval skip this list. The server switch holds in every mode.

## Claude Code

- Claude Code reads a global `corvus` entry and, per folder, an optional local entry that replaces it (`~/.claude.json`).
- `corvus install` edits both. Restart Claude Code or reconnect `corvus` in `/mcp`.

```sh
corvus install --set allow-live-attach
corvus install --set allow-live-spawn --project .
corvus install --set allow-live-attach,allow-replace-original --project .
corvus install --dry-run --set allow-live-spawn --project .
corvus install --unset allow-live-spawn --project .
```

- Without `--project`, the switch goes to every registered client's global entry. `--project` takes a folder or path.
- With `--project`, a missing local entry is copied from the global one; an existing one keeps its arguments.
- `--unset` removes the option only. A variable in the entry's `env` keeps the switch on; install names it.
- `claude mcp get corvus` shows a folder's `Args:` line, from that folder.
- `server_status` lists switches that are off under `unavailableTools`, each with the option that turns it on.

Limit the programs a session may start or attach to:

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
| `--audit <file>` | `CORVUS_AUDIT` | off | one private JSON line per call: UTC time, account, client, version, tool, arguments (secrets masked), input and result SHA-256 |

- `--timeout`: `export_project` gets 10 times as long. Tools not marked long-running end after twice the value.
- `--toolsets` profiles: `full`, `core` (at most 100 tools), `lean` (at most 40).
- `--toolsets` families: `session`, `dotnet`, `containers`, `edit`, `aot`, `native`, `native-edit`, `builds`, `notes`,
  `engine`, `android`, `dumps`, `live`, `web`. `session` is always included. Combine as `lean,dumps`.
- A tool left out by `--toolsets` is not registered. Naming its family brings it back.
- Without `--toolsets`, a client's default profile only hides tools from the listing. Direct calls still answer.
- `--tools-file`: names separated by spaces, commas or lines; `#` starts a comment; an unknown name stops startup.
  `readonly`: tools that change nothing and write no file. `triage`: a first-look set. `session` tools stay.
- `--engine auto`: IDA, then Ghidra, when either has analyzed the image; otherwise built in.
- `--trace` refuses an engine database path.
- At `information` and below, the log has one line per call (tool, outcome, ms, sizes, engine), never argument values.
  Logs go to stderr; stdout carries only the protocol.

## Config file

`corvus.json` in the data folder (`CORVUS_DATA_DIR`, default `<LocalAppData>/Corvus`), or the file named by
`CORVUS_CONFIG`, sets variables for every server and command this user starts. It is read once at startup.

```json
{
  "CORVUS_OFFLINE": true,
  "CORVUS_ANALYSIS_CACHE_MB": 65536,
  "CORVUS_GHIDRA_DIR": "D:/tools/ghidra"
}
```

- Keys are `CORVUS_` variables. Values are strings, numbers or `true`/`false` (`1`/`0`). Comments and trailing commas are allowed.
- An environment variable wins over the file. An option wins over both. A file that is not valid JSON applies nothing.
- Refused, with a warning: the [security switches](#security-switches) (set them in the client entry),
  `CORVUS_DATA_DIR`, `CORVUS_CONFIG` and `CORVUS_REPO`.
- Program, library, engine folder and URL variables, and `CORVUS_AUDIT`, apply only from a file no other account can write.
  - Windows: no write access for any account but the user, SYSTEM and Administrators.
  - POSIX: owned by the user, with no group or other write.
- `server_status` (`run.config`) names the file, the variables it set, and those lost to the environment or refused.

## Environment variables

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
| `CORVUS_GHIDRA_DECOMPILE_TIMEOUT`, `CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB` | 60, 200 | seconds per decompiled function (1-600); decompiler response limit in MB (16-2048) |
| `CORVUS_ENGINE_ANALYSIS` | `full` | `none`: open images without auto-analysis, for huge or hostile inputs |
| `CORVUS_ENGINE_MEMORY_MB` | ¾ of available | memory limit of each IDA or Ghidra worker (Windows job object); a worker at it is ended; `0`: none |
| `CORVUS_ENGINE_REQUEST_TIMEOUT`, `CORVUS_ENGINE_OPEN_TIMEOUT` | 120, 1200 | seconds per engine request (a stopped request returns what it found); seconds for an engine's start plus auto-analysis |
| `CORVUS_STALL_DIR` | `<analysis cache>/ghidra/stalls` | thread dumps of Ghidra workers stopped for time |

- `CORVUS_IDA_CONNECT`: the image's SHA-256 must match IDA's input. Reads and edits reach that database at once.
  IDA alone saves it. Corvus never rebases, closes or deletes it. No local IDA install is needed.
- PyGhidra offline install: `python -m pip install --no-index -f <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`.

### External programs

Optional. `server_status` shows where each was found, its version, or the fix. A program variable takes the program's
file or its folder.

| Variable | Program | Used for |
|---|---|---|
| `CORVUS_FRIDA_PYTHON` | Python with Frida's bindings (17.24.3 to 17.x) | the session tools' worker |
| `CORVUS_TTD` | folder with `TTDReplay.dll` and `TTDReplayCPU.dll` from WinDbg's `amd64\ttd` (TTD 1.11.617) | sessions on TTD recordings (`program=ttd:PATH`) |
| `CORVUS_JAVA` | JDK 17+ (`JAVA_HOME`, `PATH`) | the Java decompilers |
| `CORVUS_JAVA_DECOMPILER`, `CORVUS_JAVA_DECOMPILER2` | [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp) jar; [Vineflower](https://github.com/Vineflower/vineflower) jar | `decompile_java`; `decompile_java engine=vineflower` |
| `CORVUS_PY_DECOMPILER` | [pycdc](https://github.com/zrax/pycdc) or a program that prints a `.pyc`'s source | source in `summarize_file view=python` |
| `CORVUS_ADB` | `adb` (`PATH`, Android SDK) | the Android device tools |
| `CORVUS_TSHARK` | `tshark` 3+ (`PATH`, Wireshark folder) | packet filters on fields not decoded in process |
| `CORVUS_OSV_SCANNER` | [osv-scanner](https://github.com/google/osv-scanner) 2+ | advisories in `summarize_file view=dependencies` |
| `CORVUS_GUARDDOG` | [GuardDog](https://github.com/DataDog/guarddog) 3.2.0; Linux and macOS only | rule matches in `summarize_file view=package` |
| `CORVUS_CAPA` | standalone [capa](https://github.com/mandiant/capa) 10.0.0 | `survey_features` capa labels |
| `CORVUS_EMULATOR` | [speakeasy](https://github.com/mandiant/speakeasy) 2.0.0b9 (report format 5) | `emulate_native engine=speakeasy` |
| `CORVUS_DIE` | Detect It Easy `diec` | `summarize_build detectItEasy=true` |
| `CORVUS_CLR32` | `Corvus.Clr32.exe` (`clr32/` beside the server) | decoding 32-bit .NET dumps |
| `CORVUS_AAPT2`, `CORVUS_APKSIGNER`, `CORVUS_DEX_DISASSEMBLER`, `CORVUS_PROTO_COMPILER`, `CORVUS_WASM_TO_TEXT`, `CORVUS_WASM_VALIDATOR`, `CORVUS_HBC_DISASSEMBLER`, `CORVUS_DEPENDENCY_LISTER`, `CORVUS_DART`, `CORVUS_FLUTTER`, `CORVUS_RCODESIGN`, `CORVUS_ARCHIVE_LISTER`, `CORVUS_LZFSE`, `CORVUS_ASSET_CATALOG_READER`, `CORVUS_ARK_DISASSEMBLER`, `CORVUS_PAK_TOOL`, `CORVUS_GAMEMAKER_TOOL` | aapt2, apksigner, baksmali, protoc, wasm2wat, wasm-validate, hbcdump, syft, Dart SDK, Flutter SDK, rcodesign, 7-Zip, lzfse, carfile-go, ark_disasm, repak, UndertaleModCli | test oracles only |

- osv-scanner: download its databases first with `osv-scanner scan source --offline-vulnerabilities --download-offline-databases`.
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` is passed on. Without offline databases, advisories are reported as not checked.
- GuardDog: `pip install guarddog==3.2.0`. `threat-*` rules are noteworthy. It does not build on Windows.
- capa: on compiled-metadata builds, from a freeze file of the calls the metadata names. With `category=capa`, labels of
  PE, ELF and .NET files with ATT&CK and MBC entries run in the worker host and are kept per file. Without capa, labels
  are reported as not checked.
- speakeasy: `pip install speakeasy-emulator==2.0.0b9`. Another report format is refused by name.
- `CORVUS_PY_DECOMPILER` is used only when set. `CORVUS_GUARDDOG` is used only when found.

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
| `corvus update` | GitHub | `CORVUS_OFFLINE`, or not running it |
| Install scripts | GitHub | not running them |

- `CORVUS_OFFLINE`: `1` stops downloads of reference packs, symbols, DACs, revocation lists, rule packs, Frida and updates, and the IDA worker's symbol server.
- Downloads use HTTPS to the listed servers only; a redirect may go only to the server's known redirect hosts, and never to HTTP.
- `CORVUS_HTTP_SERVERS`: comma-separated server URLs or hosts that may be used over plain HTTP (internal symbol and debuginfod servers).
- Through a proxy, only IP literals are address-checked.
- A private, loopback or link-local address is refused unless it is a symbol or debuginfod server you configured.
- `CORVUS_DEBUGINFOD_URLS`: debuginfod servers for `load_pdb download=true` on ELF (else `DEBUGINFOD_URLS`; none by default).
- `load_pdb server=` takes only a configured server: `_NT_SYMBOL_PATH`, Microsoft's or a debuginfod variable.
- `GITHUB_TOKEN`: optional token for `corvus update` and the install scripts (higher API rate limit). Sent to GitHub hosts over HTTPS only.

### Naming and output

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_AUTO_PDB` | | `0`: do not read a matching local PDB or DWARF automatically |
| `CORVUS_AUTO_NATIVEAOT` | | `0`: do not name NativeAOT images from their metadata |
| `CORVUS_AUTO_APPLE_NAMES` | | `0`: do not name Mach-O images from Objective-C and Swift metadata |
| `CORVUS_AUTO_DART_NAMES` | | `0`: do not name Dart AOT images from their snapshot |
| `CORVUS_RESULT_MODE` | text | `json`: a structured result's text block is its compact JSON |
| `CORVUS_MAX_LEFTOVER_CALLS` | 2 | cancelled or timed-out calls still running; past it, new calls wait, then are refused |

### Worker processes

Untrusted file reads run in `corvus worker` child processes. A crash or memory limit ends the worker and fails the call;
the server keeps answering.

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_WORKER_HOST` | on | `0`: no workers; files read in the server; `search_container kind=yara` refused |
| `CORVUS_WORKER_MEMORY_MB` | ½ of available | memory limit per worker, at least 256; `0`: none |
| `CORVUS_WORKER_FIXTURE_OPS` | off | `1`: a worker also answers the tests' fixture ops |
| `CORVUS_YARA_LIBRARY` | shipped build | path of a libyara_x_capi 1.22.1 build for an unsupported platform |
| `CORVUS_CHILD_DATA_KB` | | set by Corvus for a capped Linux child; becomes its RLIMIT_DATA |

- The worker memory limit uses a Windows job object, Linux RLIMIT_DATA or a macOS footprint watchdog. A worker that
  reaches it fails its call with `limit_exceeded` and is replaced.

### Install, update and diagnostics

| Variable | Effect |
|---|---|
| `CORVUS_YES` | `1`: `install` and the install scripts add new clients without asking |
| `CORVUS_REPO` | repository releases come from (`owner/name`) |
| `CORVUS_VERSION`, `CORVUS_HOME`, `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | install-script options ([installation.md](installation.md#install-script)) |
| `CORVUS_REQUIRE_ATTESTATION` | `1`: the install scripts and `update` refuse a build whose provenance `gh` could not check; `0`: skip the check (self-built archive) |
| `CORVUS_RELAY_DIR` | staged copies of the [development reload](installation.md#development-reload) relay |
| `CORVUS_RELAY_TARGET` | set by the relay for its server: the publish folder, which takes no outputs |
| `CORVUS_LOCK_CHECK` | `1`: a read without the workspace lock fails (development check) |
| `CORVUS_CLEANUP_LOG` | set: record the decompiler cleanup's rewrite decisions |
