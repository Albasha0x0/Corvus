# Configuration

Every server option, environment variable and safety switch, in one place.

- Options go in the client's server entry (`args`), variables in its `env`; both apply when the client starts the server.
- An option wins over its variable. Switch variables take `1`, `true` or `on`. `server_status` shows the values in effect.
- Elsewhere: setup commands and install-script options in [installation.md](installation.md), command-line arguments
  in [cli.md](cli.md), tool arguments in [tools.md](tools.md).

```json
"corvus": { "command": "corvus", "args": ["--allow-live-attach"], "env": { "CORVUS_OFFLINE": "1" } }
```

| Section | Covers |
|---|---|
| [Security switches](#security-switches) | What can run, attach, change a device or replace the loaded file |
| [Claude Code](#claude-code) | Turning switches on for every project or one, and checking them |
| [Server options](#server-options) | Loading, limits, engines, tool profiles, logging |
| [Environment variables](#environment-variables) | Folders and caches, engines, external programs, network, install |

## Security switches

By default the server reads files and runs nothing from them. Each switch below widens that and is off by default.
Trust model: [SECURITY.md](../SECURITY.md).

Turn one on with `corvus install --set <switch>` ([examples](#claude-code)), or add it to the entry's `args`.

| Option | Variable | Allows |
|---|---|---|
| `--allow-live-attach` | `CORVUS_ALLOW_LIVE_ATTACH` | The session tools, and `live_session action=attach` on a program already running. |
| `--allow-live-spawn` | `CORVUS_ALLOW_LIVE_SPAWN` | The session tools, and `live_session action=spawn` and `live_console action=start` start a program, with your rights. |
| `--allow-live` | `CORVUS_ALLOW_LIVE` | The session tools (`live_session`, `live_break`, `live_watch`, `live_coverage`, `live_timeline`, `live_read`, `live_events`, `live_console`) without opening a program: lists processes. Implied by the two above and `--live-scripting`. |
| `--live-allow <path>` | `CORVUS_LIVE_ALLOW` | Limits attach and start to this program or folder (repeatable; the variable takes a path list). Links are resolved first. List only folders that only you can write to. |
| `--live-scripting` | `CORVUS_LIVE_SCRIPTING` | The session tools, and `live_script` loads a user-supplied script into the program, with the program's rights. |
| `--live-install-frida` | `CORVUS_LIVE_INSTALL_FRIDA` | When no tested Frida is found, the first session downloads Frida 17.24.3 (hash-checked wheels) into a private Python environment under the data folder and uses it ([live-inspection.md](live-inspection.md#frida)). Refused with `CORVUS_OFFLINE=1`. |
| `--ida-scripting` | `CORVUS_IDA_SCRIPTING` | `ida_python`: any Python in the IDA worker, with the server's rights. |
| `--ghidra-scripting` | `CORVUS_GHIDRA_SCRIPTING` | `ghidra_script`: any Java or Python in the Ghidra worker, with the server's rights. |
| `--allow-replace-original` | `CORVUS_ALLOW_REPLACE_ORIGINAL` | `save_assembly` and `save_native` with `replaceOriginal=true` replace the loaded file. Without it they only write new files. |
| `--allow-device-changes` | `CORVUS_ALLOW_DEVICE_CHANGES` | `install_android_package`, `uninstall_android_package`. The other device tools only read. |
| `--trace-args` | `CORVUS_TRACE_ARGS` | The `--trace` file records argument values (paths, code); secrets are masked, best effort. |
| `--in-process-parsing` | `CORVUS_IN_PROCESS_PARSING` | `summarize_file`, `list_assemblies path=`, `search_container` and `unpack_container` read files in the server process, where a file that crashes a reader ends the server. On by default for now; `0` with `CORVUS_WORKER_HOST=1` reads them in a worker process. |
| | `CORVUS_LIVE_MAX_MINUTES` | Minutes a session stays open before it is closed (default 30). |

### Writing files

Edits stay in memory until a save.

| Argument (`save_assembly`, `save_native`) | Effect |
|---|---|
| none | `save_assembly` writes `<name>.patched.dll`; `save_native` needs `outputPath`. An existing file is refused. |
| `overwrite=true` | Replaces an existing file, never the loaded file. |
| `replaceOriginal=true` | Replaces the loaded file; needs `--allow-replace-original`. Its `.bak` is written once and never replaced; a file changed on disk since load is refused. |
| `versioned=true` | Writes `<name>.1.dll`, `<name>.2.dll`, ...: the first free name. |

Every save is atomic: a temporary file, then a move.

Optional: to be asked before each save as well, add the save tools to your client's approval list (Claude Code:
`"permissions": { "ask": ["mcp__corvus__save_assembly", "mcp__corvus__save_native"] }` in `~/.claude/settings.json`).
Modes that skip approval skip this too; the server switch above holds in every mode.

## Claude Code

Claude Code reads a global `corvus` entry and, per folder, an optional local one that replaces it there
(`~/.claude.json`). `corvus install` edits them; restart Claude Code, or reconnect `corvus` in `/mcp`, afterwards.

Turn a switch on for every project (every registered client's global entry):

```sh
corvus install --set allow-live-attach
```

Turn one on for one project only, from its folder (`--project` also takes a path). Without a local entry, one is
made from the global entry (command, arguments, `env`) plus the switch; an existing one keeps its arguments, such as
`--load`:

```sh
corvus install --set allow-live-spawn --project .
```

```text
  ok  Claude Code, project <folder>: added a local entry (copied from the global one)  ~\.claude.json
```

Preview without writing, turn it off again, several at once:

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

In Claude Code, ask for `server_status`: switches that are off are listed under `unavailableTools` with the option that
turns each on, for example `live_session action=attach`: "off: it opens a session on a program already running".

Limit which programs a session may start or attach to (a value, so it goes in the entry's `env` or `args`):

```json
"env": { "CORVUS_ALLOW_LIVE_SPAWN": "1", "CORVUS_LIVE_ALLOW": "<program or folder>" }
```

## Server options

| Option | Variable | Default | Effect |
|---|---|---|---|
| `--load <path>` | `CORVUS_LOAD` (`;`-separated) | | Load a file or folder at startup (repeatable). |
| `--search-dir <dir>` | | | Extra folder for resolving references (repeatable). |
| `--max-output <chars>` | | 60000 | Page size of long results (minimum 2000). |
| `--timeout <s>` | | 180 | Per-call decompilation limit (minimum 5); `export_project` gets 10×, tools not marked long-running end after 2×. |
| `--no-index` | | | Don't index method bodies and build the call graph in the background after loading. |
| `--no-watch` | | | Don't reload loaded files when they change on disk. |
| `--client <id>` | `CORVUS_CLIENT` | detected | The client's limits: output ceiling, call deadline, tool profile ([client table](installation.md#clients)). Written by `corvus install`. |
| `--client-timeout <s>` | `CORVUS_CLIENT_TIMEOUT` | client's | The client's per-call limit, when raised from its default. |
| | `CORVUS_MAX_OUTPUT_TOKENS` | client's | Output ceiling in tokens (500 or more). |
| `--toolsets <list>` | `CORVUS_TOOLSETS` | every tool | Register a profile or families. Profiles: `full`, `core` (at most 100 tools), `lean` (at most 40). Families: `session`, `dotnet`, `containers`, `edit`, `il2cpp`, `native`, `native-edit`, `builds`, `notes`, `engine`, `android`, `dumps`, `live`. Combine: `lean,dumps`. A tool left out still answers a direct call. |
| `--tools-file <file\|readonly\|triage>` | `CORVUS_TOOLS_FILE` | | Register only the tools listed, after `--toolsets`. File: names separated by spaces, commas or lines, `#` comments; an unknown name stops startup. `readonly`: tools that change nothing and write no file. `triage`: a first-look set. |
| `--engine <auto\|ours\|ida\|ghidra>` | `CORVUS_ENGINE` | `auto` | Default engine of the native function, cross-reference and CFG tools. `auto`: IDA, then Ghidra, when either has analyzed the image, else built-in. |
| `--prewarm <ida\|ghidra\|auto\|off>` | `CORVUS_PREWARM` | off | Analyze each native image in that engine in the background as it loads. |
| `--ida-prewarm` | `CORVUS_IDA_PREWARM` | off | Same as `--prewarm ida`. |
| `--index-cache <dir\|off>` | `CORVUS_CODE_INDEX_CACHE` | `code-index` in the data folder | Saved native code indexes, keyed by file SHA-256. |
| `--index-cache-mb <n>` | `CORVUS_CODE_INDEX_CACHE_MB` | 8192 | Size bound of that cache. |
| `--index-cache-days <n>` | `CORVUS_CODE_INDEX_CACHE_DAYS` | 30 | Entries unused this long are deleted. |
| `--binding-style <mono\|hostapi\|il2cpp>` | | `mono` | `generate_cpp_binding` style when a call names none and no host table is found. |
| `--binding-project <dir>` | | | Project folder `generate_cpp_binding` scans for a host table. |
| `--log-level <level>` | `CORVUS_LOG_LEVEL` | `information` | Stderr log: `trace`, `debug`, `information`, `warning`, `error`, `none`. At `information` and below, one line per call: tool, outcome, ms, sizes, engine; never argument values. |
| | `CORVUS_LOG_FORMAT` | text | `json`: log lines as JSON. |
| `--trace <file>` | `CORVUS_TRACE` | off | Append one JSON line per call: time, tool, argument names, ms, error code, result size. An engine database path is refused. |
| `--trace-args` | `CORVUS_TRACE_ARGS` | off | See [Security switches](#security-switches). |

Logs go to stderr; stdout carries only the protocol.

## Environment variables

Variables of the options above are listed with them. A program variable takes the file or its folder.

### Folders and caches

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_DATA_DIR` | `<LocalAppData>/Corvus` | Per-user data folder; the folders below default to entries in it. |
| `CORVUS_ANNOTATIONS_DIR` | | Saved native names, comments and imported name layers. |
| `CORVUS_ANALYSIS_CACHE` | | Saved IDA and Ghidra databases, keyed by file hash. |
| `CORVUS_ANALYSIS_CACHE_MB`, `CORVUS_ANALYSIS_CACHE_DAYS` | 32768, 60 | Bounds of that folder; an entry open in any server is kept. |
| `CORVUS_ENGINE_OUTPUT_MB` | 1024 | Saved engine output (pseudocode, frames), so a later server answers without starting the engine; `0`: off. |
| `CORVUS_RESULT_CACHE` | `results` | Kept results that `read_result` pages; `off`: memory only. They hold analyzed-file content. |
| `CORVUS_RESULT_CACHE_MB`, `CORVUS_RESULT_CACHE_DAYS` | 512, 7 | Bounds of that folder. |
| `CORVUS_JAVA_CACHE` | `java-sources` | Saved `decompile_java` output; `off`: none. |
| `CORVUS_IL2CPP_CACHE` | | Dummy assemblies made by the Il2Cpp metadata reader. |
| `CORVUS_SYMBOL_CACHE` | | Downloaded PDBs and runtime DACs. |
| `CORVUS_DUMP_BUCKET_CACHE` | | Per-dump signatures of `bucket_minidumps`, so a rerun parses only new dumps. |
| `CORVUS_DEBUG_DIRS` | | Path list searched for the separate DWARF of ELF and Mach-O images (`.build-id`, `.gnu_debuglink`, dSYM, dwz). |

### IDA and Ghidra

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_IDA_DIR`, `CORVUS_IDA_PYTHON` | found | IDA folder and the Python for idalib. |
| `CORVUS_GHIDRA_DIR` | `GHIDRA_INSTALL_DIR` | Ghidra 12.0 or newer. |
| `CORVUS_GHIDRA_JAVA` | `JAVA_HOME`, `PATH` | JDK for Ghidra. |
| `CORVUS_GHIDRA_PYTHON` | | Python 3.9+ with PyGhidra; enables Python in `ghidra_script`. Install offline: `python -m pip install --no-index -f <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`. |
| `CORVUS_GHIDRA_ANALYSIS` | `standard` | Analysis profile: `standard`, `full`, `minimal`. |
| `CORVUS_GHIDRA_COMPLETION` | on | `off`: no background pass that completes a `standard` analysis. |
| `CORVUS_GHIDRA_MAXMEM` | | JVM heap of each Ghidra worker. |
| `CORVUS_GHIDRA_OPTIONS` | | Extra analyzer options, `Name=value;...`. |
| `CORVUS_GHIDRA_EXTENSIONS` | | Folder of Ghidra extension zips installed into the workers; nothing is downloaded. |
| `CORVUS_GHIDRA_DECOMPILE_TIMEOUT` | 60 | Seconds per decompiled function (1-600). |
| `CORVUS_GHIDRA_DECOMPILE_PAYLOAD_MB` | 200 | Decompiler response limit (16-2048). |
| `CORVUS_ENGINE_ANALYSIS` | `full` | `none`: open images without auto-analysis, kept apart from fully analyzed databases. For huge or hostile inputs. |
| `CORVUS_ENGINE_MEMORY_MB` | ¾ of available | Memory limit of each IDA or Ghidra worker (Windows job object); `0`: none. |
| `CORVUS_ENGINE_REQUEST_TIMEOUT` | 120 | Seconds per engine request; a stopped request returns what it found. |
| `CORVUS_ENGINE_OPEN_TIMEOUT` | 1200 | Seconds for an engine's start plus auto-analysis. |
| `CORVUS_STALL_DIR` | `<analysis cache>/ghidra/stalls` | Where the thread dump of a Ghidra worker stopped for time is saved. |

### External programs

Optional. `server_status` shows where each was found, its version, or the fix.

| Variable | Program | Used for |
|---|---|---|
| `CORVUS_FRIDA_PYTHON` | Python with Frida's bindings (tested: 17.24.3 to 17.x; 17.0 or newer required) | The session tools' worker. |
| `CORVUS_JAVA` | JDK 17+ (`JAVA_HOME`, `PATH`) | The Java decompilers. |
| `CORVUS_JAVA_DECOMPILER` | [jadx-headless-mcp](https://github.com/1013503897/jadx-headless-mcp) jar | `decompile_java`: Java and Kotlin source. |
| `CORVUS_JAVA_DECOMPILER2` | [Vineflower](https://github.com/Vineflower/vineflower) jar | `decompile_java engine=vineflower`. |
| `CORVUS_PY_DECOMPILER` | [pycdc](https://github.com/zrax/pycdc), or a program that prints the source of the `.pyc` it is given | Python source beside the disassembly in `summarize_file view=python`; used only when set. |
| `CORVUS_ADB` | `adb` (`PATH`, Android SDK) | The Android device tools. |
| `CORVUS_TSHARK` | `tshark` 3+ (`PATH`, Wireshark folder) | Packet filters on fields not decoded in-process. |
| `CORVUS_OSV_SCANNER` | [osv-scanner](https://github.com/google/osv-scanner) 2+ (`PATH`), with offline databases downloaded beforehand (`osv-scanner scan source --offline-vulnerabilities --download-offline-databases`; `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` names their folder and is passed on) | Advisories of the components in `summarize_file view=dependencies`, matched offline by package URL; without it they are reported not checked. |
| `CORVUS_DIE` | Detect It Easy `diec` | `unity_overview detectItEasy=true`. |
| `CORVUS_CLR32` | `Corvus.Clr32.exe` (`clr32/` beside the server) | Decoding 32-bit .NET dumps. |
| `CORVUS_AAPT2`, `CORVUS_APKSIGNER`, `CORVUS_DEX_DISASSEMBLER`, `CORVUS_PROTO_COMPILER`, `CORVUS_WASM_TO_TEXT`, `CORVUS_WASM_VALIDATOR`, `CORVUS_HBC_DISASSEMBLER`, `CORVUS_DEPENDENCY_LISTER` | aapt2, apksigner, baksmali, protoc, wasm2wat, wasm-validate, hbcdump, syft | Test oracles only. |

### Network

The server goes online only when a call or command asks for it: [SECURITY.md](../SECURITY.md#network).

| Variable | Effect |
|---|---|
| `CORVUS_OFFLINE` | `1`: never download reference packs, symbols, a runtime DAC or the private Frida environment. |
| `CORVUS_DEBUGINFOD_URLS` | debuginfod servers for `load_pdb download=true` on ELF (else `DEBUGINFOD_URLS`; none by default). |
| `GITHUB_TOKEN` | Optional token for `corvus update` and the install scripts (a higher GitHub API rate limit); sent to GitHub hosts over HTTPS only. |

### Automatic naming

| Variable | Effect |
|---|---|
| `CORVUS_AUTO_PDB` | `0`: don't read a matching local PDB or DWARF automatically. |
| `CORVUS_AUTO_NATIVEAOT` | `0`: don't name NativeAOT images from their metadata. |
| `CORVUS_AUTO_APPLE_NAMES` | `0`: don't name Mach-O images from Objective-C and Swift metadata. |

### Output and limits

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_RESULT_MODE` | text | `json`: a structured result's text block is its compact JSON. |
| `CORVUS_MAX_LEFTOVER_CALLS` | 2 | Cancelled or timed-out calls that may still run; past it, a new call waits, then is refused as busy. |

### Worker processes

Untrusted work runs in `corvus worker` child processes, so a crash or memory exhaustion ends the worker and the call reports it, while the server keeps answering. No tool uses them yet.

| Variable | Default | Effect |
|---|---|---|
| `CORVUS_WORKER_HOST` | off | `1`: start worker processes for untrusted work. |
| `CORVUS_WORKER_MEMORY_MB` | ½ of available | Memory limit of each worker (Windows job object, Linux RLIMIT_DATA, macOS footprint watchdog), at least 256; `0`: none. A worker that reaches it fails its call with `limit_exceeded` and is replaced. |
| `CORVUS_WORKER_FIXTURE_OPS` | off | `1` in a worker's environment: it also answers the fixture ops the tests use. |
| `CORVUS_YARA_LIBRARY` | shipped build | Full path of a libyara_x_capi 1.22.0 build for `search_container kind=yara` on a platform without one. |
| `CORVUS_CHILD_DATA_KB` | — | Set by Corvus for a Linux child it caps; becomes the child's RLIMIT_DATA and is not passed on. |

### Install and update

| Variable | Effect |
|---|---|
| `CORVUS_YES` | `1`: `install` and the install scripts add new clients without asking. |
| `CORVUS_REPO` | Repository releases are downloaded from (`owner/name`). |
| `CORVUS_VERSION`, `CORVUS_HOME`, `CORVUS_ARCHIVE`, `CORVUS_SHA256SUMS` | Install-script release, folder and offline archive ([installation.md](installation.md#install-script)). |
| `CORVUS_RELAY_DIR` | Staged copies of the development reload relay ([installation.md](installation.md#development-reload)). |

### Diagnostics

| Variable | Effect |
|---|---|
| `CORVUS_LOCK_CHECK` | `1`: a call that reads an assembly without the workspace lock fails (development check). |
| `CORVUS_CLEANUP_LOG` | Set: record the decompiler cleanup's rewrite decisions. |
