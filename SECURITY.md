# Security policy

## Reporting a vulnerability

Maintainer: Hossain Albasha ([@Albasha0x0](https://github.com/Albasha0x0)), owner and sole maintainer of Corvus.

Report privately through the repository's **Security** tab ("Report a vulnerability"), not in a public issue. Include
the version (`corvus version`), the operating system, the MCP client and the smallest input or tool call that shows
the problem.

Before sharing, remove what you may not share: proprietary binaries, crash dumps (they hold process memory), symbol
files, paths, user names and call traces (`--trace-args` traces hold tool arguments). A synthetic or public sample is
preferred. Fixes go into the next release; its notes name the fixed problem.

## Trust model

The person running the server and the MCP client it answers are trusted. Analyzed files (third-party programs,
modified builds, crafted containers, dumps, symbol files) and everything derived from them are not. By default the
server reads files and never runs them. The opt-ins below, each off by default, widen this.

### Untrusted inputs

- **Inputs are read as bytes.** Loading, decompiling, disassembling, extracting and patching parse files; nothing from
  an analyzed file is executed, except as listed here. Malformed files are reported as errors; size and count limits
  bound allocation and output. Calls still running after their deadline or a client cancel are capped per server
  (`CORVUS_MAX_LEFTOVER_CALLS`, default 2); past the cap new calls are refused as busy. FIFOs, sockets and devices
  are refused.
- **`simplify_methods`** emulates string-decoder calls in its own IL interpreter: a fixed instruction subset, modelled
  reflection objects, small 32-bit x86 integer routines interpreted, no I/O, nothing run natively, no mutable statics;
  an instruction budget, 16 MB of simulated memory and 5 s per method. Calls outside the subset are kept and reported
  ([docs/simplify.md](docs/simplify.md)).
- **`emulate_native`** interprets code as Ghidra p-code in Ghidra's emulator, in a private scratch area, within an
  instruction and time budget; unmodelled calls stop it. With `engine=speakeasy` it runs speakeasy (`CORVUS_EMULATOR`,
  only when set or on `PATH`) in the worker host with a minimal environment and a time, instruction and API-call
  budget: the code runs on speakeasy's CPU emulator against modelled Windows APIs and a virtual file system, never
  natively; files it writes go under the data folder's `emulation` folder.
- **Crash dumps.** .NET heap and stack decoding loads the dump's runtime data-access library (DAC) in process, only
  after its Authenticode signature verifies and chains to a trusted Microsoft root, its signer certificate allows code
  signing, and no certificate in the chain is revoked (for the bundled 32-bit decoder process, also its hash).
  Revocation is checked online, or from cached data with `CORVUS_OFFLINE=1`; when it cannot be determined the DAC
  loads and the result says "revocation not checked". A DAC is downloaded only with `downloadDac=true`.
- **`inspect_process`** is registered by default and needs no opt-in. It opens only query and read handles to a
  running process, writes and suspends nothing, and closes every handle before it returns.

### Worker and helper processes

Files are read in a Corvus worker process: `summarize_file`, `list_assemblies path=`, `search_container`, the
extraction of `unpack_container` and the dump reads (`open_minidump`, `read_dump_memory`, `dump_heap`, `dump_object`).
A file that crashes a reader, overflows the stack or exhausts memory ends the worker (`CORVUS_WORKER_MEMORY_MB`), and
the call, plus requests running beside it on that worker, fail with a named error while the server keeps answering.
Still read in the server, where such a file can end it: `load_assembly` and the tools over loaded images, the loading
half of `unpack_container`, `dump_stack`, `bucket_minidumps`, and dump reads while images are loaded.
`--in-process-parsing` and `CORVUS_WORKER_HOST=0` move every file read back into the server.

IDA (through idalib), Ghidra, the JADX server and the 32-bit dump decoder also run as workers. On Windows each worker
runs in a Job Object that ends it with the server and caps its memory (`CORVUS_ENGINE_MEMORY_MB`); on Linux and macOS
each leads its own process group, which a shell parent ends within a second of the server ending, even when the server
is killed. `get_engine_status` shows the worker's process id. IDA runs with a private user directory and no user
plugins; Ghidra with private home, settings, cache and temporary folders. The folders workers run code from or write
into (worker scripts and builds, these private folders, per-worker temporary folders, memory captures) are closed to
other user accounts, even under a shared `CORVUS_DATA_DIR` or `TEMP`: on Windows a protected DACL grants only the
user, SYSTEM and Administrators; elsewhere they are created with mode 0700. Engine workers inherit the server's
environment (Ghidra without the Java option variables); other external tools get a minimal one. These engines parse
the input themselves; their own vulnerabilities are outside this boundary, but report any way through Corvus to reach
them with more than an input file.

What starts a program outside Corvus:

| Trigger | Program |
|---|---|
| an `engine` argument (every tool that takes one); `crossCheck=true` on `find_virtual_calls` | IDA or Ghidra |
| `decompile_java` | the JADX server; Vineflower when configured |
| `detectItEasy=true` on `unity_overview` | Detect It Easy |
| the Android device tools: `list_android_devices`, `get_android_device_info`, `list_android_packages`, `get_android_package_info`, `pull_android_package`, `pull_android_file`, `read_android_log`, `install_android_package`, `uninstall_android_package` | adb |
| `server_status` | the Python IDA uses (a version probe) |
| `inspect_process` | none; it reads another process |
| `emulate_native engine=speakeasy` | speakeasy |
| a capture filter on a field the built-in decoder does not know | TShark |
| `summarize_file` on Python bytecode; `summarize_file view=dependencies` (advisories) | pycdc; osv-scanner (offline) |
| `survey_features` on an Il2Cpp build | capa |
| a snapshot of a running program on Linux; on macOS | gcore; lldb |
| `ida_python`, `ghidra_script` (behind their opt-ins) | code in the engine workers |
| the session tools (behind their opt-ins) | a Python worker with Frida's bindings; `live_timeline` an event tracing session; `live_session action=spawn` and `live_console action=start` the program they name |

### Opt-ins that widen the boundary

Off by default; each needs a server option or environment variable chosen by the person running the server
([docs/configuration.md](docs/configuration.md#security-switches)):

- `--ida-scripting` (`CORVUS_IDA_SCRIPTING=1`): `ida_python` runs arbitrary Python in the IDA worker with the server's
  rights.
- `--ghidra-scripting` (`CORVUS_GHIDRA_SCRIPTING=1`): `ghidra_script` runs arbitrary Java in the Ghidra worker with the
  server's rights.
- `--allow-replace-original` (`CORVUS_ALLOW_REPLACE_ORIGINAL=1`): `save_assembly` and `save_native` may replace the
  loaded file (`replaceOriginal=true`, keeping a `.bak`); otherwise saves write only new files.
- `--allow-device-changes` (`CORVUS_ALLOW_DEVICE_CHANGES=1`): `install_android_package` and `uninstall_android_package`
  change a connected device through adb. The other device tools only read.
- Session tools (`live_session`, `live_break`, `live_watch`, `live_coverage`, `live_timeline`, `live_read`,
  `live_events`, `live_console`) are registered by default but refuse to run without `--allow-live`
  (`CORVUS_ALLOW_LIVE=1`) or one of: `--allow-live-attach` (`CORVUS_ALLOW_LIVE_ATTACH=1`, attach to a running program),
  `--allow-live-spawn` (`CORVUS_ALLOW_LIVE_SPAWN=1`, `live_session` and `live_console` start one); `--live-allow`
  limits both to named programs or folders. They are meant for your own programs, which run with your rights.
  - **Sessions write the program's memory.** A session loads a Frida script into the program; the agent allocates
    executable memory there, and stop points, call recording (`live_watch`) and coverage are hooks that patch the
    program's code in memory. `live_read` and `inspect_process` only read. Stop points hold the hitting thread until
    `live_break action=continue`; closing the session, its deadline (`CORVUS_LIVE_MAX_MINUTES`, default 30) and server
    exit release every held thread and end a program the session started. A started program's output goes to the
    session's events, never the protocol stream.
  - `live_watch` reads arguments only; `live_coverage` resumes each function-start stop at once and records counts.
  - `live_timeline` (Windows) starts an ETW session with the kernel file, registry, network and process providers; it
    needs administrator rights or Performance Log Users, never touches the program, keeps only the traced process's
    entries, and stops on `stop`, program exit and server exit (a session a stopped server left is removed at the next
    start).
  - `live_console` (Windows) starts the named program under ConPTY in a kill-on-close job object, types only the
    script's `send` text, reads the console, and ends the program on `stop` and server exit.
- `--live-scripting` (`CORVUS_LIVE_SCRIPTING=1`) also enables `live_script`: a user-supplied script runs in the program
  with its rights and can change it.
- `--live-install-frida` (`CORVUS_LIVE_INSTALL_FRIDA=1`): with no tested Frida found, the first session installs the
  pinned Frida into a private Python environment with pip (hash-checked wheels).

`--toolsets` limits what is registered; without it every tool is registered, `inspect_process` included.

### Network

The server reaches the network only:

- for a .NET reference pack from nuget.org when analyzed code targets an uninstalled .NET version (the package's SHA-512
  must match nuget.org's catalog entry, else it is refused and `server_status` names why);
- with `load_pdb download=true` (a symbol server for a PDB, debuginfod for an ELF; `server` names another) or
  `open_minidump downloadDac=true` (the DAC from Microsoft's symbol server);
- for `--live-install-frida` (pip, hash-checked wheels);
- when a DAC loads, for the certificate revocation lists its signer's chain names (cached data only with
  `CORVUS_OFFLINE=1`);
- for `corvus update` and the install scripts (GitHub releases): a build whose SHA-256 is not in the release's
  `SHA256SUMS` is refused. `SHA256SUMS` comes from the same release, so this catches corruption, not a tampered
  release; with `gh` signed in, the archive's signed build provenance must name this repository's release workflow
  (and the tag), else it is refused. Without `gh` the result says "provenance not checked" with the reason;
  `CORVUS_REQUIRE_ATTESTATION=1` refuses then. `GITHUB_TOKEN` is sent to GitHub hosts over HTTPS only and dropped on redirects;
- for `corvus rules fetch <pack>` (a rule pack's release archive from GitHub): an archive whose SHA-256 differs from the
  one pinned in Corvus is refused and nothing is installed; refused with `CORVUS_OFFLINE=1`;
- through IDA or Ghidra when their own configuration says so (for example IDA's symbol server).

`CORVUS_OFFLINE=1` refuses the first three and keeps the fourth to cached data; updates and installs run only when
you start them, and the engines follow their own configuration.

### Files written

Tools write only to paths given in the call (another existing file only with `overwrite=true`; the loaded file only
as above), device pulls and extracted containers where the call says or to a named folder under the temporary folder,
and per-user caches and annotations under the data folder (`<LocalAppData>/Corvus`, `CORVUS_DATA_DIR`). Engine
database and code index caches are bounded by size and age ([docs/configuration.md](docs/configuration.md)).
`corvus install` writes only the client configuration files it lists, each with a `.corvus.bak` copy.
`corvus rules fetch` writes only under the data folder's `rules/<pack>/<version>/`: the rule files and their license.

### Kept results

A result too large to send is kept for `read_result` under `results` in the data folder (or `CORVUS_RESULT_CACHE`),
readable across restarts and by other servers of the same user. It holds analyzed-file content (decompiled code,
strings, names) and a side record: the tool, its arguments with secrets masked as in traces, a SHA-256 of the unmasked
arguments and the time. Kept results are deleted after 7 days unused or beyond 512 MB, least recently used first
(`CORVUS_RESULT_CACHE_DAYS`, `CORVUS_RESULT_CACHE_MB`); a small side record of an evicted result stays a while so a late
read can name the call to repeat. `CORVUS_RESULT_CACHE=off` keeps them in memory only. `corvus uninstall --purge-data`
deletes the data folder; a custom `CORVUS_RESULT_CACHE` folder is left to you.

### Logs and traces

The stderr log has one line per call: tool, outcome, milliseconds, estimated tokens and the engine, never arguments.
The opt-in call trace (`--trace FILE`, `CORVUS_TRACE`) records argument names, and their values only with
`--trace-args` (`CORVUS_TRACE_ARGS=1`). Values can hold paths, code and names from analyzed files; secrets (values of
parameters named like passwords, tokens, keys or cookies, `NAME=value` pairs with such names, Bearer and Basic
credentials, passwords in URLs, common token shapes) are written as `[redacted]`, best effort. Treat a trace file as
sensitive.

## Untrusted content in results

Results quote the analyzed file: symbol and section names, strings, resources, comments, names stored in a PDB or an
engine database, and decompiled code. Whoever built the file chose that text, and it can be written to look like
instructions to an AI agent ("ignore previous instructions", "run this command"). Treat everything a tool returns
about a file as data to report, never as instructions to follow; the server's own guidance says so too. Hosts can key
on `_meta["corvus/provenance"]`: `untrustedContent: true` and `source: "analysis_target"` on every result that may
quote a file, errors included (only `server_status` and `convert_number`, which never do, are unmarked). Agents that
act on results (patching, saving, installing on a device, running `ida_python` or `ghidra_script`) should confirm such
steps with the user.

## What counts as a vulnerability

Inside this boundary: an input that makes the server execute code from it, write outside the documented locations,
reach the network otherwise, run a script or change a device without its opt-in, or leave a worker running after the
server has ended. Crashes and hangs on malformed input are bugs; report them as issues unless they lead to one of the
above.
