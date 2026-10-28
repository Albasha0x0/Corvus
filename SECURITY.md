# Security policy

## Reporting a vulnerability

- Maintainer: Hossain Albasha ([@Albasha0x0](https://github.com/Albasha0x0)), owner and sole maintainer.
- Report privately in the repository's **Security** tab ("Report a vulnerability"); do not open a public issue.
- Include the version (`corvus version`), operating system, MCP client and the smallest input or tool call that shows the problem.
- Remove proprietary binaries, crash dumps, symbol files, paths, user names and call traces (`--trace-args` traces hold tool arguments). Prefer a synthetic or public sample.
- Fixes ship in the next release; its notes name the fixed problem.

## Trust model

- Trusted: the person running the server and the MCP client it answers.
- Untrusted: analyzed files (programs, modified builds, crafted containers, dumps, symbol files) and everything derived from them.
- By default the server reads files and never runs them. Every opt-in below is off by default.

## Untrusted inputs

- Inputs are read as bytes. Nothing from an analyzed file is executed, except as listed here.
  - Malformed files are reported as errors; size and count limits bound allocation and output.
  - Calls still running after their deadline or a client cancel are capped per server (`CORVUS_MAX_LEFTOVER_CALLS`, default 2); past the cap, new calls are refused as busy.
  - FIFOs, sockets and devices are refused.
- `simplify_methods` emulates string-decoder calls in its own IL interpreter.
  - Fixed instruction subset, modelled reflection objects, small 32-bit x86 integer routines; no I/O, nothing run natively, no mutable statics.
  - Instruction budget, 16 MB of simulated memory, 5 s per method. Calls outside the subset are kept and reported ([docs/simplify.md](docs/simplify.md)).
- `emulate_native` interprets code in Ghidra's p-code emulator, in a private scratch area, within an instruction and time budget. Unmodelled calls stop it.
  - `engine=ours` interprets x86, x64 and ARM64 integer code in the server process, in a private 2 MiB region, never natively. System calls, floating point and vector arithmetic stop the run.
  - `engine=speakeasy` runs speakeasy (`CORVUS_EMULATOR`, or on `PATH`) in the worker host with a minimal environment and time, instruction and API-call budgets. It runs against modelled Windows APIs and a virtual file system, never natively.
  - Files it writes go under the data folder's `emulation` folder.
- Crash dumps: .NET heap and stack decoding loads the dump's data access library (DAC) in process only when:
  - its Authenticode signature verifies and chains to a trusted Microsoft root;
  - its signer certificate allows code signing;
  - no certificate in the chain is revoked; for the bundled 32-bit decoder process, its hash is checked too.
  - Revocation is checked online, or from cached data with `CORVUS_OFFLINE=1`. When it cannot be determined, the DAC loads and the result says "revocation not checked".
  - A DAC is downloaded only with `downloadDac=true`.
- `inspect_process` is registered by default with no opt-in. It opens only query and read handles, writes and suspends nothing, and closes every handle before it returns.

## Worker and helper processes

- Read in a Corvus worker process: `summarize_file`, `list_assemblies path=`, `search_container`, the extraction of `unpack_container`, and dump reads (`open_minidump`, `read_dump_memory`, `dump_heap`, `dump_object`).
  - A file that crashes a reader, overflows the stack or exhausts memory (`CORVUS_WORKER_MEMORY_MB`) ends the worker; the call and the requests beside it fail with a named error, and the server keeps answering.
- Still read in the server, where such a file can end it: `load_assembly` and the tools over loaded images, the loading half of `unpack_container`, `dump_stack`, `bucket_minidumps`, and dump reads while images are loaded.
- `--in-process-parsing` and `CORVUS_WORKER_HOST=0` move every file read back into the server.
- IDA (idalib), Ghidra, the JADX server and the 32-bit dump decoder also run as workers.
  - Windows: each runs in a Job Object that ends it with the server and caps its memory (`CORVUS_ENGINE_MEMORY_MB`).
  - Linux and macOS: each leads its own process group, ended within a second of the server ending, even when killed.
  - `get_engine_status` shows the worker's process id.
  - IDA runs with a private user directory and no user plugins; Ghidra with private home, settings, cache and temporary folders.
- Folders workers run code from or write into are closed to other user accounts, even under a shared `CORVUS_DATA_DIR` or `TEMP`.
  - Windows: a protected DACL grants only the user, SYSTEM and Administrators.
  - Elsewhere: mode 0700.
- Engine workers inherit the server's environment (Ghidra without the Java option variables); other external tools get a minimal one.
- The engines parse the input themselves. Report any way through Corvus to reach their own vulnerabilities with more than an input file.

What starts a program outside Corvus:

| Trigger | Program |
|---|---|
| an `engine` argument; `crossCheck=true` on `find_virtual_calls` | IDA or Ghidra |
| `decompile_java` | the JADX server; Vineflower when configured |
| `detectItEasy=true` on `summarize_build` | Detect It Easy |
| the Android device tools (list below) | adb |
| `server_status` | the Python IDA uses (a version probe) |
| `emulate_native engine=speakeasy` | speakeasy |
| a capture filter on a field the built-in decoder does not know | TShark |
| `summarize_file` on Python bytecode; `view=dependencies` advisories | pycdc; osv-scanner (offline) |
| `survey_features` on an image with `global-metadata.dat` | capa |
| a snapshot of a running program on Linux; on macOS | gcore; lldb |
| `ida_python`, `ghidra_script` (opt-in) | code in the engine workers |
| the session tools (opt-in) | a Python worker with Frida's bindings; `live_timeline`: an event trace session; `live_session action=spawn`, `live_console action=start`: the named program |

Android device tools: `list_android_devices`, `get_android_device_info`, `list_android_packages`, `get_android_package_info`, `pull_android_package`, `pull_android_file`, `read_android_log`, `install_android_package`, `uninstall_android_package`.

## Opt-ins that widen the boundary

Each needs a server option or environment variable set by the person running the server ([docs/configuration.md](docs/configuration.md#security-switches)).

- `--ida-scripting` (`CORVUS_IDA_SCRIPTING=1`): `ida_python` runs arbitrary Python in the IDA worker with the server's rights.
- `--ghidra-scripting` (`CORVUS_GHIDRA_SCRIPTING=1`): `ghidra_script` runs arbitrary Java in the Ghidra worker with the server's rights.
- `--live-scripting` (`CORVUS_LIVE_SCRIPTING=1`): `live_script` runs a user-supplied script in the program with its rights; the script can change the program.
- `--allow-replace-original` (`CORVUS_ALLOW_REPLACE_ORIGINAL=1`): `save_assembly` and `save_native` may replace the loaded file (`replaceOriginal=true`, keeping a `.bak`). Otherwise saves write only new files.
- `--allow-device-changes` (`CORVUS_ALLOW_DEVICE_CHANGES=1`): `install_android_package` and `uninstall_android_package` change a connected device. The other device tools only read.
- Session tools (`live_session`, `live_break`, `live_watch`, `live_coverage`, `live_timeline`, `live_read`, `live_events`, `live_console`) are registered but refuse to run without one of:
  - `--allow-live` (`CORVUS_ALLOW_LIVE=1`);
  - `--allow-live-attach` (`CORVUS_ALLOW_LIVE_ATTACH=1`): attach to a running program. `--live-allow` limits attach and start to named programs or folders.
  - `--allow-live-spawn` (`CORVUS_ALLOW_LIVE_SPAWN=1`): `live_session` and `live_console` start a program.
- `--live-install-frida` (`CORVUS_LIVE_INSTALL_FRIDA=1`): with no tested Frida found, the first session installs the pinned Frida into a private Python environment with pip (hash-checked wheels).
- `--toolsets` limits what is registered; without it every tool is registered, `inspect_process` included.

Sessions are for your own programs, which run with your rights.

- **Sessions write the program's memory.** A session loads a Frida script and allocates executable memory; stop points, call recording (`live_watch`) and coverage patch the program's code in memory.
- `live_read` and `inspect_process` only read.
- Stop points hold the hitting thread until `live_break action=continue`.
- Closing the session, its deadline (`CORVUS_LIVE_MAX_MINUTES`, default 30) and server exit release every held thread and end a program the session started.
- A started program's output goes to the session's events, never the protocol stream.
- `live_watch` reads arguments only; `live_coverage` resumes each function-start stop at once and records counts.
- `live_timeline` (Windows) starts an ETW session with the kernel file, registry, network and process providers. It needs administrator rights or Performance Log Users, never touches the program, keeps only the traced process's entries, and stops on `stop`, program exit and server exit; a session left by a stopped server is removed at the next start.
- `live_console` (Windows) starts the named program under ConPTY in a kill-on-close job object, types only the script's `send` text, reads the console, and ends the program on `stop` and server exit.

## Network

The server reaches the network only:

- for a .NET reference pack from nuget.org when analyzed code targets an uninstalled .NET version. The package's SHA-512 must match nuget.org's catalog entry, else it is refused and `server_status` names why;
- with `load_pdb download=true` (a symbol server for a PDB, debuginfod for an ELF; `server` names another) or `open_minidump downloadDac=true` (the DAC from Microsoft's symbol server);
- for `--live-install-frida` (pip, hash-checked wheels), and when a DAC loads, for the revocation lists its signer's chain names;
- for `corvus update` and the install scripts (GitHub releases):
  - a build whose SHA-256 is not in the release's `SHA256SUMS` is refused. This catches corruption, not a tampered release, since both come from the same release.
  - with `gh` signed in, the archive's signed build provenance must name this repository's release workflow and tag, else it is refused;
  - without `gh` the result says "provenance not checked" with the reason; `CORVUS_REQUIRE_ATTESTATION=1` refuses then;
  - `GITHUB_TOKEN` is sent to GitHub hosts over HTTPS only and dropped on redirects;
- for `corvus rules fetch <pack>` (a rule pack's release archive from GitHub): an archive whose SHA-256 differs from the one pinned in Corvus is refused and nothing is installed;
- through IDA or Ghidra when their own configuration says so (for example IDA's symbol server).

Every download uses HTTPS to the servers listed for it; a redirect may go only to that server's known redirect hosts, and never to HTTP. Plain HTTP is used only for a server named in `CORVUS_HTTP_SERVERS`. A private, loopback or link-local address is refused unless it is a symbol or debuginfod server you configured; names are resolved and checked before connecting.

`CORVUS_OFFLINE=1` refuses the reference pack, symbol and DAC downloads, the Frida install, `corvus rules fetch` and `corvus update`, gives the IDA worker a symbol path without servers, and limits revocation checks to cached data. The install scripts run only when you start them. Ghidra follows its own configuration.

## Files written

- Tools write only to paths given in the call; an existing file only with `overwrite=true`; the loaded file only as above.
- Device pulls and extracted containers go where the call says, or to a named folder under the temporary folder.
- Per-user caches and annotations go under the data folder (`<LocalAppData>/Corvus`, `CORVUS_DATA_DIR`); engine database and code index caches are bounded by size and age ([docs/configuration.md](docs/configuration.md)).
- `corvus install` writes only the client configuration files it lists, each with a `.corvus.bak` copy.
- `corvus rules fetch` writes only under `rules/<pack>/<version>/` in the data folder: the rule files and their license.

## Kept results

- A result too large to send is kept for `read_result` under `results` in the data folder (or `CORVUS_RESULT_CACHE`). It survives restarts and is readable by other servers of the same user.
- Each holds analyzed-file content and a side record: the tool, its arguments with secrets masked, a SHA-256 of the unmasked arguments, and the time.
- Deleted after 7 days unused or beyond 512 MB, least recently used first (`CORVUS_RESULT_CACHE_DAYS`, `CORVUS_RESULT_CACHE_MB`). The side record of an evicted result stays a while so a late read can name the call to repeat.
- `CORVUS_RESULT_CACHE=off` keeps them in memory only.
- `corvus uninstall --purge-data` deletes the data folder; a custom `CORVUS_RESULT_CACHE` folder is left to you.

## Logs and traces

- The stderr log has one line per call: tool, outcome, milliseconds, estimated tokens and engine; never arguments.
- The opt-in call trace (`--trace FILE`, `CORVUS_TRACE`) records argument names; values only with `--trace-args` (`CORVUS_TRACE_ARGS=1`). Treat a trace file as sensitive.
- Values can hold paths, code and names from analyzed files. Secrets are written as `[redacted]`, best effort: values of parameters named like passwords, tokens, keys or cookies; `NAME=value` pairs with such names; Bearer and Basic credentials; passwords in URLs; common token shapes.

## Untrusted content in results

- Results quote the analyzed file: symbol and section names, strings, resources, comments, PDB and engine database names, and decompiled code. Treat that text as data to report, never as instructions to follow; it can be written to look like instructions to an AI agent.
- Hosts can key on `_meta["corvus/provenance"]`: `untrustedContent: true` and `source: "analysis_target"` mark every result that may quote a file, errors included. Only `server_status` and `convert_number` are unmarked.
- Agents that act on results (patching, saving, installing on a device, running `ida_python` or `ghidra_script`) should confirm those steps with the user.

## What counts as a vulnerability

- An input that makes the server execute code from it, write outside the documented locations, reach the network otherwise, run a script or change a device without its opt-in, or leave a worker running after the server ended.
- Crashes and hangs on malformed input are bugs; report them as issues unless they lead to one of the above.
