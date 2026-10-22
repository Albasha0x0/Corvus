# Security policy

## Reporting a vulnerability

Maintainer: Hossain Albasha ([@Albasha0x0](https://github.com/Albasha0x0)), owner and sole maintainer of Corvus.

Report vulnerabilities in Corvus privately through the repository's **Security** tab ("Report a vulnerability"). Do not
open a public issue for a security problem. Include the version (`corvus version`), the operating system, the MCP
client, and the smallest input or tool call that shows the problem.

Before sharing anything, remove what you may not keep: proprietary binaries, crash dumps (they hold process memory),
symbol files, paths, user names and call traces (`--trace-args` traces hold tool arguments). A synthetic or public sample that
reproduces the problem is preferred.

Fixes go into the next release; the release notes name the fixed problem once a release is available.

## Trust model

Corvus analyzes files that may be untrusted: third-party programs, modified builds, crafted containers, dumps and symbol files. The
person running the server and the MCP client it answers are trusted; the analyzed files and everything derived from
them are not. By default the server reads files and never runs them. The opt-ins below, each off by default, widen
this: the session tools attach to programs running on this machine only with `--allow-live-attach`,
start them only with `--allow-live-spawn` and load scripts into them only with `--live-scripting` (each turns on the
session tools, as `--allow-live` does without opening a program); they are meant for the user's own programs,
and a program run this way runs with the user's rights. The engine scripting tools and the device-changing Android
tools have opt-ins of their own.

### Untrusted inputs

- **Inputs are read as bytes.** Loading, decompiling, disassembling, extracting and patching parse files in the server's
  own process. Nothing from an analyzed file is executed, with the exceptions below. Malformed files are reported as
  errors; size and count limits bound what one input can make the server allocate or return. Calls that keep running
  after their deadline or a client cancel are capped per server (`CORVUS_MAX_LEFTOVER_CALLS`, default 2); past the cap
  new calls are refused as busy. Paths that are FIFOs,
  sockets or devices are refused instead of read.
- **`simplify_methods`** evaluates string-decoder calls in a safe IL interpreter: a fixed instruction subset, no I/O,
  reflection, native code or mutable statics, an instruction budget, 16 MB of simulated memory and 5 s per method.
  Calls outside that subset are left in place and reported ([docs/simplify.md](docs/simplify.md)).
- **`emulate_native`** interprets an image's code as Ghidra p-code in Ghidra's emulator, inside a private scratch area,
  within an instruction and time budget. Nothing runs natively, and unmodelled calls stop the emulation.
  With `engine=speakeasy` it runs speakeasy (`CORVUS_EMULATOR`, only when set or on `PATH`) in the worker host, with a
  minimal environment and a time, instruction and API-call budget: the program's code runs on speakeasy's CPU emulator
  against modelled Windows APIs and a virtual file system, never natively; files it writes are saved under the data
  folder's `emulation` folder, not on their own paths.
- **Crash dumps.** .NET heap and stack decoding loads the dump's own runtime data-access library (DAC). It is loaded
  only after its Microsoft signature (and, for the bundled 32-bit decoder process, its hash) is verified; a DAC is
  downloaded only when a call passes `downloadDac=true`.
- **`inspect_process`** (opt-in toolset `live`) opens only query and read handles to a running process, writes and
  suspends nothing, and closes every handle before it returns.

### External engines and helper processes

`decompile_native` and the IDA and Ghidra modes of other tools run IDA (through idalib) or Ghidra in separate worker
processes; the JADX server and the 32-bit dump decoder are workers too. On Windows each worker runs in a Job Object that
ends it with the server and caps its memory (`CORVUS_ENGINE_MEMORY_MB`). On Linux and macOS each worker leads a process group
of its own, and a shell parent ends that group within a second of the server ending, also when the server is killed
outright; `get_engine_status` shows the worker's own process id. IDA runs with a private user
directory and no user plugins; Ghidra runs with private home, settings, cache and temporary folders. Workers inherit the
server's environment, minus the Java option variables for Ghidra; the JADX server and other external tools get a
minimal one. These engines are third-party programs that parse the input themselves; their own vulnerabilities are
outside this boundary, but report a way through Corvus to reach them with more than an input file.

Files are read in a worker process of Corvus itself: `summarize_file`, `list_assemblies path=`, `search_container`,
the extraction of `unpack_container` and the dump reads (`open_minidump`, `read_dump_memory`, `dump_heap`,
`dump_object`). A file that crashes a reader, overflows the stack or exhausts memory there ends the worker, under the
same Job Object or process group and memory limit (`CORVUS_WORKER_MEMORY_MB`), and the call fails with a named error
while the server keeps answering; requests running beside it on the same worker fail too. These still read in the
server, where such a file can end it: `load_assembly` and the tools over loaded images, the loading half of
`unpack_container`, `dump_stack`, `bucket_minidumps`, and dump reads while images are loaded (they name frames from
those images). `--in-process-parsing` and `CORVUS_WORKER_HOST=0` move every file read back into the server.

What starts a process outside the server's own: an `engine` argument (IDA or Ghidra, on every tool that takes one),
`crossCheck=true` on `find_virtual_calls` (IDA, else Ghidra), `decompile_java` (the JADX server), `detectItEasy=true`
on `unity_overview` (Detect It Easy), the Android device tools (adb: `list_android_devices`, `get_android_device_info`,
`list_android_packages`, `get_android_package_info`, `pull_android_package`, `pull_android_file`, `read_android_log`,
`install_android_package`, `uninstall_android_package`), `server_status` (probes the Python IDA uses) and `inspect_process` (reads another process).
Behind their opt-ins (below): `ida_python` and `ghidra_script` (in the engine workers) and the session tools (a Python
worker with Frida's bindings; `live_timeline` an event tracing session; `live_session action=spawn` and
`live_console action=start` the program they name).

### Opt-ins that widen the boundary

Off by default, each needs a server option or environment variable chosen by the person running the server
([docs/configuration.md](docs/configuration.md#security-switches)):

- `--ida-scripting` (`CORVUS_IDA_SCRIPTING=1`) enables `ida_python`: arbitrary Python in the IDA worker, with the
  server's rights.
- `--ghidra-scripting` (`CORVUS_GHIDRA_SCRIPTING=1`) enables `ghidra_script`: arbitrary Java in the Ghidra worker, with
  the server's rights.
- `--allow-replace-original` (`CORVUS_ALLOW_REPLACE_ORIGINAL=1`) lets `save_assembly` and `save_native` replace the
  loaded file (`replaceOriginal=true`, with a `.bak`); without it saves write only new files.
- `--allow-device-changes` (`CORVUS_ALLOW_DEVICE_CHANGES=1`) enables `install_android_package` and
  `uninstall_android_package`, which change a connected Android device through adb. The other device tools only read
  (device facts, package lists, files, logs).
- `--allow-live` (`CORVUS_ALLOW_LIVE=1`), or any of the three switches below, enables the session tools (`live_session`, `live_break`, `live_watch`,
  `live_coverage`, `live_timeline`, `live_read`, `live_events`, `live_console`); `--allow-live-attach` (`CORVUS_ALLOW_LIVE_ATTACH=1`) also
  lets `live_session` attach to a running program, `--allow-live-spawn` (`CORVUS_ALLOW_LIVE_SPAWN=1`) lets `live_session` and `live_console`
  start one, and `--live-allow` limits both to named programs or folders. A session runs a Python worker with Frida's bindings, which loads a script into
  the program: stop points hold the hitting thread until `live_break action=continue`, and the program's memory is
  read, never written. Closing a session, its deadline (`CORVUS_LIVE_MAX_MINUTES`, default 30) and server exit
  release every held thread and end a program the session started; a started program's output reaches the session's
  events, never the server's protocol stream. `live_watch` records calls through the same script and reads arguments
  only. `live_coverage` places stop points at function starts and resumes each stop at once; it records counts only. `live_timeline` starts an event tracing session (ETW, Windows) with the kernel file, registry, network and process providers; it needs administrator rights or membership in Performance Log Users, reads what the OS reports, never touches the program, keeps only the traced process's entries, and stops its tracing session on `stop`, program exit and server exit (a session a stopped server left behind is removed by the next start). `live_console` starts the program it names under the Windows pseudoconsole (ConPTY) inside a kill-on-close job object, types only the script's `send` text into its console, reads what the console shows, and ends the program on `stop` and server exit (the job ends it should the server be killed). `--live-scripting` (`CORVUS_LIVE_SCRIPTING=1`) also enables `live_script`, which loads a user-supplied script
  into the program: it runs with the program's rights and can change it.
- `--toolsets live` registers `inspect_process` (read-only, above) and the session tools.

### Network

The server reaches the network only:

- to download a .NET reference pack from nuget.org when analyzed code targets an uninstalled .NET version
  (`CORVUS_OFFLINE=1` turns this off);
- when `load_pdb` is called with `download=true` (a symbol server for a PDB, debuginfod for an ELF; `server` names
  another), or `open_minidump` with `downloadDac=true` (the runtime's DAC from Microsoft's symbol server);
  `CORVUS_OFFLINE=1` refuses all of them;
- when `corvus update` or the install scripts fetch a release from GitHub; a build whose SHA-256 is not in the release's
  `SHA256SUMS` is refused, and `GITHUB_TOKEN` is sent to GitHub hosts over HTTPS only and dropped on redirects;
- through IDA or Ghidra when their own configuration says so (for example IDA's symbol server for a PDB).

### Files written

Tools write only to paths given in the call (saved assemblies and images replace the loaded file only with
`replaceOriginal=true` on a server started with `--allow-replace-original`, keeping a `.bak`, and another existing file only with `overwrite=true`; device pulls and extracted containers go where the call says or to a named
folder under the temporary folder), plus per-user caches and annotation files under the data folder
(`<LocalAppData>/Corvus`, `CORVUS_DATA_DIR`). The engine database and code index caches are bounded by size and age
([docs/configuration.md](docs/configuration.md)). `corvus install` writes only the client
configuration files it lists, each with a `.corvus.bak` copy of the previous version.

### Kept results

A result too large to send is kept so `read_result` can page, search or export it. Kept results are written to
`results` in the data folder (or `CORVUS_RESULT_CACHE`) and stay readable across restarts and by other servers of the
same user. They hold analyzed-file content (decompiled code, strings, names) and a side record of the call: the tool,
its arguments with secrets masked as in traces, a SHA-256 of the unmasked arguments and the time. They are deleted
after 7 days unused or beyond 512 MB, least recently used first (`CORVUS_RESULT_CACHE_DAYS`, `CORVUS_RESULT_CACHE_MB`);
a small side record of an evicted result is kept a while longer so a late read can name the call to repeat.
`CORVUS_RESULT_CACHE=off` keeps them in memory only, gone when the server exits. `corvus uninstall --purge-data` deletes
the data folder with them; a custom `CORVUS_RESULT_CACHE` folder is left for you to delete.

### Logs and traces

The stderr log has one line per tool call with the tool, outcome, milliseconds, estimated tokens of the text and
structured parts and the engine used, never the arguments. The opt-in call trace (`--trace FILE`, `CORVUS_TRACE`) records argument names; their values only with
`--trace-args` (`CORVUS_TRACE_ARGS=1`). Values can hold paths, code and names from analyzed files; secrets in them (values of parameters named like passwords, tokens, keys or cookies, `NAME=value`
pairs with such names, Bearer and Basic credentials, passwords in URLs and common token shapes) are written as
`[redacted]`, on a best-effort basis. Treat a trace file as sensitive.

## Untrusted content in results

Tool results quote the analyzed file: symbol and section names, strings, resources, comments and names stored in a PDB or
an engine database, and code decompiled from it. Whoever built the file chose that text, and it can be written to look
like instructions to an AI agent or its user ("ignore previous instructions", "run this command"). Treat everything a
tool returns about a file as data to report, never as instructions to follow; the server's own guidance says so too.
Hosts and automation can key on the result itself: `_meta["corvus/provenance"]` carries `untrustedContent: true` and
`source: "analysis_target"` on every result that may quote a file, errors included (only `server_status` and
`convert_number`, which never do, are unmarked).
Agents that act on results (patching, saving, installing on a device, running scripts with `ida_python` or
`ghidra_script`) should confirm such steps with the user.

## What counts as a vulnerability

Problems inside this boundary are security issues: an input that makes the server execute code from it, write outside
the documented locations, reach the network otherwise, run a script or change a device without its opt-in, or leave
an engine worker running after the server has ended. Crashes and hangs on malformed input are bugs; report them as
issues unless they lead to one of the above.
