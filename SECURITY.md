# Security policy

## Reporting a vulnerability

Report vulnerabilities in Corvus privately through the repository's **Security** tab ("Report a vulnerability"). Do not
open a public issue for a security problem. Include the version (`corvus version`), the operating system, the MCP
client, and the smallest input or tool call that shows the problem.

Before attaching anything, remove what you may not share: proprietary binaries, crash dumps (they hold process memory),
symbol files, paths, user names and call traces (`--trace-args` traces hold tool arguments). A synthetic or public sample that
reproduces the problem is preferred.

Fixes go into the next release; the release notes name the fixed problem once a release is available.

## Threat model

Corvus analyzes files that may be hostile: malware, tampered builds, crafted containers, dumps and symbol files. The
person running the server and the MCP client it answers are trusted; the analyzed files and everything derived from
them are not. The server analyzes files; it does not run them.

### Untrusted inputs

- **Inputs are read as bytes.** Loading, decompiling, disassembling, unpacking and patching parse files in the server's
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

### Opt-ins that widen the boundary

Off by default, each needs a server option or environment variable chosen by the person running the server:

- `--ida-scripting` (`CORVUS_IDA_SCRIPTING=1`) enables `ida_python`: arbitrary Python in the IDA worker, with the
  server's rights.
- `--ghidra-scripting` (`CORVUS_GHIDRA_SCRIPTING=1`) enables `ghidra_script`: arbitrary Java in the Ghidra worker, with
  the server's rights.
- `--allow-device-changes` (`CORVUS_ALLOW_DEVICE_CHANGES=1`) enables `install_android_package` and
  `uninstall_android_package`, which change a connected Android device through adb. The other device tools only read
  (device facts, package lists, files, logs).
- `--toolsets live` registers `inspect_process` (read-only, above).

### Network

The server reaches the network only:

- to download a .NET reference pack from nuget.org when analyzed code targets an uninstalled .NET version
  (`CORVUS_OFFLINE=1` turns this off);
- when `load_pdb` is called with `download=true` (a symbol server), or `open_minidump` with `downloadDac=true` (the
  runtime's DAC from Microsoft's symbol server); `CORVUS_OFFLINE=1` refuses both;
- when `corvus update` or the install scripts fetch a release from GitHub; a build whose SHA-256 is not in the release's
  `SHA256SUMS` is refused, and `GITHUB_TOKEN` is sent to GitHub hosts over HTTPS only and dropped on redirects;
- through IDA or Ghidra when their own configuration says so (for example IDA's symbol server for a PDB).

### Files written

Tools write only to paths given in the call (saved assemblies and images keep a `.bak` of an original they replace and
never overwrite without `overwrite=true`; device pulls and unpacked containers go where the call says or to a named
folder under the temporary folder), plus per-user caches and annotation files under the data folder
(`<LocalAppData>/Corvus`, `CORVUS_DATA_DIR`). The engine database and code index caches are bounded by size and age
(README, "Server options"; [docs/installation.md](docs/installation.md)). `corvus install` writes only the client
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
Agents that act on results (patching, saving, installing on a device, running scripts with `ida_python` or
`ghidra_script`) should confirm such steps with the user.

## What counts as a vulnerability

Problems inside this boundary are security issues: an input that makes the server execute code from it, write outside
the documented locations, reach the network otherwise, run a script or change a device without its opt-in, or leave
an engine worker running after the server has ended. Crashes and hangs on malformed input are bugs; report them as
issues unless they lead to one of the above.
