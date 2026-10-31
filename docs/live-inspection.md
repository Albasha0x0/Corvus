# Live process inspection and sessions

| | `inspect_process` | Session tools (`live_*`) |
|---|---|---|
| What it does | one read-only look: modules, regions, threads, stacks, UI elements | start or attach, stop points, call records, coverage, traces |
| Writes the program's memory | no | yes: stop points, watches and coverage patch code ([Sessions](#sessions)) |
| Opt-in | none; registered by default | registered by default, refused until an opt-in switch is on |
| Platforms | Windows (elsewhere `provider_unavailable`) | Windows, Linux, macOS; `live_timeline` and `live_console` Windows only |

- `inspect_process` takes a pid, a name or a session id (`live-1`).
- Addresses are named as in `dump_stack`: user renames, PDB, compiled-metadata and discovered names, then assemblies made for `GameAssembly.dll`, a local PDB, then exports.

## The read-only guarantee

`inspect_process` opens these handles:

| Object | API | Access rights | Lifetime |
|---|---|---|---|
| The process | `OpenProcess` | `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ` (0x410) | the call |
| Each listed thread | `OpenThread` | `THREAD_GET_CONTEXT \| THREAD_QUERY_INFORMATION` (0x48) | closed after the thread is read |
| The thread list | `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` | none on the target (system-wide) | the call |
| Selection by name or id | the system process list | none on the target | the call |

- Never called, and not bound: `WriteProcessMemory`, `VirtualProtectEx`, `VirtualAllocEx`, `DebugActiveProcess` (DbgEng too), `SuspendThread`, `NtSuspendProcess`, `SetThreadContext`, `CreateRemoteThread`, `QueueUserAPC`, handle duplication, privilege change (SeDebugPrivilege stays off), dump writing.
- Every handle closes before the call returns, also on error, cancellation and timeout; a timeout cancels at the next module, region batch, thread or frame. The report states `handlesOpened`, `handlesClosed` (equal) and `detached`.
- `GetThreadContext` on a running thread captures registers with a kernel-mode APC: no user code runs and the suspend count is unchanged. A thread running user code may show a stale frame.

## Windows and their handlers

`inspect_process view=windows` (needs `--allow-window-capture`) lists the UI Automation control view of the visible top-level windows, depth first: control type, name, automation id, class name, framework, bounds and window handle.

- An element with a window handle names its class window procedure (`GetClassLongPtr(GCLP_WNDPROC)`); a child control also names its control id and the parent procedure that gets `WM_COMMAND` and `WM_NOTIFY`.
- `imagePath` saves a PNG of the first window (`PrintWindow`, `PW_RENDERFULLCONTENT`). The program's UI threads answer `WM_GETOBJECT` and `WM_PRINT`; no other handle or right is added. Queries time out after 2 s to connect and 5 s per call.
- Another process cannot read a window's `GWLP_WNDPROC` or `DWLP_DLGPROC`; Windows returns 0, so such a handler is reported as unknown.
- At most 2,000 elements and 16 levels; the result names the cut.

## Sessions

### Opt-in

Registered by default; refused until the server starts with one of these switches. Each allows only its own action:

| Switch | Variable | Also allows |
|---|---|---|
| `--allow-live` | `CORVUS_ALLOW_LIVE=1` | nothing more: no attach, no start |
| `--allow-live-attach` | `CORVUS_ALLOW_LIVE_ATTACH=1` | attach to a running program |
| `--allow-live-spawn` | `CORVUS_ALLOW_LIVE_SPAWN=1` | start a program listed by `--live-allow` (`live_session action=spawn`, `live_console action=start`) |
| `--live-scripting` | `CORVUS_LIVE_SCRIPTING=1` | `live_script` |

- These are server start-up switches; the model cannot turn them on. See [configuration.md](configuration.md#security-switches).
- `--live-allow <program or folder>` (repeatable) limits attach and spawn to the listed programs. Spawn needs it; `--live-allow *` allows any program.
- The check uses the final path (links resolved in every folder) and, for a running program, the image path the OS reports. Anything else is refused before a session opens.
- List only folders you alone can write to: a file copied or hard-linked into one counts as inside it. `server_status` shows the list.

### What a session writes

- Only `live_read` and `inspect_process` are read-only.
- A session loads Frida's agent into the program (on Windows, a `PAGE_EXECUTE_READWRITE` page with a stub). Stop points, watches and coverage are Frida Interceptor hooks that patch code in memory.
- `live_script` runs your code inside the program with its rights. Run untrusted programs only in a disposable virtual machine: a session observes a program, it does not contain it.

### V8 inspector

Start: `live_session action=attach program=inspector:PORT` on a Node or Electron program started with `--inspect=PORT` or `--inspect-brk=PORT` (Electron: `--remote-debugging-port=PORT`).

Requires a loopback host: `inspector:HOST:PORT`, `inspector:ws://HOST:PORT/ID`, and a `#TARGET` suffix (id, type or title) name other targets. Only loopback hosts are accepted, since an inspector runs any code it is sent.

- Corvus uses the Chrome DevTools Protocol and loads nothing except the IPC recorder. Closing removes stop points and lets the program run on.
- `live_break at=FILE:LINE` takes an original source a map names (`src/app.ts:12`) and sets the point on its first generated position on that line, or the next line with code; a FILE not loaded yet is set by URL. `wait=true` returns paused frames with their original positions.
- `--inspect-brk` starts suspended: set stop points, then `continue`.
- `live_session action=status` lists scripts with their source maps; `live_events kind=output` shows `console.*` calls.
- `live_session action=ipc` on an Electron main process records each route (channel, direction, `send`, `sendSync`, `invoke` or its result) with its message count and value shape, never values. Routes join the static rows of `app.getAppPath()` (`search_container kind=electron`); unused channels are listed as not seen. The recorder keeps 500 routes; messages of later routes are counted as dropped.
- `program=cdp:PORT` attaches to a page of a browser started with `--remote-debugging-port=PORT`; `#TARGET` takes a page id, title or url, and service workers are skipped.
- Native actions (`live_watch`, `live_read`, `live_coverage`, `live_script`, snapshots) are refused. `--live-allow` is checked against the process id the program reports.

### JVM (JDWP)

Start: `live_session action=attach program=jdwp:PORT` (or `jdwp:HOST:PORT`, loopback only) on a JVM started with `java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:PORT`. `suspend=y` holds it until the first `continue`.

Requires JDK 11 or newer. Corvus speaks the Java Debug Wire Protocol; nothing is installed.

- `live_break at=File.java:LINE` stops the thread at that line in every class compiled from that file, including classes loaded later. `wait=true` names the held frames by class, method, file and line.
- `live_session action=status` lists classes by source file (JDK classes left out) and threads with stacks, read with the JVM suspended.
- `--live-allow` checks the process listening on the port. Native actions are refused. Closing removes the stop points and detaches.

### Time travel recordings (TTD)

Start: `live_session action=attach program=ttd:PATH` on a recording made with `TTD.exe -out DIR program.exe`. The session opens held at the first position; nothing runs.

Requires `CORVUS_TTD` set to a folder with `TTDReplay.dll` and `TTDReplayCPU.dll` from WinDbg's `amd64\ttd` folder (the Store install cannot be loaded in place).

- `live_break` sets points by name, `module!export` or address; `continue` replays to the next one. Stops name their stack and position as WinDbg's `!tt` does.
- Replay moves forward only; writes, scripts, coverage and child processes are refused. Windows x64 recordings only; rr recordings (Linux) are not read.

### Frida

Start: `--live-install-frida` (`CORVUS_LIVE_INSTALL_FRIDA=1`), `install.ps1 -WithLive`, `install.sh --with-live` or `corvus install --with-live` create the copy at once. Otherwise the first session creates a private environment from 64-bit Python 3.9+ at `<data>/frida/python-17.24.3`.

Requires Frida 17.24.3 to 17.24.x, from `pip install frida` or the pinned private copy. Outside the range, a session opens with an `error` event naming the version and range; older than 17.0 is refused with `provider_unavailable`.

- pip installs 17.24.3 from wheels only, SHA-256 pinned per platform (`--require-hashes`; about 60 MB). `CORVUS_OFFLINE=1` refuses the download.
- Interpreter search order: `CORVUS_FRIDA_PYTHON`; the private environment; the first Python (`py` launcher, then `PATH`) with a supported Frida; a new private environment (with `--live-install-frida`); the first Python with any Frida.
- `server_status` shows the interpreter, its source and its Frida version.

### Events and naming

- Calls keep their own ring (10,000), so a call flood never pushes out output, stops or exit; a page counts the calls dropped between its cursor and its end. Each event carries the server's record time (UTC).
- The program's image is indexed when the session opens: a stack reads `orders.exe!AddLine+0x1B  orders.c:9`, named from the PDB, exports and a MinGW-style COFF symbol table.
- Other modules are named from their file until `load_assembly` loads them; a return address is named by the call before it.
- Managed code named from metadata: NativeAOT (`app.exe!Ns_Type__Method`), and an AOT binary once `apply_metadata_names` named it (`GameAssembly.dll!Ns_Type__Update`).
- Source lines and `file:line` stop points come from PDB line tables (Windows) and DWARF line tables (Linux).
- The module list names the loaded image or assembly each module is (`= id`), by path or as a copy of the same bytes.

### Stops and reads

- A stop point holds only the thread that hits it; other threads run on. While a thread is held, `live_session status` lists a DLL mapped through a delay-load import before its `module` event.
- `live_read` on `cstring` or `utf16` stops at the terminator, at most `length` bytes (default and maximum 4096), and says where an unterminated string stops short.

### Lifetime and environment

- A session ends on `close`, after `CORVUS_LIVE_MAX_MINUTES` (default 30), or with the server. Each releases every held thread and ends a program the session started.
- A started program runs in its own folder; its output arrives as `output` events. Its environment is minimal (`PATH`, `TEMP`, the user folders, `DOTNET_ROOT*`) plus `environment=["NAME=value"]`; other server variables, such as tokens, are not passed on.
- It gets `DOTNET_EnableWriteXorExecute=0`. With W^X on, a stop point cannot write JIT-compiled code, so it is refused in an attached program or one started with W^X on.
- Attach refuses the server's own process and those it runs under (the MCP client, its terminal, the editor): holding them would freeze the client.

### .NET programs (Windows x64, and x86 under the 64-bit server)

- The runtime's DAC names JIT-compiled and ReadyToRun code: frames read `app.dll!Ns.Type.Method(System.String)+0x1B`.
- Stop points and watches take `Ns.Type::Method` (with a parameter list for an overload) or `app.dll!Ns.Type::Method`.
- A method not yet compiled is deferred until compiled (ReadyToRun binds at once); the compiling thread waits, so the first call is caught, `Main` included.
- A tiered recompile gets the point; an on-stack replacement compile for a running loop is left unhooked. Single-file bundles and .NET Framework native images (`name.ni.dll`) are named the same way.
- A 32-bit runtime is read by the bundled 32-bit decoder, which checks the DAC's hash first. Each 32-bit read has a 15-second budget; a failed or overrunning decoder is ended and the session says so once, and managed code is then named from JIT compiles.
- Another architecture or no DAC leaves managed code unnamed; a managed stop point is then set at JIT compile.
- `downloadDac=true` fetches a missing DAC from a symbol server into the signature-checked cache `open_minidump` uses. Off by default; refused under `CORVUS_OFFLINE=1`.
- `dump_heap` and `dump_object` take a session id and read heap statistics, matching objects and object fields without stopping the program. Objects allocated, moved or freed during the read can be missing or counted twice; a snapshot holds one state.

### Deferred points

- A stop point or watch on `module!name` whose module is not loaded yet is deferred: the loading thread waits before the module's code runs until the point is set (a `module` event says so).
- A packed DLL (its entry point writes code into an empty section) is waited on when that entry point returns; stops there are named by its exports. In an x64 or x86 program emulated on ARM64, such a point fails: the emulator runs the code unhooked.
- A deferred point the module never resolves is dropped; the next `live_break` or `live_watch` call says why, and the list shows it as failed until cleared.
- A managed name (`Ns.Type::Method`) that a compiled-metadata or NativeAOT layer names `Ns_Type__Method` gets that name as its next step.
- A stop point on a jump is set where the jump leads. Through a writable pointer (delay-load import, a table filled on first use), the point moves when the program rebinds it.

### Refused placements

Each refusal names the nearest place that works:

- an address inside an instruction;
- a stop point in the first 16 bytes of a watched or counted function, or a watch or count over one;
- two stop points whose hook jumps overlap (closer than 5 bytes on 32-bit x86, 16 elsewhere);
- a watch past a function's start, or a function too short for a hook's jump.

### Exit and crashes

- The `exit` event carries the exit code (`exit code 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)`; on Linux, the status passed to `_exit`).
- On Windows, a program still in a module's shutdown 10 seconds after `ExitProcess` is ended with its exit code, and an `error` event says so; the same holds for 20 seconds after the session closes.
- An access violation, illegal instruction, stack overflow or arithmetic fault waits for its `exception` event, so the crash keeps its address. Values that cannot be return addresses (small values, header bytes, non-executable pages) are left out of frames.

### Child processes

A launcher, installer or host that starts the real program is followed with `childNames` on spawn or attach (as Frida's child gating, WinDbg's `.childdbg 1` and GDB's `follow-fork-mode child`).

- Each child is held before its first instruction and reported as a `child` event (pid, image path); `action=children` lists them with command lines and states.
- `childNames=["app.exe"]` (or `app`) holds only those images; `["*"]` holds every child. `action=attach_child program=<pid>` opens a held child, still held; `action=release_child` lets a child run unobserved.
- A child never stays suspended: when the session closes (request, deadline or server exit), every held child runs on. A child session closed before its first continue returns to its parent's hold.
- Linux: a child is reported at its `exec` (from a fork or `posix_spawn`; a fork that never execs is not held); `attach_child` holds it once its own code and libraries are loaded. A session following children does not report threads that end.
- Windows: a process naming the program as parent (as WebView2 starts a Tauri program's browser process) passes no hold; `action=children` lists it, and `attach program=<pid>` opens it.
- Windows sandboxed children (Chromium and Electron GPU, utility and renderer processes) allow what their token allows. A child whose sandbox refuses the agent fails with `access_denied`, naming the sandbox (restricted token, AppContainer, low or untrusted integrity); start it with `--no-sandbox`, or `--disable-gpu-sandbox` for the GPU process.
- Under a network logon (such as ssh), a restricted-token child is refused the same way (cause unknown); under an interactive logon it attaches.

### Watches

Watches record each call's arguments and return value without stopping the program.

- Decoding, in order: the known-API table (names, strings, flags and enums, such as `dwDesiredAccess=GENERIC_READ`); the PDB or DWARF prototype; DWARF parameter names; raw `arguments` values. Strings are read up to 256 characters.
- On Linux x64, a prototype with floating-point or structure arguments falls back to names.
- Calls are sent in batches of 512 or every 100 ms, and when the program starts to exit. Calls over `rateLimit` (default 10,000 a second, range 1-100,000) are counted, not recorded.
- Each call is a `call` event named by its caller: `orders.exe!main+0xDC: AddLine(o=0xE1BAFFE50, qty=3) -> 3`.

### Coverage

`live_coverage` collects function coverage from stop events: a point at each function start of the program's image, counted without holding the thread.

- A larger match is refused with its count and narrower matches (name prefixes, namespaces, `sub_` address prefixes).
- At most 5,000 functions per run. A point is cleared after `hitLimit` stops (default 100); a count at the limit reads `100+`.
- A module not loaded yet is counted from its first call once `load_assembly` loads it; the run waits for that load.
- Left out: functions reached from TLS callbacks or a DLL's entry point (they also run at process exit), points the backend cannot hook (reported with their instructions), and functions whose first block is too short for a hook's jump ("too short to count with stop-based coverage"). A leading `endbr64` stays in place.
- Function entries only; blocks are not counted. A run whose program ends first reads `ended` and keeps its counts; `action=stop` leaves it so.
- Managed assemblies (`match=app.dll!part`, Windows): covered from the runtime's record of methods with prepared code, read each second and at exit. A report lists them by metadata token, without counts, as text only; a method not yet read as run is marked `?`.
- A runtime the server cannot read (no DAC, or a 32-bit program without the 32-bit decoder) is covered from JIT compiles instead: first compiles after the run starts, without methods compiled earlier or precompiled (ReadyToRun, NGEN) code.

### Timeline (Windows)

`live_timeline` collects a timestamped trace from an ETW session with the kernel file, registry, network and process providers, keeping the program's own events.

- Each entry has a time, a category (`file`, `registry`, `network`, `process`) and the name the OS reports: a drive-letter path, an `HKLM\...` or `HKCU\...` key, a TCP connect or accept, each UDP endpoint once, or a child program's image.
- The agent's own files are left out. The latest 100,000 entries are kept; the timeline completes on `stop` or program exit, once the OS delivers its buffers.
- `action=report` lists each name once with its count and first time; `action=diff` compares two traces as sets of (category, name), ignoring times and counts.
- Needs administrator rights or Performance Log Users membership (`access_denied` otherwise).

### Console (Windows)

`live_console` runs a program under the pseudoconsole (ConPTY, 120x30) and drives it from a script. Needs `--allow-live-spawn`.

- Steps, one per line or array element: `send <text>` (`\r` is Enter; `\n`, `\t`, `\e`, `\xHH`), `wait <text>` (`timeoutSeconds` each, default 10, range 1-300), `resize <columns> <rows>`, `delay <ms>`.
- The first step that cannot complete stops the script with its reason and the console's last lines. The transcript is plain text with escape sequences removed; it pages with a cursor. A run keeps the latest 20,000 lines.
- The program runs on after the script until it exits or `action=stop`; every run ends with the server. The script is kept for repeat runs.

### Snapshot

`live_session action=snapshot` writes the process as a standard dump file with the OS's own writer and opens it with the dump tools; the program keeps running.

- Writers: MiniDumpWriteDump (Windows), GDB's `gcore` (Linux), lldb's `process save-core` (macOS, modified memory as a Mach-O core). Output goes to `outputPath`, else a new file under the temp folder's `corvus-snapshots`.
- Saved while a thread is held, the dump or core records that stop (a breakpoint exception on Windows; `SIGTRAP`, `TRAP_BRKPT` on Linux), so `dump_stack` walks from it.
- On Linux, GDB stops every thread. A thread waiting in `vfork` for a child that has not run its program cannot stop: the snapshot is refused with `timeout` after 10 seconds. A `gcore` that is ended (that refusal, cancellation, or 5 minutes) leaves the program running as it was.

### Script

`live_script action=load path=trace.js` loads your script into the program (Frida's JavaScript API). Needs `--live-scripting`.

- What it sends arrives as `script` events; a script that does not compile is refused with the compiler's message. It runs with the program's rights and can change the program.
- On Windows, Frida 17 lists modules in no fixed order and `Process.mainModule` can name a system DLL; find the program's module by name.

## Limits

- `inspect_process` is Windows only. A 32-bit server cannot read a 64-bit process (`unsupported`, reason `bitness_mismatch`); the 64-bit server reads 64-bit and WoW64 processes.
- ARM64 process registers are read by an ARM64 server only; stacks are walked for x64 and x86. `inspect_process` identifies managed (JIT) frames without decoding them; sessions name them.
- Other users' processes, elevated processes (from a non-elevated server) and protected processes fail with `access_denied`; an exited process fails with `not_found` (reason `process_exited`).
- Sessions run on Windows, Linux and macOS (`live_timeline` and `live_console`: Windows only). Minidumps and core files open with `open_minidump` on any OS.
- macOS sessions observe what a debugger may: programs built on the machine or signed with `get-task-allow`. Requires Developer Mode on and the user in `_developer`.
- macOS `snapshot` needs lldb (Xcode command line tools); `dump_stack` takes its thread by `#index` (`open_minidump view=threads` lists them). `childNames` fails with `unsupported`: Frida's child gating misses a fork intermittently.
- Windows ARM64 observes ARM64 programs natively. x64 and x86 programs run under emulation: `module!export` resolves to the export the program calls, and `snapshot` is refused (`unsupported`), since the dump would hold the emulator's ARM64 threads.
- Linux without CAP_SYS_PTRACE is bound by Yama's `ptrace_scope`: at 1, sessions on programs the server starts work, while attach and `snapshot` fail with `access_denied` naming the setting; at 2, every session and snapshot fails so.
- musl libc (Alpine): attach works; starting a program fails with Frida's `ProcessNotRespondingError` and leaves nothing running.
- A statically linked Linux program (most Go programs, busybox) is refused with `unsupported` before anything starts, because Frida loads its agent through the dynamic loader. Read the file statically, or open a `gcore` core with `open_minidump`.
- Linux sessions report a thread's start from `pthread_create`; a bare `clone` thread has only its `ended` event. A stop's stack is unwound from the 32 KiB above its stack pointer; deeper frames come from the stack scan.
