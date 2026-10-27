# Live process inspection and sessions

Two ways to look at a running program:

| | `inspect_process` | Session tools (`live_*`) |
|---|---|---|
| What it does | one read-only look: modules, regions, threads, stacks, UI elements | start or attach, stop points, call records, coverage, traces |
| Writes the program's memory | no | yes: stop points, watches and coverage patch code ([Sessions](#sessions)) |
| Opt-in | none; registered by default | registered by default, refused until an opt-in switch is on |
| Platforms | Windows (elsewhere `provider_unavailable`) | Windows, Linux, macOS; `live_timeline` and `live_console` Windows only |

- `inspect_process` takes a pid, a name or a session id (`live-1`).
- It names addresses as `dump_stack` names a crash dump's: user renames, PDB, compiled-metadata and discovered names
  (in that order), then assemblies made for GameAssembly.dll, a matching local PDB, then exports.
- The stack walker, module lookup (the file on disk, else the image rebuilt from memory) and namer are the dump code.

## The read-only guarantee

Applies to `inspect_process`. Handles opened:

| Object | API | Access rights | Lifetime |
|---|---|---|---|
| The process | `OpenProcess` | `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ` (0x410) | the call |
| Each listed thread | `OpenThread` | `THREAD_GET_CONTEXT \| THREAD_QUERY_INFORMATION` (0x48) | one thread at a time; closed after it is read |
| The thread list | `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` | none on the target (system-wide) | the call |
| Selection by name or id | the system process list | none on the target | the call |

What is read:

- Modules: `EnumProcessModulesEx(LIST_MODULES_ALL)`, `GetModuleFileNameEx`, `GetModuleInformation`; headers and
  CodeView records with `ReadProcessMemory`.
- Regions: `VirtualQueryEx`.
- Threads: `NtQueryInformationThread` (TEB, priorities, start address, suspend count), `GetThreadDescription`, the stack
  range from the TEB, registers with `GetThreadContext` (`Wow64GetThreadContext` for a 32-bit process).
- Stacks: `ReadProcessMemory` of stack and code, unwound by Corvus's walker (x64 unwind data; x86 PDB frame data, call
  targets and EBP chain).
- Process identity: `QueryFullProcessImageName`, `GetProcessTimes`, `IsWow64Process2`, `GetExitCodeProcess`.

Never done, and none of these is even bound:

- memory write (`WriteProcessMemory`), protection change (`VirtualProtectEx`), allocation (`VirtualAllocEx`);
- stop points, debugger connection (`DebugActiveProcess`, DbgEng);
- thread suspension or resumption (`SuspendThread`, `NtSuspendProcess`), context write (`SetThreadContext`);
- remote thread or APC (`CreateRemoteThread`, `QueueUserAPC`), handle duplication;
- privilege change (SeDebugPrivilege is not enabled), dump writing.

A test checks the bound API declarations against this list and both access masks.

Nothing to detach:

- Every handle closes before the call returns, also on error, cancellation and timeout.
- The report states `handlesOpened`, `handlesClosed` (equal) and `detached`.
- A timeout cancels at the next check (each module, region batch, thread and frame).

Remaining side effects:

- `GetThreadContext` on a running thread: the kernel captures registers with a kernel-mode APC. No user-mode code runs
  and the suspend count is untouched; a thread running user code may show a stale frame. Waiting threads are exact.
- `ReadProcessMemory` may page in paged-out memory, as any reader does.
- Verified on 64-bit and WoW64 children: writable image regions (by SHA-256) and suspend counts are unchanged, and the
  child keeps running.

## Windows and their handlers

`inspect_process view=windows` lists the UI Automation control view of the program's visible top-level windows, depth
first: control type, name, automation id, class name, framework, bounds and window handle.

- An element with a window handle names its class window procedure (`GetClassLongPtr(GCLP_WNDPROC)`).
- A child control also names its control id and the parent class procedure that receives its notifications
  (`WM_COMMAND`, `WM_NOTIFY`).
- `imagePath` saves a PNG of the first window as drawn (`PrintWindow`, `PW_RENDERFULLCONTENT`).
- The program's UI threads answer each query (`WM_GETOBJECT`) and draw the image (`WM_PRINT`); no other handle or right is
  added. Queries time out after 2 s to connect and 5 s per call.
- Another process cannot read a window's own procedure (`GWLP_WNDPROC`) or a dialog procedure (`DWLP_DLGPROC`):
  Windows returns 0, so a subclassed window's or a dialog's own handler is reported as unknown.
- At most 2,000 elements and 16 levels; the result names the cut.

## Why not DbgEng

DbgEng (`IDebugClient::AttachProcess` with `DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND`) would also
leave the process running, but:

- dbgeng.dll chooses the handle's access rights, so a read-only handle can be neither guaranteed nor tested;
- its symbol engine names frames from PDBs and symbol servers, not Corvus's name layers;
- the System32 dbgeng.dll is an old, partly documented COM surface; plain Win32 calls need no extra component.

## Sessions

Session tools observe a program while it runs: `live_session`, `live_break`, `live_watch`, `live_read`, `live_events`,
`live_coverage`, `live_timeline`, `live_console`, `live_script`.

**Opt-in.** Registered by default, refused until the server starts with a switch below. Each turns the session tools on
and allows only its own action:

| Switch | Variable | Also allows |
|---|---|---|
| `--allow-live` | `CORVUS_ALLOW_LIVE=1` | nothing more: no attach, no start |
| `--allow-live-attach` | `CORVUS_ALLOW_LIVE_ATTACH=1` | attach to a running program |
| `--allow-live-spawn` | `CORVUS_ALLOW_LIVE_SPAWN=1` | start a program (`live_session action=spawn`, `live_console action=start`) |
| `--live-scripting` | `CORVUS_LIVE_SCRIPTING=1` | `live_script` |

- See [configuration.md](configuration.md#security-switches). These are server start-up switches; the model cannot turn
  them on.
- `--live-allow <program or folder>` (repeatable) limits attach and spawn to the listed programs.
- The check uses the final path (links resolved in every folder) and, for a running program, the image path the OS
  reports. Anything else is refused before a session opens; a started program is the file that was checked.
- List only folders you alone can write to: a file copied or hard-linked into one counts as inside it.
  `server_status` shows the list.

**What a session writes.**

- Only `live_read` (and `inspect_process`) are read-only.
- A session loads Frida's agent into the program; on Windows it allocates a `PAGE_EXECUTE_READWRITE` page and writes a
  small stub into it.
- Stop points, watches and coverage are Frida Interceptor hooks that patch the program's code in memory.
- `live_script` runs your code inside the program with its rights.
- Run untrusted programs only in a disposable virtual machine: a session observes a program, it does not contain it.

### V8 inspector

`live_session action=attach program=inspector:PORT` opens a session on a Node or Electron program running under its
inspector (`--inspect=PORT`, `--inspect-brk=PORT`; Electron pages with `--remote-debugging-port=PORT`).

- `inspector:HOST:PORT`, `inspector:ws://HOST:PORT/ID` and a `#TARGET` suffix (id, type or title) name others.
- Only loopback hosts are accepted: an inspector runs any code it is sent.
- Corvus serves it over the Chrome DevTools Protocol; nothing is loaded except the IPC recorder. Closing removes stop
  points and lets the program run on.
- `live_session action=status` lists scripts with their source maps and the sources they hold.
- `live_break at=FILE:LINE` takes an original source a map names (`src/app.ts:12`): the point goes on its first
  generated position on that line, or the next line with code.
- A script url ending in FILE takes a generated line; a FILE not loaded yet is set by url for when it is parsed.
- `live_break wait=true` returns the paused frames with the original position each map gives. A program started with
  `--inspect-brk` opens suspended: set stop points, then `continue`.
- `live_events kind=output` shows `console.*` calls.
- `live_session action=ipc` on an Electron main process records IPC from the first call on. Each route (channel,
  direction, `send`, `sendSync`, `invoke` or its result) shows its message count and value shape, never values.
- Routes join the static IPC rows of the app at `app.getAppPath()` (`search_container kind=electron`). Channels the code
  names but no message used are listed as not seen.
- The recorder keeps 500 routes; messages of later routes are counted as dropped.
- Native actions (`live_watch`, `live_read`, `live_coverage`, `live_script`, snapshots) are refused.
- `--live-allow` is checked against the process id the program reports.

### JVM (JDWP)

`live_session action=attach program=jdwp:PORT` (or `jdwp:HOST:PORT`, loopback only) opens a session on a JVM started
with `java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:PORT` (`suspend=y` holds it until
the first `continue`). Corvus speaks the Java Debug Wire Protocol; nothing is installed.

- `live_session action=status` lists classes by source file (JDK classes left out) and every thread with its state and
  stack, as jstack prints them; the JVM is suspended for the read only.
- `live_break at=File.java:LINE` stops the thread reaching that line, in every class compiled from that file, also
  those loaded later.
- `live_break wait=true` names the held thread's frames by class, method, file and line; `continue` resumes it.
- Closing removes the stop points and detaches; the program runs on.
- `--live-allow` checks the process listening on the port before the session connects. Native actions are refused.
- Tested with JDK 11.0.24, 22.0.1 and 24.0.1 (HotSpot, Windows x64).

### Time travel recordings (TTD)

`live_session action=attach program=ttd:PATH` opens a recording made with TTD.exe (`TTD.exe -out DIR program.exe`). The
session replays it with the TTD Replay API; nothing runs.

- Set `CORVUS_TTD` to a folder with `TTDReplay.dll` and `TTDReplayCPU.dll` from WinDbg's `amd64\ttd` folder (the Store
  install cannot be loaded in place).
- The session opens held at the first position, with every module the recording loaded.
- `live_break` sets stop points by name, `module!export` or address; `continue` replays to the next one.
- A stop names its stack (x64 unwind data from each module's file, else the recording) and its position, as WinDbg's
  `!tt` takes it.
- `live_watch` records each call: arguments at entry, return value and caller.
- `live_read` reads registers and memory at the current position.
- The end of the recording ends the session's program.
- Replay moves forward only. Writes, scripts, coverage and child processes are refused. Windows x64 recordings only.
- Tested with TTD 1.11.617 (WinDbg 1.2610.1001.0): calls and stacks equal WinDbg's `TTD.Calls` and `k`.
- rr recordings (Linux) are not read.

### Frida

A session runs a worker on Frida's Python bindings: install them (`pip install frida`), or let the server keep a pinned
private copy.

- Turn on with `--live-install-frida` (`CORVUS_LIVE_INSTALL_FRIDA=1`), or `install.ps1 -WithLive`,
  `install.sh --with-live`, `corvus install --with-live` (these create it right away).
- When no tested Frida is found, the first session creates a venv from a 64-bit Python 3.9+ at
  `<data>/frida/python-17.24.3`.
- pip installs Frida 17.24.3 from wheels only, SHA-256 pinned per platform (`--require-hashes`; about 60 MB).
- `CORVUS_OFFLINE=1` refuses the download.
- Interpreter search order: `CORVUS_FRIDA_PYTHON`; the private environment, once created; the first Python found (`py`
  launcher, then `PATH`) with a tested Frida; a new private environment (with `--live-install-frida`); the first
  Python with any Frida.
- `server_status` shows the interpreter, its source and its Frida version.
- Tested range: Frida 17.24.3 to 17.x. Outside it, a session opens with an `error` event naming the version and range.
  Older than 17.0 is refused with `provider_unavailable`.

| Step | Call |
|---|---|
| Start a program suspended, or attach | `live_session action=spawn program=app.exe` / `action=attach program=<pid or name>` |
| Follow child processes | `live_session action=spawn program=launcher.exe childNames=["app.exe"]` (`["*"]` for all) |
| Open a held child | `live_session action=children`, then `action=attach_child program=<child pid>` |
| Set stop points before it runs | `live_break action=set at=Orders::AddLine` |
| Run to the next stop | `live_break action=continue wait=true` |
| Read the held thread | `live_read registers=rcx,rdx memory=rcx type=int32[2]` |
| Scan memory with YARA rules | `live_read rules=rules.yar` |
| Record every call of a function | `live_watch action=set at=AddLine` (or `kernelbase!CreateFileA`, an address) |
| Collect code coverage | `live_coverage action=start` before `continue`, then `action=report` |
| Compare two coverage runs | `live_coverage action=diff run=cov-1 other=cov-2` |
| Trace files, registry keys and endpoints | `live_timeline action=start` before `continue`, then `action=list run=tl-1` or `action=report` |
| Compare two traces | `live_timeline action=diff a=tl-1 b=tl-2` |
| Page what happened | `live_events cursor=<from the last page> kind=stop`; one watch: `live_events from=w1` |
| Run a console program from a script | `live_console action=start program=app.exe script=["wait name?", "send Ada\r", "wait echo: Ada"]` |
| Read its transcript | `live_console action=transcript run=con-1` (`cursor=`) |
| Load your own script | `live_script action=load path=trace.js` (needs `--live-scripting`) |
| Save the process as a dump | `live_session action=snapshot` (then `dump_stack`, `read_dump_memory`) |
| End | `live_session action=close` |

- `at=` also takes `module!export`, `AddLine+0x1B`, `orders.c:42`, or an image or live address.
- `rules=` takes rule text, a folder or `pack:<name>`; it scans heap, stacks and data sections while the program runs
  (Windows and Linux).
- `live_coverage format=dot` draws the call graph.

**Events.**

- Calls keep their own ring (10,000), so a call flood never pushes out output, stops or exit.
- A page counts the calls dropped between its cursor and its end.
- Each event carries the time the server recorded it (UTC).

**Naming.**

- The program's own image is indexed when the session opens: a stack reads `orders.exe!AddLine+0x1B  orders.c:9`
  (names from the PDB, the exports and a MinGW-style COFF symbol table).
- Other modules join once loaded with `load_assembly`. Until then they are named from their file as `dump_stack` names
  a core's frames; a return address by the call before it.
- Ahead-of-time compiled managed code reads by method, and stop points take the same names: NativeAOT from its metadata
  (`app.exe!Ns_Type__Method`), an AOT binary once `apply_metadata_names` named it
  (`GameAssembly.dll!Ns_Type__Update`).
- Source lines and `file:line` stop points come from PDB line tables (Windows) and DWARF line tables (Linux).
- On Linux a stop's frames are unwound with each module's `.eh_frame` CFI.
- The module list names the loaded image or assembly each module is (`= id`), by path or as a copy of the same bytes.

**Stops and reads.**

- A stop point holds only the thread that hits it; other threads run on.
- While a thread is held, `live_session status` also lists a DLL mapped through a delay-load import before its
  `module` event, and names the stop's frames in it.
- `live_read` never writes. A `cstring` or `utf16` read stops at the terminator, at most `length` bytes (default and
  maximum 4096), and says where an unterminated string stops short.
- A `pointer` is as wide as the program's pointers.

**Lifetime.**

- A session ends on `close`, after `CORVUS_LIVE_MAX_MINUTES` (default 30), or with the server. Each releases every held
  thread and ends a program the session started.
- A started program runs in its own folder; its output arrives as `output` events.
- Its environment is minimal (`PATH`, `TEMP`, the user folders) plus `DOTNET_ROOT*`; `environment=["NAME=value"]` on
  spawn adds more. Other server variables, such as tokens, are not passed on.
- It also gets `DOTNET_EnableWriteXorExecute=0`: with W^X on, a stop point cannot write JIT-compiled code, so such a
  point is refused in an attached program or one started with W^X on.
- Attach refuses the server's own process and those it runs under (the MCP client, its terminal, the editor), by id or
  name: holding them would freeze the client.

**.NET programs (Windows x64, and x86 under the 64-bit server).**

- The runtime's DAC names JIT-compiled and ReadyToRun code: frames read `app.dll!Ns.Type.Method(System.String)+0x1B`,
  walked by the runtime from the stop's registers.
- Stop points and watches take `Ns.Type::Method`, with a parameter list for an overload, or `app.dll!Ns.Type::Method`.
- A method without code yet is deferred until compiled (ReadyToRun code binds at once): the compiling thread waits
  until the point is set, so the first call is caught, `Main` included.
- A tiered recompile gets the point too; an on-stack replacement compile for a running loop is left unhooked.
- Single-file bundled assemblies and .NET Framework native images (`name.ni.dll`) are named the same way.
- A 32-bit runtime is read by the bundled 32-bit decoder (`clr32/`), which checks the DAC's hash before loading it.
- Each 32-bit read has a 15-second budget. A decoder that fails or overruns is ended and the session says so once;
  managed code is then named from JIT compiles, and coverage counts first compiles.
- Another architecture, or no DAC, leaves managed code unnamed; a managed stop point is then set at JIT compile.
- `downloadDac=true` fetches a missing DAC from a symbol server into the signature-checked cache `open_minidump` uses.
  Off by default; refused under `CORVUS_OFFLINE=1`.
- `dump_heap` and `dump_object` take a session id: heap statistics by type, matching objects, one object's fields,
  read without stopping the program.
- Objects allocated, moved or freed during the read can be missing or counted twice, and an object listed before a GC may be gone; a snapshot holds one state.

**Deferred points.**

- A stop point or watch on `module!name` whose module is not loaded yet is deferred: the loading thread waits before
  any of the module's code runs until the point is set (a `module` event says so). The first call is caught.
- A packed DLL (its entry point writes code into an empty section) is waited on when that entry point returns, so
  the point is not overwritten; stops there are named by its exports.
- In an x64 or x86 program emulated on ARM64 such a point fails with that reason: the emulator runs the code unhooked.
- A deferred point the module does not resolve is dropped: the next `live_break` or `live_watch` call says why, and the
  list shows it as failed until cleared.
- A managed name (`Ns.Type::Method`) that a compiled-metadata or NativeAOT layer names `Ns_Type__Method` gets that name
  as its next step.
- A stop point on a jump is set where the jump leads. Through a pointer in a writable section (delay-load import, a
  table filled on first use), the point moves when the program rebinds it; a `module` event says so.

**Refused placements**, each with the nearest place that works:

- an address inside an instruction;
- a stop point in the first 16 bytes of a watched or counted function, or a watch or count over one;
- two stop points whose hook jumps overlap (closer than 5 bytes on 32-bit x86, 16 elsewhere);
- a watch past a function's start; a function too short for a hook's jump.

**Exit and crashes.**

- The `exit` event carries the exit code (`exit code 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)`; on Linux the status
  passed to `_exit`).
- On Windows, a program still in a module's shutdown 10 seconds after `ExitProcess` is ended with its chosen exit code,
  and an `error` event says so. This holds for 20 seconds after the session closes too,
  since a close meeting the start of an exit can leave the exit unable to finish.
- An access violation, illegal instruction, stack overflow or arithmetic fault waits for its `exception` event, so a
  crash keeps its address. Without one, an event is recorded from the exit code, without an address.
- Values that cannot be return addresses (small values, header bytes, non-executable pages) are left out of frames.

**Child processes.** A launcher, installer or host that starts the real program is followed with `childNames` on spawn
or attach (as Frida's child gating, WinDbg's `.childdbg 1` and GDB's `follow-fork-mode child`).

- Each child is held before its first instruction and reported as a `child` event (pid, image path);
  `action=children` lists them with command lines and states.
- `childNames=["app.exe"]` (or `app`) holds only those images; others run at once. `["*"]` holds every child.
- `action=attach_child program=<pid>` opens a session on a held child, still held, so points are in place before it
  runs. Its first `live_break action=continue` starts it; it follows its own children likewise.
- `action=release_child` lets a child run unobserved.
- A child never stays suspended: when the session closes (request, deadline or server exit), every held child runs on,
  including an attached child whose session has not continued. A child session closed before its first continue
  returns to its parent's hold.
- Linux: a child is reported at its `exec`, from a fork or `posix_spawn` (a fork that never execs is not held). A copy
  started through `/proc/self/exe` is named by its own image.
- Linux: `attach_child` runs the child to its own code, libraries loaded, and holds it there. A session following
  children does not report threads that end.
- Windows: a process started by another process naming the program as parent (as WebView2 starts a Tauri program's
  browser process) passes no hold. `action=children` lists it; `live_session action=attach program=<pid>` opens it.
- Windows sandboxed children (Chromium and Electron GPU, utility and renderer processes) allow what their token allows.
  The agent loads from a folder restricted tokens and AppContainers can read, so a GPU process attaches.
- A child whose sandbox still refuses the agent fails with `access_denied`, naming the sandbox (restricted token,
  AppContainer, low or untrusted integrity). Start the program with its sandbox off (`--no-sandbox`, or
  `--disable-gpu-sandbox` for the GPU process).
- Under a network logon (such as ssh), a restricted-token child does not load the agent and is refused the same way
  (cause unknown); under an interactive logon it attaches.

**Watches** record each call's arguments and return value without stopping the program.

- Decoding, in order: the known-API table (parameter names, strings, flags and enums by name:
  `dwDesiredAccess=GENERIC_READ`); the PDB or DWARF prototype; DWARF parameter names; else raw `arguments` values.
- On Linux x64 a prototype with floating-point or structure arguments falls back to names.
- Strings are read while the call runs, up to 256 characters.
- Calls are sent in batches (512 calls or every 100 ms, and when the program starts to exit).
- Calls over `rateLimit` (default 10,000 a second, 1-100,000) are counted, not recorded.
- Each call is a `call` event named by its caller: `orders.exe!main+0xDC: AddLine(o=0xE1BAFFE50, qty=3) -> 3`.

**`live_coverage`** collects code coverage from stop events: a point at each function start of the program's image,
each stop counted without holding the thread.

- `match=` narrows by name; `module!part` counts another module.
- A point is cleared after `hitLimit` stops (default 100), so a count at the limit reads "100+" and the program runs at
  its own speed.
- A module not loaded yet is read from its file and counted from its first call once loaded with `load_assembly`; the
  run waits for its load, as a deferred stop point does.
- At most 5,000 functions per run; a larger match is refused with the count and narrower matches (name prefixes,
  namespaces, `sub_` address prefixes), each with its count.
- Left out: functions reached from TLS callbacks or a DLL's entry point (they also run at process exit), and points the backend cannot hook (reported
  with their instructions).
- A function whose first block is too short for a hook's jump is refused as "too short to count with stop-based
  coverage". A leading `endbr64` stays in place, so its 4 bytes do not count.
- `action=report` lists functions that ran (`show=missed` or `all`), busiest first; `format=dot` draws them on the
  static call graph in Graphviz DOT, never-run functions dashed.
- `action=diff` compares two runs of the same build: functions run only in each, in both, and in neither.
- Function entries only; blocks are not counted. A run whose program ends first reads `ended` and keeps its counts;
  `action=stop` leaves it so.
- Managed assemblies (`match=app.dll!part`), Windows: covered from the runtime's record of methods with prepared code
  (JIT-compiled, or ReadyToRun bound, at first call). The program's own assembly or one next to it can be named before
  it loads.
- The record is read each second and at exit (the exiting thread is held at `RtlExitUserProcess` meanwhile), so a report lists methods that ran by metadata token, without counts, as
  text only. Until a read succeeds, a method not seen to run is unknown, marked `?`.
- A runtime the server cannot read (no DAC, or a 32-bit program without the 32-bit decoder) is covered from JIT
  compiles instead: first compiles after the run starts, without
  methods compiled earlier or precompiled (ReadyToRun, NGEN) code.

**`live_timeline`** (Windows) collects a timestamped trace from an ETW session with the kernel file, registry, network
and process providers (as PerfView and Process Monitor collect them), keeping the program's events.

- Each entry: time, category (`file`, `registry`, `network`, `process`) and the name the OS reports.
- Names: a file path with drive letter, a registry key or value as `HKLM\...` or `HKCU\...`, a TCP connect or accept
  and each UDP endpoint once, a child program's image. The agent's own files are left out.
- `action=list` pages entries with a cursor (`category=`, `match=`); `action=report` lists each name once with count and
  first time.
- A timeline keeps the latest 100,000 entries and completes on `stop` or program exit, once the OS has delivered its
  buffers.
- Needs administrator rights or Performance Log Users membership (`access_denied` otherwise).
- `action=diff a=tl-1 b=tl-2` compares two traces as sets of (category, name), ignoring times and counts; paged with
  `offset` and `limit`.

**`live_console`** (Windows) runs a program under the pseudoconsole (ConPTY, 120x30) and drives it from a script, as
expect and pexpect do.

- Steps, one per line or array element: `send <text>` (`\r` is Enter; `\n`, `\t`, `\e`, `\xHH`), `wait <text>` (until
  output since the last match contains it; `timeoutSeconds` each, default 10, range 1-300), `resize <columns> <rows>`,
  `delay <ms>`.
- `action=start` runs the steps in order and reports each; the first that cannot complete stops the script with its
  reason and the console's last lines.
- The transcript is plain text, escape sequences removed; `action=transcript` pages it with a cursor. A line still
  being written comes again on the next poll. A run keeps the latest 20,000 lines.
- The program runs on after the script until it exits or `action=stop`; every run ends with the server.
- Needs `--allow-live-spawn`.
- Session results are kept as evidence records; `live_console` keeps the script, so a run can be repeated.

**`action=snapshot`** writes the process as a standard dump file with the OS's own writer and opens it with the dump
tools; the program keeps running.

- Writers: MiniDumpWriteDump (Windows), GDB's `gcore` (Linux), lldb's `process save-core` (macOS, modified memory as a
  Mach-O core).
- Output goes to `outputPath`, else a new file under the temp folder's `corvus-snapshots`.
- Saved while a thread is held, a Windows dump or Linux core records that stop (Windows as a breakpoint exception;
  Linux as `SIGTRAP`, `TRAP_BRKPT` at the stop's address), so `dump_stack` walks from the stop.
- On Linux GDB stops every thread. A thread waiting in `vfork` for a child that has not run its program cannot stop:
  the snapshot is refused with `timeout` after 10 seconds.
- A `gcore` that is ended (that refusal, cancellation, or 5 minutes) leaves the program running as it was.

**`live_script`** loads your script into the program (Frida's JavaScript API).

- What it sends arrives as `script` events; a script that does not compile is refused with the compiler's message.
- It runs with the program's rights and can change it, hence `--live-scripting`.
- On Windows, Frida 17 lists modules in no fixed order and `Process.mainModule` can name a system DLL; find the
  program's module by name.

**Measured** on a small MSVC-built program (Windows 11, x64):

- session open with modules matched: 1.1-1.5 s; held stop to named stack: 1 ms;
- stop point by name: 0.6 s on first call (the image's index), then under 10 ms;
- a watched function called 20,000 times: every call recorded at 107,000-136,000 calls a second (target 5,000);
- coverage of the same program (3,020 functions): points placed in 1.4-1.7 s, 165 functions ran.

## Limits

- `inspect_process` is Windows only. A 32-bit server cannot read a 64-bit process (`unsupported`, reason
  `bitness_mismatch`); the 64-bit server reads 64-bit and WoW64 processes.
- ARM64 process registers are read by an ARM64 server only; stacks are walked for x64 and x86.
- Processes of another user, elevated processes (from a non-elevated server) and protected processes fail with
  `access_denied`; an exited process fails with `not_found` (reason `process_exited`).
- `inspect_process` identifies managed (JIT) frames without decoding them; sessions name them.
- Sessions run on Windows, Linux and macOS (`live_timeline`, `live_console`: Windows only). Minidumps and core files open
  with `open_minidump` on any OS.
- macOS (tested on Apple silicon, macos-latest, Developer Mode on, user in `_developer`): sessions observe what a
  debugger may, programs built on the machine or signed with `get-task-allow`.
- macOS `snapshot` needs lldb (Xcode command line tools). The core's thread ids are lldb's, so `dump_stack` takes a
  thread by `#index` (`open_minidump view=threads` lists them).
- macOS `childNames` fails with `unsupported`: Frida's child gating misses a fork there intermittently.
- Windows ARM64: ARM64 programs are observed natively. x64 and x86 programs run under emulation: `module!export`
  resolves to the export the program calls, and `snapshot` is refused (`unsupported`), since the
  dump would hold the emulator's ARM64 threads.
- Linux without CAP_SYS_PTRACE is bound by Yama's `ptrace_scope`: at 1, sessions on programs the server starts work,
  attach and `snapshot` fail with `access_denied` naming the setting; at 2 every session and snapshot fails so.
- musl libc (Alpine): attach works; starting a program fails with Frida's `ProcessNotRespondingError` and leaves
  nothing running.
- A statically linked Linux program (most Go programs, busybox) is refused with `unsupported` before anything starts:
  Frida loads its agent through the dynamic loader. Read the file statically, or open a `gcore` core with
  `open_minidump`.
- Linux sessions report a thread's start from `pthread_create`; a bare `clone` thread has only its `ended` event.
- A Linux stop's stack is unwound from the 32 KiB above its stack pointer; deeper frames come from the stack scan.
