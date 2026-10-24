# Live process inspection and sessions

Two ways to look at a running program:

| | `inspect_process` | Session tools (`live_*`) |
|---|---|---|
| What it does | One read-only look: modules, memory regions, threads, call stacks | Start or attach to a program, set stop points, record calls, collect coverage and traces |
| Writes the program's memory | No | Yes: stop points, watches and coverage patch code in memory (see [Sessions](#sessions)) |
| Opt-in | None; registered by default | Registered by default, refused until the server starts with an opt-in switch |
| Platforms | Windows (elsewhere `provider_unavailable`) | Windows, Linux, macOS; `live_timeline` and `live_console` Windows only |

`inspect_process` (src/Corvus/Tools/Dumps/LiveProcessTools.cs, Services/Dumps/LiveProcessService.cs,
Native/Live/LiveProcess.cs, Native/Live/LiveNative.cs) names every address as `dump_stack` names a crash dump's: the
loaded native image's code index (user renames, PDB, Il2Cpp and discovered names, in that priority), Il2Cpp dummy DLLs
for GameAssembly.dll, a matching local PDB, then exports. It takes a pid, a name or a session id (`live-1`). Process and
minidump share `IProcessMemory` (Native/Dump/ProcessMemory.cs), so the stack walker, the module image lookup (the file
on disk, else the image rebuilt from process memory) and the namer are the dump code, unchanged.

## The read-only guarantee

Applies to `inspect_process`. Handles opened:

| Object | API | Access rights | Lifetime |
|---|---|---|---|
| The process | `OpenProcess` | `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ` (0x410) | the call; closed before it returns |
| Each listed thread | `OpenThread` | `THREAD_GET_CONTEXT \| THREAD_QUERY_INFORMATION` (0x48) | one thread at a time; closed right after it is read |
| The thread list | `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` | none on the target (a system-wide snapshot) | the call |
| Selection by name or id | the system process list (`Process.GetProcesses` / `GetProcessById`: names, ids, sessions) | none on the target | the call |

What is read:

- Modules: `EnumProcessModulesEx(LIST_MODULES_ALL)`, `GetModuleFileNameEx`, `GetModuleInformation` (the loader's lists
  in target memory); headers and CodeView records with `ReadProcessMemory`.
- Regions: `VirtualQueryEx`.
- Threads: `NtQueryInformationThread` (TEB, priorities, start address, suspend count), `GetThreadDescription`, the stack
  range from the TEB, registers with `GetThreadContext` (`Wow64GetThreadContext` for a 32-bit process under the 64-bit
  server).
- Stacks: `ReadProcessMemory` of stack and code, unwound by Corvus's own walker (x64 unwind data; x86 PDB frame data,
  call targets and EBP chain).
- Process identity: `QueryFullProcessImageName`, `GetProcessTimes`, `IsWow64Process2`, `GetExitCodeProcess`.

Never done: memory write (`WriteProcessMemory`), protection change (`VirtualProtectEx`), allocation (`VirtualAllocEx`),
stop points, debugger connection (`DebugActiveProcess`, DbgEng), thread suspension or resumption (`SuspendThread`,
`NtSuspendProcess`), context write (`SetThreadContext`), remote thread or APC (`CreateRemoteThread`, `QueueUserAPC`),
handle duplication, privilege change (SeDebugPrivilege is not enabled), dump writing. None of these is even bound:
`LiveProcessTests.Handles_are_query_and_read_only_and_no_write_capable_api_is_bound` checks the P/Invoke declarations of
Native/Live against that list and both access masks.

Nothing to detach: every handle is a SafeHandle closed in `finally` (also on error, cancellation and timeout); the
report states `handlesOpened`, `handlesClosed` (equal) and `detached`. A timeout cancels at the next check (each
module, region batch, thread and frame), and handles close before the error returns.

Remaining side effects:

- `GetThreadContext` on a running thread: the kernel captures registers with a kernel-mode APC in that thread. No
  user-mode code runs and the suspend count is untouched, but a thread executing user code may show a stale frame.
  Waiting threads (the usual case) are exact.
- `ReadProcessMemory` may page in paged-out memory, as any reader does.

Tested by `LiveProcessTests.Inspecting_a_child_leaves_it_unchanged_and_running` (64-bit and WoW64): a child the test
owns (findstr waiting on input) is inspected with stacks; the SHA-256 of every writable committed region of its image
(which also catches a protection change: regions would merge or split) and its threads' suspend counts (kernel value
and scheduler wait reason) match before and after, and the child then takes more input and exits normally.

## Why not DbgEng

DbgEng (`IDebugClient::AttachProcess` with `DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND`) would also
leave the process running, but:

- dbgeng.dll chooses the process handle's access rights, so a read-only handle can be neither guaranteed nor tested;
  with plain Win32 calls the masks are Corvus's own and checked;
- its symbol engine (DbgHelp) names frames from PDBs and symbol servers, not from Corvus's name layers (user renames,
  Il2Cpp, discovered functions), while the minidump walker and namer already work on any `IProcessMemory`;
- the System32 dbgeng.dll is an old, partly documented COM surface; the Win32 route needs no extra component.

## Sessions

Session tools observe a program while it runs: `live_session`, `live_break`, `live_watch`, `live_read`, `live_events`,
`live_coverage`, `live_timeline`, `live_console`, `live_script`.

**Opt-in.** They are registered by default but refuse to run unless the server starts with a switch below. Each one
turns the session tools on (as `--allow-live` does alone) and allows only its own action:

| Switch | Variable | Also allows |
|---|---|---|
| `--allow-live` | `CORVUS_ALLOW_LIVE=1` | nothing more: no attach, no start |
| `--allow-live-attach` | `CORVUS_ALLOW_LIVE_ATTACH=1` | attach to a running program |
| `--allow-live-spawn` | `CORVUS_ALLOW_LIVE_SPAWN=1` | start a program (`live_session action=spawn`, `live_console action=start`) |
| `--live-scripting` | `CORVUS_LIVE_SCRIPTING=1` | `live_script` |

See [configuration.md](configuration.md#security-switches). These are server start-up switches for the whole server
process (for a stdio client, its client configuration); the model cannot turn them on.

`--live-allow <program or folder>` (repeatable) limits attach and spawn to the listed programs. The check uses the final
path (junctions and symbolic links resolved in every folder of the path) and, for a running program, the image path
the OS reports; anything else is refused before a session opens, and a started program is the file that was checked.
List only folders you alone can write to: a file copied or hard-linked into a listed folder counts as inside it.
`server_status` shows the list.

**What a session writes.** Only `live_read` (and `inspect_process`) are read-only. A session loads Frida's agent into
the program; on Windows the agent allocates a `PAGE_EXECUTE_READWRITE` page and writes a small code stub into it. Stop
points, watches (`live_watch`) and coverage are Frida Interceptor hooks that patch the program's code in memory;
`live_script` runs your code inside the program with its rights. Run programs you do not trust only in a disposable
virtual machine: a session observes the program, it does not contain it.

### Frida

A session runs a worker on Frida's Python bindings. Either install them
(`pip install frida`), or let the server keep a pinned private copy:

- Turn on with `--live-install-frida` (`CORVUS_LIVE_INSTALL_FRIDA=1`), or `install.ps1 -WithLive` /
  `install.sh --with-live` / `corvus install --with-live` (these also create it right away).
- When no tested Frida is found, the first session creates a venv (Python's `venv` module, from a 64-bit Python 3.9+)
  at `<data>/frida/python-17.24.3`, and pip installs Frida 17.24.3 from wheels only, with the SHA-256 pinned per
  platform (`--require-hashes`; about 60 MB).
- `CORVUS_OFFLINE=1` refuses the download.

Interpreter search order: `CORVUS_FRIDA_PYTHON`; the private environment, once created; the first Python found (`py`
launcher, then `PATH`) with a tested Frida; a new private environment (with `--live-install-frida`); the first Python
with any Frida. `server_status` shows the interpreter, its source (user Python or private environment) and its Frida
version.

Tested range: Frida 17.24.3 to 17.x. Outside it, a session opens with an `error` event naming the version and range;
older than 17.0 is refused with `provider_unavailable` (the session script needs the 17.x API).

| Step | Call |
|---|---|
| Start a program suspended, or attach to a running one | `live_session action=spawn program=app.exe` / `action=attach program=<pid or name>` |
| Follow the child processes it starts | `live_session action=spawn program=launcher.exe childNames=["app.exe"]` (`["*"]` for every child), then `action=children` and `action=attach_child program=<child pid>` |
| Set stop points before it runs | `live_break action=set at=Orders::AddLine` (or `module!export`, `AddLine+0x1B`, `orders.c:42`, an image or live address) |
| Run to the next stop | `live_break action=continue wait=true` |
| Read the held thread | `live_read registers=rcx,rdx memory=rcx type=int32[2]` |
| Scan its memory with YARA rules | `live_read rules=rules.yar` (rule text, a folder or `pack:<name>`; heap, stacks and data sections, while it runs; Windows and Linux) |
| Record every call of a function | `live_watch action=set at=AddLine` (or `kernelbase!CreateFileA`, an address) |
| Collect code coverage of a run | `live_coverage action=start` before `continue`, then `action=report` (`format=dot` for the call graph); two runs: `action=diff run=cov-1 other=cov-2` |
| Trace the files, registry keys and endpoints it opens | `live_timeline action=start` before `continue`, then `action=list run=tl-1` (`cursor=`) or `action=report`; two runs: `action=diff a=tl-1 b=tl-2` |
| Page what happened | `live_events cursor=<from the last page> kind=stop`; one watch's calls: `live_events from=w1` |
| Run a console program from a script | `live_console action=start program=app.exe script=["wait name?", "send Ada\r", "wait echo: Ada"]`, then `action=transcript run=con-1` (`cursor=`) |
| Load your own script | `live_script action=load path=trace.js` (needs `--live-scripting`) |
| Save the process as a dump | `live_session action=snapshot` (then `dump_stack`, `read_dump_memory` on the dump id) |
| End | `live_session action=close` |

**Events.** Calls keep a ring of their own (10,000), so a call flood never pushes out output, stops or exit; a page
counts the calls dropped between its cursor and its end. Each event row carries the time the server recorded it (UTC).

**Naming.** The program's own image is loaded and indexed when the session opens, so a stack reads
`orders.exe!AddLine+0x1B  orders.c:9` (names from the PDB, the exports, and the COFF symbol table a MinGW-style link
keeps). Other modules join once loaded with `load_assembly`; until then they are named from their file as `dump_stack`
names a core's frames (a DLL's exports within its unwind data, an ELF's `.symtab` and `.dynsym` functions), a return
address by the call before it. Ahead-of-time compiled managed code reads by method, and stop points take the same
names: NativeAOT from its own metadata (`app.exe!Ns_Type__Method`), an Il2Cpp game's binary once `apply_il2cpp_names`
has named it (`GameAssembly.dll!Ns_Type__Update`). Source lines and `file:line` stop points come from PDB line tables
on Windows and DWARF line tables on Linux; on Linux a stop's frames are unwound with each module's `.eh_frame` CFI, as
`dump_stack` walks a core. The module list names the loaded image or assembly each module is (`= id`): a native image
by path, an assembly by path or as a copy of the same bytes.

**Stops and reads.** A stop point holds only the thread that hits it; other threads run on. While a thread is held,
`live_session status` also lists a DLL the loader mapped through a delay-load import before its `module` event arrives,
and the stop's frames in it are named. `live_read` never writes: a `cstring` or `utf16` read stops at the terminator,
at most `length` bytes (default and maximum 4096), and says where an unterminated string stops short; a `pointer` is as
wide as the program's pointers.

**Lifetime.** A session ends on `close`, after `CORVUS_LIVE_MAX_MINUTES` (default 30), or with the server; each
releases every held thread and ends a program the session started. A started program runs in its own folder; its
output arrives as `output` events. Its environment is minimal (`PATH`, `TEMP`, the user folders) plus `DOTNET_ROOT*`
from the server; `environment=["NAME=value"]` on spawn adds more. Other server variables, such as tokens, are not
passed on. It also gets `DOTNET_EnableWriteXorExecute=0`: with W^X on, .NET keeps JIT-compiled code in a shared view a
stop point cannot write, so in an attached program, or one started with W^X back on, a point on JIT-compiled code is
refused.

Attach refuses the server's own process and the processes it runs under (the MCP client, its terminal, the editor),
by id or name: a session held there would freeze the client driving it.

**.NET programs (Windows x64, and x86 under the 64-bit server).** The runtime's DAC (read through ClrMD from process
memory) names JIT-compiled and ReadyToRun code: managed frames read `app.dll!Ns.Type.Method(System.String)+0x1B`,
walked by the runtime from the stop's registers.

- Stop points and watches take `Ns.Type::Method`, with a parameter list for an overload, or `app.dll!Ns.Type::Method`.
- A method without code yet is deferred until compiled (ReadyToRun code binds at once): the compiling thread waits as
  the JIT returns until the point is set, so the first call is caught, `Main` included. A tiered recompile gets the
  point too; an on-stack replacement compile for a running loop is left unhooked.
- Single-file bundled assemblies and .NET Framework native images (`name.ni.dll`) are named the same way.
- A 32-bit runtime is read by the bundled 32-bit decoder (`clr32/`), which checks the DAC's hash before loading it.
  Each read has a 15-second budget; a decoder that fails or overruns is ended, the session says so once in its events,
  names managed code from JIT compiles from then on, and its managed coverage counts first compiles.
- Another architecture, or no DAC found, leaves managed code unnamed; a managed stop point is then set when the JIT
  compiles the method.
- `downloadDac=true` on open fetches a DAC found nowhere locally from a symbol server, into the same signature-checked
  cache as `open_minidump downloadDac=true`. Off by default; refused under `CORVUS_OFFLINE=1`.

`dump_heap` and `dump_object` take a session id in place of a dump: heap statistics by type, matching objects, one
object's fields, read through the same runtime reader without stopping the program. Each report says that objects
allocated, moved or freed during the read can be missing or counted twice, and an object listed before a GC may be
gone; a snapshot (`live_session action=snapshot`) holds one state.

**Deferred points.** A stop point or watch on `module!name` whose module is not loaded yet is deferred: the loading
thread waits at the module's load, before any of its code runs, until the point is set (a `module` event says so), so
the first call is caught.

- A packed DLL (its entry point writes code into a section the file leaves empty) is waited on when that entry point
  returns instead, so the point is not overwritten; stops there are named by the DLL's exports. In an x64 or x86
  program emulated on ARM64 such a point fails with that reason: the emulator runs that code without the hook.
- A deferred point the loaded module does not resolve is dropped: the next `live_break` or `live_watch` call says why,
  and the list shows it as failed until cleared. A managed name (`Ns.Type::Method`) that an Il2Cpp or NativeAOT layer
  names `Ns_Type__Method` gets that name as its next step.
- A stop point on a jump is set where the jump leads; through a pointer in a writable section (a delay-load import, an
  export jumping through a table filled on first use), the point moves when the program rebinds the pointer, and a
  `module` event says so.

**Refused placements**, each with the nearest place that works: an address inside an instruction; a stop point in the
first 16 bytes of a watched or counted function (or a watch or count over one); two stop points whose hook jumps would
overlap (closer than 5 bytes on 32-bit x86, 16 elsewhere); a watch past a function's start; a function too short for a
hook's jump.

**Exit and crashes.** The `exit` event carries the exit code the system reports
(`exit code 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)`; on Linux the status passed to `_exit`). On Windows, a program
still in a module's shutdown 10 seconds after calling `ExitProcess` is ended with the exit code it chose, and an `error`
event says so; this holds for 20 seconds after the session closes too, since a close meeting the start of an exit can
leave the exit unable to finish. An access violation, illegal instruction, stack overflow or arithmetic fault waits
until the server has its `exception` event, so a crash keeps its address; when no event came, one is recorded from the
exit code, without an address. Stack values that cannot be return addresses (small values, header bytes,
non-executable pages) are left out of a stop's frames.

**Child processes.** A launcher, installer or host that starts the real program as a child is followed with
`childNames` on spawn or attach (as Frida's child gating, WinDbg's `.childdbg 1` and GDB's `follow-fork-mode child`).

- Each child is held at its start, before its first instruction, and reported as a `child` event (pid, image path);
  `action=children` lists them with command lines and states.
- `childNames=["app.exe"]` (or `app`) holds only those image names, others run at once; `["*"]` holds every child.
- `action=attach_child program=<pid>` opens a session on a held child, still held, so stop points, watches, coverage
  and timeline are in place before it runs; its first `live_break action=continue` starts it, and it follows its own
  children likewise. `action=release_child` lets a child run unobserved.
- A child never stays suspended: when the session closes (request, deadline or server exit), every child it holds runs
  on, including an attached child whose session has not continued; a child session closed before its first continue
  returns to its parent's hold.
- Linux: a child is reported at its `exec`, by the program it runs, whether a fork or `posix_spawn` started it (a fork
  that never execs is not held); a copy started through `/proc/self/exe` is named by its own image; `attach_child`
  lets it run to its own code, libraries loaded, and holds it at its first instruction there; a session following
  children does not report threads that end.
- Windows: a process another process starts naming the program as its parent (as the WebView2 runtime starts a Tauri
  or WebView2 program's browser process) passes no hold: `action=children` lists it as started by another process, and
  `live_session action=attach program=<pid>` opens it.
- Windows sandboxed children (Chromium and Electron GPU, utility and renderer processes) allow only what their token
  allows. The agent loads from a folder readable by restricted tokens and AppContainers, so a GPU process (restricted
  token) attaches. A child whose sandbox still refuses the agent fails with `access_denied`, naming the sandbox from
  its token (restricted token, AppContainer, low or untrusted integrity); start the program with its sandbox off
  (Chromium's `--no-sandbox`, or `--disable-gpu-sandbox` for the GPU process alone). Under a network logon (such as
  ssh) a restricted-token child does not load the agent and is refused the same way (the cause is unknown); under an
  interactive logon it attaches.

**Watches** record each call's arguments and return value without stopping the program. Decoding, in order: the
known-API table (parameter names, ANSI and wide strings, flags and enums by name: `dwDesiredAccess=GENERIC_READ`); the
PDB or DWARF prototype (names from frame records or entries, types from type records, enums by name; on Linux x64 a
prototype with floating-point or structure arguments falls back to names); DWARF parameter names; else raw `arguments`
values. Strings are read while the call runs, up to 256 characters. Calls are sent in batches (512 calls or every
100 ms, and when the program starts to exit, before its modules shut down). Calls over a watch's `rateLimit` (default
10,000 a second, 1-100,000) are counted, not recorded. Each call is a `call` event named by its caller:
`orders.exe!main+0xDC: AddLine(o=0xE1BAFFE50, qty=3) -> 3`.

**`live_coverage`** collects code coverage from stop events: a stop point at the start of each function of the
program's image (`match=` narrows by name, `module!part` counts another module), each stop counted in the program
without holding the thread, the point cleared after `hitLimit` stops (default 100), so a count at the limit reads
"100+" and the program runs at its own speed.

- A module not loaded yet is read from its file, as a `module!name` stop point reads it, and counted from its first
  call once loaded with `load_assembly`: the run waits for its load, as a deferred stop point does.
- At most 5,000 functions per run; a larger match is refused with the count and narrower matches from the image's names
  (name prefixes, namespaces, `sub_` address prefixes), each with its count.
- Left out: functions reached from TLS callbacks or a DLL's entry point (they also run at process exit), and a point
  the backend cannot hook (reported with the instructions at its start). A function whose first block is too short for
  a hook's jump is refused as "too short to count with stop-based coverage" with its instructions (a leading `endbr64`
  stays in place, so its 4 bytes do not count).
- `action=report` lists functions that ran (`show=missed` or `all`), busiest first; `format=dot` draws them on the
  static call graph in Graphviz DOT, never-run functions dashed. `action=diff` compares two runs of the same build:
  functions run only in each, in both, and in neither.
- Function entries only; blocks inside a function are not counted. A run whose program ends first reads `ended` and
  keeps its counts; `action=stop` leaves it so.

Managed assemblies (`match=app.dll!part`; the program's own assembly or one next to it can be named before it loads)
are covered on Windows from the runtime's record of methods it has prepared code for (JIT-compiled, or ReadyToRun code
bound, at first call). The record is read each second and at exit (the exiting thread is held at
`RtlExitUserProcess` meanwhile), so a report lists methods that ran, by metadata token, without counts, as text only
(no `format=dot`). Until a read succeeds (a program ending before the first read gives none), a method not seen to run
is unknown rather than missed, marked `?`. A runtime the server cannot read (no DAC, or a 32-bit program without the
32-bit decoder installed) is covered from JIT compiles instead: each method's first compile after the run starts,
which leaves out methods compiled earlier and precompiled (ReadyToRun, NGEN) code.

**`live_timeline`** (Windows) collects a timestamped trace from an ETW session with the kernel file, registry, network
and process providers (as PerfView and Process Monitor collect them), keeping the session program's events. Each entry
is a time, a category (`file`, `registry`, `network`, `process`) and the name the OS reports: a file path with drive
letter, a registry key or value as `HKLM\...` / `HKCU\...`, a TCP connect or accept and each UDP endpoint once, a child
program's image. The agent's own files are left out. `action=list` pages entries with a cursor (`category=`, `match=`
filter); `action=report` lists each name once with count and first time. A timeline keeps the latest 100,000 entries
and completes on `stop` or program exit, once the OS has delivered its buffers. Needs administrator rights or
Performance Log Users membership (`access_denied` otherwise); other platforms answer `provider_unavailable`.
`action=diff a=tl-1 b=tl-2` compares two traces as sets of (category, name), ignoring times and counts: names recorded
only in each, paged with `offset` and `limit`.

**`live_console`** (Windows) runs a program under the pseudoconsole (ConPTY, created as Microsoft's terminal samples
create it, 120x30) and drives it from a script, as expect and pexpect harnesses do. Steps, one per line or array
element: `send <text>` (`\r` is Enter; `\n`, `\t`, `\e`, `\xHH`), `wait <text>` (until output since the last match
contains the text; `timeoutSeconds` each, default 10, range 1-300), `resize <columns> <rows>`, `delay <ms>`.
`action=start` runs the steps in order and reports each; the first that cannot complete stops the script with its
reason and the console's last lines. The transcript is plain text lines, escape sequences removed; `action=transcript`
pages it with a cursor (a line still being written, such as a prompt, comes again on the next poll); a run keeps the
latest 20,000 lines. The program runs on after the script until it exits or `action=stop`; every run ends with the
server. Needs `--allow-live-spawn`; other platforms answer `provider_unavailable`.

Session tool results are kept as evidence records (`live_console` keeps the script among the arguments, so a run can
be repeated).

**`action=snapshot`** writes the process as a standard dump file with the OS's own writer (MiniDumpWriteDump on
Windows, as dotnet-dump and ProcDump; GDB's `gcore` on Linux; lldb's `process save-core` on macOS, modified memory as a
Mach-O core) and opens it with the dump tools; the program keeps running. Output goes to `outputPath`, else a new file
under the temp folder's `corvus-snapshots`. Saved while a thread is held at a stop, a Windows dump or Linux core records
that stop (Windows: as its exception, a breakpoint, as a debugger's `.dump` at a break; Linux: the stopped thread's
registers and signal, `SIGTRAP`, `TRAP_BRKPT` at the stop's address), so `dump_stack` walks from the stop. On Linux GDB
stops every thread, and a thread waiting in `vfork` for a child that has not run its program cannot stop: such a
snapshot is refused with `timeout` once that wait lasts 10 seconds; a `gcore` that is ended (that refusal,
cancellation, or 5 minutes) leaves the program running as it found it.

**`live_script`** loads your own script into the program (Frida's JavaScript API); what it sends arrives as `script`
events, and a script that does not compile is refused with the compiler's message. It runs inside the program with its
rights and can change it, hence `--live-scripting`. On Windows, Frida 17 lists modules in no fixed order and its
`Process.mainModule` can name a system DLL; find the program's module by name.

Measured on a small MSVC-built program (Windows 11, x64): session open with modules matched 1.1-1.5 s; held stop to
named stack 1 ms; stop point set by name 0.6 s on first call (the image's index), then under 10 ms; a watched function
called 20,000 times in a loop: every call recorded at 107,000-136,000 calls a second (target 5,000). Coverage of the same
program (3,020 functions, static C runtime): stop points placed in 1.4-1.7 s, 165 functions ran.

## Limits

- `inspect_process` is Windows only. A 32-bit server cannot read a 64-bit process (`unsupported`, reason
  `bitness_mismatch`); the 64-bit server reads 64-bit and WoW64 processes. ARM64 process registers are read by an ARM64
  server only; stacks are walked for x64 and x86.
- Processes of another user, elevated processes (from a non-elevated server) and protected processes fail with
  `access_denied`; an exited process fails with `not_found` (reason `process_exited`).
- `inspect_process` identifies managed (JIT) frames without decoding them; sessions name them.
- Sessions run on Windows, Linux and macOS (`live_timeline`, `live_console`: Windows only). Minidumps and core files
  open with `open_minidump` on any OS.
- macOS (tested on Apple silicon, GitHub's macos-latest: Developer Mode on, user in `_developer`): a session observes
  what a debugger may, programs built on the machine or signed with `get-task-allow`. `snapshot` needs lldb (Xcode
  command line tools); the core's thread ids are lldb's, so `dump_stack` takes a thread by `#index` there
  (`open_minidump view=threads` lists them). `childNames` fails with `unsupported`, since Frida's child gating misses a
  fork there intermittently.
- Windows ARM64: ARM64 programs are observed natively. x64 and x86 programs run under emulation: `module!export`
  resolves to the export the program calls (the x64 or x86 view of a system DLL), and `snapshot` is refused
  (`unsupported`), since the dump would hold the emulator's ARM64 threads.
- Linux without CAP_SYS_PTRACE is bound by Yama's `ptrace_scope`: at 1, sessions on programs the server starts work,
  while attach and `snapshot` fail with `access_denied` naming the setting; at 2 every session and snapshot fails so.
- musl libc (Alpine): attach works; starting a program fails with Frida's `ProcessNotRespondingError` and leaves
  nothing running.
- A statically linked Linux program (no program interpreter: most Go programs, busybox) is refused with `unsupported`
  before anything starts, since Frida loads its agent through the dynamic loader and C library. Read the file
  statically, or write a core with `gcore` and open it with `open_minidump`.
- Linux sessions report a thread's start from `pthread_create`; a bare `clone` thread has only its `ended` event. A
  stop's stack is unwound from the 32 KiB above its stack pointer; deeper frames come from the stack scan.
