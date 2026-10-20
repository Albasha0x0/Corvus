# Live process inspection and sessions

Tool: `inspect_process` (src/Corvus/Tools/Dumps/LiveProcessTools.cs, Services/LiveProcessService.cs,
Native/Live/LiveProcess.cs, Native/Live/LiveNative.cs). Windows only; elsewhere it fails with `provider_unavailable`.

It reports a running local process's modules, memory regions, threads and call stacks, with every address named the
same way `dump_stack` names a crash dump's: a loaded native image's code index (user renames, PDB, Il2Cpp and discovered
names, in that priority), Il2Cpp dummy DLLs for GameAssembly.dll, a matching local PDB, then exports. Live process and
minidump share one abstraction (`IProcessMemory` in Native/Dump/ProcessMemory.cs): the stack walker, the module image
lookup (matching file on disk, else the image rebuilt from process memory) and the namer are the dump code, unchanged.

## The read-only guarantee

What is opened, with which rights:

| Object | API | Access rights | Lifetime |
|---|---|---|---|
| The process | `OpenProcess` | `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ` (0x410) | the call; closed before it returns |
| Each listed thread | `OpenThread` | `THREAD_GET_CONTEXT \| THREAD_QUERY_INFORMATION` (0x48) | one thread at a time; closed right after it is read |
| The thread list | `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` | none on the target (a system-wide snapshot) | the call |
| Selection by name or id | the system process list (`Process.GetProcesses` / `GetProcessById`: names, ids, sessions) | none on the target | the call |

What is read, and how:

- Modules: `EnumProcessModulesEx(LIST_MODULES_ALL)`, `GetModuleFileNameEx`, `GetModuleInformation` (these read the
  loader's lists from the target's memory), headers and CodeView records with `ReadProcessMemory`.
- Regions: `VirtualQueryEx`.
- Threads: `NtQueryInformationThread` (basic information: TEB, priorities; start address; suspend count),
  `GetThreadDescription`, the stack range from the TEB (`ReadProcessMemory`), registers with `GetThreadContext`
  (`Wow64GetThreadContext` for a 32-bit process seen from the 64-bit server).
- Stacks: `ReadProcessMemory` of the stack and code, unwound by our own walker (x64 unwind data, x86 EBP chain).
- Process identity: `QueryFullProcessImageName`, `GetProcessTimes`, `IsWow64Process2`, `GetExitCodeProcess`.

What is never done: no memory write (`WriteProcessMemory`), no protection change (`VirtualProtectEx`), no allocation
(`VirtualAllocEx`), no stop points, no debugger connection (`DebugActiveProcess`, DbgEng), no thread suspension or resumption
(`SuspendThread`, `NtSuspendProcess`), no context write (`SetThreadContext`), no remote thread or APC
(`CreateRemoteThread`, `QueueUserAPC`), no handle duplication, no privilege change (SeDebugPrivilege is not enabled), no
dump written. None of these functions is even bound: `LiveProcessTests.Handles_are_query_and_read_only_...` checks the
P/Invoke declarations of Native/Live against that list and the two access masks.

Disconnecting: there is no session to undo. Every handle is a SafeHandle closed in `finally` (also on errors, cancellation and
timeouts); the report states `handlesOpened`, `handlesClosed` and `detached` (equal counts). A timeout cancels the work
at its next check (each module, region batch, thread and frame) and the handles are closed before the error is returned.

Side effects that remain:

- `GetThreadContext` on a thread that is not suspended: the kernel captures the registers with a kernel-mode APC in the
  target thread. No user-mode code runs in the target and its suspend count is not touched, but the values are a snapshot
  of a running thread, so a thread that was executing user code may show a stale frame. Waiting threads (the usual case)
  are exact.
- The target's working set is unchanged by reads in practice, but `ReadProcessMemory` may page in memory that was paged
  out, as any reader does.

Tested by `LiveProcessTests.Inspecting_a_child_leaves_it_unchanged_and_running` (64-bit and WoW64): a child process the
test owns (findstr waiting on its input) is inspected with stacks; the SHA-256 of every writable committed region of its
image (which also catches a protection change: regions would merge or split), and its threads' suspend counts (kernel
value and the scheduler's wait reason) are the same before and after, and the child then takes more input and exits
normally.

## Why not DbgEng

DbgEng (`IDebugClient::AttachProcess` with `DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND`) would also
leave the process running, but:

- the access rights of the process handle are chosen inside dbgeng.dll, not by the caller, so a read-only handle can be
  neither guaranteed nor tested; with the plain Win32 calls above the access masks are ours and checked;
- its symbol engine (DbgHelp) names frames from PDBs and symbol servers, not from our name layers (user renames, Il2Cpp,
  discovered functions), so the naming would have to be redone on top of it anyway, while the minidump stack walker and
  namer already work on any `IProcessMemory`;
- the System32 dbgeng.dll is an old, partly documented COM surface; the Win32 route needs no extra component.

## Sessions

The session tools observe a program while it runs. They are off unless the server starts with `--allow-live-attach`
(attach to a program already running), `--allow-live-spawn` (start one) or `--live-scripting`; each turns them on, as
`--allow-live` does without opening a program ([configuration.md](configuration.md#security-switches)).
`--live-allow <program or folder>` (repeatable) limits both to the programs listed: the check uses the final path
(junctions and symbolic links in any folder of the path resolved) and, for a running program, the image path the
operating system reports; anything outside the list is refused before a session opens, and a started program is the
file that was checked. List only folders that you alone can write to: a file copied or hard-linked into a listed folder
counts as inside it. `server_status` shows the list. These are server start-up switches (each also an environment variable, such as `CORVUS_ALLOW_LIVE=1`): they
apply to the whole server process, which for a stdio client means its client configuration. The model cannot turn them on.

Run programs you do not trust only in a disposable virtual machine: a session observes the program, it does not contain
it. A session runs a worker on Frida's Python bindings
(`pip install frida`; `CORVUS_FRIDA_PYTHON` names the interpreter when the first one found lacks them).

| Step | Call |
|---|---|
| Start a program suspended, or attach to a running one | `live_session action=spawn program=app.exe` / `action=attach program=<pid or name>` |
| Set stop points before it runs | `live_break action=set at=Orders::AddLine` (or `module!export`, `AddLine+0x1B`, `orders.c:42`, an image or live address) |
| Run to the next stop | `live_break action=continue wait=true` |
| Read the held thread | `live_read registers=rcx,rdx memory=rcx type=int32[2]` |
| Record every call of a function | `live_watch action=set at=AddLine` (or `kernelbase!CreateFileA`, an address) |
| Collect code coverage of a run | `live_coverage action=start` before `continue`, then `action=report` (`format=dot` for the call graph); two runs: `action=diff run=cov-1 other=cov-2` |
| Trace the files, registry keys and endpoints it opens | `live_timeline action=start` before `continue`, then `action=list run=tl-1` (`cursor=`) or `action=report`; two runs: `action=diff a=tl-1 b=tl-2` |
| Page what happened | `live_events cursor=<from the last page> kind=stop`; one watch's calls: `live_events from=w1` |
| Run a console program from a script | `live_console action=start program=app.exe script=["wait name?", "send Ada\r", "wait echo: Ada"]`, then `action=transcript run=con-1` (`cursor=`) |
| Load your own script | `live_script action=load path=trace.js` (needs `--live-scripting`) |
| Save the process as a dump | `live_session action=snapshot` (then `dump_stack`, `read_dump_memory` on the dump id) |
| End | `live_session action=close` |

Addresses are joined to the static model: the program's own image is loaded and indexed when the session opens, so a
stack reads `orders.exe!AddLine+0x1B  orders.c:9`, not a bare address; other modules join once loaded with
`load_assembly`. Source lines and `file:line` stop points come from the PDB line tables on Windows and the DWARF line
tables on Linux; on Linux a stop's frames are unwound from its stack with each module's `.eh_frame` CFI, as `dump_stack`
walks a core. Stop points hold only the thread that hits them; other threads run on. Memory is read, never written.
A session ends on `close`, after `CORVUS_LIVE_MAX_MINUTES` (default 30) and with the server; each releases every held
thread, and a program the session started is ended. A started program runs in its own folder and its output arrives
as `output` events. It gets a minimal environment (`PATH`, `TEMP`, the user folders) plus `DOTNET_ROOT*` from the server;
`environment=["NAME=value"]` on spawn sets more. Other server variables, such as tokens, are not passed on.

Attach refuses the server's own process and the processes it runs under (the MCP client, its terminal, the editor), by id
or by name: a session held there would freeze the client driving it.

A stop point or watch on `module!name` whose module is not loaded yet is deferred, as a debugger defers an unresolved
breakpoint: the loading thread waits at the module's load, before any of the module's code runs, until the point is set
(a `module` event says so), so its first call is caught. An address inside an instruction, a stop point in the first 16 bytes of a watched or counted function (or a watch or count over one),
two stop points whose hook jumps would overlap (closer than 5 bytes on 32-bit x86, 16 elsewhere), a watch past a function's
start, and a function too short for a hook's jump are refused with the nearest place that works. The `exit` event carries the
exit code the system reports (`exit code 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)`; on Linux the status passed to `_exit`). On Windows, a program that called
`ExitProcess` but is still in a module's shutdown 10 seconds later is ended with the exit code it chose, and an `error` event says so. An access violation, illegal
instruction, stack overflow or arithmetic fault waits until the server has its `exception` event, so a crash keeps its
address; when no event came, one is recorded from the exit code, without an address. Stack values that cannot be
return addresses (small values, header bytes, non-executable pages) are left out of a stop's frames.

A watch records each call's arguments and return value without stopping the program. They are decoded from, in order:
the known-API table (parameter names, ANSI and wide strings, flags and enumerations by name: `dwDesiredAccess=GENERIC_READ`),
the PDB or DWARF prototype (parameter names from the procedure's frame records or entries, types from the type records,
enums by name; on Linux x64 a prototype with floating-point or structure arguments falls back to names), DWARF
parameter names, else `arguments` raw values. Strings are read while the call runs, up to 256 characters. The session
script sends calls in batches (512 calls or every 100 ms, and at exit); calls over a watch's `rateLimit` (default 10,000
a second) are counted, not recorded, so a hot function does not slow the program. Each call is a `call` event named by
its caller: `orders.exe!main+0xDC: AddLine(o=0xE1BAFFE50, qty=3) -> 3`.

`live_coverage` collects code coverage the way a coverage profiler does, from stop events: a stop point at the start
of each function of the program's image (`match=` narrows by name, `module!part` counts another module), each stop
counted and resumed at once, the point cleared after `hitLimit` stops (default 100), so a count at the limit reads
"100+". Functions reached from TLS callbacks or a DLL's entry point are left out, since they also run at process exit;
a function whose first block is too short is refused with the reason "too short to count with stop-based coverage".
`action=report` lists the functions that ran (`show=missed` or `all`), busiest first, and `format=dot` draws them on
the static call graph in Graphviz DOT, functions that never ran dashed. `action=diff` compares two runs of the same
build: the functions that ran only in each, in both and in neither. Counting covers function entries; blocks inside a
function are not counted.

`live_timeline` collects a timestamped trace from the OS diagnostics channel: an event tracing session (ETW) with the
kernel file, registry, network and process providers, as PerfView and Process Monitor collect them, keeping the
session program's events. Each entry is a time, a category (`file`, `registry`, `network`, `process`) and the name the
OS reports: a file path with its drive letter, a registry key or value as `HKLM\...` / `HKCU\...`, a TCP connect or
accept and each UDP endpoint once, a child program's image. `action=list` pages entries with a cursor (`category=`,
`match=` filter), `action=report` lists each name once with its count and first time; a timeline keeps the latest
100,000 entries, and it completes on `stop` or when the program exits, once the OS has delivered its buffers. Event
tracing needs administrator rights or membership in Performance Log Users (`access_denied` otherwise); other platforms
answer `provider_unavailable`. Results are kept as evidence records like the other session tools.
`action=diff a=tl-1 b=tl-2` compares two traces as sets of (category, name), times and counts aside: the names recorded
only in each, paged with `offset` and `limit`.

`live_console` runs a program under a console host and drives it from a script, as expect and pexpect test harnesses do:
the Windows pseudoconsole (ConPTY), created as Microsoft's terminal samples create it, at 120x30. The script is a list of
steps, one per line or array element: `send <text>` types into the console (`\r` is Enter; `\n`, `\t`, `\e`, `\xHH`),
`wait <text>` waits until the output since the last match contains the text (`timeoutSeconds` each, default 10),
`resize <columns> <rows>` and `delay <ms>`. `action=start` runs the steps in order and reports each one; the first that
cannot complete stops the script with its reason and the last lines the console showed. The transcript is the console's
output as plain text lines, escape sequences left out; `action=transcript` pages it with a cursor (a line still being
written, such as a prompt, comes again on the next poll), and a run keeps the latest 20,000 lines. The program keeps
running after the script until it exits or `action=stop`; every run ends with the server. Starting one needs
`--allow-live-spawn`; other platforms answer `provider_unavailable`. Results are kept as evidence records, the script
among the arguments, so the same run can be repeated.

`action=snapshot` writes the session's process as a standard dump file with the operating system's own writer (MiniDumpWriteDump
on Windows, as dotnet-dump and ProcDump write them; GDB's `gcore` on Linux) and opens it
with the dump tools; the program keeps running. The dump goes to `outputPath`, else a new
file under the temp folder's `corvus-snapshots`.

`live_script` loads a script you wrote into the program (Frida's JavaScript API); what it sends arrives as `script`
events, and a script that does not compile is refused with the compiler's message. A script runs inside the program
with its rights and can change it, so the tool is off unless the server also starts with `--live-scripting`.

Measured on a small MSVC-built program (Windows 11, x64): session open with modules matched 1.1-1.5 s; a held stop to
its named stack 1 ms; a stop point set by name 0.6 s on the first call (the image's index), then under 10 ms; a watched
function called 20,000 times in a loop: every call recorded at 107,000-136,000 calls a second (target 5,000). Coverage
of the same program (3,020 functions, statically linked C runtime): stop points placed in 1.4-1.7 s, 165 functions ran.

## Limits

- Windows only. A 32-bit server cannot read a 64-bit process (`unsupported`, reason `bitness_mismatch`); the 64-bit server
  reads 64-bit and WoW64 processes. Registers of an ARM64 process are read by an ARM64 server only, and stacks are
  walked for x64 and x86.
- Processes of another user, elevated processes (from a non-elevated server) and protected processes fail with
  `access_denied`. A process that has exited fails with `not_found` (reason `process_exited`).
- Managed (JIT) frames are identified, not decoded; use a managed debugger or SOS for those.
- Sessions on Linux report a thread's start from `pthread_create`; a thread made with a bare `clone` has only its `ended`
  event. A stop's stack is unwound from the 32 KiB above its stack pointer; deeper frames are the stack scan's.
