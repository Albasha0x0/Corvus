# Live process inspection (read-only)

Tool: `inspect_process` (src/Corvus/Tools/LiveProcessTools.cs, Services/LiveProcessService.cs,
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
(`VirtualAllocEx`), no breakpoint, no debugger attach (`DebugActiveProcess`, DbgEng), no thread suspension or resumption
(`SuspendThread`, `NtSuspendProcess`), no context write (`SetThreadContext`), no remote thread or APC
(`CreateRemoteThread`, `QueueUserAPC`), no handle duplication, no privilege change (SeDebugPrivilege is not enabled), no
dump written. None of these functions is even bound: `LiveProcessTests.Handles_are_query_and_read_only_...` checks the
P/Invoke declarations of Native/Live against that list and the two access masks.

Detaching: there is no attach to undo. Every handle is a SafeHandle closed in `finally` (also on errors, cancellation and
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

## Limits

- Windows only. A 32-bit server cannot read a 64-bit process (`unsupported`, reason `bitness_mismatch`); the 64-bit server
  reads 64-bit and WoW64 processes. Registers of an ARM64 process are read by an ARM64 server only, and stacks are
  walked for x64 and x86.
- Processes of another user, elevated processes (from a non-elevated server) and protected processes fail with
  `access_denied`. A process that has exited fails with `not_found` (reason `process_exited`).
- Managed (JIT) frames are identified, not decoded; use a managed debugger or SOS for those.
