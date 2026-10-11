# Guide: dumps

<!-- Generated from src/NetDecompilerMcp/Mcp/Guide.cs; run the tests with NDM_UPDATE_DOCS=1 to update. -->

Crash dumps and live processes.
open_minidump (user-mode .dmp: exception, faulting module+function and instruction, modules and whether the binaries exist
locally, threads), dump_stack (x64 unwind data, x86 frame pointers; scanned frames marked heuristic), read_dump_memory.
Load the crashed binaries first so frames get your names, PDB and Il2Cpp names; pass imageDirectories when they are not at
their recorded paths. Managed frames are only identified.
inspect_process does the same for a running local process (Windows), read-only: modules, regions, threads and stacks. It
opens only query and read handles, writes and suspends nothing, and closes every handle before returning. Pick the target
by pid or name (a shared name is refused with the candidate pids).
