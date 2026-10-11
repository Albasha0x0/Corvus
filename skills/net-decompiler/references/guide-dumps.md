# Guide: dumps

<!-- Generated from src/NetDecompilerMcp/Mcp/Guide.cs; run the tests with NDM_UPDATE_DOCS=1 to update. -->

Crash dumps and live processes.
open_minidump (user-mode .dmp: exception, faulting module+function and instruction, modules and whether the binaries exist
locally, threads), dump_stack (x64 unwind data, x86 frame pointers; scanned frames marked heuristic), read_dump_memory.
Load the crashed binaries first so frames get your names, PDB and Il2Cpp names; pass imageDirectories when they are not at
their recorded paths. .NET dumps: the runtime's DAC (found locally: dacPath, the same runtime installed here, symbol stores;
downloadDac=true fetches it, never under NDM_OFFLINE=1; always signature-checked) decodes the managed exception and its
inner chain, and gives managed frames a token, IL offset and the loaded assembly of that build (load the app's assemblies
first; decompile_member assembly=<id> member=<token>). Mono frames stay identified only. With heap memory in the dump:
dump_heap (stats per type, or objects by type) and dump_object (fields, strings, arrays; the exception's address works).
inspect_process does the same for a running local process (Windows), read-only: modules, regions, threads and stacks. It
opens only query and read handles, writes and suspends nothing, and closes every handle before returning. Pick the target
by pid or name (a shared name is refused with the candidate pids).
