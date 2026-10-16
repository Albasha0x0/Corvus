namespace Corvus.Mcp;

public static partial class Guide
{
    private const string DumpsTopic = """
        Crash dumps and live processes.
        open_minidump (user-mode .dmp; view=summary: exception, faulting module+function, instruction and thread; view=modules:
        whether the binaries exist locally; threads, memory, unloaded), dump_stack (x64 unwind data, x86 frame pointers; scanned
        frames carry basis inferred), read_dump_memory. Linux / Android ELF cores open the same way: threads and registers, the signal,
        modules matched to local files by GNU build id, .eh_frame CFI unwinding with a frame-pointer fallback (no managed heap: that
        needs the Linux DAC).
        Load the crashed binaries first so frames get your names, PDB and Il2Cpp names; pass imageDirectories when they are not at
        their recorded paths. .NET dumps: the runtime's DAC (found locally: dacPath, the same runtime installed here, symbol stores;
        downloadDac=true fetches it, never under CORVUS_OFFLINE=1; always signature-checked) decodes the managed exception and its
        inner chain, and gives managed frames a token, IL offset, the C# statement and the loaded assembly of that build (load the
        app's assemblies first; decompile_member assembly=<id> member=<token>); .NET Framework and 32-bit dumps too. Unity Mono:
        the runtime's report beside the dump (Player.log, error.log) names the JIT frames. With heap memory in the dump:
        dump_heap (stats per type, or objects by type) and dump_object (fields, strings, arrays; the exception's address works).
        No dump, only text (Player.log, error.log, Report.wer, event text, an exception's ToString, a debugger stack):
        symbolize_stack_text names each frame in the loaded build; check buildCheck before trusting a name (mismatch: another build).
        A folder of dumps: bucket_minidumps groups them by signature; open the largest bucket's representative.
        inspect_process does the same for a running local process (Windows), read-only: view=summary, modules, regions, threads, stacks. It
        opens only query and read handles, writes and suspends nothing, and closes every handle before returning. Pick the target
        by pid or name (a shared name is refused with the candidate pids).
        Sessions (off unless the server runs with --allow-live; Python with Frida's bindings): live_session attaches to a local
        program, or spawns one suspended (--allow-live-spawn), and matches its modules to loaded images; live_break sets stop
        points by name, module!export, address or file:line, continue resumes held threads (and starts a spawned program), and
        wait returns the next stop with a named stack; live_read reads a held thread's registers and memory as typed values;
        live_events pages the event ring with a cursor. Close sessions when done: held threads are released, a spawned program ends.
        """;
}
