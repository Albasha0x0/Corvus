namespace Corvus.Mcp;

public static partial class Guide
{
    private const string DumpsTopic = """
        Crash dumps and running processes.
        - open_minidump reads a user-mode .dmp: view=summary (exception, faulting function, thread), modules, threads, memory, unloaded.
        - dump_stack unwinds a thread (scanned frames carry basis inferred); read_dump_memory reads its memory.
        - Linux / Android ELF cores and macOS Mach-O cores open the same way; modules match local files by build id or UUID.
        - A .NET Linux core reads through the Windows-hosted DAC; pass the runtime's folder in imageDirectories.
        - A region-set manifest (JSON: format, arch, regions, modules; region files beside it) opens as a dump; its threads and exception are unknown.
        - Load the crashed binaries first so frames get your names; pass imageDirectories when they moved.
        - .NET dumps: the runtime's DAC decodes the managed exception and gives frames a token, IL offset and C# statement; load the app's assemblies first.
        - The DAC is found locally (dacPath, installed runtime, symbol stores); downloadDac=true fetches it, never under CORVUS_OFFLINE=1; its signature is always checked.
        - Mono: the runtime's log beside the dump (Player.log, error.log) names JIT frames.
        - With heap memory in the dump: dump_heap (per-type stats or objects) and dump_object (fields, strings, arrays).
        - Text only (a log, Report.wer, an exception's ToString, a debugger stack): symbolize_stack_text names frames in the loaded build.
        - symbolize_stack_text: check buildCheck before trusting a name; a mismatch means another build.
        - A folder of dumps: bucket_minidumps groups them by signature; open the largest bucket's representative.
        - inspect_process reads a running local Windows process (view=summary, modules, regions, threads, stacks) with query and read handles only; nothing is written or suspended.
        - inspect_process refuses a name several processes share and lists their pids.
        - Sessions are off unless the server runs with --allow-live-attach, --allow-live-spawn, --live-scripting or --allow-live; they need Python with Frida's bindings.
        - live_session attaches (--allow-live-attach) or spawns suspended (--allow-live-spawn with --live-allow <paths or *>), limited to --live-allow paths when set.
        - live_break sets stop points (name, module!export, address, file:line); continue resumes (and starts a spawned program); wait returns the next stop with a stack.
        - live_read reads a held thread's registers and memory; live_watch records calls with decoded arguments.
        - live_coverage counts which functions ran and diffs two runs; live_timeline traces files, registry keys, endpoints and child processes (Windows).
        - live_console (--allow-live-spawn) runs a console program with a send / wait / resize / delay script.
        - live_script (--live-scripting) loads your own script; live_events pages the event ring with a cursor.
        - Close sessions when done: held threads are released and a spawned program ends.
        """;
}
