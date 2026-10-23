using System.Diagnostics;
using System.Runtime.InteropServices;
using Corvus.Native.Providers.Live;

namespace Corvus.Tests;

/// <summary>A target the session tests build programs for: Windows with MSVC, Linux with gcc or macOS with clang; x64, x86 or arm64.</summary>
internal sealed class LiveTarget
{
    public static readonly LiveTarget WinX64 = new("win-x64", windows: true, is64: true);
    public static readonly LiveTarget WinX86 = new("win-x86", windows: true, is64: false);
    public static readonly LiveTarget LinuxX64 = new("linux-x64", windows: false, is64: true);
    public static readonly LiveTarget LinuxX86 = new("linux-x86", windows: false, is64: false);
    public static readonly LiveTarget LinuxArm64 = new("linux-arm64", windows: false, is64: true, arm64: true);
    public static readonly LiveTarget WinArm64 = new("win-arm64", windows: true, is64: true, arm64: true);
    public static readonly LiveTarget MacArm64 = new("osx-arm64", windows: false, is64: true, arm64: true, mac: true);

    public string Name { get; }
    public bool Windows { get; }
    public bool Is64 { get; }
    public bool Arm64 { get; }
    public bool Mac { get; }
    private readonly Lazy<string?> _missing;

    private LiveTarget(string name, bool windows, bool is64, bool arm64 = false, bool mac = false)
    {
        Name = name;
        Windows = windows;
        Is64 = is64;
        Arm64 = arm64;
        Mac = mac;
        _missing = new(FindMissing);
    }

    /// <summary>The C library is musl (Alpine): Frida attaches there, but a program it starts never answers its agent.</summary>
    public static bool Musl { get; } = OperatingSystem.IsLinux() && Directory.Exists("/lib") && Directory.EnumerateFiles("/lib", "ld-musl-*.so.1").Any();

    public const string MuslStart = "Frida does not start programs on musl libc (ProcessNotRespondingError); sessions attach to running programs there.";

    public static LiveTarget Of(string name) => new[] { WinX64, WinX86, WinArm64, LinuxX64, LinuxX86, LinuxArm64, MacArm64 }.Single(t => t.Name == name);

    /// <summary>Why this target's programs cannot be built and observed here; null when they can.</summary>
    public string? Missing => _missing.Value;

    public string Exe(string name) => Windows ? name + ".exe" : name;

    /// <summary>The register holding the first integer argument at a function's entry; null where it is on the stack (x86).</summary>
    public string? FirstArgument => ArgumentRegisters?[0];

    /// <summary>The registers holding the first three integer arguments at a function's entry; null where they are on the stack (x86).</summary>
    public string[]? ArgumentRegisters => !Is64 ? null : Arm64 ? ["x0", "x1", "x2"] : Windows ? ["rcx", "rdx", "r8"] : ["rdi", "rsi", "rdx"];

    /// <summary>The architecture as Frida names it (Process.arch).</summary>
    public string FridaArch => Arm64 ? "arm64" : Is64 ? "x64" : "ia32";

    /// <summary>An x64 or x86 Windows program on an arm64 machine, which runs it under emulation.</summary>
    public bool Emulated => Windows && !Arm64 && RuntimeInformation.OSArchitecture == Architecture.Arm64;

    /// <summary>The module that exports the C library's file open: <c>module!name</c> for a watch.</summary>
    public string FileOpen => Windows ? "kernelbase!CreateFileA" : Mac ? "libsystem_kernel.dylib!open" : "libc.so.6!open";

    private string? FindMissing()
    {
        var system = Windows ? "Windows" : Mac ? "macOS" : "Linux";
        if (Windows != OperatingSystem.IsWindows() || Mac != OperatingSystem.IsMacOS() || (!Windows && !Mac && !OperatingSystem.IsLinux())) return $"{Name} programs run on {system}.";
        // x64 and x86 Windows programs also run on an arm64 machine, under
        // emulation.
        if ((Arm64 || !Windows) && Arm64 != (RuntimeInformation.OSArchitecture == Architecture.Arm64)) return $"{Name} programs run on {(Arm64 ? "an arm64" : "an x64")} machine.";
        if (new FridaBackend().Unavailable() is { } frida) return frida.Reason;
        if (Windows) return VisualStudio.VcVarsAll() == null ? "No Visual Studio C++ toolset." : null;
        using var dir = new TempDir();
        File.WriteAllText(dir.File("probe.c"), "#include <pthread.h>\nint main(void){return 0;}\n");
        var (code, log) = Tools.Run(Gcc(dir, "probe"));
        return code == 0 ? null : $"{(Mac ? "clang" : "gcc")} cannot build {Name} programs here ({(Is64 ? "" : "gcc-multilib, ")}{log.Trim().Split('\n')[^1]}).";
    }

    /// <summary>
    /// Compiles <paramref name="source"/> into <c>name</c>(.exe) in <paramref name="dir"/>, unoptimized with full debug information;
    /// <paramref name="linkStatic"/> links the C library in (gcc only).
    /// </summary>
    public string Build(TempDir dir, string name, string source, bool linkStatic = false)
    {
        File.WriteAllText(dir.File(name + ".c"), source);
        var (code, log) = Tools.Run(Windows ? Msvc(dir, name) : Gcc(dir, name, linkStatic: linkStatic), 300_000);
        Assert.True(code == 0 && File.Exists(dir.File(Exe(name))), log);
        if (Mac) Debuggable(dir, dir.File(Exe(name)));
        return dir.File(Exe(name));
    }

    /// <summary>The file a shared library <c>name</c> builds to: name.dll, or libname.so.</summary>
    public string Library(string name) => Windows ? name + ".dll" : "lib" + name + (Mac ? ".dylib" : ".so");

    /// <summary>Compiles <paramref name="source"/> into the shared library <see cref="Library"/> in <paramref name="dir"/>, unoptimized, with full debug information or none.</summary>
    public string BuildLibrary(TempDir dir, string name, string source, bool debugInfo = true)
    {
        File.WriteAllText(dir.File(name + ".c"), source);
        var (code, log) = Tools.Run(Windows ? Msvc(dir, name, library: true, debugInfo) : Gcc(dir, name, library: true, debugInfo), 300_000);
        Assert.True(code == 0 && File.Exists(dir.File(Library(name))), log);
        return dir.File(Library(name));
    }

    /// <summary>
    /// Signs a macOS program ad hoc with the get-task-allow entitlement, as Xcode signs a debug build: without it the
    /// system lets no other process (Frida included) read the program's task.
    /// </summary>
    private static void Debuggable(TempDir dir, string exe)
    {
        File.WriteAllText(dir.File("debuggable.plist"), """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
            """);
        var psi = new ProcessStartInfo("codesign") { WorkingDirectory = dir.Path };
        foreach (var a in new[] { "--force", "--sign", "-", "--entitlements", "debuggable.plist", exe }) psi.ArgumentList.Add(a);
        var (code, log) = Tools.Run(psi);
        Assert.True(code == 0, log);
    }

    private ProcessStartInfo Msvc(TempDir dir, string name, bool library = false, bool debugInfo = true) => new("cmd.exe")
    {
        WorkingDirectory = dir.Path,
        Arguments = $"/s /c \"\"{VisualStudio.VcVarsAll()}\" {VcVarsTarget} >nul && cl /nologo /Od {(debugInfo ? "/Zi " : "")}{(library ? "/LD " : "")}{name}.c /link {(debugInfo ? "/DEBUG:FULL" : "/DEBUG:NONE")} /INCREMENTAL:NO /OUT:{(library ? Library(name) : name + ".exe")}\"",
    };

    /// <summary>vcvarsall's argument: the host's own tools for its architecture, the x64-hosted ones (under emulation on arm64) otherwise.</summary>
    private string VcVarsTarget => !Arm64 ? (Is64 ? "x64" : "x86") : RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "arm64" : "x64_arm64";

    private ProcessStartInfo Gcc(TempDir dir, string name, bool library = false, bool debugInfo = true, bool linkStatic = false)
    {
        var psi = new ProcessStartInfo("gcc") { WorkingDirectory = dir.Path };
        foreach (var a in new[] { debugInfo ? "-g" : "-g0", "-O0", "-fno-omit-frame-pointer", Arm64 ? "" : Is64 ? "-m64" : "-m32", linkStatic ? "-static" : "" })
            if (a.Length > 0) psi.ArgumentList.Add(a);
        foreach (var a in library ? ["-fPIC", "-shared", "-o", Library(name), name + ".c"] : new[] { "-o", name, name + ".c", "-lpthread", "-ldl" }) psi.ArgumentList.Add(a);
        return psi;
    }

    public override string ToString() => Name;
}

/// <summary>Runs when programs for the target can be built and observed on this machine (started by the session, unless <paramref name="attaches"/>).</summary>
public sealed class LiveTargetFactAttribute : FactAttribute
{
    public LiveTargetFactAttribute(string target, bool attaches = false)
    {
        if (LiveTarget.Of(target).Missing is { } reason) Skip = reason;
        else if (!attaches && LiveTarget.Musl) Skip = LiveTarget.MuslStart;
    }
}

/// <summary>Runs where the C library is musl and Linux x64 programs can be built and observed.</summary>
public sealed class MuslFactAttribute : FactAttribute
{
    public MuslFactAttribute()
    {
        if (LiveTarget.LinuxX64.Missing is { } reason) Skip = reason;
        else if (!LiveTarget.Musl) Skip = "The C library here is not musl.";
    }
}

/// <summary>Programs the session tests observe, in C that builds with MSVC and gcc.</summary>
internal static class LivePrograms
{
    private const string Platform = """
        #include <stdio.h>
        #include <stdlib.h>
        #ifdef _WIN32
        #include <windows.h>
        #define NOINLINE __declspec(noinline)
        static void Pause(int ms) { Sleep(ms); }
        static void Touch(const char* path)
        {
            HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
        #else
        #include <fcntl.h>
        #include <unistd.h>
        #include <pthread.h>
        #define NOINLINE __attribute__((noinline))
        static void Pause(int ms) { usleep(ms * 1000); }
        static void Touch(const char* path)
        {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) close(fd);
        }
        #endif

        """;

    /// <summary>
    /// orders [rounds] [pause ms] [discount]: AddLine once per round, then Discount when a third argument is given, then
    /// opens its own file and prints the line count.
    /// </summary>
    public const string Orders = Platform + """
        struct Order { int id; int lines; double total; };
        static volatile int g_sink;
        NOINLINE int AddLine(struct Order* o, int qty)
        {
            o->lines += 1;
            o->total += qty * 2.5;
            return o->lines;
        }
        NOINLINE int Discount(struct Order* o)
        {
            return o->lines > 10 ? 5 : 0;
        }
        int main(int argc, char** argv)
        {
            struct Order o = { 7, 0, 0.0 };
            int rounds = argc > 1 ? atoi(argv[1]) : 1000, pause = argc > 2 ? atoi(argv[2]) : 20;
            for (int i = 0; i < rounds; i++) { g_sink = AddLine(&o, i + 1); if (pause) Pause(pause); }
            if (argc > 3) g_sink += Discount(&o);
            Touch(argv[0]);
            printf("lines %d\n", o.lines);
            fflush(stdout);
            return 0;
        }
        """;

    public const int WorkerThreads = 16;

    /// <summary>
    /// workers [calls] [pause ms]: 16 threads each call Work that many times, then the program prints the sum of
    /// i % 7 over every call.
    /// </summary>
    public const string Workers = Platform + """
        #define THREADS 16
        static volatile long g_total[THREADS];
        static int g_calls, g_pause;
        NOINLINE long Work(int slot, int i)
        {
            g_total[slot] += i % 7;
            return g_total[slot];
        }
        #ifdef _WIN32
        static DWORD WINAPI Run(LPVOID p)
        #else
        static void* Run(void* p)
        #endif
        {
            int slot = (int)(size_t)p;
            for (int i = 0; i < g_calls; i++) { Work(slot, i); if (g_pause) Pause(g_pause); }
            return 0;
        }
        int main(int argc, char** argv)
        {
            g_calls = argc > 1 ? atoi(argv[1]) : 1000;
            g_pause = argc > 2 ? atoi(argv[2]) : 0;
        #ifdef _WIN32
            HANDLE threads[THREADS];
            for (int t = 0; t < THREADS; t++) threads[t] = CreateThread(NULL, 0, Run, (LPVOID)(size_t)t, 0, NULL);
            WaitForMultipleObjects(THREADS, threads, TRUE, INFINITE);
        #else
            pthread_t threads[THREADS];
            for (int t = 0; t < THREADS; t++) pthread_create(&threads[t], NULL, Run, (void*)(size_t)t);
            for (int t = 0; t < THREADS; t++) pthread_join(threads[t], NULL);
        #endif
            long sum = 0;
            for (int t = 0; t < THREADS; t++) sum += g_total[t];
            printf("total %ld\n", sum);
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>
    /// lifecycle [steps] [calls]: steps joined by '+'; "line" waits for a line on stdin, "sleep" pauses 10 minutes, then
    /// AddLine runs that many times (default 1000), the program prints the line count and ends: "fastexit" by _exit(3),
    /// "fault" by a write through a null pointer, "stuck" by returning 7 with a TLS callback that holds the exit forever
    /// and first creates hold-&lt;pid&gt; beside the program (MSVC), otherwise by returning 5.
    /// AtExit is registered with atexit.
    /// </summary>
    public const string Lifecycle = Platform + """
        #include <string.h>
        struct Order { int id; int lines; double total; };
        static volatile int g_sink, g_stuck;
        NOINLINE int AddLine(struct Order* o, int qty)
        {
            o->lines += 1;
            o->total += qty * 2.5;
            return o->lines;
        }
        NOINLINE void AtExit(void)
        {
            g_sink += 1;
        }
        #ifdef _MSC_VER
        static void NTAPI OnTls(PVOID h, DWORD reason, PVOID r)
        {
            if (reason != DLL_PROCESS_DETACH || !g_stuck) return;
            // hold-<pid> beside the program marks the hold entered; built by hand, as the C runtime has ended.
            char path[MAX_PATH + 32], digits[16];
            DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH), pid = GetCurrentProcessId();
            int d = 0;
            while (len > 0 && path[len - 1] != '\\') len--;
            memcpy(path + len, "hold-", 5);
            len += 5;
            do { digits[d++] = (char)('0' + pid % 10); pid /= 10; } while (pid);
            while (d) path[len++] = digits[--d];
            path[len] = 0;
            CloseHandle(CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL));
            for (;;) Sleep(10);
        }
        #ifdef _M_IX86
        #pragma comment(linker, "/INCLUDE:__tls_used")
        #pragma comment(linker, "/INCLUDE:_tls_callback")
        #else
        #pragma comment(linker, "/INCLUDE:_tls_used")
        #pragma comment(linker, "/INCLUDE:tls_callback")
        #endif
        #pragma const_seg(".CRT$XLB")
        EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback = OnTls;
        #pragma const_seg()
        #endif
        int main(int argc, char** argv)
        {
            const char* steps = argc > 1 ? argv[1] : "";
            int calls = argc > 2 ? atoi(argv[2]) : 1000;
            struct Order o = { 7, 0, 0.0 };
        #ifdef _WIN32
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        #endif
            atexit(AtExit);
            if (strstr(steps, "line")) { char line[16]; if (!fgets(line, sizeof line, stdin)) return 9; }
            if (strstr(steps, "sleep")) for (int i = 0; i < 6000; i++) Pause(100);
            for (int i = 0; i < calls; i++) g_sink = AddLine(&o, i + 1);
            printf("lines %d\n", o.lines);
            fflush(stdout);
            if (strstr(steps, "fastexit")) _exit(3);
            if (strstr(steps, "fault")) *(volatile int*)0 = o.lines;
            if (strstr(steps, "stuck")) { g_stuck = 1; return 7; }
            return 5;
        }
        """;

    /// <summary>
    /// values [rounds] [pause ms]: Show once per round with a 300-character string and its UTF-16 copy, then the count;
    /// a global of each scalar type.
    /// </summary>
    public const string Values = Platform + """
        #include <string.h>
        #ifdef _WIN32
        typedef wchar_t Text16;
        #else
        typedef unsigned short Text16;
        #endif
        int g_count = 42;
        double g_ratio = 2.5;
        float g_scale = 0.5f;
        long long g_big = -5000000000LL;
        unsigned char g_bytes[4] = { 1, 2, 3, 4 };
        static char g_text[301];
        static Text16 g_wide[301];
        NOINLINE int Show(const char* text, const Text16* wide, int round)
        {
            return (int)strlen(text) + wide[0] + round;
        }
        int main(int argc, char** argv)
        {
            int rounds = argc > 1 ? atoi(argv[1]) : 1, pause = argc > 2 ? atoi(argv[2]) : 0;
            for (int i = 0; i < 300; i++) { g_text[i] = (char)('a' + i % 26); g_wide[i] = (Text16)('A' + i % 26); }
            for (int i = 0; i < rounds; i++) { g_count += Show(g_text, g_wide, i) > 0; if (pause) Pause(pause); }
            if (g_ratio + g_scale + (double)g_big + g_bytes[0] == 0) puts("never");
            printf("count %d\n", g_count);
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>
    /// inrange start end (Windows, an image of over 2 MiB): commits a page in the first free 64 KiB block between the
    /// addresses, writes 7 there and passes it to Hold; when every block is in use it prints the range and exits 3.
    /// </summary>
    public const string InImageRange = Platform + """
        #include <stdint.h>
        static char g_pad[0x200000];
        NOINLINE int Hold(volatile int* p) { return *p; }
        int main(int argc, char** argv)
        {
            uintptr_t start = (uintptr_t)strtoull(argc > 1 ? argv[1] : "0", NULL, 16), end = (uintptr_t)strtoull(argc > 2 ? argv[2] : "0", NULL, 16);
            int* p = NULL;
            for (uintptr_t at = start; !p && at + 0x10000 <= end; at += 0x10000)
                p = (int*)VirtualAlloc((void*)at, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!p)
            {
                printf("no free 64 KiB block from 0x%llx to 0x%llx\n", (unsigned long long)start, (unsigned long long)end);
                fflush(stdout);
                return 3;
            }
            *p = 7;
            g_pad[0] = 1;
            printf("held %d\n", Hold(p));
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>plugin (a shared library): PluginWork and PluginOther, each returning twice its argument.</summary>
    public const string Plugin = """
        #ifdef _WIN32
        #define EXPORT __declspec(dllexport) __declspec(noinline)
        #else
        #define EXPORT __attribute__((visibility("default"), noinline))
        #endif
        EXPORT int PluginWork(int i) { return i * 2; }
        EXPORT int PluginOther(int i) { return i * 2; }
        """;

    /// <summary>
    /// plugin (Windows) whose DllMain writes PluginWork's code into an executable section the file leaves empty, as a packed
    /// DLL's start-up code does; PluginWork and PluginOther each return twice their argument.
    /// </summary>
    public const string CodeWrittenAtLoadPlugin = """
        #include <windows.h>
        #include <string.h>
        #pragma comment(linker, "/SECTION:.bss,ERW")
        __declspec(dllexport) unsigned char PluginWork[4096]; // uninitialized: no file bytes behind it
        __declspec(noinline) static int Twice(int i) { return i * 2; }
        __declspec(dllexport) __declspec(noinline) int PluginOther(int i) { return i * 2; }
        BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
        {
            if (reason == DLL_PROCESS_ATTACH) memcpy(PluginWork, (const void*)Twice, 64);
            return TRUE;
        }
        """;

    /// <summary>
    /// leaver (a Linux shared library): PluginWork(i) returns twice its argument below 3, else calls the static Finish, which
    /// exits with i through a noreturn call at its end; PluginOther returns twice its argument.
    /// </summary>
    public const string Leaver = """
        #include <stdio.h>
        #include <stdlib.h>
        #define EXPORT __attribute__((visibility("default"), noinline))
        static __attribute__((noinline, noreturn)) void Finish(int code) { printf("leaving %d\n", code); fflush(stdout); exit(code); }
        EXPORT int PluginWork(int i) { if (i < 3) return i * 2; Finish(i); }
        EXPORT int PluginOther(int i) { return i * 2; }
        """;

    /// <summary>children (Linux): prints "ready", reads a line, then prints how many SIGCHLD signals it received ("children N").</summary>
    public const string ChildSignals = """
        #include <signal.h>
        #include <stdio.h>
        #include <string.h>
        static volatile sig_atomic_t g_children;
        static void OnChild(int sig) { (void)sig; g_children++; }
        int main(void)
        {
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = OnChild;
            sa.sa_flags = SA_RESTART;
            sigaction(SIGCHLD, &sa, NULL);
            char line[16];
            printf("ready\n");
            fflush(stdout);
            if (!fgets(line, sizeof line, stdin)) return 9;
            printf("children %d\n", (int)g_children);
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>loader [library] [calls]: loads the library after a pause, calls PluginWork and PluginOther that many times, prints the sum.</summary>
    public const string Loader = Platform + """
        #ifndef _WIN32
        #include <dlfcn.h>
        #endif
        typedef int (*Fn)(int);
        int main(int argc, char** argv)
        {
            int calls = argc > 2 ? atoi(argv[2]) : 1;
            long total = 0;
            Pause(300);
        #ifdef _WIN32
            HMODULE lib = LoadLibraryA(argv[1]);
            Fn work = lib ? (Fn)GetProcAddress(lib, "PluginWork") : NULL, other = lib ? (Fn)GetProcAddress(lib, "PluginOther") : NULL;
        #else
            void* lib = dlopen(argv[1], RTLD_NOW);
            Fn work = lib ? (Fn)dlsym(lib, "PluginWork") : NULL, other = lib ? (Fn)dlsym(lib, "PluginOther") : NULL;
        #endif
            if (!work || !other) { printf("no plugin\n"); return 2; }
            for (int i = 0; i < calls; i++) total += work(i) + other(i);
            printf("plugin %ld\n", total);
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>
    /// delay-load (Windows): main asks shell32 for a known folder, which loads windows.storage.dll through shell32's
    /// delay-load import, then calls Ready and prints whether the folder was found.
    /// </summary>
    public const string DelayLoad = Platform + """
        #include <shlobj.h>
        #pragma comment(lib, "shell32.lib")
        #pragma comment(lib, "ole32.lib")
        NOINLINE int Ready(int i) { return i + 1; }
        int main(int argc, char** argv)
        {
            PWSTR path = NULL;
            int found = SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &path) == S_OK;
            CoTaskMemFree(path);
            int ready = Ready(1);
            printf("ready %d found %d\n", ready, found);
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>probe [arg] [seconds]: prints PROBE_MODE, PROBE_SECRET, its working folder and arguments, then waits; exits 3.</summary>
    public const string Probe = Platform + """
        #ifdef _WIN32
        #include <direct.h>
        #define getcwd _getcwd
        #endif
        int main(int argc, char** argv)
        {
            char cwd[4096];
            const char* mode = getenv("PROBE_MODE");
            const char* secret = getenv("PROBE_SECRET");
            printf("mode=%s\nsecret=%s\ncwd=%s\nargc=%d arg1=%s\n", mode ? mode : "(none)", secret ? secret : "(none)",
                getcwd(cwd, sizeof cwd) ? cwd : "?", argc, argc > 1 ? argv[1] : "");
            fflush(stdout);
            int seconds = argc > 2 ? atoi(argv[2]) : 0;
            for (int i = 0; i < seconds * 10; i++) Pause(100);
            return 3;
        }
        """;

    /// <summary>
    /// launcher [--restricted] [--parent pid] program [arguments]: starts the program as a child process (on Windows,
    /// under a restricted token with --restricted, and named the child of process pid with --parent, as a broker
    /// starts a process for another), waits for it, prints its exit code and returns it.
    /// </summary>
    public const string Launcher = Platform + """
        #include <string.h>
        #ifdef _WIN32
        #pragma comment(lib, "advapi32")
        /* A restricted copy of this process's token: only Everyone, Users, RESTRICTED and the logon session pass the
           second access check, as in a Chromium GPU process. */
        static HANDLE RestrictedToken(void)
        {
            HANDLE token, restricted = NULL;
            static BYTE groups[4096];
            DWORD size, count = 0;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) return NULL;
            if (!GetTokenInformation(token, TokenGroups, groups, sizeof groups, &size)) return NULL;
            SID_AND_ATTRIBUTES sids[4] = { 0 };
            SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY, nt = SECURITY_NT_AUTHORITY;
            AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &sids[count++].Sid);
            AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &sids[count++].Sid);
            AllocateAndInitializeSid(&nt, 1, SECURITY_RESTRICTED_CODE_RID, 0, 0, 0, 0, 0, 0, 0, &sids[count++].Sid);
            TOKEN_GROUPS* all = (TOKEN_GROUPS*)groups;
            for (DWORD i = 0; i < all->GroupCount && count < 4; i++)
                if (all->Groups[i].Attributes & SE_GROUP_LOGON_ID) sids[count++].Sid = all->Groups[i].Sid;
            CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, count, sids, &restricted);
            return restricted;
        }
        #else
        #include <sys/wait.h>
        #endif
        int main(int argc, char** argv)
        {
            int code, restricted = 0, parent = 0;
            for (; argc > 2 && strncmp(argv[1], "--", 2) == 0; argc--, argv++)
                if (strcmp(argv[1], "--restricted") == 0) restricted = 1;
                else if (strcmp(argv[1], "--parent") == 0) { parent = atoi(argv[2]); argc--; argv++; }
            if (argc < 2) return 2;
        #ifdef _WIN32
            char line[8192] = "";
            for (int i = 1; i < argc; i++) { strcat(line, "\""); strcat(line, argv[i]); strcat(line, "\" "); }
            STARTUPINFOEXA si = { { sizeof si } };
            PROCESS_INFORMATION pi;
            if (parent)
            {
                HANDLE named = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent);
                SIZE_T size = 0;
                InitializeProcThreadAttributeList(NULL, 1, 0, &size);
                si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
                InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
                UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &named, sizeof named, NULL, NULL);
            }
            HANDLE token = restricted ? RestrictedToken() : NULL;
            if (restricted && !token) { printf("no restricted token %lu\n", GetLastError()); return 2; }
            DWORD flags = parent ? EXTENDED_STARTUPINFO_PRESENT : 0;
            if (!(token ? CreateProcessAsUserA(token, NULL, line, NULL, NULL, FALSE, flags, NULL, NULL, &si.StartupInfo, &pi)
                        : CreateProcessA(NULL, line, NULL, NULL, FALSE, flags, NULL, NULL, &si.StartupInfo, &pi))) { printf("start failed %lu\n", GetLastError()); return 2; }
            DWORD status = 0;
            WaitForSingleObject(pi.hProcess, INFINITE);
            GetExitCodeProcess(pi.hProcess, &status);
            code = (int)status;
        #else
            pid_t pid = fork();
            if (pid == 0) { execv(argv[1], argv + 1); _exit(127); }
            int status = 0;
            waitpid(pid, &status, 0);
            code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
        #endif
            printf("child exited %d\n", code);
            fflush(stdout);
            return code;
        }
        """;

    /// <summary>
    /// selfstart [fork|spawn] [ms] (Linux): starts a copy of itself through /proc/self/exe, by fork and execv or by posix_spawn;
    /// the copy calls Tick every 10 ms for ms (default 200) and exits with 3, and the first prints the copy's exit code.
    /// </summary>
    public const string SelfStarter = Platform + """
        #include <string.h>
        #include <spawn.h>
        #include <sys/wait.h>
        extern char** environ;
        volatile int g_ticks;
        NOINLINE void Tick(int i) { g_ticks += i; }
        int main(int argc, char** argv)
        {
            if (argc > 1 && strcmp(argv[1], "copy") == 0)
            {
                for (int i = 0, n = (argc > 2 ? atoi(argv[2]) : 200) / 10; i < n; i++) { Tick(i); Pause(10); }
                exit(3);
            }
            char* args[] = { argv[0], "copy", argc > 2 ? argv[2] : NULL, NULL };
            pid_t pid;
            if (argc > 1 && strcmp(argv[1], "spawn") == 0) { if (posix_spawn(&pid, "/proc/self/exe", NULL, NULL, args, environ) != 0) return 2; }
            else if ((pid = fork()) == 0) { execv("/proc/self/exe", args); _exit(127); }
            int status = 0;
            waitpid(pid, &status, 0);
            printf("copy exited %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : 128);
            fflush(stdout);
            return 0;
        }
        """;

    /// <summary>What workers prints for <paramref name="calls"/> calls per thread.</summary>
    public static long WorkersTotal(int calls) => WorkerThreads * Enumerable.Range(0, calls).Sum(i => (long)(i % 7));

    /// <summary>The 1-based line of <paramref name="source"/> that contains <paramref name="text"/>.</summary>
    public static int Line(string source, string text) =>
        source.ReplaceLineEndings("\n").Split('\n').Select((l, i) => (l, i)).Single(x => x.l.Contains(text, StringComparison.Ordinal)).i + 1;
}
