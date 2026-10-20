using System.Diagnostics;
using Corvus.Native.Providers.Live;

namespace Corvus.Tests;

/// <summary>A target the session tests build programs for: Windows with MSVC or Linux with gcc, 64- or 32-bit.</summary>
internal sealed class LiveTarget
{
    public static readonly LiveTarget WinX64 = new("win-x64", windows: true, is64: true);
    public static readonly LiveTarget WinX86 = new("win-x86", windows: true, is64: false);
    public static readonly LiveTarget LinuxX64 = new("linux-x64", windows: false, is64: true);
    public static readonly LiveTarget LinuxX86 = new("linux-x86", windows: false, is64: false);

    public string Name { get; }
    public bool Windows { get; }
    public bool Is64 { get; }
    private readonly Lazy<string?> _missing;

    private LiveTarget(string name, bool windows, bool is64)
    {
        Name = name;
        Windows = windows;
        Is64 = is64;
        _missing = new(FindMissing);
    }

    public static LiveTarget Of(string name) => new[] { WinX64, WinX86, LinuxX64, LinuxX86 }.Single(t => t.Name == name);

    /// <summary>Why this target's programs cannot be built and observed here; null when they can.</summary>
    public string? Missing => _missing.Value;

    public string Exe(string name) => Windows ? name + ".exe" : name;

    /// <summary>The register holding the first integer argument at a function's entry; null where it is on the stack (x86).</summary>
    public string? FirstArgument => !Is64 ? null : Windows ? "rcx" : "rdi";

    /// <summary>The module that exports the C library's file open: <c>module!name</c> for a watch.</summary>
    public string FileOpen => Windows ? "kernelbase!CreateFileA" : "libc.so.6!open";

    private string? FindMissing()
    {
        if (Windows != OperatingSystem.IsWindows()) return $"{Name} programs run on {(Windows ? "Windows" : "Linux")}.";
        if (!Windows && !OperatingSystem.IsLinux()) return $"{Name} programs run on Linux.";
        if (new FridaBackend().Unavailable() is { } frida) return frida.Reason;
        if (Windows) return VisualStudio.VcVarsAll() == null ? "No Visual Studio C++ toolset." : null;
        using var dir = new TempDir();
        File.WriteAllText(dir.File("probe.c"), "#include <pthread.h>\nint main(void){return 0;}\n");
        var (code, log) = Tools.Run(Gcc(dir, "probe"));
        return code == 0 ? null : $"gcc cannot build {Name} programs here ({(Is64 ? "" : "gcc-multilib, ")}{log.Trim().Split('\n')[^1]}).";
    }

    /// <summary>Compiles <paramref name="source"/> into <c>name</c>(.exe) in <paramref name="dir"/>, unoptimized with full debug information.</summary>
    public string Build(TempDir dir, string name, string source)
    {
        File.WriteAllText(dir.File(name + ".c"), source);
        var (code, log) = Tools.Run(Windows ? Msvc(dir, name) : Gcc(dir, name), 300_000);
        Assert.True(code == 0 && File.Exists(dir.File(Exe(name))), log);
        return dir.File(Exe(name));
    }

    private ProcessStartInfo Msvc(TempDir dir, string name) => new("cmd.exe")
    {
        WorkingDirectory = dir.Path,
        Arguments = $"/s /c \"\"{VisualStudio.VcVarsAll()}\" {(Is64 ? "x64" : "x86")} >nul && cl /nologo /Od /Zi {name}.c /link /DEBUG:FULL /INCREMENTAL:NO /OUT:{name}.exe\"",
    };

    private ProcessStartInfo Gcc(TempDir dir, string name)
    {
        var psi = new ProcessStartInfo("gcc") { WorkingDirectory = dir.Path };
        foreach (var a in new[] { "-g", "-O0", "-fno-omit-frame-pointer", Is64 ? "-m64" : "-m32", "-o", name, name + ".c", "-lpthread" }) psi.ArgumentList.Add(a);
        return psi;
    }

    public override string ToString() => Name;
}

/// <summary>Runs when programs for the target can be built and observed on this machine.</summary>
public sealed class LiveTargetFactAttribute : FactAttribute
{
    public LiveTargetFactAttribute(string target)
    {
        if (LiveTarget.Of(target).Missing is { } reason) Skip = reason;
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

    /// <summary>What workers prints for <paramref name="calls"/> calls per thread.</summary>
    public static long WorkersTotal(int calls) => WorkerThreads * Enumerable.Range(0, calls).Sum(i => (long)(i % 7));

    /// <summary>The 1-based line of <paramref name="source"/> that contains <paramref name="text"/>.</summary>
    public static int Line(string source, string text) =>
        source.ReplaceLineEndings("\n").Split('\n').Select((l, i) => (l, i)).Single(x => x.l.Contains(text, StringComparison.Ordinal)).i + 1;
}
