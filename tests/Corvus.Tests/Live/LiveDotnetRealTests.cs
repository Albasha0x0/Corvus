using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Native.Providers.Live;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A .NET target the session tests build a console program for: its framework, runtime identifier and runtime.</summary>
internal sealed class DotnetTarget
{
    public static readonly DotnetTarget WinX64 = new("win-x64", "net10.0", null, windows: true, is64: true);
    // framework-dependent x86: the apphost finds the x86 runtime in its default folder
    public static readonly DotnetTarget WinX86 = new("win-x86", "net9.0", "win-x86", windows: true, is64: false);
    public static readonly DotnetTarget LinuxX64 = new("linux-x64", "net10.0", null, windows: false, is64: true);

    public string Name { get; }
    public string Framework { get; }
    public string? RuntimeIdentifier { get; }
    public bool Windows { get; }
    public bool Is64 { get; }
    private readonly Lazy<string?> _missing;

    private DotnetTarget(string name, string framework, string? rid, bool windows, bool is64)
    {
        Name = name;
        Framework = framework;
        RuntimeIdentifier = rid;
        Windows = windows;
        Is64 = is64;
        _missing = new(FindMissing);
    }

    public static DotnetTarget Of(string name) => new[] { WinX64, WinX86, LinuxX64 }.Single(t => t.Name == name);

    /// <summary>Why this target's program cannot be built and observed here; null when it can.</summary>
    public string? Missing => _missing.Value;

    private int Major => int.Parse(Framework[3..Framework.IndexOf('.')], CultureInfo.InvariantCulture);

    /// <summary>The OS file-open API the runtime calls for <c>File.ReadAllBytes</c>, as <c>module!export</c>.</summary>
    public string FileOpen => Windows ? "kernelbase!CreateFileW" : "libc.so.6!open";

    private string? FindMissing()
    {
        if (Windows ? !OperatingSystem.IsWindows() : !OperatingSystem.IsLinux()) return $"{Name} programs run on {(Windows ? "Windows" : "Linux")}.";
        if (new FridaBackend().Unavailable() is { } frida) return frida.Reason;
        if (!Windows && LiveTarget.Musl) return LiveTarget.MuslStart;
        var (code, sdks) = Tools.Dotnet(null, "--list-sdks");
        if (code != 0 || !Regex.Matches(sdks, @"(?m)^(\d+)\.").Any(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) >= Major))
            return $"No .NET SDK that builds {Framework}.";
        if (RuntimeIdentifier == "win-x86")
        {
            var shared = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "dotnet", "shared", "Microsoft.NETCore.App");
            return Directory.Exists(shared) && Directory.EnumerateDirectories(shared, $"{Major}.*").Any() ? null : $"No x86 .NET {Major} runtime in {shared}.";
        }
        var (_, runtimes) = Tools.Dotnet(null, "--list-runtimes");
        return runtimes.Contains($"Microsoft.NETCore.App {Major}.", StringComparison.Ordinal) ? null : $"No .NET {Major} runtime.";
    }

    /// <summary>Builds <see cref="LiveDotnetRealTests.Readers"/> in <paramref name="dir"/>; returns the program's apphost.</summary>
    public string Build(TempDir dir)
    {
        // the folder's own (empty) build files keep a parent folder's out of the build
        File.WriteAllText(dir.File("Directory.Build.props"), "<Project />");
        File.WriteAllText(dir.File("Directory.Build.targets"), "<Project />");
        File.WriteAllText(dir.File("readers.csproj"), $"""
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>{Framework}</TargetFramework>
                {(RuntimeIdentifier != null ? $"<RuntimeIdentifier>{RuntimeIdentifier}</RuntimeIdentifier><SelfContained>false</SelfContained>" : "")}
                <ImplicitUsings>enable</ImplicitUsings>
              </PropertyGroup>
            </Project>
            """);
        File.WriteAllText(dir.File("Program.cs"), LiveDotnetRealTests.Readers);
        var (code, log) = Tools.Dotnet(dir.Path, "build", "-c", "Release", "-o", "out", "-nologo");
        var exe = dir.File(Path.Combine("out", Windows ? "readers.exe" : "readers"));
        Assert.True(code == 0 && File.Exists(exe), log);
        return exe;
    }

    /// <summary>
    /// Sets DOTNET_ROOT for the in-process server while the runtime is outside its default folders (an SDK installed
    /// per user): the apphost of a started program looks there. Restores the variable on dispose.
    /// </summary>
    public IDisposable RuntimeRoot()
    {
        var saved = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        if (Windows || saved != null) return new Restore(null, null);
        var dotnet = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Select(d => Path.Combine(d, "dotnet")).FirstOrDefault(File.Exists);
        if (dotnet == null) return new Restore(null, null);
        var root = Path.GetDirectoryName(new FileInfo(dotnet).ResolveLinkTarget(true)?.FullName ?? dotnet)!;
        if (root is "/usr/share/dotnet" or "/usr/lib/dotnet" or "/usr/lib64/dotnet") return new Restore(null, null);
        Environment.SetEnvironmentVariable("DOTNET_ROOT", root);
        return new Restore("DOTNET_ROOT", saved);
    }

    private sealed class Restore(string? variable, string? value) : IDisposable
    {
        public void Dispose()
        {
            if (variable != null) Environment.SetEnvironmentVariable(variable, value);
        }
    }

    public override string ToString() => Name;
}

/// <summary>Runs when the target's .NET program can be built and observed on this machine.</summary>
public sealed class DotnetTargetFactAttribute : FactAttribute
{
    public DotnetTargetFactAttribute(string target)
    {
        if (DotnetTarget.Of(target).Missing is { } reason) Skip = reason;
    }
}

/// <summary>
/// Sessions on a .NET console program per target (Windows x64 on .NET 10, Windows x86 on .NET 9, Linux x64 on .NET 10):
/// started suspended, the OS file-open API watched and stopped on with the managed callers in the stack, a snapshot read
/// with dump_stack, the program run to its exit code, and close ending a started program.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Collection(LiveSessions.Collection)]
public sealed class LiveDotnetRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>
    /// readers path threads rounds pause: each thread reads the file once per round with a pause (ms) between, then the
    /// program prints the bytes read and the opens.
    /// </summary>
    internal const string Readers = """
        using System.Runtime.CompilerServices;

        static class Readers
        {
            static long s_bytes;

            static int Main(string[] args)
            {
                string path = args[0];
                int threads = int.Parse(args[1]), rounds = int.Parse(args[2]), pause = int.Parse(args[3]);
                var all = new Thread[threads];
                for (int t = 0; t < threads; t++)
                {
                    all[t] = new Thread(() => ReadLoop(path, rounds, pause)) { Name = "reader-" + t };
                    all[t].Start();
                }
                foreach (var t in all) t.Join();
                Console.WriteLine($"read {Interlocked.Read(ref s_bytes)} bytes in {threads * rounds} opens");
                return 0;
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            static void ReadLoop(string path, int rounds, int pause)
            {
                for (int i = 0; i < rounds; i++)
                {
                    ReadOnce(path);
                    Thread.Sleep(pause);
                }
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            static void ReadOnce(string path) => Interlocked.Add(ref s_bytes, File.ReadAllBytes(path).Length);
        }
        """;

    private const string InputName = "readers-input.txt";

    [DotnetTargetFact("win-x64")] public Task Dotnet_program_on_win_x64() => ReadersProgram(DotnetTarget.WinX64);
    [DotnetTargetFact("win-x86")] public Task Dotnet_program_on_win_x86() => ReadersProgram(DotnetTarget.WinX86);
    [DotnetTargetFact("linux-x64")] public Task Dotnet_program_on_linux_x64() => ReadersProgram(DotnetTarget.LinuxX64);

    private async Task ReadersProgram(DotnetTarget target)
    {
        var exe = target.Build(_dir);
        var input = _dir.File(InputName);
        File.WriteAllText(input, new string('x', 1000));
        const int threads = 4, rounds = 400;
        using var root = target.RuntimeRoot();
        await using var server = await Server();

        var pid = await Spawn(server, exe, "live-1", input, $"{threads}", $"{rounds}", "20");
        Assert.Contains("w1", await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = target.FileOpen, ["rateLimit"] = 100_000 }));
        Assert.Contains("program started", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        var opened = new Regex(Regex.Escape(InputName) + "\"");
        string opens = "";
        for (int i = 0; i < 300 && !opened.IsMatch(opens); i++)
        {
            opens = await Events(server, "live-1", from: "w1", log: false);
            await Task.Delay(100);
        }
        if (!opened.IsMatch(opens)) Assert.Fail($"no open of {InputName}:\n{opens}\n{await Events(server, "live-1", log: false)}");

        // a stop at the file-open API, on a call that opens the input file
        Assert.Contains("s1 set", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = target.FileOpen }));
        string stop = "", thread = "";
        for (int i = 0; i < 50; i++)
        {
            stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = i == 0 ? "list" : "continue", ["wait"] = true, ["waitSeconds"] = 60 });
            thread = Regex.Match(stop, @"thread (\d+) stopped at s1").Groups[1].Value;
            Assert.False(thread.Length == 0, stop);
            if ((await PathArgument(server, target, thread)).Contains(InputName, StringComparison.Ordinal)) break;
            thread = "";
        }
        Assert.False(thread.Length == 0, "no stop on an open of the input file in 50 stops");
        // native frames by module and export; the managed caller named by the runtime (x64), else as the runtime library's precompiled code or JIT code outside every module
        var api = target.Windows ? @"KERNELBASE\.dll!CreateFileW" : @"libc\.so\.6!(?:__libc_)?open(?:64)?\b"; // glibc exports open and its aliases at one address
        var caller = !target.Windows ? @"libSystem\.Native\.so!SystemNative_Open\S*"
            : target.Is64 ? @"System\.Private\.CoreLib\.dll!\S.*\(.*\)\+0x[0-9A-F]+" : @"System\.Private\.CoreLib\.dll\+0x[0-9A-F]+|0x\k<b>";
        // a frame with debug information ends in its source file and line
        Assert.Matches($@"thread {thread} stopped at s1 \({api}\)\r?\n  #0 0x[0-9A-F]+ {api}(?:  \S+:\d+)?\r?\n  #1 0x(?<b>[0-9A-F]+) ({caller})(?:  \S+:\d+)?\r?\n", stop);

        Assert.Contains("s1 cleared", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" }));
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });

        // a snapshot of the running program; the stopped thread is still in its read loop. gcore is not the program's parent.
        if (Corvus.Native.Live.PtraceScope.Refusing(started: false) is { } scope)
            Assert.Contains($"ptrace_scope is {scope}", await Refused(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" }, "access_denied"));
        else await Snapshot(server, target, thread);

        var exited = await Exited(server, "live-1", pid);
        Assert.Matches(@"exit code 0(?![0-9xX])", exited);
        await Task.Delay(500); // the last batch
        const int total = threads * rounds;
        Assert.Contains($"read {total * 1000} bytes in {total} opens", await Events(server, "live-1", kind: "output"));
        var watched = await Events(server, "live-1", from: "w1", log: false);
        Assert.Equal(total, opened.Count(watched));
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
        Ended(pid);

        // close ends a program the session started
        var pid2 = await Spawn(server, exe, "live-2", input, "2", "100000", "20");
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        await Task.Delay(2_000);
        Assert.Contains($"pid {pid2}, running", await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-2" }));
        Assert.Contains($"pid {pid2}, closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" }));
        Ended(pid2);

        // a return address is never the entry of the function stopped at
        var entry = Regex.Match(stop, @"#0 (0x[0-9A-F]+) ").Groups[1].Value;
        Assert.DoesNotMatch($@"#[1-9]\d* {entry} ", stop);
    }

    /// <summary>A stop at a JIT-compiled method by name, deferred until the runtime compiles it; the stack names the managed frames.</summary>
    [DotnetTargetFact("win-x64")]
    public async Task Managed_stop_point_on_win_x64()
    {
        var exe = DotnetTarget.WinX64.Build(_dir);
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        await using var server = await Server();
        await Spawn(server, exe, "live-1", input, "1", "100000", "20");
        // a name the assembly does not define fails when set, before the assembly loads
        await Refused(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "readers.dll!Readers::ReadTwice" }, "not_found");
        Assert.Contains("deferred until readers.dll loads", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Readers::ReadOnce" }));
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches(@"stopped at s1 \(readers\.dll!Readers\.ReadOnce\(System\.String\)\)\r?\n  #0 0x[0-9A-F]+ readers\.dll!Readers\.ReadOnce\(System\.String\)\r?\n" +
                       @"  #1 0x[0-9A-F]+ readers\.dll!Readers\.ReadLoop\(System\.String, Int32, Int32\)\+0x[0-9A-F]+\r?\n", stop);
        Assert.Contains("compiled", await Events(server, "live-1", kind: "module"));
        await Refused(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Readers::ReadTwice" }, "not_found");
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
    }

    /// <summary>Saves a snapshot of the running program and reads its stacks.</summary>
    private async Task Snapshot(InProcessServer server, DotnetTarget target, string thread)
    {
        var snapshot = await Ok(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" });
        var dump = Regex.Match(snapshot, @"written to (.+?) \(([\d,]+) bytes\), opened as (\S+);");
        Assert.True(dump.Success, snapshot);
        try
        {
            var stack = await Ok(server, "dump_stack", new() { ["dump"] = dump.Groups[3].Value, ["thread"] = thread });
            var main = await Ok(server, "dump_stack", new() { ["dump"] = dump.Groups[3].Value, ["thread"] = "#0" });
            if (target.Windows && target.Is64)
            {
                // the runtime's DAC names the managed frames
                Assert.Contains($"thread {thread} \"reader-", stack);
                Assert.Contains("managed frames: decoded", stack);
                Assert.Matches(@"readers!Readers\.ReadLoop\(System\.String, Int32, Int32\) \[clr\] 0x06000002 IL_[0-9A-F]+  managed, clr", stack);
                Assert.Matches(@"readers!Readers\.Main\(System\.String\[\]\) \[clr\] 0x06000001 IL_[0-9A-F]+  managed, clr", main);
            }
            else if (target.Windows)
            {
                // an x86 runtime's DAC does not load in this 64-bit process: managed frames are found by their frame pointers, unnamed
                Assert.Contains("managed frames: bitness_mismatch", stack);
                Assert.Matches(@"#\d+ 0x[0-9A-F]+ \?  managed, frame_pointer", stack);
                Assert.Contains("kernel32!BaseThreadInitThunk", stack);
            }
            else Output.WriteLine(stack + "\n" + main); // a Linux core's stacks are shown, not yet checked
        }
        finally { File.Delete(dump.Groups[1].Value); }
    }

    /// <summary>Waits for the program's exit; on a timeout writes what its threads wait on and the session's last events.</summary>
    private async Task<string> Exited(InProcessServer server, string session, int pid)
    {
        try { return await UntilExited(server, session); }
        catch (Xunit.Sdk.XunitException)
        {
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                Output.WriteLine($"process {pid}: cpu {p.TotalProcessorTime}, threads " + string.Join(", ", p.Threads.Cast<System.Diagnostics.ProcessThread>()
                    .Select(t => $"{t.Id} {t.ThreadState}{(t.ThreadState == System.Diagnostics.ThreadState.Wait ? "/" + t.WaitReason : "")}")));
            }
            catch (ArgumentException) { Output.WriteLine($"process {pid} has ended"); }
            Output.WriteLine("last events:\n" + string.Join('\n', (await Events(server, session, log: false)).Split('\n').TakeLast(40)));
            throw;
        }
    }

    /// <summary>The path argument of the file-open call the thread is stopped at.</summary>
    private async Task<string> PathArgument(InProcessServer server, DotnetTarget target, string thread)
    {
        string pointer = target.Windows ? (target.Is64 ? "rcx" : "") : "rdi";
        if (pointer.Length == 0)
        {
            // x86: at the entry, [esp] is the return address and [esp+4] the first argument
            var stack = await Ok(server, "live_read", new() { ["session"] = "live-1", ["thread"] = thread, ["memory"] = "esp", ["type"] = "uint32[2]" });
            var value = Regex.Match(stack, @"\[1\] (0x[0-9A-Fa-f]+|\d+)").Groups[1].Value;
            Assert.False(string.IsNullOrEmpty(value), stack);
            pointer = value.StartsWith("0x", StringComparison.Ordinal) ? value : $"0x{ulong.Parse(value, CultureInfo.InvariantCulture):X}";
        }
        return await Ok(server, "live_read", new() { ["session"] = "live-1", ["thread"] = thread, ["memory"] = pointer, ["type"] = target.Windows ? "utf16" : "cstring", ["length"] = 1024 });
    }
}
