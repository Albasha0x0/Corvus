using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Native.Providers.Live;
using Corvus.Services;
using Microsoft.Extensions.DependencyInjection;
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
        // The x64 builds take the SDK's own architecture, which on an arm64
        // machine is arm64.
        if (Is64 && System.Runtime.InteropServices.RuntimeInformation.OSArchitecture != System.Runtime.InteropServices.Architecture.X64) return $"{Name} programs are built on an x64 machine.";
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

    /// <summary>Builds <see cref="LiveDotnetRealTests.Readers"/> (or <paramref name="source"/>) in <paramref name="dir"/>; returns the program's apphost, or its single-file bundle (ReadyToRun on request).</summary>
    public string Build(TempDir dir, bool singleFile = false, bool readyToRun = false, string? source = null)
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
        File.WriteAllText(dir.File("Program.cs"), source ?? LiveDotnetRealTests.Readers);
        var (code, log) = singleFile
            ? Tools.Dotnet(dir.Path, "publish", "-c", "Release", "-r", RuntimeIdentifier ?? Name, "--self-contained", "false", "-p:PublishSingleFile=true", $"-p:PublishReadyToRun={readyToRun}", "-o", "out", "-nologo")
            : Tools.Dotnet(dir.Path, "build", "-c", "Release", "-o", "out", "-nologo");
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

/// <summary>Runs when the target's program can be built and observed and CORVUS_SNAPSHOT_RUNS is set.</summary>
public sealed class SnapshotRunsFactAttribute : FactAttribute
{
    public SnapshotRunsFactAttribute(string target)
    {
        if (DotnetTarget.Of(target).Missing is { } reason) Skip = reason;
        else if (LiveDotnetRealTests.SnapshotRuns == 0) Skip = "Set CORVUS_SNAPSHOT_RUNS to the number of runs.";
    }
}

/// <summary>Runs on Windows x64 with Frida, the .NET Framework 4.8 reference assemblies and a native image (NGEN) of System.dll.</summary>
public sealed class FrameworkNativeImageFactAttribute : FactAttribute
{
    public FrameworkNativeImageFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || System.Runtime.InteropServices.RuntimeInformation.OSArchitecture != System.Runtime.InteropServices.Architecture.X64) Skip = "Windows x64 only.";
        else if (new FridaBackend().Unavailable() is { } frida) Skip = frida.Reason;
        else if (!Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "assembly", "NativeImages_v4.0.30319_64", "System")))
            Skip = "No native image of System.dll.";
    }
}

/// <summary>
/// Sessions on a .NET console program per target (Windows x64 on .NET 10, Windows x86 on .NET 9, Linux x64 on .NET 10):
/// started suspended, the OS file-open API watched and stopped on with the managed callers in the stack, a snapshot read
/// with dump_stack, the program run to its exit code, and close ending a started program.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
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
        var input = ReadersInput();
        using var root = target.RuntimeRoot();
        await using var server = await Server();

        var stop = await SnapshotRun(server, target, exe, input);

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

    /// <summary>The number of runs of the snapshot loop (CORVUS_SNAPSHOT_RUNS); 0 when unset.</summary>
    internal static int SnapshotRuns => int.TryParse(Environment.GetEnvironmentVariable("CORVUS_SNAPSHOT_RUNS"), out var n) ? Math.Max(n, 0) : 0;

    /// <summary>
    /// The snapshot run repeated CORVUS_SNAPSHOT_RUNS times, each on a new
    /// server: after each snapshot the program finishes every open and exits
    /// with code 0. Opt-in: set CORVUS_SNAPSHOT_RUNS (such as 30) with the full
    /// set (CORVUS_ALL_TESTS=1). Regression: a program once stayed running
    /// 2 minutes after a snapshot (1 in 6 runs).
    /// </summary>
    [SnapshotRunsFact("win-x64")] public Task A_dotnet_program_exits_after_every_repeated_snapshot_on_win_x64() => RepeatedSnapshots(DotnetTarget.WinX64);
    [SnapshotRunsFact("win-x86")] public Task A_dotnet_program_exits_after_every_repeated_snapshot_on_win_x86() => RepeatedSnapshots(DotnetTarget.WinX86);
    [SnapshotRunsFact("linux-x64")] public Task A_dotnet_program_exits_after_every_repeated_snapshot_on_linux_x64() => RepeatedSnapshots(DotnetTarget.LinuxX64);

    private async Task RepeatedSnapshots(DotnetTarget target)
    {
        var exe = target.Build(_dir);
        var input = ReadersInput();
        using var root = target.RuntimeRoot();
        for (int run = 1; run <= SnapshotRuns; run++)
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            await using (var server = await Server()) await SnapshotRun(server, target, exe, input);
            Output.WriteLine($"run {run} of {SnapshotRuns}: exit code 0, every open done ({clock.Elapsed.TotalSeconds:F0} s)");
        }
    }

    private string ReadersInput()
    {
        var input = _dir.File(InputName);
        File.WriteAllText(input, new string('x', 1000));
        return input;
    }

    /// <summary>
    /// Starts the program in session live-1, stops at a file open of the
    /// input, snapshots it while it runs, then checks that it finishes every
    /// open and exits with code 0; closes the session. Returns the stop's stack.
    /// </summary>
    private async Task<string> SnapshotRun(InProcessServer server, DotnetTarget target, string exe, string input)
    {
        const int threads = 4, rounds = 400;
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
        // native frames by module and export; the managed caller named by the runtime (on x86 read by the 32-bit decoder process)
        // The caller's offset is within its method: a start read from another
        // version of the method's code gave offsets past 0x10000. A frame in
        // code a JIT tier has since replaced has no start the runtime reads
        // give (ClrMD 3.1 describes a method's current code only, see
        // microsoft/clrmd#1171), so its offset is reported unknown.
        // glibc exports open and its aliases at one address.
        var api = target.Windows ? @"KERNELBASE\.dll!CreateFileW" : @"libc\.so\.6!(?:__libc_|__)?open(?:64)?\b";
        var caller = !target.Windows ? @"libSystem\.Native\.so!SystemNative_Open\S*"
            : @"System\.Private\.CoreLib\.dll!\S.*\(.*\)(?:\+0x[0-9A-F]{1,4}| \(offset unknown\))";
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
        return stop;
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
        // a snapshot at the stop: the runtime walks the held thread from the stop, not from where the backend holds it
        var snapshot = await Ok(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" });
        var dump = Regex.Match(snapshot, @"written to (.+?) \([\d,]+ bytes\), opened as (\S+);");
        try
        {
            var stack = await Ok(server, "dump_stack", new() { ["dump"] = dump.Groups[2].Value, ["thread"] = Regex.Match(stop, @"thread (\d+) stopped").Groups[1].Value });
            Assert.Matches(@"#0 0x[0-9A-F]+ readers!Readers\.ReadOnce\(System\.String\) \[clr\] 0x06000003", stack);
        }
        finally { File.Delete(dump.Groups[1].Value); }
        await Refused(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Readers::ReadTwice" }, "not_found");
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
    }

    /// <summary>Methods called once stop at that call: Main, set before the program starts, and a method compiled later.</summary>
    [DotnetTargetFact("win-x64")]
    public async Task First_calls_of_JIT_compiled_methods_stop_on_win_x64()
    {
        var exe = DotnetTarget.WinX64.Build(_dir);
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        await using var server = await Server();
        var pid = await Spawn(server, exe, "live-1", input, "1", "1", "0");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Readers::Main" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Readers::ReadOnce" });
        var main = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches(@"stopped at s1 \(readers\.dll!Readers\.Main\(System\.String\[\]\)\)", main);
        var once = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches(@"stopped at s2 \(readers\.dll!Readers\.ReadOnce\(System\.String\)\)\r?\n  #0 0x[0-9A-F]+ readers\.dll!Readers\.ReadOnce\(System\.String\)\r?\n", once);
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await Exited(server, "live-1", pid));
        Assert.Contains("read 1 bytes in 1 opens", await Events(server, "live-1", kind: "output"));
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
    }

    /// <summary>
    /// A stop point set on a method's first JIT version keeps stopping once the runtime compiles it again (tiered
    /// compilation); a compile for a running loop (on-stack replacement) adds no stop mid-method.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Stop_points_follow_recompiled_methods_on_win_x64()
    {
        var exe = DotnetTarget.WinX64.Build(_dir);
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        await using var server = await Server();
        await Spawn(server, exe, "live-1", input, "1", "100000", "5");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Readers::ReadOnce" });
        // every call stops: past the call count after which the runtime compiles the method again, and three calls more
        int after = -1;
        for (int i = 0; i < 200 && after < 3; i++)
        {
            var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 30 });
            // A missed stop names the modules the session saw, where s1 was set and any error binding it.
            if (!stop.Contains("stopped at s1", StringComparison.Ordinal))
                Assert.Fail($"{stop}\nafter {i} stops; module events:\n{await Events(server, "live-1", kind: "module", log: false)}\nerrors:\n{await Events(server, "live-1", kind: "error", log: false)}");
            if (after >= 0 || (await Events(server, "live-1", kind: "module", log: false)).Contains("s1 also set at", StringComparison.Ordinal)) after++;
        }
        Assert.Equal(3, after);
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));

        var pid = await Spawn(server, exe, "live-2", input, "1", "20000", "0");
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "set", ["at"] = "Readers::ReadLoop" });
        var first = await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        // A missed stop on the method entered once lists the session's events, which order s1's bind among the loads.
        if (!first.Contains("stopped at s1", StringComparison.Ordinal))
            Assert.Fail($"{first}\nevents:\n{await Events(server, "live-2", log: false)}");
        Assert.Contains("the program ended before a stop", await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
        Assert.DoesNotContain("also set at", await Events(server, "live-2", kind: "module"));
        Ended(pid);
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" }));
    }

    /// <summary>
    /// A runtime whose DAC is on no local path (a copy of the runtime without one, its build stamp changed) is read only
    /// when the session was opened with downloadDac=true; the download is refused under CORVUS_OFFLINE=1.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Dac_download_is_opted_in_per_session_on_win_x64()
    {
        // It sets CORVUS_OFFLINE for the process, so it runs in a process of its own.
        if (ChildTest.Rerun(this, Output)) return;
        var exe = DotnetTarget.WinX64.Build(_dir);
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        var shared = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var root = Directory.GetParent(shared)!.Parent!.Parent!.FullName;
        var copy = _dir.File("dotnet");
        var runtime = Path.Combine(copy, "shared", "Microsoft.NETCore.App", Path.GetFileName(shared));
        foreach (var f in Directory.EnumerateFiles(shared).Where(f => !Path.GetFileName(f).StartsWith("mscordac", StringComparison.OrdinalIgnoreCase)))
            File.Copy(f, Path.Combine(Directory.CreateDirectory(runtime).FullName, Path.GetFileName(f)));
        var fxr = Directory.EnumerateDirectories(Path.Combine(root, "host", "fxr")).OrderBy(d => Version.Parse(Path.GetFileName(d).Split('-')[0])).Last();
        File.Copy(Path.Combine(fxr, "hostfxr.dll"), Path.Combine(Directory.CreateDirectory(Path.Combine(copy, "host", "fxr", Path.GetFileName(fxr))).FullName, "hostfxr.dll"));
        using (var coreclr = File.Open(Path.Combine(runtime, "coreclr.dll"), FileMode.Open, FileAccess.ReadWrite))
        {
            var pe = new byte[4];
            coreclr.Position = 0x3C;
            coreclr.ReadExactly(pe);
            coreclr.Position = BitConverter.ToInt32(pe) + 8; // the COFF header's TimeDateStamp
            coreclr.Write(BitConverter.GetBytes(0x12345678));
        }
        using var env = new EnvironmentScope().Set("CORVUS_OFFLINE", "1");
        await using var server = await Server();
        string[] variables = [$"DOTNET_ROOT={copy}", $"DOTNET_ROOT_X64={copy}"];
        foreach (var (download, reason) in new[] { (false, "not_found"), (true, "download_refused_offline") })
        {
            var id = download ? "live-2" : "live-1";
            var opened = await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { input, "1", "100000", "20" }, ["environment"] = variables, ["downloadDac"] = download });
            Assert.Contains(id, opened);
            await Ok(server, "live_break", new() { ["session"] = id, ["action"] = "continue" });
            // a point set while the runtime cannot be read names the reason, and waits for the JIT's compile
            var set = "";
            for (int i = 0; i < 100 && !set.Contains("cannot be read", StringComparison.Ordinal); i++)
            {
                await Task.Delay(100);
                set = (await Call(server, "live_break", new() { ["session"] = id, ["action"] = "set", ["at"] = "Readers::ReadOnce" })).Text;
            }
            Assert.True(set.Contains($"cannot be read: {reason}", StringComparison.Ordinal), set +"\n" + await Events(server, id, kind: "module"));
            Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = id }));
        }
    }

    /// <summary>A stop by name in an assembly bundled into a single-file program, which never loads as a module of its own.</summary>
    [DotnetTargetFact("win-x64")]
    public async Task Managed_stop_point_in_a_single_file_program_on_win_x64()
    {
        var exe = DotnetTarget.WinX64.Build(_dir, singleFile: true);
        Assert.False(File.Exists(Path.ChangeExtension(exe, ".dll")));
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        await using var server = await Server();
        await Spawn(server, exe, "live-1", input, "1", "100000", "20");
        await Refused(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "readers.dll!Readers::ReadTwice" }, "not_found");
        Assert.Contains("is compiled", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "readers.dll!Readers::ReadOnce" }));
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        // A missed stop names the modules the session saw, where s1 was set and any error binding it.
        if (!stop.Contains("stopped at s1", StringComparison.Ordinal))
            Assert.Fail($"{stop}\nmodule events:\n{await Events(server, "live-1", kind: "module", log: false)}\nstop events:\n{await Events(server, "live-1", kind: "stop", log: false)}\nerrors:\n{await Events(server, "live-1", kind: "error", log: false)}");
        Assert.Matches(@"stopped at s1 \(readers\.dll!Readers\.ReadOnce\(System\.String\)\)\r?\n  #0 0x[0-9A-F]+ readers\.dll!Readers\.ReadOnce\(System\.String\)\r?\n", stop);
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
    }

    /// <summary>
    /// A stop at ReadyToRun code of an assembly the runtime maps from a single-file bundle: a mapped file view, not an
    /// image, which the backend's hooks cannot write. It stops twice, is cleared, then a watch there records calls, and the method still runs.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Stop_point_in_a_mapped_code_view_on_win_x64()
    {
        var exe = DotnetTarget.WinX64.Build(_dir, singleFile: true, readyToRun: true);
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        await using var server = await Server();
        await Spawn(server, exe, "live-1", input, "1", "100000", "20");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "readers.dll!Readers::ReadOnce" });
        for (int round = 0; round < 2; round++)
            Assert.Matches(@"stopped at s1 \(readers\.dll!Readers\.ReadOnce\(System\.String\)\)",
                await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
        Assert.Contains("cleared", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" }));
        await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "readers.dll!Readers::ReadOnce" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        string calls = "";
        for (int i = 0; i < 50 && !calls.Contains(" call ", StringComparison.Ordinal); i++)
        {
            await Task.Delay(100);
            calls = await Events(server, "live-1", from: "w1", log: false);
        }
        Assert.Contains(" call ", calls);
        Assert.Contains("running", await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" }));
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
    }

    /// <summary>
    /// A stop at JIT-compiled code, then many more methods compiled after it, which the runtime places next to the stopped
    /// one: a write to the code must not leave the program running stale copies of those pages.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Methods_compiled_after_a_stop_run_on_win_x64()
    {
        const int methods = 400;
        var source = $$"""
            using System.Runtime.CompilerServices;

            static class Compiled
            {
                static long s_sum;

                static int Main()
                {
                    for (int i = 0; i < 1000; i++) { Once(); Thread.Sleep(10); }
                    {{string.Concat(Enumerable.Range(0, methods).Select(i => $"M{i}(); "))}}
                    Console.WriteLine(s_sum);
                    return 0;
                }

                [MethodImpl(MethodImplOptions.NoInlining)] static void Once() => s_sum += 1;
                {{string.Concat(Enumerable.Range(0, methods).Select(i => $"[MethodImpl(MethodImplOptions.NoInlining)] static void M{i}() => s_sum += {i} * (s_sum | 1) % 7; "))}}
            }
            """;
        var exe = DotnetTarget.WinX64.Build(_dir, source: source);
        await using var server = await Server();
        var pid = await Spawn(server, exe, "live-1");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "readers.dll!Compiled::Once" });
        Assert.Contains("stopped at s1", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await Exited(server, "live-1", pid));
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));

        // with W^X turned back on, a point there is refused rather than set
        await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["environment"] = new[] { "DOTNET_EnableWriteXorExecute=1" } });
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "set", ["at"] = "readers.dll!Compiled::Once" });
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        string errors = "";
        for (int i = 0; i < 100 && !errors.Contains("could not be set", StringComparison.Ordinal); i++)
        {
            await Task.Delay(100);
            errors = await Events(server, "live-2", kind: "error", log: false);
        }
        Assert.Contains("shared memory view", errors);
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" }));
    }

    /// <summary>A stop by name in a .NET Framework assembly whose native image (name.ni.dll) loads in its place.</summary>
    [FrameworkNativeImageFact]
    public async Task Stop_point_in_a_framework_native_image()
    {
        File.WriteAllText(_dir.File("Directory.Build.props"), "<Project />");
        File.WriteAllText(_dir.File("Directory.Build.targets"), "<Project />");
        File.WriteAllText(_dir.File("matcher.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net48</TargetFramework><PlatformTarget>x64</PlatformTarget></PropertyGroup>
            </Project>
            """);
        File.WriteAllText(_dir.File("Program.cs"), """
            static class Matcher
            {
                static void Main()
                {
                    for (int i = 0; i < 100000; i++)
                    {
                        System.Text.RegularExpressions.Regex.IsMatch("x" + i, "x[0-9]+");
                        System.Threading.Thread.Sleep(20);
                    }
                }
            }
            """);
        var (code, log) = Tools.Dotnet(_dir.Path, "build", "-c", "Release", "-o", "out", "-nologo");
        var exe = _dir.File(Path.Combine("out", "matcher.exe"));
        Assert.True(code == 0 && File.Exists(exe), log);
        await using var server = await Server();
        await Spawn(server, exe, "live-1");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "System.dll!System.Text.RegularExpressions.Regex::IsMatch(string, string)" });
        Assert.Matches(@"stopped at s1 \(System\.dll!System\.Text\.RegularExpressions\.Regex\.IsMatch\(System\.String, System\.String\)\)",
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
    }

    /// <summary>Coverage of a managed assembly in two runs, recorded to the exit; with no rounds the read method never runs.</summary>
    [DotnetTargetFact("win-x64")]
    public async Task Managed_coverage_on_win_x64()
    {
        var exe = DotnetTarget.WinX64.Build(_dir);
        var input = _dir.File(InputName);
        File.WriteAllText(input, "x");
        await using var server = await Server();
        var runs = new List<string>();
        foreach (var (session, rounds) in new[] { ("live-1", "0"), ("live-2", "1") })
        {
            await Spawn(server, exe, session, input, "1", rounds, "0");
            var start = await Ok(server, "live_coverage", new() { ["session"] = session, ["action"] = "start", ["match"] = "readers.dll!" });
            runs.Add(Regex.Match(start, @"^(cov-\d+) recording which of \d+ methods of readers\.dll run").Groups[1].Value);
            await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
            await UntilExited(server, session);
        }
        Assert.Matches(@"ran  0x06000002  Readers::ReadLoop\(string, int, int\)", await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = runs[0] }));
        var diff = await Ok(server, "live_coverage", new() { ["action"] = "diff", ["run"] = runs[0], ["other"] = runs[1] });
        Assert.Matches(@"0 functions ran only in cov-\d+, 1 only in cov-\d+", diff);
        Assert.Matches(@"only in cov-\d+:\r?\n\s+ran  0x06000003  Readers::ReadOnce\(string\)", diff);
        await Refused(server, "live_coverage", new() { ["action"] = "report", ["run"] = runs[0], ["format"] = "dot" }, "unsupported");
    }

    /// <summary>Builds a 32-bit .NET Framework program <paramref name="name"/>.exe from <paramref name="source"/>.</summary>
    private string Framework32(string name, string source)
    {
        File.WriteAllText(_dir.File("Directory.Build.props"), "<Project />");
        File.WriteAllText(_dir.File("Directory.Build.targets"), "<Project />");
        File.WriteAllText(_dir.File($"{name}.csproj"), $"""
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net48</TargetFramework><PlatformTarget>x86</PlatformTarget><AssemblyName>{name}</AssemblyName></PropertyGroup>
            </Project>
            """);
        File.WriteAllText(_dir.File("Program.cs"), source);
        var (code, log) = Tools.Dotnet(_dir.Path, "build", "-c", "Release", "-o", "out", "-nologo");
        var exe = _dir.File(Path.Combine("out", $"{name}.exe"));
        Assert.True(code == 0 && File.Exists(exe), log);
        return exe;
    }

    /// <summary>Builds a 32-bit .NET Framework program: Main calls Add <paramref name="rounds"/> times, 20 ms apart, then Late; Unused never runs.</summary>
    /// <summary>Calc: rounds calls of Add, then Late; with <paramref name="gate"/>, Late waits until that file exists.</summary>
    private string Calc32(int rounds = 10, string? gate = null) => Framework32("Calc", $$"""
            static class Calc
            {
                [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
                static int Add(int a, int b) { return a + b; }
                static int Unused() { return 1; }
                static void Main()
                {
                    int t = 0;
                    for (int i = 0; i < {{rounds}}; i++) { t = Add(t, i); System.Threading.Thread.Sleep(20); }
                    {{(gate != null ? $"while (!System.IO.File.Exists(@\"{gate}\")) System.Threading.Thread.Sleep(20);" : "")}}
                    System.Console.WriteLine(t + Late());
                }
                [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
                static int Late() { return 2; }
            }
            """);

    /// <summary>shelf pause: holds 1234 Item objects, prints "ready", then sleeps pause ms; builds for .NET and .NET Framework.</summary>
    private const string Shelf = """
        class Item
        {
            public int Id;
            public string Name;
            public Item(int id) { Id = id; Name = "item-" + id; }
        }

        static class Shelf
        {
            static System.Collections.Generic.List<Item> s_items = new System.Collections.Generic.List<Item>();

            static void Main(string[] args)
            {
                for (int i = 0; i < 1234; i++) s_items.Add(new Item(i));
                System.Console.WriteLine("ready");
                System.Threading.Thread.Sleep(int.Parse(args[0]));
                System.GC.KeepAlive(s_items);
            }
        }
        """;

    /// <summary>The heap of a running program by type, its objects and one object's fields, read without stopping it.</summary>
    [DotnetTargetFact("win-x64")]
    public Task Heap_of_a_running_program_on_win_x64() => HeapOfARunningProgram(DotnetTarget.WinX64.Build(_dir, source: Shelf));

    /// <summary>As on x64, for a 32-bit .NET Framework program read by the 32-bit decoder process.</summary>
    [DotnetTargetFact("win-x64")]
    public Task Heap_of_a_running_32_bit_framework_program() => HeapOfARunningProgram(Framework32("Shelf", Shelf));

    private async Task HeapOfARunningProgram(string exe)
    {
        await using var server = await Server();
        await Spawn(server, exe, "live-1", "120000");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        bool ready = false;
        for (int i = 0; i < 900 && !(ready = (await Events(server, "live-1", kind: "output", log: false)).Contains("ready")); i++) await Task.Delay(100);
        // A heap read before "ready" sees a runtime still starting, so a
        // missed signal fails here with what the session saw.
        if (!ready)
            Assert.Fail($"no \"ready\" within 90 s\n{await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" })}\nmodule events:\n{await Events(server, "live-1", kind: "module", log: false)}\nerrors:\n{await Events(server, "live-1", kind: "error", log: false)}");
        var stats = await Ok(server, "dump_heap", new() { ["dump"] = "live-1", ["type"] = "Item" });
        Assert.Matches(@"(?m)^ *Item  1,234 objects, [\d,]+ bytes", stats);
        Assert.Contains("note: The program runs during the read", stats);
        var objects = await Ok(server, "dump_heap", new() { ["dump"] = "live-1", ["mode"] = "objects", ["type"] = "Item", ["limit"] = 1 });
        var address = Regex.Match(objects, @"(0x[0-9A-F]+)  Item  \d+ bytes").Groups[1].Value;
        Assert.False(address.Length == 0, objects);
        var item = await Ok(server, "dump_object", new() { ["dump"] = "live-1", ["address"] = address });
        Assert.Matches(@"(?m)^type: Item\r?$", item);
        Assert.Matches(@"Name\s+1\s+System\.String\s+\d+\s+""item-\d+""", item);
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
        Assert.Contains("has ended", await Refused(server, "dump_heap", new() { ["dump"] = "live-1" }, "not_found"));
    }

    /// <summary>
    /// A 32-bit .NET Framework program under this 64-bit server: its runtime is read by the 32-bit decoder process, so a
    /// stop names the managed caller the runtime compiled, not only the method the stop point was set in.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Frames_of_a_32_bit_framework_program_are_named_by_its_runtime()
    {
        var exe = Calc32();
        await using var server = await Server();
        await Spawn(server, exe, "live-1");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Calc::Add" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "list", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches(@"#0 0x[0-9A-F]+ Calc\.exe!Calc\.Add\(Int32, Int32\)", stop);
        Assert.Matches(@"#1 0x[0-9A-F]+ Calc\.exe!Calc\.Main\(\)\+0x[0-9A-F]+", stop);
    }

    /// <summary>
    /// Managed coverage of a running 32-bit .NET Framework program from its runtime's record, read by the 32-bit decoder
    /// process: methods compiled before the run started count too.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Managed_coverage_of_a_32_bit_framework_program()
    {
        // The program exits only after the run has started.
        var gate = _dir.File("exit.gate");
        var exe = Calc32(gate: gate);
        await using var server = await Server();
        await Spawn(server, exe, "live-1");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Calc::Add" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "list", ["wait"] = true, ["waitSeconds"] = 60 });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var start = await Ok(server, "live_coverage", new() { ["session"] = "live-1", ["action"] = "start", ["match"] = "Calc.exe!" });
        var run = Regex.Match(start, @"^(cov-\d+) recording which of \d+ methods of Calc\.exe run in live-1, from the runtime's record");
        Assert.True(run.Success, start);
        File.WriteAllText(gate, "");
        await UntilExited(server, "live-1");
        var report = await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = run.Groups[1].Value });
        Assert.Matches(@": 3 of 4 functions ran \(75%\), complete", report);
        Assert.Matches(@"ran  0x06000001  Calc::Add\(int, int\)", report);
        Assert.Matches(@"ran  0x06000003  Calc::Main\(\)", report);
        Assert.DoesNotMatch(@"ran  0x06000002", report);
    }

    /// <summary>
    /// The 32-bit decoder stops mid-session (here one that never answers, ended at its per-read budget): the stop still
    /// comes, the session says so once, and a coverage run read from the runtime goes on counting first compiles.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task A_32_bit_session_goes_on_when_its_decoder_stops()
    {
        var gate = _dir.File("late.gate");
        var exe = Calc32(gate: gate);
        Directory.CreateDirectory(_dir.File("silent"));
        File.WriteAllText(_dir.File(Path.Combine("silent", "silent.csproj")), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup>
            </Project>
            """);
        File.WriteAllText(_dir.File(Path.Combine("silent", "Program.cs")), """
            System.Console.Out.WriteLine("{\"ok\":true,\"value\":{\"runtime\":\"4.8\"}}");
            System.Console.Out.Flush();
            if (System.Console.ReadLine() != null) System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
            """);
        var (code, log) = Tools.Dotnet(_dir.File("silent"), "build", "-c", "Release", "-o", "out", "-nologo");
        var silent = _dir.File(Path.Combine("silent", "out", "silent.exe"));
        Assert.True(code == 0 && File.Exists(silent), log);
        var budget = Corvus.Native.Dump.Managed.ClrHelperClient.LiveCallTimeout;
        Corvus.Native.Dump.Managed.ClrHelperClient.LiveCallTimeout = TimeSpan.FromSeconds(2);
        try
        {
            await using var server = await Server();
            server.Services.GetRequiredService<LiveSessionService>().DecoderPath = silent;
            await Spawn(server, exe, "live-1");
            var start = await Ok(server, "live_coverage", new() { ["session"] = "live-1", ["action"] = "start", ["match"] = "Calc.exe!" });
            var run = Regex.Match(start, @"^(cov-\d+) recording which of \d+ methods of Calc\.exe run in live-1, from the runtime's record");
            Assert.True(run.Success, start);
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Calc::Late" });
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
            // Late runs only once the run counts first compiles, however long the decoder takes to stop.
            string errors = "";
            for (int i = 0; i < 600 && !errors.Contains("first compiles from now on", StringComparison.Ordinal); i++)
            {
                errors = await Events(server, "live-1", kind: "error", log: false);
                await Task.Delay(100);
            }
            File.WriteAllText(gate, "");
            var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "list", ["wait"] = true, ["waitSeconds"] = 60 });
            Assert.Matches(@"thread \d+ stopped at s1", stop);
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
            await UntilExited(server, "live-1");
            var report = await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = run.Groups[1].Value });
            Assert.Matches(@"ran  0x06000004  Calc::Late\(\)", report);
            // No read of the runtime succeeded: what the run did not see is unknown.
            Assert.Contains("seen to run; the rest are unknown, not missed: no read of the program's runtime succeeded", report);
            var all = await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = run.Groups[1].Value, ["show"] = "all" });
            Assert.Matches(@"\?  0x06000002  Calc::Unused\(\)", all);
            var events = await Ok(server, "live_events", new() { ["session"] = "live-1", ["kind"] = "error" });
            Assert.Single(Regex.Matches(events, "the 32-bit .NET decoder stopped"));
            Assert.Contains($"{run.Groups[1].Value} counts first compiles from now on", events);
        }
        finally { Corvus.Native.Dump.Managed.ClrHelperClient.LiveCallTimeout = budget; }
    }

    /// <summary>
    /// Without the 32-bit decoder a 32-bit program's methods are counted from the JIT's compiles, also when the program
    /// file was loaded with load_assembly first.
    /// </summary>
    [DotnetTargetFact("win-x64")]
    public async Task Managed_coverage_of_a_32_bit_program_without_the_decoder()
    {
        var exe = Calc32();
        await using var server = await Server();
        // Regression (push run on b474b551): a process-wide CORVUS_CLR32 here hid the decoder from tests running beside it.
        server.Services.GetRequiredService<LiveSessionService>().DecoderPath = _dir.File(Path.Combine("missing", "decoder.exe"));
        await Ok(server, "load_assembly", new() { ["path"] = exe });
        await Spawn(server, exe, "live-1");
        var start = await Ok(server, "live_coverage", new() { ["session"] = "live-1", ["action"] = "start", ["match"] = "Calc.exe!" });
        var run = Regex.Match(start, @"^(cov-\d+) recording which of \d+ methods of Calc\.exe run in live-1, from the JIT's compiles");
        Assert.True(run.Success, start);
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        await UntilExited(server, "live-1");
        var report = await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = run.Groups[1].Value });
        Assert.Matches(@"ran  0x06000001  Calc::Add\(int, int\)", report);
        Assert.Matches(@"ran  0x06000003  Calc::Main\(\)", report);
        Assert.DoesNotMatch(@"ran  0x06000002", report);
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
