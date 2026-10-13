using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Real .NET crash dumps: a console program compiled here throws an exception wrapped in another, unhandled, and the
/// runtime's own dump writer (createdump, switched on by its documented environment variables) writes the dump. The
/// DAC is the one of the runtime running the tests, found locally.
/// </summary>
[Trait("Speed", "Slow")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class ManagedDumpRealTests(ITestOutputHelper output)
{
    private const string Source = """
        using System;
        using System.Runtime.CompilerServices;

        namespace Probe;

        public static class Program
        {
            public static void Main()
            {
                try { Inner(); }
                catch (Exception e) { throw new ApplicationException("sample-outer", e); }
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            public static void Inner() => throw new InvalidOperationException("sample-probe");
        }
        """;

    /// <summary>The runtime's dump-on-crash switches; type 1 is a minidump (stacks), 4 a full-memory dump.</summary>
    private static Dictionary<string, string> DumpSwitches(string path, int type) => new()
    {
        ["DOTNET_DbgEnableMiniDump"] = "1",
        ["DOTNET_DbgMiniDumpType"] = type.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["DOTNET_DbgMiniDumpName"] = path,
    };

    private static string Build(TempDir dir)
    {
        var bytes = Roslyn.Compile("Probe", Source, new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug));
        var dll = dir.File("Probe.dll");
        File.WriteAllBytes(dll, bytes);
        File.WriteAllText(dir.File("Probe.runtimeconfig.json"),
            System.Text.Json.JsonSerializer.Serialize(new
            {
                runtimeOptions = new { tfm = $"net{Environment.Version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version = Environment.Version.ToString() } },
            }));
        return dll;
    }

    private static string Crash(string dll, string dump, int type)
    {
        var psi = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        psi.ArgumentList.Add(dll);
        foreach (var (k, v) in DumpSwitches(dump, type)) psi.Environment[k] = v;
        var (code, log) = Tools.Run(psi, 120_000);
        Assert.True(code != 0 && File.Exists(dump), $"no dump written (exit {code}): {log}");
        return dump;
    }

    private static int MethodToken(string dll, string name)
    {
        using var pe = new PEReader(File.OpenRead(dll));
        var md = pe.GetMetadataReader();
        foreach (var h in md.MethodDefinitions)
            if (md.GetString(md.GetMethodDefinition(h).Name) == name) return MetadataTokens.GetToken(h);
        throw new InvalidOperationException(name);
    }

    [Fact]
    public async Task UnhandledExceptionIsDecodedWithItsInnerChain()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var dll = Build(dir);
        var dump = Crash(dll, dir.File("full.dmp"), 4);
        using var ws = new AssemblyWorkspace();
        var probe = ws.Load(dll);
        using var service = new MinidumpService(ws, decompiler: new DecompilerService(ws, new ServerOptions()));

        var summary = await service.Summarize(dump, null, default);
        var m = summary.Managed!;
        output.WriteLine($"{m.Runtime}: DAC {m.Dac.Status} {m.Dac.Path} ({m.Dac.Detail}); heap {m.Heap}");
        Assert.Equal("loaded", m.Dac.Status);
        Assert.True(m.Heap!.Walkable, m.Heap.Reason);
        Assert.Equal("throw new InvalidOperationException(\"sample-probe\");",
            m.Exception!.Inner.Single().Stack.First(f => f.Function.Contains("Inner", StringComparison.Ordinal)).Statement); // the IL offset as a C# statement
        var e = m.Exception!;
        Assert.Equal("System.ApplicationException", e.Type);
        Assert.Equal("sample-outer", e.Message);
        var inner = Assert.Single(e.Inner);
        Assert.Equal("System.InvalidOperationException", inner.Type);
        Assert.Equal("sample-probe", inner.Message);
        Assert.Equal("0x80131509", inner.HResult);
        var thrower = inner.Stack.First(f => f.Function.Contains("Inner", StringComparison.Ordinal));
        Assert.Equal($"0x{MethodToken(dll, "Inner"):X8}", thrower.Token);
        Assert.Equal(probe.Id, thrower.Assembly);
        Assert.Equal("match", thrower.BuildCheck);
        Assert.Contains(e.Stack, f => f.Function.Contains("Main", StringComparison.Ordinal));

        var stack = await service.Stack(dump, e.ThreadId?.ToString(System.Globalization.CultureInfo.InvariantCulture), true, 256, 0, 256, null, default);
        foreach (var f in stack.Frames) output.WriteLine($"{f.Index,2} {f.StackPointer} {f.Symbol} [{f.SymbolSource}] {f.Method} {f.Token} il={f.IlOffset} {f.Assembly} {f.BuildCheck}");
        Assert.Equal("decoded", stack.Managed);
        var main = stack.Frames.First(f => f.SymbolSource == "clr" && f.Function!.Contains("Main", StringComparison.Ordinal));
        Assert.Equal($"0x{MethodToken(dll, "Main"):X8}", main.Token);
        Assert.Equal(probe.Id, main.Assembly);
        Assert.NotNull(main.IlOffset);
        // native frames stay: the runtime's exception dispatch below the managed frames
        Assert.Contains(stack.Frames, f => f.SymbolSource != "clr" && f.Module != null);
        AssertSortedBySp(stack);

        var heap = await service.Heap(dump, "stats", null, 0, 0, 1000, MinidumpService.DefaultMaxHeapObjects, default);
        Assert.False(heap.WalkStopped);
        var strings = heap.Types.Single(t => t.Type == "System.String");
        Assert.True(strings.Count > 10 && strings.TotalSize > 0);
        Assert.Contains(heap.Types, t => t.Type == "System.ApplicationException");
        var probeType = await service.Heap(dump, "stats", "System.*Exception", 0, 0, 50, MinidumpService.DefaultMaxHeapObjects, default);
        Assert.All(probeType.Types, t => Assert.EndsWith("Exception", t.Type, StringComparison.Ordinal));
        var objects = await service.Heap(dump, "objects", "System.String", 0, 0, 5, MinidumpService.DefaultMaxHeapObjects, default);
        Assert.Equal(5, objects.Objects.Count);
        Assert.True(objects.Truncated);
        Assert.All(objects.Objects, o => Assert.NotNull(o.Value));

        var outer = await service.Object(dump, e.Address, 2, 100, 32, default);
        output.WriteLine(string.Join("\n", outer.Fields.Select(f => $"{new string(' ', f.Depth * 2)}{f.Path}: {f.Type} = {f.Value} {f.Address}")));
        Assert.Equal("System.ApplicationException", outer.Type);
        Assert.Equal("\"sample-outer\"", outer.Fields.Single(f => f.Path == "_message").Value);
        Assert.Equal(inner.Address, outer.Fields.Single(f => f.Path == "_innerException").Address);
        Assert.Equal("\"sample-probe\"", outer.Fields.Single(f => f.Path == "_innerException._message").Value);
        Assert.Equal("-2146232832", outer.Fields.Single(f => f.Path == "_HResult").Value); // COR_E_APPLICATION
        var message = await service.Object(dump, outer.Fields.Single(f => f.Path == "_message").Address!, 1, 100, 32, default);
        Assert.Equal("sample-outer", message.Value);
        await Assert.ThrowsAsync<ToolError>(() => service.Object(dump, "0x10", 1, 100, 32, default));
        Assert.DoesNotContain(stack.Frames.GroupBy(f => f.StackPointer), g => g.Count() > 1 && g.Any(f => f.SymbolSource == "clr")); // one frame per stack pointer
    }

    [Fact]
    public async Task StacksOnlyDumpDecodesFramesButNotTheHeap()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var dump = Crash(Build(dir), dir.File("mini.dmp"), 1);
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, default);
        var m = summary.Managed!;
        Assert.Equal("loaded", m.Dac.Status);
        Assert.False(m.Heap!.Walkable);
        Assert.StartsWith("heap_not_captured", m.Heap.Reason);
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Heap(dump, "stats", null, 0, 0, 50, MinidumpService.DefaultMaxHeapObjects, default));
        Assert.StartsWith("heap_not_captured", error.Message);
        Assert.Equal("sample-probe", m.Exception!.Inner.Single().Message);
        var stack = await service.Stack(dump, m.Exception.ThreadId?.ToString(System.Globalization.CultureInfo.InvariantCulture), true, 256, 0, 256, null, default);
        Assert.Contains(stack.Frames, f => f.SymbolSource == "clr" && f.Function!.Contains("Inner", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DotNetCrashesBucketByExceptionTypeAndManagedFrames()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var dll = Build(dir);
        var dumps = Directory.CreateDirectory(dir.File("dumps")).FullName;
        Crash(dll, Path.Combine(dumps, "one.dmp"), 1);
        Crash(dll, Path.Combine(dumps, "two.dmp"), 1);
        using var service = new MinidumpService { BucketCache = dir.File("cache") };
        var r = await service.Bucket(dumps, false, null, 3, null, false, true, 10, null, 0, 10, null, default);
        var bucket = Assert.Single(r.Buckets);
        output.WriteLine(bucket.Signature);
        Assert.Equal(2, bucket.Count);
        Assert.Equal("clr_exception", bucket.Kind);
        Assert.StartsWith("clr | System.ApplicationException | Probe.Program.Main", bucket.Signature);
        var native = await service.Bucket(dumps, false, null, 3, null, false, false, 10, null, 0, 10, null, default);
        Assert.NotEqual("clr_exception", Assert.Single(native.Buckets).Kind);
    }

    /// <summary>
    /// The DAC of the dumped runtime downloaded from Microsoft's symbol server (CORVUS_NETWORK_TESTS=1): signature checked,
    /// loaded, and kept in the download cache, where the next call finds it without a request.
    /// </summary>
    [Fact]
    public async Task DacIsDownloadedFromTheSymbolServerAndCached()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("CORVUS_NETWORK_TESTS") != "1") return;
        using var dir = new TempDir();
        using var env = new EnvironmentScope().Set(Native.Pdb.PdbLocator.CacheVariable, dir.File("cache")).Set("CORVUS_OFFLINE", null)
            .Set("_NT_SYMBOL_PATH", null).Set("_NT_ALT_SYMBOL_PATH", null);
        var dump = Crash(Build(dir), dir.File("mini.dmp"), 1);
        var request = new Native.Dump.Managed.DacRequest(Download: true) { DownloadOnly = true };

        using var first = new MinidumpService();
        var m = (await first.Summarize(dump, null, request, default)).Managed!;
        output.WriteLine($"{m.Runtime}: DAC {m.Dac.Status} {m.Dac.Path} ({m.Dac.Detail})");
        Assert.Equal("loaded", m.Dac.Status);
        Assert.StartsWith(dir.File("cache"), m.Dac.Path);
        Assert.Contains("downloaded from https://msdl.microsoft.com", m.Dac.Detail);
        Assert.Equal("sample-probe", m.Exception!.Inner.Single().Message);
        Assert.Null(DacLocatorVerify(m.Dac.Path!));

        var written = File.GetLastWriteTimeUtc(m.Dac.Path!);
        using var second = new MinidumpService();
        var again = (await second.Summarize(dump, null, request, default)).Managed!;
        Assert.Equal((m.Dac.Path, written), (again.Dac.Path, File.GetLastWriteTimeUtc(again.Dac.Path!))); // from the cache
        // the cache is a local store: found without a download
        using var third = new MinidumpService();
        var local = (await third.Summarize(dump, null, new Native.Dump.Managed.DacRequest(), default)).Managed!;
        Assert.Equal("loaded", local.Dac.Status);
    }

    /// <summary>A 32-bit .NET process (the x86 runtime, when installed) is decoded by the 32-bit decoder process with the x86 DAC.</summary>
    [Fact]
    public async Task X86CoreClrDumpIsDecodedOutOfProcess()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) return;
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "dotnet");
        var host = Path.Combine(root, "dotnet.exe");
        var shared = Path.Combine(root, "shared", "Microsoft.NETCore.App");
        if (!File.Exists(host) || !Directory.Exists(shared)) return;
        var version = Directory.GetDirectories(shared).Select(Path.GetFileName).Select(v => Version.TryParse(v, out var x) ? x : null)
            .Where(v => v is { Major: >= 6 }).Max();
        if (version == null) return;
        using var dir = new TempDir();
        var bytes = Roslyn.Compile("Probe", Source, new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug, platform: Platform.X86));
        var dll = dir.File("Probe.dll");
        File.WriteAllBytes(dll, bytes);
        File.WriteAllText(dir.File("Probe.runtimeconfig.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            runtimeOptions = new { tfm = $"net{version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version = version.ToString() } },
        }));
        var dump = dir.File("x86.dmp");
        var psi = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(dll);
        foreach (var (k, v) in DumpSwitches(dump, 4)) psi.Environment[k] = v;
        var (code, log) = Tools.Run(psi, 120_000);
        Assert.True(code != 0 && File.Exists(dump), $"no dump written (exit {code}): {log}");

        using var ws = new AssemblyWorkspace();
        var probe = ws.Load(dll);
        using var service = new MinidumpService(ws);
        var summary = await service.Summarize(dump, null, default);
        var m = summary.Managed!;
        output.WriteLine($"{m.Runtime}: DAC {m.Dac.Status} {m.Dac.Path} ({m.Dac.Detail}); heap {m.Heap}");
        Assert.Equal("x86", summary.System!.Architecture);
        Assert.Equal("loaded", m.Dac.Status);
        Assert.Contains("32-bit decoder process", m.Dac.Detail);
        Assert.Contains(m.Notes, n => n.StartsWith("A 32-bit process", StringComparison.Ordinal));
        var inner = Assert.Single(m.Exception!.Inner);
        Assert.Equal("sample-probe", inner.Message);
        foreach (var e in new[] { m.Exception, inner })
            foreach (var f in e.Stack) output.WriteLine($"{e.Type} {f.Address} {f.Function} {f.Token} il={f.IlOffset}");
        // the trace array's header on x86 (.NET 9+) is not ClrMD's: its frames are read here
        Assert.Contains(inner.Stack, f => f.Function.Contains("Inner", StringComparison.Ordinal) && f.Token == $"0x{MethodToken(dll, "Inner"):X8}");
        var stack = await service.Stack(dump, m.Exception.ThreadId?.ToString(System.Globalization.CultureInfo.InvariantCulture), true, 256, 0, 256, null, default);
        Assert.Equal("decoded", stack.Managed);
        Assert.Contains(stack.Frames, f => f.SymbolSource == "clr" && f.Function!.Contains("Main", StringComparison.Ordinal) && f.Token == $"0x{MethodToken(dll, "Main"):X8}");
        var heap = await service.Heap(dump, "stats", "System.String", 0, 0, 10, MinidumpService.DefaultMaxHeapObjects, default);
        Assert.True(heap.Types.Single().Count > 10);
        // the bucket names the CLR exception and its managed frames
        using var bucketing = new MinidumpService { BucketCache = dir.File("cache") };
        var bucket = Assert.Single((await bucketing.Bucket(dir.Path, false, null, 3, null, false, true, 10, null, 0, 10, null, default)).Buckets);
        output.WriteLine(bucket.Signature);
        Assert.StartsWith("clr | System.ApplicationException | ", bucket.Signature);
        Assert.Contains("Probe.Program.Main", bucket.Signature);
    }

    /// <summary>A program that writes a stacks-only and a full dump of itself (dbghelp) from an exception filter, as crash reporters do.</summary>
    private const string SelfDumpSource = """
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Runtime.CompilerServices;
        using System.Runtime.InteropServices;

        namespace Probe;

        public static class Program
        {
            [DllImport("dbghelp.dll", SetLastError = true)]
            private static extern bool MiniDumpWriteDump(IntPtr process, int processId, IntPtr file, int type, IntPtr exception, IntPtr user, IntPtr callback);

            [DllImport("kernel32.dll")]
            private static extern int GetCurrentThreadId();

            public static int Main(string[] args)
            {
                try { Validate(2); }
                catch (Exception) when (DumpSelf(args[0], 0x4 | 0x20 | 0x100 | 0x1000) & DumpSelf(args[1], 0x2 | 0x4 | 0x800 | 0x1000) & false) { }
                catch (Exception) { return 0; }
                return 1;
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            public static void Validate(int depth)
            {
                if (depth > 0) Validate(depth - 1);
                else Inner();
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            public static void Inner() => throw new InvalidOperationException("sample-probe");

            private static bool DumpSelf(string path, int type)
            {
                var info = Marshal.AllocHGlobal(16); // MINIDUMP_EXCEPTION_INFORMATION, packed to 4
                Marshal.WriteInt32(info, 0, GetCurrentThreadId());
                Marshal.WriteIntPtr(info, 4, Marshal.GetExceptionPointers());
                Marshal.WriteInt32(info, 4 + IntPtr.Size, 0);
                using var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite);
                var self = Process.GetCurrentProcess();
                MiniDumpWriteDump(self.Handle, self.Id, file.SafeFileHandle.DangerousGetHandle(), type, info, IntPtr.Zero, IntPtr.Zero);
                Marshal.FreeHGlobal(info);
                return true;
            }
        }
        """;

    private static (string Dll, string Mini, string Full) SelfDumps(TempDir dir)
    {
        var dll = dir.File("SelfDump.dll");
        File.WriteAllBytes(dll, Roslyn.Compile("SelfDump", SelfDumpSource, new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug)));
        File.WriteAllText(dir.File("SelfDump.runtimeconfig.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            runtimeOptions = new { tfm = $"net{Environment.Version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version = Environment.Version.ToString() } },
        }));
        var psi = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        foreach (var a in new[] { dll, dir.File("mini.dmp"), dir.File("full.dmp") }) psi.ArgumentList.Add(a);
        var (code, log) = Tools.Run(psi, 120_000);
        Assert.True(code == 0 && File.Exists(dir.File("full.dmp")), $"no dump written (exit {code}): {log}");
        return (dll, dir.File("mini.dmp"), dir.File("full.dmp"));
    }

    /// <summary>
    /// A dbghelp dump without memory holds no JIT IL maps: the frames have no IL offset (not offset 0); the full dump
    /// of the same moment has them.
    /// </summary>
    [Fact]
    public async Task SelfWrittenDumps_IlOffsetsOnlyWhereTheDumpHoldsTheIlMap()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var (dll, mini, full) = SelfDumps(dir);
        using var ws = new AssemblyWorkspace();
        ws.Load(dll);
        using var service = new MinidumpService(ws, decompiler: new DecompilerService(ws, new ServerOptions()));

        var small = (await service.Summarize(mini, null, default)).Managed!;
        foreach (var f in small.Exception!.Stack) output.WriteLine($"mini {f.Function} il={f.IlOffset} {f.Statement}");
        Assert.Contains(small.Exception.Stack, f => f.Function.Contains("Probe.Program.Validate", StringComparison.Ordinal));
        Assert.All(small.Exception.Stack, f => Assert.Null(f.IlOffset));
        var thread = await service.Stack(mini, small.Exception.ThreadId?.ToString(System.Globalization.CultureInfo.InvariantCulture), true, 256, 0, 256, null, default);
        Assert.All(thread.Frames.Where(f => f.SymbolSource == "clr" && f.Function!.StartsWith("Probe.", StringComparison.Ordinal)), f => Assert.Null(f.IlOffset)); // CoreLib's precompiled maps are in its image

        var whole = (await service.Summarize(full, null, default)).Managed!;
        foreach (var f in whole.Exception!.Stack) output.WriteLine($"full {f.Function} il={f.IlOffset} {f.Statement}");
        var calls = whole.Exception.Stack.Where(f => f.Function.Contains("Probe.Program.Validate", StringComparison.Ordinal)).ToList();
        Assert.Equal(3, calls.Count);
        Assert.Equal("Validate(depth - 1);", calls[^1].Statement);
        Assert.Equal("Inner();", calls[0].Statement);
        Assert.Equal("throw new InvalidOperationException(\"sample-probe\");", whole.Exception.Stack.First(f => f.Function.Contains("Inner", StringComparison.Ordinal)).Statement);
    }

    /// <summary>The CLR exception code's description names the decoded exception instead of calling it unreadable.</summary>
    [Fact]
    public async Task SelfWrittenDump_ClrExceptionDescriptionNamesTheDecodedException()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var (_, mini, _) = SelfDumps(dir);
        using var service = new MinidumpService();
        var summary = await service.Summarize(mini, null, default);
        Assert.Equal("0xE0434352", summary.Exception!.Code);
        Assert.Equal("System.InvalidOperationException", summary.Managed!.Exception!.Type);
        Assert.DoesNotContain("managed debugger", summary.Exception.Description);
        Assert.Contains("System.InvalidOperationException: sample-probe", summary.Exception.Description);
    }

    /// <summary>A dbghelp dump without memory still lets the DAC list the GC segments; none of their memory is in it, so there is no heap to walk.</summary>
    [Fact]
    public async Task SelfWrittenDump_WithoutMemoryHasNoHeap()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var (_, mini, full) = SelfDumps(dir);
        using var service = new MinidumpService();
        var heap = (await service.Summarize(mini, null, default)).Managed!.Heap!;
        Assert.False(heap.Walkable);
        Assert.StartsWith("heap_not_captured", heap.Reason);
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Heap(mini, "stats", null, 0, 0, 50, MinidumpService.DefaultMaxHeapObjects, default));
        Assert.StartsWith("heap_not_captured", error.Message);
        Assert.Contains("full memory", error.Remediation);
        Assert.True((await service.Summarize(full, null, default)).Managed!.Heap!.Walkable);
        Assert.True((await service.Heap(full, "stats", null, 0, 0, 50, MinidumpService.DefaultMaxHeapObjects, default)).Walked > 0);
    }

    private static string? DacLocatorVerify(string path) => Native.Dump.Managed.DacLocator.Verify(File.ReadAllBytes(path), path);

    private static void AssertSortedBySp(MinidumpService.StackReport stack)
    {
        var sps = stack.Frames.Where(f => !f.Heuristic).Select(f => Convert.ToUInt64(f.StackPointer[2..], 16)).ToList();
        for (int i = 1; i < sps.Count; i++) Assert.True(sps[i] >= sps[i - 1], $"frame {i}: stack pointers out of order");
    }
}
