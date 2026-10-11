using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Real .NET crash dumps: a console program compiled here throws an exception wrapped in another, unhandled, and the
/// runtime's own dump writer (createdump, switched on by its documented environment variables) writes the dump. The
/// DAC is the one of the runtime running the tests, found locally.
/// </summary>
[Trait("Speed", "Slow")]
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
                catch (Exception e) { throw new ApplicationException("ndm-outer", e); }
            }

            [MethodImpl(MethodImplOptions.NoInlining)]
            public static void Inner() => throw new InvalidOperationException("ndm-probe");
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
        var service = new MinidumpService(ws);

        var summary = await service.Summarize(dump, null, 0, 50, 0, 50, default);
        var m = summary.Managed!;
        output.WriteLine($"{m.Runtime}: DAC {m.Dac.Status} {m.Dac.Path} ({m.Dac.Detail}); heap {m.Heap}");
        Assert.Equal("loaded", m.Dac.Status);
        Assert.True(m.Heap!.Walkable, m.Heap.Reason);
        var e = m.Exception!;
        Assert.Equal("System.ApplicationException", e.Type);
        Assert.Equal("ndm-outer", e.Message);
        var inner = Assert.Single(e.Inner);
        Assert.Equal("System.InvalidOperationException", inner.Type);
        Assert.Equal("ndm-probe", inner.Message);
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
        Assert.Equal("\"ndm-outer\"", outer.Fields.Single(f => f.Path == "_message").Value);
        Assert.Equal(inner.Address, outer.Fields.Single(f => f.Path == "_innerException").Address);
        Assert.Equal("\"ndm-probe\"", outer.Fields.Single(f => f.Path == "_innerException._message").Value);
        Assert.Equal("-2146232832", outer.Fields.Single(f => f.Path == "_HResult").Value); // COR_E_APPLICATION
        var message = await service.Object(dump, outer.Fields.Single(f => f.Path == "_message").Address!, 1, 100, 32, default);
        Assert.Equal("ndm-outer", message.Value);
        await Assert.ThrowsAsync<ToolError>(() => service.Object(dump, "0x10", 1, 100, 32, default));
        Assert.DoesNotContain(stack.Frames.GroupBy(f => f.StackPointer), g => g.Count() > 1 && g.Any(f => f.SymbolSource == "clr")); // one frame per stack pointer
    }

    [Fact]
    public async Task StacksOnlyDumpDecodesFramesButNotTheHeap()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var dump = Crash(Build(dir), dir.File("mini.dmp"), 1);
        var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, 0, 50, 0, 50, default);
        var m = summary.Managed!;
        Assert.Equal("loaded", m.Dac.Status);
        Assert.False(m.Heap!.Walkable);
        Assert.StartsWith("heap_not_captured", m.Heap.Reason);
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Heap(dump, "stats", null, 0, 0, 50, MinidumpService.DefaultMaxHeapObjects, default));
        Assert.StartsWith("heap_not_captured", error.Message);
        Assert.Equal("ndm-probe", m.Exception!.Inner.Single().Message);
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
        var service = new MinidumpService { BucketCache = dir.File("cache") };
        var r = await service.Bucket(dumps, false, null, 3, null, false, true, 10, null, 0, 10, null, default);
        var bucket = Assert.Single(r.Buckets);
        output.WriteLine(bucket.Signature);
        Assert.Equal(2, bucket.Count);
        Assert.Equal("clr_exception", bucket.Kind);
        Assert.StartsWith("clr | System.ApplicationException | Probe.Program.Main", bucket.Signature);
        var native = await service.Bucket(dumps, false, null, 3, null, false, false, 10, null, 0, 10, null, default);
        Assert.NotEqual("clr_exception", Assert.Single(native.Buckets).Kind);
    }

    private static void AssertSortedBySp(MinidumpService.StackReport stack)
    {
        var sps = stack.Frames.Where(f => !f.Heuristic).Select(f => Convert.ToUInt64(f.StackPointer[2..], 16)).ToList();
        for (int i = 1; i < sps.Count; i++) Assert.True(sps[i] >= sps[i - 1], $"frame {i}: stack pointers out of order");
    }
}
