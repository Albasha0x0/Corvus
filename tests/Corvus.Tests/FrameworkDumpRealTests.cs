using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Real .NET Framework dumps: a program compiled here against the .NET Framework 4.8 reference assemblies writes a dump of
/// itself (dbghelp) inside a catch block, as a 64-bit and as a 32-bit process. The DAC (mscordacwks) is the installed
/// Framework's. Windows only.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class FrameworkDumpRealTests(ITestOutputHelper output)
{
    private const string Source = """
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Runtime.CompilerServices;
        using System.Runtime.InteropServices;

        namespace FxProbe
        {
            public static class Program
            {
                public static Exception Kept;

                [DllImport("dbghelp.dll", SetLastError = true)]
                private static extern bool MiniDumpWriteDump(IntPtr process, int processId, IntPtr file, int type, IntPtr exception, IntPtr user, IntPtr callback);

                public static int Main(string[] args)
                {
                    try { Inner(); }
                    catch (Exception e)
                    {
                        Kept = new ApplicationException("ndm-outer", e);
                        try { throw Kept; }
                        catch (ApplicationException) { return DumpSelf(args[0]); }
                    }
                    return 1;
                }

                [MethodImpl(MethodImplOptions.NoInlining)]
                public static void Inner() { throw new InvalidOperationException("ndm-probe"); }

                [MethodImpl(MethodImplOptions.NoInlining)]
                public static int DumpSelf(string path)
                {
                    using (var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
                    {
                        var self = Process.GetCurrentProcess();
                        // full memory, handles, thread info, full memory info
                        bool ok = MiniDumpWriteDump(self.Handle, self.Id, file.SafeFileHandle.DangerousGetHandle(), 0x2 | 0x4 | 0x1000 | 0x800, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                        return ok ? 0 : Marshal.GetLastWin32Error();
                    }
                }
            }
        }
        """;

    private static readonly string[] Reference = ["Microsoft.NETFramework.ReferenceAssemblies.net48", "1.0.3", "build", ".NETFramework", "v4.8"];

    private static string Build(TempDir dir, Platform platform)
    {
        var refs = new[] { "mscorlib.dll", "System.dll", "System.Core.dll" }.Select(f => (MetadataReference)MetadataReference.CreateFromFile(RealPackages.File(Reference[0], Reference[1], [.. Reference[2..], f])));
        var compilation = CSharpCompilation.Create("FxProbe", [CSharpSyntaxTree.ParseText(Source)], refs,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug, platform: platform));
        var exe = dir.File($"FxProbe{platform}.exe");
        using (var fs = File.Create(exe))
        {
            var result = compilation.Emit(fs);
            Assert.True(result.Success, string.Join("\n", result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error)));
        }
        return exe;
    }

    private static string Dump(string exe, string dump)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(dump);
        var (code, log) = Tools.Run(psi, 120_000);
        Assert.True(code == 0 && File.Exists(dump), $"no dump written (exit {code}): {log}");
        return dump;
    }

    private static int MethodToken(string exe, string name)
    {
        using var pe = new PEReader(File.OpenRead(exe));
        var md = pe.GetMetadataReader();
        foreach (var h in md.MethodDefinitions)
            if (md.GetString(md.GetMethodDefinition(h).Name) == name) return MetadataTokens.GetToken(h);
        throw new InvalidOperationException(name);
    }

    private async Task Decode(Platform platform, string arch)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var exe = Build(dir, platform);
        var dump = Dump(exe, dir.File($"fx-{arch}.dmp"));
        using var ws = new Core.AssemblyWorkspace();
        var probe = ws.Load(exe);
        var service = new MinidumpService(ws);

        var summary = await service.Summarize(dump, null, 0, 50, 0, 50, default);
        Assert.Equal(arch, summary.System!.Architecture);
        var m = summary.Managed!;
        output.WriteLine($"{m.Runtime}: DAC {m.Dac.Status} {m.Dac.Path} ({m.Dac.Detail}); heap {m.Heap}");
        Assert.StartsWith(".NET Framework 4.", m.Runtime);
        Assert.Equal("loaded", m.Dac.Status);
        Assert.EndsWith("mscordacwks.dll", m.Dac.Path, StringComparison.OrdinalIgnoreCase);
        Assert.True(m.Heap!.Walkable, m.Heap.Reason);
        var e = m.Exception!;
        Assert.Equal(("System.ApplicationException", "ndm-outer"), (e.Type, e.Message));
        var inner = Assert.Single(e.Inner);
        Assert.Equal(("System.InvalidOperationException", "ndm-probe"), (inner.Type, inner.Message));
        var thrower = inner.Stack.First(f => f.Function.Contains("Inner", StringComparison.Ordinal));
        Assert.Equal($"0x{MethodToken(exe, "Inner"):X8}", thrower.Token);
        Assert.Equal(probe.Id, thrower.Assembly);

        var stack = await service.Stack(dump, e.ThreadId?.ToString(System.Globalization.CultureInfo.InvariantCulture), true, 256, 0, 256, null, default);
        foreach (var f in stack.Frames) output.WriteLine($"{f.Index,2} {f.StackPointer} {f.Symbol} [{f.SymbolSource}] {f.Method} {f.Token} il={f.IlOffset} {f.Assembly}");
        Assert.Equal("decoded", stack.Managed);
        var dumpSelf = stack.Frames.First(f => f.SymbolSource == "clr" && f.Function!.Contains("DumpSelf", StringComparison.Ordinal));
        Assert.Equal($"0x{MethodToken(exe, "DumpSelf"):X8}", dumpSelf.Token);
        Assert.Contains(stack.Frames, f => f.SymbolSource == "clr" && f.Function!.Contains("Main", StringComparison.Ordinal));

        var heap = await service.Heap(dump, "objects", "System.ApplicationException", 0, 0, 10, MinidumpService.DefaultMaxHeapObjects, default);
        var kept = await service.Object(dump, heap.Objects.Single().Address, 1, 100, 32, default);
        Assert.Equal("\"ndm-outer\"", kept.Fields.Single(f => f.Path == "_message").Value);
    }

    [Fact]
    public Task X64FrameworkDumpIsDecodedWithMscordacwks() => Decode(Platform.X64, "x64");

    [Fact]
    public Task X86FrameworkDumpIsDecodedOutOfProcess() => Decode(Platform.X86, "x86");
}
