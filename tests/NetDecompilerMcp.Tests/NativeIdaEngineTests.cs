using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The native code tools on top of the IDA session: architectures the built-in analysis does not decode.</summary>
public sealed class NativeIdaEngineTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private (AssemblyWorkspace Workspace, NativeCodeTools Tools, NativeEngineService Engines) Setup(IdaProviderOptions? ida = null)
    {
        var options = new ServerOptions { TimeoutSeconds = 120, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engines = new NativeEngineService(ida ?? new IdaProviderOptions { CacheRoot = _dir.File("cache") });
        _owned.Add(engines);
        var code = new NativeCodeService(workspace, options);
        return (workspace, new NativeCodeTools(workspace, code, new OutputPager(options), null, engines, new NativeNamePush(code)), engines);
    }

    /// <summary>An ARM64 PE with code but no unwind data: the built-in analysis only lists the entry point.</summary>
    private string SyntheticArm64()
    {
        var b = new PeBuilder { Machine = 0xAA64, ImageBase = 0x180000000, EntryPoint = 0x1000 };
        b.Add(".text", [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6], 0x60000020); // mov w0, #0; ret
        var path = _dir.File("arm64.dll");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    [WindowsFact]
    public async Task Undecoded_architecture_without_IDA_is_unsupported_with_remediation()
    {
        var (_, tools, _) = Setup(new IdaProviderOptions { InstallDirectory = _dir.File("no-ida-here"), CacheRoot = _dir.File("cache") });
        var path = SyntheticArm64();
        foreach (var call in new Func<Task<string>>[] { () => tools.Disassemble(path, "rva:0x1000"), () => tools.GetCfg(path, "rva:0x1000") })
        {
            var e = await Assert.ThrowsAsync<ToolError>(call);
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains("Arm64", e.Message);
            Assert.Contains("IDA", e.Remediation);
        }
        // list_functions still answers from the declared starts.
        Assert.Contains("1 function", await tools.ListFunctions(path));
    }

    /// <summary>A small ARM64 PE on this machine (the .NET host packs ship some), or null.</summary>
    internal static string? FindArm64Image()
    {
        var roots = new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }
            .Select(Environment.GetFolderPath).Where(r => r.Length > 0 && Directory.Exists(r)).Distinct().ToList();
        foreach (var root in roots)
        {
            var packs = Path.Combine(root, "dotnet", "packs");
            if (!Directory.Exists(packs)) continue;
            foreach (var dir in Directory.EnumerateDirectories(packs, "*win-arm64*"))
                foreach (var file in SafeFiles(dir, "nethost.dll"))
                    if (IsArm64(file)) return file;
        }
        int seen = 0;
        foreach (var root in roots)
            foreach (var file in SafeFiles(root, "*.dll"))
            {
                if (++seen > 50_000) return null;
                if (file.Contains("arm64", StringComparison.OrdinalIgnoreCase) && new FileInfo(file).Length is > 40_000 and < 2_000_000 && IsArm64(file)) return file;
            }
        return null;
    }

    private static IEnumerable<string> SafeFiles(string root, string pattern)
    {
        try { return Directory.EnumerateFiles(root, pattern, new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static bool IsArm64(string file)
    {
        try
        {
            var pe = PeFile.Open(file);
            return pe.Arch == Native.NativeArch.Arm64 && pe.Exports.Count > 0 && !pe.IsDotNet;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError) { return false; }
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Arm64_code_tools_answer_through_IDA()
    {
        var path = FindArm64Image();
        if (path == null) { output.WriteLine("no ARM64 image found on this machine"); return; }
        output.WriteLine(path);
        var (workspace, tools, _) = Setup();
        var clock = Stopwatch.StartNew();
        var list = await tools.ListFunctions(path, limit: 5000);
        output.WriteLine($"list_functions {clock.Elapsed.TotalSeconds:0.0} s (includes IDA analysis)\n{string.Join('\n', list.Split('\n').Take(12))}");
        Assert.Contains(NativeEngineCode.Via, list);
        var id = workspace.Read(() => workspace.Natives[0].Id);
        var pe = workspace.Read(() => workspace.Natives[0].Image);
        var export = pe.Exports.First(e => e.Rva != 0 && e.Name != null && pe.SectionAt(e.Rva) is { IsExecutable: true });
        var declared = int.Parse(list.Split(':')[1].Trim().Split(' ')[0]);
        Assert.True(declared > 10, list[..200]);

        clock.Restart();
        var asm = await tools.Disassemble(id, export.Name!);
        output.WriteLine($"disassemble {export.Name}: {clock.ElapsedMilliseconds} ms\n{string.Join('\n', asm.Split('\n').Take(10))}");
        Assert.Contains(NativeEngineCode.Via, asm);
        Assert.Contains($"{pe.ImageBase + export.Rva:X}", asm);
        Assert.Matches(@"(?m)^  [0-9A-F]+  [0-9A-F]{8} +\S", asm); // ARM64: 4-byte instructions

        var linear = await tools.Disassemble(id, export.Name!, function: false, maxInstructions: 5);
        Assert.Equal(5, linear.Split('\n').Count(l => l.StartsWith("  ", StringComparison.Ordinal)));

        var cfg = await tools.GetCfg(id, export.Name!);
        output.WriteLine(cfg);
        Assert.Contains(NativeEngineCode.Via, cfg);
        Assert.Matches(@"insn  (Return|Jump|ConditionalJump|FallThrough|TailCall|NoReturnCall|IndirectJump|Switch)", cfg);

        var callees = await tools.NativeCallTree(id, export.Name!, depth: 2);
        output.WriteLine(callees);
        Assert.Contains(NativeEngineCode.Via, callees);

        // References to some function that is called: callers in the tree match find_xrefs.
        var called = list.Split('\n').Select(l => System.Text.RegularExpressions.Regex.Match(l, @"^\s*(0x[0-9A-F]+) .*; (\d+) refs\)\s*$"))
            .Where(m => m.Success && int.Parse(m.Groups[2].Value) > 1).Select(m => m.Groups[1].Value).FirstOrDefault();
        Assert.NotNull(called);
        var xrefs = await tools.FindXrefs(id, called!);
        output.WriteLine(string.Join('\n', xrefs.Split('\n').Take(8)));
        Assert.Contains(NativeEngineCode.Via, xrefs);
        Assert.Matches(@"(?m)^\s*0x[0-9A-F]+  Call ", xrefs);
        var callers = await tools.NativeCallTree(id, called!, direction: "callers", depth: 1);
        Assert.True(callers.Split('\n').Length > 2, callers);
    }
}
