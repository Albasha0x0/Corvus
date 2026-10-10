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

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeAnalysisTools Analysis, NativeEngineService Engines);

    private Rig Setup(IdaProviderOptions? ida = null)
    {
        var options = new ServerOptions { TimeoutSeconds = 120, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(ida ?? new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code);
        _owned.Add(engines);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeCodeTools(workspace, code, pager, null, engines, names), new NativeAnalysisTools(workspace, engines, pager, names, code), engines);
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
        var tools = Setup(new IdaProviderOptions { InstallDirectory = _dir.File("no-ida-here"), CacheRoot = _dir.File("cache") }).Tools;
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
        var (workspace, _, tools, _, _) = Setup();
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

    private const string StaticSource = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        static int cmp(const void* a, const void* b) { return *(const int*)a - *(const int*)b; }
        int main(int argc, char** argv)
        {
            int v[64];
            char buf[128];
            for (int i = 0; i < 64; i++) v[i] = rand();
            qsort(v, 64, sizeof(int), cmp);
            snprintf(buf, sizeof buf, "%s %d", argv[0], v[0]);
            char* copy = _strdup(buf);
            printf("%s %zu\n", copy, strlen(copy));
            free(copy);
            FILE* f = fopen("x.txt", "r");
            if (f) fclose(f);
            return (int)strtol(argv[argc - 1], NULL, 10);
        }
        """;

    /// <summary>
    /// A statically linked (/MT) MSVC build: the CRT functions IDA recognizes become the ida name layer once a session is
    /// open (list_functions alone does not start IDA for x64), flagged library; user names still win.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Library_functions_IDA_recognizes_name_a_static_MSVC_build()
    {
        var path = CallArgumentTests.BuildSample(_dir, "x64", StaticSource, "static", "/MT");
        if (path == null) { output.WriteLine("no MSVC build tools"); return; }
        var rig = Setup();
        var before = await rig.Tools.ListFunctions(path, limit: 5000);
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        Assert.Null(rig.Engines.LibraryNames(native));
        Assert.DoesNotContain("[library", before);

        var clock = Stopwatch.StartNew();
        await rig.Analysis.DecompileNative(native.Id, $"rva:0x{native.Image.EntryPointRva:X}");
        var imported = await rig.Engines.LibraryNames(native)!;
        var opened = clock.Elapsed;
        var after = await rig.Tools.ListFunctions(native.Id, limit: 5000);
        var rows = after.Split('\n').Where(l => l.StartsWith("  0x", StringComparison.Ordinal)).ToList();
        var library = rows.Where(r => r.Contains("library") && r.Contains(", ida;")).ToList();
        output.WriteLine($"{Path.GetFileName(path)} ({new FileInfo(path).Length:N0} bytes): {rows.Count} functions, {imported} library names from IDA, " +
                         $"{library.Count} of the listed functions named by them ({100.0 * library.Count / rows.Count:0.0}%); IDA open + import {opened.TotalSeconds:0.0} s");
        output.WriteLine(string.Join('\n', library.Take(15)));
        Assert.True(imported >= 50, $"{imported} library names");
        Assert.True(library.Count >= 50);
        Assert.Contains(library, r => r.Contains("qsort") || r.Contains("strtol") || r.Contains("_strdup") || r.Contains("memset"));
        Assert.DoesNotContain(rows, r => r.Contains("unknown_libname_"));

        // A user name wins over the library name.
        var index = await rig.Code.Index(native, null, default);
        var first = index.Functions.First(f => EngineLibraryNames.IsLibrary(index, f.Start));
        new NativeEditService(rig.Workspace, rig.Code).Rename(native, index, first.Start, "MyLibraryFunction", false);
        Assert.Contains("MyLibraryFunction  [library", await rig.Tools.ListFunctions(native.Id, filter: "MyLibraryFunction"));
    }
}
