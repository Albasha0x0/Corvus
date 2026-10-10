using System.Reflection.Metadata.Ecma335;
using dnlib.DotNet;
using Xunit.Abstractions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// verify_native_imports verdicts beyond the export check: run-time loading found in the IL (dynamic_only), and
/// assemblies with obfuscator-style malformed metadata (synthesized by patching a compiled fixture), which must give
/// typed results with locations in verify_native_imports, load_assembly, get_assembly_info and the decompiler.
/// </summary>
public class NativeImportVerdictTests(ITestOutputHelper output)
{
    private const string Source = """
        using System;
        using System.Runtime.InteropServices;
        public static class N
        {
            [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
            [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
            [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
            [DllImport("plugin_engine_7c1e.dll")] public static extern int EngineStart();
            [DllImport("absent_lib_51d0.dll")] public static extern void Absent();
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr LoadLibrary(string name);
            [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string name);
            delegate int Start();

            public static IntPtr Engine()
            {
                var h = NativeLibrary.Load("plugin_engine_7c1e.dll");
                return NativeLibrary.GetExport(h, "EngineStart");
            }

            public static int Helper()
            {
                var lib = "helper_9a2d.dll";
                var m = LoadLibrary(lib);
                var p = GetProcAddress(m, "HelperInit");
                return Marshal.GetDelegateForFunctionPointer<Start>(p)();
            }
        }
        """;

    private const string Resolver = """
        public static class R
        {
            public static void Install() =>
                System.Runtime.InteropServices.NativeLibrary.SetDllImportResolver(typeof(R).Assembly, (name, asm, path) => System.IntPtr.Zero);
        }
        """;

    private static Dictionary<string, NativeImportVerifier.Check> ByMethod(NativeImportVerifier.Result result) =>
        result.Checks.ToDictionary(c => c.Method.Split("::")[1].Split('(')[0]);

    [WindowsFact]
    public void RunTimeLoadingMakesUnresolvedDeclarationsDynamicOnly()
    {
        using var env = new Env();
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("Dyn.dll"), Fixture());
        var result = new NativeImportVerifier(PeFile.Open).Verify(env.Workspace.Load(dir.File("Dyn.dll")), default);
        var checks = ByMethod(result);
        Assert.Equal("dynamic_only/library_loaded_at_run_time", $"{checks["EngineStart"].Status}/{checks["EngineStart"].Reason}");
        Assert.Contains("native_library_load in N::Engine()", checks["EngineStart"].Detail);
        // A DllImportResolver may send any declaration elsewhere: unresolved ones become dynamic_only.
        Assert.Equal("dynamic_only/dll_import_resolver", $"{checks["Absent"].Status}/{checks["Absent"].Reason}");
        Assert.Contains("R::Install()", checks["Absent"].Detail);
        Assert.Equal("verified/exact", $"{checks["GetCurrentProcess"].Status}/{checks["GetCurrentProcess"].Reason}");
        Assert.Equal("verified/suffixed", $"{checks["LoadLibrary"].Status}/{checks["LoadLibrary"].Reason}");

        var loads = result.DynamicLoads.Select(d => $"{d.Kind} {d.Library ?? "-"} {d.Export ?? "-"}").ToList();
        output.WriteLine(string.Join("\n", loads));
        Assert.Contains("native_library_load plugin_engine_7c1e.dll -", loads);
        Assert.Contains("native_library_get_export plugin_engine_7c1e.dll EngineStart", loads);
        Assert.Contains("load_library helper_9a2d.dll -", loads); // through a local
        Assert.Contains("get_proc_address helper_9a2d.dll HelperInit", loads);
        Assert.Contains("delegate_for_function_pointer helper_9a2d.dll HelperInit", loads);
        Assert.Contains("dll_import_resolver - -", loads);
    }

    /// <summary>One compile shared by the tests here (a release build is cached per name and source).</summary>
    private static byte[] Fixture() => Roslyn.Release("Dyn", Source + Resolver);

    /// <summary>The compiled fixture with one obfuscator-style change each.</summary>
    internal static Dictionary<string, byte[]> MalformedCases(byte[] clean)
    {
        int map = MetadataPatcher.ImplMapRidOf(clean, "GetCurrentThreadId");
        var (row, _) = MetadataPatcher.Row(clean, TableIndex.ImplMap, map);
        var (modref, _) = MetadataPatcher.Row(clean, TableIndex.ModuleRef, 1);
        return new()
        {
            ["duplicate_tables"] = MetadataPatcher.RewriteStreams(clean, s => [.. s, new("#~", new byte[64])]),
            ["duplicate_tables_first"] = MetadataPatcher.RewriteStreams(clean, s => [new("#~", new byte[64]), .. s]),
            ["duplicate_strings"] = MetadataPatcher.RewriteStreams(clean, s => [.. s, new("#Strings", "\0junk\0"u8.ToArray())]),
            ["bogus_streams"] = MetadataPatcher.RewriteStreams(clean, s => [.. s, new("#Koi", new byte[16]), new("#GUlD", new byte[16])]),
            ["extra_table_bits"] = MetadataPatcher.RewriteTablesHeader(clean, [0x2D, 0x3F], null),
            ["extra_data"] = MetadataPatcher.RewriteTablesHeader(clean, [], 0xDEADBEEF),
            ["implmap_scope"] = MetadataPatcher.SetUInt16(clean, row + 6, 0x7F),
            ["implmap_name"] = MetadataPatcher.SetUInt16(clean, row + 4, 0xFFF0),
            ["moduleref_name"] = MetadataPatcher.SetUInt16(clean, modref, 0xFFF0),
        };
    }

    [WindowsFact]
    public void MalformedImplMapRowsAreUnresolvedWithTheirLocation()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var cases = MalformedCases(Fixture());
        foreach (var (name, code, method) in new[] { ("implmap_scope", "implmap_scope_out_of_range", "GetCurrentThreadId"), ("moduleref_name", "moduleref_name_out_of_range", "GetCurrentProcess") })
        {
            File.WriteAllBytes(dir.File(name + ".dll"), cases[name]);
            var result = new NativeImportVerifier(PeFile.Open).Verify(env.Workspace.Load(dir.File(name + ".dll")), default);
            var check = ByMethod(result)[method];
            Assert.Equal("unresolved/malformed_metadata", $"{check.Status}/{check.Reason}");
            Assert.StartsWith(code, check.Detail);
            Assert.Matches(@"#~ (ImplMap|ModuleRef) row \d+ \(token 0x1[CA]0000\d\d\).*, file offset 0x[0-9A-F]+", check.Location);
            Assert.Contains(result.MetadataIssues, i => i.Code == code);
            Assert.Equal("verified/exact", $"{ByMethod(result)["GetSystemMetrics"].Status}/{ByMethod(result)["GetSystemMetrics"].Reason}");
        }
    }

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void ObfuscatorStyleMetadataGivesTypedResultsWithLocations()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var expected = new Dictionary<string, string>
        {
            ["duplicate_tables"] = "duplicate_stream", ["duplicate_tables_first"] = "duplicate_stream", ["duplicate_strings"] = "duplicate_stream",
            ["bogus_streams"] = "unknown_stream", ["extra_table_bits"] = "unknown_tables", ["extra_data"] = "extra_data_flag",
            ["implmap_scope"] = "implmap_scope_out_of_range", ["implmap_name"] = "implmap_name_out_of_range", ["moduleref_name"] = "moduleref_name_out_of_range",
        };
        foreach (var (name, bytes) in MalformedCases(Fixture()))
        {
            var path = dir.File(name + ".dll");
            File.WriteAllBytes(path, bytes);
            LoadedAssembly asm;
            try { asm = env.Workspace.Load(path); }
            catch (ToolError ex)
            {
                output.WriteLine($"{name}: load refused ({ex.Code}): {ex.Message}");
                Assert.Equal(ErrorCode.MalformedInput, ex.Code);
                Assert.Contains("file offset 0x", ex.Message);
                continue;
            }
            var result = env.Workspace.Read(() => new NativeImportVerifier(PeFile.Open).Verify(asm, default));
            var issue = result.MetadataIssues.First(i => i.Code == expected[name]);
            Assert.NotNull(issue.FileOffset);
            Assert.False(string.IsNullOrEmpty(issue.Location));
            var info = env.Workspace.Read(() => env.Report.Build(asm));
            Assert.Contains($"{expected[name]} at ", info);

            string decompiled;
            try
            {
                decompiled = env.Workspace.Read(() => asm.Module.Find("N", false) is { } n ? env.Decompiler.DecompileType(asm, n, default) : "(no type N)");
            }
            catch (ToolError ex) { decompiled = $"error ({ex.Code}): {ex.Message}"; }
            output.WriteLine($"{name}: {issue.Code} at {issue.Location}, {issue.FileOffset}: {issue.Detail}");
            output.WriteLine($"   {string.Join(", ", result.Checks.GroupBy(c => $"{c.Status}/{c.Reason}").Select(g => $"{g.Key} {g.Count()}"))}; " +
                             $"decompile: {decompiled.Split('\n')[0]}");
            if (name == "duplicate_strings")
                Assert.All(result.Checks, c => Assert.Equal("malformed_metadata", c.Reason));
            if (name is "bogus_streams" or "extra_table_bits" or "extra_data" or "duplicate_tables_first")
            {
                Assert.Contains("static extern int GetSystemMetrics", decompiled);
                Assert.Equal("verified", ByMethod(result)["GetCurrentThreadId"].Status);
            }
        }
    }
}
