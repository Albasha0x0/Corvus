using Xunit.Abstractions;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

public class NativeImportVerifierTests
{
    private const string Source = """
        using System;
        using System.Runtime.InteropServices;
        public static class N
        {
            [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
            [DllImport("kernel32", CharSet = CharSet.Unicode)] public static extern IntPtr GetModuleHandle(string name);
            [DllImport("user32.dll", CharSet = CharSet.Ansi)] public static extern int MessageBox(IntPtr h, string text, string caption, uint type);
            [DllImport("kernel32.dll", EntryPoint = "GetModuleHandle", ExactSpelling = true)] public static extern IntPtr ExactName(string name);
            [DllImport("kernel32.dll", EntryPoint = "HeapAlloc")] public static extern IntPtr Forwarded(IntPtr heap, uint flags, UIntPtr size);
            [DllImport("no_such_library_8f3a.dll")] public static extern void MissingDll();
            [DllImport("kernel32.dll")] public static extern void NoSuchExport8f3a();
            [DllImport("api-ms-win-core-processthreads-l1-1-0.dll")] public static extern uint GetCurrentThreadId();
            [DllImport("QCall")] public static extern void RuntimeCall();
            [DllImport("kernel32.dll", EntryPoint = "#1")] public static extern uint GetTickCount();
            [DllImport("kernel32.dll")] public static extern void Sizes(int a, long b, double c, IntPtr d, string s, ref int r, bool f, char ch);
        }
        """;

    private static LoadedAssembly Compile(Env env, string name, Platform platform)
    {
        var bytes = Roslyn.Compile(name, Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, platform: platform));
        var dir = Path.Combine(Path.GetTempPath(), "corvus-test-pinvoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name + ".dll");
        File.WriteAllBytes(path, bytes);
        return env.Workspace.Load(path);
    }

    [WindowsFact]
    public void ChecksEachDeclarationAgainstTheDllExports()
    {
        using var env = new Env();
        var asm = Compile(env, "PInvokes64", Platform.X64);
        var checks = new NativeImportVerifier(PeFile.Open).Verify(asm, default).Checks.ToDictionary(c => c.Method.Split("::")[1].Split('(')[0]);
        string Verdict(string method) => $"{checks[method].Status}/{checks[method].Reason}";

        Assert.Equal("verified/exact", Verdict("GetCurrentProcess"));
        Assert.Equal("verified/suffixed", Verdict("GetModuleHandle"));
        Assert.Equal("GetModuleHandleW", checks["GetModuleHandle"].Export);
        Assert.Equal("MessageBoxA", checks["MessageBox"].Export);
        Assert.Equal("contradicted/exact_spelling", Verdict("ExactName"));
        Assert.Contains("GetModuleHandleA", checks["ExactName"].Detail);
        Assert.Equal("verified/forwarded", Verdict("Forwarded"));
        Assert.Contains("RtlAllocateHeap", checks["Forwarded"].Detail);
        Assert.Equal("unresolved/dll_not_found", Verdict("MissingDll"));
        Assert.Equal("contradicted/missing_export", Verdict("NoSuchExport8f3a"));
        Assert.Equal("verified/exact", Verdict("GetCurrentThreadId"));
        Assert.EndsWith(".dll", checks["GetCurrentThreadId"].ResolvedFile!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api-ms-win", Path.GetFileName(checks["GetCurrentThreadId"].ResolvedFile!), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("not_checked/runtime_internal", Verdict("RuntimeCall"));
        Assert.Equal("contradicted/ordinal_points_elsewhere", Verdict("GetTickCount"));
        Assert.Contains("is ordinal", checks["GetTickCount"].Detail);
        Assert.All(checks.Values, c => Assert.Null(c.Location));
    }

    [WindowsFact]
    public void X86ModulesBindToSysWow64()
    {
        using var env = new Env();
        var asm = Compile(env, "PInvokes32", Platform.X86);
        var check = new NativeImportVerifier(PeFile.Open).Verify(asm, default).Checks.Single(c => c.Method.Contains("GetCurrentProcess"));
        Assert.Equal(NativeImportVerifier.Verified, check.Status);
        Assert.Equal(NativeArch.X86, PeFile.Open(check.ResolvedFile!).Arch);
    }

    /// <summary>A DLL next to the assembly exporting Foo (1), an unnamed ordinal (2), Fwd -> KERNEL32.HeapAlloc (3) and Other -> a missing DLL (4).</summary>
    private static byte[] AppLocalDll()
    {
        var b = new PeBuilder();
        var text = b.Add(".text", [0xC3, 0xC3], 0x60000020);
        uint dir = 0, size = 0;
        b.Add(".edata", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(40);
            uint dll = blob.Ascii("applib.dll");
            uint eat = blob.U32(text.Rva);
            blob.U32(text.Rva + 1);
            uint fwdSlot = blob.U32(0);
            uint otherSlot = blob.U32(0);
            uint foo = blob.Ascii("Foo"), fwd = blob.Ascii("Fwd"), other = blob.Ascii("Other");
            uint fwdTarget = blob.Ascii("KERNEL32.HeapAlloc"), otherTarget = blob.Ascii("helper_missing_7c1.Thing");
            blob.Align(4);
            uint names = blob.U32(foo);
            blob.U32(fwd);
            blob.U32(other);
            uint ordinals = blob.U16(0);
            blob.U16(2);
            blob.U16(3);
            size = blob.Here - dir;
            blob.Patch32(fwdSlot, fwdTarget);
            blob.Patch32(otherSlot, otherTarget);
            blob.Patch32(dir + 12, dll);
            blob.Patch32(dir + 16, 1);
            blob.Patch32(dir + 20, 4);
            blob.Patch32(dir + 24, 3);
            blob.Patch32(dir + 28, eat);
            blob.Patch32(dir + 32, names);
            blob.Patch32(dir + 36, ordinals);
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (dir, size);
        b.Characteristics = 0x2022;
        return b.Build();
    }

    /// <summary>On a host without Windows system DLLs: app-local DLLs are still checked with the PE reader; system DLLs are system_dll_not_on_host.</summary>
    [Fact]
    public void WithoutSystemDlls_AppLocalDllsAreStillChecked()
    {
        const string source = """
            using System;
            using System.Runtime.InteropServices;
            public static class H
            {
                [DllImport("applib")] public static extern void Foo();
                [DllImport("APPLIB.dll", EntryPoint = "#2")] public static extern void ByOrdinal();
                [DllImport("applib.dll")] public static extern void Missing7c1();
                [DllImport("applib.dll")] public static extern void Fwd();
                [DllImport("applib.dll")] public static extern void Other();
                [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
                [DllImport("api-ms-win-core-processthreads-l1-1-0.dll")] public static extern uint GetCurrentThreadId();
                [DllImport("no_such_library_8f3a.dll")] public static extern void MissingDll();
            }
            """;
        using var env = new Env();
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("applib.dll"), AppLocalDll());
        File.WriteAllBytes(dir.File("Host.dll"), Roslyn.Compile("Host", source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        var asm = env.Workspace.Load(dir.File("Host.dll"));
        var checks = env.Workspace.Read(() => new NativeImportVerifier(PeFile.Open, hostHasSystemDlls: false).Verify(asm, default))
            .Checks.ToDictionary(c => c.Method.Split("::")[1].Split('(')[0]);
        string Verdict(string method) => $"{checks[method].Status}/{checks[method].Reason}";

        Assert.Equal("verified/exact", Verdict("Foo"));
        Assert.Equal("applib.dll", Path.GetFileName(checks["Foo"].ResolvedFile), ignoreCase: true);
        Assert.Equal("verified/ordinal", Verdict("ByOrdinal"));
        Assert.Equal("contradicted/missing_export", Verdict("Missing7c1"));
        Assert.Equal("unresolved/system_dll_not_on_host", Verdict("Fwd"));
        Assert.Contains("KERNEL32.HeapAlloc", checks["Fwd"].Detail);
        Assert.Equal("unresolved/forwarder_dll_not_found", Verdict("Other"));
        Assert.Equal("unresolved/system_dll_not_on_host", Verdict("GetCurrentProcess"));
        Assert.Equal("unresolved/system_dll_not_on_host", Verdict("GetCurrentThreadId"));
        Assert.Equal("unresolved/dll_not_found", Verdict("MissingDll"));
        Assert.True(NativeImportVerifier.IsSystemDll("USER32.DLL") && NativeImportVerifier.IsSystemDll("winspool.drv") && !NativeImportVerifier.IsSystemDll("applib.dll"));
    }

    [Fact]
    public void StdcallStackBytesFollowX86ArgumentSizes()
    {
        using var env = new Env();
        var asm = Compile(env, "PInvokeSizes", Platform.X86);
        var sizes = asm.Module.Find("N", false)!.FindMethod("Sizes");
        // int 4, long 8, double 8, IntPtr 4, string 4, ref 4, bool 4, char 4
        Assert.Equal(40, NativeImportVerifier.StackBytes(sizes));
    }

    [Fact]
    public void CandidatesFollowTheRuntimeLookupOrder()
    {
        Assert.Equal(["FooW", "Foo"], NativeImportVerifier.Candidates("Foo", "Unicode", false, null).Select(c => c.Name));
        Assert.Equal(["Foo", "FooA", "_Foo@8", "_FooA@8"], NativeImportVerifier.Candidates("Foo", "Ansi", false, 8).Select(c => c.Name));
        Assert.Equal(["Foo"], NativeImportVerifier.Candidates("Foo", "Unicode", true, null).Select(c => c.Name));
    }

    [WindowsFact]
    public void ApiSetMapResolvesContractsToHostDlls()
    {
        var map = ApiSetSchema.FromSystem(PeFile.Open);
        Assert.NotNull(map);
        Assert.True(map!.Count > 100, $"{map.Count} entries");
        var host = map.Resolve("api-ms-win-core-processthreads-l1-1-3.dll");
        Assert.NotNull(host);
        Assert.Contains(host!.ToLowerInvariant(), new[] { "kernel32.dll", "kernelbase.dll" });
        Assert.Null(map.Resolve("api-ms-win-not-a-contract-l1-1-0.dll"));
        Assert.True(ApiSetSchema.IsApiSetName("ext-ms-win-foo-l1-1-0"));
        Assert.False(ApiSetSchema.IsApiSetName("kernel32.dll"));
    }
}

public class NativeImportVerifierSweepTests(ITestOutputHelper output)
{
    /// <summary>Every DllImport of the running .NET runtime's libraries: none may point at a missing export of a DLL that exists.</summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void RuntimeLibrariesBindToRealExports()
    {
        using var env = new Env();
        var verifier = new NativeImportVerifier(PeFile.Open);
        var all = new List<NativeImportVerifier.Check>();
        int dynamic = 0, issues = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        foreach (var file in Directory.EnumerateFiles(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "System.*.dll"))
        {
            LoadedAssembly asm;
            try { asm = env.Workspace.Load(file); }
            catch (ToolError) { continue; }
            var result = verifier.Verify(asm, default);
            all.AddRange(result.Checks);
            dynamic += result.DynamicLoads.Count;
            issues += result.MetadataIssues.Count;
        }
        output.WriteLine($"{all.Count} declarations in {sw.Elapsed.TotalSeconds:0.0} s; {dynamic} run-time loading sites; {issues} metadata issues");
        foreach (var g in all.GroupBy(c => $"{c.Status} {c.Reason}").OrderBy(g => g.Key))
            output.WriteLine($"{g.Key}: {g.Count()}");
        var contradicted = all.Where(c => c.Status == NativeImportVerifier.Contradicted).ToList();
        foreach (var c in contradicted.Concat(all.Where(c => c.Status == NativeImportVerifier.Unresolved)).Take(60))
            output.WriteLine($"  {c.Status} {c.Reason} {c.Module}!{c.EntryPoint} ({c.Method}): {c.Detail}");
        Assert.True(all.Count > 500, $"{all.Count} declarations");
        Assert.Empty(contradicted.Select(c => $"{c.Module}!{c.EntryPoint}: {c.Reason} {c.Detail}"));
        Assert.Empty(all.Where(c => c.Status == NativeImportVerifier.Unresolved).Select(c => $"{c.Module}!{c.EntryPoint}: {c.Reason} {c.Detail}"));
        Assert.Equal(0, issues);
    }
}
