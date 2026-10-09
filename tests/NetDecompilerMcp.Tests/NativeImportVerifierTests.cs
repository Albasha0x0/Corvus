using Xunit.Abstractions;
using dnlib.DotNet;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

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
            [DllImport("kernel32.dll")] public static extern void Sizes(int a, long b, double c, IntPtr d, string s, ref int r, bool f, char ch);
        }
        """;

    private static LoadedAssembly Compile(Env env, string name, Platform platform)
    {
        var bytes = Roslyn.Compile(name, Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, platform: platform));
        var dir = Path.Combine(Path.GetTempPath(), "ndm-pinvoke-" + Guid.NewGuid().ToString("N"));
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
        var checks = new NativeImportVerifier(PeFile.Open).Verify(asm, default).ToDictionary(c => c.Method.Split("::")[1].Split('(')[0]);

        Assert.Equal(NativeImportVerifier.Verified, checks["GetCurrentProcess"].Status);
        Assert.Equal(NativeImportVerifier.Decorated, checks["GetModuleHandle"].Status);
        Assert.Equal("GetModuleHandleW", checks["GetModuleHandle"].Export);
        Assert.Equal("MessageBoxA", checks["MessageBox"].Export);
        Assert.Equal(NativeImportVerifier.MissingExport, checks["ExactName"].Status);
        Assert.Contains("GetModuleHandleA", checks["ExactName"].Detail);
        Assert.Equal(NativeImportVerifier.Forwarded, checks["Forwarded"].Status);
        Assert.Contains("RtlAllocateHeap", checks["Forwarded"].Detail);
        Assert.Equal(NativeImportVerifier.DllNotFound, checks["MissingDll"].Status);
        Assert.Equal(NativeImportVerifier.MissingExport, checks["NoSuchExport8f3a"].Status);
        Assert.Equal(NativeImportVerifier.Verified, checks["GetCurrentThreadId"].Status);
        Assert.EndsWith(".dll", checks["GetCurrentThreadId"].ResolvedFile!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api-ms-win", Path.GetFileName(checks["GetCurrentThreadId"].ResolvedFile!), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(NativeImportVerifier.NotChecked, checks["RuntimeCall"].Status);
    }

    [WindowsFact]
    public void X86ModulesBindToSysWow64()
    {
        using var env = new Env();
        var asm = Compile(env, "PInvokes32", Platform.X86);
        var check = new NativeImportVerifier(PeFile.Open).Verify(asm, default).Single(c => c.Method.Contains("GetCurrentProcess"));
        Assert.Equal(NativeImportVerifier.Verified, check.Status);
        Assert.Equal(NativeArch.X86, PeFile.Open(check.ResolvedFile!).Arch);
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
        foreach (var file in Directory.EnumerateFiles(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "System.*.dll"))
        {
            LoadedAssembly asm;
            try { asm = env.Workspace.Load(file); }
            catch (ToolError) { continue; }
            all.AddRange(verifier.Verify(asm, default));
        }
        foreach (var g in all.GroupBy(c => c.Status).OrderBy(g => g.Key))
            output.WriteLine($"{g.Key}: {g.Count()}");
        var missing = all.Where(c => c.Status == NativeImportVerifier.MissingExport).ToList();
        foreach (var c in missing.Concat(all.Where(c => c.Status == NativeImportVerifier.DllNotFound)).Take(60))
            output.WriteLine($"  {c.Status} {c.Module}!{c.EntryPoint} ({c.Method}): {c.Detail}");
        Assert.True(all.Count > 500, $"{all.Count} declarations");
        Assert.Empty(missing.Select(c => $"{c.Module}!{c.EntryPoint}: {c.Detail}"));
        Assert.Empty(all.Where(c => c.Status == NativeImportVerifier.DllNotFound).Select(c => $"{c.Module}!{c.EntryPoint}: {c.Detail}"));
    }
}
