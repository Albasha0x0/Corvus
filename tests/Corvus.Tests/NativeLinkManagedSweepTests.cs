using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

public sealed class NativeLinkManagedSweepTests(ITestOutputHelper output)
{
    /// <summary>System DLL file names differ in case between imports, API set hosts and the disk.</summary>
    private static void HasI(string text, string expected) =>
        Assert.True(text.Contains(expected, StringComparison.OrdinalIgnoreCase), $"'{expected}' not in:\n{text}");

    /// <summary>
    /// Every P/Invoke of the running runtime's libraries bound by the navigation service agrees with
    /// verify_native_imports: resolved exactly where the verifier finds the export, with the same DLL.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void RuntimePInvokesBindLikeTheVerifier()
    {
        using var dir = new TempDir();
        using var env = new Env();
        var link = new NativeLinkService(env.Workspace, new NativeCodeService(env.Workspace, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(dir.File("ann"))));
        var verifier = new NativeImportVerifier(PeFile.Open);
        int total = 0, agree = 0;
        var byStatus = new Dictionary<string, int>();
        var disagreements = new List<string>();
        var sw = Stopwatch.StartNew();
        foreach (var file in Directory.EnumerateFiles(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "System.*.dll"))
        {
            LoadedAssembly asm;
            try { asm = env.Workspace.Load(file); }
            catch (ToolError) { continue; }
            var checks = verifier.Verify(asm, default).Checks.ToDictionary(c => c.Method);
            foreach (var type in asm.Module.GetTypes())
                foreach (var m in type.Methods)
                {
                    if (m.ImplMap == null) continue;
                    total++;
                    var b = link.BindPInvoke(asm, m)!;
                    var key = b.Status == NativeLinkService.Unresolved ? $"unresolved {b.Reason}" : b.Status;
                    byStatus[key] = byStatus.GetValueOrDefault(key) + 1;
                    var check = checks[Format.MemberLabel(m)];
                    bool verifierResolved = check.Status == NativeImportVerifier.Verified;
                    bool same = verifierResolved == (b.Status != NativeLinkService.Unresolved)
                                && (!verifierResolved || string.Equals(b.Link.Hops[0].File, check.ResolvedFile, StringComparison.OrdinalIgnoreCase));
                    if (same) agree++;
                    else disagreements.Add($"{Format.MemberLabel(m)}: verifier {check.Status} {check.ResolvedFile}, link {NativeLinkService.Describe(b)}");
                }
        }
        output.WriteLine($"{total} P/Invokes in {sw.Elapsed.TotalSeconds:0.0} s: {string.Join(", ", byStatus.OrderByDescending(s => s.Value).Select(s => $"{s.Key} {s.Value}"))}; agree with verify_native_imports: {agree}");
        foreach (var d in disagreements.Take(30)) output.WriteLine("  " + d);
        Assert.True(total > 500, $"{total} P/Invokes");
        Assert.Empty(disagreements);
    }

    private const string Program = """
        using System;
        using System.Runtime.InteropServices;
        public static class Native
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
            [DllImport("kernel32.dll")] public static extern uint GetCurrentProcessId();
            [DllImport("kernel32.dll", EntryPoint = "HeapAlloc")] public static extern IntPtr Alloc(IntPtr heap, uint flags, UIntPtr size);
        }
        public static class Program
        {
            public static void Main() { Open(); Console.WriteLine(Native.GetCurrentProcessId()); Native.Alloc(IntPtr.Zero, 0, UIntPtr.Zero); }
            static void Open() => Native.CreateFile("x", 0, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        }
        """;

    /// <summary>
    /// A .NET program calling kernel32, with kernel32, KERNELBASE and ntdll loaded: callee trees cross into the
    /// native functions (the jump thunk in kernel32 followed to KERNELBASE, the HeapAlloc forwarder to ntdll) at the
    /// export addresses, and the native exports list the managed callers back.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task ProgramCallingKernel32CrossesIntoNative()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var kernel32 = Path.Combine(system, "kernel32.dll");
        var kernelbase = Path.Combine(system, "KernelBase.dll");
        var ntdll = Path.Combine(system, "ntdll.dll");
        if (!File.Exists(kernel32) || !File.Exists(kernelbase) || !File.Exists(ntdll)) return;
        using var dir = new TempDir();
        var path = dir.File("CallsKernel32.dll");
        File.WriteAllBytes(path, Roslyn.Compile("CallsKernel32", Program, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, platform: Platform.X64)));
        using var env = new Env(path);
        foreach (var f in new[] { kernel32, kernelbase, ntdll }) env.Workspace.LoadAny(f);
        var code = new NativeCodeService(env.Workspace, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(dir.File("ann")));
        var link = new NativeLinkService(env.Workspace, code);
        var graph = new CallGraphTools(env.Workspace, new CallGraphService(env.Workspace), env.Pager, link);
        var refs = new ReferenceTools(env.Workspace, env.References, env.Pager, link);
        var sw = Stopwatch.StartNew();
        await link.WarmUp(null, default);
        output.WriteLine($"indexed kernel32, KERNELBASE and ntdll in {sw.Elapsed.TotalSeconds:0.0} s");

        string Va(string file, string export)
        {
            var pe = PeFile.Open(file);
            return NativeAddress.Va(pe, pe.Exports.Single(e => e.Name == export).Rva);
        }
        var tree = await graph.GetCallTree("Program::Main", "callees", depth: 5, limit: 5_000);
        output.WriteLine(tree);
        HasI(tree, $"native: kernel32.dll!CreateFileW -> KERNELBASE.dll!CreateFileW at {Va(kernelbase, "CreateFileW")} [KernelBase.dll]");
        HasI(tree, $"native: kernel32.dll!HeapAlloc -> ntdll.dll!RtlAllocateHeap at {Va(ntdll, "RtlAllocateHeap")} [ntdll.dll]");
        HasI(tree, $"native: kernel32.dll!GetCurrentProcessId");

        // KERNELBASE!CreateFileW calls further KERNELBASE / ntdll code: the native subtree continues below the P/Invoke.
        var createFile = tree.Split('\n').SkipWhile(l => !l.Contains("native: kernel32.dll!CreateFileW")).Skip(1).TakeWhile(l => l.StartsWith("        ")).ToList();
        output.WriteLine($"{createFile.Count} native lines under CreateFileW");
        Assert.NotEmpty(createFile);

        var back = await refs.FindReferences("KERNELBASE.dll!CreateFileW");
        output.WriteLine(back[..Math.Min(back.Length, 3000)]);
        HasI(back, "Native::CreateFile(string, uint, uint, nint, uint, uint, nint)  [CallsKernel32]");
        HasI(back, "Program::Open()");
        HasI(back, "[KernelBase.dll]");
        var callers = await graph.GetCallTree("native:kernel32.dll!HeapAlloc", "callers", depth: 2, limit: 5_000);
        HasI(callers, "Native::Alloc(");
        HasI(callers, "Program::Main()");
    }
}
