using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Linking;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

public sealed class NativeLinkMixedTests(ITestOutputHelper output)
{
    /// <summary>The fixture assembly with the COR header's IL-only flag cleared: loads as .NET and gets a native view.</summary>
    [Fact]
    public void MixedModeAssembliesGetANativeViewThatFollowsTheirLifetime()
    {
        using var dir = new TempDir();
        var bytes = File.ReadAllBytes(Env.FixturePath);
        var pe = PeFile.FromBytes(bytes);
        Assert.True(pe.TryRvaToFileOffset(pe.DataDirectories[PeDirectory.ClrRuntimeHeader].Rva, out var cor));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan((int)cor + 16), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)cor + 16)) & ~1u);
        var path = dir.File("MixedFixture.dll");
        File.WriteAllBytes(path, bytes);

        using var ws = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false });
        var raised = new List<LoadedNative>();
        ws.NativeLoaded += raised.Add;
        var (asm, view) = ws.LoadAny(path);
        Assert.NotNull(asm);
        Assert.NotNull(view);
        Assert.Same(asm, view!.ManagedView);
        Assert.Equal("MixedFixture.dll", view.Id);
        Assert.Equal([view], raised);
        Assert.Same(view, ws.FindNative(asm!.Id));                  // the assembly id names the native view too
        Assert.Equal((asm, view), ws.LoadAny(path));                // loading again is a no-op

        var fresh = ws.Reload(asm);
        var freshView = Assert.Single(ws.Natives);
        Assert.Same(fresh, freshView.ManagedView);
        ws.Unload(fresh);
        Assert.Empty(ws.Natives);
    }

    private const string MixedSource = """
        #include <windows.h>
        using namespace System::Runtime::InteropServices;
        #pragma unmanaged
        extern "C" __declspec(dllexport) int NativeAdd(int a, int b) { return a + b + (int)GetCurrentProcessId(); }
        #pragma managed
        [DllImport("mixedtest.dll", EntryPoint = "NativeAdd")] extern "C" int ViaPInvoke(int a, int b);
        public ref class Mixed
        {
        public:
            static int Call(int x) { return NativeAdd(x, 1); }
            static int Call2(int x) { return ViaPInvoke(x, 2); }
        };
        int ManagedHelper(int x) { return x * 3; }
        #pragma unmanaged
        extern "C" __declspec(dllexport) int CallsManaged(int x) { return ManagedHelper(x) + 1; }
        """;

    /// <summary>Builds a small C++/CLI DLL with MSVC (/clr); null when no Visual C++ toolset with /clr support is installed.</summary>
    private string? BuildMixed(TempDir dir)
    {
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return null;
        File.WriteAllText(dir.File("mixedtest.cpp"), MixedSource);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" x64 >nul && cl /nologo /clr /LD mixedtest.cpp /Fe:mixedtest.dll /link kernel32.lib\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        if (code != 0 || !File.Exists(dir.File("mixedtest.dll")))
        {
            output.WriteLine("cl /clr failed (C++/CLI support missing?):\n" + log);
            return null;
        }
        return dir.File("mixedtest.dll");
    }

    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task CompiledMixedModeAssemblyNavigatesBothWays()
    {
        using var dir = new TempDir();
        var path = BuildMixed(dir);
        if (path == null) { output.WriteLine("no MSVC with /clr: skipped"); return; }
        using var env = new Env(path);
        var view = env.Workspace.FindNative("mixedtest.dll");
        Assert.NotNull(view);
        var code = new NativeCodeService(env.Workspace, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(dir.File("ann")));
        var link = new NativeLinkService(env.Workspace, code);
        var graph = new CallGraphTools(env.Workspace, new CallGraphService(env.Workspace), link);
        var refs = new ReferenceTools(env.Workspace, env.References, link);
        var calls = new NativeCodeTools(env.Workspace, code, env.Pager, link);
        var native = new NativeTools(env.Workspace, env.Pager, code, link);
        await link.WarmUp(null, default);
        var map = link.Mixed(env.Fixture);
        output.WriteLine($"native bodies {map.Bodies.Count}, vtables {map.VTables}, slots {map.Slots.Count}");

        // managed -> native: a native body and a P/Invoke into the same image
        var callees = await graph.GetCallTree("Mixed::Call", "callees", depth: 3);
        output.WriteLine(callees);
        NativeLinkTests.Has(callees, "native: mixedtest.dll!NativeAdd at 0x");
        NativeLinkTests.Has(callees, "[mixedtest.dll]");
        NativeLinkTests.Has(callees, "GetCurrentProcessId");
        NativeLinkTests.Has(await graph.GetCallTree("Mixed::Call2", "callees", depth: 2), "native: mixedtest.dll!NativeAdd at 0x");

        // native -> managed: the exported native function enters ManagedHelper through its vtfixup slot
        var nativeTree = await calls.NativeCallTree("mixedtest.dll", "CallsManaged", depth: 3);
        output.WriteLine(nativeTree);
        NativeLinkTests.Has(nativeTree, "managed: <Module>::ManagedHelper(int)");
        var callers = await graph.GetCallTree("ManagedHelper", "callers", depth: 3);
        output.WriteLine(callers);
        NativeLinkTests.Has(callers, "native: ");
        NativeLinkTests.Has(callers, "through vtfixup slot");
        NativeLinkTests.Has(await refs.FindReferences("ManagedHelper"), "native call: [mixedtest.dll]");

        // the native export back to its managed callers, through both seams
        var back = await refs.FindReferences("mixedtest.dll!NativeAdd");
        output.WriteLine(back);
        NativeLinkTests.Has(back, "Mixed::Call(int)");
        NativeLinkTests.Has(back, "Mixed::Call2(int)");
        var nativeCallers = await calls.NativeCallTree("mixedtest.dll", "NativeAdd", direction: "callers");
        NativeLinkTests.Has(nativeCallers, "managed: <Module>::ViaPInvoke(int, int)");
        NativeLinkTests.Has(await native.ResolveAddress("mixedtest.dll", "NativeAdd"), "native body of managed method <Module>::NativeAdd(int, int)");
    }

    /// <summary>Mixed-mode assemblies found on this machine (IL with native code): loaded, with their seams counted.</summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public async Task MixedModeAssembliesOnThisMachine()
    {
        var roots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Microsoft.NET", "assembly", "GAC_64"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Microsoft.NET", "assembly", "GAC_32"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };
        var sw = Stopwatch.StartNew();
        var found = new List<string>();
        int scanned = 0;
        foreach (var root in roots.Where(Directory.Exists))
            foreach (var file in MsvcCorpus.SafeFiles(root, "*.dll", recursive: true))
            {
                if (sw.Elapsed > TimeSpan.FromSeconds(60) || found.Count >= 12) break;
                scanned++;
                if (IsMixed(file)) found.Add(file);
            }
        output.WriteLine($"scanned {scanned} DLLs in {sw.Elapsed.TotalSeconds:0.0} s: {found.Count} mixed-mode");
        using var dir = new TempDir();
        using var ws = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false });
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(dir.File("ann")));
        var link = new NativeLinkService(ws, code);
        foreach (var file in found)
        {
            LoadedAssembly? asm;
            LoadedNative? view;
            try { (asm, view) = ws.LoadAny(file); }
            catch (ToolError ex) { output.WriteLine($"  {file}: {ex.Message}"); continue; }
            Assert.NotNull(asm);
            Assert.NotNull(view);
            var index = await code.Index(view!, null, default);
            var map = link.Mixed(asm!);
            int bodies = map.Bodies.Values.Distinct().Count(), functions = map.Bodies.Values.Distinct().Count(r => index.FunctionByStart(r) != null);
            int slotUsers = map.Slots.Keys.Count(s => index.RefsTo(s, 1).Count > 0);
            output.WriteLine($"  {file}: {view!.Image.MachineName}, {index.Stats.Functions} functions; {bodies} native bodies ({functions} are functions), " +
                             $"{map.VTables} vtables, {map.Slots.Count} slots ({slotUsers} referenced by native code), {map.UnresolvedSlots} unresolved");
            Assert.Equal(bodies, functions);
        }
    }

    private static bool IsMixed(string file)
    {
        try
        {
            using var stream = File.OpenRead(file);
            using var pe = new PEReader(stream);
            return pe.PEHeaders.CorHeader is { } cor && (cor.Flags & CorFlags.ILOnly) == 0;
        }
        catch (Exception ex) when (ex is BadImageFormatException or IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
    }
}
