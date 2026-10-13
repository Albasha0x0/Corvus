using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Linking;
using Corvus.Native.Pe;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>
/// Small x64 DLLs for cross-image tests: exports (code or forwarders), imports by name or ordinal, and code that
/// calls or jumps through import slots ("call [Module!Name]" by slot).
/// </summary>
internal static class LinkedImages
{
    public const uint Text = 0x1000, Data = 0x2000;

    /// <param name="exports">Name and either a code offset into <paramref name="code"/> or a forwarder ("module.name").</param>
    /// <param name="imports">Module and names ("#n" imports by ordinal).</param>
    /// <param name="code">Code bytes, given the slot RVA of each "module!name" import (and of each item <paramref name="data"/> adds).</param>
    /// <param name="data">Adds read-only data (strings, pointer tables) and returns their RVAs by name; pointers it lists are relocated.</param>
    public static byte[] Build(string dllName, (string Name, object Target)[] exports, (string Module, string[] Names)[] imports,
        Func<Dictionary<string, uint>, byte[]> code, Func<PeBlob, List<uint>, Dictionary<string, uint>>? data = null)
    {
        var blob = new PeBlob(Data);
        var slots = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
        uint descriptors = imports.Length > 0 ? blob.Zero(20 * (imports.Length + 1)) : 0;
        for (int m = 0; m < imports.Length; m++)
        {
            var (module, names) = imports[m];
            uint moduleName = blob.Ascii(module);
            var hints = new List<ulong>();
            foreach (var n in names)
            {
                if (n.StartsWith('#')) { hints.Add(0x8000000000000000UL | ushort.Parse(n[1..])); continue; }
                blob.Align(2);
                uint hint = blob.U16(0);
                blob.Ascii(n);
                hints.Add(hint);
            }
            blob.Align(8);
            uint ilt = blob.Here;
            foreach (var h in hints) blob.U64(h);
            blob.U64(0);
            uint iat = blob.Here;
            for (int i = 0; i < hints.Count; i++) slots[$"{module}!{names[i]}"] = blob.U64(hints[i]);
            blob.U64(0);
            uint d = descriptors + (uint)(20 * m);
            blob.Patch32(d, ilt);
            blob.Patch32(d + 12, moduleName);
            blob.Patch32(d + 16, iat);
        }

        var relocations = new List<uint>();
        if (data != null)
            foreach (var (k, v) in data(blob, relocations)) slots[k] = v;

        uint exportDir = 0, exportSize = 0;
        if (exports.Length > 0)
        {
            blob.Align(4);
            exportDir = blob.Zero(40);
            uint dll = blob.Ascii(dllName);
            blob.Align(4);
            uint eat = blob.Zero(4 * exports.Length);
            var sorted = exports.Select((e, i) => (e.Name, Index: i)).OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
            var nameRvas = sorted.Select(e => blob.Ascii(e.Name)).ToList();
            for (int i = 0; i < exports.Length; i++)
                blob.Patch32(eat + 4 * (uint)i, exports[i].Target is string forward ? blob.Ascii(forward) : Text + (uint)(int)exports[i].Target);
            blob.Align(4);
            uint names = blob.Here;
            foreach (var r in nameRvas) blob.U32(r);
            uint ordinals = blob.Here;
            foreach (var e in sorted) blob.U16((ushort)e.Index);
            blob.Patch32(exportDir + 12, dll);
            blob.Patch32(exportDir + 16, 1);
            blob.Patch32(exportDir + 20, (uint)exports.Length);
            blob.Patch32(exportDir + 24, (uint)exports.Length);
            blob.Patch32(exportDir + 28, eat);
            blob.Patch32(exportDir + 32, names);
            blob.Patch32(exportDir + 36, ordinals);
            exportSize = blob.Here - exportDir;
        }

        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x180000000, Characteristics = 0x2022 };
        var text = b.Add(".text", code(slots), 0x60000020);
        b.EntryPoint = text.Rva;
        b.Add(".rdata", blob.ToArray());
        if (relocations.Count > 0)
            b.Add(".reloc", rva =>
            {
                var r = new PeBlob(rva);
                foreach (var page in relocations.GroupBy(x => x & ~0xFFFu))
                {
                    uint block = r.U32(page.Key);
                    uint size = r.U32(0);
                    foreach (var x in page) r.U16((ushort)(0xA000 | (x & 0xFFF)));
                    r.Align(4);
                    r.Patch32(size, r.Here - block);
                }
                b.Directories[PeDirectory.BaseRelocation] = (rva, (uint)r.Length);
                return r.ToArray();
            }, 0x42000040);
        if (imports.Length > 0) b.Directories[PeDirectory.Import] = (descriptors, 20u * (uint)(imports.Length + 1));
        if (exports.Length > 0) b.Directories[PeDirectory.Export] = (exportDir, exportSize);
        return b.Build();
    }

    /// <summary>x64 code assembler for the samples: call/jmp [rip+slot] and ret, tracking the current RVA.</summary>
    public sealed class Code(Dictionary<string, uint> slots)
    {
        private readonly List<byte> _bytes = [];
        public int Offset => _bytes.Count;
        public Code CallImport(string slot) => Indirect(0x15, slots[slot]);
        public Code JumpImport(string slot) => Indirect(0x25, slots[slot]);
        public Code Ret() { _bytes.Add(0xC3); return this; }
        public Code Raw(params byte[] bytes) { _bytes.AddRange(bytes); return this; }
        public Code Pad(int to) { while (_bytes.Count < to) _bytes.Add(0xCC); return this; }

        private Code Indirect(byte modrm, uint target)
        {
            uint next = Text + (uint)_bytes.Count + 6;
            _bytes.AddRange([0xFF, modrm]);
            var disp = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(disp, (int)(target - next));
            _bytes.AddRange(disp);
            return this;
        }

        public byte[] ToArray() => [.. _bytes];
    }

    /// <summary>
    /// deeplib.dll (Deep, Other), provlib.dll (Work: a thunk to deeplib!Deep, Plain: calls deeplib!Deep, Fwd: forwarder to
    /// deeplib.Other) and app.dll whose entry calls provlib!Work, Plain, Fwd, #2 (Plain by ordinal), Missing and nosuch!X.
    /// </summary>
    public static (string App, string Prov, string Deep) Trio(TempDir dir)
    {
        var deep = dir.File("deeplib.dll");
        File.WriteAllBytes(deep, Build("deeplib.dll", [("Deep", 0), ("Other", 16)], [], _ => new Code([]).Ret().Pad(16).Ret().ToArray()));
        var prov = dir.File("provlib.dll");
        File.WriteAllBytes(prov, Build("provlib.dll", [("Work", 0), ("Plain", 16), ("Fwd", "deeplib.Other")], [("deeplib.dll", ["Deep"])],
            slots => new Code(slots).JumpImport("deeplib.dll!Deep").Pad(16).CallImport("deeplib.dll!Deep").Ret().ToArray()));
        var app = dir.File("app.dll");
        File.WriteAllBytes(app, Build("app.dll", [("Main", 0)], [("provlib.dll", ["Work", "Plain", "Fwd", "#2", "Missing"]), ("nosuch_8f3a.dll", ["X"])],
            slots => new Code(slots).CallImport("provlib.dll!Work").CallImport("provlib.dll!Plain").CallImport("provlib.dll!Fwd")
                .CallImport("provlib.dll!#2").CallImport("provlib.dll!Missing").CallImport("nosuch_8f3a.dll!X").Ret().ToArray()));
        return (app, prov, deep);
    }
}

public sealed class NativeLinkTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new(new ServerOptions { BackgroundIndexing = false });
    private readonly NativeCodeService _code;
    private readonly NativeLinkService _link;
    private readonly OutputPager _pager = new(new ServerOptions());

    public NativeLinkTests()
    {
        _code = new NativeCodeService(_ws, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(_dir.File("ann")));
        _link = new NativeLinkService(_ws, _code);
    }

    public void Dispose()
    {
        _ws.Dispose();
        _dir.Dispose();
    }

    internal static void Has(string text, string expected) => Assert.True(text.Contains(expected, StringComparison.Ordinal), $"'{expected}' not in:\n{text}");

    [Fact]
    public async Task ImportsBindAcrossLoadedImages()
    {
        var (app, prov, deep) = LinkedImages.Trio(_dir);
        _ws.LoadAny(app);
        var native = new NativeTools(_ws, _pager, _code, _link);
        var calls = new NativeCodeTools(_ws, _code, _pager, _link);

        // Providers that are not loaded are named with their path, and load on demand (capped).
        var imports = await native.ListImports("app.dll", bind: true);
        Has(imports, "Bindings: 0 bound to loaded images, 4 in 2 images not loaded, 2 unresolved");
        Has(imports, $"provlib.dll!Work in {prov} (not loaded)");
        Has(imports, $"provlib.dll!Fwd -> deeplib.dll!Other in {deep} (not loaded)");
        var (loaded, skipped) = _link.LoadProviders(_ws.Read(() => _link.BindAll(_ws.GetNative("app.dll"))), 1);
        Assert.Equal(["provlib.dll"], loaded);
        Assert.Equal([deep], skipped);
        Has(await native.ListImports("app.dll", bind: true), "Bindings: 3 bound to loaded images, 1 in 1 image not loaded");
        _ws.LoadAny(deep);

        imports = await native.ListImports("app.dll", bind: true);
        Has(imports, "Bindings: 4 bound to loaded images, 0 in 0 images not loaded, 2 unresolved (");
        Has(imports, "provlib.dll!Work -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]");   // jump thunk followed
        Has(imports, "provlib.dll!Fwd -> deeplib.dll!Other at 0x180001010 [deeplib.dll]");   // forwarder
        Has(imports, "!#2  -> provlib.dll!Plain at 0x180001010 [provlib.dll]");               // by ordinal
        Has(imports, "unresolved (missing_export)");
        Has(imports, "unresolved (dll_not_found)");

        var tree = await calls.NativeCallTree("app.dll", "Main", depth: 3);
        Has(tree, "provlib!Plain -> provlib.dll!Plain at 0x180001010 [provlib.dll]");
        Has(tree, "    deeplib!Deep -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]");   // two images deep

        // The same tree as rows: one per line, parents and images set.
        var appImage = _ws.GetNative("app.dll");
        var appIndex = _code.Ready(appImage)!;
        var main = appIndex.FunctionAt(appIndex.AddressOfName("Main")!.Value)!;
        var rows = new List<NativeTreeNode>();
        var text = new System.Text.StringBuilder();
        _ws.Read(() => _link.AppendTree(text, appImage, main, false, 3, 100, 0, true, default, rows: rows, home: appImage));
        Assert.Equal(text.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length, rows.Count);
        Assert.Equal(("Main", null, 0), (rows[0].Name, rows[0].Parent, rows[0].Depth));
        var deepRow = rows.Single(r => r.Name == "deeplib!Deep");
        Assert.Equal(("import", "deeplib.dll", "0x180001000", 2), (deepRow.Edge, deepRow.Image, deepRow.Address, deepRow.Depth));
        Assert.Equal(1, rows[deepRow.Parent!.Value].Depth);

        var callers = await calls.NativeCallTree("deeplib.dll", "Deep", direction: "callers", depth: 4);
        Has(callers, "Plain  0x180001010  [provlib.dll]");
        Has(callers, "Work  0x180001000  [provlib.dll]");
        Has(callers, "Main  0x180001000  [app.dll]");

        var xrefs = await calls.FindXrefs("provlib.dll", "Plain");
        Has(xrefs, "[app.dll] 0x180001006  ImportCall Main+0x6  via provlib!Plain");
        Has(xrefs, "[app.dll] 0x180001012  ImportCall Main+0x12  via provlib!#2");

        Assert.Contains("bound to provlib.dll!Fwd -> deeplib.dll!Other at 0x180001010 [deeplib.dll]", await native.ResolveAddress("app.dll", "provlib.dll!Fwd"));
        Assert.Contains("imported by app.dll (provlib!Plain, provlib!#2)", await native.ResolveAddress("provlib.dll", "Plain"));
        Assert.Contains(";   provlib!Work -> provlib.dll!Work -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]", await calls.Disassemble("app.dll", "Main"));
    }

    private const string PInvokeSource = """
        using System.Runtime.InteropServices;
        public static class Interop
        {
            [DllImport("provlib.dll")] public static extern void Plain();
            [DllImport("provlib.dll", EntryPoint = "Work")] public static extern void Thunked();
            [DllImport("provlib.dll")] public static extern void NotThere();
        }
        public static class App
        {
            public static void Run() { Interop.Plain(); Helper(); }
            public static void Helper() => Interop.Thunked();
            public static void Main() => Run();
        }
        """;

    private (Env Env, ReferenceTools Refs, CallGraphTools Graph) ManagedSetup()
    {
        var (app, prov, deep) = LinkedImages.Trio(_dir);
        var path = _dir.File("Managed.dll");
        File.WriteAllBytes(path, Roslyn.Compile("Managed", PInvokeSource,
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary)));
        var env = new Env(path);
        foreach (var f in new[] { app, prov, deep }) env.Workspace.LoadAny(f);
        var code = new NativeCodeService(env.Workspace, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(_dir.File("ann2")));
        var link = new NativeLinkService(env.Workspace, code);
        return (env, new ReferenceTools(env.Workspace, env.References, link),
            new CallGraphTools(env.Workspace, new CallGraphService(env.Workspace), link));
    }

    [WindowsFact("P/Invoke DLL lookup is done on Windows hosts only.")]
    public async Task ManagedCallsContinueIntoNativeCode()
    {
        var (env, refs, graph) = ManagedSetup();
        using var _ = env;
        Has(await refs.FindCallees("App::Run"), "-> native: provlib.dll!Plain at 0x180001010 [provlib.dll]");
        var own = await refs.FindCallees("Interop::Thunked");
        Has(own, "is a P/Invoke with no IL body");
        Has(own, "native: provlib.dll!Work -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]");
        Has(await refs.FindCallees("Interop::NotThere"), "native: provlib.dll: unresolved (missing_export)");

        var tree = await graph.GetCallTree("App::Main", "callees", depth: 4);
        Has(tree, "    Interop::Plain()");
        Has(tree, "      native: provlib.dll!Plain at 0x180001010 [provlib.dll]");
        Has(tree, "        deeplib!Deep -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]");

        // Native exports list their managed callers.
        var plain = await refs.FindReferences("provlib.dll!Plain");
        Has(plain, "References to native provlib.dll!Plain: provlib.dll!Plain at 0x180001010 [provlib.dll]");
        Has(plain, "  Interop::Plain()  [Managed]");
        Has(plain, "  App::Run()  [Managed] 0x06000004  IL_0001  call  (through Interop::Plain() [Managed])");
        Has(plain, "[app.dll] 0x180001006  ImportCall Main+0x6  via provlib!Plain");

        // Through the jump thunk provlib!Work, the P/Invoke reaches deeplib!Deep.
        Has(await refs.FindReferences("native:deeplib.dll!Deep"), "  Interop::Thunked()  [Managed]");

        var callers = await graph.GetCallTree("provlib.dll!Plain", "callers", depth: 3);
        Has(callers, "  Main at 0x180001000 [app.dll]  (calls provlib!Plain)");
        Has(callers, "  Interop::Plain()  [Managed]  (P/Invoke: provlib.dll!Plain");
        Has(callers, "    App::Run()");
        Has(callers, "      App::Main()");

        var paths = await graph.FindCallPaths("native:provlib!Plain");
        Has(paths, "Paths to native provlib!Plain");
        Has(paths, "1 path (showing 1-1)");
        Has(paths, "      -> native: provlib.dll!Plain at 0x180001010 [provlib.dll]");
        await Assert.ThrowsAsync<ToolError>(() => refs.FindReferences("native:provlib.dll!NoSuchExport"));
    }

    [Fact]
    public void NativeSymbolSyntax()
    {
        Assert.Equal(new NativeSymbol("kernel32.dll", "CreateFileW"), SymbolResolver.ParseNative("kernel32.dll!CreateFileW"));
        Assert.Equal(new NativeSymbol("KERNELBASE", "0x180001000"), SymbolResolver.ParseNative(" native:KERNELBASE!0x180001000 "));
        Assert.Equal(new NativeSymbol(@"C:\x\a.dll", "#5"), SymbolResolver.ParseNative(@"C:\x\a.dll!#5"));
        Assert.Null(SymbolResolver.ParseNative("Ns.Type::Method(!!0)"));
        Assert.Null(SymbolResolver.ParseNative("List<T>!x"));
        Assert.Null(SymbolResolver.ParseNative("Ns.Type::Method"));
        Assert.Throws<ToolError>(() => SymbolResolver.ParseNative("native:kernel32.dll"));
    }

    [Fact]
    public void ForwarderLoopsAndBadOrdinalsStopWithAReason()
    {
        var a = _dir.File("loopa.dll");
        File.WriteAllBytes(a, LinkedImages.Build("loopa.dll", [("F", "loopb.G"), ("Bad", "loopb.#x")], [], _ => [0xC3]));
        File.WriteAllBytes(_dir.File("loopb.dll"), LinkedImages.Build("loopb.dll", [("G", "loopa.F")], [], _ => [0xC3]));
        var linker = new NativeLinker(PeFile.Open);
        Assert.Equal(NativeLinker.ForwarderTooDeep, linker.Bind(a, null, false, "F", null, "import").Status);
        Assert.Equal(NativeLinker.ForwarderBroken, linker.Bind(a, null, false, "Bad", null, "import").Status);
        Assert.Equal(NativeLinker.MissingOrdinal, linker.Bind(a, null, false, null, 99, "import").Status);
        Assert.Equal(NativeLinker.DllNotFound, linker.Bind("nosuch_8f3a.dll", a, false, "F", null, "import").Status);
    }
}
