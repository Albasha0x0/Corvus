using System.Buffers.Binary;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Linking;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Small x64 DLLs for cross-image tests: exports (code or forwarders), imports by name or ordinal, and code that
/// calls or jumps through import slots ("call [Module!Name]" by slot).
/// </summary>
internal static class LinkedImages
{
    public const uint Text = 0x1000, Data = 0x2000;

    /// <param name="exports">Name and either a code offset into <paramref name="code"/> or a forwarder ("module.name").</param>
    /// <param name="imports">Module and names ("#n" imports by ordinal).</param>
    /// <param name="code">Code bytes, given the slot RVA of each "module!name" import.</param>
    public static byte[] Build(string dllName, (string Name, object Target)[] exports, (string Module, string[] Names)[] imports,
        Func<Dictionary<string, uint>, byte[]> code)
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
        foreach (var f in new[] { app, prov, deep }) _ws.LoadAny(f);
        var native = new NativeTools(_ws, _pager, _code, _link);
        var calls = new NativeCodeTools(_ws, _code, _pager, _link);

        var imports = await native.ListImports("app.dll", bind: true);
        Has(imports, "Bindings: 4 bound to loaded images, 0 in 0 images not loaded, 2 unresolved (");
        Has(imports, "provlib.dll!Work -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]");   // jump thunk followed
        Has(imports, "provlib.dll!Fwd -> deeplib.dll!Other at 0x180001010 [deeplib.dll]");   // forwarder
        Has(imports, "!#2  -> provlib.dll!Plain at 0x180001010 [provlib.dll]");               // by ordinal
        Has(imports, "unresolved (missing_export)");
        Has(imports, "unresolved (dll_not_found)");

        var tree = await calls.NativeCallTree("app.dll", "Main", depth: 3);
        Has(tree, "provlib!Plain -> provlib.dll!Plain at 0x180001010 [provlib.dll]");
        Has(tree, "    deeplib!Deep -> deeplib.dll!Deep at 0x180001000 [deeplib.dll]");   // two images deep

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

    [Fact]
    public async Task ProvidersThatAreNotLoadedAreNamedAndLoadOnDemand()
    {
        var (app, prov, deep) = LinkedImages.Trio(_dir);
        _ws.LoadAny(app);
        var native = new NativeTools(_ws, _pager, _code, _link);
        var imports = await native.ListImports("app.dll", bind: true);
        Has(imports, "Bindings: 0 bound to loaded images, 4 in 2 images not loaded, 2 unresolved");
        Has(imports, $"provlib.dll!Work in {prov} (not loaded)");
        Has(imports, $"provlib.dll!Fwd -> deeplib.dll!Other in {deep} (not loaded)");

        var (loaded, skipped) = _link.LoadProviders(_ws.Read(() => _link.BindAll(_ws.GetNative("app.dll"))), 1);
        Assert.Equal(["provlib.dll"], loaded);
        Assert.Equal([deep], skipped);
        Assert.Contains("Bindings: 3 bound to loaded images, 1 in 1 image not loaded", await native.ListImports("app.dll", bind: true));
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
