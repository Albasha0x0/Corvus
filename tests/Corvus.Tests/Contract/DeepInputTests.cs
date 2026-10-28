using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Core.Python;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;
using Corvus.Services.Web;
using Corvus.Services.Web.Scripts;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Corvus.Tests;

/// <summary>
/// Recursive readers and printers on deeply nested input built in the test:
/// each ends in a refusal or a partial result, never a stack overflow.
/// </summary>
public sealed class DeepInputTests : IDisposable
{
    private const int Levels = 100_000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string NestedArrays() => new string('[', Levels) + "0" + new string(']', Levels);

    [Fact]
    public void A_deep_script_parses_or_is_refused_in_the_module_reader()
    {
        var notes = new List<string>();
        var tree = JsModules.Parse("var a = " + NestedArrays() + ";", notes);
        Assert.True(tree != null || notes.Count > 0);
    }

    [Fact]
    public void A_deep_script_is_formatted_or_refused_by_the_beautifier()
    {
        try { Assert.NotNull(JsBeautify.Format("var a = " + NestedArrays() + ";", null, false, default)); }
        catch (InvalidDataException) { }
    }

    [Fact]
    public void A_deep_script_is_read_or_marked_partial_by_the_script_reader()
    {
        var reading = ScriptReader.Read("var a = " + NestedArrays() + "; eval('x');", "javascript");
        Assert.NotNull(reading.Plain);
    }

    [Fact]
    public void A_deep_expression_decompiles_or_falls_back_to_IL()
    {
        var path = _dir.File("Deep.dll");
        File.WriteAllBytes(path, ContainerFixtures.Module("Deep", module =>
        {
            var type = new TypeDefUser("Deep", "Sums", module.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed };
            module.Types.Add(type);
            var method = new MethodDefUser("Sum", MethodSig.CreateStatic(module.CorLibTypes.Int32), MethodAttributes.Public | MethodAttributes.Static);
            var body = new CilBody { MaxStack = 2 };
            body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
            // 10,000 terms: well past a default stack, and quick to decompile.
            for (int i = 0; i < 10_000; i++)
            {
                body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                body.Instructions.Add(OpCodes.Add.ToInstruction());
            }
            body.Instructions.Add(OpCodes.Ret.ToInstruction());
            method.Body = body;
            type.Methods.Add(method);
        }));
        using var env = new Env();
        var asm = env.Workspace.Load(path);
        var sum = asm.Module.Find("Deep.Sums", false)!.FindMethod("Sum");
        try { Assert.Contains("Sum", env.Decompiler.DecompileMembers(asm, [sum], default)); }
        catch (ToolError e) when (e.Code is ErrorCode.Timeout or ErrorCode.LimitExceeded) { }
    }

    [Fact]
    public void Deeply_nested_xar_folders_are_listed_to_a_partial_result()
    {
        var toc = new StringBuilder("<?xml version=\"1.0\"?><xar><toc>");
        for (int i = 0; i < Levels; i++) toc.Append("<file><name>d</name><type>directory</type>");
        toc.Append("<file><name>f.bin</name><type>file</type><data><offset>0</offset><length>4</length><size>4</size>")
            .Append("<encoding style=\"application/octet-stream\"/></data></file>");
        for (int i = 0; i < Levels; i++) toc.Append("</file>");
        var text = Encoding.UTF8.GetBytes(toc.Append("</toc></xar>").ToString());
        var compressed = new MemoryStream();
        using (var z = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true)) z.Write(text);
        var header = new byte[28];
        "xar!"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 28);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), 1);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(8), (ulong)compressed.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(16), (ulong)text.Length);
        try
        {
            var contents = Containers.Open([.. header, .. compressed.ToArray(), 1, 2, 3, 4], "deep.xar", AnalysisLimits.Default, default, allFiles: true);
            Assert.Contains(contents.Notes, n => n.Contains("nested deeper than the stack allows", StringComparison.Ordinal));
        }
        catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
    }

    [Fact]
    public void A_deep_constant_prints_its_start_and_an_ellipsis()
    {
        object o = 1L;
        for (int i = 0; i < Levels; i++) o = new PySequence('(', [o]);
        var text = PyRepr.Of(o, (3, 12));
        Assert.EndsWith("...", text);
        Assert.True(text.Length <= PyRepr.MaxChars + 3);
    }

    [Fact]
    public void Shared_constants_print_once_each_and_stop_at_the_limit()
    {
        // Each level holds the one below twice: 2^64 leaves as a tree.
        object o = "x";
        for (int i = 0; i < 64; i++) o = new PySequence('(', [o, o]);
        var text = PyRepr.Of(o, (3, 12));
        Assert.EndsWith("...", text);
        Assert.True(text.Length <= PyRepr.MaxChars + 3);
        Assert.Equal("(('x', 'x'), ('x', 'x'))", PyRepr.Of(new PySequence('(', [new PySequence('(', ["x", "x"]), new PySequence('(', ["x", "x"])]), (3, 12)));
    }

    [Fact]
    public void A_keyed_archive_chain_of_references_stops_with_an_issue()
    {
        var objects = new List<PlistNode> { new PlistString("$null") };
        for (int i = 1; i <= Levels; i++) objects.Add(new PlistArray([new PlistUid((ulong)(i + 1))]));
        objects.Add(new PlistString("end"));
        var root = new PlistDict(
        [
            new("$archiver", new PlistString("NSKeyedArchiver")),
            new("$objects", new PlistArray(objects)),
            new("$top", new PlistDict([new("root", new PlistUid(1))])),
        ]);
        var result = KeyedArchive.Project(root);
        Assert.Contains(result.Issues, i => i.Message.StartsWith("nested deeper", StringComparison.Ordinal) || i.Message.StartsWith("more than", StringComparison.Ordinal));
    }

    [Fact]
    public void Deep_pdb_type_chains_spell_and_declare_without_overflow()
    {
        var t = new TpiBuilder();
        uint pointer = 0x74, inner = t.Struct("S0", t.FieldList(TpiBuilder.Member(0x74, 0, "v")), 4);
        // 10,000 levels: past every depth limit of the type reader.
        for (int i = 0; i < 10_000; i++)
        {
            pointer = t.Pointer(pointer);
            inner = t.Struct($"S{i + 1}", t.FieldList(TpiBuilder.Member(inner, 0, "inner"), TpiBuilder.Member(pointer, 4, "p")), 12);
        }
        var builder = PdbBuilder.Sample();
        builder.GlobalRecords.Add(PdbBuilder.Record(0x1108, b => { TpiBuilder.U32(b, inner); TpiBuilder.Name(b, "Top"); }));
        var msf = builder.Msf();
        msf.Streams[2] = t.Build();
        var path = _dir.File("deep.pdb");
        File.WriteAllBytes(path, msf.Build());
        var pdb = PdbFile.Open(path);
        var model = PdbTypeModel.Read(pdb, 8);
        Assert.NotNull(model.Spell(pointer));
        Assert.Contains("struct S1", PdbTypes.Build(pdb, 8).Declarations);
    }

    [Fact]
    public void Deeply_nested_dwarf_namespaces_qualify_a_bounded_name()
    {
        var abbrev = new List<byte>
        {
            1, (byte)Dw.TagCompileUnit, 1, 0, 0,
            2, (byte)Dw.TagNamespace, 1, 0x03, 0x08, 0, 0,
            3, (byte)Dw.TagStructureType, 0, 0x03, 0x08, 0, 0,
            0,
        };
        var dies = new List<byte> { 1 };
        for (int i = 0; i < Levels; i++) dies.AddRange([2, (byte)'n', 0]);
        dies.AddRange([3, (byte)'S', 0]);
        dies.AddRange(new byte[Levels + 1]);
        var info = new List<byte>();
        info.AddRange(BitConverter.GetBytes(2 + 4 + 1 + dies.Count));
        info.AddRange(BitConverter.GetBytes((ushort)4));
        info.AddRange(BitConverter.GetBytes(0));
        info.Add(8);
        info.AddRange(dies);
        var sections = new Dictionary<string, DwarfSection>
        {
            [".debug_info"] = new(".debug_info", info.ToArray()),
            [".debug_abbrev"] = new(".debug_abbrev", abbrev.ToArray()),
        };
        var reader = new DwarfReader(n => sections.GetValueOrDefault(n), bigEndian: false, addressSize: 8, family: null);
        var unit = reader.Parse(reader.UnitHeaders[0], 0);
        Assert.Null(unit.Problem);
        var name = DwarfTypes.Qualify(unit, unit.Dies[^1], "S");
        Assert.StartsWith("...::n::", name);
        Assert.EndsWith("n::S", name);
        Assert.True(name.Length < 1000);
    }
}
