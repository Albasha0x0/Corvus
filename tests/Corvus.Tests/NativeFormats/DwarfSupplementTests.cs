using System.Text;
using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;

namespace Corvus.Tests.NativeFormats;

/// <summary>Names and types in a dwz supplementary file, in the GNU and DWARF 5 forms.</summary>
public sealed class DwarfSupplementTests
{
    private const string AltId = "a1b2c3d4e5f60718293a4b5c6d7e8f9011223344";
    private const uint FunctionRva = 0x1000, VariableRva = 0x2000;

    /// <summary>A unit: header (DWARF 4, or 5 with DW_UT_compile / DW_UT_partial), then the entries <paramref name="body"/> writes from offset <c>start</c>.</summary>
    private static byte[] Unit(int version, Action<BinaryWriter, int> body)
    {
        var s = new MemoryStream();
        var w = new BinaryWriter(s);
        w.Write(0u);
        w.Write((ushort)version);
        if (version >= 5) { w.Write((byte)1); w.Write((byte)8); w.Write(0u); }
        else { w.Write(0u); w.Write((byte)8); }
        body(w, (int)s.Position);
        w.Flush();
        var bytes = s.ToArray();
        BitConverter.GetBytes((uint)(bytes.Length - 4)).CopyTo(bytes, 0);
        return bytes;
    }

    private static byte[] Uleb(int v)
    {
        var bytes = new List<byte>();
        do { byte b = (byte)(v & 0x7F); v >>= 7; bytes.Add(v != 0 ? (byte)(b | 0x80) : b); } while (v != 0);
        return [.. bytes];
    }

    private static void Text(BinaryWriter w, string s) { w.Write(Encoding.ASCII.GetBytes(s)); w.Write((byte)0); }

    private static (string Main, string Alt) Write(TempDir dir, int version, ulong imageBase)
    {
        bool dwarf5 = version >= 5;
        int strpAlt = dwarf5 ? Dw.FormStrpSup : Dw.FormGnuStrpAlt, refAlt = dwarf5 ? Dw.FormRefSup4 : Dw.FormGnuRefAlt;

        // The supplementary file: a partial unit with int and struct AltPoint { int x; int y; }, and the names.
        byte[] altAbbrev =
        [
            1, 0x3c, 1, 0x03, 0x08, 0, 0,
            2, 0x24, 0, 0x03, 0x08, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0,
            3, 0x13, 1, 0x03, 0x08, 0x0b, 0x0b, 0, 0,
            4, 0x0d, 0, 0x03, 0x08, 0x49, 0x13, 0x38, 0x0b, 0, 0,
            0,
        ];
        long intAt = 0, pointAt = 0;
        var altInfo = Unit(version, (w, start) =>
        {
            w.Write((byte)1); Text(w, "alt.c");
            intAt = w.BaseStream.Position;
            w.Write((byte)2); Text(w, "int"); w.Write((byte)4); w.Write((byte)5);
            pointAt = w.BaseStream.Position;
            w.Write((byte)3); Text(w, "AltPoint"); w.Write((byte)8);
            w.Write((byte)4); Text(w, "x"); w.Write((uint)intAt); w.Write((byte)0);
            w.Write((byte)4); Text(w, "y"); w.Write((uint)intAt); w.Write((byte)4);
            w.Write((byte)0);
            w.Write((byte)0);
        });
        var altStr = "\0alt_fn\0alt_var\0"u8.ToArray();
        var alt = dir.File("alt.debug");
        var altSections = new List<DebugFileWriter.Section>
        {
            DebugFileWriter.Bytes(".debug_abbrev", altAbbrev), DebugFileWriter.Bytes(".debug_info", altInfo), DebugFileWriter.Bytes(".debug_str", altStr),
        };
        if (dwarf5) altSections.Add(DebugFileWriter.Bytes(".debug_sup", [5, 0, 1, 0, 0]));
        else altSections.Insert(0, DebugFileWriter.BuildId(AltId));
        DebugFileWriter.Write(alt, altSections);

        // The main file: a function and a variable named and typed in the supplementary file.
        byte[] abbrev =
        [
            1, 0x11, 1, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0,
            2, 0x2e, 0, 0x03, .. Uleb(strpAlt), 0x11, 0x01, 0x12, 0x06, 0x3f, 0x19, 0x49, .. Uleb(refAlt), 0, 0,
            3, 0x34, 0, 0x03, .. Uleb(strpAlt), 0x49, .. Uleb(refAlt), 0x02, 0x18, 0x3f, 0x19, 0, 0,
            0,
        ];
        var info = Unit(version, (w, _) =>
        {
            w.Write((byte)1); Text(w, "main.c"); w.Write(imageBase + FunctionRva); w.Write(0x40u);
            w.Write((byte)2); w.Write(1u); w.Write(imageBase + FunctionRva); w.Write(0x40u); w.Write((uint)intAt);
            w.Write((byte)3); w.Write(8u); w.Write((uint)pointAt); w.Write((byte)9); w.Write((byte)0x03); w.Write(imageBase + VariableRva);
            w.Write((byte)0);
        });
        var link = new MemoryStream();
        link.Write("alt.debug\0"u8);
        if (dwarf5) link = new MemoryStream([5, 0, 0, .. "alt.debug\0"u8.ToArray(), 0]);
        else link.Write(Convert.FromHexString(AltId));
        var main = dir.File("main.debug");
        DebugFileWriter.Write(main,
        [
            DebugFileWriter.Bytes(".debug_abbrev", abbrev), DebugFileWriter.Bytes(".debug_info", info),
            DebugFileWriter.Bytes(dwarf5 ? ".debug_sup" : ".gnu_debugaltlink", link.ToArray()),
        ]);
        return (main, alt);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(5)]
    public void Names_and_types_in_the_supplementary_file_are_read(int version)
    {
        using var dir = new TempDir();
        var image = NativeImageLoader.Open(NativeFixtures.NativeAotLib("linux-x64", "libSystem.Native.so"));
        var (main, alt) = Write(dir, version, image.ImageBase);
        PdbFile Read()
        {
            using var container = DebugContainer.Open(main);
            return DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(main));
        }

        var pdb = Read();
        Assert.Empty(pdb.Issues);
        var model = PdbTypeModel.Of(pdb, 8);
        var fn = pdb.Symbols.Single(s => s.Name == "alt_fn");
        Assert.Equal((PdbSymbolKind.GlobalProc, FunctionRva), (fn.Kind, fn.Rva));
        Assert.StartsWith("int ", model.Spell(model.FunctionTypeOf(fn.TypeIndex)));
        var variable = pdb.Symbols.Single(s => s.Name == "alt_var");
        Assert.Equal((PdbSymbolKind.GlobalData, VariableRva, 8u), (variable.Kind, variable.Rva, variable.Size));
        Assert.Equal("AltPoint", model.Spell(variable.TypeIndex));
        Assert.Equal([("x", 0L), ("y", 4L)], model.Node(Assert.Single(model.Named("AltPoint")))!.Members.Select(m => (m.Name, m.Offset)));

        // Another build of the supplementary file (GNU: by build-id), then none: reported, the rest still read.
        if (version < 5)
        {
            DebugFileWriter.Write(alt, [DebugFileWriter.BuildId("ff" + AltId[2..])]);
            Assert.Contains(Read().Issues, i => i.Message.Contains("not matching") && i.Message.Contains("build-id ff"));
        }
        File.Delete(alt);
        var without = Read();
        Assert.Contains(without.Issues, i => i.Message.Contains("supplementary file alt.debug") && i.Message.Contains("is not found"));
        Assert.DoesNotContain(without.Symbols, s => s.Name == "alt_fn");
    }
}
