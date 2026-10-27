using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Elf;

namespace Corvus.Tests.NativeFormats;

/// <summary>Data pointers of images without relocations: cross-references marked unconfirmed, never in images that have relocations.</summary>
public sealed class UnrelocatedPointerTests
{
    private const ulong Base = 0x400000;

    // Two functions, a table of both at the start of .data, a lone pointer to the second at +0x20.
    private static byte[] Text()
    {
        var text = new byte[0x20];
        Array.Fill(text, (byte)0xCC);
        text[0] = 0xC3;
        text[0x10] = 0xC3;
        return text;
    }

    private static byte[] Data(ulong textVa)
    {
        var data = new byte[0x40];
        BinaryPrimitives.WriteUInt64LittleEndian(data, textVa);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(8), textVa + 0x10);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x20), textVa + 0x10);
        // A run whose other value is inside code but no function start (a small integer, where the image base is low).
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x30), textVa + 0x10);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x38), textVa + 0x14);
        return data;
    }

    private static byte[] Elf() => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Type = 2, Base = Base, Entry = ElfWriter.TextRva, Text = Text(), Hash = ElfWriter.HashKind.None,
        Data = Data(Base + ElfWriter.TextRva),
    }.Build();

    [Fact]
    public async Task Pointer_runs_in_data_are_unconfirmed_pointer_references()
    {
        var index = NativeCodeIndex.Build(ElfFile.FromBytes(Elf(), "static"));
        Assert.True(index.PointersUnconfirmed);
        Assert.Equal([(ElfWriter.DataRva, XrefKind.Pointer)], index.RefsTo(ElfWriter.TextRva).Select(x => (x.From, x.Kind)));
        // The lone value at +0x20 stands in no run, the one at +0x30 beside no other function start.
        Assert.Equal([(ElfWriter.DataRva + 8, XrefKind.Pointer)], index.RefsTo(ElfWriter.TextRva + 0x10).Select(x => (x.From, x.Kind)));

        using var dir = new TempDir();
        var path = dir.File("static");
        File.WriteAllBytes(path, Elf());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var to = await h.CodeTools.FindXrefs(path, $"rva:0x{ElfWriter.TextRva + 0x10:X}");
        Assert.Contains("Pointer", to);
        Assert.Contains("unconfirmed: no relocations, accepted by address range", to);
        Assert.Contains("unconfirmed: no relocations", await h.CodeTools.FindXrefs(path, $"rva:0x{ElfWriter.DataRva:X}", direction: "from"));
        Assert.Contains("data pointers are runs of values that are function starts, unconfirmed", await h.CodeTools.ListFunctions(path));
    }

    /// <summary>A value inside a declared function starts no function and is no pointer; a value past every declared extent still is.</summary>
    [Fact]
    public void Values_inside_declared_functions_start_none()
    {
        const uint Text = ElfWriter.TextRva;
        var text = new byte[0x30];
        Array.Fill(text, (byte)0xCC);
        text[0] = text[0x10] = text[0x20] = 0xC3;
        var data = new byte[0x18];
        BinaryPrimitives.WriteUInt64LittleEndian(data, Base + Text);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(8), Base + Text + 0x20);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x10), Base + Text + 0x10);
        var elf = new ElfWriter
        {
            Machine = ElfWriter.EmX64, Type = 2, Base = Base, Entry = Text, Text = text, Hash = ElfWriter.HashKind.None, Data = data,
            StaticSymbols = [new ElfWriter.Symbol("declared", Text, 0x20, Type: 2)],
        }.Build();
        var index = NativeCodeIndex.Build(ElfFile.FromBytes(elf, "static"));
        Assert.Null(index.FunctionByStart(Text + 0x10));
        Assert.DoesNotContain(index.RefsTo(Text + 0x10), x => x.Kind == XrefKind.Pointer);
        Assert.Equal(FunctionSource.DataPointer, index.FunctionByStart(Text + 0x20)!.Sources);
        Assert.Equal([ElfWriter.DataRva + 8], index.RefsTo(Text + 0x20).Where(x => x.Kind == XrefKind.Pointer).Select(x => x.From));
    }

    [Fact]
    public void Images_with_relocations_take_only_relocated_slots()
    {
        var probe = CodeTestImage.Synthetic(NativeArch.X64, Text());
        var data = Data(probe.ImageBase + CodeTestImage.SyntheticCodeRva);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, Text(), data, relocations: [CodeTestImage.SyntheticDataRva]));
        Assert.False(index.PointersUnconfirmed);
        Assert.Equal([CodeTestImage.SyntheticDataRva], index.RefsFrom(CodeTestImage.SyntheticDataRva, CodeTestImage.SyntheticDataRva + 0x40).Select(x => x.From));
    }
}
