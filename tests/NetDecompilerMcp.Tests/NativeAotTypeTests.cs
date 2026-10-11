using System.Buffers.Binary;
using NetDecompilerMcp.Native.NativeAot;
using B = NetDecompilerMcp.Tests.NativeAotBuilder;
using E = NetDecompilerMcp.Native.NativeAot.NativeAotElementType;
using static NetDecompilerMcp.Tests.NativeAotNameMapTests;

namespace NetDecompilerMcp.Tests;

public class NativeAotTypeTests
{
    internal const uint SpeakCode = B.TextRva + 0x10, ToStringCode = B.TextRva + 0x60, EqualsCode = B.TextRva + 0x70, HashCode = B.TextRva + 0x80;
    /// <summary>Dog's implementation of the interface's slot 1, reached only through its sealed vtable.</summary>
    internal const uint SealedCode = B.TextRva + 0x90;
    private const uint HasDispatchMap = 0x40000, HasSealedVTable = 0x400000;
    private const uint KindCanonical = 0, KindGenericDefinition = 3;
    private const uint IsGeneric = 0x02000000, IsGeneric7 = 0x400, OptionalFields7 = 0x100;

    /// <summary>Writes a MethodTable of <paramref name="layout"/> and the builder's pointer size into .data; returns its RVA.</summary>
    private static uint Mt(B b, MethodTableLayout layout, E element, uint kind, uint baseSize, uint related, uint[] vtable, uint[] interfaces,
        ushort componentSize = 0, uint genericDefinition = 0, uint genericArgument = 0, uint dispatchMap = 0, uint sealedVTable = 0)
    {
        var d = b.Data;
        bool generic = genericDefinition != 0;
        bool net7 = layout == MethodTableLayout.Net7;
        uint optionalFields = 0, composition = 0;
        if (net7 && dispatchMap != 0)
        {
            // Rare flags with HasSealedVTableEntries (0x200, NativeFormat 01 08), then the dispatch map's index 0 in section 203.
            optionalFields = d.Bytes([0x00, 0x01, 0x08, 0x81, 0x00]);
            d.Align(b.PointerSize);
            uint table = b.Pointer(d, dispatchMap);
            b.Row(203, table, table + (uint)b.PointerSize);
        }
        if (net7 && generic)
        {
            d.Align(b.PointerSize);
            composition = d.U16(1); // arity, no variance, padding to a pointer
            d.Zero(b.PointerSize - 2);
            b.Pointer(d, genericArgument);
        }
        d.Align(b.PointerSize);
        if (net7)
        {
            d.U16(componentSize);
            d.U16((ushort)(((uint)element << 11) | kind | (generic ? IsGeneric7 : 0) | (optionalFields != 0 ? OptionalFields7 : 0)));
        }
        else
        {
            uint flags = ((uint)element << 26) | (kind << 16) | (generic ? IsGeneric : 0) | (dispatchMap != 0 ? HasDispatchMap : 0) | (sealedVTable != 0 ? HasSealedVTable : 0);
            if (componentSize != 0) flags |= 0x80000000 | componentSize;
            d.U32(flags);
        }
        uint at = d.Rva + (uint)d.Length - 4;
        d.U32(baseSize);
        if (related != 0) b.Pointer(d, related); else d.Ptr(!b.Is32, 0);
        d.U16((ushort)vtable.Length);
        d.U16((ushort)interfaces.Length);
        d.U32(0x1234);
        foreach (var v in vtable) b.Pointer(d, v);
        foreach (var i in interfaces) b.Pointer(d, i);
        d.U32(0); // type manager indirection
        d.U32(0); // writable data
        if (net7)
        {
            if (optionalFields != 0) d.U32(optionalFields - d.Here);
            if (sealedVTable != 0) d.U32(sealedVTable - d.Here);
            if (generic)
            {
                d.U32(genericDefinition - d.Here);
                d.U32(composition - d.Here);
            }
            return at;
        }
        if (dispatchMap != 0) d.U32(dispatchMap - d.Here);
        if (sealedVTable != 0) d.U32(sealedVTable - d.Here);
        if (generic)
        {
            uint def = d.Here;
            d.U32(genericDefinition - def);
            uint arg = d.Here;
            d.U32(genericArgument - arg); // arity 1: the composition is the argument itself
        }
        return at;
    }

    internal sealed record World(NativeAotImage Aot, uint Object, uint Speaker, uint Dog, uint DogArray, uint BoxDefinition, uint BoxOfDog, uint Frozen, uint LookAlike)
    {
        public uint Text { get; init; }
        public uint String { get; init; }
    }

    /// <summary>Sizes of the fixture's objects: Object, Dog (one field more) and String (two pointers, the length and a character).</summary>
    internal static (uint Object, uint Dog, uint String) Sizes(bool is32) => is32 ? (12u, 16u, 14u) : (0x18u, 0x20u, 0x16u);

    internal static World Build(ushort major, bool is32 = false)
    {
        var m = NativeAotMetadataTests.Model(major);
        var md = new NativeAotMetadata(m.Blob, m.Format);
        var layout = m.Format.Layout;
        var b = new B { Major = major, Is32 = is32 };
        int p = b.PointerSize;
        var size = Sizes(is32);
        b.Text = new byte[0x200];
        b.Blob(BlobId.EmbeddedMetadata, m.Blob);

        uint obj = Mt(b, layout, E.Class, KindCanonical, size.Object, 0, [ToStringCode, EqualsCode, HashCode], []);
        uint speaker = Mt(b, layout, E.Interface, KindCanonical, 0, 0, [], []);
        // Dog's dispatch map: the interface's slot 0 is vtable slot 0 (Speak), slot 1 is slot 3, the sealed vtable's first.
        b.Data.Align(4);
        uint dogMap = b.Data.Here;
        foreach (var v in new ushort[] { 2, 0, 0, 0, 0, 0, 0, 0, 1, 3 }) b.Data.U16(v);
        uint dogSealed = b.Data.Here;
        b.Data.U32(SealedCode - dogSealed);
        uint dog = Mt(b, layout, E.Class, KindCanonical, size.Dog, obj, [SpeakCode, EqualsCode, HashCode], [speaker], dispatchMap: dogMap, sealedVTable: dogSealed);
        uint dogArray = Mt(b, layout, E.SzArray, KindCanonical, size.Object, dog, [ToStringCode, EqualsCode, HashCode], [], componentSize: (ushort)p);
        // .NET 9+: a generic definition's BaseSize is its arity; .NET 8: its component size.
        uint boxDef = Mt(b, layout, E.Class, KindGenericDefinition, 1, 0, [], [], componentSize: (ushort)(layout == MethodTableLayout.Net8 ? 1 : 0));
        uint boxOfDog = Mt(b, layout, E.Class, KindCanonical, size.Dog, obj, [ToStringCode, EqualsCode, HashCode], [], genericDefinition: boxDef, genericArgument: dog);
        uint str = Mt(b, layout, E.Class, KindCanonical, size.String, obj, [ToStringCode, EqualsCode, HashCode], [], componentSize: 2);
        // Frozen region: padding, a Dog (header, MethodTable pointer, fields) and the string "hi". Their +8 points at a
        // MethodTable, like a statics base after it does: none of them is a MethodTable.
        b.Data.Align(8);
        uint region = b.Data.Zero(2 * p);
        uint frozen = b.Data.Zero(p);
        b.Pointer(b.Data, dog);
        b.Data.Zero((int)size.Dog - 2 * p);
        uint text = b.Data.Zero(p);
        b.Pointer(b.Data, str);
        b.Data.U32(2);
        b.Data.U16('h');
        b.Data.U16('i');
        b.Data.Zero(p + 4);
        b.Row(SectionId.FrozenObjectRegion, region, b.Data.Here);
        b.Data.Align(p);
        uint lookAlike = b.Data.U32(layout == MethodTableLayout.Net7 ? 0x4000_0000u : (uint)E.Int32 << 26);
        b.Data.U32(0x40);
        b.Pointer(b.Data, dog);
        b.Data.Zero(16);

        // Names: the type map names Object and the Box`1 definition; the stack-trace map names Dog::Speak (vtable owner).
        b.Rdata.Align(4);
        uint fixups = b.Rdata.Here;
        b.Blob(BlobId.CommonFixupsTable, RelativeTable(fixups, obj, boxDef, str));
        b.Blob(BlobId.TypeMap, Hashtable([.. Unsigned(0), .. Unsigned(m.Writer.Token(m.Object))], [.. Unsigned(1), .. Unsigned(m.Writer.Token(m.Box))],
            [.. Unsigned(2), .. Unsigned(m.Writer.Token(m.String))]));
        b.Rdata.Align(4);
        uint st = b.Rdata.Here;
        var map = new byte[m.Format.StackTrace == StackTraceFormat.Pairs ? 8 : 4 + 1 + 4 + 2 + 4];
        if (m.Format.StackTrace == StackTraceFormat.Pairs)
        {
            BinaryPrimitives.WriteInt32LittleEndian(map, (int)(SpeakCode - st));
            BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(4), m.Writer.Token(m.Qualified));
        }
        else
        {
            uint name = md.Ref(m.Speak, "name");
            Assert.InRange(name, 0u, 0x3FFFu);
            uint signature = md.Ref(m.Speak, "signature"); // an instance method
            byte[] tail = [.. Unsigned(name), .. Unsigned(signature)];
            map = new byte[9 + tail.Length + 4];
            map[0] = 1;
            map[4] = 0x07;
            BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(5), m.Writer.Token(m.Dog));
            tail.CopyTo(map, 9);
            int code = 9 + tail.Length;
            BinaryPrimitives.WriteInt32LittleEndian(map.AsSpan(code), (int)(SpeakCode - (st + (uint)code)));
        }
        Assert.Equal(st, b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, map));
        var aot = NativeAotImage.Open(b.Image())!;
        return new World(aot, obj, speaker, dog, dogArray, boxDef, boxOfDog, frozen, lookAlike) { Text = text, String = str };
    }

    [Theory]
    [InlineData((ushort)9)]
    [InlineData((ushort)10)]
    [InlineData((ushort)16)]
    public void Crawl_FindsAndNamesMethodTables(ushort major)
    {
        var w = Build(major);
        var types = w.Aot.Types.ByRva;
        Assert.Equal(NativeAotStage.Complete, w.Aot.Types.Stage.Status);
        Assert.Equal(("System.Object", "typemap"), (types[w.Object].Name, types[w.Object].NameOrigin));
        Assert.Equal(("Sample.Zoo.Dog", "vtable"), (types[w.Dog].Name, types[w.Dog].NameOrigin));
        Assert.Equal(("Sample.Zoo.Dog[]", "element"), (types[w.DogArray].Name, types[w.DogArray].NameOrigin));
        Assert.Equal(("Sample.Zoo.Box<Sample.Zoo.Dog>", "composition"), (types[w.BoxOfDog].Name, types[w.BoxOfDog].NameOrigin));
        Assert.Equal(("Sample.Zoo.Box`1", "generic definition"), (types[w.BoxDefinition].Name, types[w.BoxDefinition].Kind));
        Assert.Equal(("interface", "generated"), (types[w.Speaker].Kind, types[w.Speaker].NameOrigin));
        Assert.Equal($"MT_{w.Speaker:X}", types[w.Speaker].Name);
        Assert.Equal([w.Speaker], types[w.Dog].Interfaces);
        Assert.Equal(w.Object, types[w.Dog].RelatedType);
        Assert.Equal([SpeakCode, EqualsCode, HashCode], types[w.Dog].Vtable);
        Assert.Equal((ushort)8, types[w.DogArray].ComponentSize);
        Assert.False(types.ContainsKey(w.Frozen) || types.ContainsKey(w.Text) || types.ContainsKey(w.LookAlike));
        Assert.Equal(7, types.Count);
        var impls = w.Aot.Types.Implementations(types[w.Dog]);
        Assert.Equal([new NativeAotInterfaceImpl(w.Speaker, 0, 0, SpeakCode), new NativeAotInterfaceImpl(w.Speaker, 1, 3, SealedCode)], impls);
        Assert.Equal(SealedCode, w.Aot.Types.SlotCode(types[w.Dog], 3));
        Assert.Equal(0u, w.Aot.Types.SlotCode(types[w.Dog], 4));
        var summary = w.Aot.Summary();
        Assert.Equal((7, 6), (summary.Counts["methodTables"], summary.Counts["namedMethodTables"]));
        Assert.Equal((2, 1), (summary.Counts["frozenObjects"], summary.Counts["frozenStrings"]));
    }

    [Fact]
    public void Crawl_Net7Layout()
    {
        var w = Build(8);
        var types = w.Aot.Types.ByRva;
        Assert.Equal(NativeAotStage.Complete, w.Aot.Types.Stage.Status);
        Assert.Equal("System.Object", types[w.Object].Name);
        Assert.Equal("Sample.Zoo.Dog", types[w.Dog].Name);
        Assert.Equal("Sample.Zoo.Dog[]", types[w.DogArray].Name);
        // Generic instantiations: definition by relative pointer, arguments in the composition; dispatch map through the optional fields.
        Assert.Equal(("Sample.Zoo.Box<Sample.Zoo.Dog>", "composition"), (types[w.BoxOfDog].Name, types[w.BoxOfDog].NameOrigin));
        Assert.Equal([w.Dog], types[w.BoxOfDog].GenericArguments);
        Assert.Equal(w.BoxDefinition, types[w.BoxOfDog].GenericDefinition);
        Assert.Equal([new NativeAotInterfaceImpl(w.Speaker, 0, 0, SpeakCode), new NativeAotInterfaceImpl(w.Speaker, 1, 3, SealedCode)],
            w.Aot.Types.Implementations(types[w.Dog]));
        Assert.Equal(SealedCode, w.Aot.Types.SlotCode(types[w.Dog], 3));
        Assert.False(types.ContainsKey(w.LookAlike));
    }

    [Theory]
    [InlineData((ushort)8)]
    [InlineData((ushort)9)]
    [InlineData((ushort)16)]
    public void FrozenRegion_ObjectsAndStrings(ushort major)
    {
        var w = Build(major);
        var frozen = w.Aot.Frozen;
        Assert.Equal(NativeAotStage.Complete, frozen.Stage.Status);
        Assert.Equal(2, frozen.Objects.Count);
        Assert.Equal((w.Frozen + 8, "Sample.Zoo.Dog", 0x20u, (string?)null), (frozen.Objects[0].Rva, frozen.Objects[0].TypeName, frozen.Objects[0].Size, frozen.Objects[0].Text));
        Assert.Equal((w.Text + 8, w.String, "hi", 0x20u), (frozen.Objects[1].Rva, frozen.Objects[1].MethodTable, frozen.Objects[1].Text, frozen.Objects[1].Size));
    }

    /// <summary>x86: 4-byte pointers in the header rows, MethodTables (vtable at +20), fixups and frozen objects.</summary>
    [Theory]
    [InlineData((ushort)9)]
    [InlineData((ushort)16)]
    public void Image32_MethodTablesAndFrozenObjects(ushort major)
    {
        var w = Build(major, is32: true);
        Assert.False(w.Aot.Image.Is64Bit);
        var types = w.Aot.Types.ByRva;
        Assert.Equal(NativeAotStage.Complete, w.Aot.Types.Stage.Status);
        Assert.Equal(("System.Object", "typemap"), (types[w.Object].Name, types[w.Object].NameOrigin));
        Assert.Equal(("Sample.Zoo.Dog", "vtable"), (types[w.Dog].Name, types[w.Dog].NameOrigin));
        Assert.Equal("Sample.Zoo.Dog[]", types[w.DogArray].Name);
        Assert.Equal("Sample.Zoo.Box<Sample.Zoo.Dog>", types[w.BoxOfDog].Name);
        Assert.Equal([SpeakCode, EqualsCode, HashCode], types[w.Dog].Vtable);
        Assert.Equal([w.Speaker], types[w.Dog].Interfaces);
        Assert.Equal(SealedCode, w.Aot.Types.SlotCode(types[w.Dog], 3));
        Assert.False(types.ContainsKey(w.Frozen) || types.ContainsKey(w.Text) || types.ContainsKey(w.LookAlike));
        Assert.Equal(7, types.Count);
        Assert.Contains(w.Aot.Names.Methods, m => m.Rva == SpeakCode && m.Name.Name == "Speak");

        var frozen = w.Aot.Frozen;
        Assert.Equal(NativeAotStage.Complete, frozen.Stage.Status);
        Assert.Equal((w.Frozen + 4, "Sample.Zoo.Dog", 16u), (frozen.Objects[0].Rva, frozen.Objects[0].TypeName, frozen.Objects[0].Size));
        Assert.Equal((w.Text + 4, "hi", 20u), (frozen.Objects[1].Rva, frozen.Objects[1].Text, frozen.Objects[1].Size));
    }

    [Fact]
    public void FrozenRegion_StopsAtAnUnknownObject()
    {
        var b = new B();
        b.Data.Zero(8);
        b.Pointer(b.Data, B.TextRva); // not a MethodTable
        b.Data.Zero(16);
        b.Row(SectionId.FrozenObjectRegion, B.DataRva, b.Data.Here);
        var frozen = NativeAotImage.Open(b.Image())!.Frozen;
        Assert.Equal(NativeAotStage.Partial, frozen.Stage.Status);
        Assert.Contains("no MethodTable for the object", frozen.Stage.Detail);
    }

    /// <summary>Mutated images: every stage ends complete, partial, absent or unsupported, never with an exception.</summary>
    [Fact]
    public void MutatedImages_NeverThrow()
    {
        var image = (Native.Pe.PeFile)Build(16).Aot.Image;
        var bytes = image.FileBytes.ToArray();
        Assert.True(image.TryRvaToFileOffset(B.RdataRva, out long start));
        Assert.True(image.TryRvaToFileOffset(B.DataRva, out long dataStart));
        int end = (int)dataStart + 0x400;
        var random = new Random(7);
        string[] statuses = [NativeAotStage.Complete, NativeAotStage.Partial, NativeAotStage.Absent, NativeAotStage.Unsupported];
        for (int i = 0; i < 500; i++)
        {
            var copy = (byte[])bytes.Clone();
            for (int k = 0; k < 8; k++) copy[random.Next((int)start, Math.Min(end, copy.Length))] = (byte)random.Next(256);
            var aot = NativeAotImage.Open(Native.Pe.PeFile.FromBytes(copy));
            if (aot == null) continue;
            Assert.All(aot.Summary().Stages, s => Assert.Contains(s.Status, statuses));
        }
    }
}
