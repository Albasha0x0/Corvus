using System.Buffers.Binary;
using NetDecompilerMcp.Native.NativeAot;
using B = NetDecompilerMcp.Tests.NativeAotBuilder;
using E = NetDecompilerMcp.Native.NativeAot.NativeAotElementType;
using static NetDecompilerMcp.Tests.NativeAotNameMapTests;

namespace NetDecompilerMcp.Tests;

public class NativeAotTypeTests
{
    private const uint SpeakCode = B.TextRva + 0x10, ToStringCode = B.TextRva + 0x60, EqualsCode = B.TextRva + 0x70, HashCode = B.TextRva + 0x80;
    private const uint KindCanonical = 0, KindGenericDefinition = 3;
    private const uint IsGeneric = 0x02000000, IsGeneric7 = 0x400;

    /// <summary>Writes a 64-bit MethodTable of <paramref name="layout"/> into .data; returns its RVA.</summary>
    private static uint Mt(B b, MethodTableLayout layout, E element, uint kind, uint baseSize, uint related, uint[] vtable, uint[] interfaces,
        ushort componentSize = 0, uint genericDefinition = 0, uint genericArgument = 0)
    {
        var d = b.Data;
        d.Align(8);
        bool generic = genericDefinition != 0;
        if (layout == MethodTableLayout.Net7)
        {
            d.U16(componentSize);
            d.U16((ushort)(((uint)element << 11) | kind | (generic ? IsGeneric7 : 0)));
        }
        else
        {
            uint flags = ((uint)element << 26) | (kind << 16) | (generic ? IsGeneric : 0);
            if (componentSize != 0) flags |= 0x80000000 | componentSize;
            d.U32(flags);
        }
        uint at = d.Rva + (uint)d.Length - 4;
        d.U32(baseSize);
        if (related != 0) b.Pointer(d, related); else d.U64(0);
        d.U16((ushort)vtable.Length);
        d.U16((ushort)interfaces.Length);
        d.U32(0x1234);
        foreach (var v in vtable) b.Pointer(d, v);
        foreach (var i in interfaces) b.Pointer(d, i);
        d.U32(0); // type manager indirection
        d.U32(0); // writable data
        if (generic && layout != MethodTableLayout.Net7)
        {
            uint def = d.Here;
            d.U32(genericDefinition - def);
            uint arg = d.Here;
            d.U32(genericArgument - arg); // arity 1: the composition is the argument itself
        }
        return at;
    }

    private sealed record World(NativeAotImage Aot, uint Object, uint Speaker, uint Dog, uint DogArray, uint BoxDefinition, uint BoxOfDog, uint Frozen, uint LookAlike);

    private static World Build(ushort major)
    {
        var m = NativeAotMetadataTests.Model(major);
        var md = new NativeAotMetadata(m.Blob, m.Format);
        var layout = m.Format.Layout;
        var b = new B { Major = major };
        b.Text = new byte[0x200];
        b.Blob(BlobId.EmbeddedMetadata, m.Blob);

        uint obj = Mt(b, layout, E.Class, KindCanonical, 0x18, 0, [ToStringCode, EqualsCode, HashCode], []);
        uint speaker = Mt(b, layout, E.Interface, KindCanonical, 0, 0, [], []);
        uint dog = Mt(b, layout, E.Class, KindCanonical, 0x20, obj, [SpeakCode, EqualsCode, HashCode], [speaker]);
        uint dogArray = Mt(b, layout, E.SzArray, KindCanonical, 0x18, dog, [ToStringCode, EqualsCode, HashCode], [], componentSize: 8);
        // .NET 9+: a generic definition's BaseSize is its arity; .NET 8: its component size.
        uint boxDef = Mt(b, layout, E.Class, KindGenericDefinition, 1, 0, [], [], componentSize: (ushort)(layout == MethodTableLayout.Net8 ? 1 : 0));
        uint boxOfDog = Mt(b, layout, E.Class, KindCanonical, 0x20, obj, [ToStringCode, EqualsCode, HashCode], [], genericDefinition: boxDef, genericArgument: dog);
        // A frozen object (header, MethodTable pointer) and a statics base whose +8 points at Dog: neither is a MethodTable.
        b.Data.Align(8);
        uint frozen = b.Data.Zero(8);
        b.Pointer(b.Data, dog);
        b.Data.U64(0);
        uint frozenEnd = b.Data.Here;
        b.Row(SectionId.FrozenObjectRegion, frozen, frozenEnd);
        uint lookAlike = b.Data.U32(layout == MethodTableLayout.Net7 ? 0x4000_0000u : (uint)E.Int32 << 26);
        b.Data.U32(0x40);
        b.Pointer(b.Data, dog);
        b.Data.Zero(16);

        // Names: the type map names Object and the Box`1 definition; the stack-trace map names Dog::Speak (vtable owner).
        b.Rdata.Align(4);
        uint fixups = b.Rdata.Here;
        b.Blob(BlobId.CommonFixupsTable, RelativeTable(fixups, obj, boxDef));
        b.Blob(BlobId.TypeMap, Hashtable([.. Unsigned(0), .. Unsigned(m.Writer.Token(m.Object))], [.. Unsigned(1), .. Unsigned(m.Writer.Token(m.Box))]));
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
            map[0] = 1;
            map[4] = 0x03;
            BinaryPrimitives.WriteUInt32LittleEndian(map.AsSpan(5), m.Writer.Token(m.Dog));
            Unsigned(name).CopyTo(map, 9);
            int code = Unsigned(name).Length + 9;
            Array.Resize(ref map, code + 4);
            BinaryPrimitives.WriteInt32LittleEndian(map.AsSpan(code), (int)(SpeakCode - (st + (uint)code)));
        }
        Assert.Equal(st, b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, map));
        var aot = NativeAotImage.Open(b.Image())!;
        return new World(aot, obj, speaker, dog, dogArray, boxDef, boxOfDog, frozen, lookAlike);
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
        Assert.False(types.ContainsKey(w.Frozen));
        Assert.False(types.ContainsKey(w.LookAlike));
        Assert.Equal(6, types.Count);
        var summary = w.Aot.Summary();
        Assert.Equal((6, 5), (summary.Counts["methodTables"], summary.Counts["namedMethodTables"]));
    }

    [Fact]
    public void Crawl_Net7Layout()
    {
        var w = Build(8);
        var types = w.Aot.Types.ByRva;
        Assert.Equal(NativeAotStage.Partial, w.Aot.Types.Stage.Status);
        Assert.Contains("generic instantiations are not decoded", w.Aot.Types.Stage.Detail);
        Assert.Equal("System.Object", types[w.Object].Name);
        Assert.Equal("Sample.Zoo.Dog", types[w.Dog].Name);
        Assert.Equal("Sample.Zoo.Dog[]", types[w.DogArray].Name);
        Assert.Equal("generated", types[w.BoxOfDog].NameOrigin);
        Assert.False(types.ContainsKey(w.LookAlike));
    }
}
