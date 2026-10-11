using System.Buffers.Binary;
using Corvus.Native.NativeAot;
using B = Corvus.Tests.NativeAotBuilder;

namespace Corvus.Tests;

public class NativeAotNameMapTests
{
    /// <summary>NativeFormat unsigned integer.</summary>
    internal static byte[] Unsigned(uint v) => v switch
    {
        < 0x80 => [(byte)(v << 1)],
        < 0x4000 => [(byte)((v << 2) | 1), (byte)(v >> 6)],
        < 0x200000 => [(byte)((v << 3) | 3), (byte)(v >> 5), (byte)(v >> 13)],
        _ => [0x0F, (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24)],
    };

    /// <summary>A NativeHashtable with one bucket: header, two 1-byte bucket offsets, (hash, delta) pairs, then the vertices.</summary>
    internal static byte[] Hashtable(params byte[][] vertices)
    {
        int n = vertices.Length;
        var table = new List<byte> { 0x00, 2, (byte)(2 + 2 * n) };
        int data = 1 + 2 + 2 * n; // offset of the first vertex from the table start
        for (int i = 0; i < n; i++)
        {
            int pos = 1 + 2 + 2 * i + 1;
            int delta = data - pos;
            Assert.InRange(delta, 0, 63);
            table.Add(0x5A); // low hash byte
            table.Add((byte)(delta << 1));
            data += vertices[i].Length;
        }
        foreach (var v in vertices) table.AddRange(v);
        return [.. table];
    }

    /// <summary>Relative pointers (from each slot) to <paramref name="targets"/>, for a table placed at <paramref name="rva"/>.</summary>
    internal static byte[] RelativeTable(uint rva, params uint[] targets)
    {
        var bytes = new byte[4 * targets.Length];
        for (int i = 0; i < targets.Length; i++)
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4 * i), (int)(targets[i] - (rva + 4 * (uint)i)));
        return bytes;
    }

    private const uint SpeakCode = B.TextRva + 0x10, HiddenCode = B.TextRva + 0x20, InvokeCode = B.TextRva + 0x40, GetCode = B.TextRva + 0x50;
    private const uint DogMt = B.DataRva + 0x100, BoxOfIntMt = B.DataRva + 0x200;

    private static NativeAotImage Image(ushort major)
    {
        var m = NativeAotMetadataTests.Model(major);
        var md = new NativeAotMetadata(m.Blob, m.Format);
        uint speakName = md.Ref(m.Speak, "name"), speakSig = md.Ref(m.Speak, "signature");
        var b = new B { Major = major };
        b.Data.Zero(0x300);
        b.Blob(BlobId.EmbeddedMetadata, m.Blob);

        // Stack-trace map, placed at a known RVA so the code pointers can be relative to their slots.
        b.Rdata.Align(4);
        uint at = b.Rdata.Here;
        var st = new List<byte>();
        void Code(uint target)
        {
            var rel = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(rel, (int)(target - (at + (uint)st.Count)));
            st.AddRange(rel);
        }
        if (m.Format.StackTrace == StackTraceFormat.Pairs)
        {
            Code(SpeakCode); st.AddRange(BitConverter.GetBytes(m.Writer.Token(m.Qualified)));
            Code(GetCode); st.AddRange(BitConverter.GetBytes(m.Writer.Token(m.GetInst)));
        }
        else
        {
            st.AddRange(BitConverter.GetBytes(3));
            st.Add(0x10); Code(B.TextRva); // hidden wrapper before any name
            st.Add(0x07); st.AddRange(BitConverter.GetBytes(m.Writer.Token(m.Dog))); st.AddRange(Unsigned(speakName)); st.AddRange(Unsigned(speakSig)); Code(SpeakCode);
            st.Add(0x10); Code(HiddenCode); // same method, another body
        }
        Assert.Equal(at, b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, [.. st]));

        b.Rdata.Align(4);
        uint fixups = b.Rdata.Here;
        Assert.Equal(fixups, b.Blob(BlobId.CommonFixupsTable, RelativeTable(fixups, DogMt, BoxOfIntMt, InvokeCode)));
        b.Blob(BlobId.TypeMap, Hashtable([.. Unsigned(0), .. Unsigned(m.Writer.Token(m.Dog))], [.. Unsigned(1), .. Unsigned(m.Writer.Token(m.BoxOfInt))]));
        uint flags = 0x20 | 0x80 | (m.Format.InvokeMapAlwaysHasMethodHandle ? 0u : 0x4u);
        b.Blob(BlobId.InvokeMap, Hashtable(
            [.. Unsigned(flags), .. Unsigned(m.Speak.Offset), .. Unsigned(0), .. Unsigned(2)],
            [.. Unsigned(0x80), .. Unsigned(m.Speak.Offset), .. Unsigned(0)])); // abstract: no entry point
        return NativeAotImage.Open(b.Image())!;
    }

    [Theory]
    [InlineData((ushort)9)]
    [InlineData((ushort)10)]
    [InlineData((ushort)16)]
    [InlineData((ushort)31)]
    public void StackTraceTypeAndInvokeMaps(ushort major)
    {
        var maps = Image(major).Names;
        Assert.All(maps.Stages, s => Assert.Equal(NativeAotStage.Complete, s.Status));
        var speak = maps.MethodAt[SpeakCode];
        Assert.Equal("Sample.Zoo.Dog::Speak(int, Sample.Zoo.Dog[])", speak.Name.Full);
        Assert.Equal("stacktrace", speak.Origin);
        Assert.True(maps.MethodAt[HiddenCode].Hidden);
        Assert.Equal("Sample.Zoo.Dog::Speak", maps.MethodAt[HiddenCode].Name.Short);
        Assert.False(maps.MethodAt.ContainsKey(B.TextRva)); // nameless hidden wrapper
        Assert.Contains("1 without a name", maps.Stages[0].Detail);
        Assert.Equal(("Sample.Zoo.Dog::Speak(int, Sample.Zoo.Dog[])", "invoke"), (maps.MethodAt[InvokeCode].Name.Full, maps.MethodAt[InvokeCode].Origin));
        Assert.Equal("Sample.Zoo.Dog", maps.TypeNames[DogMt]);
        Assert.Equal("Sample.Zoo.Box<int>", maps.TypeNames[BoxOfIntMt]);
        Assert.Equal([DogMt, BoxOfIntMt, InvokeCode], maps.CommonFixups);
        Assert.Contains("1 methods with entry points named of 2 entries", maps.Stages[2].Detail);
    }

    [Fact]
    public void StackTracePairs_Net7()
    {
        var aot = Image(8);
        var maps = aot.Names;
        Assert.Equal("Sample.Zoo.Dog::Speak(int, Sample.Zoo.Dog[])", maps.MethodAt[SpeakCode].Name.Full);
        Assert.Equal("Sample.Zoo.Box<int>::Get<int>()", maps.MethodAt[GetCode].Name.Full);
        Assert.Contains("token pairs", maps.Stages[0].Detail);
        var summary = aot.Summary();
        Assert.Equal(3, summary.Counts["namedMethods"]); // two stack-trace entries and the invoke-map entry
        Assert.Equal(2, summary.Counts["typeMapMethodTables"]);
    }

    [Fact]
    public void InvokeMapWithoutHandle_BeforeNet10_IsSkipped()
    {
        var m = NativeAotMetadataTests.Model(10);
        var b = new B { Major = 10 };
        b.Blob(BlobId.EmbeddedMetadata, m.Blob);
        b.Rdata.Align(4);
        uint fixups = b.Rdata.Here;
        b.Blob(BlobId.CommonFixupsTable, RelativeTable(fixups, DogMt, InvokeCode));
        b.Blob(BlobId.InvokeMap, Hashtable([.. Unsigned(0x20), .. Unsigned(5), .. Unsigned(0), .. Unsigned(1)])); // name-and-signature vertex, not a handle
        b.Data.Zero(0x200);
        var maps = NativeAotImage.Open(b.Image())!.Names;
        Assert.Empty(maps.Methods);
        Assert.Contains("1 without a metadata handle", maps.Stages[2].Detail);
        Assert.Equal(NativeAotStage.Absent, maps.Stages[0].Status);
        Assert.Equal(NativeAotStage.Absent, maps.Stages[1].Status);
    }

    [Fact]
    public void MissingMetadata_MapsAreUnsupported()
    {
        var b = new B();
        b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
        var maps = NativeAotImage.Open(b.Image())!.Names;
        Assert.Equal(NativeAotStage.Unsupported, maps.Stages[0].Status);
        Assert.Empty(maps.Methods);
    }

    [Fact]
    public void TruncatedStackTrace_IsPartial()
    {
        var m = NativeAotMetadataTests.Model(16);
        var b = new B();
        b.Blob(BlobId.EmbeddedMetadata, m.Blob);
        b.Blob(BlobId.StackTraceMethodRvaToTokenMapping, [5, 0, 0, 0, 0x01, 1, 2]); // owner token cut short
        var maps = NativeAotImage.Open(b.Image())!.Names;
        Assert.Equal(NativeAotStage.Partial, maps.Stages[0].Status);
    }
}
