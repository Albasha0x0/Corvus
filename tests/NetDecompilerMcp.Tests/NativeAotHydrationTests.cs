using System.Buffers.Binary;
using NetDecompilerMcp.Native.NativeAot;
using B = NetDecompilerMcp.Tests.NativeAotBuilder;

namespace NetDecompilerMcp.Tests;

public class NativeAotHydrationTests
{
    /// <summary>DehydratedDataCommand.Encode: payload above 28 moves to 1–3 little-endian extra bytes.</summary>
    internal static byte[] Command(int command, int payload)
    {
        if (payload <= 28) return [(byte)(command | (payload << 3))];
        var extra = new List<byte>();
        for (int rest = payload - 28; rest != 0; rest >>= 8) extra.Add((byte)rest);
        return [(byte)(command | ((28 + extra.Count) << 3)), .. extra];
    }

    /// <summary>
    /// Writes section 207 rehydrating <paramref name="commands"/> into the hydrated section; <paramref name="fixups"/> are
    /// the targets of the fixup table, written right after the command stream.
    /// </summary>
    internal static void Dehydrated(B b, byte[] commands, uint[] fixups, bool lengthPrefixed = false)
    {
        b.Rdata.Align(4);
        uint start = b.Rdata.U32(0);
        b.Rdata.Patch32(start, B.HydratedRva - start);
        if (lengthPrefixed) b.Rdata.U32((uint)(8 + commands.Length));
        b.Rdata.Bytes(commands);
        uint end = b.Rdata.Here;
        foreach (var target in fixups)
        {
            uint at = b.Rdata.Here;
            b.Rdata.U32(target - at);
        }
        b.Row(SectionId.DehydratedData, start, lengthPrefixed ? b.Rdata.Here : end);
    }

    private static readonly byte[] Bytes40 = [.. Enumerable.Range(10, 40).Select(i => (byte)i)];

    /// <summary>
    /// Every command, short and extended payloads, both pointer forms, both fixup forms; inline operands are rel32 from
    /// their own position, so they are written for the stream's final RVA.
    /// </summary>
    private static HydratedImage Build(ushort major, bool lengthPrefixed)
    {
        var b = new B { Major = major };
        b.Rdata.Align(4);
        uint streamRva = b.Rdata.Here + (lengthPrefixed ? 8u : 4u);
        var cmds = new List<byte>();
        void Inline(uint target)
        {
            var operand = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(operand, (int)(target - (streamRva + (uint)cmds.Count)));
            cmds.AddRange(operand);
        }
        cmds.AddRange(Command(0, 3)); cmds.AddRange([1, 2, 3]);
        cmds.AddRange(Command(1, 5));
        cmds.AddRange(Command(0, 40)); cmds.AddRange(Bytes40);
        cmds.AddRange(Command(3, 1));
        cmds.AddRange(Command(2, 0));
        cmds.AddRange(Command(5, 2)); Inline(B.TextRva + 0x20); Inline(B.DataRva);
        cmds.AddRange(Command(4, 1)); Inline(B.RdataRva);
        cmds.AddRange(Command(1, 300));
        Dehydrated(b, [.. cmds], [B.TextRva, B.DataRva + 0x10], lengthPrefixed);
        b.Data.Zero(0x40);
        var image = b.Image();
        return HydratedImage.Create(image, Assert.Single(NativeAotLocator.Find(image)));
    }

    [Theory]
    [InlineData((ushort)9, false)]
    [InlineData((ushort)16, false)]
    [InlineData((ushort)31, true)]
    [InlineData((ushort)20, true)] // unknown major: the length header is detected
    public void Rehydrate_AllCommands(ushort major, bool lengthPrefixed)
    {
        var h = Build(major, lengthPrefixed);
        Assert.Equal(NativeAotStage.Complete, h.Stage.Status);
        Assert.Equal(B.HydratedRva, h.DestinationRva);
        Assert.Equal(380, h.HydratedLength);
        var bytes = new byte[380];
        Assert.Equal(380, h.Read(B.HydratedRva, bytes));
        Assert.Equal([1, 2, 3, 0, 0, 0, 0, 0], bytes[..8]);
        Assert.Equal(Bytes40, bytes[8..48]);
        Assert.Equal(B.DataRva + 0x10, h.PointerAt(B.HydratedRva + 48));
        Assert.Equal(B.TextRva, h.RelativeAt(B.HydratedRva + 56));
        Assert.Equal(B.TextRva + 0x20, h.PointerAt(B.HydratedRva + 60));
        Assert.Equal(B.DataRva, h.PointerAt(B.HydratedRva + 68));
        Assert.Equal(B.RdataRva, h.RelativeAt(B.HydratedRva + 76));
        Assert.All(bytes[80..], x => Assert.Equal(0, x));
        Assert.True(h.IsPointerSlot(B.HydratedRva + 48) && h.IsPointerSlot(B.HydratedRva + 60) && h.IsPointerSlot(B.HydratedRva + 68));
        Assert.False(h.IsPointerSlot(B.HydratedRva + 56));
        Assert.NotNull(h.Sha256);
        Assert.Equal(1, h.View.U8(B.HydratedRva)); // reads through the overlay, the section has no raw bytes
    }

    [Fact]
    public void NotDehydrated_PointerSlotsAreRelocations()
    {
        var b = new B();
        uint slot = b.Pointer(b.Data, B.TextRva);
        b.Row(206, B.DataRva, B.DataRva + 8);
        var image = b.Image();
        var h = HydratedImage.Create(image, Assert.Single(NativeAotLocator.Find(image)));
        Assert.Equal(NativeAotStage.Absent, h.Stage.Status);
        Assert.Equal(0, h.HydratedLength);
        Assert.True(h.IsPointerSlot(slot));
        Assert.Equal(B.TextRva, h.PointerAt(slot));
    }

    [Fact]
    public void Malformed_StopsWithPartialStage()
    {
        var b = new B();
        Dehydrated(b, [.. Command(0, 3), 1, 2, 3, 6], []); // command 6 does not exist
        var image = b.Image();
        var h = HydratedImage.Create(image, Assert.Single(NativeAotLocator.Find(image)));
        Assert.Equal(NativeAotStage.Partial, h.Stage.Status);
        Assert.Contains("unknown dehydrated command 6", h.Stage.Detail);
        Assert.Equal(3, h.HydratedLength);

        var overflow = new B();
        Dehydrated(overflow, Command(1, (int)B.HydratedSize + 1), []);
        image = overflow.Image();
        h = HydratedImage.Create(image, Assert.Single(NativeAotLocator.Find(image)));
        Assert.Contains("overflows its destination", h.Stage.Detail);
    }
}
