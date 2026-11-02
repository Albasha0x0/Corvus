using Corvus.Native;
using Corvus.Native.Emulation;

namespace Corvus.Tests;

public sealed class EmulatorMemorySnapshotTests
{
    private const ulong Base = 0x10000, Region = 0x400000;
    private const int Pages = 600;

    // Incompressible pages, so the deflate stream returns in several chunks.
    [Fact]
    public void Hundreds_of_incompressible_pages_load_back_exactly()
    {
        var image = new byte[64];
        RawCodeImage Make() => new(image, "m.bin", RawLayout.Parse("arm64", $"0x{Base:x}", null, image.Length));
        var memory = new EmulatorMemory(Make(), Base, Region, 0x2000000);
        var data = new byte[Pages * 4096];
        new Random(5).NextBytes(data);
        memory.Write(Region, data);
        using var ms = new MemoryStream();
        using (var packed = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
        using (var w = new BinaryWriter(packed)) memory.Save(w);
        ms.Position = 0;
        var loaded = new EmulatorMemory(Make(), Base, Region, 0x2000000);
        using (var packed = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress))
        using (var r = new BinaryReader(packed)) loaded.Load(r);
        var back = new byte[data.Length];
        loaded.Read(Region, back);
        Assert.Equal(data, back);
    }
}
