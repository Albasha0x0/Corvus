using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>summarize_file view=firmware: formats found at their offsets, sized by their own headers.</summary>
public sealed class FirmwareViewTests
{
    private static byte[] Image()
    {
        var d = new byte[0x10000];
        new Random(7).NextBytes(d.AsSpan(0x100, 0x1000));
        // uImage: magic, data size, image name
        BinaryPrimitives.WriteUInt32BigEndian(d, 0x27051956);
        BinaryPrimitives.WriteUInt32BigEndian(d.AsSpan(12), 0x1000);
        d[28] = 5; d[29] = 2; d[30] = 2;
        Encoding.ASCII.GetBytes("Linux-6.1").CopyTo(d, 32);
        // squashfs superblock: magic, version 4.0, bytes used
        "hsqs"u8.CopyTo(d.AsSpan(0x2000));
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0x2000 + 28), 4);
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x2000 + 40), 0x1000);
        // an ELF64 header and a gzip member
        d[0x8000] = 0x7F; "ELF"u8.CopyTo(d.AsSpan(0x8001)); d[0x8004] = 2; d[0x8005] = 1;
        d[0xA000] = 0x1F; d[0xA001] = 0x8B; d[0xA002] = 8;
        return d;
    }

    private static FirmwareFileView.Facts? Facts(byte[] d) =>
        new FirmwareFileView().Inspect(new FileInput("fw.bin", d, Blob.Identify(d)), default)?.Detail as FirmwareFileView.Facts;

    [Fact]
    public void Formats_are_found_at_their_offsets()
    {
        var hits = Facts(Image())!.Signatures.Select(h => $"{h.Offset} {h.Format} {h.Size}").ToList();
        Assert.Contains("0x0 U-Boot uImage 4160", hits);
        Assert.Contains("0x2000 squashfs (little endian) 4096", hits);
        Assert.Contains("0x8000 ELF64 ", hits);
        Assert.Contains("0xA000 gzip ", hits);
    }

    [Fact]
    [FuzzEntry(typeof(FirmwareFileView))]
    public void Fuzzed_images_never_throw()
    {
        var failures = FormatFuzz.Run(Image(), b => Facts(b), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
