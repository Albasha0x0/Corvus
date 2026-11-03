using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The row features of the changes view leave its output unchanged until they are filled in.</summary>
public sealed class DumpRowFeatureTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Default_row_features_leave_the_changes_view_unchanged()
    {
        var app = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())]));
        var mapped = RebuildFixtures.Mapped(app.Bytes);
        mapped[0x1000] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(mapped.AsSpan(0x1001), 0x100);
        mapped[0x1010] = 0x0F;
        var b = new MinidumpBuilder();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(nt + 8)), "app.exe"));
        b.Memory.Add((AppBase, mapped));
        var dump = _dir.File("rows.dmp");
        File.WriteAllBytes(dump, b.Build());
        var images = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(images, "app.exe"), app.Bytes);
        using var service = new MinidumpService();

        var rows = service.Changes(dump, images, "app.exe", 0, 50, CancellationToken.None).Rows;

        Assert.Equal(["code", "code"], rows.Select(r => r.Kind));
        Assert.StartsWith("jump to 0x", rows[0].Description);
        Assert.Equal("bytes changed", rows[1].Description);
        Assert.DoesNotContain(rows, r => r.Kind is "section" or "pointer");
        using var memory = MinidumpFile.Open(dump);
        Assert.Equal("", MinidumpService.ChainText(memory, new ExportMap(memory), AppBase, NativeArch.X64));
    }
}
