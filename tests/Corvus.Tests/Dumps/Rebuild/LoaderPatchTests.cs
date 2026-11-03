using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Sites the loader rewrites are restored from the file of the same build when a module is rebuilt.</summary>
public sealed class LoaderPatchTests : IDisposable
{
    private const ulong Loaded = 0x180000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private RebuiltModule Rebuild(LoaderPatchImage image, bool withFile, BaseMode mode, OutputLayout layout = OutputLayout.Mapped, byte[]? memory = null)
    {
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        if (withFile) File.WriteAllBytes(Path.Combine(folder, "patched.dll"), image.Linked);
        using var dump = RebuildFixtures.Dump(_dir, new Placed("patched.dll", new PeBuilt(memory ?? image.Patched, new Dictionary<string, uint>()), Loaded));
        var options = RebuildOptions.Default with { Base = mode, CompareWithDisk = false, Layout = layout, ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    private static RebuildCheck Check(RebuiltModule m) => Assert.Single(m.Checks, c => c.Name == "loader patches");

    [Fact]
    public void Patched_sites_are_restored_from_the_file_at_the_preferred_base()
    {
        var image = LoaderPatchImage.Build();
        var m = Rebuild(image, true, BaseMode.Preferred);

        Assert.Equal(("ok", "2 sites restored from the file"), (Check(m).State, Check(m).Detail));
        Assert.Equal(BinaryPrimitives.ReadInt32LittleEndian(image.Linked.AsSpan(LoaderPatchImage.RawAt(image.Linked, image.ThunkRva) + 1)),
            BinaryPrimitives.ReadInt32LittleEndian(m.Bytes!.AsSpan((int)image.ThunkRva + 1)));
        Assert.Equal(image.LinkedBase + 0x1020, BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes.AsSpan((int)image.SlotRva)));
    }

    [Fact]
    public void A_restored_address_follows_the_loaded_base_when_the_image_keeps_it()
    {
        var image = LoaderPatchImage.Build();
        var m = Rebuild(image, true, BaseMode.Loaded);

        Assert.Equal("ok", Check(m).State);
        Assert.Equal(Loaded + 0x1020, BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes!.AsSpan((int)image.SlotRva)));
    }

    [Fact]
    public void Without_a_file_the_patched_sites_are_counted_and_kept()
    {
        var image = LoaderPatchImage.Build();
        var m = Rebuild(image, false, BaseMode.Loaded);

        Assert.Equal(("unknown", "2 loader-patched sites kept: no file of the same build"), (Check(m).State, Check(m).Detail));
        Assert.Equal(0x1818B8140UL + (Loaded - image.LinkedBase), BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes!.AsSpan((int)image.SlotRva)));
        Assert.Equal(0x7FFF0000, BinaryPrimitives.ReadInt32LittleEndian(m.Bytes.AsSpan((int)image.ThunkRva + 1)));
    }

    [Fact]
    public void An_image_without_dynamic_relocations_skips_the_check()
    {
        var m = Rebuild(LoaderPatchImage.Build(withTable: false), true, BaseMode.Loaded);

        Assert.Equal(("skipped", "no dynamic relocations"), (Check(m).State, Check(m).Detail));
    }

    [Fact]
    public void An_unread_record_kind_is_named_and_reported_partial()
    {
        var image = LoaderPatchImage.Build();
        var linked = (byte[])image.Linked.Clone();
        var patched = (byte[])image.Patched.Clone();
        foreach (var bytes in new[] { linked, patched })
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(LoaderPatchImage.RawAt(bytes, 0x2000 + 0x200 + 8)), 1);
        var m = Rebuild(image with { Linked = linked, Patched = patched }, true, BaseMode.Preferred);

        Assert.Equal(("partial", "1 of 1 sites restored from the file; not read: guard RF prologue"), (Check(m).State, Check(m).Detail));
    }

    [Fact]
    public void The_checksum_of_a_written_file_verifies_and_the_security_directory_is_cleared()
    {
        var image = LoaderPatchImage.Build();
        var memory = (byte[])image.Patched.Clone();
        BinaryPrimitives.WriteUInt64LittleEndian(memory.AsSpan(LoaderPatchImage.DirectoryAt(memory, 4)), 0x0000_0100_0001_F000UL);
        var m = Rebuild(image, true, BaseMode.Preferred, OutputLayout.File, memory);

        Assert.True(PeFile.FromBytes(m.Bytes!).Checksum.Matches);
        Assert.Equal(0UL, BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes.AsSpan(LoaderPatchImage.DirectoryAt(m.Bytes!, 4))));
        var layout = Assert.Single(m.Checks, c => c.Name == "layout");
        Assert.Contains("security directory cleared", layout.Detail);
        Assert.Contains("checksum recomputed", layout.Detail);
    }
}
