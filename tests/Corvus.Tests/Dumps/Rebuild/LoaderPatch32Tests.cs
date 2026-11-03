using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Sites the loader rewrites in a 32-bit image are restored from the file of the same build.</summary>
public sealed class LoaderPatch32Tests : IDisposable
{
    private const ulong Loaded = 0x20000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private RebuiltModule Rebuild(LoaderPatchImage32 image, BaseMode mode)
    {
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "patched.dll"), image.Linked);
        using var dump = RebuildFixtures.Dump(_dir, new Placed("patched.dll", new PeBuilt(image.Patched, new Dictionary<string, uint>()), Loaded));
        var options = RebuildOptions.Default with { Base = mode, CompareWithDisk = false, Layout = OutputLayout.Mapped, ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    private static RebuildCheck Check(RebuiltModule m) => Assert.Single(m.Checks, c => c.Name == "loader patches");

    private static uint Word(RebuiltModule m, uint rva) => BinaryPrimitives.ReadUInt32LittleEndian(m.Bytes!.AsSpan((int)rva));

    [Fact]
    public void A_32_bit_guard_slot_is_restored_from_the_file()
    {
        var image = LoaderPatchImage32.Build();
        var m = Rebuild(image, BaseMode.Preferred);

        Assert.Equal(("ok", "3 sites restored from the file"), (Check(m).State, Check(m).Detail));
        Assert.Equal(image.LinkedBase + 0x1020, Word(m, image.CheckSlotRva));
        Assert.Equal(image.LinkedBase + 0x1030, Word(m, image.DispatchSlotRva));
    }

    [Fact]
    public void A_32_bit_function_override_site_is_restored_from_the_file()
    {
        var image = LoaderPatchImage32.Build();
        var m = Rebuild(image, BaseMode.Preferred);

        Assert.Equal("ok", Check(m).State);
        Assert.Equal(0x20, BinaryPrimitives.ReadInt32LittleEndian(m.Bytes!.AsSpan((int)image.ThunkRva + 1)));
    }

    [Fact]
    public void A_32_bit_record_kind_that_is_not_read_is_named_and_reported_partial()
    {
        var image = LoaderPatchImage32.Build();
        var linked = (byte[])image.Linked.Clone();
        var patched = (byte[])image.Patched.Clone();
        foreach (var bytes in new[] { linked, patched })
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(LoaderPatchImage.RawAt(bytes, 0x2000 + 0x200 + 8)), 2);
        var m = Rebuild(image with { Linked = linked, Patched = patched }, BaseMode.Preferred);

        Assert.Equal(("partial", "2 of 2 sites restored from the file; not read: guard RF epilogue"), (Check(m).State, Check(m).Detail));
    }

    [Fact]
    public void A_32_bit_slot_takes_the_load_delta_when_the_loaded_base_is_kept()
    {
        var image = LoaderPatchImage32.Build();
        var m = Rebuild(image, BaseMode.Loaded);

        Assert.Equal("ok", Check(m).State);
        Assert.Equal((uint)Loaded + 0x1020, Word(m, image.CheckSlotRva));
        Assert.Equal((uint)Loaded + 0x1030, Word(m, image.DispatchSlotRva));
    }
}
