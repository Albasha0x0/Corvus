using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Sites the loader rewrites in an ARM64 image are restored from the file of the same build.</summary>
public sealed class LoaderPatchArm64Tests : IDisposable
{
    private const ulong Loaded = 0x180000000UL;
    private const uint Text = 0x1000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private RebuiltModule Rebuild(LoaderPatchImageArm64 image)
    {
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "patched.dll"), image.Linked);
        using var dump = RebuildFixtures.Dump(_dir, new Placed("patched.dll", new PeBuilt(image.Patched, new Dictionary<string, uint>()), Loaded));
        var options = RebuildOptions.Default with { Base = BaseMode.Preferred, CompareWithDisk = false, Layout = OutputLayout.Mapped, ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    private static RebuildCheck Check(RebuiltModule m) => Assert.Single(m.Checks, c => c.Name == "loader patches");

    private static byte[] Slice(byte[] bytes, uint textOffset, int length) => bytes.AsSpan((int)(Text + textOffset), length).ToArray();

    [Fact]
    public void An_arm64x_fixup_is_restored_from_the_file()
    {
        // A value of 4 bytes at 0x10, a zero fill of 8 bytes at 0x28 and a
        // delta of 4 bytes at 0x30.
        var body = LoaderPatchImageArm64.Arm64XBody(
            LoaderPatchImageArm64.Fixup(0x10, 1, 2), 0x1111, 0x2222,
            LoaderPatchImageArm64.Fixup(0x28, 0, 3),
            LoaderPatchImageArm64.Fixup(0x30, 2, 2), 0x0004);
        var image = LoaderPatchImageArm64.Build((6, body));
        var m = Rebuild(image);

        Assert.Equal(("ok", "3 sites restored from the file"), (Check(m).State, Check(m).Detail));
        var linked = RebuildFixtures.Mapped(image.Linked);
        foreach (var (at, length) in new[] { (0x10u, 4), (0x28u, 8), (0x30u, 4) })
            Assert.Equal(Slice(linked, at, length), Slice(m.Bytes!, at, length));
        Assert.All(Slice(m.Bytes!, 0x14, 0x14), b => Assert.Equal(0xEE, b));
    }

    [Fact]
    public void An_arm64_import_control_transfer_site_is_restored_from_the_file()
    {
        var image = LoaderPatchImageArm64.Build((3, LoaderPatchImageArm64.ImportTransferBody(0x20)));
        var m = Rebuild(image);

        Assert.Equal(("ok", "1 sites restored from the file"), (Check(m).State, Check(m).Detail));
        var linked = RebuildFixtures.Mapped(image.Linked);
        Assert.Equal(Slice(linked, 0x20, 4), Slice(m.Bytes!, 0x20, 4));
        Assert.Equal(0xEE, m.Bytes![(int)Text + 0x24]);
    }

    [Fact]
    public void An_unread_arm64_record_kind_is_named_partial()
    {
        var image = LoaderPatchImageArm64.Build((3, LoaderPatchImageArm64.ImportTransferBody(0x20)), (8, []));
        var m = Rebuild(image);

        Assert.Equal(("partial", "1 of 1 sites restored from the file; not read: ARM64 kernel import call transfer"), (Check(m).State, Check(m).Detail));
    }
}
