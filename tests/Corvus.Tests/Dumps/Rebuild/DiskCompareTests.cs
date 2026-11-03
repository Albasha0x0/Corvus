using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A rebuilt image is compared with its file on disk, section by section.</summary>
public sealed class DiskCompareTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(ulong? imageBase = null)
    {
        var code = new byte[0x40];
        Array.Fill(code, (byte)0x90);
        return new PeSpec(true, [new SectionSpec(".text", 0x60000020, code), new SectionSpec(".data", 0xC0000040, new byte[0x40])],
            [new PointerSite(".data", 8, 0x1000)], imageBase);
    }

    private RebuiltModule Rebuild(PeBuilt built, ulong at, byte[] disk)
    {
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "probe.dll"), disk);
        using var dump = RebuildFixtures.Dump(_dir, new Placed("probe.dll", built, at));
        var options = RebuildOptions.Default with { ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    [Fact]
    [FuzzEntry(typeof(DiskCompare))]
    public void Fuzzed_images_never_throw_when_parsed_for_a_comparison()
    {
        var failures = FormatFuzz.Run(RebuildFixtures.Pe(Spec()), b => _ = DiskCompare.TryParse(b, out _), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void A_patched_instruction_in_memory_is_reported_as_a_differing_code_range()
    {
        var disk = RebuildFixtures.Pe(Spec());
        var patched = RebuildFixtures.Build(Spec());
        int text = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(patched.Bytes.AsSpan(0x40 + 24 + 240 + 20));
        patched.Bytes[text + 0x10] = 0xCC;
        patched.Bytes[text + 0x11] = 0xCC;

        var m = Rebuild(patched, 0x140000000UL, disk);

        var range = Assert.Single(m.Disk!.Differences);
        Assert.Equal(2, m.Disk.DifferingBytes);
        Assert.Equal(1, m.Disk.Ranges);
        Assert.Equal(".text", range.Section);
        Assert.Equal("0x1010", range.Start);
        Assert.Equal(2, range.Length);
        Assert.True(range.Code);
        Assert.Equal("partial", Assert.Single(m.Checks, c => c.Name == "disk").State);
    }

    [Fact]
    public void An_image_moved_by_the_loader_compares_equal_after_its_fixups_are_left_out()
    {
        var built = RebuildFixtures.Build(Spec());

        var m = Rebuild(built, 0x150000000UL, built.Bytes);

        Assert.Equal(0, m.Disk!.DifferingBytes);
        var check = Assert.Single(m.Checks, c => c.Name == "disk");
        Assert.Equal("ok", check.State);
        Assert.Equal("same as the file", check.Detail);
    }
}
