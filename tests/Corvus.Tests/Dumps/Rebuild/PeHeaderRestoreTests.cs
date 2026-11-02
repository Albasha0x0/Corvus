using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Headers restored from the file of the same build.</summary>
public sealed class PeHeaderRestoreTests
{
    private static ushort Magic(byte[] image) =>
        BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C)) + 24));

    private static uint ClrSize(byte[] image) =>
        BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)ManagedHeaderFixtures.ClrRva));

    [Fact]
    public void A_pe32_image_the_loader_widened_is_restored_to_the_file_header()
    {
        var file = ManagedHeaderFixtures.Managed(false);
        var memory = RebuildFixtures.Mapped(ManagedHeaderFixtures.Managed(true));

        var restored = PeHeaderRestore.Restore(memory, file);

        Assert.Equal(0x10B, Magic(restored.Image));
        Assert.Equal("ok", restored.Check.State);
        Assert.Contains("PE32 optional header", restored.Check.Detail);
        Assert.Equal(file.AsSpan(0, 0x200).ToArray(), restored.Image.AsSpan(0, 0x200).ToArray());
    }

    [Fact]
    public void A_cleared_clr_header_is_restored_from_the_file()
    {
        var file = ManagedHeaderFixtures.Managed(false);
        var memory = RebuildFixtures.Mapped(file);
        memory.AsSpan((int)ManagedHeaderFixtures.ClrRva, 72).Clear();

        var restored = PeHeaderRestore.Restore(memory, file);

        Assert.Equal("ok", restored.Check.State);
        Assert.Equal(72u, ClrSize(restored.Image));
        Assert.Equal(ManagedHeaderFixtures.MetadataRva, BinaryPrimitives.ReadUInt32LittleEndian(restored.Image.AsSpan((int)ManagedHeaderFixtures.ClrRva + 8)));
    }

    [Fact]
    public void A_widened_image_with_a_cleared_clr_header_is_restored_in_both_parts()
    {
        var file = ManagedHeaderFixtures.Managed(false);
        var memory = RebuildFixtures.Mapped(ManagedHeaderFixtures.Managed(true));
        memory.AsSpan((int)ManagedHeaderFixtures.ClrRva, 72).Clear();

        var restored = PeHeaderRestore.Restore(memory, file);

        Assert.Equal("ok", restored.Check.State);
        Assert.Contains("CLR header", restored.Check.Detail);
        Assert.Equal(0x10B, Magic(restored.Image));
        Assert.Equal(72u, ClrSize(restored.Image));
    }

    [Fact]
    public void An_image_that_matches_the_file_has_nothing_to_restore()
    {
        var file = ManagedHeaderFixtures.Managed(false);
        var memory = RebuildFixtures.Mapped(file);

        var restored = PeHeaderRestore.Restore(memory, file);

        Assert.Equal("ok", restored.Check.State);
        Assert.Contains("nothing to restore", restored.Check.Detail);
        Assert.Equal(memory, restored.Image);
    }

    [Fact]
    public void The_input_image_is_not_changed()
    {
        var file = ManagedHeaderFixtures.Managed(false);
        var memory = RebuildFixtures.Mapped(ManagedHeaderFixtures.Managed(true));
        var before = (byte[])memory.Clone();

        PeHeaderRestore.Restore(memory, file);

        Assert.Equal(before, memory);
    }

    [Fact]
    public void A_file_of_another_build_is_skipped()
    {
        var file = ManagedHeaderFixtures.Managed(false, stamp: 7);
        var memory = RebuildFixtures.Mapped(ManagedHeaderFixtures.Managed(true));

        var restored = PeHeaderRestore.Restore(memory, file);

        Assert.Equal("skipped", restored.Check.State);
        Assert.Equal(memory, restored.Image);
    }

    [Fact]
    public void A_missing_file_is_skipped()
    {
        var memory = RebuildFixtures.Mapped(ManagedHeaderFixtures.Managed(true));

        Assert.Equal("skipped", PeHeaderRestore.Restore(memory, null).Check.State);
    }

    [Fact]
    public void An_unreadable_file_is_reported_unknown()
    {
        var memory = RebuildFixtures.Mapped(ManagedHeaderFixtures.Managed(true));

        Assert.Equal("unknown", PeHeaderRestore.Restore(memory, new byte[16]).Check.State);
    }
}
