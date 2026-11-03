using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Change rows of a dump group by shape, with the count of each group.</summary>
public sealed class DumpChangeGroupTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Repeated_stubs_are_one_group_with_their_count(bool is64)
    {
        var dump = StubFixtures.Repeated(_dir, is64, 6);
        using var service = new MinidumpService();

        var (_, rows, total, _) = service.ChangeGroups(dump.DumpPath, dump.ImageFolder, null, 0, 100, default);

        var group = Assert.Single(rows);
        Assert.Equal(1, total);
        Assert.Equal(6, group.Count);
        Assert.Equal("code", group.Kind);
        Assert.Equal($"0x{dump.Stubs[0]:X}", group.FirstAddress);
        Assert.Equal($"0x{dump.Stubs[^1]:X}", group.LastAddress);
        Assert.Equal(6L * 3, group.Bytes);
        Assert.NotNull(group.Description);
    }

    [Fact]
    public void Groups_page_like_rows()
    {
        var dump = StubFixtures.Repeated(_dir, true, 4);
        using var service = new MinidumpService();

        var past = service.ChangeGroups(dump.DumpPath, dump.ImageFolder, null, 1, 100, default);
        var capped = service.ChangeGroups(dump.DumpPath, dump.ImageFolder, null, 0, 1, default);

        Assert.Empty(past.Rows);
        Assert.Equal(1, past.Total);
        Assert.Single(capped.Rows);
        Assert.Equal(1, capped.Total);
        Assert.Equal(1, service.ChangeComputations);
    }

    [Fact]
    public void An_unknown_kind_is_its_own_group()
    {
        var dump = StubFixtures.Repeated(_dir, true, 3);
        var empty = Directory.CreateDirectory(_dir.File("none")).FullName;
        using var service = new MinidumpService();

        var (_, rows, _, _) = service.ChangeGroups(dump.DumpPath, empty, null, 0, 100, default);

        var group = Assert.Single(rows);
        Assert.Equal("unknown", group.Kind);
        Assert.StartsWith("unknown ", group.Shape);
        Assert.Equal(1, group.Count);
    }
}
