using Corvus.Native.Dump;

namespace Corvus.Tests;

/// <summary>The function table stream of a minidump is read as absolute ranges.</summary>
public sealed class FunctionTableStreamTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Function_table_entries_are_read_as_absolute_ranges()
    {
        var stream = FunctionTableFixtures.Stream([
            new(0x7000_0000, 0x7000_2000, 0x7000_0000, [(0x100, 0x180, 0x1000), (0x200, 0x240, 0x1010)]),
            new(0x9000_0000, 0x9000_1000, 0x9000_0000, [(0x10, 0x20, 0x800)]),
        ]);
        using var dump = MinidumpFile.Open(FunctionTableFixtures.Dump(_dir, stream));

        var result = MinidumpFunctionTables.Read(dump, out var reason);

        Assert.Null(reason);
        Assert.NotNull(result);
        Assert.Equal(2, result.Tables.Count);
        Assert.Equal(0x7000_2000UL, result.Tables[0].MaximumAddress);
        Assert.Equal([new RegisteredFunction(0x7000_0100, 0x7000_0180, 0x7000_1000), new RegisteredFunction(0x7000_0200, 0x7000_0240, 0x7000_1010)],
            result.Tables[0].Functions);
        Assert.Equal(new RegisteredFunction(0x9000_0010, 0x9000_0020, 0x9000_0800), Assert.Single(result.Tables[1].Functions));
    }

    [Fact]
    public void A_truncated_stream_is_refused_with_the_reason()
    {
        var full = FunctionTableFixtures.Stream([new(0, 0x1000, 0x5000, [(1, 2, 3), (4, 5, 6)])]);
        using var dump = MinidumpFile.Open(FunctionTableFixtures.Dump(_dir, full[..^6]));

        var result = MinidumpFunctionTables.Read(dump, out var reason);

        Assert.Null(result);
        Assert.Contains("truncated", reason);
    }

    [Fact]
    public void A_dump_without_the_stream_returns_none()
    {
        var path = _dir.File("plain.dmp");
        File.WriteAllBytes(path, new MinidumpBuilder().Build());
        using var dump = MinidumpFile.Open(path);

        Assert.Null(MinidumpFunctionTables.Read(dump, out var reason));
        Assert.Null(reason);
    }

    [Fact]
    public void A_dump_built_from_bytes_reads_its_function_table_stream()
    {
        var stream = FunctionTableFixtures.Stream([new(0x7000_0000, 0x7000_2000, 0x7000_0000, [(0x100, 0x180, 0x1000)])]);
        var b = new MinidumpBuilder();
        b.ExtraStreams.Add((FunctionTableFixtures.StreamType, stream));
        using var dump = MinidumpFile.FromBytes(b.Build());

        var result = MinidumpFunctionTables.Read(dump, out var reason);

        Assert.Null(reason);
        Assert.NotNull(result);
        Assert.Equal(new RegisteredFunction(0x7000_0100, 0x7000_0180, 0x7000_1000), Assert.Single(Assert.Single(result.Tables).Functions));
    }
}
