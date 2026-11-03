using System.Buffers.Binary;
using System.IO.Compression;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>FileTimes: the times stored inside a file, read by content as Timesketch events.</summary>
public sealed class FileTimesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly DateTime Stamp = new(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);

    private string Pe(uint stamp)
    {
        var bytes = File.ReadAllBytes(typeof(FileTimesTests).Assembly.Location);
        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(lfanew + 8), stamp);
        var path = _dir.File("image.bin");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private string Write(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void A_pe_header_stamp_is_one_event()
    {
        var result = FileTimes.Read(Pe((uint)new DateTimeOffset(Stamp).ToUnixTimeSeconds()), default);
        var e = Assert.Single(result.Events);
        Assert.Equal(Stamp, e.Utc);
        Assert.Equal("COFF TimeDateStamp", e.Desc);
    }

    [Fact]
    public void A_deterministic_pe_stamp_is_a_note_not_an_event()
    {
        var result = FileTimes.Read(Pe(0x9A3B5C7D), default);
        Assert.Empty(result.Events);
        Assert.Contains(result.Notes, n => n.Contains("deterministic stamp, not a time"));
    }

    [Fact]
    public void A_link_gives_three_events_for_present_times()
    {
        var result = FileTimes.Read(Write("a.lnk", ShellLinkTests.Shortcut("/c echo")), default);
        Assert.Equal(3, result.Events.Count);
        Assert.All(result.Events, e => Assert.Equal(new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc), e.Utc));
        Assert.Contains(result.Events, e => e.Desc == "Link creation time");
    }

    [Fact]
    public void A_compound_file_entry_time_is_read()
    {
        var bytes = DocumentFixtures.Compound([("Stream", new byte[10])]);
        // The second directory entry (the stream) holds its modified time at byte 108.
        int dir = (BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(48)) + 1) * 512;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(dir + 128 + 108), Stamp.ToFileTimeUtc());
        var result = FileTimes.Read(Write("a.cfb", bytes), default);
        var e = Assert.Single(result.Events);
        Assert.Equal(Stamp, e.Utc);
        Assert.Equal("Directory entry modified", e.Desc);
        Assert.Equal("Stream", e.Where);
    }

    [Fact]
    public void A_hive_key_time_is_read_and_a_recovered_key_is_marked()
    {
        var builder = new HiveSamples();
        builder.Deleted.Add(new HiveSamples.Node("Gone") { Written = Stamp.AddDays(1) });
        var root = new HiveSamples.Node("ROOT");
        root.Children.Add(new HiveSamples.Node("Live") { Written = Stamp });
        var result = FileTimes.Read(Write("hive.dat", builder.Build(root)), default);
        Assert.Contains(result.Events, e => e.Desc == "Key last written" && e.Where == "Live" && e.Utc == Stamp);
        Assert.Contains(result.Events, e => e.Name == "Gone" && e.Where.EndsWith("(recovered)") && e.Utc == Stamp.AddDays(1));
    }

    [Fact]
    public void A_zip_entry_time_is_read()
    {
        var path = _dir.File("a.zip");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("dir/item.txt");
            entry.LastWriteTime = new DateTimeOffset(2022, 3, 4, 10, 20, 30, TimeSpan.Zero);
            using var w = entry.Open();
            w.WriteByte(1);
        }
        var result = FileTimes.Read(path, default);
        var e = Assert.Single(result.Events);
        Assert.Equal("Zip entry modified", e.Desc);
        Assert.Equal("dir/item.txt", e.Where);
        Assert.Equal(new DateTime(2022, 3, 4, 10, 20, 30, DateTimeKind.Utc), e.Utc);
    }

    [Fact]
    public void An_unknown_file_gives_a_note_and_no_events()
    {
        var result = FileTimes.Read(Write("plain.txt", "just text"u8.ToArray()), default);
        Assert.Empty(result.Events);
        Assert.Single(result.Notes);
    }

    [Fact]
    public void A_line_has_the_timesketch_fields()
    {
        var line = FileTimes.Line(new FileTimeEvent(Stamp, "Key last written", "Live", "Live"), "hive.dat");
        Assert.Equal("2024-05-06T07:08:09.000000+00:00", (string?)line["datetime"]);
        Assert.Equal("Key last written", (string?)line["timestamp_desc"]);
        Assert.Equal("corvus:file_times", (string?)line["data_type"]);
        Assert.Equal("hive.dat", (string?)line["source_file"]);
        Assert.Equal("Key last written: Live", (string?)line["message"]);
    }
}
