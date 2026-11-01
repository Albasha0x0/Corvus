using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Archives;

namespace Corvus.Tests;

/// <summary>Images built here from zip archives laid end to end, and a zip whose local entries the central directory omits.</summary>
public sealed class AppendedArchiveTests
{
    private static byte[] Zip(params (string Name, string Text)[] files)
    {
        var o = new MemoryStream();
        using (var z = new ZipArchive(o, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, text) in files)
            {
                using var w = z.CreateEntry(name).Open();
                w.Write(Encoding.UTF8.GetBytes(text));
            }
        return o.ToArray();
    }

    private static ContainerContents Open(byte[] data) =>
        Containers.Open(data, "image.bin", AnalysisLimits.Default, CancellationToken.None, allFiles: true);

    [Fact]
    public void A_zip_after_a_zip_is_listed_with_its_members()
    {
        var contents = Open([.. Zip(("a.txt", "first")), .. Zip(("b.txt", "second"))]);

        Assert.Contains(contents.Items, i => i.Name == "a.txt");
        var second = Assert.Single(contents.Items, i => i.Name == "archive_2/b.txt");
        Assert.Equal("second", Encoding.UTF8.GetString(second.Bytes));
        Assert.Contains(contents.Notes, n => n.StartsWith("archive_2: zip archive at 0x"));
    }

    [Fact]
    public void Three_zips_laid_end_to_end_are_each_listed()
    {
        var contents = Open([.. Zip(("a.txt", "1")), .. Zip(("b.txt", "2")), .. Zip(("c.txt", "3"))]);

        Assert.Equal(["a.txt", "archive_2/b.txt", "archive_3/c.txt"], contents.Items.Select(i => i.Name).Order().ToArray());
    }

    [Fact]
    public void Local_entries_missing_from_the_central_directory_are_listed_as_unlisted()
    {
        var listed = Zip(("a.txt", "listed"));
        var appended = Zip(("extra.txt", "extra"));
        int listedDirectory = listed.AsSpan().LastIndexOf("PK\x01\x02"u8);
        int appendedDirectory = appended.AsSpan().LastIndexOf("PK\x01\x02"u8);
        // The appended zip's local headers go between the last entry and the directory.
        var image = new List<byte>(listed[..listedDirectory]);
        image.AddRange(appended[..appendedDirectory]);
        image.AddRange(listed[listedDirectory..]);
        var bytes = image.ToArray();
        int end = bytes.AsSpan().LastIndexOf("PK\x05\x06"u8);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(end + 16), (uint)(listedDirectory + appendedDirectory));

        var contents = Open(bytes);

        Assert.Contains(contents.Items, i => i.Name == "a.txt");
        Assert.Contains(contents.Items, i => i.Name == "unlisted/extra.txt");
        Assert.Contains(contents.Notes, n => n.Contains("are not in the central directory"));
    }

    // Regression: InstallerStubTests fuzz iteration 29 sliced past the image end.
    [Fact]
    public void A_listed_offset_past_the_central_directory_marks_the_unlisted_check_partial()
    {
        var data = Zip(("a.txt", "x"));
        int central = data.AsSpan().IndexOf("PK"u8);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(central + 42), (uint)data.Length + 100);
        var contents = Open(data);
        Assert.Contains(contents.Notes, n => n.StartsWith("A listed entry has no local header at its offset", StringComparison.Ordinal));
    }

    [Fact]
    public void A_single_zip_has_no_second_archive()
    {
        var contents = Open(Zip(("a.txt", "only")));

        Assert.Equal(["a.txt"], contents.Items.Select(i => i.Name).ToArray());
        Assert.DoesNotContain(contents.Notes, n => n.StartsWith("archive_") || n.Contains("central directory"));
    }

    [Fact]
    public void A_7z_end_record_followed_by_a_zip_splits_into_two_ranges()
    {
        var image = SevenZipThenZip();

        var parts = AppendedArchive.Split(image, "7z");

        Assert.Equal([(0, 32), (32, image.Length)], parts);
    }

    [Fact]
    public void A_7z_start_header_with_a_wrapping_next_header_has_no_split()
    {
        byte[] sevenZip = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4, .. new byte[24]];
        BinaryPrimitives.WriteUInt64LittleEndian(sevenZip.AsSpan(12), ulong.MaxValue - 8);
        BinaryPrimitives.WriteUInt64LittleEndian(sevenZip.AsSpan(20), 40);

        Assert.Null(AppendedArchive.Split([.. sevenZip, .. Zip(("b.txt", "x"))], "7z"));
    }

    private static byte[] ZipWithStoredZip()
    {
        var o = new MemoryStream();
        using (var z = new ZipArchive(o, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var w = z.CreateEntry("inner.zip", CompressionLevel.NoCompression).Open())
                w.Write(Zip(("inner.txt", "inside")));
            using var t = z.CreateEntry("outer.txt").Open();
            t.Write("outer"u8);
        }
        return o.ToArray();
    }

    [Fact]
    public void A_stored_zip_inside_a_zip_is_not_a_second_archive()
    {
        var image = ZipWithStoredZip();

        Assert.Null(AppendedArchive.Split(image, "zip"));
        var contents = Open(image);
        Assert.Contains(contents.Items, i => i.Name == "outer.txt");
        Assert.DoesNotContain(contents.Notes, n => n.StartsWith("archive_"));
    }

    [Fact]
    public void A_stored_zip_inside_the_first_of_two_zips_leaves_two_ranges()
    {
        var first = ZipWithStoredZip();

        var parts = AppendedArchive.Split([.. first, .. Zip(("b.txt", "x"))], "zip");

        Assert.Equal(2, parts!.Count);
        Assert.Equal(first.Length, parts[0].End);
    }

    [Fact]
    public void Archives_past_the_cap_are_counted_and_their_offsets_named()
    {
        int cap = AppendedArchive.MaxArchives;
        var image = Enumerable.Range(0, cap + 1).SelectMany(i => Zip(($"f{i}.txt", "x"))).ToArray();

        var contents = Open(image);

        Assert.Contains(contents.Items, i => i.Name == $"archive_{cap}/f{cap - 1}.txt");
        Assert.DoesNotContain(contents.Items, i => i.Name.StartsWith($"archive_{cap + 1}/"));
        Assert.Contains(contents.Notes, n => n.StartsWith($"Opened {cap} of {cap + 1} archives; unread archives start at 0x"));
    }

    [Fact]
    public void A_later_archive_that_does_not_open_keeps_the_first_listing()
    {
        // A 7z start header with an empty next header, after the zip.
        byte[] broken = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4, .. new byte[24]];
        var image = (byte[])[.. Zip(("a.txt", "first")), .. broken];

        var contents = Open(image);

        Assert.Contains(contents.Items, i => i.Name == "a.txt");
        Assert.Contains(contents.Notes, n => n.StartsWith("archive_2:"));
    }

    [Fact]
    public void A_cancelled_token_stops_the_listing_of_two_zips()
    {
        var image = (byte[])[.. Zip(("a.txt", "1")), .. Zip(("b.txt", "2"))];
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            Containers.Open(image, "image.bin", AnalysisLimits.Default, cts.Token, allFiles: true));
    }

    private static byte[] SevenZipThenZip()
    {
        // A start header whose next header is empty: the archive ends at byte 32.
        byte[] sevenZip = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4, .. new byte[24]];
        return [.. sevenZip, .. Zip(("b.txt", "x"))];
    }
}
