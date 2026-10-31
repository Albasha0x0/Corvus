using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The Zone.Identifier stream of the input: its zone and URLs in the summary highlights.</summary>
public sealed class ZoneIdentifierTests
{
    private static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Zip(params (string Name, byte[] Data)[] entries) => ContainerFixtures.Zip(entries);

    private static InspectionService.FileSummary Summarize(string path)
    {
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        return new InspectionService(workspace).Summarize(null, path, default);
    }

    [WindowsFact("Zone.Identifier is an NTFS stream.")]
    public void A_zone_identifier_stream_shows_its_zone_and_urls()
    {
        using var dir = new TempDir();
        var path = dir.File("a.zip");
        File.WriteAllBytes(path, Zip(("readme.txt", U("x"))));
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/a.zip\r\nReferrerUrl=https://example.com/\r\n");
        var zone = Assert.IsType<ZoneIdentifier>(Summarize(path).File.Zone);
        Assert.Equal((3, "https://example.com/a.zip", "https://example.com/"), (zone.ZoneId, zone.HostUrl, zone.ReferrerUrl));
        Assert.Contains("Zone.Identifier: ZoneId=3 HostUrl=https://example.com/a.zip ReferrerUrl=https://example.com/.", Summarize(path).Highlights);
    }

    [WindowsFact("Zone.Identifier is an NTFS stream.")]
    public void A_file_without_a_zone_identifier_stream_has_no_zone()
    {
        using var dir = new TempDir();
        var path = dir.File("a.zip");
        File.WriteAllBytes(path, Zip(("readme.txt", U("x"))));
        Assert.Null(Summarize(path).File.Zone);
    }

    [Fact]
    public void A_zone_identifier_reads_keys_of_its_own_section_only()
    {
        var zone = ZoneIdentifier.Parse(U("[Other]\r\nZoneId=1\r\n[ZoneTransfer]\r\nZoneId=3\r\nHostUrl = https://example.com/a\r\n"));
        Assert.Equal(new ZoneIdentifier(3, "https://example.com/a", null), zone);
        Assert.Null(ZoneIdentifier.Parse(U("[Other]\r\nZoneId=1\r\n")));
    }

    [Fact]
    public void A_zone_identifier_stream_is_read_to_a_fixed_size()
    {
        var zone = ZoneIdentifier.Parse(U("[ZoneTransfer]\r\nZoneId=3\r\n" + new string(' ', ZoneIdentifier.MaxBytes) + "HostUrl=https://example.com/\r\n"));
        Assert.Equal(new ZoneIdentifier(3, null, null), zone);
    }

    [Fact]
    [FuzzEntry(typeof(ZoneIdentifier))]
    public void Fuzzed_zone_identifier_streams_never_throw()
    {
        var failures = FormatFuzz.Run(U("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/a.zip\r\nReferrerUrl=https://example.com/\r\n"),
            b => ZoneIdentifier.Parse(b), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
