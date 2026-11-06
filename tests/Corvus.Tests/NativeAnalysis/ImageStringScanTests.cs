using System.Text;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The network values of an image's strings: the bounds of the scan and what it reports it did not read.</summary>
public sealed class ImageStringScanTests
{
    private static byte[] Image(int ascii, string? wide, int pad = 0)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < ascii; i++) bytes.AddRange(Encoding.ASCII.GetBytes($"host{i:D3}.example.net\0"));
        bytes.AddRange(new byte[4]);
        bytes.AddRange(new byte[pad]);
        if (wide != null) { bytes.AddRange(Encoding.Unicode.GetBytes(wide)); bytes.AddRange(new byte[2]); }
        return [.. bytes];
    }

    private static List<string> Values(byte[] image, IndicatorList.ImageScanBounds bounds, out IndicatorList.ImageScanReport report) =>
        [.. IndicatorList.FromImageStrings("native", image, default, bounds, out report).Select(h => h.Value)];

    [Fact]
    public void Passes_that_share_a_budget_read_no_wide_string_after_it_is_spent()
    {
        var found = Values(Image(10, "wide.example.org"), new IndicatorList.ImageScanBounds(5), out var report);
        Assert.DoesNotContain("wide.example.org", found);
        Assert.Contains(report.Limits, l => l.StartsWith("ASCII string scan stopped", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void A_pass_with_its_own_budget_reads_a_wide_string_at_either_parity(int pad)
    {
        var found = Values(Image(10, "wide.example.org", pad), new IndicatorList.ImageScanBounds(5, PerPass: true, BothParities: true), out _);
        Assert.Contains("wide.example.org", found);
    }

    [Fact]
    public void A_range_that_is_excluded_is_not_read()
    {
        var image = Image(3, null);
        var first = Encoding.ASCII.GetByteCount("host000.example.net\0");
        var found = Values(image, new IndicatorList.ImageScanBounds(100, Excluded: (0, first)), out _);
        Assert.DoesNotContain("host000.example.net", found);
        Assert.Contains("host001.example.net", found);
    }

    [Fact]
    public void Runs_the_caller_drops_are_counted_and_not_returned()
    {
        var found = Values(Image(3, null), new IndicatorList.ImageScanBounds(100, Skipped: at => at == 0), out var report);
        Assert.Equal(1, report.Skipped);
        Assert.DoesNotContain("host000.example.net", found);
        Assert.Equal(2, found.Count);
    }
}
