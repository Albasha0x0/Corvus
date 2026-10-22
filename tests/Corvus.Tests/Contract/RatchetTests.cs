namespace Corvus.Tests;

/// <summary>Ratchets are gates: every list under Ratchets/ holds only reviewed exemptions ("# permanent: reason"), nothing left to fix; the measured lists (CountRatchet, perf-baseline) hold values instead.</summary>
public class RatchetTests
{
    [Fact]
    public void EveryExemptionIsReviewedPermanent()
    {
        var folder = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Ratchets");
        var lists = Directory.EnumerateFiles(folder, "*.txt").Select(Path.GetFileNameWithoutExtension)
            .Where(name => !CountRatchet.Names.Contains(name) && name is not (QuarantineListTests.Name or PerfBaselineTests.Name)).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(lists);
        var open = lists.SelectMany(name => Ratchet.Entries(name!)!.Where(e => e.Value == null).Select(e => $"{name}: {e.Key}")).ToList();
        Assert.True(open.Count == 0, "exemptions without a reviewed reason (fix them, or mark them '# permanent: <reason>'):\n" + string.Join("\n", open));
    }
}
