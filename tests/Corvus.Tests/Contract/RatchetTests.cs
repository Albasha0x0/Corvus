namespace Corvus.Tests;

/// <summary>Every Ratchets/ list holds only reviewed permanent exemptions; measured lists hold values.</summary>
public class RatchetTests
{
    [Fact]
    public void Every_exemption_is_reviewed_or_permanent()
    {
        var folder = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Ratchets");
        var lists = Directory.EnumerateFiles(folder, "*.txt").Select(Path.GetFileNameWithoutExtension)
            .Where(name => !CountRatchet.Names.Contains(name) && name is not (QuarantineListTests.Name or PerfBaselineTests.Name)).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(lists);
        var open = lists.SelectMany(name => Ratchet.Entries(name!)!.Where(e => e.Value == null).Select(e => $"{name}: {e.Key}")).ToList();
        Assert.True(open.Count == 0, "exemptions without a reviewed reason (fix them, or mark them '# permanent: <reason>'):\n" + string.Join("\n", open));
    }
}
