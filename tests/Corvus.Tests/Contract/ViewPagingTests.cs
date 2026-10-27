using System.Text.RegularExpressions;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>summarize_file passes table=, columns=, offset= and limit= to every view that reads them.</summary>
public sealed partial class ViewPagingTests
{
    // Regression (1d77b83a, 2ca14eb5, 0bd7ab85): view=registry, view=python and view=xbf refused their paging parameters.
    [Fact]
    public void Every_view_that_reads_a_paging_option_gets_it()
    {
        var folder = Path.Combine(DocsTests.RepoRoot(), "src", "Corvus", "Services", "Analysis");
        var checkedViews = 0;
        foreach (var file in Directory.GetFiles(folder, "*FileView.cs"))
        {
            var source = File.ReadAllText(file);
            if (ViewName().Match(source) is not { Success: true } name) continue;
            var view = name.Groups[1].Value;
            var read = OptionRead().Matches(source).Select(m => m.Groups[1].Value).ToHashSet(StringComparer.Ordinal);
            var refused = InspectionTools.Refused(view, read.Contains("Table"), read.Contains("Columns"), read.Contains("Offset"), read.Contains("Limit"));
            Assert.True(refused == null, $"view={view} reads {refused?.Parameter}= and summarize_file refuses it");
            checkedViews++;
        }
        Assert.True(checkedViews > 10);
    }

    [GeneratedRegex(@"public string Name => ""([a-z0-9-]+)""")]
    private static partial Regex ViewName();

    [GeneratedRegex(@"\bOptions\.(Table|Columns|Offset|Limit)\b")]
    private static partial Regex OptionRead();
}
