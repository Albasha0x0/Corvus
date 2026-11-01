using System.Reflection;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>RT-318: tools that answer one question are grouped, and each group has an agreement test.</summary>
public class ToolAgreementTests
{
    // Toolsets.All is every family, the opt-in live and engine tools included.
    private static List<string> Advertised() => Catalog.OfThisBuild(Toolsets.All).Tools.Select(t => (string)t["name"]!).ToList();

    private static IEnumerable<string> Grouped() => ToolAgreement.Groups.SelectMany(g => g.Answers).Select(a => a.Tool);

    [Fact]
    public void Every_tool_is_in_an_agreement_group_or_has_a_single_answer_reason()
    {
        var grouped = Grouped().ToHashSet(StringComparer.Ordinal);
        var names = Advertised();
        var uncovered = names.Where(n => !grouped.Contains(n) && !ToolAgreement.SingleAnswer.ContainsKey(n)).ToList();
        Assert.True(uncovered.Count == 0, "in neither an agreement group nor SingleAnswer (Mcp/Contract/Agreement.cs): " + string.Join(", ", uncovered));
        var unknown = grouped.Concat(ToolAgreement.SingleAnswer.Keys).Where(n => !names.Contains(n)).ToList();
        Assert.True(unknown.Count == 0, "named in Agreement.cs but not advertised: " + string.Join(", ", unknown));
        var both = ToolAgreement.SingleAnswer.Keys.Where(grouped.Contains).ToList();
        Assert.True(both.Count == 0, "in a group and in SingleAnswer: " + string.Join(", ", both));
        Assert.All(ToolAgreement.SingleAnswer, p => Assert.False(string.IsNullOrWhiteSpace(p.Value), p.Key));
    }

    [Fact]
    public void Every_group_names_an_existing_agreement_test_or_is_listed_as_pending()
    {
        var tests = typeof(ToolAgreementTests).Assembly.GetTypes()
            .Where(t => t.Namespace == typeof(ToolAgreementTests).Namespace)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(m => m.GetCustomAttribute<FactAttribute>() != null)
            .GroupBy(m => m.Name, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        var pending = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var g in ToolAgreement.Groups)
        {
            if (g.Test is null) pending[g.Question] = 1;
            else Assert.True(tests.GetValueOrDefault(g.Test) == 1, $"{g.Question}: {g.Test} is not exactly one [Fact] or [Theory] in Corvus.Tests");
        }
        CountRatchet.Check("agreement-test", "agreement groups without a test that compares their tools on a built fixture may only fall (RT-318)", pending, floor: false);
    }

    [Fact]
    public void A_group_has_at_least_two_tools_a_fixture_and_no_tool_field_repeats_in_the_catalog()
    {
        foreach (var g in ToolAgreement.Groups)
        {
            Assert.True(g.Answers.Count >= 2, g.Question);
            Assert.False(string.IsNullOrWhiteSpace(g.Fixture), g.Question);
            Assert.Equal(g.Answers.Count, g.Answers.Select(a => a.Tool).Distinct().Count());
        }
        // A tool in two groups answers each with a different field.
        var repeated = ToolAgreement.Groups.SelectMany(g => g.Answers).GroupBy(a => a).Where(x => x.Count() > 1).Select(x => x.Key.Tool).ToList();
        Assert.True(repeated.Count == 0, "same tool and field in two groups: " + string.Join(", ", repeated));
    }
}
