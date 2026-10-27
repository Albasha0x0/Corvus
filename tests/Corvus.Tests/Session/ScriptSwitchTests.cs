using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>Repository scripts never assign a variable named like a switch: PowerShell ignores case, so the value becomes a switch and fails.</summary>
public class ScriptSwitchTests
{
    public static TheoryData<string> Scripts() => [.. Directory.GetFiles(DocsTests.RepoRoot(), "*.ps1").Select(p => Path.GetFileName(p)).Order()];

    [Theory]
    [MemberData(nameof(Scripts))]
    public void No_variable_shares_a_switch_name(string script) =>
        Assert.Empty(SharedNames(File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), script))));

    [Fact]
    public void Assignments_and_loop_variables_named_like_a_switch_are_found()
    {
        const string text = "param(\n    [switch]$All,\n    [switch]$Full,\n    [string]$Base\n)\n$all = @{}\n$base = 'x'\n$Full = $true\nforeach ($full in 1..2) { }\nif ($All -eq $true) { }\n";
        Assert.Equal(["all", "full"], SharedNames(text));
    }

    /// <summary>Variables assigned (or looped over) after the script's top-level param block that share a switch's name, ignoring case.</summary>
    private static List<string> SharedNames(string text)
    {
        var m = Regex.Match(text, @"(?im)^\s*param\s*\(");
        if (!m.Success) return [];
        int depth = 1, end = m.Index + m.Length;
        for (; end < text.Length && depth > 0; end++)
            depth += text[end] switch { '(' => 1, ')' => -1, _ => 0 };
        var switches = Regex.Matches(text[m.Index..end], @"\[switch\]\s*\$(\w+)", RegexOptions.IgnoreCase)
            .Select(s => s.Groups[1].Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // $true and $false convert to a switch; any other value fails
        return Regex.Matches(text[end..], @"\$(\w+)\s*(?:=(?!=|\s*\$(?:true|false)\b)|\+=|-=)|foreach\s*\(\s*\$(\w+)\s+in\b", RegexOptions.IgnoreCase)
            .Select(a => a.Groups[1].Success ? a.Groups[1].Value : a.Groups[2].Value)
            .Where(switches.Contains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
