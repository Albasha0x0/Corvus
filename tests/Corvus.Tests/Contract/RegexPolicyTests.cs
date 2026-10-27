using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Regexes over file contents match in linear time without a timeout; only caller patterns keep one, through <see cref="RegexTimeouts"/>.</summary>
public sealed partial class RegexPolicyTests
{
    private static readonly string Root = DocsTests.RepoRoot();

    [Fact]
    public void Fixed_patterns_take_no_match_timeout()
    {
        // Regression: a 1 s timeout on the package rules ran out on macOS CI (08f2735f) and threw from the package view.
        var timed = new List<string>();
        foreach (var type in typeof(RegexTimeouts).Assembly.GetTypes().Where(t => !t.ContainsGenericParameters))
            foreach (var field in type.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                if (HoldsRegex(field.FieldType, 0))
                    foreach (var regex in Regexes(field.GetValue(null), 0))
                        if (regex.MatchTimeout != Regex.InfiniteMatchTimeout)
                            timed.Add($"{type.FullName}.{field.Name}: {regex}");
        Assert.True(timed.Count == 0, string.Join("\n", timed));
    }

    [Fact]
    public void No_regex_call_in_the_source_names_a_match_timeout()
    {
        // Static fields are read by the test above; this one sees regexes built inside methods.
        var found = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)) continue;
            var text = File.ReadAllText(file);
            foreach (Match m in TimedRegexCall().Matches(text))
                found.Add($"{Path.GetRelativePath(Root, file)}:{text.AsSpan(0, m.Index).Count('\n') + 1}");
        }
        Assert.True(found.Count == 0, string.Join("\n", found));
    }

    [Fact]
    public void Every_rule_pattern_matches_in_linear_time()
    {
        var patterns = Features.Rules.Concat(MobileRules.All).SelectMany(r => r.Groups).SelectMany(g => g).Select(Pattern).OfType<string>().Distinct().ToList();
        Assert.NotEmpty(patterns);
        foreach (var pattern in patterns)
            Assert.Equal(RegexOptions.NonBacktracking, Features.RulePattern(pattern).Options & RegexOptions.NonBacktracking);
    }

    /// <summary>The regular expression in a rule's feature, or null for a feature that names no pattern.</summary>
    private static string? Pattern(string feature)
    {
        foreach (var prefix in new[] { "dex:str:", "str:", "rtti:", "sym:", "section:name=" })
            if (feature.StartsWith(prefix, StringComparison.Ordinal)) return feature[prefix.Length..];
        return feature.StartsWith("dex:call:", StringComparison.Ordinal) && feature.LastIndexOf("=s:", StringComparison.Ordinal) is var s and > 0 ? feature[(s + 3)..] : null;
    }

    private static bool HoldsRegex(Type type, int depth) =>
        type == typeof(Regex) || type.IsSubclassOf(typeof(Regex))
        || depth < 3 && (type.IsArray && HoldsRegex(type.GetElementType()!, depth + 1)
                         || type.IsGenericType && type.GetGenericArguments().Any(a => HoldsRegex(a, depth + 1))
                         || type.Assembly == typeof(RegexTimeouts).Assembly && !type.IsEnum
                            && type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Any(f => HoldsRegex(f.FieldType, depth + 1)));

    private static IEnumerable<Regex> Regexes(object? value, int depth)
    {
        if (value is Regex regex) yield return regex;
        else if (value is null or string || depth > 3) yield break;
        else if (value is IDictionary dictionary)
            foreach (var v in dictionary.Values) foreach (var r in Regexes(v, depth + 1)) yield return r;
        else if (value is IEnumerable items)
            foreach (var v in items) foreach (var r in Regexes(v, depth + 1)) yield return r;
        else if (value.GetType() is var type && (type.Assembly == typeof(RegexTimeouts).Assembly || type.IsGenericType))
            foreach (var f in type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Where(f => HoldsRegex(f.FieldType, 0)))
                foreach (var r in Regexes(f.GetValue(value), depth + 1)) yield return r;
    }

    // A Regex constructor, static call or attribute that names a time limit.
    [GeneratedRegex(@"(?:\bnew\s+(?:System\.Text\.RegularExpressions\.)?Regex\s*\(|\bRegex\.(?:IsMatch|Match|Matches|Replace|Split|Count)\s*\(|\[GeneratedRegex\s*\()[^;\]]*?(?:TimeSpan\.From|RegexTimeouts\.Limit|matchTimeoutMilliseconds)")]
    private static partial Regex TimedRegexCall();
}
