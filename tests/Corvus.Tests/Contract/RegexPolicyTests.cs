using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;

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

    // Readers that apply fixed patterns to file text: package and repository reviews, documents, embedded data.
    private static readonly string[] FileTextNamespaces = ["Corvus.Services.Web.Packages", "Corvus.Core.Documents"];
    private static readonly Type[] FileTextTypes = [typeof(Embedded)];

    // Backtracking patterns over file text, each with why it runs in linear time.
    private static readonly Dictionary<string, string> LinearBacktracking = new()
    {
        ["PackageReview.ReverseShell"] = "Gaps are bounded at 1,500 and 300 characters per start.",
        ["PackageReview.CompiledEval"] = "The lookahead reads one [\\w.] run after a fixed prefix.",
        ["PackageReview.RawAddressUrl"] = "Repeats and the lookahead are bounded; the port is one digit run.",
        ["PackageReview.RawAddressSocket"] = "Repeats and lookaheads are bounded after a fixed prefix.",
        ["PackageReview.HiddenPowerShell"] = "Gaps are bounded at 120 and 40 characters per start.",
        ["PackageReview.ProjectScripts"] = "A section starts at its header and ends at the next one.",
        ["PackageReview.EntryPointSection"] = "A section starts at its header and ends at the next one.",
    };

    // Backtracking regex types over file text, each with why every instance
    // runs in linear time.
    private static readonly Dictionary<Type, string> LinearTypes = new()
    {
        [typeof(BoundedRegex)] = "Its constructor refuses any pattern but literals, bounded repeats and one loop with a fixed start.",
    };

    [Fact]
    public void A_bounded_regex_refuses_patterns_that_can_backtrack_past_linear()
    {
        foreach (var pattern in new[] { @"(?:a+)+", @"\w+\w+", @"a*b*", @"\w+_x", @"x.*y", @"\s+a", @"(?=a)b", @"(a)\1", @"^a+", @"(?:\w+_x)" })
            Assert.True(BoundedRegex.Problem(pattern) != null, pattern);
        foreach (var pattern in new[] { @"\bAutoOpen\b", @"\b\w+_Click\b", @"\b\.\s*Variables\b", @"\bEnumDateFormats(?:W|(?:Ex){1,2})?\b", @"\bexec[lv][ep]?\b",
                     Regex.Escape("Print #"), Regex.Escape(@"HKCU\Environment"), Regex.Escape("http://a.test/x?y=1&z=[2]{3}") })
            Assert.Null(BoundedRegex.Problem(pattern, RegexOptions.IgnoreCase));
        Assert.Throws<ArgumentException>(() => new BoundedRegex(@"(?:a+)+"));
    }

    [Fact]
    public void Macro_keyword_rules_finish_hostile_lines_under_100_ms()
    {
        var rules = Corvus.Core.Documents.MacroScan.KeywordRules().ToList();
        Assert.All(rules, r => Assert.IsType<BoundedRegex>(r));
        string[] lines = [string.Concat(Enumerable.Repeat("a_", 10_000)), string.Concat(Enumerable.Repeat(". ", 10_000)) + ".", new string('a', 20_000)];
        foreach (var rule in rules) Within100Ms(rule, lines);
    }

    [Fact]
    public void File_text_patterns_are_NonBacktracking_or_listed_as_linear()
    {
        var problems = new List<string>();
        var seen = new HashSet<string>();
        foreach (var type in typeof(RegexTimeouts).Assembly.GetTypes().Where(t => !t.ContainsGenericParameters && ReadsFileText(t)))
            foreach (var (name, regex) in StaticRegexes(type))
            {
                bool linear = (regex.Options & RegexOptions.NonBacktracking) != 0 || LinearTypes.ContainsKey(regex.GetType());
                if (!LinearBacktracking.ContainsKey(name)) { if (!linear) problems.Add($"{name}: {regex}"); }
                else if (seen.Add(name) && linear) problems.Add($"{name}: NonBacktracking, drop it from the list");
            }
        problems.AddRange(LinearBacktracking.Keys.Except(seen).Select(k => $"{k}: listed, not found"));
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void Inline_regex_calls_over_file_text_name_NonBacktracking()
    {
        var found = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)) continue;
            var text = File.ReadAllText(file);
            if (!FileTextNamespaces.Any(n => text.Contains($"namespace {n};", StringComparison.Ordinal))
                && !FileTextTypes.Any(t => Regex.IsMatch(text, $@"\bclass\s+{t.Name}\b"))) continue;
            var linear = LinearOptionsConst().Matches(text).Select(c => c.Groups[1].Value).Append("NonBacktracking").ToList();
            foreach (Match m in InlineRegexCall().Matches(text))
                if (Arguments(text, m.Index + m.Length - 1) is var args && !linear.Any(n => Regex.IsMatch(args, $@"\b{n}\b")))
                    found.Add($"{Path.GetRelativePath(Root, file)}:{text.AsSpan(0, m.Index).Count('\n') + 1}");
        }
        Assert.True(found.Count == 0, string.Join("\n", found));
    }

    [Fact]
    public void Hostile_lines_finish_under_100_ms()
    {
        var configLine = FieldRegex(typeof(Embedded), "ConfigLine");
        string[] lines =
        [
            "/" + new string('a', 20_000) + "!",
            "c:\\" + new string('a', 20_000) + "!",
            "x://" + new string('a', 20_000) + " !",
            string.Concat(Enumerable.Repeat("a.", 10_000)) + "1:",
        ];
        Within100Ms(configLine, lines);
        var command = "node" + string.Concat(Enumerable.Repeat(" --a", 10_000));
        foreach (var name in new[] { "NodeScript", "NodeRequire", "NetworkCommand" })
            Within100Ms(FieldRegex(typeof(PackageReview), name), [command, "'" + string.Concat(Enumerable.Repeat("a/", 10_000))]);
    }

    [Fact]
    public void Rewritten_patterns_keep_their_matches()
    {
        var oldConfigLine = new Regex(@"^(?:[a-z][a-z0-9+.\-]*://[\w.\-]*[a-z][\w.\-]*\S*|[a-z_][\w.\-\[\] ]{0,63}\s*[=:]\s*\S.*|(?=[\w.\-]*[a-z])[\w\-]+(?:\.[\w\-]+)+:\d{1,5}|[a-z]:\\[\w .\\\-]*[a-z][\w .\\\-]*|/(?:[\w.\-]*[a-z][\w.\-]*/?)+|#\s*[a-z].*|;\s*[a-z].*|\[[a-z][^\]]*\])$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var configLine = FieldRegex(typeof(Embedded), "ConfigLine");
        foreach (var line in new[]
        {
            "https://example.com/a", "x://1.2", "key = value", "_k:v", "host.example.com:8080", "127.0.0.1:80", "a1.2b:99999", "1.2:3",
            "a.b:123456", "x.y.1:22", "-a.b:1", "a..b:1", "C:\\Program Files\\App", "c:\\123", "/usr/local/bin", "/123/456", "# note", "; note",
            "[section]", "plain words", "1234",
        })
            Assert.True(oldConfigLine.IsMatch(line) == configLine.IsMatch(line), line);

        var oldScript = new Regex(@"\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*(['""]?)([^\s'""&|;]+\.(?:c|m)?js)\1");
        var oldRequire = new Regex(@"\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*?(?:-r|--require)[\s=]+(['""]?)(\.{1,2}/[^\s'""&|;]+)\1");
        var script = FieldRegex(typeof(PackageReview), "NodeScript");
        var require = FieldRegex(typeof(PackageReview), "NodeRequire");
        foreach (var command in new[]
        {
            "node install.js", "node 'a.js'", "node \"b.cjs\" && node c.mjs", "node 'a.js", "node \"a.js'", "node a.js.bak", "node --x -y ./s.js",
            "node -r ./hook.js index.js", "node --require=./x", "node --require './y.js'", "node -r \"../z\" -r ./w", "node.exe ---a b.js",
        })
        {
            Assert.Equal(oldScript.Matches(command).Select(m => m.Groups[2].Value), script.Matches(command).Select(m => m.Groups["t"].Value));
            Assert.Equal(oldRequire.Matches(command).Select(m => m.Groups[2].Value), require.Matches(command).Select(m => m.Groups["t"].Value));
        }
    }

    private static void Within100Ms(Regex regex, string[] inputs)
    {
        foreach (var input in inputs)
        {
            // NonBacktracking builds its states on first use: a short line of the
            // same shape builds them, so only the scan is timed.
            _ = regex.Count(input[..200] + input[^2..]);
            var clock = System.Diagnostics.Stopwatch.StartNew();
            _ = regex.Count(input);
            Assert.True(clock.ElapsedMilliseconds < 100, $"{regex}: {clock.ElapsedMilliseconds} ms on {input[..20]}...");
        }
    }

    private static Regex FieldRegex(Type type, string name) =>
        (Regex)type.GetField(name, BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;

    private static bool ReadsFileText(Type type)
    {
        for (var t = type; t != null; t = t.DeclaringType)
            if (FileTextNamespaces.Contains(t.Namespace) || FileTextTypes.Contains(t)) return true;
        return false;
    }

    /// <summary>Regexes held by a type's static fields, or returned by its parameterless static methods and properties, with their member names.</summary>
    private static IEnumerable<(string Name, Regex Regex)> StaticRegexes(Type type)
    {
        const BindingFlags Static = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
        foreach (var field in type.GetFields(Static).Where(f => HoldsRegex(f.FieldType, 0)))
            foreach (var regex in Regexes(field.GetValue(null), 0))
                yield return ($"{type.Name}.{field.Name}", regex);
        foreach (var method in type.GetMethods(Static).Where(m => typeof(Regex).IsAssignableFrom(m.ReturnType) && m.GetParameters().Length == 0 && !m.ContainsGenericParameters))
            yield return ($"{type.Name}.{(method.IsSpecialName ? method.Name[4..] : method.Name)}", (Regex)method.Invoke(null, null)!);
    }

    /// <summary>The text from an opening parenthesis to its match, skipping string and character literals.</summary>
    private static string Arguments(string text, int open)
    {
        int depth = 0;
        for (int i = open; i < text.Length; i++)
        {
            switch (text[i])
            {
                case '"':
                    bool verbatim = text[Math.Max(0, i - 2)..i].Contains('@');
                    for (i++; i < text.Length; i++)
                    {
                        if (!verbatim && text[i] == '\\') i++;
                        else if (text[i] != '"') continue;
                        else if (verbatim && i + 1 < text.Length && text[i + 1] == '"') i++;
                        else break;
                    }
                    break;
                case '\'':
                    i = text.IndexOf('\'', i + (text[i + 1] == '\\' ? 3 : 2));
                    break;
                case '(':
                    depth++;
                    break;
                case ')' when --depth == 0:
                    return text[open..(i + 1)];
            }
        }
        return text[open..];
    }

    // A static Regex call or constructor, up to its opening parenthesis.
    [GeneratedRegex(@"\b(?:Regex\.(?:IsMatch|Match|Matches|Replace|Split|Count|EnumerateMatches|EnumerateSplits)|new\s+(?:System\.Text\.RegularExpressions\.)?Regex)\s*\(")]
    private static partial Regex InlineRegexCall();

    // A RegexOptions constant that includes NonBacktracking.
    [GeneratedRegex(@"\bconst\s+RegexOptions\s+(\w+)\s*=[^;]*\bNonBacktracking\b")]
    private static partial Regex LinearOptionsConst();

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
