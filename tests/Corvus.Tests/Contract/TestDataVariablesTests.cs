using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>
/// The test data variables of docs/testing.md match the CORVUS_* variables the tests and test scripts read, with the
/// classes and scripts that read each. Run the tests with CORVUS_UPDATE_DOCS=1 to rewrite the "Read by" cells.
/// </summary>
public partial class TestDataVariablesTests
{
    private const string TableHeading = "### Test data variables";
    private const string ListHeading = "### Variables the test scripts set";

    /// <summary>CORVUS_* names in test code that are not environment variables: values the tests construct.</summary>
    private static readonly Dictionary<string, string> NotVariables = new(StringComparer.Ordinal)
    {
        ["CORVUS_PE32"] = "an enum member the engine type tests declare",
        ["CORVUS_PATCH_RESULT"] = "a global of the generated patch script",
        ["CORVUS_SEGMENTS_RESULT"] = "a global of the generated patch script",
        ["CORVUS_TEST_SECRET"] = "a variable the test sets to check that external tools do not receive it",
    };

    /// <summary>Files that name data variables without reading them.</summary>
    private static readonly HashSet<string> Registries = new(StringComparer.Ordinal)
    {
        // Lists the data variables so the speed check can find the tests that read them.
        "RealDataSpeedTests",
    };

    [Fact]
    public void Every_variable_the_tests_read_is_listed_with_its_readers()
    {
        var root = DocsTests.RepoRoot();
        var path = Path.Combine(root, "docs", "testing.md");
        var text = File.ReadAllText(path).ReplaceLineEndings("\n");
        var readers = Readers(root);
        var listed = Listed(text);
        if (Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1")
        {
            text = Rewrite(text, readers, listed);
            File.WriteAllText(path, text);
            listed = Listed(text);
        }

        var problems = new List<string>();
        foreach (var (name, files) in readers.Where(r => !listed.ContainsKey(r.Key)))
            problems.Add($"{name} is read by {string.Join(", ", files)} and not listed");
        foreach (var name in listed.Keys.Where(n => !readers.ContainsKey(n)))
            problems.Add($"{name} is listed and no test or test script reads it");
        foreach (var (name, entry) in listed.Where(l => readers.ContainsKey(l.Key)))
        {
            var expected = string.Join(", ", readers[name]);
            if (entry.ReadBy != expected) problems.Add($"{name}: Read by is \"{entry.ReadBy}\", the code has \"{expected}\"");
            if (entry.Description.Length == 0) problems.Add($"{name} has no description");
        }
        Assert.True(problems.Count == 0, "docs/testing.md test data variables (CORVUS_UPDATE_DOCS=1 rewrites Read by and adds missing rows):\n"
            + string.Join("\n", problems));
    }

    /// <summary>Each variable the tests and test scripts read, with its readers in ordinal order.</summary>
    private static SortedDictionary<string, List<string>> Readers(string root)
    {
        var server = Server(root);
        var self = Path.GetFullPath(Path.Combine(root, "tests", "Corvus.Tests", "Contract", nameof(TestDataVariablesTests) + ".cs"));
        var code = Files(Path.Combine(root, "tests"), "*.cs").Where(f => Path.GetFullPath(f) != self)
            .Select(f => (Name: Path.GetFileName(f).Split('.')[0], Text: File.ReadAllText(f))).ToList();
        var scripts = Files(Path.Combine(root, "tests"), "*.ps1").Concat(Files(Path.Combine(root, "tests"), "*.psm1"))
            .Concat(Directory.EnumerateFiles(root, "*.ps1")).Concat(Directory.EnumerateFiles(root, "*.psm1"))
            .Select(f => (Name: Path.GetRelativePath(root, f).Replace('\\', '/'), Text: File.ReadAllText(f))).ToList();

        // A constant declared as `const string Name = "CORVUS_..."` is read where `Type.Name`, or Name in its own file, appears.
        var constants = new List<(string Variable, string Type, string Name, string File)>();
        foreach (var (name, text) in code)
            foreach (Match m in Constant().Matches(text))
                constants.Add((m.Groups[2].Value, DeclaringType(text, m.Index) ?? name, m.Groups[1].Value, name));

        var result = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        void Add(string variable, string reader)
        {
            if (server.Contains(variable) || NotVariables.ContainsKey(variable)) return;
            if (!result.TryGetValue(variable, out var list)) result[variable] = list = [];
            if (!list.Contains(reader)) list.Add(reader);
        }
        foreach (var (name, text) in code.Where(c => !Registries.Contains(c.Name)))
        {
            foreach (Match m in QuotedVariable().Matches(text))
                if (!Constant().IsMatch(Line(text, m.Index))) Add(m.Groups[1].Value, name);
            foreach (var c in constants)
                if (Regex.IsMatch(text, $@"\b{c.Type}\.{c.Name}\b")
                    || (c.File == name && Regex.Count(text, $@"\b{c.Name}\b") > 1)) Add(c.Variable, name);
        }
        foreach (var (name, text) in scripts)
            foreach (Match m in Variable().Matches(text)) Add(m.Value, name);
        foreach (var list in result.Values) list.Sort(StringComparer.Ordinal);
        return result;
    }

    /// <summary>The server's own variables, documented in docs/configuration.md.</summary>
    private static HashSet<string> Server(string root) =>
        Variable().Matches(File.ReadAllText(Path.Combine(root, "docs", "configuration.md"))).Select(m => m.Value).ToHashSet(StringComparer.Ordinal);

    private static IEnumerable<string> Files(string folder, string pattern) =>
        Directory.EnumerateFiles(folder, pattern, SearchOption.AllDirectories)
            .Where(f => !f.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(p => p is "bin" or "obj"));

    private static string? DeclaringType(string text, int index) =>
        TypeDeclaration().Matches(text[..index]).LastOrDefault()?.Groups[1].Value;

    private static string Line(string text, int index)
    {
        int start = text.LastIndexOf('\n', index) + 1, end = text.IndexOf('\n', index);
        return text[start..(end < 0 ? text.Length : end)];
    }

    private sealed record Entry(string Description, string ReadBy, bool InTable);

    /// <summary>The table rows and list items of the two sections, by variable.</summary>
    private static Dictionary<string, Entry> Listed(string text)
    {
        var listed = new Dictionary<string, Entry>(StringComparer.Ordinal);
        foreach (var line in Section(text, TableHeading).Split('\n'))
            if (TableRow().Match(line) is { Success: true } m)
            {
                var cells = CellSplit().Split(line.Trim().Trim('|')).Select(c => c.Trim()).ToArray();
                listed[m.Groups[1].Value] = new Entry(cells[1], cells[2], true);
            }
        foreach (var line in Section(text, ListHeading).Split('\n'))
            if (ListItem().Match(line) is { Success: true } m)
                listed[m.Groups[1].Value] = new Entry(m.Groups[3].Value.Trim(), m.Groups[2].Value, false);
        return listed;
    }

    /// <summary>The text from a heading to the next heading of the same or a higher level.</summary>
    private static string Section(string text, string heading)
    {
        int start = text.IndexOf("\n" + heading + "\n", StringComparison.Ordinal);
        Assert.True(start >= 0, $"docs/testing.md has no \"{heading}\" section");
        int end = NextHeading().Match(text, start + heading.Length + 2) is { Success: true } m ? m.Index : text.Length;
        return text[start..end];
    }

    /// <summary>Rewrites each Read by cell, drops variables no longer read and adds a row for each one not listed.</summary>
    private static string Rewrite(string text, SortedDictionary<string, List<string>> readers, Dictionary<string, Entry> listed)
    {
        var lines = text.Split('\n').ToList();
        int lastRow = -1;
        for (int i = 0; i < lines.Count; i++)
        {
            if (TableRow().Match(lines[i]) is { Success: true } row)
            {
                var name = row.Groups[1].Value;
                if (!readers.TryGetValue(name, out var files)) { lines.RemoveAt(i--); continue; }
                lines[i] = $"| `{name}` | {listed[name].Description} | {string.Join(", ", files)} |";
                lastRow = i;
            }
            else if (ListItem().Match(lines[i]) is { Success: true } item)
            {
                var name = item.Groups[1].Value;
                if (!readers.TryGetValue(name, out var files)) { lines.RemoveAt(i--); continue; }
                lines[i] = $"- `{name}` ({string.Join(", ", files)}): {listed[name].Description}";
            }
        }
        Assert.True(lastRow >= 0, "docs/testing.md has no test data variables table rows to extend");
        var added = readers.Where(r => !listed.ContainsKey(r.Key)).Select(r => $"| `{r.Key}` |  | {string.Join(", ", r.Value)} |");
        lines.InsertRange(lastRow + 1, added);
        return string.Join("\n", lines);
    }

    [GeneratedRegex(@"CORVUS_[A-Z0-9_]*[A-Z0-9]")]
    private static partial Regex Variable();

    [GeneratedRegex(@"""(CORVUS_[A-Z0-9_]*[A-Z0-9])""")]
    private static partial Regex QuotedVariable();

    [GeneratedRegex(@"const string (\w+)\s*=\s*""(CORVUS_[A-Z0-9_]*[A-Z0-9])""")]
    private static partial Regex Constant();

    [GeneratedRegex(@"\b(?:class|struct|record)\s+([A-Z]\w*)")]
    private static partial Regex TypeDeclaration();

    [GeneratedRegex(@"^\| `(CORVUS_[A-Z0-9_]+)` \|")]
    private static partial Regex TableRow();

    [GeneratedRegex(@"^- `(CORVUS_[A-Z0-9_]+)` \(([^)]*)\): (.*)$")]
    private static partial Regex ListItem();

    [GeneratedRegex(@"\n#{1,3} ")]
    private static partial Regex NextHeading();

    [GeneratedRegex(@"(?<!\\)\|")]
    private static partial Regex CellSplit();
}
