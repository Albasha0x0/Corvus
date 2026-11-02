using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The tools that Next: steps of thrown errors name: they exist and take the parameters given.</summary>
public partial class NextHintTests
{
    // Tool names in prose that are not calls: "tool k=v" pairs are checked, bare names only for existence.
    private static readonly string[] NotTools = ["dump_from_memory", "list_changed", "patch_native", "stub_needs_reloc"];

    // The target a step runs against is the caller's own, so a step may omit it.
    private static readonly string[] Targets = ["session", "image", "assembly", "path"];

    [GeneratedRegex(@"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)((?: [A-Za-z]+=[^\s,;)""]*)+)")]
    private static partial Regex Call();

    /// <summary>The text of every <c>new ToolError(...)</c> expression in the sources, parentheses balanced.</summary>
    private static IEnumerable<(string File, string Text)> ErrorExpressions()
    {
        var root = Path.Combine(DocsTests.RepoRoot(), "src", "Corvus");
        foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            for (int at = text.IndexOf("new ToolError(", StringComparison.Ordinal); at >= 0; at = text.IndexOf("new ToolError(", at + 1, StringComparison.Ordinal))
            {
                int depth = 0, i = at + "new ToolError".Length;
                for (; i < text.Length; i++)
                {
                    char c = text[i];
                    if (c == '"') { i = SkipString(text, i); continue; }
                    if (c == '(') depth++;
                    else if (c == ')' && --depth == 0) break;
                }
                yield return (Path.GetRelativePath(root, file), text[at..Math.Min(i + 1, text.Length)]);
            }
        }
    }

    private static int SkipString(string text, int start)
    {
        bool verbatim = start > 0 && (text[start - 1] == '@' || start > 1 && text[start - 2] == '@');
        for (int i = start + 1; i < text.Length; i++)
        {
            if (text[i] == '"' && verbatim && i + 1 < text.Length && text[i + 1] == '"') i++;
            else if (text[i] == '"') return i;
            else if (text[i] == '\\' && !verbatim) i++;
        }
        return text.Length - 1;
    }

    [Fact]
    public void Next_steps_name_existing_tools_with_declared_parameters()
    {
        var tools = ToolCli.CatalogTools.ToDictionary(t => (string)t["name"]!, StringComparer.Ordinal);
        var problems = new List<string>();
        int calls = 0;
        foreach (var (file, text) in ErrorExpressions())
        {
            foreach (var unknown in McpProtocolTests.UnknownTools(text, tools.Keys.ToHashSet(StringComparer.Ordinal), NotTools))
                problems.Add($"{file}: names {unknown}, which is not a tool");
            foreach (Match m in Call().Matches(text))
            {
                if (!tools.TryGetValue(m.Groups[1].Value, out var tool)) continue;
                calls++;
                var schema = tool["inputSchema"];
                var declared = schema?["properties"]?.AsObject().Select(p => p.Key).ToHashSet(StringComparer.Ordinal) ?? [];
                var given = Regex.Matches(m.Groups[2].Value, @"([A-Za-z]+)=").Select(p => p.Groups[1].Value).ToList();
                foreach (var name in given.Where(g => !declared.Contains(g)))
                    problems.Add($"{file}: {m.Groups[1].Value} has no parameter {name}");
                var required = schema?["required"]?.AsArray().Select(r => (string)r!) ?? [];
                foreach (var name in required.Where(r => !given.Contains(r) && !Targets.Contains(r)))
                    if (!text.Contains(name, StringComparison.Ordinal))
                        problems.Add($"{file}: {m.Groups[1].Value} needs {name}, which the step does not give or name");
            }
        }
        Assert.True(calls >= 20, $"only {calls} tool calls with parameters found");
        Assert.True(problems.Count == 0, string.Join("\n", problems.Distinct()));
    }

    [Fact]
    public void An_asset_bundle_that_is_not_a_container_is_pointed_to_the_assets_view()
    {
        var dir = Directory.CreateTempSubdirectory("nexthint").FullName;
        try
        {
            var path = Path.Combine(dir, "a.bundle");
            var bytes = new byte[256];
            "UnityFS\0"u8.CopyTo(bytes);
            File.WriteAllBytes(path, bytes);
            var error = Assert.Throws<Corvus.Core.ToolError>(() =>
                new Corvus.Services.Analysis.UnpackService(new Corvus.Core.AssemblyWorkspace(new Corvus.Core.ServerOptions())).Extract(path, null, Corvus.Core.AnalysisLimits.Default, CancellationToken.None));
            Assert.Contains("summarize_file", error.NextFor("unpack_container"));
            Assert.Contains("view=assets", error.NextFor("unpack_container"));
            Assert.DoesNotContain("extract_strings", error.NextFor("unpack_container"));
        }
        finally { Directory.Delete(dir, true); }
    }
}
