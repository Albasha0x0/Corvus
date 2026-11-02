using System.Text.RegularExpressions;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The tools that Next: steps of thrown errors name: they exist and take the parameters given.</summary>
public partial class NextHintTests
{
    // Tool names in prose that are not calls: "tool k=v" pairs are checked, bare names only for existence.
    private static readonly string[] NotTools = ["dump_from_memory", "list_changed", "patch_native", "save_modules", "stub_needs_reloc"];

    // A step that refines the call just made runs against the same target, so it may omit it.
    private static readonly string[] Targets = ["session", "image", "assembly", "path", "dump"];

    private static readonly string[] Constructors = ["new ToolError(", "ToolError.NotLoaded(", "Targets.NotLoaded("];

    [GeneratedRegex(@"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)((?: [A-Za-z]+=(?:\{[^}]*\}|[^\s,;)""])*)+)")]
    private static partial Regex Call();

    /// <summary>The Next: argument of every error built in the sources, as an expression text.</summary>
    private static IEnumerable<(string File, string Next)> Steps()
    {
        var root = Path.Combine(DocsTests.RepoRoot(), "src", "Corvus");
        foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            foreach (var ctor in Constructors)
                for (int at = text.IndexOf(ctor, StringComparison.Ordinal); at >= 0; at = text.IndexOf(ctor, at + 1, StringComparison.Ordinal))
                {
                    var args = Arguments(text, at + ctor.Length - 1);
                    int next = ctor == "new ToolError(" ? 2 : 1;
                    if (args.Count > next) yield return (Path.GetRelativePath(root, file), args[next]);
                }
        }
    }

    /// <summary>The top-level arguments of the call whose opening parenthesis is at <paramref name="open"/>.</summary>
    private static List<string> Arguments(string text, int open)
    {
        var args = new List<string>();
        int depth = 0, start = open + 1;
        for (int i = open; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '"') { i = SkipString(text, i); continue; }
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (--depth == 0) { args.Add(text[start..i].Trim()); break; }
            }
            else if (c == ',' && depth == 1) { args.Add(text[start..i].Trim()); start = i + 1; }
        }
        return args;
    }

    private static int SkipString(string text, int start)
    {
        bool verbatim = start > 0 && (text[start - 1] == '@' || start > 1 && text[start - 2] == '@');
        bool interpolated = start > 0 && (text[start - 1] == '$' || start > 1 && text[start - 2] == '$');
        for (int i = start + 1; i < text.Length; i++)
        {
            if (text[i] == '"' && verbatim && i + 1 < text.Length && text[i + 1] == '"') i++;
            else if (text[i] == '"') return i;
            else if (text[i] == '\\' && !verbatim) i++;
            else if (interpolated && text[i] == '{' && i + 1 < text.Length && text[i + 1] == '{') i++;
            else if (interpolated && text[i] == '{') i = SkipHole(text, i);
        }
        return text.Length - 1;
    }

    private static int SkipHole(string text, int open)
    {
        int depth = 0;
        for (int i = open; i < text.Length; i++)
        {
            if (text[i] == '"') i = SkipString(text, i);
            else if (text[i] == '{') depth++;
            else if (text[i] == '}' && --depth == 0) return i;
        }
        return text.Length - 1;
    }

    /// <summary>What is wrong with a step: unknown tools, undeclared parameters, required parameters it neither gives nor leaves to the caller.</summary>
    private static List<string> Problems(string step, IReadOnlyDictionary<string, System.Text.Json.Nodes.JsonNode> tools)
    {
        var problems = new List<string>();
        foreach (var unknown in McpProtocolTests.UnknownTools(step, tools.Keys.ToHashSet(StringComparer.Ordinal), NotTools))
            problems.Add($"names {unknown}, which is not a tool");
        foreach (Match m in Call().Matches(step))
        {
            if (!tools.TryGetValue(m.Groups[1].Value, out var tool)) continue;
            var schema = tool["inputSchema"];
            var declared = schema?["properties"]?.AsObject().Select(p => p.Key).ToHashSet(StringComparer.Ordinal) ?? [];
            var given = Regex.Matches(m.Groups[2].Value, @"([A-Za-z]+)=").Select(p => p.Groups[1].Value).ToList();
            foreach (var name in given.Where(g => !declared.Contains(g)))
                problems.Add($"{m.Groups[1].Value} has no parameter {name}");
            var required = schema?["required"]?.AsArray().Select(r => (string)r!) ?? [];
            foreach (var name in required.Where(r => !given.Contains(r) && !Targets.Contains(r)))
                problems.Add($"{m.Groups[1].Value} needs {name}, which the step does not give");
        }
        return problems;
    }

    private static Dictionary<string, System.Text.Json.Nodes.JsonNode> Catalog() =>
        ToolCli.CatalogTools.ToDictionary(t => (string)t["name"]!, t => (System.Text.Json.Nodes.JsonNode)t, StringComparer.Ordinal);

    [Fact]
    public void Next_steps_name_existing_tools_with_declared_parameters()
    {
        var tools = Catalog();
        var problems = new List<string>();
        int steps = 0, calls = 0;
        foreach (var (file, next) in Steps())
        {
            steps++;
            calls += Call().Matches(next).Count(m => tools.ContainsKey(m.Groups[1].Value));
            problems.AddRange(Problems(next, tools).Select(p => $"{file}: {p}"));
        }
        Assert.True(steps >= 1000 && calls >= 20, $"only {steps} steps and {calls} tool calls found");
        Assert.True(problems.Count == 0, string.Join("\n", problems.Distinct()));
    }

    [Fact]
    public void A_step_without_a_required_parameter_or_with_an_undeclared_one_is_a_problem()
    {
        var tools = Catalog();
        Assert.Empty(Problems("update_note id=<id> expectedRevision=<revision> status=dropped", tools));
        Assert.Contains(Problems("update_note status=dropped", tools), p => p.Contains("needs id"));
        Assert.Contains(Problems("update_note id=<id> expectedRevision=1 bogus=1", tools), p => p.Contains("no parameter bogus"));
        Assert.Contains(Problems("get_no_such_tool path=x", tools), p => p.Contains("get_no_such_tool"));
    }

    private static string NextOfUnpacking(byte[] bytes)
    {
        var dir = Directory.CreateTempSubdirectory("nexthint").FullName;
        try
        {
            var path = Path.Combine(dir, "a.bin");
            File.WriteAllBytes(path, bytes);
            var error = Assert.Throws<Corvus.Core.ToolError>(() =>
                new Corvus.Services.Analysis.UnpackService(new Corvus.Core.AssemblyWorkspace(new Corvus.Core.ServerOptions())).Extract(path, null, Corvus.Core.AnalysisLimits.Default, CancellationToken.None));
            return error.NextFor("unpack_container");
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void An_asset_bundle_that_is_not_a_container_is_pointed_to_the_assets_view()
    {
        var bytes = new byte[256];
        "UnityFS\0"u8.CopyTo(bytes);
        var next = NextOfUnpacking(bytes);
        Assert.Contains("summarize_file", next);
        Assert.Contains("view=assets", next);
        Assert.DoesNotContain("extract_strings", next);
    }

    [Fact]
    public void A_serialized_file_that_is_not_a_container_is_pointed_to_the_assets_view()
    {
        // Format 17 header: size at 4, format at 8, data offset at 12, little-endian flag at 16.
        var bytes = new byte[128];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), (uint)bytes.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), 17);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(12), 100);
        Assert.True(Corvus.Core.Assets.SerializedFile.IsSerializedFile(bytes, bytes.Length));
        var next = NextOfUnpacking(bytes);
        Assert.Contains("view=assets", next);
        Assert.DoesNotContain("extract_strings", next);
    }

    [Fact]
    public void Plain_data_that_is_not_a_container_keeps_the_strings_step()
    {
        var next = NextOfUnpacking(System.Text.Encoding.ASCII.GetBytes(new string('x', 300)));
        Assert.Contains("extract_strings", next);
        Assert.DoesNotContain("view=assets", next);
    }
}
