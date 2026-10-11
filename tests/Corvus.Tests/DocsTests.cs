using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>
/// Generated documentation: docs/tools.md from the tool catalog and the client table of docs/installation.md from the
/// client catalog. Run the tests with NDM_UPDATE_DOCS=1 to regenerate them.
/// </summary>
[Collection(InProcessCatalogCollection.Name)]
public class DocsTests
{
    internal static string RepoRoot()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "Corvus.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        return root;
    }

    private static bool Update => Environment.GetEnvironmentVariable("NDM_UPDATE_DOCS") == "1";

    [Fact]
    public void ToolReferenceIsCurrent()
    {
        var path = Path.Combine(RepoRoot(), "docs", "tools.md");
        var expected = ToolsMarkdown();
        if (Update) File.WriteAllText(path, expected);
        Assert.True(File.Exists(path) && File.ReadAllText(path).ReplaceLineEndings("\n") == expected,
            "docs/tools.md is out of date: run the tests once with NDM_UPDATE_DOCS=1");
    }

    [Fact]
    public void InstallationClientTableIsCurrent()
    {
        var path = Path.Combine(RepoRoot(), "docs", "installation.md");
        var text = File.ReadAllText(path).ReplaceLineEndings("\n");
        int start = text.IndexOf(ClientsBegin, StringComparison.Ordinal), end = text.IndexOf(ClientsEnd, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start, $"docs/installation.md has no {ClientsBegin} ... {ClientsEnd} block");
        var expected = text[..(start + ClientsBegin.Length)] + "\n" + ClientTable() + text[end..];
        if (Update) File.WriteAllText(path, text = expected);
        Assert.True(text == expected,"docs/installation.md's client table is out of date: run the tests once with NDM_UPDATE_DOCS=1");
    }

    internal const string ClientsBegin = "<!-- clients:begin (generated from Setup/ClientCatalog.cs; NDM_UPDATE_DOCS=1 updates it) -->";
    internal const string ClientsEnd = "<!-- clients:end -->";

    private static string Cell(string text) => text.ReplaceLineEndings(" ").Replace("|", "\\|", StringComparison.Ordinal).Trim();

    internal static string ToolsMarkdown()
    {
        var tools = ToolCli.CatalogTools;
        var sb = new StringBuilder();
        sb.Append("# Tools\n\n<!-- Generated from the tool catalog by DocsTests; run the tests with NDM_UPDATE_DOCS=1 to update. -->\n\n");
        sb.Append($"{tools.Count} tools in {Toolsets.Families.Count} toolsets. A server registers every tool unless it is started with ");
        sb.Append("`--toolsets` (README, \"Server options\"). From a terminal, `NetDecompilerMcp describe <tool>` prints the same ");
        sb.Append("reference and `NetDecompilerMcp <tool> name=value ...` calls a tool ([cli.md](cli.md)).\n\n");
        sb.Append("Annotations: **read-only** tools change nothing; **edit** tools change the in-memory workspace; **destructive** ");
        sb.Append("tools can remove or overwrite state; **long-running** tools can take more than 10 s and have no call deadline.\n\n");
        sb.Append("| Toolset | In `core` | Tools |\n|---|---|---|\n");
        foreach (var f in Toolsets.Families)
            sb.Append($"| [{f.Name}](#{f.Name}) | {(f.InCore ? "yes" : "no")} | {f.Tools.Length}: {Cell(f.Description)} |\n");
        foreach (var family in Toolsets.Families)
        {
            sb.Append($"\n## {family.Name}\n\n{char.ToUpperInvariant(family.Description[0])}{family.Description[1..]}.\n");
            foreach (var name in family.Tools)
            {
                if (ToolCli.FindTool(name) is not { } tool) continue;
                var e = Mcp.ToolEffects.Of(name);
                var flags = new List<string> { e.ReadOnly ? "read-only" : e.Destructive ? "destructive" : "edit" };
                if (e.Idempotent) flags.Add("idempotent");
                if (e.OpenWorld) flags.Add("open-world");
                if (e.LongRunning) flags.Add("long-running");
                var title = (string?)tool["title"] ?? (string?)tool["annotations"]?["title"] ?? name;
                var description = ((string?)tool["description"] ?? "").Replace(Mcp.ToolEffects.LongRunningSuffix, "", StringComparison.Ordinal).Trim();
                sb.Append($"\n### {name}\n\n**{title}** ({string.Join(", ", flags)})\n\n{description.ReplaceLineEndings("\n")}\n\n");
                var parameters = ToolCli.Parameters(tool);
                if (parameters.Count == 0) sb.Append("No parameters.\n");
                else
                {
                    sb.Append("| Parameter | Type | Required | Default | Description |\n|---|---|---|---|---|\n");
                    foreach (var p in parameters)
                    {
                        var described = p.Values is { } values ? $"{p.Description} Values: {values}." : p.Description;
                        sb.Append($"| `{p.Name}` | {Cell(p.Type)} | {(p.Required ? "yes" : "")} | {(p.Default is { } d ? $"`{Cell(d)}`" : "")} | {Cell(described)} |\n");
                    }
                }
                if (tool["outputSchema"]?["properties"] is JsonObject output)
                    sb.Append($"\nStructured output: {string.Join(", ", output.Select(o => $"`{o.Key}`"))}.\n");
            }
        }
        return sb.ToString();
    }

    private static readonly HostOs[] Systems = [HostOs.Windows, HostOs.MacOs, HostOs.Linux];

    /// <summary>A system's catalog with placeholder folders; <paramref name="variable"/> set to a sample value when given.</summary>
    private static IReadOnlyList<McpClient> Catalog(HostOs os, string? variable, HashSet<string>? queried = null) => ClientCatalog.All(new SetupEnvironment
    {
        Os = os,
        Home = "~",
        AppData = "%APPDATA%",
        LocalAppData = "%LOCALAPPDATA%",
        XdgConfig = variable == "XDG_CONFIG_HOME" ? "work" : "~/.config",
        Variable = name =>
        {
            queried?.Add(name);
            return name == variable ? "work" : null;
        },
        FindTool = _ => null,
        DirectoryExists = _ => false,
    });

    private static string Shape(ConfigTarget target) => target switch
    {
        JsonTarget json => $"JSON `{string.Join(".", json.Container)}`",
        CodexTomlTarget => "TOML `[mcp_servers]`",
        _ => target.GetType().Name,
    };

    /// <summary>Per client: id, name, entry shape, the file on each system, and the variables that move it.</summary>
    internal static string ClientTable()
    {
        var queried = new HashSet<string>(StringComparer.Ordinal) { "XDG_CONFIG_HOME" };
        var bySystem = Systems.ToDictionary(os => os, os => Catalog(os, null, queried));
        var overrides = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var variable in queried.Where(v => v != "ProgramFiles"))
            foreach (var os in Systems)
                foreach (var moved in Catalog(os, variable))
                    if (bySystem[os].FirstOrDefault(c => c.Id == moved.Id) is { } plain && plain.Target.Path != moved.Target.Path)
                    {
                        if (!overrides.TryGetValue(moved.Id, out var set)) overrides[moved.Id] = set = new SortedSet<string>(StringComparer.Ordinal);
                        set.Add(variable);
                    }
        var sb = new StringBuilder("| Id | Client | Entry | Windows | macOS | Linux | Moved by |\n|---|---|---|---|---|---|---|\n");
        foreach (var client in bySystem.Values.SelectMany(c => c).DistinctBy(c => c.Id))
        {
            string PathOn(HostOs os) => bySystem[os].FirstOrDefault(c => c.Id == client.Id) is { } c ? $"`{c.Target.Path.Replace('\\', '/')}`" : "-";
            var moved = overrides.TryGetValue(client.Id, out var vars) ? string.Join(", ", vars.Select(v => $"`{v}`")) : "";
            sb.Append($"| `{client.Id}` | {client.Name} | {Shape(client.Target)} | {PathOn(HostOs.Windows)} | {PathOn(HostOs.MacOs)} | {PathOn(HostOs.Linux)} | {moved} |\n");
        }
        return sb.ToString();
    }
}
