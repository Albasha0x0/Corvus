using System.Text.Json.Nodes;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The generated skill: the repository copy is current, it names only real tools, and install / status / uninstall manage it.</summary>
public sealed class SkillTests : IDisposable
{
    private readonly SetupHome _home = new();
    public void Dispose() => _home.Dispose();

    private static string RepoRoot()
    {
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "Corvus.slnx"))) root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("repository root not found");
        return root;
    }

    [Fact]
    public void The_repository_copy_of_the_skill_is_current()
    {
        var folder = Path.Combine(RepoRoot(), "skills", Skill.Name);
        var expected = Skill.Files();
        if (Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1")
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
            foreach (var (path, text) in expected)
            {
                var file = Path.Combine([folder, .. path.Split('/')]);
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllText(file, text);
            }
        }
        var actual = Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories).ToDictionary(
                f => Path.GetRelativePath(folder, f).Replace('\\', '/'), f => File.ReadAllText(f).ReplaceLineEndings("\n"))
            : [];
        Assert.True(actual.Count == expected.Count && expected.All(e => actual.TryGetValue(e.Key, out var text) && text == e.Value),
            "skills/corvus is out of date: run the tests once with CORVUS_UPDATE_DOCS=1");
    }

    [Fact]
    public void The_skill_fits_client_limits_and_names_only_real_tools()
    {
        var files = Skill.Files();
        var body = files["SKILL.md"];
        Assert.StartsWith($"---\nname: {Skill.Name}\ndescription: \"{Skill.Description}\"\n---\n", body, StringComparison.Ordinal);
        Assert.DoesNotContain('"', Skill.Description);
        Assert.True(Skill.Description.Length <= 1024, $"description is {Skill.Description.Length} characters");
        Assert.True(body.Split('\n').Length < 200, "SKILL.md should stay under 200 lines");
        Assert.Contains(Mcp.Guide.Core.Trim().ReplaceLineEndings("\n"), body, StringComparison.Ordinal);
        var tools = Mcp.Catalog.OfThisBuild().Tools.Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);
        foreach (var (path, text) in files)
            Assert.True(McpProtocolTests.UnknownTools(text, tools, ["dump_from_memory"]) is [], $"{path}: {string.Join(", ", McpProtocolTests.UnknownTools(text, tools, ["dump_from_memory"]))}");
        foreach (var topic in Mcp.Guide.Topics.Keys) Assert.Contains($"(references/guide-{topic}.md)", body, StringComparison.Ordinal);
    }

    [Fact]
    public void Install_status_and_uninstall_manage_marked_folders()
    {
        Directory.CreateDirectory(_home.Path(".claude"));
        Directory.CreateDirectory(_home.Path(".codex"));
        var claude = _home.Path(".claude", "skills", Skill.Name);
        var shared = _home.Path(".agents", "skills", Skill.Name);

        // Without --skill nothing is written; the dry run lists the folders and writes nothing.
        Assert.Equal(0, _home.Run("install", "--no-check", "--yes").Code);
        Assert.False(Directory.Exists(claude));
        var before = _home.Snapshot();
        var (code, output) = _home.Run("install", "--no-check", "--yes", "--skill", "--dry-run");
        Assert.Equal(0, code);
        Assert.Contains("would write", output);
        Assert.Equal(before, _home.Snapshot());

        (code, output) = _home.Run("install", "--no-check", "--yes", "--skill", "--json");
        Assert.Equal(0, code);
        var skills = JsonNode.Parse(output)!["skills"]!.AsArray();
        Assert.Equal(2, skills.Count);
        Assert.Equal(Skill.Aligned, Skill.StateOf(claude));
        Assert.Equal(Skill.Aligned, Skill.StateOf(shared));
        Assert.Contains("\"catalog\"", File.ReadAllText(Path.Combine(claude, Skill.Marker)));

        // Status: aligned, then stale after a change; any install brings a stale skill back.
        Assert.Contains($"skills{Path.DirectorySeparatorChar}{Skill.Name}: aligned", _home.Run("status", "--client", "claude-code").Output);
        File.AppendAllText(Path.Combine(claude, "SKILL.md"), "edited\n");
        Assert.Equal(Skill.Stale, Skill.StateOf(claude));
        Assert.Contains(": stale - written by another build", _home.Run("status", "--client", "claude-code").Output);
        Assert.Equal(0, _home.Run("install", "--no-check").Code);
        Assert.Equal(Skill.Aligned, Skill.StateOf(claude));

        // A folder of the same name that install did not write is never touched.
        Directory.Delete(shared, recursive: true);
        _home.Write("mine", ".agents", "skills", Skill.Name, "SKILL.md");
        Assert.Contains("left unchanged", _home.Run("install", "--no-check", "--skill").Output);
        Assert.Equal("mine", File.ReadAllText(Path.Combine(shared, "SKILL.md")));

        // Uninstall removes marked folders only.
        Assert.Equal(0, _home.Run("uninstall", "--keep-files").Code);
        Assert.False(Directory.Exists(claude));
        Assert.Equal("mine", File.ReadAllText(Path.Combine(shared, "SKILL.md")));
    }

    [Fact]
    public void Clients_with_their_own_skill_folders_get_the_skill_there()
    {
        var (code, output) = _home.Run("install", "--no-check", "--skill", "--client", "cline,roo-code,kilo-code,windsurf,qwen-code,command-code,pi");
        Assert.True(code == 0, output);
        foreach (var folder in new[]
                 {
                     _home.Path(".agents", "skills", Skill.Name), _home.Path(".roo", "skills", Skill.Name), _home.Path(".kilocode", "skills", Skill.Name),
                     _home.Path(".codeium", "windsurf", "skills", Skill.Name), _home.Path(".qwen", "skills", Skill.Name),
                     _home.Path(".commandcode", "skills", Skill.Name), _home.Path(".pi", "agent", "skills", Skill.Name),
                 })
            Assert.Equal(Skill.Aligned, Skill.StateOf(folder));
        // QWEN_HOME moves Qwen Code's skills with its settings.
        var moved = _home.Env(variables: new Dictionary<string, string> { ["QWEN_HOME"] = _home.Path("q") });
        Assert.Contains(Skill.Targets(moved), t => t == ("qwen-code", _home.Path("q", "skills", Skill.Name)));
    }

    [Fact]
    public void Uninstall_of_one_client_keeps_a_folder_another_registered_client_reads()
    {
        Directory.CreateDirectory(_home.Path(".codex"));
        Directory.CreateDirectory(_home.Path(".cursor"));
        Assert.Equal(0, _home.Run("install", "--no-check", "--yes", "--skill").Code);
        var shared = _home.Path(".agents", "skills", Skill.Name);
        Assert.Equal(Skill.Aligned, Skill.StateOf(shared));
        Assert.Contains("kept: also read by", _home.Run("uninstall", "codex").Output);
        Assert.Equal(Skill.Aligned, Skill.StateOf(shared));
        _home.Run("uninstall", "cursor");
        Assert.Equal(Skill.Missing, Skill.StateOf(shared));
    }
}
