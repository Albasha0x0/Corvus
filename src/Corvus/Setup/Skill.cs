using System.Text;
using System.Text.Json.Nodes;
using Corvus.Mcp;

namespace Corvus.Setup;

/// <summary>
/// The optional agent skill, generated from the server's own guidance (<see cref="Guide"/>), so it never describes tools
/// the server lacks. The repository keeps a copy in skills/net-decompiler (checked by a test); install --skill writes it
/// for clients that read skills, with a marker file, and only marked folders are refreshed or removed.
/// </summary>
internal static class Skill
{
    public const string Name = "net-decompiler";
    public const string Marker = ".netdecompiler-skill";

    /// <summary>Folder states: written by this build, by another build, absent, or a folder of the same name not written by us.</summary>
    public const string Aligned = "aligned", Stale = "stale", Missing = "missing", Foreign = "foreign";

    /// <summary>The skill's files by relative path ('/' separated).</summary>
    public static SortedDictionary<string, string> Files()
    {
        var files = new SortedDictionary<string, string>(StringComparer.Ordinal) { ["SKILL.md"] = Body() };
        foreach (var (topic, text) in Guide.Topics)
            files[$"references/guide-{topic}.md"] = $"# Guide: {topic}\n\n{Generated}\n\n{text.Trim().ReplaceLineEndings("\n")}\n";
        return files;
    }

    private const string Generated = "<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->";

    public const string Description =
        "Reverse engineering of compiled .NET assemblies and native PE, ELF and Mach-O binaries with the net-decompiler MCP server " +
        "or its NetDecompilerMcp command line: decompile, search, follow calls, compare builds, read crash dumps, patch and save a copy. " +
        "Use when an answer depends on what a compiled program does (an .exe or .dll, a Unity or Il2Cpp game build, a package without " +
        "source, a crash dump, two builds of one app). Skip it when the source code is at hand.";

    private static string Body()
    {
        var sb = new StringBuilder();
        // Quoted: the description holds ": ", which a plain YAML scalar cannot.
        sb.Append($"---\nname: {Name}\ndescription: \"{Description}\"\n---\n\n");
        sb.Append($"# {Name}\n\n{Generated}\n\n");
        sb.Append("## Server guidance\n\n");
        sb.Append(Guide.Core.Trim().ReplaceLineEndings("\n")).Append("\n\n");
        sb.Append("""
            ## Connect only when needed

            If the net-decompiler tools are available, use them. If they are not:

            1. `NetDecompilerMcp status --client <id>` says whether this client has the server registered and whether it starts.
            2. `NetDecompilerMcp install --client <id> --yes` registers it; then restart the client and call `server_status`.

            Without the `NetDecompilerMcp` command, install it first (see the project README); this skill does not include the server.

            ## Terminal fallback

            With only a shell, every tool runs from the command line through the same server code:

            ```sh
            NetDecompilerMcp tools                                   # the tools by toolset
            NetDecompilerMcp describe decompile_member               # parameters and an example
            NetDecompilerMcp decompile_member --load app.dll member=Ns.Type::Method
            NetDecompilerMcp find_references --load app.dll symbol=Ns.Type::Method --json
            NetDecompilerMcp batch steps.jsonl                       # several calls in one session
            ```

            A batch file holds one `{"tool": "...", "args": {...}}` object per line; ids such as `app.dll#2` and unsaved
            edits carry from line to line. Exit codes: 0 success, 1 tool error, 2 usage or invalid argument, 3 engine
            missing or unsupported, 124 timeout, 130 cancelled.

            ## Evidence

            - Separate what a tool showed (cite the token, address or file offset and the tool) from inferences and unknowns.
            - A search that finds nothing is not proof of absence: name what was searched and what was not loaded.
            - Edits stay in memory until saved; preview with `dryRun=true`, and save to a new file.

            ## Topics

            The full guidance per area, also served by the `guide` prompt and `corvus://guide/{topic}`:


            """);
        foreach (var topic in Guide.Topics.Keys) sb.Append($"- [{topic}](references/guide-{topic}.md)\n");
        return sb.ToString();
    }

    /// <summary>The skill folder of each client that reads user skills; several clients can share one folder.</summary>
    public static IReadOnlyList<(string Client, string Folder)> Targets(SetupEnvironment env)
    {
        var claude = env.Set("CLAUDE_CONFIG_DIR") ?? env.InHome(".claude");
        var shared = env.InHome(".agents", "skills", Name);
        return
        [
            ("claude-code", Path.Combine(claude, "skills", Name)),
            ("codex", shared),
            ("gemini-cli", shared),
            ("cursor", shared),
            ("copilot-cli", shared),
            ("opencode", shared),
            ("antigravity", env.InHome(".gemini", "config", "skills", Name)),
        ];
    }

    /// <summary>The folders of <paramref name="clients"/> that read skills, each with the clients it serves.</summary>
    public static List<(string Folder, List<string> Clients)> FoldersOf(SetupEnvironment env, IEnumerable<string> clients)
    {
        var wanted = clients.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. Targets(env).Where(t => wanted.Contains(t.Client))
            .GroupBy(t => t.Folder, StringComparer.OrdinalIgnoreCase)
            .Select(g => (g.Key, g.Select(t => t.Client).ToList()))];
    }

    public static string StateOf(string folder)
    {
        if (!Directory.Exists(folder)) return Missing;
        if (!File.Exists(Path.Combine(folder, Marker))) return Foreign;
        return Files().All(f => File.Exists(Path.Combine(folder, f.Key)) && File.ReadAllText(Path.Combine(folder, f.Key)).ReplaceLineEndings("\n") == f.Value)
            ? Aligned : Stale;
    }

    /// <summary>Writes the skill into <paramref name="folder"/> unless a folder of that name exists that we did not write.</summary>
    public static ConfigChange Write(string folder)
    {
        var state = StateOf(folder);
        if (state == Foreign) return new ConfigChange(false, $"left unchanged: {folder} exists and has no {Marker}");
        if (state == Aligned) return new ConfigChange(false, "already current");
        if (state == Stale) Directory.Delete(folder, recursive: true);
        foreach (var (path, text) in Files())
        {
            var file = Path.Combine([folder, .. path.Split('/')]);
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file, text);
        }
        var (tools, prompts) = Catalog.OfThisBuild();
        var marker = new JsonObject { ["version"] = Installation.Version, ["catalog"] = Catalog.Digest(tools, prompts) };
        File.WriteAllText(Path.Combine(folder, Marker), marker.ToJsonString() + "\n");
        return new ConfigChange(true, state == Stale ? "updated" : "written");
    }

    /// <summary>Deletes the folder when it carries the marker; a folder we did not write is kept.</summary>
    public static ConfigChange Remove(string folder)
    {
        var state = StateOf(folder);
        if (state == Missing) return new ConfigChange(false, "not installed");
        if (state == Foreign) return new ConfigChange(false, $"kept: no {Marker}");
        Directory.Delete(folder, recursive: true);
        return new ConfigChange(true, "removed");
    }
}
