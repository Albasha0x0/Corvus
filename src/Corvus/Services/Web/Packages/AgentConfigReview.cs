using System.Text;
using System.Text.Json;

namespace Corvus.Services.Web.Packages;

/// <summary>
/// Agent configuration a package or repository carries: an instruction file, a Claude Code hook, an MCP server or a VS
/// Code task that runs on folder open, at its file and line (null when the entry is the whole file).
/// </summary>
/// <param name="Kind">instruction file, hook, mcp server, or folder-open task.</param>
public sealed record AgentEntry(string Kind, string Name, string? Command, string Path, int? Line = null);

// Kept apart from PackageReview, whose regex tables every file read would otherwise build: summarize_file asks
// whether a path is an agent file before it knows the input is a package.
/// <summary>Names agent configuration files by path; no file is read.</summary>
internal static class AgentFiles
{
    private static readonly HashSet<string> InstructionNames = new(StringComparer.Ordinal)
    {
        "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
    };

    /// <summary>Folders whose files configure an agent or editor; a path inside one is rooted at the folder's parent.</summary>
    internal static readonly string[] Folders = [".claude", ".cursor", ".vscode", ".github", ".windsurf", ".clinerules"];

    /// <summary>
    /// What an agent configuration file is (instructions, settings, mcp, tasks, editor settings) by its path with '/'
    /// separators, or null when it is none of them.
    /// </summary>
    internal static string? Kind(string path)
    {
        var slashed = "/" + path;
        var name = path[(path.LastIndexOf('/') + 1)..];
        var dir = slashed[..slashed.LastIndexOf('/')];
        dir = dir[(dir.LastIndexOf('/') + 1)..];
        if (InstructionNames.Contains(name) || slashed.Contains("/.cursor/rules/", StringComparison.Ordinal) || slashed.Contains("/.windsurf/rules/", StringComparison.Ordinal)
            || slashed.Contains("/.clinerules/", StringComparison.Ordinal) || slashed.EndsWith("/.github/copilot-instructions.md", StringComparison.Ordinal)
            || slashed.Contains("/.github/instructions/", StringComparison.Ordinal) && name.EndsWith(".instructions.md", StringComparison.Ordinal))
            return "instructions";
        return (dir, name) switch
        {
            (".claude", "settings.json" or "settings.local.json") => "settings",
            (_, ".mcp.json") or (".cursor" or ".vscode", "mcp.json") => "mcp",
            (".vscode", "tasks.json") => "tasks",
            (".vscode", "settings.json") => "editor settings",
            _ => null,
        };
    }
}

public static partial class PackageReview
{
    internal sealed record AgentReview(List<PackageFinding> Findings, List<AgentEntry> Entries, List<string> Notes);

    // Claude Code runs these without a tool call: at session start and end, on a prompt, at a stop or a notification.
    private static readonly HashSet<string> UnpromptedEvents = new(StringComparer.Ordinal)
    {
        "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop", "SubagentStop", "Notification", "PreCompact",
    };

    private const int MaxHiddenLines = 20, MaxAgentFiles = 500;

    /// <summary>
    /// The agent configuration in <paramref name="files"/>: hidden characters in instruction files, hooks, MCP servers and
    /// folder-open tasks. With <paramref name="standalone"/> (no package manifest), null unless an agent file is present.
    /// </summary>
    internal static AgentReview? AgentConfig(PackageFiles files, bool standalone, CancellationToken ct)
    {
        var agent = files.Paths.Where(p => !p.Contains("node_modules/", StringComparison.Ordinal))
            .Select(p => (Path: p, Kind: AgentFiles.Kind(p))).Where(f => f.Kind != null)
            .OrderBy(f => f.Path.Count(c => c == '/')).ThenBy(f => f.Path, StringComparer.Ordinal).Take(MaxAgentFiles).ToList();
        if (standalone && agent.Count == 0) return null;
        var roots = new HashSet<string>(StringComparer.Ordinal) { "" };
        var tops = files.Paths.Select(p => p.IndexOf('/') is var i and > 0 ? p[..(i + 1)] : "").Distinct().Take(2).ToList();
        if (tops is [{ Length: > 0 } top]) roots.Add(top);
        if (files.Has("extension/package.json")) roots.Add("extension/");
        var rootMarkdown = files.Paths.Where(p => p.EndsWith(".md", StringComparison.OrdinalIgnoreCase) && roots.Contains(Folder(p)) && AgentFiles.Kind(p) == null)
            .Order(StringComparer.Ordinal).Take(MaxAgentFiles);
        var review = new AgentReview([], [], []);
        var editor = agent.Where(f => f.Kind == "editor settings").Select(f => Tree(files, f.Path, review.Notes)).ToList();
        bool automaticTasks = editor.Any(s => s?["task.allowAutomaticTasks"]?.Text == "on");
        foreach (var (path, kind) in agent)
        {
            ct.ThrowIfCancellationRequested();
            switch (kind)
            {
                case "instructions":
                    review.Entries.Add(new AgentEntry("instruction file", path[(path.LastIndexOf('/') + 1)..], null, path));
                    HiddenText(files, path, review, instructions: true);
                    break;
                case "settings" when Tree(files, path, review.Notes) is { } s:
                    Hooks(s, path, review, ct);
                    break;
                case "mcp" when Tree(files, path, review.Notes) is { } s:
                    McpServers(s, path, review, ct);
                    break;
                case "tasks" when Tree(files, path, review.Notes) is { } s:
                    FolderOpenTasks(s, path, automaticTasks, review, ct);
                    break;
            }
        }
        foreach (var path in rootMarkdown) HiddenText(files, path, review, instructions: false);
        return review.Entries.Count > 0 || review.Findings.Count > 0 || review.Notes.Count > 0 ? review : null;
    }

    private static JsonTree? Tree(PackageFiles files, string path, List<string> notes)
    {
        if (files.Text(path) is not { } text)
        {
            notes.Add($"{path}: not read ({files.Size(path):N0} bytes, over the per-file limit or unreadable); its agent configuration is unknown");
            return null;
        }
        var tree = JsonTree.Parse(text);
        if (tree == null) notes.Add($"{path}: not valid JSON (comments and trailing commas allowed); its agent configuration is unknown");
        return tree;
    }

    // --- hidden characters in instruction files ---

    // Right-to-left text in an ordinary README uses bidirectional controls, so outside instruction files they are
    // only worth reviewing; tag runs have no ordinary use and stay noteworthy everywhere.
    private static void HiddenText(PackageFiles files, string path, AgentReview review, bool instructions)
    {
        if (files.Text(path) is not { } text)
        {
            if (files.Has(path)) review.Notes.Add($"{path}: not read ({files.Size(path):N0} bytes); hidden characters not checked");
            return;
        }
        int line = 0, reported = 0, more = 0;
        foreach (var raw in text.Split('\n'))
        {
            line++;
            var found = HiddenOnLine(line == 1 && raw.StartsWith('﻿') ? raw[1..] : raw);
            if (!instructions) found = [.. found.Select(f => f.Level == "noteworthy" && !f.Detail.Contains("tag character", StringComparison.Ordinal) ? f with { Level = "review" } : f)];
            if (found.Count == 0) continue;
            if (reported++ >= MaxHiddenLines) { more++; continue; }
            review.Findings.AddRange(found.Select(f => f with { Path = path, Line = line }));
        }
        if (more > 0) review.Notes.Add($"{path}: {more} more line(s) with hidden characters, not listed");
    }

    /// <summary>Bidirectional controls, zero-width characters and Unicode tag runs on one line, each as a finding.</summary>
    private static List<PackageFinding> HiddenOnLine(string line)
    {
        var findings = new List<PackageFinding>();
        var bidi = new SortedSet<int>();
        var zeroWidth = new SortedSet<int>();
        int zeroCount = 0;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069') bidi.Add(c);
            else if (c is >= '\u200B' and <= '\u200D' or '\u2060' or '\uFEFF')
            {
                // Joiners after non-ASCII text are ordinary: emoji sequences and scripts that shape with them.
                if (c is '\u200C' or '\u200D' && i > 0 && line[i - 1] > '\u007F') continue;
                zeroWidth.Add(c);
                zeroCount++;
            }
            else if (char.IsHighSurrogate(c) && i + 1 < line.Length && char.IsLowSurrogate(line[i + 1]) && IsTag(char.ConvertToUtf32(c, line[i + 1])))
            {
                var hidden = new StringBuilder();
                int count = 0;
                for (; i + 1 < line.Length && char.IsHighSurrogate(line[i]) && char.IsLowSurrogate(line[i + 1]) && IsTag(char.ConvertToUtf32(line[i], line[i + 1])); i += 2, count++)
                {
                    // U+E0020..U+E007E mirror printable ASCII; U+E0001 (language tag) and U+E007F (cancel tag) carry none.
                    int cp = char.ConvertToUtf32(line[i], line[i + 1]);
                    if (cp is >= 0xE0020 and <= 0xE007E) hidden.Append((char)(cp - 0xE0000));
                }
                i--;
                findings.Add(new PackageFinding("noteworthy", "hidden text",
                    $"{count} Unicode tag character(s), invisible in an editor, read as text: \"{Corvus.Core.Format.EscapeInvisible(Clip(hidden.ToString(), 200)!)}\""));
            }
        }
        if (bidi.Count > 0)
            findings.Add(new PackageFinding("noteworthy", "hidden text", $"bidirectional control character(s) ({Codes(bidi)}) change the order the line displays in"));
        if (zeroCount > 0)
            findings.Add(new PackageFinding(zeroCount >= 8 ? "noteworthy" : "review", "hidden text",
                $"{zeroCount} zero-width character(s) ({Codes(zeroWidth)})" + (zeroCount >= 8 ? ", enough to encode hidden text" : "")));
        return findings;
    }

    private static bool IsTag(int cp) => cp is >= 0xE0000 and <= 0xE007F;

    private static string Codes(IEnumerable<int> chars) => string.Join(", ", chars.Select(c => $"U+{c:X4}"));

    // --- hooks, MCP servers and tasks ---

    private static void Hooks(JsonTree settings, string path, AgentReview review, CancellationToken ct)
    {
        if (settings["hooks"]?.Props is { } events)
            foreach (var (name, groups) in events)
                foreach (var group in groups.Items ?? [])
                {
                    var matcher = group["matcher"]?.Text;
                    foreach (var hook in group["hooks"]?.Items ?? [])
                    {
                        var command = hook["command"] ?? hook["prompt"];
                        var text = command?.Text ?? hook["type"]?.Text ?? "(no command)";
                        int line = command?.Line ?? hook.Line;
                        var label = string.IsNullOrEmpty(matcher) ? name : $"{name} ({matcher})";
                        review.Entries.Add(new AgentEntry("hook", label, Clip(text), path, line));
                        bool unprompted = UnpromptedEvents.Contains(name);
                        review.Findings.Add(new PackageFinding(unprompted ? "noteworthy" : "review", "agent configuration",
                            $"Claude Code hook {label} runs: {Clip(text, 200)}" + (unprompted ? "; it runs without a tool call" : ""), path, line));
                        ScanCommand(text, "hook command", path, line, review, ct);
                    }
                }
        if (settings["enableAllProjectMcpServers"] is { Kind: JsonTokenType.True } all)
            review.Findings.Add(new PackageFinding("review", "agent configuration", "enableAllProjectMcpServers approves every server in .mcp.json without asking", path, all.Line));
        if (settings["enabledMcpjsonServers"] is { Items.Count: > 0 } enabled)
            review.Findings.Add(new PackageFinding("review", "agent configuration",
                $"enabledMcpjsonServers approves these .mcp.json servers without asking: {Clip(string.Join(", ", enabled.Items.Select(i => i.Text)), 200)}", path, enabled.Line));
    }

    private static void McpServers(JsonTree config, string path, AgentReview review, CancellationToken ct)
    {
        // .mcp.json and Cursor name the map mcpServers; VS Code names it servers.
        foreach (var (name, server) in (config["mcpServers"] ?? config["servers"])?.Props ?? [])
        {
            var command = server["command"]?.Text is { } exe
                ? string.Join(" ", new[] { exe }.Concat((server["args"]?.Items ?? []).Select(a => a.Text ?? "")))
                : server["url"]?.Text;
            review.Entries.Add(new AgentEntry("mcp server", name, Clip(command), path, server.Line));
            if (command != null) ScanCommand(command, $"MCP server {name}", path, server.Line, review, ct);
        }
    }

    private static void FolderOpenTasks(JsonTree tasks, string path, bool automatic, AgentReview review, CancellationToken ct)
    {
        foreach (var task in tasks["tasks"]?.Items ?? [])
        {
            if (task["runOptions"]?["runOn"] is not { Text: "folderOpen" } runOn) continue;
            var label = task["label"]?.Text ?? task["taskName"]?.Text ?? "(no label)";
            var command = TaskCommand(task) ?? TaskCommand(task["windows"]) ?? TaskCommand(task["linux"]) ?? TaskCommand(task["osx"]) ?? "(no command)";
            review.Entries.Add(new AgentEntry("folder-open task", label, Clip(command), path, runOn.Line));
            review.Findings.Add(new PackageFinding(automatic ? "noteworthy" : "review", "agent configuration",
                $"VS Code task '{Clip(label, 80)}' runs when the folder opens: {Clip(command, 200)}" + (automatic ? "; task.allowAutomaticTasks is on, so it runs without asking" : ""), path, runOn.Line));
            ScanCommand(command, $"task {label}", path, runOn.Line, review, ct);
        }
    }

    /// <summary>A task's command and arguments; each may be a string or an object with a value.</summary>
    private static string? TaskCommand(JsonTree? task)
    {
        static string? Value(JsonTree? v) => v?.Text ?? v?["value"]?.Text;
        if (Value(task?["command"]) is not { } command) return null;
        return string.Join(" ", new[] { command }.Concat((task!["args"]?.Items ?? []).Select(a => Value(a) ?? "")));
    }

    /// <summary>Noteworthy code-rule findings for a command the configuration runs.</summary>
    private static void ScanCommand(string command, string what, string path, int line, AgentReview review, CancellationToken ct)
    {
        foreach (var f in Scan(path, command, install: false, ct, peel: false))
            if (f.Level == "noteworthy") review.Findings.Add(f with { Detail = $"{what}: {f.Detail}", Line = line });
    }

    /// <summary>A JSON value with the 1-based line it starts on; comments and trailing commas are allowed (JSONC).</summary>
    internal sealed class JsonTree
    {
        public JsonTokenType Kind { get; private init; }
        public int Line { get; private init; }

        /// <summary>A string's value, or a number or literal's raw text; null for an object or array.</summary>
        public string? Text { get; private init; }

        public List<(string Name, JsonTree Value)>? Props { get; private init; }
        public List<JsonTree>? Items { get; private init; }

        /// <summary>The first property of that name, or null when absent or not an object.</summary>
        public JsonTree? this[string name] => Props?.FirstOrDefault(p => p.Name == name).Value;

        /// <summary>The tree of <paramref name="text"/>, or null when it is not valid JSON.</summary>
        public static JsonTree? Parse(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            var lines = new List<int> { 0 };
            for (int i = 0; i < bytes.Length; i++) if (bytes[i] == '\n') lines.Add(i + 1);
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true, MaxDepth = 64 });
            try { return reader.Read() ? Read(ref reader, lines) : null; }
            catch (JsonException) { return null; }
        }

        private static JsonTree Read(ref Utf8JsonReader reader, List<int> lines)
        {
            int at = lines.BinarySearch((int)reader.TokenStartIndex);
            int line = (at >= 0 ? at : ~at - 1) + 1;
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    var props = new List<(string, JsonTree)>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                    {
                        var name = reader.GetString()!;
                        reader.Read();
                        props.Add((name, Read(ref reader, lines)));
                    }
                    return new JsonTree { Kind = JsonTokenType.StartObject, Line = line, Props = props };
                case JsonTokenType.StartArray:
                    var items = new List<JsonTree>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray) items.Add(Read(ref reader, lines));
                    return new JsonTree { Kind = JsonTokenType.StartArray, Line = line, Items = items };
                case JsonTokenType.String:
                    return new JsonTree { Kind = JsonTokenType.String, Line = line, Text = reader.GetString() };
                default:
                    return new JsonTree { Kind = reader.TokenType, Line = line, Text = Encoding.UTF8.GetString(reader.ValueSpan) };
            }
        }
    }
}
