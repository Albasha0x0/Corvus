using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Services.Web.Packages;

/// <summary>Configuration that runs or steers code, at its file and line (null: the whole file).</summary>
/// <param name="Kind">instruction file, hook, mcp server, folder-open task, workflow job, git hook, git config, dev container, direnv, or build step.</param>
public sealed record AgentEntry(string Kind, string Name, string? Command, string Path, int? Line = null);

public static partial class PackageReview
{
    internal sealed record AgentReview(List<PackageFinding> Findings, List<AgentEntry> Entries, List<string> Notes);

    // Claude Code runs these without a tool call: at session start and end, on a prompt, at a stop or a notification.
    private static readonly HashSet<string> UnpromptedEvents = new(StringComparer.Ordinal)
    {
        "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop", "SubagentStop", "Notification", "PreCompact",
    };

    private const int MaxHiddenLines = 20, MaxAgentFiles = 500;

    /// <summary>Hooks, MCP servers, folder-open tasks and hidden text in <paramref name="files"/>; null when none, or when <paramref name="standalone"/> and no agent file.</summary>
    internal static AgentReview? AgentConfig(PackageFiles files, bool standalone, CancellationToken ct)
    {
        var agent = files.Paths.Where(p => !p.Contains("node_modules/", StringComparison.Ordinal))
            .Select(p => (Path: p, Kind: AgentFiles.Kind(p) ?? McpKind(p))).Where(f => f.Kind != null)
            .OrderBy(f => f.Path.Count(c => c == '/')).ThenBy(f => f.Path, StringComparer.Ordinal).Take(MaxAgentFiles).ToList();
        if (standalone && agent.Count == 0) return null;
        var roots = new HashSet<string>(StringComparer.Ordinal) { "" };
        var tops = files.Paths.Select(p => p.IndexOf('/') is var i and > 0 ? p[..(i + 1)] : "").Distinct().Take(2).ToList();
        if (tops is [{ Length: > 0 } top]) roots.Add(top);
        if (files.Has("extension/package.json")) roots.Add("extension/");
        var rootMarkdown = files.Paths.Where(p => p.EndsWith(".md", StringComparison.OrdinalIgnoreCase) && roots.Contains(Folder(p)) && AgentFiles.Kind(p) == null)
            .Order(StringComparer.Ordinal).Take(MaxAgentFiles);
        var review = new AgentReview([], [], []);
        var editor = agent.Where(f => f.Kind == "editor settings").Select(f => (f.Path, Tree: Tree(files, f.Path, review.Notes))).ToList();
        bool automaticTasks = editor.Any(e => e.Tree?["task.allowAutomaticTasks"]?.Text == "on");
        foreach (var (editorPath, tree) in editor)
            if (tree != null) EditorAutoApprove(tree, editorPath, review);
        foreach (var (path, kind) in agent)
        {
            ct.ThrowIfCancellationRequested();
            switch (kind)
            {
                case "instructions":
                    review.Entries.Add(new AgentEntry("instruction file", path[(path.LastIndexOf('/') + 1)..], null, path));
                    HiddenText(files, path, review, instructions: true, ct);
                    break;
                case "settings" when Tree(files, path, review.Notes) is { } s:
                    Hooks(s, path, review, ct);
                    AgentSettings(s, path, review, ct);
                    break;
                case "codex settings" when files.Text(path) is { } toml:
                    CodexSettings(toml, path, review, ct);
                    break;
                case "codex settings":
                    review.Notes.Add($"{path}: not read ({files.Size(path):N0} bytes, over the limit or unreadable); agent configuration unknown");
                    break;
                case "plugin hooks" when Tree(files, path, review.Notes) is { } s:
                    Hooks(s, path, review, ct);
                    break;
                case "plugin manifest" when Tree(files, path, review.Notes) is { } s:
                    PluginManifest(s, path, review, ct);
                    break;
                case "plugin marketplace" when Tree(files, path, review.Notes) is { } s:
                    PluginMarketplace(s, path, review);
                    break;
                case "mcp" when Tree(files, path, review.Notes) is { } s:
                    McpServers(s, path, review, ct);
                    break;
                case "mcp manifest" or "mcp registry" or "mcp tools" when Tree(files, path, review.Notes) is { } s:
                    if (kind == "mcp manifest") McpManifest(s, path, review, ct);
                    else if (kind == "mcp registry") McpRegistry(s, path, review, ct);
                    else McpToolsList(s, path, review, ct);
                    break;
                case "workflow" when files.Text(path) is { } yaml:
                    Workflow(yaml, path, review, ct);
                    break;
                case "tasks" when Tree(files, path, review.Notes) is { } s:
                    FolderOpenTasks(s, path, automaticTasks, review, ct);
                    break;
            }
        }
        foreach (var path in rootMarkdown) HiddenText(files, path, review, instructions: false, ct);
        McpSource(files, review, ct);
        return review.Entries.Count > 0 || review.Findings.Count > 0 || review.Notes.Count > 0 ? review : null;
    }

    private static JsonTree? Tree(PackageFiles files, string path, List<string> notes)
    {
        if (files.Text(path) is not { } text)
        {
            notes.Add($"{path}: not read ({files.Size(path):N0} bytes, over the limit or unreadable); agent configuration unknown");
            return null;
        }
        var tree = JsonTree.Parse(text);
        if (tree == null) notes.Add($"{path}: not valid JSON (comments and trailing commas allowed); agent configuration unknown");
        return tree;
    }

    // --- hidden characters in instruction files ---

    // READMEs use bidirectional controls for right-to-left text, so outside instruction files they rank review.
    private static void HiddenText(PackageFiles files, string path, AgentReview review, bool instructions, CancellationToken ct)
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
            var found = HiddenOnLine(line == 1 && raw.StartsWith('﻿') ? raw[1..] : raw, ct);
            if (!instructions) found = [.. found.Select(f => f.Level == "noteworthy" && f.Rule is not ("package/tag-characters" or "package/hidden-bytes") ? f with { Level = "review" } : f)];
            if (found.Count == 0) continue;
            if (reported++ >= MaxHiddenLines) { more++; continue; }
            review.Findings.AddRange(found.Select(f => f with { Path = path, Line = line }));
        }
        if (more > 0) review.Notes.Add($"{path}: {more} more line(s) with hidden characters, not listed");
        if (instructions) MarkdownComments(text, path, review);
    }

    // Comments and reference definitions are not rendered.
    [GeneratedRegex(@"<!--(.*?)-->|^[ \t]{0,3}\[(?://|comment)\]:[ \t]*(?:<>|#)[ \t]*[(""']([^\n]*)[)""']", RegexOptions.Singleline | RegexOptions.Multiline | RegexOptions.NonBacktracking)]
    private static partial Regex RenderedHidden();

    // Linter and generator directives are ordinary comments.
    [GeneratedRegex(@"^\s*(?:markdownlint|prettier|toc|/toc|tocstop|vale|cspell|begin|end|start|stop|auto-?generated|generated|all-contributors|lint|eslint|spell|docusaurus|truncate|more|readme)\b", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex MarkupDirective();

    [GeneratedRegex(@"\s+", RegexOptions.NonBacktracking)]
    private static partial Regex Blanks();

    // A URL, a path, a secret or script file, a command line or an agent tool call; plain words such as git or node do not count.
    [GeneratedRegex(@"https?://|~/|\.\.?/|/[\w.-]+/[\w.-]|\\\w+\\|\b[\w-]+\.(?:env|pem|key|sh|ps1|py)\b|\b(?:curl|wget|powershell|pwsh|sudo|chmod|ssh|scp|npx)\b|\brm\s+-|\|\s*(?:ba)?sh\b|\b(?:npm|pip3?)\s+install\b|\bmcp__|\b(?:Bash|WebFetch|WebSearch|Read|Write|Edit)\(", RegexOptions.NonBacktracking)]
    private static partial Regex NamesAction();

    /// <summary>Text a Markdown renderer drops, in an instruction file: review, noteworthy when it names a tool, path, URL or command.</summary>
    private static void MarkdownComments(string text, string path, AgentReview review)
    {
        int reported = 0, more = 0;
        foreach (Match m in RenderedHidden().Matches(text))
        {
            var body = (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).Trim();
            if (body.Length == 0 || MarkupDirective().IsMatch(body)) continue;
            if (reported++ >= MaxHiddenLines) { more++; continue; }
            int line = 1 + text.AsSpan(0, m.Index).Count('\n');
            bool acts = NamesAction().IsMatch(body);
            review.Findings.Add(new PackageFinding("package/markdown-hidden", acts ? "noteworthy" : "review", "hidden text",
                $"{(m.Groups[1].Success ? "comment" : "link reference definition")} not shown when rendered" + (acts ? " names a tool, path, URL or command" : "")
                + $": \"{Corvus.Core.Format.EscapeInvisible(Clip(Blanks().Replace(body, " "), 200)!)}\"", path, line));
        }
        if (more > 0) review.Notes.Add($"{path}: {more} more hidden Markdown block(s), not listed");
    }

    /// <summary>Bidirectional controls, zero-width characters, Unicode tag runs, byte-encoding runs and terminal escapes on one line, each as a finding.</summary>
    private static List<PackageFinding> HiddenOnLine(string line, CancellationToken ct = default)
    {
        var findings = new List<PackageFinding>();
        findings.AddRange(HiddenBytes(line, ct));
        findings.AddRange(TerminalEscapes(line));
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
                findings.Add(new PackageFinding("package/tag-characters", "noteworthy", "hidden text",
                    $"{count} Unicode tag character(s), invisible in an editor, read as text: \"{Corvus.Core.Format.EscapeInvisible(Clip(hidden.ToString(), 200)!)}\""));
            }
        }
        if (bidi.Count > 0)
            findings.Add(new PackageFinding("package/bidi-controls", "noteworthy", "hidden text", $"bidirectional control character(s) ({Codes(bidi)}) change the order the line displays in"));
        if (zeroCount > 0)
            findings.Add(new PackageFinding("package/zero-width", zeroCount >= 8 ? "noteworthy" : "review", "hidden text",
                $"{zeroCount} zero-width character(s) ({Codes(zeroWidth)})" + (zeroCount >= 8 ? ", enough to encode hidden text" : "")));
        return findings;
    }

    private const int MinHiddenRun = 8;

    /// <summary>The byte a variation selector (0..15, then 16..255) or private-use code point (low byte) carries; group 1 or 2, else 0.</summary>
    private static int CarriedByte(int cp, out int group)
    {
        group = 1;
        if (cp is >= 0xFE00 and <= 0xFE0F) return cp - 0xFE00;
        if (cp is >= 0xE0100 and <= 0xE01EF) return cp - 0xE0100 + 16;
        group = 2;
        if (cp is >= 0xE000 and <= 0xF8FF or >= 0xF0000 and <= 0xFFFFD or >= 0x100000 and <= 0x10FFFD) return cp & 0xFF;
        group = 0;
        return 0;
    }

    /// <summary>Runs of 8 or more variation selectors or private-use code points, read as bytes; the decoded text is also scanned for code rules.</summary>
    internal static List<PackageFinding> HiddenBytes(string line, CancellationToken ct = default)
    {
        var findings = new List<PackageFinding>();
        var run = new List<byte>();
        int group = 0;
        void Flush()
        {
            if (run.Count >= MinHiddenRun)
            {
                var decoded = Encoding.UTF8.GetString([.. run]);
                var what = group == 1 ? "variation selector(s)" : "private-use character(s)";
                findings.Add(new PackageFinding("package/hidden-bytes", "noteworthy", "hidden text",
                    $"{run.Count} {what} in a row, invisible in an editor, decode to bytes: \"{Corvus.Core.Format.EscapeInvisible(Clip(decoded, 200)!)}\""));
                foreach (var f in Scan("hidden-bytes.txt", decoded, install: false, ct, peel: false))
                    if (f.Level == "noteworthy") findings.Add(f with { Detail = $"hidden bytes: {f.Detail}" });
            }
            run.Clear();
            group = 0;
        }
        for (int i = 0; i < line.Length; i++)
        {
            int cp = char.IsHighSurrogate(line[i]) && i + 1 < line.Length && char.IsLowSurrogate(line[i + 1]) ? char.ConvertToUtf32(line[i], line[i + 1]) : line[i];
            int b = CarriedByte(cp, out int g);
            if (cp > 0xFFFF) i++;
            if (g == 0 || g != group && group != 0) Flush();
            if (g == 0) continue;
            group = g;
            run.Add((byte)b);
        }
        Flush();
        return findings;
    }

    /// <summary>Escape sequences that style, hide or retitle text when printed: CSI (ESC [) and OSC (ESC ]).</summary>
    private static List<PackageFinding> TerminalEscapes(string line)
    {
        int csi = 0, osc = 0;
        for (int i = 0; i + 1 < line.Length; i++)
        {
            if (line[i] != '\u001B') continue;
            if (line[i + 1] == '[') csi++;
            else if (line[i + 1] == ']') osc++;
        }
        if (csi + osc == 0) return [];
        return [new PackageFinding("package/ansi-escape", "noteworthy", "hidden text",
            $"{csi + osc} terminal escape sequence(s) ({(csi > 0 ? $"{csi} CSI" : "")}{(csi > 0 && osc > 0 ? ", " : "")}{(osc > 0 ? $"{osc} OSC" : "")}) can restyle, hide or replace text when the line is printed")];
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
                        review.Findings.Add(new PackageFinding("package/agent-hook", unprompted ? "noteworthy" : "review", "agent configuration",
                            $"Claude Code hook {label} runs: {Clip(text, 200)}" + (unprompted ? "; it runs without a tool call" : ""), path, line));
                        ScanCommand(text, "hook command", path, line, review, ct);
                    }
                }
        if (settings["enableAllProjectMcpServers"] is { Kind: JsonTokenType.True } all)
            review.Findings.Add(new PackageFinding("package/mcp-approve-all", "review", "agent configuration", "enableAllProjectMcpServers approves every server in .mcp.json without asking", path, all.Line));
        if (settings["enabledMcpjsonServers"] is { Items.Count: > 0 } enabled)
            review.Findings.Add(new PackageFinding("package/mcp-approve", "review", "agent configuration",
                $"enabledMcpjsonServers approves these .mcp.json servers without asking: {Clip(string.Join(", ", enabled.Items.Select(i => i.Text)), 200)}", path, enabled.Line));
    }

    private static void McpServers(JsonTree config, string path, AgentReview review, CancellationToken ct)
    {
        // .mcp.json and Cursor name the map mcpServers; VS Code names it servers.
        foreach (var (name, server) in (config["mcpServers"] ?? config["servers"])?.Props ?? [])
            McpServer(name, server, path, review, ct);
    }

    private static void FolderOpenTasks(JsonTree tasks, string path, bool automatic, AgentReview review, CancellationToken ct)
    {
        foreach (var task in tasks["tasks"]?.Items ?? [])
        {
            if (task["runOptions"]?["runOn"] is not { Text: "folderOpen" } runOn) continue;
            var label = task["label"]?.Text ?? task["taskName"]?.Text ?? "(no label)";
            var command = TaskCommand(task) ?? TaskCommand(task["windows"]) ?? TaskCommand(task["linux"]) ?? TaskCommand(task["osx"]) ?? "(no command)";
            review.Entries.Add(new AgentEntry("folder-open task", label, Clip(command), path, runOn.Line));
            review.Findings.Add(new PackageFinding("package/folder-open-task", automatic ? "noteworthy" : "review", "agent configuration",
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

        /// <summary>A node built by another reader, such as the TOML reader.</summary>
        internal static JsonTree Node(JsonTokenType kind, int line, string? text = null, List<(string Name, JsonTree Value)>? props = null, List<JsonTree>? items = null) =>
            new() { Kind = kind, Line = line, Text = text, Props = props, Items = items };

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
