using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace NetDecompilerMcp.Setup;

/// <summary>How the server is started: an executable and its arguments.</summary>
internal sealed record ServerLaunch(string Command, IReadOnlyList<string> Args);

/// <summary>The outcome of changing one configuration file.</summary>
internal sealed record ConfigChange(bool Changed, string Message);

/// <summary>A registered server entry as the client reads it; <see cref="Disabled"/> when the client will not start it.</summary>
internal sealed record RegisteredEntry(string Command, IReadOnlyList<string> Args, IReadOnlyDictionary<string, string> Env, bool Disabled);

/// <summary>Plan actions; the strings appear in --json output.</summary>
internal static class SetupAction
{
    public const string Add = "add", Refresh = "refresh", Unchanged = "unchanged", Skip = "skip", Blocked = "blocked", Remove = "remove";
}

/// <summary>
/// What installing would do to one file, computed without writing: <see cref="SetupAction"/> Add, Refresh, Unchanged or
/// Blocked (with <see cref="Reason"/>), the entry before and after, whether comments survive and the backup path.
/// </summary>
internal sealed record TargetPreview(string Action, string? Reason, JsonNode? Before, JsonNode? After, bool PreservesComments, string? BackupPath);

/// <summary>A configuration file that lists MCP servers.</summary>
internal abstract class ConfigTarget(string path)
{
    public string Path { get; } = path;

    /// <summary>The launch command registered under the name, or null when absent or unreadable.</summary>
    public abstract string? Registered(string name);
    /// <summary>The entry registered under the name, or null when absent or unreadable.</summary>
    public abstract RegisteredEntry? Current(string name);
    public abstract TargetPreview Preview(string name, ServerLaunch launch);
    public abstract ConfigChange Install(string name, ServerLaunch launch);
    public abstract ConfigChange Uninstall(string name);

    protected const string BackupSuffix = ".netdecompiler.bak";

    /// <summary>Where the first pre-install copy is (or would be) kept; null for a file that does not exist yet.</summary>
    protected string? BackupPath() => File.Exists(Path) ? Path + BackupSuffix : null;

    public static JsonObject ToJson(RegisteredEntry entry) => new()
    {
        ["command"] = entry.Command,
        ["args"] = new JsonArray([.. entry.Args.Select(a => (JsonNode)JsonValue.Create(a)!)]),
        ["env"] = new JsonObject(entry.Env.Select(e => KeyValuePair.Create(e.Key, (JsonNode?)JsonValue.Create(e.Value)))),
        ["disabled"] = entry.Disabled,
    };

    /// <summary>
    /// The user's arguments, with ours in front unless already there. Another launch's program argument (the
    /// NetDecompilerMcp.dll of a dotnet launch) is dropped so switching launchers does not carry it over.
    /// </summary>
    public static List<string> MergeArgs(IEnumerable<string> user, IReadOnlyList<string> ours)
    {
        var kept = user.Where(a => ours.Contains(a) || !System.IO.Path.GetFileName(a).Equals("NetDecompilerMcp.dll", StringComparison.OrdinalIgnoreCase)).ToList();
        return kept.Take(ours.Count).SequenceEqual(ours) ? kept : [.. ours, .. kept];
    }

    /// <summary>Keeps the first pre-install copy of a file next to it.</summary>
    protected void Backup()
    {
        if (File.Exists(Path) && !File.Exists(Path + BackupSuffix)) File.Copy(Path, Path + BackupSuffix);
    }

    /// <summary>
    /// Writes through a temporary file in the same folder so a crash never leaves a partial file, then reads the file
    /// back; when it does not hold what was written (another program rewrote it, a sync tool interfered) the previous
    /// content is restored and the reason is returned.
    /// </summary>
    protected string? WriteAtomically(string text)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        byte[]? previous = File.Exists(Path) ? File.ReadAllBytes(Path) : null;
        var temp = Path + ".tmp-" + Guid.NewGuid().ToString("N")[..8];
        File.WriteAllText(temp, text, new UTF8Encoding(false));
        File.Move(temp, Path, overwrite: true);
        string? written;
        try { written = File.ReadAllText(Path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { written = null; }
        if (written == text) return null;
        if (previous != null) File.WriteAllBytes(Path, previous);
        else File.Delete(Path);
        return "left unchanged: the file did not read back as written, so the previous content was restored";
    }

    protected ConfigChange Write(string text, string message) =>
        WriteAtomically(text) is { } failed ? new ConfigChange(false, failed) : new ConfigChange(true, message);
}

/// <summary>A JSON file with servers in an object at <see cref="Container"/> (e.g. "mcpServers").</summary>
internal sealed class JsonTarget(string path, string[] container, Func<ServerLaunch, JsonObject> entry) : ConfigTarget(path)
{
    public IReadOnlyList<string> Container { get; } = container;
    public Func<ServerLaunch, JsonObject> Entry { get; } = entry;

    private static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>The parsed file (empty when missing), whether it had comments, or an error.</summary>
    private (JsonObject? Root, bool HadComments, string? Error) Load()
    {
        if (!File.Exists(Path)) return (new JsonObject(), false, null);
        string text;
        try { text = File.ReadAllText(Path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (null, false, ex.Message); }
        if (string.IsNullOrWhiteSpace(text)) return (new JsonObject(), false, null);
        try
        {
            if (JsonNode.Parse(text, documentOptions: Lenient) is not JsonObject root) return (null, false, "the file is not a JSON object");
            bool strict;
            try { JsonDocument.Parse(text).Dispose(); strict = true; }
            catch (JsonException) { strict = false; }
            return (root, !strict, null);
        }
        catch (JsonException ex) { return (null, false, $"invalid JSON ({ex.Message})"); }
    }

    private JsonObject? Servers(JsonObject root, bool create)
    {
        JsonObject current = root;
        foreach (var key in Container)
        {
            if (current[key] is JsonObject next) { current = next; continue; }
            if (!create) return null;
            next = new JsonObject();
            current[key] = next;
            current = next;
        }
        return current;
    }

    public override string? Registered(string name)
    {
        var (root, _, _) = Load();
        if (root == null || Servers(root, false)?[name] is not JsonObject server) return null;
        return server["command"] switch
        {
            JsonValue v when v.TryGetValue<string>(out var s) => s,
            JsonArray a => a.FirstOrDefault()?.GetValue<string>(),
            _ => "",
        };
    }

    /// <summary>The entry registered under the name, or null.</summary>
    public JsonObject? Existing(string name)
    {
        var (root, _, _) = Load();
        return root == null ? null : Servers(root, false)?[name] as JsonObject;
    }

    public override RegisteredEntry? Current(string name) => Existing(name) is { } entry ? Parse(entry) : null;

    /// <summary>Command and arguments from "command" (a string, or an array holding both) and "args"; env from "env" or "environment".</summary>
    public static RegisteredEntry Parse(JsonObject entry)
    {
        static string Text(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : n?.ToJsonString() ?? "";
        var command = entry["command"] is JsonArray a ? a.Select(Text).ToList() : [Text(entry["command"])];
        IEnumerable<string> args = entry["args"] is JsonArray list ? list.Select(Text) : [];
        var env = (entry["env"] ?? entry["environment"]) is JsonObject e
            ? e.ToDictionary(p => p.Key, p => Text(p.Value), StringComparer.Ordinal)
            : new Dictionary<string, string>(StringComparer.Ordinal);
        bool disabled = entry["disabled"] is JsonValue d && d.TryGetValue<bool>(out var off) && off
                        || entry["enabled"] is JsonValue en && en.TryGetValue<bool>(out var on) && !on;
        return new RegisteredEntry(command.FirstOrDefault() ?? "", [.. command.Skip(1), .. args], env, disabled);
    }

    public override TargetPreview Preview(string name, ServerLaunch launch)
    {
        var (root, hadComments, error) = Load();
        if (root == null) return new TargetPreview(SetupAction.Blocked, error, null, null, false, null);
        var existing = Servers(root, false)?[name] as JsonObject;
        var next = Merge(existing, launch);
        var action = existing == null ? SetupAction.Add : JsonNode.DeepEquals(existing, next) ? SetupAction.Unchanged : SetupAction.Refresh;
        return new TargetPreview(action, null, existing?.DeepClone(), next, !hadComments, BackupPath());
    }

    /// <summary>
    /// Our entry for a new registration; for an existing one, the user's entry with our command, user arguments kept
    /// (see <see cref="ConfigTarget.MergeArgs"/>) and our other keys added only where absent.
    /// </summary>
    public JsonObject Merge(JsonObject? existing, ServerLaunch launch)
    {
        var fresh = Entry(launch);
        if (existing == null) return fresh;
        var merged = (JsonObject)existing.DeepClone();
        static List<string>? Strings(JsonNode? node, int skip) =>
            node is JsonArray a && a.All(i => i is JsonValue v && v.TryGetValue<string>(out _)) ? [.. a.Skip(skip).Select(i => i!.GetValue<string>())] : null;
        static JsonArray ToArray(IEnumerable<string> items) => new([.. items.Select(i => (JsonNode)JsonValue.Create(i)!)]);
        if (fresh["command"] is JsonArray)
        {
            // Command and arguments in one array (OpenCode).
            var user = Strings(existing["command"], 1);
            merged["command"] = user == null ? fresh["command"]!.DeepClone() : ToArray([launch.Command, .. MergeArgs(user, launch.Args)]);
        }
        else
        {
            merged["command"] = launch.Command;
            if (existing["args"] != null && Strings(existing["args"], 0) is { } user) merged["args"] = ToArray(MergeArgs(user, launch.Args));
        }
        foreach (var (key, value) in fresh)
            if (!merged.ContainsKey(key)) merged[key] = value?.DeepClone();
        return merged;
    }

    public override ConfigChange Install(string name, ServerLaunch launch) => Put(name, existing => Merge(existing, launch));

    /// <summary>Writes the entry made from the current one (null when absent) under the name.</summary>
    public ConfigChange Put(string name, Func<JsonObject?, JsonObject> entry)
    {
        var (root, hadComments, error) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, true)!;
        var existing = servers[name] as JsonObject;
        var next = entry(existing);
        if (existing != null && JsonNode.DeepEquals(existing, next)) return new ConfigChange(false, "already registered");
        servers[name] = next;
        Backup();
        return Write(root.ToJsonString(Indented) + Environment.NewLine,
            hadComments ? $"registered (comments were not kept; original saved as {System.IO.Path.GetFileName(Path)}{BackupSuffix})" : "registered");
    }

    public override ConfigChange Uninstall(string name)
    {
        var (root, _, error) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, false);
        if (servers == null || !servers.Remove(name)) return new ConfigChange(false, "not registered");
        Backup();
        return Write(root.ToJsonString(Indented) + Environment.NewLine, "removed");
    }
}

/// <summary>Codex's config.toml: one [mcp_servers.NAME] table, edited as text so the rest of the file is untouched.</summary>
internal sealed partial class CodexTomlTarget(string path) : ConfigTarget(path)
{
    [GeneratedRegex(@"^\s*\[\s*mcp_servers\s*\.\s*(?:""(?<n>[^""]+)""|'(?<n>[^']+)'|(?<n>[A-Za-z0-9_-]+))(?<sub>\s*\.[^\]]*)?\s*\]\s*(#.*)?$")]
    private static partial Regex ServerHeader();

    [GeneratedRegex(@"^\s*\[")]
    private static partial Regex AnyHeader();

    [GeneratedRegex(@"^\s*command\s*=\s*(?:""(?<v>(?:[^""\\]|\\.)*)""|'(?<v>[^']*)')")]
    private static partial Regex CommandLine();

    private List<string> Lines() => File.Exists(Path) ? [.. File.ReadAllText(Path).Replace("\r\n", "\n").Split('\n')] : [];

    /// <summary>Line ranges [start, end) of the server's table and its sub-tables.</summary>
    private static List<(int Start, int End)> Blocks(List<string> lines, string name)
    {
        var blocks = new List<(int, int)>();
        for (int i = 0; i < lines.Count; i++)
        {
            var m = ServerHeader().Match(lines[i]);
            if (!m.Success || m.Groups["n"].Value != name) continue;
            int end = i + 1;
            while (end < lines.Count && !AnyHeader().IsMatch(lines[end])) end++;
            blocks.Add((i, end));
            i = end - 1;
        }
        return blocks;
    }

    public override string? Registered(string name)
    {
        try
        {
            var lines = Lines();
            foreach (var (start, end) in Blocks(lines, name))
                for (int i = start + 1; i < end; i++)
                    if (CommandLine().Match(lines[i]) is { Success: true } m)
                        return m.Groups["v"].Value.Replace("\\\\", "\\").Replace("\\\"", "\"");
            return Blocks(lines, name).Count > 0 ? "" : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static List<string> Remove(List<string> lines, string name)
    {
        foreach (var (start, end) in Blocks(lines, name).AsEnumerable().Reverse()) lines.RemoveRange(start, end - start);
        while (lines.Count > 0 && lines[^1].Trim().Length == 0) lines.RemoveAt(lines.Count - 1);
        return lines;
    }

    public override ConfigChange Install(string name, ServerLaunch launch)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ConfigChange(false, $"left unchanged: {ex.Message}"); }
        if (Installed(lines, name, launch) is not { } text) return new ConfigChange(false, "already registered");
        Backup();
        return Write(text, "registered");
    }

    public override TargetPreview Preview(string name, ServerLaunch launch)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new TargetPreview(SetupAction.Blocked, ex.Message, null, null, false, null); }
        var before = Parse(lines, name);
        var text = Installed([.. lines], name, launch);
        var after = text == null ? before : Parse([.. text.Split('\n')], name);
        var action = before == null ? SetupAction.Add : text == null ? SetupAction.Unchanged : SetupAction.Refresh;
        return new TargetPreview(action, null, before is null ? null : ToJson(before), after is null ? null : ToJson(after), true, BackupPath());
    }

    public override RegisteredEntry? Current(string name)
    {
        try { return Parse(Lines(), name); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    [GeneratedRegex(@"^\s*(?<k>[A-Za-z0-9_-]+|""[^""]*"")\s*=\s*(?:""(?<v>(?:[^""\\]|\\.)*)""|'(?<v>[^']*)'|(?<v>[^#\s]+))")]
    private static partial Regex KeyValue();

    [GeneratedRegex(@"^\s*env\s*=\s*\{(?<items>[^}]*)\}")]
    private static partial Regex InlineEnv();

    [GeneratedRegex(@"^\s*enabled\s*=\s*false\b")]
    private static partial Regex EnabledFalse();

    /// <summary>The server's table and its env sub-table (or inline env), or null when it has no table.</summary>
    private static RegisteredEntry? Parse(List<string> lines, string name)
    {
        var blocks = Blocks(lines, name);
        if (blocks.Count == 0) return null;
        string command = "";
        List<string> args = [];
        var env = new Dictionary<string, string>(StringComparer.Ordinal);
        bool disabled = false;
        foreach (var (start, end) in blocks)
        {
            var sub = ServerHeader().Match(lines[start]).Groups["sub"];
            bool envTable = sub.Success && sub.Value.Trim().TrimStart('.').Trim() == "env";
            for (int i = start + 1; i < end; i++)
            {
                if (envTable)
                {
                    if (KeyValue().Match(lines[i]) is { Success: true } kv) env[kv.Groups["k"].Value.Trim('"')] = Unescape(kv.Groups["v"].Value);
                    continue;
                }
                if (sub.Success) continue;
                if (CommandLine().IsMatch(lines[i])) command = CommandValue(lines[i]);
                else if (ParseArgs(lines[i]) is { } a) args = a;
                else if (EnabledFalse().IsMatch(lines[i])) disabled = true;
                else if (InlineEnv().Match(lines[i]) is { Success: true } inline)
                    foreach (var item in inline.Groups["items"].Value.Split(','))
                        if (KeyValue().Match(item) is { Success: true } kv) env[kv.Groups["k"].Value.Trim('"')] = Unescape(kv.Groups["v"].Value);
            }
        }
        return new RegisteredEntry(command, args, env, disabled);
    }

    /// <summary>The file text with the server registered, or null when it already is.</summary>
    private static string? Installed(List<string> lines, string name, ServerLaunch launch)
    {
        var command = $"command = {Quote(launch.Command)}";
        string ArgsLine(IEnumerable<string> args) => $"args = [{string.Join(", ", args.Select(Quote))}]";
        var mains = Blocks(lines, name).Where(b => !ServerHeader().Match(lines[b.Start]).Groups["sub"].Success).ToList();
        if (mains.Count == 0)
        {
            while (lines.Count > 0 && lines[^1].Trim().Length == 0) lines.RemoveAt(lines.Count - 1);
            if (lines.Count > 0) lines.Add("");
            lines.AddRange([$"[mcp_servers.{name}]", command, ArgsLine(launch.Args)]);
            return string.Join("\n", lines) + "\n";
        }

        // An existing table keeps its other keys, its env sub-table and the user's arguments; only the command is replaced.
        var (start, end) = mains[0];
        var updated = new List<string>(lines);
        int commandAt = -1, argsAt = -1;
        for (int i = start + 1; i < end; i++)
        {
            if (commandAt < 0 && CommandLine().IsMatch(lines[i])) commandAt = i;
            else if (argsAt < 0 && ArgsKey().IsMatch(lines[i])) argsAt = i;
        }
        if (argsAt >= 0 && ParseArgs(lines[argsAt]) is { } user && MergeArgs(user, launch.Args) is var merged && !merged.SequenceEqual(user))
            updated[argsAt] = ArgsLine(merged);
        if (commandAt >= 0 && CommandValue(lines[commandAt]) != launch.Command) updated[commandAt] = command;
        var missing = new List<string>();
        if (commandAt < 0) missing.Add(command);
        if (argsAt < 0) missing.Add(ArgsLine(launch.Args));
        updated.InsertRange(start + 1, missing);
        if (updated.SequenceEqual(lines)) return null;
        var text = string.Join("\n", updated);
        return text.EndsWith('\n') ? text : text + "\n";
    }

    [GeneratedRegex(@"^\s*args\s*=")]
    private static partial Regex ArgsKey();

    [GeneratedRegex(@"^\s*args\s*=\s*\[\s*(?<items>(?:(?:""(?:[^""\\]|\\.)*""|'[^']*')\s*,?\s*)*)\]\s*(#.*)?$")]
    private static partial Regex ArgsArray();

    [GeneratedRegex(@"""(?<v>(?:[^""\\]|\\.)*)""|'(?<v>[^']*)'")]
    private static partial Regex TomlString();

    /// <summary>A one-line array of strings, or null for anything else (left untouched).</summary>
    private static List<string>? ParseArgs(string line) =>
        ArgsArray().Match(line) is { Success: true } m
            ? [.. TomlString().Matches(m.Groups["items"].Value).Select(s => s.Value[0] == '\'' ? s.Groups["v"].Value : Unescape(s.Groups["v"].Value))]
            : null;

    private static string Unescape(string s) => s.Replace("\\\\", "\\").Replace("\\\"", "\"");

    private static string CommandValue(string line)
    {
        var m = CommandLine().Match(line);
        return m.Value.TrimEnd().EndsWith('\'') ? m.Groups["v"].Value : Unescape(m.Groups["v"].Value);
    }

    public override ConfigChange Uninstall(string name)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ConfigChange(false, $"left unchanged: {ex.Message}"); }
        if (Blocks(lines, name).Count == 0) return new ConfigChange(false, "not registered");
        Backup();
        return Write(string.Join("\n", Remove(lines, name)) + "\n", "removed");
    }
}

/// <summary>
/// Claude Code through its own CLI (`claude mcp add/add-json/remove --scope user`), which coordinates with a running Claude Code
/// that rewrites ~/.claude.json; falls back to editing the file when the CLI fails.
/// </summary>
internal sealed class ClaudeCliTarget(string cli, JsonTarget file) : ConfigTarget(file.Path)
{
    public override string? Registered(string name) => file.Registered(name);
    public override RegisteredEntry? Current(string name) => file.Current(name);
    public override TargetPreview Preview(string name, ServerLaunch launch) => file.Preview(name, launch);

    public override ConfigChange Install(string name, ServerLaunch launch)
    {
        if (Preview(name, launch).Action == SetupAction.Unchanged) return new ConfigChange(false, "already registered");
        // Taken before the CLI removes the entry: the user's arguments, env and other keys go into the new one.
        var existing = file.Existing(name);
        var entry = file.Merge(existing, launch);
        Run(["mcp", "remove", "--scope", "user", name]);
        string[] add = existing == null
            ? ["mcp", "add", "--scope", "user", name, "--", launch.Command, .. launch.Args]
            : ["mcp", "add-json", "--scope", "user", name, entry.ToJsonString()];
        if (Run(add) && Registered(name) is { } now && now.Equals(launch.Command, StringComparison.OrdinalIgnoreCase))
            return new ConfigChange(true, "registered");
        return file.Put(name, _ => entry);
    }

    public override ConfigChange Uninstall(string name)
    {
        if (Registered(name) == null) return new ConfigChange(false, "not registered");
        if (Run(["mcp", "remove", "--scope", "user", name]) && Registered(name) == null) return new ConfigChange(true, "removed");
        return file.Uninstall(name);
    }

    private bool Run(string[] args)
    {
        var batch = cli.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) || cli.EndsWith(".bat", StringComparison.OrdinalIgnoreCase);
        var psi = batch
            ? new System.Diagnostics.ProcessStartInfo("cmd.exe") { Arguments = "/d /s /c \"" + string.Join(" ", new[] { cli }.Concat(args).Select(Quote)) + "\"" }
            : new System.Diagnostics.ProcessStartInfo(cli);
        if (!batch) foreach (var a in args) psi.ArgumentList.Add(a);
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = psi.RedirectStandardError = psi.RedirectStandardInput = true;
        psi.CreateNoWindow = true;
        try
        {
            using var p = System.Diagnostics.Process.Start(psi)!;
            p.StandardInput.Close();
            _ = p.StandardOutput.ReadToEndAsync();
            _ = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(60_000)) { try { p.Kill(true); } catch (InvalidOperationException) { } return false; }
            return p.ExitCode == 0;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException) { return false; }
    }

    private static string Quote(string s) => s.Length > 0 && s.IndexOfAny([' ', '&', '(', ')', '^', '"']) < 0 ? s : "\"" + s.Replace("\"", "\"\"") + "\"";
}
