using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Corvus.Setup;

/// <summary>How the server is started: an executable and its arguments.</summary>
internal sealed record ServerLaunch(string Command, IReadOnlyList<string> Args);

/// <summary>The outcome of changing one configuration file.</summary>
internal sealed record ConfigChange(bool Changed, string Message);

/// <summary>
/// A registered server entry as the client reads it; <see cref="Disabled"/> when the client will not start it,
/// <see cref="StartupTimeout"/> the seconds it waits for the server and <see cref="ToolTimeout"/> for one call, when the
/// entry says (Codex, Grok Build).
/// </summary>
internal sealed record RegisteredEntry(string Command, IReadOnlyList<string> Args, IReadOnlyDictionary<string, string> Env, bool Disabled,
    double? StartupTimeout = null, double? ToolTimeout = null);

/// <summary>Plan actions; the strings appear in --json output.</summary>
internal static class SetupAction
{
    public const string Add = "add", Refresh = "refresh", Unchanged = "unchanged", Skip = "skip", Blocked = "blocked", Remove = "remove", Rename = "rename";
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

    /// <summary>
    /// Moves the entry under <paramref name="from"/> to <paramref name="to"/>, started by <paramref name="launch"/> with the
    /// entry's own arguments, env (keys renamed by <see cref="ClientCatalog.MigratedEnvKey"/>) and other keys; when
    /// <paramref name="to"/> is already registered the old entry is only removed.
    /// </summary>
    public abstract ConfigChange Rename(string from, string to, ServerLaunch launch);

    /// <summary>Turns the entry on: its own switch and every disable list that names it (install --enable).</summary>
    public virtual ConfigChange Enable(string name) => new(false, "not supported");

    /// <summary>Projects whose own list turns the entry off while the user-level entry is on (Claude Code).</summary>
    public virtual IReadOnlyList<string> DisabledInProjects(string name) => [];

    protected const string BackupSuffix = ".corvus.bak";

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
    /// corvus.dll of a dotnet launch) is dropped so switching launchers does not carry it over, and so is a
    /// development relay prefix (relay --target dir), so a registration switches between the relay and the server.
    /// The user's --client and --client-timeout give way to ours; ours --toolsets gives way to the user's.
    /// </summary>
    public static List<string> MergeArgs(IEnumerable<string> user, IReadOnlyList<string> ours)
    {
        var kept = Corvus.Relay.RelayCli.WithoutRelayPrefix(user).Where(a => ours.Contains(a) || !Corvus.Relay.RelayBuilds.IsProgramDll(a)).ToList();
        kept = WithoutOption(WithoutOption(kept, Core.ClientProfiles.ClientOption), Core.ClientProfiles.ClientTimeoutOption);
        if (kept.Contains(Core.Toolsets.Option, StringComparer.OrdinalIgnoreCase)) ours = WithoutOption([.. ours], Core.Toolsets.Option);
        return kept.Take(ours.Count).SequenceEqual(ours) ? kept : [.. ours, .. kept];
    }

    /// <summary><paramref name="args"/> without each <paramref name="option"/> and the value after it.</summary>
    private static List<string> WithoutOption(List<string> args, string option)
    {
        var result = new List<string>(args.Count);
        for (int i = 0; i < args.Count; i++)
        {
            if (args[i].Equals(option, StringComparison.OrdinalIgnoreCase)) { i++; continue; }
            result.Add(args[i]);
        }
        return result;
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
    protected string? WriteAtomically(string text, bool bom = false)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        byte[]? previous = File.Exists(Path) ? File.ReadAllBytes(Path) : null;
        var temp = Path + ".tmp-" + Guid.NewGuid().ToString("N")[..8];
        File.WriteAllText(temp, text, new UTF8Encoding(bom));
        File.Move(temp, Path, overwrite: true);
        string? written;
        try { written = File.ReadAllText(Path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { written = null; }
        if (written == text) return null;
        if (previous != null) File.WriteAllBytes(Path, previous);
        else File.Delete(Path);
        return "left unchanged: the file did not read back as written, so the previous content was restored";
    }

    protected ConfigChange Write(string text, string message, bool bom = false) =>
        WriteAtomically(text, bom) is { } failed ? new ConfigChange(false, failed) : new ConfigChange(true, message);
}

/// <summary>
/// A JSON file with servers in an object at <see cref="Container"/> (e.g. "mcpServers"). <paramref name="listed"/>
/// reads root-level lists that override an entry's own switch: true off, false forced on, null no say.
/// </summary>
internal sealed class JsonTarget(string path, string[] container, Func<ServerLaunch, JsonObject> entry, Func<JsonObject, string, bool?>? listed = null) : ConfigTarget(path)
{
    public IReadOnlyList<string> Container { get; } = container;
    public Func<ServerLaunch, JsonObject> Entry { get; } = entry;

    private static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>The parsed file (empty when missing), whether it had comments (or trailing commas), its text and BOM, or an error.</summary>
    private (JsonObject? Root, bool HadComments, string? Error, string Text, bool Bom) Load()
    {
        if (!File.Exists(Path)) return (new JsonObject(), false, null, "", false);
        string text;
        bool bom;
        try
        {
            var bytes = File.ReadAllBytes(Path);
            bom = bytes.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]);
            text = File.ReadAllText(Path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (null, false, ex.Message, "", false); }
        if (string.IsNullOrWhiteSpace(text)) return (new JsonObject(), false, null, text, bom);
        try
        {
            if (JsonNode.Parse(text, documentOptions: Lenient) is not JsonObject root) return (null, false, "the file is not a JSON object", text, bom);
            return (root, !IsStrict(text), null, text, bom);
        }
        catch (JsonException ex) { return (null, false, $"invalid JSON ({ex.Message})", text, bom); }
    }

    private static bool IsStrict(string text)
    {
        try { JsonDocument.Parse(text).Dispose(); return true; }
        catch (JsonException) { return false; }
    }

    /// <summary>
    /// The new file text: edited in place when <see cref="JsoncEditor"/> can and the result parses to exactly
    /// <paramref name="expected"/> (and stays strict JSON when it was), else <paramref name="expected"/> reserialized.
    /// </summary>
    private (string Text, bool InPlace) Render(string text, bool hadComments, string name, JsonObject? entry, JsonObject expected)
    {
        if (text.Trim().Length > 0 && JsoncEditor.Edit(text, Container, name, entry) is { } edited)
        {
            try
            {
                if (JsonNode.Parse(edited, documentOptions: Lenient) is JsonObject parsed && JsonNode.DeepEquals(parsed, expected)
                    && (hadComments || IsStrict(edited)))
                    return (edited, true);
            }
            catch (JsonException) { }
        }
        return (expected.ToJsonString(Indented) + Environment.NewLine, false);
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
        var (root, _, _, _, _) = Load();
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
        var (root, _, _, _, _) = Load();
        return root == null ? null : Servers(root, false)?[name] as JsonObject;
    }

    public override RegisteredEntry? Current(string name)
    {
        var (root, _, _, _, _) = Load();
        if (root == null || Servers(root, false)?[name] is not JsonObject entry) return null;
        var parsed = Parse(entry);
        return listed?.Invoke(root, name) is { } off ? parsed with { Disabled = off } : parsed;
    }

    /// <summary>Whether a root-level string array names the server.</summary>
    public static bool Lists(JsonObject root, string key, string name) =>
        root[key] is JsonArray list && list.Any(i => i is JsonValue v && v.TryGetValue<string>(out var s) && s == name);

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
        var (root, hadComments, error, text, _) = Load();
        if (root == null) return new TargetPreview(SetupAction.Blocked, error, null, null, false, null);
        var servers = Servers(root, true)!;
        var existing = servers[name] as JsonObject;
        var before = existing?.DeepClone();
        var next = Merge(existing, launch);
        var action = existing == null ? SetupAction.Add : JsonNode.DeepEquals(existing, next) ? SetupAction.Unchanged : SetupAction.Refresh;
        bool preserved = !hadComments || action == SetupAction.Unchanged;
        if (hadComments && action != SetupAction.Unchanged)
        {
            servers[name] = next.DeepClone();
            preserved = Render(text, hadComments, name, next, root).InPlace;
        }
        return new TargetPreview(action, null, before, next, preserved, BackupPath());
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
        var (root, hadComments, error, text, bom) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, true)!;
        var existing = servers[name] as JsonObject;
        var next = entry(existing);
        if (existing != null && JsonNode.DeepEquals(existing, next)) return new ConfigChange(false, "already registered");
        servers[name] = next.DeepClone();
        var (updated, inPlace) = Render(text, hadComments, name, next, root);
        Backup();
        return Write(updated, hadComments && !inPlace
            ? $"registered (comments were not kept; original saved as {System.IO.Path.GetFileName(Path)}{BackupSuffix})"
            : "registered", bom);
    }

    public override ConfigChange Uninstall(string name)
    {
        var (root, hadComments, error, text, bom) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, false);
        if (servers == null || !servers.Remove(name)) return new ConfigChange(false, "not registered");
        Backup();
        return Write(Render(text, hadComments, name, null, root).Text, "removed", bom);
    }

    public override ConfigChange Rename(string from, string to, ServerLaunch launch)
    {
        var (root, hadComments, error, text, bom) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, false);
        if (servers?[from] is not JsonObject old) return new ConfigChange(false, "not registered");
        bool keepOurs = servers[to] != null;
        if (!keepOurs)
        {
            var entry = Merge(WithMigratedEnv(old), launch);
            servers[to] = entry;
            text = Render(text, hadComments, to, entry, root).Text;
        }
        servers.Remove(from);
        text = Render(text, hadComments, from, null, root).Text;
        Backup();
        return Write(text, keepOurs ? $"removed the {from} entry ({to} is registered)" : $"renamed from {from}", bom);
    }

    /// <summary>Root lists that turn servers off: OMP disabledServers, Claude Code disabledMcpServers (also per project).</summary>
    private static IEnumerable<JsonArray> DisableLists(JsonObject root)
    {
        foreach (var key in new[] { "disabledServers", "disabledMcpServers" })
            if (root[key] is JsonArray list) yield return list;
        if (root["projects"] is JsonObject projects)
            foreach (var (_, project) in projects)
                if (project?["disabledMcpServers"] is JsonArray list) yield return list;
    }

    private static bool Names(JsonArray list, string name) => list.Any(i => i is JsonValue v && v.TryGetValue<string>(out var s) && s == name);

    public override IReadOnlyList<string> DisabledInProjects(string name)
    {
        var (root, _, _, _, _) = Load();
        return root?["projects"] is JsonObject projects
            ? [.. projects.Where(p => p.Value?["disabledMcpServers"] is JsonArray list && Names(list, name)).Select(p => p.Key)]
            : [];
    }

    public override ConfigChange Enable(string name)
    {
        var (root, hadComments, error, text, bom) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, false);
        bool changed = false;
        if (servers?[name] is JsonObject entry)
        {
            if (entry["disabled"] is JsonValue d && d.TryGetValue<bool>(out var off) && off) { entry["disabled"] = false; changed = true; }
            if (entry["enabled"] is JsonValue e && e.TryGetValue<bool>(out var on) && !on) { entry["enabled"] = true; changed = true; }
        }
        foreach (var list in DisableLists(root).ToList())
            foreach (var item in list.Where(i => i is JsonValue v && v.TryGetValue<string>(out var s) && s == name).ToList())
            {
                list.Remove(item);
                changed = true;
            }
        if (!changed) return new ConfigChange(false, "already enabled");
        Backup();
        return Write(Render(text, hadComments, name, servers?[name] as JsonObject, root).Text, "enabled", bom);
    }

    /// <summary>A copy of the entry with its env keys (env or environment) under their current names.</summary>
    public static JsonObject WithMigratedEnv(JsonObject entry)
    {
        var copy = (JsonObject)entry.DeepClone();
        foreach (var key in new[] { "env", "environment" })
            if (copy[key] is JsonObject env)
            {
                var renamed = new JsonObject();
                // A key set under both names keeps the value of the current one.
                foreach (var (name, value) in env)
                    if (ClientCatalog.MigratedEnvKey(name) is var current && (current == name || !env.ContainsKey(current)) && !renamed.ContainsKey(current))
                        renamed[current] = value?.DeepClone();
                copy[key] = renamed;
            }
        return copy;
    }
}

/// <summary>Codex's and Grok Build's config.toml: one [mcp_servers.NAME] table, edited as text so the rest of the file is untouched.</summary>
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
        double? timeout = null, toolTimeout = null;
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
                else if (StartupTimeoutLine().Match(lines[i]) is { Success: true } t
                         && double.TryParse(t.Groups["v"].Value, System.Globalization.CultureInfo.InvariantCulture, out var seconds)) timeout = seconds;
                else if (ToolTimeoutLine().Match(lines[i]) is { Success: true } tt
                         && double.TryParse(tt.Groups["v"].Value, System.Globalization.CultureInfo.InvariantCulture, out var callSeconds)) toolTimeout = callSeconds;
                else if (InlineEnv().Match(lines[i]) is { Success: true } inline)
                    foreach (var item in inline.Groups["items"].Value.Split(','))
                        if (KeyValue().Match(item) is { Success: true } kv) env[kv.Groups["k"].Value.Trim('"')] = Unescape(kv.Groups["v"].Value);
            }
        }
        // A root disabled_mcp_servers list (Grok Build) turns the server off whatever its table says.
        for (int i = 0; i < lines.Count && !AnyHeader().IsMatch(lines[i]); i++)
            if (DisabledList().Match(lines[i]) is { Success: true } list
                && TomlString().Matches(list.Groups["items"].Value).Any(s => (s.Value[0] == '\'' ? s.Groups["v"].Value : Unescape(s.Groups["v"].Value)) == name))
                disabled = true;
        return new RegisteredEntry(command, args, env, disabled, timeout, toolTimeout);
    }

    [GeneratedRegex(@"^\s*tool_timeout_sec\s*=\s*(?<v>[0-9.]+)")]
    private static partial Regex ToolTimeoutLine();

    [GeneratedRegex(@"^\s*disabled_mcp_servers\s*=\s*\[(?<items>[^\]]*)\]")]
    private static partial Regex DisabledList();

    public override ConfigChange Enable(string name)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ConfigChange(false, $"left unchanged: {ex.Message}"); }
        var updated = new List<string>(lines);
        foreach (var (start, end) in Blocks(lines, name).Where(b => !ServerHeader().Match(lines[b.Start]).Groups["sub"].Success).Reverse())
            for (int i = end - 1; i > start; i--)
                if (EnabledFalse().IsMatch(updated[i])) updated.RemoveAt(i);
        for (int i = 0; i < updated.Count && !AnyHeader().IsMatch(updated[i]); i++)
            if (DisabledList().Match(updated[i]) is { Success: true } list)
            {
                var items = TomlString().Matches(list.Groups["items"].Value)
                    .Select(s => s.Value[0] == '\'' ? s.Groups["v"].Value : Unescape(s.Groups["v"].Value)).ToList();
                if (!items.Remove(name)) continue;
                var at = list.Groups["items"];
                updated[i] = updated[i][..at.Index] + string.Join(", ", items.Select(Quote)) + updated[i][(at.Index + at.Length)..];
            }
        if (updated.SequenceEqual(lines)) return new ConfigChange(false, "already enabled");
        Backup();
        return Write(string.Join("\n", updated).TrimEnd('\n') + "\n", "enabled");
    }

    [GeneratedRegex(@"^\s*startup_timeout_sec\s*=\s*(?<v>[0-9.]+)")]
    private static partial Regex StartupTimeoutLine();

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

    [GeneratedRegex(@"(?<=^\s*|[{,]\s*)(?<q>""?)(?<k>[A-Za-z0-9_]+)\k<q>(?=\s*=)")]
    private static partial Regex EnvKey();

    /// <summary>The line with its env keys (a key line or an inline env table) under their current names.</summary>
    private static string MigrateEnvKeys(string line) =>
        EnvKey().Replace(line, m => m.Groups["q"].Value + ClientCatalog.MigratedEnvKey(m.Groups["k"].Value) + m.Groups["q"].Value);

    public override ConfigChange Rename(string from, string to, ServerLaunch launch)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ConfigChange(false, $"left unchanged: {ex.Message}"); }
        var blocks = Blocks(lines, from);
        if (blocks.Count == 0) return new ConfigChange(false, "not registered");
        bool keepOurs = Blocks(lines, to).Count > 0;
        if (keepOurs) lines = Remove(lines, from);
        else
        {
            foreach (var (start, end) in blocks)
            {
                var header = ServerHeader().Match(lines[start]);
                var sub = header.Groups["sub"];
                bool envTable = sub.Success && sub.Value.Trim().TrimStart('.').Trim() == "env";
                var n = header.Groups["n"];
                lines[start] = lines[start][..n.Index] + to + lines[start][(n.Index + n.Length)..];
                for (int i = start + 1; i < end; i++)
                    if (envTable ? KeyValue().IsMatch(lines[i]) : !sub.Success && InlineEnv().IsMatch(lines[i])) lines[i] = MigrateEnvKeys(lines[i]);
            }
            if (Installed(lines, to, launch) is { } text) lines = [.. text.Split('\n')];
            while (lines.Count > 0 && lines[^1].Trim().Length == 0) lines.RemoveAt(lines.Count - 1);
        }
        Backup();
        return Write(string.Join("\n", lines) + "\n", keepOurs ? $"removed the {from} entry ({to} is registered)" : $"renamed from {from}");
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

    public override ConfigChange Enable(string name) => file.Enable(name);
    public override IReadOnlyList<string> DisabledInProjects(string name) => file.DisabledInProjects(name);

    public override ConfigChange Uninstall(string name)
    {
        if (Registered(name) == null) return new ConfigChange(false, "not registered");
        if (Run(["mcp", "remove", "--scope", "user", name]) && Registered(name) == null) return new ConfigChange(true, "removed");
        return file.Uninstall(name);
    }

    public override ConfigChange Rename(string from, string to, ServerLaunch launch)
    {
        if (file.Existing(from) is not { } old) return new ConfigChange(false, "not registered");
        if (file.Existing(to) != null)
        {
            var removed = Uninstall(from);
            return removed.Changed ? new ConfigChange(true, $"removed the {from} entry ({to} is registered)") : removed;
        }
        var entry = file.Merge(JsonTarget.WithMigratedEnv(old), launch);
        if (Run(["mcp", "add-json", "--scope", "user", to, entry.ToJsonString()]) && Registered(to) is { } now && now.Equals(launch.Command, StringComparison.OrdinalIgnoreCase)
            && Run(["mcp", "remove", "--scope", "user", from]) && Registered(from) == null)
            return new ConfigChange(true, $"renamed from {from}");
        // Whatever the CLI managed, the file ends with ours under the new name and nothing under the old one.
        var put = file.Put(to, _ => entry);
        var dropped = file.Uninstall(from);
        return put.Changed || dropped.Changed ? new ConfigChange(true, $"renamed from {from}") : put;
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

/// <summary>A client whose file location cannot be worked out (an invalid override): every change is refused with the reason.</summary>
internal sealed class InvalidTarget(string path, string reason) : ConfigTarget(path)
{
    public override string? Registered(string name) => null;
    public override RegisteredEntry? Current(string name) => null;
    public override TargetPreview Preview(string name, ServerLaunch launch) => new(SetupAction.Blocked, reason, null, null, false, null);
    public override ConfigChange Install(string name, ServerLaunch launch) => new(false, $"left unchanged: {reason}");
    public override ConfigChange Uninstall(string name) => new(false, "not registered");
    public override ConfigChange Rename(string from, string to, ServerLaunch launch) => new(false, $"left unchanged: {reason}");
}
