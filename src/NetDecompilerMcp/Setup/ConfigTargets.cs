using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace NetDecompilerMcp.Setup;

/// <summary>How the server is started: an executable and its arguments.</summary>
internal sealed record ServerLaunch(string Command, IReadOnlyList<string> Args);

/// <summary>The outcome of changing one configuration file.</summary>
internal sealed record ConfigChange(bool Changed, string Message);

/// <summary>A configuration file that lists MCP servers.</summary>
internal abstract class ConfigTarget(string path)
{
    public string Path { get; } = path;

    /// <summary>The launch command registered under the name, or null when absent or unreadable.</summary>
    public abstract string? Registered(string name);
    public abstract ConfigChange Install(string name, ServerLaunch launch);
    public abstract ConfigChange Uninstall(string name);

    protected const string BackupSuffix = ".netdecompiler.bak";

    /// <summary>Keeps the first pre-install copy of a file next to it.</summary>
    protected void Backup()
    {
        if (File.Exists(Path) && !File.Exists(Path + BackupSuffix)) File.Copy(Path, Path + BackupSuffix);
    }

    /// <summary>Writes through a temporary file in the same folder so a crash never leaves a partial file.</summary>
    protected void WriteAtomically(string text)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var temp = Path + ".tmp-" + Guid.NewGuid().ToString("N")[..8];
        File.WriteAllText(temp, text, new UTF8Encoding(false));
        File.Move(temp, Path, overwrite: true);
    }
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

    public override ConfigChange Install(string name, ServerLaunch launch)
    {
        var (root, hadComments, error) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, true)!;
        var fresh = Entry(launch);
        if (servers[name] is JsonObject existing && JsonNode.DeepEquals(existing, fresh)) return new ConfigChange(false, "already registered");
        servers[name] = fresh;
        Backup();
        WriteAtomically(root.ToJsonString(Indented) + Environment.NewLine);
        return new ConfigChange(true, hadComments ? $"registered (comments were not kept; original saved as {System.IO.Path.GetFileName(Path)}{BackupSuffix})" : "registered");
    }

    public override ConfigChange Uninstall(string name)
    {
        var (root, _, error) = Load();
        if (root == null) return new ConfigChange(false, $"left unchanged: {error}");
        var servers = Servers(root, false);
        if (servers == null || !servers.Remove(name)) return new ConfigChange(false, "not registered");
        Backup();
        WriteAtomically(root.ToJsonString(Indented) + Environment.NewLine);
        return new ConfigChange(true, "removed");
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
        var block = new List<string>
        {
            $"[mcp_servers.{name}]",
            $"command = {Quote(launch.Command)}",
            $"args = [{string.Join(", ", launch.Args.Select(Quote))}]",
        };
        var current = Blocks(lines, name);
        if (current.Count == 1 && lines.Skip(current[0].Start).Take(current[0].End - current[0].Start).Where(l => l.Trim().Length > 0).SequenceEqual(block))
            return new ConfigChange(false, "already registered");
        lines = Remove(lines, name);
        if (lines.Count > 0) lines.Add("");
        lines.AddRange(block);
        Backup();
        WriteAtomically(string.Join("\n", lines) + "\n");
        return new ConfigChange(true, "registered");
    }

    public override ConfigChange Uninstall(string name)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ConfigChange(false, $"left unchanged: {ex.Message}"); }
        if (Blocks(lines, name).Count == 0) return new ConfigChange(false, "not registered");
        Backup();
        WriteAtomically(string.Join("\n", Remove(lines, name)) + "\n");
        return new ConfigChange(true, "removed");
    }
}
