using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Setup;

/// <summary>A YAML file edited as text, changing only the server's lines; a file it cannot place the entry in is left unchanged.</summary>
internal abstract partial class YamlTarget(string path) : ConfigTarget(path)
{
    /// <summary>The lines uninstall removes [Start, End) and the command/args/env mapping [MapStart, MapEnd); MapStart -1 when absent.</summary>
    protected readonly record struct Block(int Start, int End, int MapStart, int MapEnd, int MapIndent);

    /// <summary>The server's entry, or null when the file has none.</summary>
    protected abstract Block? Find(List<string> lines, string name);
    /// <summary>Why the entry cannot be added to this file, or null when it can.</summary>
    protected abstract string? Refusal(List<string> lines);
    /// <summary>The lines with a new entry; <paramref name="body"/> holds its mapping keys without indent.</summary>
    protected abstract List<string> Appended(List<string> lines, string name, List<string> body, bool disabled);
    protected abstract List<string> Removed(List<string> lines, Block block);
    protected abstract bool IsDisabled(List<string> lines, Block block);
    /// <summary>The lines without the entry's off switch; unchanged when it has none.</summary>
    protected abstract List<string> Enabled(List<string> lines, Block block);

    private List<string> Lines() => File.Exists(Path) ? [.. File.ReadAllText(Path).Replace("\r\n", "\n").Split('\n')] : [];

    private static string Text(List<string> lines)
    {
        var text = string.Join("\n", lines).TrimEnd('\n');
        return text.Length == 0 ? "" : text + "\n";
    }

    protected static int Indent(string line) => line.Length - line.TrimStart(' ').Length;

    /// <summary>Blank or a comment: lines that never end a block.</summary>
    protected static bool Skipped(string line) => line.Trim() is var t && (t.Length == 0 || t[0] == '#');

    /// <summary>The index after the last line of a block whose lines are indented more than <paramref name="indent"/>, without its trailing blank and comment lines.</summary>
    protected static int BlockEnd(List<string> lines, int from, int indent)
    {
        int end = from;
        while (end < lines.Count && (Skipped(lines[end]) || Indent(lines[end]) > indent)) end++;
        while (end > from && Skipped(lines[end - 1])) end--;
        return end;
    }

    /// <summary>The indent of the first content line in [from, end), or <paramref name="fallback"/>.</summary>
    protected static int FirstIndent(List<string> lines, int from, int end, int fallback)
    {
        for (int i = from; i < end; i++)
            if (!Skipped(lines[i])) return Indent(lines[i]);
        return fallback;
    }

    private static readonly JsonSerializerOptions Relaxed = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>A double-quoted YAML scalar (JSON string syntax is a subset).</summary>
    protected static string Quote(string s) => JsonSerializer.Serialize(s, Relaxed);

    protected static List<string> Body(string command, IEnumerable<string> args, IReadOnlyDictionary<string, string>? env)
    {
        List<string> body = [$"command: {Quote(command)}", $"args: [{string.Join(", ", args.Select(Quote))}]"];
        if (env is { Count: > 0 }) body.AddRange(["env:", .. env.Select(e => $"  {e.Key}: {Quote(e.Value)}")]);
        return body;
    }

    protected static IEnumerable<string> Indented(IEnumerable<string> body, int indent) => body.Select(l => new string(' ', indent) + l);

    [GeneratedRegex(@"^(?<i> *)(?<k>[A-Za-z0-9_.-]+|""[^""]*""|'[^']*')\s*:(?:\s+(?<v>.*?))?\s*$")]
    protected static partial Regex KeyLine();

    /// <summary>A key line's key without quotes and its value text (empty for a nested block), or null.</summary>
    protected static (string Key, string Value)? Key(string line) =>
        KeyLine().Match(line) is { Success: true } m ? (m.Groups["k"].Value.Trim('"', '\''), m.Groups["v"].Value) : null;

    /// <summary>A scalar's value: quoted forms unescaped, a plain one without its comment; null for a comment-only value.</summary>
    protected static string? Scalar(string raw)
    {
        raw = raw.Trim();
        if (raw.Length == 0 || raw[0] == '#') return null;
        int pos = 0;
        if (raw[0] is '"' or '\'') return Quoted(raw, ref pos);
        int hash = raw.IndexOf(" #", StringComparison.Ordinal);
        return (hash >= 0 ? raw[..hash] : raw).Trim();
    }

    private static string Quoted(string s, ref int pos)
    {
        char q = s[pos];
        int start = pos++;
        if (q == '\'')
        {
            var sb = new System.Text.StringBuilder();
            while (pos < s.Length)
            {
                if (s[pos] == '\'' && pos + 1 < s.Length && s[pos + 1] == '\'') { sb.Append('\''); pos += 2; continue; }
                if (s[pos] == '\'') { pos++; return sb.ToString(); }
                sb.Append(s[pos++]);
            }
            return sb.ToString();
        }
        while (pos < s.Length && s[pos] != '"') pos += s[pos] == '\\' ? 2 : 1;
        pos = Math.Min(pos + 1, s.Length);
        var span = s[start..pos];
        try { return JsonSerializer.Deserialize<string>(span) ?? ""; }
        catch (JsonException) { return span.Trim('"').Replace("\\\\", "\\").Replace("\\\"", "\""); }
    }

    /// <summary>A one-line flow list of scalars, or null for anything else (left untouched).</summary>
    protected static List<string>? FlowList(string raw)
    {
        raw = raw.Trim();
        if (raw.Length == 0 || raw[0] != '[') return null;
        var items = new List<string>();
        int pos = 1;
        void Spaces() { while (pos < raw.Length && raw[pos] == ' ') pos++; }
        Spaces();
        if (pos < raw.Length && raw[pos] == ']') { pos++; return Rest() ? items : null; }
        while (pos < raw.Length)
        {
            Spaces();
            if (pos >= raw.Length) return null;
            if (raw[pos] is '"' or '\'') items.Add(Quoted(raw, ref pos));
            else
            {
                int start = pos;
                while (pos < raw.Length && raw[pos] is not (',' or ']')) pos++;
                items.Add(raw[start..pos].Trim());
            }
            Spaces();
            if (pos >= raw.Length) return null;
            if (raw[pos] == ']') { pos++; return Rest() ? items : null; }
            if (raw[pos] != ',') return null;
            pos++;
        }
        return null;
        bool Rest() => raw[pos..].Trim() is var rest && (rest.Length == 0 || rest[0] == '#');
    }

    /// <summary>Where the mapping's command and args are: line indices (-1 when absent) and the args value when it is a list read here.</summary>
    private readonly record struct Fields(int Command, string? CommandValue, int ArgsStart, int ArgsEnd, List<string>? Args,
        Dictionary<string, string> Env);

    private static Fields Scan(List<string> lines, Block b)
    {
        int command = -1, argsStart = -1, argsEnd = -1;
        string? commandValue = null;
        List<string>? args = null;
        var env = new Dictionary<string, string>(StringComparer.Ordinal);
        if (b.MapStart < 0) return new(command, commandValue, argsStart, argsEnd, args, env);
        for (int i = b.MapStart; i < b.MapEnd; i++)
        {
            if (Skipped(lines[i]) || Indent(lines[i]) != b.MapIndent || Key(lines[i]) is not (string key, string value)) continue;
            int nested = BlockEnd(lines, i + 1, b.MapIndent);
            if (key == "command" && command < 0) (command, commandValue) = (i, Scalar(value) ?? "");
            else if (key == "args" && argsStart < 0)
            {
                (argsStart, argsEnd) = (i, Math.Max(i + 1, nested));
                if (Scalar(value) is null)
                {
                    // A block list: one "- item" per line.
                    args = [];
                    for (int j = i + 1; j < nested && args != null; j++)
                        if (!Skipped(lines[j])) args = lines[j].TrimStart() is ['-', ' ', .. var item] ? [.. args, Scalar(item) ?? ""] : null;
                }
                else args = FlowList(value);
            }
            else if (key == "env")
            {
                for (int j = i + 1; j < nested; j++)
                    if (!Skipped(lines[j]) && Key(lines[j]) is (string k, string v)) env[k] = Scalar(v) ?? "";
                if (Scalar(value) is ['{', ..] inline)
                    foreach (var pair in inline.Trim('{', '}').Split(','))
                        if (pair.Split(':', 2) is [var k, var v]) env[k.Trim().Trim('"', '\'')] = Scalar(v) ?? "";
            }
        }
        return new(command, commandValue, argsStart, argsEnd, args, env);
    }

    private RegisteredEntry? Parse(List<string> lines, string name)
    {
        if (Find(lines, name) is not { } b) return null;
        var f = Scan(lines, b);
        return new RegisteredEntry(f.CommandValue ?? "", f.Args ?? [], f.Env, IsDisabled(lines, b));
    }

    public override string? Registered(string name) => Current(name) is { } entry ? entry.Command : null;

    public override RegisteredEntry? Current(string name)
    {
        try { return Parse(Lines(), name); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The lines with the server registered, null when it already is, or the reason it cannot be.</summary>
    private (List<string>? Lines, string? Refused) Installed(List<string> lines, string name, ServerLaunch launch)
    {
        if (Find(lines, name) is not { } b)
            return Refusal(lines) is { } refused ? (null, refused) : (Appended(lines, name, Body(launch.Command, launch.WithSwitches(launch.Args), null), false), null);
        if (b.MapStart < 0) return (null, "the entry has no mapping for its command");

        // An existing entry keeps its other keys, its env and the user's arguments; only the command is replaced.
        var f = Scan(lines, b);
        var updated = new List<string>(lines);
        var pad = new string(' ', b.MapIndent);
        if (f.Args is { } user && MergeArgs(user, launch) is var merged && !merged.SequenceEqual(user))
        {
            updated.RemoveRange(f.ArgsStart, f.ArgsEnd - f.ArgsStart);
            updated.Insert(f.ArgsStart, pad + $"args: [{string.Join(", ", merged.Select(Quote))}]");
        }
        if (f.Command >= 0 && f.CommandValue != launch.Command) updated[f.Command] = pad + $"command: {Quote(launch.Command)}";
        var missing = new List<string>();
        if (f.Command < 0) missing.Add(pad + $"command: {Quote(launch.Command)}");
        if (f.ArgsStart < 0) missing.Add(pad + $"args: [{string.Join(", ", launch.WithSwitches(launch.Args).Select(Quote))}]");
        updated.InsertRange(b.MapStart, missing);
        return updated.SequenceEqual(lines) ? (null, null) : (updated, null);
    }

    private ConfigChange Edit(Func<List<string>, ConfigChange?> change)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ConfigChange(false, $"left unchanged: {ex.Message}"); }
        return change(lines) ?? new ConfigChange(false, "unchanged");
    }

    public override ConfigChange Install(string name, ServerLaunch launch) => Edit(lines =>
    {
        var (text, refused) = Installed(lines, name, launch);
        if (refused != null) return new ConfigChange(false, $"left unchanged: {refused}");
        if (text == null) return new ConfigChange(false, "already registered");
        Backup();
        return Write(Text(text), "registered");
    });

    public override TargetPreview Preview(string name, ServerLaunch launch)
    {
        List<string> lines;
        try { lines = Lines(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new TargetPreview(SetupAction.Blocked, ex.Message, null, null, false, null); }
        var before = Parse(lines, name);
        var (text, refused) = Installed([.. lines], name, launch);
        if (refused != null) return new TargetPreview(SetupAction.Blocked, refused, before is null ? null : ToJson(before), null, true, null);
        var after = text == null ? before : Parse(text, name);
        var action = before == null ? SetupAction.Add : text == null ? SetupAction.Unchanged : SetupAction.Refresh;
        return new TargetPreview(action, null, before is null ? null : ToJson(before), after is null ? null : ToJson(after), true, BackupPath());
    }

    public override ConfigChange Uninstall(string name) => Edit(lines =>
    {
        if (Find(lines, name) is not { } b) return new ConfigChange(false, "not registered");
        Backup();
        return Write(Text(Removed(lines, b)), "removed");
    });

    public override ConfigChange Enable(string name) => Edit(lines =>
    {
        if (Find(lines, name) is not { } b) return new ConfigChange(false, "not registered");
        var updated = Enabled(lines, b);
        if (updated.SequenceEqual(lines)) return new ConfigChange(false, "already enabled");
        Backup();
        return Write(Text(updated), "enabled");
    });

    public override ConfigChange Rename(string from, string to, ServerLaunch launch) => Edit(lines =>
    {
        if (Find(lines, from) is not { } b) return new ConfigChange(false, "not registered");
        bool keepOurs = Find(lines, to) is not null;
        var entry = Parse(lines, from)!;
        var updated = Removed(lines, b);
        if (!keepOurs)
        {
            var env = entry.Env.ToDictionary(e => ClientCatalog.MigratedEnvKey(e.Key), e => e.Value, StringComparer.Ordinal);
            updated = Appended(updated, to, Body(launch.Command, MergeArgs(entry.Args, launch), env), entry.Disabled);
        }
        Backup();
        return Write(Text(updated), keepOurs ? $"removed the {from} entry ({to} is registered)" : $"renamed from {from}");
    });
}

/// <summary>Hermes' config.yaml: one entry under the top-level mcp_servers mapping, off when it says enabled: false.</summary>
internal sealed partial class HermesYamlTarget(string path) : YamlTarget(path)
{
    [GeneratedRegex(@"^mcp_servers\s*:\s*(?<v>[^#\s][^#]*?)?\s*(?<c>#.*)?$")]
    private static partial Regex Header();

    [GeneratedRegex(@"^\s*enabled\s*:\s*(false|no|off)\s*(#.*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex EnabledFalse();

    private static int HeaderAt(List<string> lines) => lines.FindIndex(l => Header().IsMatch(l));

    protected override string? Refusal(List<string> lines) =>
        HeaderAt(lines) is >= 0 and var h && Header().Match(lines[h]).Groups["v"] is { Success: true } v && v.Value.Trim() != "{}"
            ? "mcp_servers is not a block mapping" : null;

    protected override Block? Find(List<string> lines, string name)
    {
        int h = HeaderAt(lines);
        if (h < 0 || Refusal(lines) != null) return null;
        int region = BlockEnd(lines, h + 1, 0);
        int child = FirstIndent(lines, h + 1, region, 2);
        for (int i = h + 1; i < region; i++)
            if (!Skipped(lines[i]) && Indent(lines[i]) == child && Key(lines[i]) is (string key, string value) && key == name && Scalar(value) is null)
            {
                int end = BlockEnd(lines, i + 1, child);
                return new Block(i, end, i + 1, end, FirstIndent(lines, i + 1, end, child + 2));
            }
        return null;
    }

    protected override List<string> Appended(List<string> lines, string name, List<string> body, bool disabled)
    {
        var updated = new List<string>(lines);
        if (disabled) body = [.. body, "enabled: false"];
        int h = HeaderAt(updated);
        if (h < 0)
        {
            while (updated.Count > 0 && updated[^1].Trim().Length == 0) updated.RemoveAt(updated.Count - 1);
            if (updated.Count > 0) updated.Add("");
            updated.AddRange(["mcp_servers:", $"  {name}:", .. Indented(body, 4)]);
            return updated;
        }
        updated[h] = "mcp_servers:" + (Header().Match(updated[h]).Groups["c"] is { Success: true } c ? " " + c.Value : "");
        int region = BlockEnd(updated, h + 1, 0);
        int child = FirstIndent(updated, h + 1, region, 2);
        updated.InsertRange(region, [new string(' ', child) + name + ":", .. Indented(body, child + 2)]);
        return updated;
    }

    protected override List<string> Removed(List<string> lines, Block block)
    {
        var updated = new List<string>(lines);
        updated.RemoveRange(block.Start, block.End - block.Start);
        // An emptied mcp_servers would read as null; drop the header with its last entry.
        int h = HeaderAt(updated);
        if (h >= 0 && BlockEnd(updated, h + 1, 0) == h + 1) updated.RemoveAt(h);
        return updated;
    }

    protected override bool IsDisabled(List<string> lines, Block block) =>
        Enumerable.Range(block.MapStart, block.MapEnd - block.MapStart).Any(i => Indent(lines[i]) == block.MapIndent && EnabledFalse().IsMatch(lines[i]));

    protected override List<string> Enabled(List<string> lines, Block block)
    {
        var updated = new List<string>(lines);
        for (int i = block.MapEnd - 1; i >= block.MapStart; i--)
            if (Indent(updated[i]) == block.MapIndent && EnabledFalse().IsMatch(updated[i])) updated.RemoveAt(i);
        return updated;
    }
}

/// <summary>DeepSeek Harness's cordis.patch.yml: an insert patch with one dsh-mcp-client row (id mcp-NAME); disabled: true turns it off.</summary>
internal sealed partial class HarnessPatchTarget(string path) : YamlTarget(path)
{
    public const string Plugin = "@deepseek-ai/dsh-mcp-client";

    [GeneratedRegex(@"^(?<d> *)- +(?<k>id) *: *(?<q>['""]?)(?<n>[A-Za-z0-9_-]+)\k<q> *(#.*)?$")]
    private static partial Regex RowLine();

    [GeneratedRegex(@"^(?<d> *)- +insert *: *(#.*)?$")]
    private static partial Regex InsertLine();

    [GeneratedRegex(@"^\s*disabled\s*:\s*true\s*(#.*)?$")]
    private static partial Regex DisabledTrue();

    private static string RowId(string name) => "mcp-" + name;

    protected override string? Refusal(List<string> lines) =>
        lines.FirstOrDefault(l => !Skipped(l)) is { } first && !first.StartsWith('-') ? "the patch file is not a YAML sequence" : null;

    protected override Block? Find(List<string> lines, string name)
    {
        for (int r = 0; r < lines.Count; r++)
        {
            if (RowLine().Match(lines[r]) is not { Success: true } m || m.Groups["n"].Value != RowId(name)) continue;
            int keys = m.Groups["k"].Index;
            int end = BlockEnd(lines, r + 1, keys - 1);
            for (int i = r + 1; i < end; i++)
                if (Indent(lines[i]) == keys && Key(lines[i]) is ("config", var value) && Scalar(value) is null)
                {
                    int mapEnd = BlockEnd(lines, i + 1, keys);
                    return new Block(r, end, i + 1, mapEnd, FirstIndent(lines, i + 1, mapEnd, keys + 2));
                }
            return new Block(r, end, -1, -1, 0);
        }
        return null;
    }

    protected override List<string> Appended(List<string> lines, string name, List<string> body, bool disabled)
    {
        var updated = new List<string>(lines);
        while (updated.Count > 0 && updated[^1].Trim().Length == 0) updated.RemoveAt(updated.Count - 1);
        if (updated.Count > 0) updated.Add("");
        updated.AddRange(["- insert:", $"    - id: {RowId(name)}", $"      name: '{Plugin}'"]);
        if (disabled) updated.Add("      disabled: true");
        updated.AddRange(["      config:", $"        serverName: {name}", "        transport: stdio", .. Indented(body, 8)]);
        return updated;
    }

    protected override List<string> Removed(List<string> lines, Block block)
    {
        var updated = new List<string>(lines);
        int dash = Indent(lines[block.Start]);
        updated.RemoveRange(block.Start, block.End - block.Start);
        // An insert patch left with no rows is dropped with its row.
        for (int i = block.Start - 1; i >= 0; i--)
        {
            if (Skipped(updated[i]) || Indent(updated[i]) >= dash) continue;
            if (InsertLine().Match(updated[i]) is { Success: true } m && BlockEnd(updated, i + 1, m.Groups["d"].Length) == i + 1)
                updated.RemoveAt(i);
            break;
        }
        return updated;
    }

    private static int KeyIndent(List<string> lines, Block block) => RowLine().Match(lines[block.Start]).Groups["k"].Index;

    protected override bool IsDisabled(List<string> lines, Block block)
    {
        int keys = KeyIndent(lines, block);
        return Enumerable.Range(block.Start + 1, block.End - block.Start - 1).Any(i => Indent(lines[i]) == keys && DisabledTrue().IsMatch(lines[i]));
    }

    protected override List<string> Enabled(List<string> lines, Block block)
    {
        int keys = KeyIndent(lines, block);
        var updated = new List<string>(lines);
        for (int i = block.End - 1; i > block.Start; i--)
            if (Indent(updated[i]) == keys && DisabledTrue().IsMatch(updated[i])) updated.RemoveAt(i);
        return updated;
    }
}
