using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Core.Registry;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=registry: a hive file's counts, cells recovered from free space, Run
/// dialog commands, and a page of one key's subkeys and values (table= path,
/// root by default; offset=, limit=).
/// </summary>
internal sealed class RegistryFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 50;

    public sealed record SubkeyRow(string Name, DateTime? LastWritten, int Subkeys, int Values, string? Class);

    public sealed record ValueRow(string Name, string Type, long Size, object Data);

    /// <summary>
    /// A Run dialog command: its RunMRU value name, the command as typed, and
    /// its plain text with the layers that reach it (null when nothing peels).
    /// </summary>
    public sealed record RunCommand(string Name, string Command, string? Plain, IReadOnlyList<string>? Via);

    public sealed record RecoveredKey(string Path, DateTime? LastWritten, int Values);

    public sealed record Facts(RegistryHive.BaseBlock Header, long Keys, long Values, string Path, DateTime? LastWritten, string? Class,
        int Subkeys, int KeyValues, IReadOnlyList<SubkeyRow> SubkeyPage, IReadOnlyList<ValueRow> ValuePage, long Offset, long? Next,
        int RecoveredKeys, int RecoveredValues, IReadOnlyList<RecoveredKey> RecoveredKeyList, IReadOnlyList<ValueRow> RecoveredValueList, IReadOnlyList<string> Notes,
        IReadOnlyList<RunCommand>? RunCommands = null);

    public string Name => "registry";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!RegistryHive.Looks(file.Head)) return null;
        RegistryHive hive;
        try { hive = RegistryHive.Read(file.Bytes); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{System.IO.Path.GetFileName(file.Path)}: not a readable registry hive: {ex.Message}"); }
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset);
        var path = file.Options.View == Name ? file.Options.Table?.Trim() ?? "" : "";
        long keys = 0, values = 0;
        var paths = new Dictionary<int, string>();
        foreach (var (p, k) in hive.Walk(ct))
        {
            keys++;
            values += k.ValueCount;
            paths[k.Cell] = p;
        }
        var notes = new List<string>();
        var key = hive.Find(path);
        if (key == null)
        {
            notes.Add($"no key '{path}'; the root is shown");
            key = hive.Root;
            path = "";
        }
        var subkeys = hive.Subkeys(key);
        var keyValues = hive.Values(key);
        // One page across the key's subkeys, then its values.
        var subkeyPage = subkeys.Skip((int)Math.Min(offset, int.MaxValue)).Take(limit).Select(Row).ToList();
        long valueStart = Math.Max(0, offset - subkeys.Count);
        var valuePage = keyValues.Skip((int)Math.Min(valueStart, int.MaxValue)).Take(limit - subkeyPage.Count).Select(Row).ToList();
        long shown = offset + subkeyPage.Count + valuePage.Count;
        long? next = shown < subkeys.Count + keyValues.Count ? shown : null;
        if (next != null) notes.Add($"offset={next} lists the next subkeys and values");
        var (lostKeys, lostValues) = hive.Recover(ct);
        var recoveredKeys = lostKeys.Take(MaxRecovered).Select(k => new RecoveredKey(
            paths.TryGetValue(k.Parent, out var parent) ? (parent.Length == 0 ? k.Name : parent + "\\" + k.Name) : "?\\" + k.Name, k.LastWritten, k.ValueCount)).ToList();
        if (lostKeys.Count > MaxRecovered || lostValues.Count > MaxRecovered) notes.Add($"recovered keys and values: the first {MaxRecovered}");
        if (lostKeys.Count > 0) notes.Add("recovered cells were freed; space reused since may have overwritten part of them");
        var run = RunCommands(hive, ct);
        notes.AddRange(hive.Notes);
        var h = hive.Header;
        var highlights = new List<string>
        {
            $"Registry hive{(h.FileName.Length > 0 ? $" ({h.FileName})" : "")}, format {h.Major}.{h.Minor}: {keys:N0} key(s), {values:N0} value(s)" +
            (h.LastWritten is { } t ? $", last written {t:yyyy-MM-dd HH:mm:ss} UTC" : "") + ".",
        };
        if (run.Count > 0)
        {
            var peeled = run.Where(r => r.Plain != null).ToList();
            highlights.Add($"Run dialog history (RunMRU): {run.Count} command(s), most recent first: {string.Join("; ", run.Take(3).Select(r => ShellLinkRules.Clip(r.Command)))}{(run.Count > 3 ? "; ..." : "")}.");
            highlights.AddRange(peeled.Take(3).Select(r => $"RunMRU {r.Name} reads as: {ShellLinkRules.Clip(r.Plain!)}."));
        }
        if (h.Dirty) highlights.Add("The hive is dirty: its transaction logs may hold newer data, not applied.");
        if (lostKeys.Count + lostValues.Count > 0) highlights.Add($"{lostKeys.Count:N0} deleted key(s) and {lostValues.Count:N0} deleted value(s) recovered from free cells.");
        return new FileView(new Facts(h, keys, values, path.Length == 0 ? key.Name : path, key.LastWritten, key.Class, subkeys.Count, keyValues.Count,
            subkeyPage, valuePage, offset, next, lostKeys.Count, lostValues.Count, recoveredKeys, [.. lostValues.Take(MaxRecovered).Select(Row)], notes,
            run.Count > 0 ? run : null), highlights);
    }

    private const string RunMru = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";

    /// <summary>
    /// The RunMRU commands in MRUList order, each read as a command line;
    /// commands MRUList does not name follow. Empty when the key is absent.
    /// </summary>
    private static List<RunCommand> RunCommands(RegistryHive hive, CancellationToken ct)
    {
        if (hive.Find(RunMru) is not { } key) return [];
        var values = hive.Values(key).Where(v => v.Type is 1 or 2).ToDictionary(v => v.Name, v => (string)RegistryHive.Render(v.Type, v.Data), StringComparer.OrdinalIgnoreCase);
        var order = values.GetValueOrDefault("MRUList", "").Select(c => c.ToString()).Where(values.ContainsKey).ToList();
        order.AddRange(values.Keys.Where(n => n.Length == 1 && char.IsAsciiLetter(n[0]) && !order.Contains(n, StringComparer.OrdinalIgnoreCase)).Order(StringComparer.Ordinal));
        var list = new List<RunCommand>();
        foreach (var name in order.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // Explorer ends each command with "\1".
            var command = values[name].EndsWith(@"\1", StringComparison.Ordinal) ? values[name][..^2] : values[name];
            var reading = ScriptReader.Read(command, "cmd", ct, milliseconds: ScriptBudget.BlockMilliseconds);
            bool peeled = reading.Layers.Count > 0 && reading.Plain.Trim() != command.Trim();
            list.Add(new RunCommand(name, command, peeled ? reading.Plain.Trim() : null, peeled ? [.. reading.Layers.Select(l => l.Via)] : null));
        }
        return list;
    }

    private static SubkeyRow Row(RegistryHive.Key k) => new(k.Name, k.LastWritten, k.SubkeyCount, k.ValueCount, k.Class);

    private static ValueRow Row(RegistryHive.Value v) => new(v.Name.Length == 0 ? "(Default)" : v.Name, RegistryHive.TypeName(v.Type), v.DeclaredSize, RegistryHive.Render(v.Type, v.Data));
}
