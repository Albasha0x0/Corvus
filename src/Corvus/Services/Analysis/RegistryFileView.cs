using Corvus.Core;
using Corvus.Core.Registry;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=registry: a registry hive file (NTUSER.DAT, SOFTWARE, SYSTEM, settings.dat, Amcache.hve) read without the
/// registry API: base block facts, key and value counts, the keys and values recovered from free cells, then one key
/// (table= names its path; the root by default) with a page of its subkeys and values (offset=, limit=).
/// </summary>
internal sealed class RegistryFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 50;

    public sealed record SubkeyRow(string Name, DateTime? LastWritten, int Subkeys, int Values, string? Class);

    public sealed record ValueRow(string Name, string Type, long Size, object Data);

    public sealed record RecoveredKey(string Path, DateTime? LastWritten, int Values);

    public sealed record Facts(RegistryHive.BaseBlock Header, long Keys, long Values, string Path, DateTime? LastWritten, string? Class,
        int Subkeys, int KeyValues, IReadOnlyList<SubkeyRow> SubkeyPage, IReadOnlyList<ValueRow> ValuePage, long Offset, long? Next,
        int RecoveredKeys, int RecoveredValues, IReadOnlyList<RecoveredKey> RecoveredKeyList, IReadOnlyList<ValueRow> RecoveredValueList, IReadOnlyList<string> Notes);

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
        notes.AddRange(hive.Notes);
        var h = hive.Header;
        var highlights = new List<string>
        {
            $"Registry hive{(h.FileName.Length > 0 ? $" ({h.FileName})" : "")}, format {h.Major}.{h.Minor}: {keys:N0} key(s), {values:N0} value(s)" +
            (h.LastWritten is { } t ? $", last written {t:yyyy-MM-dd HH:mm:ss} UTC" : "") + ".",
        };
        if (h.Dirty) highlights.Add("The hive is dirty: its transaction logs may hold newer data, not applied.");
        if (lostKeys.Count + lostValues.Count > 0) highlights.Add($"{lostKeys.Count:N0} deleted key(s) and {lostValues.Count:N0} deleted value(s) recovered from free cells.");
        return new FileView(new Facts(h, keys, values, path.Length == 0 ? key.Name : path, key.LastWritten, key.Class, subkeys.Count, keyValues.Count,
            subkeyPage, valuePage, offset, next, lostKeys.Count, lostValues.Count, recoveredKeys, [.. lostValues.Take(MaxRecovered).Select(Row)], notes), highlights);
    }

    private static SubkeyRow Row(RegistryHive.Key k) => new(k.Name, k.LastWritten, k.SubkeyCount, k.ValueCount, k.Class);

    private static ValueRow Row(RegistryHive.Value v) => new(v.Name.Length == 0 ? "(Default)" : v.Name, RegistryHive.TypeName(v.Type), v.DeclaredSize, RegistryHive.Render(v.Type, v.Data));
}
