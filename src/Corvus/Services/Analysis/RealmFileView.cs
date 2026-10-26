using Corvus.Core;
using Corvus.Core.Databases;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=realm: a Realm file: file format, the tables of the current commit with their columns and object counts, a
/// page of one table's objects (table= names it; offset=, limit=), and when asked for, the objects the previous commit
/// and free space still hold that the current commit deleted or changed.
/// </summary>
internal sealed class RealmFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 200, MaxText = 512;

    public sealed record ColumnEntry(string Name, string Type);

    public sealed record TableEntry(string Name, bool Embedded, long Objects, IReadOnlyList<ColumnEntry> Columns);

    /// <summary>An object: its key (null when unknown), values in column order as text, and for a recovered one its table (null when unknown) and where it was found.</summary>
    public sealed record Entry(long? Key, IReadOnlyList<string> Values, string? Table = null, string? Source = null);

    public sealed record Facts(int FileFormat, long Length, IReadOnlyList<TableEntry> Tables, string Table, IReadOnlyList<string> Columns,
        long Offset, long? Next, IReadOnlyList<Entry> Objects, IReadOnlyList<Entry>? Recovered, IReadOnlyList<string> Notes);

    public string Name => "realm";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Realm.Looks(file.Head)) return null;
        Realm realm;
        try { realm = new Realm(file.OpenRead()); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable Realm file: {ex.Message}"); }
        using (realm)
        {
            bool asked = file.Options.Wants(Name);
            string? wanted = asked ? file.Options.Table : null;
            var table = wanted == null
                ? realm.Tables.FirstOrDefault(t => t.Name.StartsWith("class_", StringComparison.Ordinal)) ?? realm.Tables.FirstOrDefault()
                : realm.Tables.FirstOrDefault(t => t.Name == wanted || t.Name == "class_" + wanted);
            if (table == null && wanted != null)
                throw new ToolError(ErrorCode.InvalidArgument, $"no table named '{wanted}'; tables: {string.Join(", ", realm.Tables.Select(t => Display(t.Name)))}", "pass table= with one of them, or none for the first class");
            int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
            long offset = Math.Max(0, file.Options.Offset);
            var page = new List<Entry>();
            long? next = null;
            if (table != null)
            {
                var rows = realm.Objects(table, ct).Skip((int)Math.Min(offset, int.MaxValue)).Take(limit + 1).ToList();
                next = rows.Count > limit ? offset + limit : null;
                page = [.. rows.Take(limit).Select(o => new Entry(o.Key, Values(o)))];
            }
            List<Entry>? recovered = null;
            int found = 0;
            if (asked)
            {
                var list = realm.Recover(MaxRecovered + 1, ct);
                found = list.Count;
                recovered = [.. list.Take(MaxRecovered).Select(r => new Entry(r.Object.Key, Values(r.Object), r.Table == null ? null : Display(r.Table), r.Source))];
            }
            var notes = new List<string>(realm.Notes.Take(20));
            if (next != null) notes.Add($"offset={next} lists the next objects of {Display(table!.Name)}");
            if (found > MaxRecovered) notes.Add($"recovered: the first {MaxRecovered}; more remain");
            if (realm.Streaming) notes.Add("streaming form (written by a file copy): one commit, no previous one");
            if (!asked) notes.Add("view=realm adds the objects the previous commit and free space hold that the current commit deleted or changed");

            var tables = realm.Tables.Select(t => new TableEntry(Display(t.Name), t.Embedded, t.Objects,
                [.. Shown(t).Select(c => new ColumnEntry(c.Name, c.Kind))])).ToList();
            var classes = tables.Where(t => realm.Tables.Any(x => x.Name == "class_" + t.Name)).ToList();
            var highlights = new List<string>
            {
                $"Realm file: format {realm.FileFormat}, {realm.Length:N0} bytes; {classes.Count} classes" +
                (classes.Count > 0 ? $": {string.Join(", ", classes.Take(8).Select(t => $"{t.Name} ({t.Objects:N0})"))}{(classes.Count > 8 ? ", ..." : "")}" : "") + ".",
            };
            if (found > 0) highlights.Add($"Recoverable: {found:N0}{(found > MaxRecovered ? "+" : "")} objects the previous commit or free space hold that the current commit deleted or changed.");
            return new FileView(new Facts(realm.FileFormat, realm.Length, tables, table == null ? "" : Display(table.Name),
                table == null ? [] : [.. Shown(table).Select(c => c.Name)], offset, next, page, recovered, notes), highlights);
        }
    }

    // Columns as objects show them: backlink columns hold no stored value.
    private static IEnumerable<Realm.Column> Shown(Realm.Table t) => t.Columns.Where(c => c.Type != 14);

    private static string Display(string table) => table.StartsWith("class_", StringComparison.Ordinal) ? table[6..] : table;

    private static List<string> Values(Realm.Obj o) => [.. o.Values.Select(v => Realm.Text(v) is var s && s.Length > MaxText ? s[..MaxText] + "..." : s)];
}
