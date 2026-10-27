using Corvus.Core;
using Corvus.Core.Databases;

namespace Corvus.Services.Analysis;

/// <summary>view=berkeleydb: format, databases, a page of one database's records (table=, offset=, limit=), and on request the recoverable records.</summary>
internal sealed class BerkeleyDbFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 200;

    public sealed record DatabaseEntry(string Name, string Kind, string Flags, long Keys, long Records);

    /// <summary>A record as text (\xNN for other bytes); Key is null in recno and queue databases, Database null when unknown.</summary>
    public sealed record Entry(string? Key, string Value, long? Number = null, string? Database = null, string? Source = null);

    public sealed record Facts(string Format, int PageSize, string ByteOrder, long Pages, IReadOnlyList<DatabaseEntry> Databases, string Database,
        long Offset, long? Next, IReadOnlyList<Entry> Records, IReadOnlyList<Entry>? Recovered, IReadOnlyList<string> Notes);

    public string Name => "berkeleydb";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!BerkeleyDb.Looks(file.Head)) return null;
        BerkeleyDb bdb;
        try { bdb = new BerkeleyDb(file.OpenRead()); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable Berkeley DB file: {ex.Message}"); }
        using (bdb)
        {
            bool asked = file.Options.Wants(Name);
            string? wanted = asked ? file.Options.Table : null;
            var db = wanted == null ? bdb.Databases.FirstOrDefault() : bdb.Databases.FirstOrDefault(d => d.Name == wanted);
            if (db == null && wanted != null)
                throw new ToolError(ErrorCode.InvalidArgument, $"no database named '{wanted}'; databases: {string.Join(", ", bdb.Databases.Select(d => d.Name))}", "pass table= with one of them, or none for the first database");
            int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
            long offset = Math.Max(0, file.Options.Offset);
            var page = new List<Entry>();
            long? next = null;
            if (db != null)
            {
                var rows = bdb.Records(db, null, ct).Skip((int)Math.Min(offset, int.MaxValue)).Take(limit + 1).ToList();
                next = rows.Count > limit ? offset + limit : null;
                page = [.. rows.Take(limit).Select(r => new Entry(r.Key == null ? null : LevelDbFileView.Text(r.Key), LevelDbFileView.Text(r.Value), r.Number))];
            }
            List<Entry>? recovered = null;
            int found = 0;
            if (asked)
            {
                var reached = new HashSet<uint>();
                var live = new HashSet<string>(StringComparer.Ordinal);
                foreach (var d in bdb.Databases)
                    foreach (var r in bdb.Records(d, reached, ct)) live.Add(BerkeleyDb.Id(r));
                var list = bdb.Recover(live, reached, MaxRecovered + 1, ct);
                found = list.Count;
                recovered = [.. list.Take(MaxRecovered).Select(r => new Entry(r.Record.Key == null ? null : LevelDbFileView.Text(r.Record.Key), LevelDbFileView.Text(r.Record.Value),
                    r.Record.Number, r.Database == null ? null : r.Database == "" ? "(main)" : r.Database, r.Source))];
            }
            var notes = new List<string>(bdb.Notes.Distinct().Take(20));
            if (next != null) notes.Add($"offset={next} lists the next records of {(db!.Name == "" ? "the database" : db.Name)}");
            if (found > MaxRecovered) notes.Add($"recovered: the first {MaxRecovered}; more remain");
            if (!asked) notes.Add("view=berkeleydb also recovers deleted, consumed and unreachable records");

            string method = bdb.Magic switch { 0x053162 => "btree", 0x061561 => "hash", 0x042253 => "queue", _ => "heap" };
            string format = $"{method} version {bdb.Version}";
            var dbs = bdb.Databases.Select(d => new DatabaseEntry(d.Name == "" ? "(main)" : d.Name, d.Kind, Flags(d), d.Keys, d.Records)).ToList();
            bool named = bdb.Databases.Any(d => d.Name != "");
            var highlights = new List<string>
            {
                $"Berkeley DB file: {format}, {bdb.PageSize:N0}-byte pages, {(bdb.BigEndian ? "big" : "little")}-endian" +
                (named ? $"; {dbs.Count} databases: {string.Join(", ", dbs.Take(8).Select(d => $"{d.Name} ({d.Kind})"))}{(dbs.Count > 8 ? ", ..." : "")}" : "") +
                (bdb.Encrypted ? "; encrypted" : "") + ".",
            };
            if (found > 0) highlights.Add($"Recoverable: {found:N0}{(found > MaxRecovered ? "+" : "")} deleted, consumed or unreachable records.");
            return new FileView(new Facts(format, bdb.PageSize, bdb.BigEndian ? "big-endian" : "little-endian", bdb.LastPage + 1, dbs,
                db == null ? "" : db.Name == "" ? "(main)" : db.Name, offset, next, page, recovered, notes), highlights);
        }
    }

    private static string Flags(BerkeleyDb.Database d)
    {
        var names = new List<string>();
        if (d.Duplicates) names.Add(d.SortedDuplicates ? "sorted duplicates" : "duplicates");
        if (d.Kind == "recno" && (d.Flags & 0x10) != 0) names.Add("renumber");
        if (d.Kind == "recno" && (d.Flags & 0x08) != 0) names.Add("fixed-length");
        if (d.Kind == "queue") names.Add($"{d.RecordLength}-byte records");
        return string.Join(", ", names);
    }
}
