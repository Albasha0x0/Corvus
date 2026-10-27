using Corvus.Core;
using Corvus.Core.Databases;

namespace Corvus.Services.Analysis;

/// <summary>view=lmdb: an LMDB environment's transactions, databases, a page of one database's records (table=, offset=, limit=), and on request recoverable records.</summary>
internal sealed class LmdbFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 200;

    public sealed record DatabaseEntry(string Name, string Flags, int Depth, long Entries, long Pages);

    /// <summary>A record: key and value as text (\xNN for other bytes) or hex, and for a recovered one where it was found.</summary>
    public sealed record Entry(string Key, string Value, string? Database = null, string? Source = null);

    public sealed record Facts(int PageSize, long MapSize, long LastPage, long Transaction, long? PreviousTransaction, IReadOnlyList<DatabaseEntry> Databases,
        string Database, long Offset, long? Next, IReadOnlyList<Entry> Records, IReadOnlyList<Entry>? Recovered, IReadOnlyList<string> Notes);

    public string Name => "lmdb";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Lmdb.Looks(file.Head)) return null;
        Lmdb env;
        try { env = new Lmdb(file.OpenRead()); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable LMDB file: {ex.Message}"); }
        using (env)
        {
            bool asked = file.Options.Wants(Name);
            var meta = env.Current;
            var named = env.Named(meta, null, ct);
            var all = new List<Lmdb.Database> { meta.Main };
            all.AddRange(named);
            string wanted = asked ? file.Options.Table ?? "" : "";
            var db = all.FirstOrDefault(d => d.Name == wanted)
                ?? throw new ToolError(ErrorCode.InvalidArgument, $"no database named '{wanted}'; named databases: {string.Join(", ", named.Select(d => d.Name))}", "pass table= with one of them, or none for the main database");
            int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
            long offset = Math.Max(0, file.Options.Offset);
            var rows = env.Records(db, null, ct).Skip((int)Math.Min(offset, int.MaxValue)).Take(limit + 1).ToList();
            long? next = rows.Count > limit ? offset + limit : null;
            var page = rows.Take(limit).Select(r => new Entry(LevelDbFileView.Text(r.Key), LevelDbFileView.Text(r.Value))).ToList();

            List<Entry>? recovered = null;
            int found = 0;
            if (asked)
            {
                var reached = new HashSet<long>();
                var live = new HashSet<string>(StringComparer.Ordinal);
                env.Named(meta, reached, ct);
                foreach (var d in all)
                    foreach (var r in env.Records(d, reached, ct)) live.Add(Lmdb.Id(r));
                var list = env.Recover(live, reached, MaxRecovered + 1, ct);
                found = list.Count;
                recovered = [.. list.Take(MaxRecovered).Select(r => new Entry(LevelDbFileView.Text(r.Record.Key), LevelDbFileView.Text(r.Record.Value), r.Record.Database == "" ? "(main)" : r.Record.Database, r.Source))];
            }
            var notes = new List<string>(env.Notes.Distinct().Take(20));
            if (next != null) notes.Add($"offset={next} lists the next records of {(db.Name == "" ? "the main database" : db.Name)}");
            if (found > MaxRecovered) notes.Add($"recovered: the first {MaxRecovered}; more remain");
            if (!asked) notes.Add("view=lmdb also recovers records only the previous commit or unreachable pages hold");

            var dbs = all.Select(d => new DatabaseEntry(d.Name == "" ? "(main)" : d.Name, Flags(d.Flags), d.Depth, d.Entries, d.BranchPages + d.LeafPages + d.OverflowPages)).ToList();
            var highlights = new List<string>
            {
                $"LMDB environment: {env.PageSize:N0}-byte pages, {meta.LastPage + 1:N0} pages used, transaction {meta.TxnId}; main database of {meta.Main.Entries:N0} entries" +
                (named.Count > 0 ? $", {named.Count} named: {string.Join(", ", named.Take(8).Select(d => $"{d.Name} ({d.Entries:N0})"))}" : "") + ".",
            };
            if (found > 0) highlights.Add($"Recoverable: {found:N0}{(found > MaxRecovered ? "+" : "")} records only the previous commit or unreachable pages hold.");
            return new FileView(new Facts(env.PageSize, meta.MapSize, meta.LastPage, meta.TxnId, env.Previous?.TxnId, dbs, db.Name == "" ? "(main)" : db.Name,
                offset, next, page, recovered, notes), highlights);
        }
    }

    private static string Flags(ushort f)
    {
        var names = new List<string>();
        foreach (var (bit, name) in new[] { (0x02, "reverse keys"), (0x04, "duplicate values"), (0x08, "integer keys"), (0x10, "fixed-size duplicates"), (0x20, "integer duplicates"), (0x40, "reverse duplicates") })
            if ((f & bit) != 0) names.Add(name);
        return string.Join(", ", names);
    }
}
