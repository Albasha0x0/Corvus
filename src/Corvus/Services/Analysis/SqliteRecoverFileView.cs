using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>view=sqlite-recover: deleted rows carved from free space and unapplied -wal frames; carving runs only when asked for; table=, offset=, limit= page the rows.</summary>
internal sealed class SqliteRecoverFileView : IFileSummaryView
{
    private const int DefaultLimit = 100, MaxLimit = 1000, MaxValue = 200;

    /// <summary>A recovered candidate: its table (null when unsure), rowid when the cell header survived, values in column order, source and method.</summary>
    public sealed record Candidate(string? Table, long? RowId, IReadOnlyList<string> Values, string Source, string Method);

    public sealed record Facts(long FreelistPages, int WalFramesNotApplied, int Total, long Offset, int Limit, IReadOnlyList<Candidate> Rows, long? Next,
        IReadOnlyDictionary<string, int> ByTable, IReadOnlyList<string> Notes);

    public string Name => "sqlite-recover";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        using var open = SqliteFileView.Database.Open(file, ct);
        if (open?.Db is not { } db) return null;
        var options = file.Options;
        int walFrames = db.WalLog?.Frames.Count(f => f.State != "applied") ?? 0;
        if (!options.Wants(Name))
        {
            var where = new List<string>();
            if (db.FreelistPages > 0) where.Add($"{db.FreelistPages:N0} freelist pages");
            if (walFrames > 0) where.Add($"{walFrames:N0} -wal frames that are not applied");
            return new FileView(new Facts(db.FreelistPages, walFrames, 0, 0, 0, [], null, new Dictionary<string, int>(),
                    ["carving runs only for view=sqlite-recover"]),
                where.Count > 0 ? [$"Deleted rows may remain in {string.Join(" and ", where)} and in freed cells: view=sqlite-recover carves them."] : []);
        }
        var notes = new List<string>();
        var all = db.Recover(notes, ct);
        if (options.Table != null && db.Table(options.Table) is null)
            throw new ToolError(ErrorCode.NotFound, $"no stored table '{options.Table}' in the database.", $"pass table as one of {string.Join(", ", db.Tables().Select(t => t.Name).Take(50))}");
        var rows = options.Table == null ? all : all.Where(r => r.Table != null && r.Table.Equals(options.Table, StringComparison.OrdinalIgnoreCase)).ToList();
        int limit = Math.Clamp(options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, options.Offset);
        var page = rows.Skip((int)Math.Min(offset, int.MaxValue)).Take(limit)
            .Select(r => new Candidate(r.Table, r.RowId, [.. r.Values.Select(v => SqliteFileView.Show(v, MaxValue))], r.Source, r.Method)).ToList();
        notes.AddRange(db.Issues.Distinct().Take(20));
        notes.Add("candidates can be partial or an older row version; a rowid is shown only when its cell header survived.");
        var byTable = all.GroupBy(r => r.Table ?? "(unsure)").ToDictionary(g => g.Key, g => g.Count());
        long next = offset + page.Count;
        var facts = new Facts(db.FreelistPages, walFrames, rows.Count, offset, limit, page, next < rows.Count ? next : null, byTable, notes);
        return new FileView(facts, [$"{all.Count:N0} deleted-row candidates carved ({string.Join(", ", byTable.Select(t => $"{t.Key}: {t.Value:N0}"))})."]);
    }
}
