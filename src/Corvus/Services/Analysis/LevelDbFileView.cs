using System.Text;
using Corvus.Core.Databases;

namespace Corvus.Services.Analysis;

/// <summary>view=leveldb: a LevelDB database from any of its files: files, live records in key order (offset=, limit=), and recoverable records.</summary>
internal sealed class LevelDbFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxRecovered = 50, MaxValue = 200;
    private const long MaxRead = 1L << 30;

    /// <summary>A record: key and value as text (\xNN for other bytes) or hex, its sequence number, state and file.</summary>
    public sealed record Entry(string Key, string? Value, ulong Sequence, string State, string File);

    public sealed record Facts(string? Comparator, ulong? LastSequence, IReadOnlyList<LevelDb.FileFacts> Files, int LiveKeys, int DeletedKeys,
        int OlderVersions, int UnlistedRecords, long Offset, long? Next, IReadOnlyList<Entry> Records, IReadOnlyList<Entry> Recovered, IReadOnlyList<string> Notes);

    public string Name => "leveldb";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!LevelDb.IsDatabaseFile(file.Path, file.Head, () => Tail(file)) || Path.GetDirectoryName(Path.GetFullPath(file.Path)) is not { } folder) return null;
        var db = LevelDb.Read(folder, file.Path, MaxRead, ct);
        var liveFiles = db.Files.Where(f => f.Live).Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        var winners = db.Live.ToHashSet();
        var present = db.Live.Where(r => !r.Deleted).ToList();
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Clamp(file.Options.Offset, 0, present.Count);
        var page = present.Skip((int)offset).Take(limit).Select(r => Show(r, "live")).ToList();
        long? next = offset + page.Count < present.Count ? offset + page.Count : null;

        string State(LevelDb.Record r) =>
            !liveFiles.Contains(r.File) ? "in a file no longer read by the database" : winners.Contains(r) ? "deleted" : r.Deleted ? "older deletion" : "older version";
        var others = db.Records.Where(r => !winners.Contains(r) || r.Deleted).ToList();
        var recovered = others.OrderBy(r => Convert.ToHexString(r.Key), StringComparer.Ordinal).ThenByDescending(r => r.Sequence)
            .Take(MaxRecovered).Select(r => Show(r, State(r))).ToList();
        int deleted = db.Live.Count(r => r.Deleted), unlisted = db.Records.Count(r => !liveFiles.Contains(r.File));
        int older = others.Count - deleted - unlisted;
        var notes = new List<string>(db.Notes);
        if (next != null) notes.Add($"{present.Count:N0} live records; offset={next} lists the next");
        if (others.Count > MaxRecovered) notes.Add($"recovered: the first {MaxRecovered} of {others.Count:N0} records the live state no longer shows");

        var highlights = new List<string>
        {
            $"LevelDB database: {present.Count:N0} live keys in {db.Files.Count(f => f.Name.EndsWith(".ldb") || f.Name.EndsWith(".sst"))} tables and " +
            $"{db.Files.Count(f => f.Name.EndsWith(".log"))} logs{(db.Comparator is { } c ? $", comparator {c}" : "")}.",
        };
        if (others.Count > 0)
            highlights.Add($"Recoverable: {deleted:N0} deleted keys, {older:N0} older versions, {unlisted:N0} records in files the database no longer reads.");
        return new FileView(new Facts(db.Comparator, db.LastSequence, db.Files, present.Count, deleted, older, unlisted, offset, next, page, recovered, notes), highlights);
    }

    private static byte[]? Tail(FileInput file)
    {
        if (!file.Streamed) return file.Bytes;
        using var s = file.OpenRead();
        if (s.Length < 48) return null;
        s.Seek(-48, SeekOrigin.End);
        var b = new byte[48];
        s.ReadExactly(b);
        return b;
    }

    private static Entry Show(LevelDb.Record r, string state) => new(Text(r.Key), r.Deleted ? null : Text(r.Value), r.Sequence, state, r.File);

    /// <summary>Bytes as text (\xNN escapes) when mostly printable, else hex; clipped to <see cref="MaxValue"/> characters with the length named.</summary>
    internal static string Text(byte[] b)
    {
        var span = b.AsSpan(0, Math.Min(b.Length, MaxValue * 4));
        int printable = 0;
        foreach (var x in span) if (x is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\n' or (byte)'\r' or >= 0x80) printable++;
        string text;
        if (span.Length == 0) text = "";
        else if (printable * 10 >= span.Length * 7)
        {
            var sb = new StringBuilder();
            var decoder = new UTF8Encoding(false, true);
            for (int i = 0; i < span.Length && sb.Length < MaxValue;)
            {
                byte x = span[i];
                int len = x < 0x80 ? 1 : x >= 0xF0 ? 4 : x >= 0xE0 ? 3 : x >= 0xC0 ? 2 : 0;
                string? ch = null;
                if (len > 1 && i + len <= span.Length)
                    try { ch = decoder.GetString(span.Slice(i, len)); } catch (DecoderFallbackException) { }
                if (len == 1 && x is >= 0x20 and < 0x7F) ch = ((char)x).ToString();
                if (ch == null) { sb.Append($"\\x{x:x2}"); i++; }
                else { sb.Append(ch); i += len; }
            }
            text = sb.ToString();
        }
        else text = "hex:" + Convert.ToHexStringLower(span[..Math.Min(span.Length, MaxValue / 2)]);
        return text.Length >= MaxValue || span.Length < b.Length ? $"{text}... ({b.Length:N0} bytes)" : text;
    }
}
