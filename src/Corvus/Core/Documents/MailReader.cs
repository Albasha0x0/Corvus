using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>Finds the files an HTML body builds in a Blob; implemented where the page reader lives, so the lower layer does not reference it.</summary>
internal interface IHtmlPayloadSource
{
    /// <summary>The payloads of <paramref name="html"/>; empty when it builds none.</summary>
    IReadOnlyList<(string Name, string Kind, long Size, string Sha256, byte[] Bytes)> Find(string html, CancellationToken ct);
}

/// <summary>A MIME message (.eml, .mht) or calendar file (.ics) as a container: its bodies and attachments; .msg files reach <see cref="Contents"/> through the compound file reader.</summary>
internal sealed class MailReader : IContainerReader
{
    public string Kind => "mail";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => MailMessage.LooksLikeMime(data) || MailMessage.LooksLikeCalendar(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Contents(MailMessage.LooksLikeCalendar(data) ? MailMessage.ReadCalendar(data, limits, ct) : MailMessage.ReadMime(data, name, limits, ct), limits, ct: ct);

    /// <summary>Bodies as body.txt / body.html, each decoded attachment under attachments/ (undecoded ones listed, size unknown) and a .msg file's streams under streams/.</summary>
    public static ContainerContents Contents(MailMessage m, AnalysisLimits limits, CompoundFile? streams = null, bool allFiles = false, CancellationToken ct = default)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var extractedAs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Add(m, "", items, entries, notes, used, extractedAs, limits, ref total, ct);
        if (streams != null) CompoundFileReader.TakeStreams(streams, "streams/", items, entries, notes, allFiles, limits, ref total, ct, extractedAs);
        notes.Insert(0, $"{m.Format}: {m.Attachments.Count} attachment(s), {m.Links.Count} link(s); summarize_file view=mail lists the headers, received chain and recorded authentication results.");
        return new ContainerContents(m.Format, items, notes) { Entries = entries };
    }

    /// <summary>A message's bodies and attachments under <paramref name="prefix"/>; an embedded message's own under attachments/name.msg/.</summary>
    private static void Add(MailMessage m, string prefix, List<ExtractedItem> items, List<ContainerEntry> entries, List<string> notes, HashSet<string> used,
        Dictionary<string, string> extractedAs, AnalysisLimits limits, ref long total, CancellationToken ct)
    {
        string Unique(string path)
        {
            if (used.Add(path)) return path;
            var stem = Path.ChangeExtension(path, null);
            var ext = Path.GetExtension(path);
            for (int i = 2; ; i++)
                if (used.Add($"{stem}-{i}{ext}")) return $"{stem}-{i}{ext}";
        }
        foreach (var (kind, text) in m.Bodies)
        {
            ArchiveItems.Take(items, entries, "message body", Unique($"{prefix}body.{kind}"), Encoding.UTF8.GetBytes(text), true, limits, ref total);
            if (kind != "html") continue;
            foreach (var source in Providers.Of<IHtmlPayloadSource>())
            foreach (var p in source.Find(text, ct))
            {
                ArchiveItems.Take(items, entries, "payload built in a Blob", Unique($"{prefix}body-payloads/{p.Name}"), p.Bytes, true, limits, ref total);
                notes.Add($"{prefix}body-payloads/{p.Name}: {p.Kind}, {p.Size:N0} bytes, SHA-256 {p.Sha256}");
            }
        }
        foreach (var a in m.Attachments)
        {
            var path = Unique($"{prefix}attachments/{a.Name}");
            if (a.Embedded is { } inner) Add(inner, path + "/", items, entries, notes, used, extractedAs, limits, ref total, ct);
            else if (a.Bytes is { } bytes)
            {
                ArchiveItems.Take(items, entries, "attachment", path, bytes, true, limits, ref total);
                if (a.Stream != null) extractedAs[a.Stream] = path;
            }
            else entries.Add(new ContainerEntry(path, 0, "not extracted; size unknown"));
            if (a.Problem != null) notes.Add($"{path}: {a.Problem}");
        }
        notes.AddRange(prefix.Length == 0 ? m.Notes : m.Notes.Select(n => $"{prefix.TrimEnd('/')}: {n}"));
    }
}
