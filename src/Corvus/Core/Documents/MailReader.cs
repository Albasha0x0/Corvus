using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>A MIME message (.eml) as a container: its bodies and attachments; .msg files reach <see cref="Contents"/> through the compound file reader.</summary>
internal sealed class MailReader : IContainerReader
{
    public string Kind => "mail";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => MailMessage.LooksLikeMime(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Contents(MailMessage.ReadMime(data, name, limits, ct), limits, ct: ct);

    /// <summary>Bodies as body.txt / body.html, each decoded attachment under attachments/ (undecoded ones listed, size unknown) and a .msg file's streams under streams/.</summary>
    public static ContainerContents Contents(MailMessage m, AnalysisLimits limits, CompoundFile? streams = null, bool allFiles = false, CancellationToken ct = default)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Add(m, "", items, entries, notes, used, limits, ref total);
        if (streams != null) CompoundFileReader.TakeStreams(streams, "streams/", items, entries, notes, allFiles, limits, ref total, ct);
        notes.Insert(0, $"{m.Format}: {m.Attachments.Count} attachment(s), {m.Links.Count} link(s); summarize_file view=mail lists the headers, received chain and recorded authentication results.");
        return new ContainerContents(m.Format, items, notes) { Entries = entries };
    }

    /// <summary>A message's bodies and attachments under <paramref name="prefix"/>; an embedded message's own under attachments/name.msg/.</summary>
    private static void Add(MailMessage m, string prefix, List<ExtractedItem> items, List<ContainerEntry> entries, List<string> notes, HashSet<string> used,
        AnalysisLimits limits, ref long total)
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
            ArchiveItems.Take(items, entries, "message body", Unique($"{prefix}body.{kind}"), Encoding.UTF8.GetBytes(text), true, limits, ref total);
        foreach (var a in m.Attachments)
        {
            var path = Unique($"{prefix}attachments/{a.Name}");
            if (a.Embedded is { } inner) Add(inner, path + "/", items, entries, notes, used, limits, ref total);
            else if (a.Bytes is { } bytes) ArchiveItems.Take(items, entries, "attachment", path, bytes, true, limits, ref total);
            else entries.Add(new ContainerEntry(path, 0, "not extracted; size unknown"));
            if (a.Problem != null) notes.Add($"{path}: {a.Problem}");
        }
        notes.AddRange(prefix.Length == 0 ? m.Notes : m.Notes.Select(n => $"{prefix.TrimEnd('/')}: {n}"));
    }
}
