using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>A MIME message (.eml) as a container: its bodies and attachments; .msg files reach <see cref="Contents"/> through the compound file reader.</summary>
internal sealed class MailReader : IContainerReader
{
    public string Kind => "mail";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => MailMessage.LooksLikeMime(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Contents(MailMessage.ReadMime(data, name, limits, ct), limits);

    /// <summary>Bodies as body.txt / body.html and each decoded attachment under attachments/; undecoded ones are listed, size unknown.</summary>
    public static ContainerContents Contents(MailMessage m, AnalysisLimits limits)
    {
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>();
        long total = 0;
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string Unique(string path)
        {
            if (used.Add(path)) return path;
            var stem = Path.ChangeExtension(path, null);
            var ext = Path.GetExtension(path);
            for (int i = 2; ; i++)
                if (used.Add($"{stem}-{i}{ext}")) return $"{stem}-{i}{ext}";
        }
        foreach (var (kind, text) in m.Bodies)
            ArchiveItems.Take(items, entries, "message body", Unique($"body.{kind}"), Encoding.UTF8.GetBytes(text), true, limits, ref total);
        foreach (var a in m.Attachments)
        {
            var path = Unique("attachments/" + a.Name);
            if (a.Bytes is { } bytes) ArchiveItems.Take(items, entries, "attachment", path, bytes, true, limits, ref total);
            else entries.Add(new ContainerEntry(path, 0, "not extracted; size unknown"));
            if (a.Problem != null) notes.Add($"{path}: {a.Problem}");
        }
        notes.Insert(0, $"{m.Format}: {m.Attachments.Count} attachment(s), {m.Links.Count} link(s); summarize_file view=mail lists the headers, received chain and recorded authentication results.");
        notes.AddRange(m.Notes);
        return new ContainerContents(m.Format, items, notes) { Entries = entries };
    }
}
