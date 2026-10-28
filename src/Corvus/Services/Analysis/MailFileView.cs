using Corvus.Core;
using Corvus.Core.Documents;

namespace Corvus.Services.Analysis;

/// <summary>view=mail: a .eml or .msg message's headers, received chain, recorded authentication results, links and attachments.</summary>
internal sealed class MailFileView : IFileSummaryView
{
    /// <summary>An attachment; null Size, Kind and Sha256 mean its content was not decoded, and Problem says why.</summary>
    public sealed record Attachment(string Name, string? ContentType, string? Disposition, string? ContentId, long? Size, string? Kind, string? Sha256, string? Problem);

    public sealed record Facts(string Format, string? Subject, string? From, string? Sender, string? ReplyTo, string? ReturnPath, IReadOnlyList<string> To,
        IReadOnlyList<string> Cc, DateTimeOffset? Date, string? MessageId, string? MessageClass, string? Mailer, bool HeadersRecorded,
        IReadOnlyList<ReceivedHop> Received, IReadOnlyList<AuthenticationResult> Authentication, IReadOnlyList<MailSignature> Signatures,
        IReadOnlyList<string> Links, IReadOnlyList<Attachment> Attachments, IReadOnlyList<MailHeader> Headers, IReadOnlyList<string> Notes);

    public string Name => "mail";

    /// <summary>Messages above this size are not read by the view.</summary>
    private const long MaxMessage = 512L << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxMessage) return null;
        var name = Path.GetFileName(file.Path);
        MailMessage m;
        if (MailMessage.LooksLikeMime(file.Head)) m = MailMessage.ReadMime(file.Bytes, name, AnalysisLimits.Default, ct);
        else if (CompoundFile.Looks(file.Head) && !Core.Installers.MsiDatabase.Looks(file.Head) && CompoundFile.Read(file.Bytes, name) is var cf && OutlookMessage.Is(cf))
            m = OutlookMessage.Read(cf, AnalysisLimits.Default, ct);
        else return null;
        var facts = new Facts(m.Format, m.Subject, m.From, m.Sender, m.ReplyTo, m.ReturnPath, m.To, m.Cc, m.Date, m.MessageId, m.MessageClass, m.Mailer,
            m.HeadersRecorded, m.Received, m.Authentication, m.Signatures, m.Links,
            [.. m.Attachments.Select(a => new Attachment(a.Name, a.ContentType, a.Disposition, a.ContentId, a.Bytes?.Length,
                a.Bytes is { } b ? Blob.Identify(b) : null, a.Bytes is { } h ? Blob.Sha256(h) : null, a.Problem))],
            m.Headers, m.Notes);
        return new FileView(facts, Highlights(m));
    }

    private static List<string> Highlights(MailMessage m)
    {
        var h = new List<string>
        {
            $"{m.Format} from {m.From ?? "(unknown sender)"} to {(m.To.Count > 0 ? string.Join(", ", m.To.Take(3)) + (m.To.Count > 3 ? ", ..." : "") : "(no recipient listed)")}" +
            $"{(m.Subject is { Length: > 0 } s ? $", subject \"{s}\"" : "")}{(m.Date is { } d ? $", {d:yyyy-MM-dd HH:mm:ss zzz}" : "")}.",
        };
        if (!m.HeadersRecorded) h.Add("No internet headers recorded: the received chain and authentication results are unknown.");
        else if (m.Received.Count > 0)
        {
            var first = m.Received[^1];
            h.Add($"{m.Received.Count} Received header(s); the earliest names {first.From ?? "(no from clause)"} handing to {first.By ?? "(no by clause)"}.");
        }
        if (m.Authentication.Count > 0)
            h.Add($"Recorded results, not re-checked: {string.Join(", ", m.Authentication.Select(a => $"{a.Method}={a.Result}").Distinct().Take(8))}.");
        foreach (var sig in m.Signatures.Where(s => s.Header == "DKIM-Signature").Take(3))
            h.Add($"DKIM-Signature present for d={sig.Domain ?? "(none)"} s={sig.Selector ?? "(none)"}; not verified.");
        foreach (var a in m.Attachments.Take(5))
            h.Add(a.Bytes is { } b ? $"Attachment {a.Name} ({b.Length:N0} bytes, {Blob.Identify(b)})." : $"Attachment {a.Name}: {a.Problem}.");
        if (m.Links.Count > 0) h.Add($"{m.Links.Count} link(s) in the body, first {m.Links[0]}.");
        return h;
    }
}
