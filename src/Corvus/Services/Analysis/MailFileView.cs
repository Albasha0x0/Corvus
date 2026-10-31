using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Web;
using MimeKit;

namespace Corvus.Services.Analysis;

/// <summary>view=mail: a .eml, .mht, .ics or .msg file's headers, received chain, recorded authentication results, sender identity, links, parts and attachments.</summary>
internal sealed class MailFileView : IFileSummaryView
{
    /// <summary>An attachment; null Size and Sha256 mean no bytes were decoded: Kind then names a message read in place, else Problem says why.</summary>
    public sealed record Attachment(string Name, string? ContentType, string? Disposition, string? ContentId, long? Size, string? Kind, string? Sha256, string? Problem);

    /// <summary>A part as stored, with its Content-Location; null Size means it was not decoded.</summary>
    public sealed record Part(string Name, string? ContentType, string? Location, long? Size);

    /// <summary>A file a body script builds in a Blob, carved from its literal.</summary>
    public sealed record Payload(string Kind, long Size, string Sha256);

    /// <summary>
    /// The sender fields side by side, as recorded. NameAddress is an address
    /// written in the From display name; the Differs flags are null when a
    /// field is absent.
    /// </summary>
    public sealed record SenderIdentity(string? FromName, string? FromAddress, string? NameAddress, IReadOnlyList<string> ReplyToAddresses, string? ReturnPathAddress,
        bool? ReplyToDiffers, bool? ReturnPathDiffers, bool? NameAddressDiffers);

    public sealed record Facts(string Format, string? Subject, string? From, string? Sender, string? ReplyTo, string? ReturnPath, IReadOnlyList<string> To,
        IReadOnlyList<string> Cc, DateTimeOffset? Date, string? MessageId, string? MessageClass, string? Mailer, bool HeadersRecorded,
        IReadOnlyList<ReceivedHop> Received, IReadOnlyList<AuthenticationResult> Authentication, IReadOnlyList<MailSignature> Signatures,
        IReadOnlyList<string> Links, IReadOnlyList<Attachment> Attachments, IReadOnlyList<MailHeader> Headers, IReadOnlyList<string> Notes)
    {
        public SenderIdentity? Identity { get; init; }
        public IReadOnlyList<Part> Parts { get; init; } = [];
        public IReadOnlyList<Payload> Payloads { get; init; } = [];
    }

    public string Name => "mail";

    /// <summary>Messages above this size are not read by the view.</summary>
    private const long MaxMessage = 512L << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxMessage) return null;
        var name = Path.GetFileName(file.Path);
        MailMessage m;
        if (MailMessage.LooksLikeMime(file.Head)) m = MailMessage.ReadMime(file.Bytes, name, AnalysisLimits.Default, ct);
        else if (MailMessage.LooksLikeCalendar(file.Head)) m = MailMessage.ReadCalendar(file.Bytes, AnalysisLimits.Default, ct);
        else if (CompoundFile.Looks(file.Head) && !Core.Installers.MsiDatabase.Looks(file.Head) && CompoundFile.Read(file.Bytes, name) is var cf && OutlookMessage.Is(cf))
            m = OutlookMessage.Read(cf, AnalysisLimits.Default, ct);
        else return null;
        var payloads = m.Bodies.Where(b => b.Name == "html").SelectMany(b => BlobPayloads.Find(b.Text, ct)).ToList();
        var facts = new Facts(m.Format, m.Subject, m.From, m.Sender, m.ReplyTo, m.ReturnPath, m.To, m.Cc, m.Date, m.MessageId, m.MessageClass, m.Mailer,
            m.HeadersRecorded, m.Received, m.Authentication, m.Signatures, m.Links,
            [.. m.Attachments.Select(a => new Attachment(a.Name, a.ContentType, a.Disposition, a.ContentId, a.Bytes?.Length,
                a.Bytes is { } b ? Blob.Identify(b) : a.Embedded != null ? "embedded Outlook message" : null, a.Bytes is { } h ? Blob.Sha256(h) : null, a.Problem))],
            m.Headers, m.Notes)
        {
            Identity = IdentityOf(m),
            Parts = [.. m.Parts.Select(p => new Part(p.Name, p.ContentType, p.Location, p.Size))],
            Payloads = [.. payloads.Select(p => new Payload(p.Kind, p.Size, p.Sha256))],
        };
        return new FileView(facts, Highlights(m, facts.Identity, facts.Parts, payloads));
    }

    private static MailboxAddress? Mailbox(string? text) =>
        text != null && InternetAddressList.TryParse(text, out var list) ? list.Mailboxes.FirstOrDefault() : null;

    private static SenderIdentity? IdentityOf(MailMessage m)
    {
        var from = Mailbox(m.From);
        var named = from?.Name is { Length: > 0 } n && InternetAddressList.TryParse(n, out var inner) && inner.Mailboxes.FirstOrDefault() is { Address: var inside } && inside.Contains('@') ? inside : null;
        var replyTo = m.ReplyTo != null && InternetAddressList.TryParse(m.ReplyTo, out var rl) ? rl.Mailboxes.Select(a => a.Address).ToList() : [];
        var path = Mailbox(m.ReturnPath)?.Address;
        if (from == null && replyTo.Count == 0 && path == null) return null;
        bool Differs(string a, string b) => !a.Equals(b, StringComparison.OrdinalIgnoreCase);
        return new SenderIdentity(from?.Name is { Length: > 0 } fn ? fn : null, from?.Address, named, replyTo, path,
            from != null && replyTo.Count > 0 ? replyTo.Any(r => Differs(r, from.Address)) : null,
            from != null && path != null ? Differs(path, from.Address) : null,
            from != null && named != null ? Differs(named, from.Address) : null);
    }

    private static List<string> Highlights(MailMessage m, SenderIdentity? id, IReadOnlyList<Part> parts, IReadOnlyList<BlobPayload> payloads)
    {
        var h = new List<string>
        {
            $"{m.Format} from {m.From ?? "(unknown sender)"} to {(m.To.Count > 0 ? string.Join(", ", m.To.Take(3)) + (m.To.Count > 3 ? ", ..." : "") : "(no recipient listed)")}" +
            $"{(m.Subject is { Length: > 0 } s ? $", subject \"{s}\"" : "")}{(m.Date is { } d ? $", {d:yyyy-MM-dd HH:mm:ss zzz}" : "")}.",
        };
        if (id is { NameAddressDiffers: true }) h.Add($"The From display name \"{id.FromName}\" names {id.NameAddress}; the address is {id.FromAddress}.");
        if (id is { ReplyToDiffers: true }) h.Add($"Reply-To {string.Join(", ", id.ReplyToAddresses)} differs from From {id.FromAddress}.");
        if (id is { ReturnPathDiffers: true }) h.Add($"Return-Path {id.ReturnPathAddress} differs from From {id.FromAddress}.");
        if (m.Format == "MHTML page") h.Add($"{parts.Count} part(s): {string.Join(", ", parts.Take(5).Select(p => p.Location ?? p.Name))}{(parts.Count > 5 ? ", ..." : "")}.");
        foreach (var p in payloads) h.Add($"The HTML body builds a {p.Kind} ({p.Size:N0} bytes) in a Blob.");
        if (!m.HeadersRecorded && m.Format != "iCalendar") h.Add("No internet headers recorded: the received chain and authentication results are unknown.");
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
            h.Add(a.Bytes is { } b ? $"Attachment {a.Name} ({b.Length:N0} bytes, {Blob.Identify(b)})."
                : a.Embedded is { } e ? $"Attachment {a.Name}: an embedded message, subject \"{e.Subject}\", {e.Attachments.Count} attachment(s)."
                : $"Attachment {a.Name}: {a.Problem}.");
        if (MemberNames.Check(m.Attachments.Select(a => a.Name)) is { } disguised) h.Add($"Attachment names that disguise their type: {disguised}.");
        if (m.Links.Count > 0) h.Add($"{m.Links.Count} link(s) in the body, first {m.Links[0]}.");
        return h;
    }
}
