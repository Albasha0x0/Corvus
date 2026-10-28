using System.Text;
using System.Text.RegularExpressions;
using MimeKit;
using MimeKit.Utils;

namespace Corvus.Core.Documents;

/// <summary>One header line as recorded, unfolded.</summary>
internal sealed record MailHeader(string Name, string Value);

/// <summary>One Received header: the clauses it names and its date; null when the header leaves a clause out.</summary>
internal sealed record ReceivedHop(int Index, string? From, string? By, string? Via, string? With, string? Id, string? For, DateTimeOffset? Date, string Raw);

/// <summary>One method result recorded by a receiving server (Authentication-Results, ARC-Authentication-Results, Received-SPF); not re-checked.</summary>
internal sealed record AuthenticationResult(string Header, int? Instance, string? AuthServId, string Method, string Result, string? Properties);

/// <summary>A DKIM-Signature, ARC-Message-Signature or ARC-Seal as recorded: its tags only, the signature is not verified.</summary>
internal sealed record MailSignature(string Header, int? Instance, string? Domain, string? Selector, string? Algorithm, string? SignedHeaders, string? ChainValidation);

/// <summary>An attachment or inline part; null <see cref="Bytes"/> means its content was not decoded, and <see cref="Problem"/> says why.</summary>
internal sealed record MailAttachment(string Name, string? ContentType, string? Disposition, string? ContentId, byte[]? Bytes, string? Problem)
{
    /// <summary>An Outlook message stored as the attachment, read in place; null for other attachments.</summary>
    public MailMessage? Embedded { get; init; }
}

/// <summary>A mail message read from a MIME (.eml) or Outlook (.msg) file: headers, received chain, recorded authentication results, links and attachments.</summary>
internal sealed class MailMessage
{
    /// <summary>Headers, links and attachments kept per message; more are counted in a note.</summary>
    private const int MaxHeaders = 2_000, MaxLinks = 1_000, MaxParts = 5_000;

    private static readonly string[] MimeHeaders = ["from", "received", "date", "subject", "message-id", "mime-version", "to", "return-path", "content-type", "x-mailer", "reply-to", "delivered-to"];
    private static readonly string[] KnownTransferEncodings = ["7bit", "8bit", "binary", "base64", "quoted-printable", "x-uuencode", "uuencode", "x-uue"];

    private static readonly Regex Url = new(@"(?i)\b(?:https?|ftp)://[^\s""'<>()\[\]{}\\^`|]+", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public required string Format { get; init; }
    public string? Subject { get; set; }
    public string? From { get; set; }
    public string? Sender { get; set; }
    public string? ReplyTo { get; set; }
    public string? ReturnPath { get; set; }
    public List<string> To { get; } = [];
    public List<string> Cc { get; } = [];
    public DateTimeOffset? Date { get; set; }
    public string? MessageId { get; set; }
    public string? MessageClass { get; set; }
    public string? Mailer { get; set; }
    /// <summary>False when the file keeps no internet headers (an unsent or locally made .msg): chain and results are unknown, not empty.</summary>
    public bool HeadersRecorded { get; set; } = true;
    public List<MailHeader> Headers { get; } = [];
    public List<ReceivedHop> Received { get; } = [];
    public List<AuthenticationResult> Authentication { get; } = [];
    public List<MailSignature> Signatures { get; } = [];
    public List<(string Name, string Text)> Bodies { get; } = [];
    public List<string> Links { get; } = [];
    public List<MailAttachment> Attachments { get; } = [];
    public List<string> Notes { get; } = [];

    /// <summary>Whether <paramref name="b"/> starts with an RFC 5322 header block that names at least two message headers.</summary>
    public static bool LooksLikeMime(ReadOnlySpan<byte> b)
    {
        int at = 0, known = 0, lines = 0;
        var window = b[..Math.Min(b.Length, 64 << 10)];
        while (at < window.Length && lines < 400)
        {
            int nl = window[at..].IndexOf((byte)'\n');
            if (nl < 0) return false;
            var line = window.Slice(at, nl).TrimEnd((byte)'\r');
            at += nl + 1;
            lines++;
            if (line.IsEmpty) return known >= 2;
            if (line[0] is (byte)' ' or (byte)'\t') { if (lines == 1) return false; continue; }
            int colon = line.IndexOf((byte)':');
            if (colon <= 0) return false;
            foreach (var c in line[..colon])
                if (c is <= 32 or >= 127) return false;
            var name = Encoding.ASCII.GetString(line[..colon]).ToLowerInvariant();
            if (MimeHeaders.Contains(name)) known++;
        }
        return false;
    }

    /// <summary>Reads a MIME message; a file without a header block is malformed input.</summary>
    public static MailMessage ReadMime(byte[] data, string name, AnalysisLimits limits, CancellationToken ct)
    {
        MimeMessage message;
        try { message = MimeMessage.Load(new ParserOptions { MaxMimeDepth = 64 }, new MemoryStream(data, writable: false), ct); }
        catch (FormatException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a MIME message: {ex.Message}"); }
        var m = new MailMessage { Format = "MIME message" };
        m.ReadHeaders(message.Headers);
        m.From = Join(message.From) ?? m.From;
        m.Sender = message.Sender?.ToString() ?? m.Sender;
        m.ReplyTo = Join(message.ReplyTo) ?? m.ReplyTo;
        m.To.Clear(); m.To.AddRange(message.To.Select(a => a.ToString()));
        m.Cc.Clear(); m.Cc.AddRange(message.Cc.Select(a => a.ToString()));
        m.Subject = message.Subject;
        m.MessageId = message.MessageId;
        if (message.Headers.Contains(HeaderId.Date)) m.Date = message.Date;
        int parts = 0;
        foreach (var entity in message.BodyParts)
        {
            ct.ThrowIfCancellationRequested();
            if (++parts > MaxParts) { m.Notes.Add($"more than {MaxParts:N0} body parts; the rest are not listed"); break; }
            m.TakePart(entity, limits, ct);
        }
        m.FindLinks();
        return m;
    }

    private static string? Join(InternetAddressList list) => list.Count == 0 ? null : string.Join(", ", list.Select(a => a.ToString()));

    /// <summary>Header fields, received chain and recorded results from a header block.</summary>
    internal void ReadHeaders(HeaderList headers)
    {
        int received = 0;
        foreach (var h in headers)
        {
            if (Headers.Count < MaxHeaders) Headers.Add(new MailHeader(h.Field, h.Value));
            var value = h.Value;
            switch (h.Field.ToLowerInvariant())
            {
                case "received": Received.Add(Hop(++received, value)); break;
                case "authentication-results": Results("Authentication-Results", value, arc: false); break;
                case "arc-authentication-results": Results("ARC-Authentication-Results", value, arc: true); break;
                case "received-spf": Spf(value); break;
                case "dkim-signature": Signatures.Add(Signature("DKIM-Signature", value)); break;
                case "arc-message-signature": Signatures.Add(Signature("ARC-Message-Signature", value)); break;
                case "arc-seal": Signatures.Add(Signature("ARC-Seal", value)); break;
                case "subject": Subject ??= value.Trim(); break;
                case "from": From ??= value.Trim(); break;
                case "sender": Sender ??= value.Trim(); break;
                case "reply-to": ReplyTo ??= value.Trim(); break;
                case "return-path": ReturnPath ??= value.Trim(); break;
                case "message-id": MessageId ??= value.Trim(); break;
                case "x-mailer" or "user-agent": Mailer ??= value.Trim(); break;
                case "date" when Date == null && DateUtils.TryParse(value, out var date): Date = date; break;
            }
        }
        if (headers.Count > MaxHeaders) Notes.Add($"{headers.Count:N0} headers; the first {MaxHeaders:N0} are listed");
    }

    private static string StripComments(string s)
    {
        var b = new StringBuilder(s.Length);
        int depth = 0;
        bool quoted = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '\\' && i + 1 < s.Length) { if (depth == 0) b.Append(c).Append(s[i + 1]); i++; continue; }
            if (c == '"' && depth == 0) quoted = !quoted;
            else if (!quoted && c == '(') { depth++; continue; }
            else if (!quoted && c == ')' && depth > 0) { depth--; continue; }
            if (depth == 0) b.Append(c);
        }
        return b.ToString();
    }

    private static ReceivedHop Hop(int index, string value)
    {
        int semi = value.LastIndexOf(';');
        DateTimeOffset? date = semi >= 0 && DateUtils.TryParse(value[(semi + 1)..].Trim(), out var d) ? d : null;
        var words = StripComments(semi >= 0 ? value[..semi] : value).Split((char[])[' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var clauses = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i + 1 < words.Length; i++)
        {
            var key = words[i].ToLowerInvariant();
            if (key is "from" or "by" or "via" or "with" or "id" or "for" && !clauses.ContainsKey(key)) clauses[key] = words[++i].Trim('<', '>');
        }
        string? C(string k) => clauses.GetValueOrDefault(k);
        return new ReceivedHop(index, C("from"), C("by"), C("via"), C("with"), C("id"), C("for"), date, value.Trim());
    }

    private static int? Instance(string segment) =>
        segment.Trim() is var s && s.StartsWith("i=", StringComparison.OrdinalIgnoreCase) && int.TryParse(s[2..].Trim(), out int i) ? i : null;

    private void Results(string header, string value, bool arc)
    {
        var segments = StripComments(value).Split(';').Select(s => s.Trim()).ToList();
        int? instance = null;
        if (arc && segments.Count > 0 && Instance(segments[0]) is { } i) { instance = i; segments.RemoveAt(0); }
        if (segments.Count == 0) return;
        // The authserv-id may carry a version number after it.
        var authServ = segments[0].Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        bool any = false;
        foreach (var segment in segments.Skip(1))
        {
            var words = segment.Split((char[])[' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0 || words[0].Equals("none", StringComparison.OrdinalIgnoreCase)) continue;
            int eq = words[0].IndexOf('=');
            if (eq <= 0) continue;
            any = true;
            Authentication.Add(new AuthenticationResult(header, instance, authServ, words[0][..eq].ToLowerInvariant(), words[0][(eq + 1)..].ToLowerInvariant(),
                words.Length > 1 ? string.Join(' ', words[1..]) : null));
        }
        if (!any && segments.Count > 1 && !segments.Skip(1).All(s => s.Equals("none", StringComparison.OrdinalIgnoreCase) || s.Length == 0))
            Notes.Add($"{header}: no method result could be read from '{Clip(value)}'");
    }

    private void Spf(string value)
    {
        var words = StripComments(value).Split((char[])[' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0) { Notes.Add("Received-SPF: empty value"); return; }
        Authentication.Add(new AuthenticationResult("Received-SPF", null, null, "spf", words[0].ToLowerInvariant(), words.Length > 1 ? string.Join(' ', words[1..]) : null));
    }

    private static MailSignature Signature(string header, string value)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in value.Split(';'))
        {
            int eq = segment.IndexOf('=');
            if (eq <= 0) continue;
            var key = segment[..eq].Trim();
            if (key.Length > 0) tags.TryAdd(key, string.Concat(segment[(eq + 1)..].Where(c => !char.IsWhiteSpace(c))));
        }
        string? T(string k) => tags.TryGetValue(k, out var v) && v.Length > 0 ? v : null;
        return new MailSignature(header, int.TryParse(T("i"), out int i) ? i : null, T("d"), T("s"), T("a"), T("h"), T("cv"));
    }

    private void TakePart(MimeEntity entity, AnalysisLimits limits, CancellationToken ct)
    {
        string? type = entity.ContentType?.MimeType;
        string? disposition = entity.ContentDisposition?.Disposition;
        string? contentId = entity.ContentId;
        if (entity is MessagePart embedded)
        {
            var name = Name(entity.ContentDisposition?.FileName ?? entity.ContentType?.Name, "message", ".eml");
            if (embedded.Message is null) { Attachments.Add(new MailAttachment(name, type, disposition, contentId, null, "the embedded message is empty")); return; }
            var o = new BoundedStream(limits.MaxItemBytes);
            try { embedded.Message.WriteTo(o, ct); Attachments.Add(new MailAttachment(name, type, disposition, contentId, o.ToArray(), null)); }
            catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { Attachments.Add(new MailAttachment(name, type, disposition, contentId, null, ex.Message)); }
            return;
        }
        if (entity is not MimePart part) return;
        var file = part.FileName;
        if (part is TextPart text && !part.IsAttachment && file == null)
        {
            var body = text.Text ?? "";
            Bodies.Add((text.IsHtml ? "html" : text.IsPlain ? "txt" : text.ContentType.MediaSubtype.ToLowerInvariant(), body));
            return;
        }
        var label = Name(file ?? part.ContentType?.Name, "attachment", Extension(type));
        var encoding = part.Headers[HeaderId.ContentTransferEncoding]?.Trim().ToLowerInvariant();
        string? problem = encoding is { Length: > 0 } && !KnownTransferEncodings.Contains(encoding)
            ? $"transfer encoding '{Clip(encoding)}' is unknown; the bytes are kept as stored" : null;
        if (part.Content is null) { Attachments.Add(new MailAttachment(label, type, disposition, contentId, null, "the part has no content")); return; }
        var output = new BoundedStream(limits.MaxItemBytes);
        try
        {
            part.Content.DecodeTo(output, ct);
            Attachments.Add(new MailAttachment(label, type, disposition, contentId, output.ToArray(), problem));
        }
        catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { Attachments.Add(new MailAttachment(label, type, disposition, contentId, null, ex.Message)); }
    }

    private int _unnamed;

    /// <summary>A file name without directories or control characters; unnamed parts are numbered.</summary>
    private string Name(string? given, string stem, string extension)
    {
        var name = Path.GetFileName((given ?? "").Replace('\\', '/'));
        name = string.Concat(name.Where(c => c >= 32 && c != 127)).Trim();
        if (name is "" or "." or "..") name = $"{stem}-{++_unnamed}{extension}";
        return name;
    }

    private static string Extension(string? mimeType) => (mimeType ?? "").ToLowerInvariant() switch
    {
        "application/zip" or "application/x-zip-compressed" => ".zip",
        "application/pdf" => ".pdf",
        "message/rfc822" => ".eml",
        "text/calendar" => ".ics",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "application/ms-tnef" or "application/vnd.ms-tnef" => ".dat",
        "text/html" => ".html",
        "text/plain" => ".txt",
        _ => ".bin",
    };

    private static string Clip(string s) => s.Length <= 120 ? s : s[..117] + "...";

    /// <summary>URLs from the bodies, HTML entities in them decoded, in first-seen order.</summary>
    internal void FindLinks()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (kind, text) in Bodies)
            foreach (Match match in Url.Matches(text))
            {
                var link = match.Value.TrimEnd('.', ',', ';', ':', '!', '?');
                if (kind == "html") link = System.Net.WebUtility.HtmlDecode(link);
                if (!seen.Add(link)) continue;
                if (Links.Count == MaxLinks) { Notes.Add($"more than {MaxLinks:N0} links; the rest are not listed"); return; }
                Links.Add(link);
            }
    }

    /// <summary>A write-only memory stream that refuses to grow past the item limit.</summary>
    internal sealed class BoundedStream(long max) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count) { Check(count); base.Write(buffer, offset, count); }

        public override void Write(ReadOnlySpan<byte> buffer) { Check(buffer.Length); base.Write(buffer); }

        public override void WriteByte(byte value) { Check(1); base.WriteByte(value); }

        private void Check(int count)
        {
            if (Length + count > max) throw new ToolError(ErrorCode.LimitExceeded, $"a part passes the {max:N0}-byte item limit; it is not decoded.");
        }
    }
}
