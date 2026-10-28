using System.Buffers.Binary;
using System.Text;
using MimeKit;
using MimeKit.Tnef;

namespace Corvus.Core.Documents;

/// <summary>Outlook .msg files (MS-OXMSG): MAPI properties of a compound file read into a <see cref="MailMessage"/>.</summary>
internal static class OutlookMessage
{
    private const string Properties = "__properties_version1.0", AttachPrefix = "__attach_version1.0_#", RecipientPrefix = "__recip_version1.0_#";
    private const ushort Unicode = 0x001F, String8 = 0x001E, Binary = 0x0102, Object = 0x000D, Int32 = 0x0003, Time = 0x0040;

    /// <summary>Whether the compound file holds a message: a top-level property stream and property streams beside it.</summary>
    public static bool Is(CompoundFile cf) =>
        cf.Find(Properties) != null && cf.Entries.Any(e => !e.Path.Contains('/') && e.Name.StartsWith("__substg1.0_", StringComparison.Ordinal));

    /// <summary>Reads the message; streams the file does not hold are reported as unknown in the notes.</summary>
    public static MailMessage Read(CompoundFile cf, AnalysisLimits limits, CancellationToken ct)
    {
        var m = Read(cf, "", 32, limits, 0, ct);
        m.Notes.AddRange(cf.Notes.Where(n => !m.Notes.Contains(n)));
        return m;
    }

    private static string At(string root, string name) => root.Length > 0 ? root + "/" + name : name;

    /// <summary>The message in storage <paramref name="root"/>; an embedded message's property stream has a 24-byte header, a top-level one 32.</summary>
    private static MailMessage Read(CompoundFile cf, string root, int header, AnalysisLimits limits, int depth, CancellationToken ct)
    {
        var props = PropertyValues(cf, At(root, Properties), header);
        var m = new MailMessage { Format = "Outlook message" };
        var encoding = Ansi(props, m.Notes);
        string? S(string storage, ushort id) => Str(cf, storage, id, encoding, limits);
        m.MessageClass = S(root, 0x001A);
        var headers = S(root, 0x007D);
        if (headers is { Length: > 0 })
        {
            try { m.ReadHeaders(HeaderList.Load(new MemoryStream(Encoding.UTF8.GetBytes(headers.TrimEnd() + "\r\n\r\n"), writable: false), ct)); }
            catch (FormatException ex) { m.HeadersRecorded = false; m.Notes.Add($"the transport message headers could not be read ({ex.Message}); the received chain and authentication results are unknown"); }
        }
        else
        {
            m.HeadersRecorded = false;
            m.Notes.Add("no transport message headers (PidTagTransportMessageHeaders), as in a draft or a locally saved message; the received chain and authentication results are unknown");
        }
        m.Subject = S(root, 0x0037) ?? m.Subject;
        var senderName = S(root, 0x0C1A);
        var senderAddress = S(root, 0x5D01) ?? S(root, 0x0C1F);
        if (senderName != null || senderAddress != null)
            m.From ??= senderAddress != null && senderName != null && senderName != senderAddress ? $"\"{senderName}\" <{senderAddress}>" : senderAddress ?? senderName;
        m.MessageId = S(root, 0x1035) ?? m.MessageId;
        if (Value(props, 0x0039, Time) is { } submit) m.Date ??= FileTime(submit);
        else if (Value(props, 0x0E06, Time) is { } delivered) m.Date ??= FileTime(delivered);

        foreach (var storage in Storages(cf, root, RecipientPrefix))
        {
            ct.ThrowIfCancellationRequested();
            var rp = PropertyValues(cf, At(storage, Properties), 8);
            var name = S(storage, 0x3001);
            var address = S(storage, 0x39FE) ?? S(storage, 0x3003);
            var shown = address != null && name != null && name != address ? $"\"{name}\" <{address}>" : address ?? name;
            if (shown == null) continue;
            // PidTagRecipientType: 1 To, 2 Cc, 3 Bcc.
            switch (Value(rp, 0x0C15, Int32))
            {
                case 2: m.Cc.Add(shown); break;
                case 3: m.Cc.Add(shown + " (Bcc)"); break;
                default: m.To.Add(shown); break;
            }
        }
        if (m.To.Count == 0 && S(root, 0x0E04) is { Length: > 0 } to) m.To.Add(to);
        if (m.Cc.Count == 0 && S(root, 0x0E03) is { Length: > 0 } cc) m.Cc.Add(cc);

        if (S(root, 0x1000) is { } plain) m.Bodies.Add(("txt", plain));
        var html = Bytes(cf, root, 0x1013, Binary, limits) is { } htmlBytes ? Encoding.UTF8.GetString(htmlBytes) : S(root, 0x1013);
        if (html != null) m.Bodies.Add(("html", html));
        if (Bytes(cf, root, 0x1009, Binary, limits) is { } rtf)
        {
            if (Rtf(rtf, out bool crc) is { } decoded)
            {
                m.Bodies.Add(("rtf", decoded));
                if (!crc) m.Notes.Add("the compressed RTF body fails its CRC; the decoded text may be partial");
            }
            else m.Notes.Add("the compressed RTF body (PidTagRtfCompressed) could not be decompressed; its content is unknown");
        }

        foreach (var storage in Storages(cf, root, AttachPrefix))
        {
            ct.ThrowIfCancellationRequested();
            var name = S(storage, 0x3707) ?? S(storage, 0x3704) ?? S(storage, 0x3001);
            var type = S(storage, 0x370E);
            var contentId = S(storage, 0x3712);
            byte[]? data = null;
            string? problem = null;
            MailMessage? embedded = null;
            var objectStorage = At(storage, $"__substg1.0_3701{Object:X4}");
            bool stored = cf.Entries.Any(e => e.IsStorage && e.Path.Equals(objectStorage, StringComparison.OrdinalIgnoreCase));
            // PidTagAttachMethod 5 (ATTACH_EMBEDDED_MSG): a message in the object storage.
            bool message = stored && Value(PropertyValues(cf, At(storage, Properties), 8), 0x3705, Int32) == 5;
            var label = SafeName(name, storage, message ? ".msg" : ".bin");
            if (message && depth + 1 < limits.MaxDepth) embedded = Read(cf, objectStorage, 24, limits, depth + 1, ct);
            else if (message) problem = $"an embedded message {depth + 1} levels deep, not read (the nesting limit)";
            else
            {
                try { data = Bytes(cf, storage, 0x3701, Binary, limits); }
                catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { problem = ex.Message; }
                if (data == null && problem == null)
                    problem = stored ? "stored as an OLE object storage; not extracted" : "no attachment data stream, as for an attachment by reference";
            }
            m.Attachments.Add(new MailAttachment(label, type ?? (message ? "application/vnd.ms-outlook" : null), contentId != null ? "inline" : "attachment", contentId, data, problem)
                { Embedded = embedded, Stream = data != null ? At(storage, $"__substg1.0_3701{Binary:X4}") : null });
        }
        m.FindLinks();
        return m;
    }

    private static string SafeName(string? given, string storage, string extension)
    {
        var name = Path.GetFileName((given ?? "").Replace('\\', '/'));
        name = string.Concat(name.Where(c => c >= 32 && c != 127)).Trim();
        bool unnamed = name is "" or "." or "..";
        if (unnamed) name = $"attachment-{storage[(storage.LastIndexOf('#') + 1)..]}";
        return unnamed || extension == ".msg" && !name.EndsWith(".msg", StringComparison.OrdinalIgnoreCase) ? name + extension : name;
    }

    private static IEnumerable<string> Storages(CompoundFile cf, string root, string prefix) =>
        cf.Entries.Where(e => e.IsStorage && e.Path.Equals(At(root, e.Name), StringComparison.Ordinal) && e.Name.StartsWith(prefix, StringComparison.Ordinal))
            .Select(e => e.Path).Order(StringComparer.Ordinal);

    private static byte[]? Bytes(CompoundFile cf, string storage, ushort id, ushort type, AnalysisLimits limits)
    {
        var entry = cf.Find(At(storage, $"__substg1.0_{id:X4}{type:X4}"));
        return entry == null ? null : cf.Read(entry, limits.MaxItemBytes);
    }

    private static string? Str(CompoundFile cf, string storage, ushort id, Encoding ansi, AnalysisLimits limits)
    {
        try
        {
            if (Bytes(cf, storage, id, Unicode, limits) is { } u) return Encoding.Unicode.GetString(u).TrimEnd('\0');
            if (Bytes(cf, storage, id, String8, limits) is { } a) return ansi.GetString(a).TrimEnd('\0');
        }
        catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { cf.Notes.Add(ex.Message); }
        return null;
    }

    /// <summary>Fixed-size property values of a property stream by property tag; empty when the stream is missing.</summary>
    private static Dictionary<uint, ulong> PropertyValues(CompoundFile cf, string path, int header)
    {
        var values = new Dictionary<uint, ulong>();
        if (cf.Find(path) is not { IsStorage: false } entry) return values;
        byte[] data;
        try { data = cf.Read(entry, 16L << 20); }
        catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { cf.Notes.Add(ex.Message); return values; }
        for (int at = header; at + 16 <= data.Length; at += 16)
            values.TryAdd(BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at)), BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(at + 8)));
        return values;
    }

    private static ulong? Value(Dictionary<uint, ulong> props, ushort id, ushort type) =>
        props.TryGetValue((uint)id << 16 | type, out var v) ? type == Int32 ? (uint)v : v : null;

    private static DateTimeOffset? FileTime(ulong v) =>
        v is > 0 and < 2650467743999999999 ? new DateTimeOffset(DateTime.FromFileTimeUtc((long)v)) : null;

    /// <summary>The code page of 8-bit strings: PidTagInternetCodepage, then PidTagMessageCodepage, else Windows-1252.</summary>
    private static Encoding Ansi(Dictionary<uint, ulong> props, List<string> notes)
    {
        var cp = (int?)Value(props, 0x3FDE, Int32) ?? (int?)Value(props, 0x3FFD, Int32) ?? 1252;
        Encoding? found = null;
        try { found = cp == 65001 ? Encoding.UTF8 : CodePagesEncodingProvider.Instance.GetEncoding(cp); }
        catch (ArgumentException) { }
        if (found == null) notes.Add($"8-bit strings name code page {cp}, which is not available; they are decoded as Latin-1 and may be partial");
        return found ?? Encoding.Latin1;
    }

    private static string? Rtf(byte[] compressed, out bool crc)
    {
        crc = false;
        try
        {
            var filter = new RtfCompressedToRtf();
            var output = filter.Flush(compressed, 0, compressed.Length, out int index, out int length);
            if (filter.CompressionMode is not (RtfCompressionMode.Compressed or RtfCompressionMode.Uncompressed)) return null;
            crc = filter.CompressionMode == RtfCompressionMode.Uncompressed || filter.IsValidCrc32;
            return Encoding.Latin1.GetString(output, index, length);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or InvalidOperationException) { return null; }
    }
}
