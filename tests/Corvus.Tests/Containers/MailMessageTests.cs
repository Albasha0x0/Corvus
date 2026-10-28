using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Mail files: headers, received chain, recorded authentication results, links and attachments of .eml and .msg messages.</summary>
public sealed class MailMessageTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static readonly byte[] Report = ContainerFixtures.Zip(("notes/readme.txt", "quarterly figures"u8.ToArray()));

    /// <summary>A multipart message with plain and HTML bodies, a zip attachment and a part in an unknown transfer encoding.</summary>
    internal static byte[] Eml()
    {
        var zip = Convert.ToBase64String(Report, Base64FormattingOptions.InsertLineBreaks);
        var text = $"""
            Return-Path: <bounce@mail.example.org>
            Received: from relay.example.net (relay.example.net [192.0.2.10])
            	by mx.example.com (Postfix) with ESMTPS id 4AbC12
            	for <alice@example.com>; Tue, 6 Oct 2026 10:00:05 +0000
            Received: from sender.example.org (sender.example.org [198.51.100.7])
            	by relay.example.net with ESMTP id 77xyz; Tue, 6 Oct 2026 10:00:01 +0000
            Authentication-Results: mx.example.com; spf=pass (sender ok) smtp.mailfrom=mail.example.org;
            	dkim=pass header.d=example.org header.s=sel1; dmarc=pass header.from=example.org
            ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.net; s=arc1; b=AAAA
            ARC-Message-Signature: i=1; a=rsa-sha256; d=example.net; s=arc1; h=from:to:subject; bh=BBBB; b=CCCC
            ARC-Authentication-Results: i=1; relay.example.net; spf=pass smtp.mailfrom=mail.example.org
            Received-SPF: pass (relay.example.net: domain of mail.example.org designates 198.51.100.7) client-ip=198.51.100.7;
            DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=sel1;
            	h=from:to:subject:date; bh=DDDD; b=EEEE
            From: Bob Sender <bob@example.org>
            To: Alice <alice@example.com>
            Cc: carol@example.com
            Subject: Quarterly report
            Date: Tue, 6 Oct 2026 09:59:58 +0000
            Message-ID: <report-1@example.org>
            MIME-Version: 1.0
            X-Mailer: Sample Mailer 1.0
            Content-Type: multipart/mixed; boundary="outer"

            --outer
            Content-Type: multipart/alternative; boundary="inner"

            --inner
            Content-Type: text/plain; charset=utf-8

            The report is attached. Details: https://www.example.org/reports/q3?id=7.
            --inner
            Content-Type: text/html; charset=utf-8

            <p>See <a href="https://portal.example.net/view?a=1&amp;b=2">the portal</a>.</p>
            --inner--
            --outer
            Content-Type: application/zip; name="report.zip"
            Content-Disposition: attachment; filename="report.zip"
            Content-Transfer-Encoding: base64

            {zip}
            --outer
            Content-Type: application/octet-stream; name="data.bin"
            Content-Disposition: attachment; filename="data.bin"
            Content-Transfer-Encoding: x-private

            raw-bytes
            --outer--

            """;
        return Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n").Replace("\n", "\r\n"));
    }

    private static byte[] U16(string s) => Encoding.Unicode.GetBytes(s);

    /// <summary>A property stream: a header of <paramref name="header"/> bytes, then 16-byte fixed-size entries.</summary>
    private static byte[] Props(int header, params (uint Tag, ulong Value)[] values)
    {
        var o = new MemoryStream();
        o.Write(new byte[header]);
        foreach (var (tag, value) in values)
        {
            o.Write(BitConverter.GetBytes(tag)); o.Write(BitConverter.GetBytes(6u)); o.Write(BitConverter.GetBytes(value));
        }
        return o.ToArray();
    }

    /// <summary>A .msg with one recipient and two attachments; transport headers and a third, embedded message, attachment on request.</summary>
    internal static byte[] Msg(bool headers, bool embedded = false)
    {
        var submit = (ulong)new DateTime(2026, 10, 6, 9, 59, 58, DateTimeKind.Utc).ToFileTimeUtc();
        var streams = new List<(string, byte[])>
        {
            ("__properties_version1.0", Props(32, (0x00390040, submit))),
            ("__substg1.0_001A001F", U16("IPM.Note")),
            ("__substg1.0_0037001F", U16("Quarterly report")),
            ("__substg1.0_0C1A001F", U16("Bob Sender")),
            ("__substg1.0_5D01001F", U16("bob@example.org")),
            ("__substg1.0_1000001F", U16("Figures at https://www.example.org/reports/q3 today.")),
            ("__recip_version1.0_#00000000/__properties_version1.0", Props(8, (0x0C150003, 1))),
            ("__recip_version1.0_#00000000/__substg1.0_3001001F", U16("Alice")),
            ("__recip_version1.0_#00000000/__substg1.0_39FE001F", U16("alice@example.com")),
            ("__attach_version1.0_#00000000/__properties_version1.0", Props(8)),
            ("__attach_version1.0_#00000000/__substg1.0_3707001F", U16("report.zip")),
            ("__attach_version1.0_#00000000/__substg1.0_370E001F", U16("application/zip")),
            ("__attach_version1.0_#00000000/__substg1.0_37010102", Report),
            ("__attach_version1.0_#00000001/__properties_version1.0", Props(8)),
            ("__attach_version1.0_#00000001/__substg1.0_3707001F", U16("notes.txt")),
            ("__attach_version1.0_#00000001/__substg1.0_37010102", "plain notes"u8.ToArray()),
        };
        if (headers)
            streams.Add(("__substg1.0_007D001F", U16("Received: from relay.example.net by mx.example.com with ESMTP id 9; Tue, 6 Oct 2026 10:00:05 +0000\r\n" +
                "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=example.org; dkim=none\r\n")));
        if (embedded)
        {
            const string at = "__attach_version1.0_#00000002", inner = at + "/__substg1.0_3701000D";
            streams.AddRange(
            [
                (at + "/__properties_version1.0", Props(8, (0x37050003, 5))),
                (at + "/__substg1.0_3707001F", U16("Forwarded")),
                (inner + "/__properties_version1.0", Props(24)),
                (inner + "/__substg1.0_0037001F", U16("Original figures")),
                (inner + "/__substg1.0_1000001F", U16("Earlier draft.")),
                (inner + "/__attach_version1.0_#00000000/__properties_version1.0", Props(8)),
                (inner + "/__attach_version1.0_#00000000/__substg1.0_3707001F", U16("draft.zip")),
                (inner + "/__attach_version1.0_#00000000/__substg1.0_37010102", Report),
            ]);
        }
        return DocumentFixtures.Compound(streams);
    }

    private static MailFileView.Facts View(byte[] data, string name) =>
        (MailFileView.Facts)new MailFileView().Inspect(new FileInput(name, data, Blob.Identify(data)), default)!.Detail;

    [Fact]
    public void An_eml_reads_headers_the_received_chain_and_recorded_results()
    {
        var f = View(Eml(), "report.eml");
        Assert.Equal(("MIME message", "Quarterly report", "<bounce@mail.example.org>"), (f.Format, f.Subject, f.ReturnPath));
        Assert.Equal("\"Bob Sender\" <bob@example.org>", f.From);
        Assert.Equal(["\"Alice\" <alice@example.com>"], f.To);
        Assert.Equal(new DateTimeOffset(2026, 10, 6, 9, 59, 58, TimeSpan.Zero), f.Date);
        Assert.Equal(("report-1@example.org", "Sample Mailer 1.0"), (f.MessageId, f.Mailer));
        Assert.Equal(2, f.Received.Count);
        var newest = f.Received[0];
        Assert.Equal(("relay.example.net", "mx.example.com", "ESMTPS", "4AbC12", "alice@example.com"), (newest.From, newest.By, newest.With, newest.Id, newest.For));
        Assert.Equal(new DateTimeOffset(2026, 10, 6, 10, 0, 5, TimeSpan.Zero), newest.Date);
        Assert.Equal("sender.example.org", f.Received[1].From);
        Assert.Contains(f.Authentication, a => a is { Header: "Authentication-Results", AuthServId: "mx.example.com", Method: "dkim", Result: "pass" });
        Assert.Contains(f.Authentication, a => a is { Header: "Authentication-Results", Method: "dmarc", Result: "pass" });
        Assert.Contains(f.Authentication, a => a is { Header: "ARC-Authentication-Results", Instance: 1, AuthServId: "relay.example.net", Method: "spf" });
        Assert.Contains(f.Authentication, a => a is { Header: "Received-SPF", Method: "spf", Result: "pass" });
        Assert.Contains(f.Signatures, s => s is { Header: "DKIM-Signature", Domain: "example.org", Selector: "sel1", Algorithm: "rsa-sha256", SignedHeaders: "from:to:subject:date" });
        Assert.Contains(f.Signatures, s => s is { Header: "ARC-Seal", Instance: 1, ChainValidation: "none" });
        Assert.Equal(["https://www.example.org/reports/q3?id=7", "https://portal.example.net/view?a=1&b=2"], f.Links);
    }

    [Fact]
    public void An_eml_zip_attachment_unpacks_and_its_member_is_reachable()
    {
        var c = Containers.Open(Eml(), "report.eml", AnalysisLimits.Default, default);
        Assert.Equal("MIME message", c.Kind);
        var zip = Assert.Single(c.Items, i => i.Name == "attachments/report.zip");
        Assert.Equal(Report, zip.Bytes);
        Assert.Contains(c.Items, i => i.Name == "body.txt");
        var inner = Containers.Open(zip.Bytes, "report.zip", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("quarterly figures"u8.ToArray(), Assert.Single(inner.Items, i => i.Name == "notes/readme.txt").Bytes);

        var path = Path.Combine(_dir.Path, "report.eml");
        File.WriteAllBytes(path, Eml());
        var r = new UnpackService(_workspace).Unpack(path, _dir.File("out"), load: false, AnalysisLimits.Default, default);
        Assert.Contains(r.Files, f => f.Path.Replace('\\', '/').EndsWith("notes/readme.txt", StringComparison.Ordinal));
    }

    [Fact]
    public void A_part_in_an_unknown_transfer_encoding_is_kept_as_stored_and_named()
    {
        var f = View(Eml(), "report.eml");
        var part = Assert.Single(f.Attachments, a => a.Name == "data.bin");
        Assert.Contains("x-private", part.Problem);
        Assert.NotNull(part.Size);
    }

    [Fact]
    public void A_msg_lists_its_attachments_recipients_and_transport_headers()
    {
        var f = View(Msg(headers: true), "report.msg");
        Assert.Equal(("Outlook message", "IPM.Note", "Quarterly report"), (f.Format, f.MessageClass, f.Subject));
        Assert.Equal("\"Bob Sender\" <bob@example.org>", f.From);
        Assert.Equal(["\"Alice\" <alice@example.com>"], f.To);
        Assert.Equal(new DateTimeOffset(2026, 10, 6, 9, 59, 58, TimeSpan.Zero), f.Date);
        Assert.Equal(["report.zip", "notes.txt"], f.Attachments.Select(a => a.Name));
        Assert.Equal(("application/zip", (long?)Report.Length, "zip"), (f.Attachments[0].ContentType, f.Attachments[0].Size, f.Attachments[0].Kind));
        Assert.True(f.HeadersRecorded);
        Assert.Equal(("relay.example.net", "mx.example.com"), (f.Received[0].From, f.Received[0].By));
        Assert.Contains(f.Authentication, a => a is { Method: "spf", Result: "fail" });
        Assert.Equal(["https://www.example.org/reports/q3"], f.Links);

        var c = Containers.Open(Msg(headers: true), "report.msg", AnalysisLimits.Default, default);
        Assert.Equal("Outlook message", c.Kind);
        Assert.Equal(Report, Assert.Single(c.Items, i => i.Name == "attachments/report.zip").Bytes);
        Assert.Contains(c.Entries!, e => e.Path == "attachments/notes.txt");
    }

    [Fact]
    public void An_embedded_message_attachment_is_read_in_place_with_its_own_attachments()
    {
        var f = View(Msg(headers: true, embedded: true), "report.msg");
        var forwarded = Assert.Single(f.Attachments, a => a.Name == "Forwarded.msg");
        Assert.Equal(("embedded Outlook message", null), (forwarded.Kind, forwarded.Problem));

        var c = Containers.Open(Msg(headers: true, embedded: true), "report.msg", AnalysisLimits.Default, default);
        Assert.Equal("Earlier draft.", Encoding.UTF8.GetString(Assert.Single(c.Items, i => i.Name == "attachments/Forwarded.msg/body.txt").Bytes));
        Assert.Equal(Report, Assert.Single(c.Items, i => i.Name == "attachments/Forwarded.msg/attachments/draft.zip").Bytes);
    }

    [Fact]
    public void A_msg_still_lists_its_compound_file_streams()
    {
        var c = Containers.Open(Msg(headers: true), "report.msg", AnalysisLimits.Default, default);
        Assert.Contains(c.Entries!, e => e.Path == "streams/__substg1.0_0037001F" && e.Size == U16("Quarterly report").Length);
        Assert.Contains(c.Entries!, e => e.Path == "streams/__attach_version1.0_#00000000/__substg1.0_37010102");
        var all = Containers.Open(Msg(headers: true), "report.msg", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(U16("IPM.Note"), Assert.Single(all.Items, i => i.Name == "streams/__substg1.0_001A001F").Bytes);
    }

    [Fact]
    public void A_msg_without_transport_headers_reports_the_chain_as_unknown()
    {
        var f = View(Msg(headers: false), "draft.msg");
        Assert.False(f.HeadersRecorded);
        Assert.Empty(f.Received);
        Assert.Contains(f.Notes, n => n.Contains("unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void Text_without_message_headers_is_not_taken_for_mail()
    {
        Assert.False(MailMessage.LooksLikeMime("key: value\r\nother: 1\r\n\r\nbody"u8));
        Assert.False(MailMessage.LooksLikeMime("Subject: only one known header\r\n\r\n"u8));
        Assert.True(MailMessage.LooksLikeMime("From: a@example.org\r\nSubject: s\r\n\r\n"u8));
        Assert.Null(new MailFileView().Inspect(new FileInput("a.txt", "plain words\n"u8.ToArray(), "text"), default));
    }

    [Fact]
    [FuzzEntry(typeof(MailReader), typeof(MailFileView))]
    public void Fuzzed_mail_files_never_throw_past_a_tool_error()
    {
        foreach (var (seed, name) in new[] { (Eml(), "a.eml"), (Msg(headers: true, embedded: true), "a.msg") })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, name, AnalysisLimits.Default, default); } catch (ToolError) { }
                try { new MailFileView().Inspect(new FileInput(name, b, Blob.Identify(b)), default); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }
}
