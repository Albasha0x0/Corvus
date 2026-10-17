using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>PDF objects, filters, actions, scripts, embedded files, pdfid counts and the empty-password security handler.</summary>
public sealed class PdfDocumentTests
{
    private const string Script = "var s = unescape('%41%42');\nthis.exportDataObject({ cName: 'module.dll', nLaunch: 0 });\neval(s);\n";

    private static PdfFixtures Base() => new PdfFixtures()
        .Add(1, "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS 5 0 R >> /Names << /EmbeddedFiles << /Names [(module.dll) 6 0 R] >> >> >>")
        .Add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Add(3, "<< /Type /Page /Parent 2 0 R /AA << /O 4 0 R >> /Annots [8 0 R] >>")
        .Add(4, "<< /S /Launch /Win << /F (notepad.exe) /P (readme.txt) >> >>")
        .Add(5, "<< /Filter [/ASCIIHexDecode /FlateDecode] >>", Encoding.ASCII.GetBytes(Convert.ToHexString(PdfFixtures.Deflate(Script)) + ">"))
        .Add(6, "<< /Type /Filespec /F (module.dll) /UF (module.dll) /Desc (the module) /EF << /F 7 0 R >> >>")
        .Add(7, "<< /Type /EmbeddedFile /Filter /FlateDecode >>", PdfFixtures.Deflate(Payload))
        .Add(8, "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (http://example.test/next) >> >>");

    private static readonly byte[] Payload = ContainerFixtures.Module("Embedded");

    private static PdfFileView.Facts View(byte[] pdf) =>
        (PdfFileView.Facts)new PdfFileView().Inspect(new FileInput("a.pdf", pdf, Blob.Identify(pdf)), default)!.Detail;

    [Fact]
    public void Actions_name_what_triggers_them()
    {
        var f = View(Base().Build());
        Assert.Contains(f.Actions, a => a is { Object: 1, Type: "JavaScript", Trigger: "object 1 /OpenAction (document opens)" });
        Assert.Contains(f.Actions, a => a is { Object: 4, Type: "Launch", Target: "notepad.exe readme.txt", Trigger: "object 3 /AA/O (page or annotation opens)" });
        Assert.Contains(f.Actions, a => a is { Object: 8, Type: "URI", Target: "http://example.test/next", Trigger: "object 8 /A (link, outline item or field activated)" });
    }

    [Fact]
    public void Scripts_are_decoded_through_their_filter_chain_and_scanned_by_line()
    {
        var f = View(Base().Build());
        var s = Assert.Single(f.Scripts);
        Assert.Equal(Script.Length, s.Length);
        Assert.Contains(f.Findings, x => x is { Keyword: "unescape(", Location: "object 1:1" });
        Assert.Contains(f.Findings, x => x is { Keyword: "exportDataObject(", Location: "object 1:2" });
        Assert.Contains(f.Findings, x => x is { Keyword: "eval(", Location: "object 1:3" });
        Assert.Contains(f.Findings, x => x is { Type: "Suspicious", Keyword: "Launch" });
    }

    [Fact]
    public void Embedded_files_come_out_under_their_file_specification_name()
    {
        var pdf = Base().Build();
        var e = Assert.Single(View(pdf).EmbeddedFiles);
        Assert.Equal(("module.dll", "the module", ".NET assembly"), (e.Name, e.Description, e.Kind));
        var c = Containers.Open(pdf, "a.pdf", AnalysisLimits.Default, default);
        Assert.Equal(Payload, c.Items.Single(i => i.Name == "EmbeddedFiles/module.dll").Bytes);
        Assert.Equal(Script, Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "JavaScript/object1.js").Bytes));
    }

    [Fact]
    public void A_file_specification_inline_in_the_name_tree_names_its_file()
    {
        var pdf = new PdfFixtures()
            .Add(1, "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(a.txt) << /Type /Filespec /UF (report.txt) /EF << /F 3 0 R >> >>] >> >> >>")
            .Add(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Add(3, "<< /Type /EmbeddedFile >>", "hello"u8.ToArray()).Build();
        Assert.Equal("report.txt", Assert.Single(View(pdf).EmbeddedFiles).Name);
    }

    [Fact]
    public void Pdfid_counts_keywords_and_names_hidden_with_hex_escapes()
    {
        var pdf = new PdfFixtures()
            .Add(1, "<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>")
            .Add(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Add(3, "<< /S /J#61vaScript /J#53 (app.alert(1)) >>").Build();
        var f = View(pdf);
        var k = f.Keywords.ToDictionary(x => x.Keyword);
        Assert.Equal((3, 0), (k["obj"].Count, k["obj"].Escaped));
        Assert.Equal((1, 1), (k["/JavaScript"].Count, k["/JavaScript"].Escaped));
        Assert.Equal((1, 1), (k["/JS"].Count, k["/JS"].Escaped));
        Assert.Equal(1, k["/OpenAction"].Count);
        Assert.Contains(f.Actions, a => a is { Object: 3, Type: "JavaScript", Trigger: "object 1 /OpenAction (document opens)" });
        Assert.Contains(f.Findings, x => x is { Keyword: "/JavaScript" } && x.Description.Contains("escapes", StringComparison.Ordinal));
    }

    [Fact]
    public void Objects_in_object_streams_and_incremental_updates_are_read()
    {
        // object 3 lives in object stream 4; an update replaces the catalog to point its OpenAction at it
        var inner = "3 0 << /S /JavaScript /JS (app.launchURL\\('http://example.test'\\)) >>";
        var header = "3 0 ";
        var objstm = Encoding.Latin1.GetBytes("3 0\n" + inner[header.Length..]);
        var pdf = new PdfFixtures()
            .Add(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Add(2, "<< /Type /Pages /Kids [] /Count 0 >>")
            .Add(4, $"<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>", PdfFixtures.Deflate(objstm))
            .Update((1, "<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>"))
            .Build();
        var f = View(pdf);
        Assert.Equal(1, f.Updates);
        Assert.Equal(1, f.ObjectStreams);
        Assert.Contains(f.Actions, a => a is { Object: 3, Type: "JavaScript", Trigger: "object 1 /OpenAction (document opens)" });
        Assert.Contains(f.Findings, x => x is { Keyword: "launchURL(", Location: "object 3:1" });
    }

    [Fact]
    public void A_file_encrypted_with_the_empty_user_password_is_decrypted()
    {
        var builder = Base();
        builder.EncryptRc4(9);
        var f = View(builder.Build());
        Assert.Equal("RC4 128-bit, revision 3", f.Encryption);
        Assert.Contains(f.Actions, a => a is { Type: "Launch", Target: "notepad.exe readme.txt" });
        Assert.Equal(Script.Length, Assert.Single(f.Scripts).Length);
        Assert.Equal(".NET assembly", Assert.Single(f.EmbeddedFiles).Kind);
    }

    [Fact]
    public void Filters_decode_the_spec_examples()
    {
        // ISO 32000-1 7.4.4.2: "-----A---B" with early change
        Assert.Equal("-----A---B"u8.ToArray(), PdfFilters.Lzw([0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01], true, 1 << 20));
        Assert.Equal("Hello"u8.ToArray(), PdfFilters.Ascii85("87cURDZ~>"u8.ToArray()));
        Assert.Equal("abc\0\0\0\0\0"u8.ToArray(), PdfFilters.Ascii85("@:E^Hz~>"u8.ToArray()));
        Assert.Equal("aaaaabc"u8.ToArray(), PdfFilters.RunLength([0xFC, (byte)'a', 0x01, (byte)'b', (byte)'c', 0x80], 1 << 20));
        Assert.Equal("Hi"u8.ToArray(), PdfFilters.AsciiHex("48 69>"u8.ToArray()));
    }

    [Fact]
    [FuzzEntry(typeof(PdfReader), typeof(PdfFileView), typeof(PdfFile), typeof(PdfDocument), typeof(PdfFilters), typeof(PdfSecurity))]
    public void Fuzzed_pdfs_never_throw_past_a_tool_error()
    {
        var plain = Base().Build();
        var encrypted = Base();
        encrypted.EncryptRc4(9);
        foreach (var seed in new[] { plain, encrypted.Build() })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, "a.pdf", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
                try { new PdfFileView().Inspect(new FileInput("a.pdf", b, Blob.Identify(b)), default); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }
}
