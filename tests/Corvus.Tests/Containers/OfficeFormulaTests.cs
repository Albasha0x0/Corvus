using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>Word fields, Excel DDE links and formulas, and altChunk parts in OOXML packages.</summary>
public sealed class OfficeFormulaTests
{
    private const string W = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"";
    private const string S = "xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"";
    private const string Rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    private const string Pkg = "xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"";

    private static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Word(string body, params (string Name, byte[] Data)[] more) =>
        Ooxml([("word/document.xml", U($"<w:document {W}><w:body><w:p>{body}</w:p></w:body></w:document>")), .. more]);

    private static string Run(string instruction) => $"<w:r><w:instrText xml:space=\"preserve\">{instruction}</w:instrText></w:r>";

    private static string Field(params string[] instructionRuns) =>
        "<w:r><w:fldChar w:fldCharType=\"begin\"/></w:r>" + string.Concat(instructionRuns.Select(Run))
        + "<w:r><w:fldChar w:fldCharType=\"separate\"/></w:r><w:r><w:t>PAGE</w:t></w:r><w:r><w:fldChar w:fldCharType=\"end\"/></w:r>";

    private static byte[] Chunked(string target, byte[] part) =>
        Word("<w:altChunk xmlns:r=\"" + Rel + "\" r:id=\"rId9\"/>",
            ("word/_rels/document.xml.rels", U($"<Relationships {Pkg}><Relationship Id=\"rId9\" Type=\"{Rel}/aFChunk\" Target=\"{target}\"/></Relationships>")),
            ("word/" + target, part));

    private static byte[] Sheet(params (string Cell, string Formula)[] cells) =>
        Ooxml(("xl/workbook.xml", U($"<workbook {S} xmlns:r=\"{Rel}\"><sheets><sheet name=\"Quote\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>")),
            ("xl/_rels/workbook.xml.rels", U($"<Relationships {Pkg}><Relationship Id=\"rId1\" Type=\"{Rel}/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>")),
            ("xl/worksheets/sheet1.xml", U($"<worksheet {S}><sheetData><row r=\"1\">{string.Concat(cells.Select(c => $"<c r=\"{c.Cell}\"><f>{c.Formula}</f><v>1</v></c>"))}</row></sheetData></worksheet>")));

    private static IReadOnlyList<Finding> Findings(byte[] data, string name) =>
        new OfficeFileView().Inspect(new FileInput(name, data, Blob.Identify(data)), default)?.Findings ?? [];

    [Fact]
    public void A_ddeauto_field_split_across_runs_is_noteworthy_at_its_part()
    {
        var f = Assert.Single(Findings(Word(Field("DDEAUTO ", "c:\\\\windows\\\\system32\\\\", "notepad.exe")), "a.docx"), x => x.Rule == "office/dde");
        Assert.Equal("noteworthy", f.Level);
        Assert.Equal("word/document.xml", f.Location);
        Assert.Contains("DDEAUTO c:\\\\windows\\\\system32\\\\notepad.exe", f.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void A_dde_simple_field_in_a_footer_is_found_at_the_footer()
    {
        var footer = U($"<w:ftr {W}><w:p><w:fldSimple w:instr=\" DDE calc.exe x \"><w:r><w:t>x</w:t></w:r></w:fldSimple></w:p></w:ftr>");
        var f = Assert.Single(Findings(Word("", ("word/footer1.xml", footer)), "a.docx"), x => x.Rule == "office/dde");
        Assert.Equal("word/footer1.xml", f.Location);
    }

    [Fact]
    public void A_quotation_with_page_date_and_https_hyperlink_fields_has_nothing_above_info()
    {
        var doc = Word(Field("PAGE") + Field("DATE \\@ \"d MMMM yyyy\"") + Field("HYPERLINK \"https://example.test/terms\""));
        var findings = Findings(doc, "quote.docx");
        Assert.DoesNotContain(findings, f => f.Level != "info");
        Assert.Single(findings, f => f.Rule == "office/field");
    }

    [Fact]
    public void An_include_field_with_a_remote_target_is_review_and_a_local_one_is_info()
    {
        var doc = Word(Field("INCLUDEPICTURE \"https://example.test/a.png\"") + Field("INCLUDETEXT \"\\\\\\\\host\\\\share\\\\a.docx\"") + Field("INCLUDEPICTURE \"logo.png\""));
        Assert.Equal(["review", "review", "info"], Findings(doc, "a.docx").Where(f => f.Rule == "office/field").Select(f => f.Level));
    }

    [Fact]
    public void A_hyperlink_field_to_a_local_handler_scheme_is_a_local_handler_finding()
    {
        var doc = Word(Field("HYPERLINK \"ms-msdt:/id PCWDiagnostic\""));
        Assert.Contains(Findings(doc, "a.docx"), f => f is { Rule: "link/local-handler", Level: "review", Location: "word/document.xml" });
    }

    [Fact]
    public void A_workbook_dde_link_is_noteworthy_at_its_external_link_part()
    {
        var book = Ooxml(("xl/workbook.xml", U($"<workbook {S}/>")),
            ("xl/externalLinks/externalLink1.xml", U($"<externalLink {S}><ddeLink ddeService=\"cmd\" ddeTopic=\"/c calc\"><ddeItems><ddeItem name=\"A1\"/></ddeItems></ddeLink></externalLink>")));
        var f = Assert.Single(Findings(book, "a.xlsx"), x => x.Rule == "office/dde");
        Assert.Equal("noteworthy", f.Level);
        Assert.Equal("xl/externalLinks/externalLink1.xml", f.Location);
        Assert.Contains("cmd|/c calc", f.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void A_webservice_formula_is_review_at_its_cell()
    {
        var f = Assert.Single(Findings(Sheet(("B2", "WEBSERVICE(\"https://example.test\")")), "a.xlsx"), x => x.Rule == "office/formula");
        Assert.Equal("review", f.Level);
        Assert.EndsWith(":Quote!B2", f.Location, StringComparison.Ordinal);
    }

    [Fact]
    public void A_dde_style_formula_reference_is_noteworthy_at_its_cell()
    {
        var f = Assert.Single(Findings(Sheet(("A1", "cmd|'/c calc'!A1")), "a.xlsx"), x => x.Rule == "office/dde");
        Assert.EndsWith(":Quote!A1", f.Location, StringComparison.Ordinal);
    }

    [Fact]
    public void A_hyperlink_formula_is_info_and_its_handler_target_is_review()
    {
        var findings = Findings(Sheet(("A1", "HYPERLINK(\"https://example.test\",\"site\")"), ("A2", "HYPERLINK(\"search-ms:query=a\",\"x\")")), "a.xlsx");
        Assert.Equal(["info", "info"], findings.Where(f => f.Rule == "office/formula").Select(f => f.Level));
        Assert.Single(findings, f => f.Rule == "link/local-handler" && f.Location!.EndsWith(":Quote!A2", StringComparison.Ordinal));
    }

    [Fact]
    public void A_workbook_with_sum_formulas_and_a_chart_reports_nothing_noteworthy()
    {
        var book = Ooxml(("xl/workbook.xml", U($"<workbook {S}/>")),
            ("xl/worksheets/sheet1.xml", U($"<worksheet {S}><sheetData><row r=\"1\"><c r=\"A1\"><f>SUM(B1:B9)</f></c></row></sheetData></worksheet>")),
            ("xl/charts/chart1.xml", U("<c:chartSpace xmlns:c=\"http://schemas.openxmlformats.org/drawingml/2006/chart\"/>")));
        Assert.Empty(Findings(book, "a.xlsx"));
    }

    [Fact]
    public void An_altchunk_html_part_is_read_and_its_targets_carry_the_chunk_path()
    {
        var doc = Chunked("afchunk.html", U("<html><a href=\"search-ms:query=x\">x</a></html>"));
        Assert.Contains(Findings(doc, "a.docx"), f => f.Rule == "link/local-handler" && f.Location!.StartsWith("word/afchunk.html", StringComparison.Ordinal));
    }

    [Fact]
    public void An_altchunk_mhtml_part_is_read_and_its_html_targets_carry_the_chunk_path()
    {
        var mime = "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<html><a href=\"search-ms:query=x\">x</a></html>\r\n--b--\r\n";
        var doc = Chunked("afchunk.mht", U(mime));
        Assert.Contains(Findings(doc, "a.docx"), f => f.Rule == "link/local-handler" && f.Location!.StartsWith("word/afchunk.mht", StringComparison.Ordinal));
    }

    [Fact]
    public void An_altchunk_docx_part_carries_the_findings_of_the_inner_document()
    {
        var f = Assert.Single(Findings(Chunked("afchunk.docx", Word(Field("DDEAUTO calc.exe"))), "a.docx"), x => x.Rule == "office/dde");
        Assert.Equal("word/afchunk.docx/word/document.xml", f.Location);
    }

    [Fact]
    [FuzzEntry(typeof(OfficeFormulas))]
    public void Fuzzed_fields_formulas_and_chunks_never_throw_past_a_tool_error()
    {
        var seeds = new[]
        {
            Word(Field("DDEAUTO calc.exe")), Sheet(("A1", "WEBSERVICE(\"https://example.test\")")), Chunked("afchunk.html", U("<a href=\"x\">")),
        };
        foreach (var seed in seeds)
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Findings(b, "f.docx"); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures.Take(20)));
        }
    }
}
