using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>OLE compound files and OOXML packages: VBA sources, Excel 4.0 macros, OLE Package objects and the macro findings.</summary>
public sealed class OfficeDocumentTests
{
    private const string StartupMacro = "Sub AutoOpen()\r\n  Dim s\r\n  s = \"https://example.test/readme.txt\"\r\n  Shell \"cmd /c echo \" & s, vbHide\r\n  x = \"6E6F74657061642E657865\"\r\nEnd Sub\r\n";

    private static byte[] WordDocument() => Compound([("WordDocument", new byte[600]), .. VbaStreams("Macros/", ("ThisDocument", "document", ""), ("Module1", "standard", StartupMacro))]);

    private static OfficeFileView.Facts? View(byte[] data, string name = "doc.doc") =>
        new OfficeFileView().Inspect(new FileInput(name, data, Blob.Identify(data)), default)?.Detail as OfficeFileView.Facts;

    [Fact]
    public void Ovba_compression_round_trips_with_copy_tokens_across_chunks()
    {
        var text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 900).Select(i => $"Line {i % 37}: Shell \"cmd\"\r\n")));
        var packed = Compress(text);
        Assert.True(packed.Length < text.Length / 3, $"{packed.Length} of {text.Length}");
        Assert.Equal(text, VbaProject.Decompress(packed, 1 << 20));
    }

    [Fact]
    public void A_word_document_lists_its_streams_and_writes_the_module_sources()
    {
        var c = Containers.Open(WordDocument(), "doc.doc", AnalysisLimits.Default, default, allFiles: false);
        Assert.Equal("Word document", c.Kind);
        var module = Assert.Single(c.Items, i => i.Name == "Macros/VBA/Module1.bas");
        Assert.Contains("Shell \"cmd /c echo \" & s, vbHide", Encoding.UTF8.GetString(module.Bytes));
        Assert.Contains(c.Items, i => i.Name == "Macros/VBA/ThisDocument.cls");
        Assert.Contains(c.Entries!, e => e.Path == "Macros/VBA/dir");
        Assert.Contains(c.Entries!, e => e.Path == "WordDocument" && e.Size == 600);
        // Not a binary: listed, not extracted.
        Assert.DoesNotContain(c.Items, i => i.Name == "WordDocument");
    }

    [Fact]
    public void Findings_name_autorun_entry_points_calls_and_addresses_with_their_line()
    {
        var f = View(WordDocument())!;
        Assert.Equal("Word document", f.Format);
        var project = Assert.Single(f.Projects);
        Assert.Equal(["ThisDocument:document", "Module1:standard"], project.Modules.Select(m => $"{m.Name}:{m.Type}"));
        var rows = f.Findings.ToDictionary(r => (r.Type, r.Keyword));
        Assert.Equal("Module1:2", rows[("AutoExec", "AutoOpen")].Location);
        Assert.Equal("Module1:5", rows[("Suspicious", "Shell")].Location);
        Assert.True(rows.ContainsKey(("Suspicious", "vbHide")));
        Assert.True(rows.ContainsKey(("IOC", "https://example.test/readme.txt")));
        // The hex string decodes to a program name, found again under Hex.
        Assert.Equal("Hex", rows[("IOC", "notepad.exe")].Decoded);
        Assert.True(rows.ContainsKey(("Hex String", "notepad.exe")));
    }

    [Fact]
    public void Macro_findings_read_as_shared_records_and_a_decoded_keyword_beside_autorun_is_noteworthy()
    {
        var data = WordDocument();
        var view = new OfficeFileView().Inspect(new FileInput("doc.doc", data, Blob.Identify(data)), default)!;
        Assert.Contains(view.Findings, f => f is { Rule: "office/autoexec", Level: "info", Location: "Module1:2" });
        Assert.Contains(view.Findings, f => f is { Rule: "office/suspicious", Level: "review", Category: "keyword" } && f.Evidence.StartsWith("Shell: ", StringComparison.Ordinal));
        Assert.Contains(view.Findings, f => f is { Rule: "office/encoded-string", Level: "info" });

        MacroFinding auto = new("AutoExec", "AutoOpen", "runs when opened"), hidden = new("Suspicious", "Shell", "runs a program") { Decoded = "Base64" };
        Assert.Equal("noteworthy", FindingRules.FromMacros([auto, hidden], "office").Single(f => f.Rule == "office/suspicious").Level);
        Assert.Equal("review", FindingRules.FromMacros([hidden], "office").Single().Level);
        Assert.Equal("review", FindingRules.FromMacros([hidden with { Decoded = null }, auto], "office").Single(f => f.Rule == "office/suspicious").Level);
    }

    [Fact]
    public void A_module_with_a_chr_chain_shows_the_folded_string()
    {
        var data = Compound([("WordDocument", new byte[600]), .. VbaStreams("Macros/", ("Module1", "standard", "Sub AutoOpen()\r\n  s = Chr(104) & Chr(105) & \"-corvus\"\r\n  MsgBox s\r\nEnd Sub\r\n"))]);
        var module = Assert.Single(View(data)!.Projects.Single().Modules);
        Assert.Contains("\"hi-corvus\"", module.Plain);
    }

    [Fact]
    public void A_module_without_constants_to_fold_has_no_peeled_text()
    {
        var data = Compound([("WordDocument", new byte[600]), .. VbaStreams("Macros/", ("Module1", "standard", "Sub AutoOpen()\r\n  MsgBox Now\r\nEnd Sub\r\n"))]);
        Assert.Null(Assert.Single(View(data)!.Projects.Single().Modules).Plain);
    }

    [Fact]
    public void A_macro_enabled_ooxml_document_is_read_through_its_vba_project_part()
    {
        var bin = Compound(VbaStreams("", ("ThisDocument", "document", "Private Sub Document_Open()\r\n  CreateObject(\"WScript.Shell\").Run \"calc\"\r\nEnd Sub\r\n")));
        var rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"http://example.test/t.dotm\" TargetMode=\"External\"/></Relationships>";
        var docm = Ooxml(("word/document.xml", "<w:document/>"u8.ToArray()), ("word/vbaProject.bin", bin), ("word/_rels/settings.xml.rels", Encoding.UTF8.GetBytes(rels)));
        var f = View(docm, "a.docm")!;
        Assert.Equal("Word document (OOXML)", f.Format);
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Document_Open", Location: "ThisDocument:2" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "WScript.Shell" });
        Assert.Contains(f.Findings, r => r is { Type: "IOC", Keyword: "http://example.test/t.dotm", Location: "word/_rels/settings.xml.rels" });

        // Unpack follows the part into the compound file.
        var c = Containers.Open(bin, "vbaProject.bin", AnalysisLimits.Default, default);
        Assert.Equal("VBA project", c.Kind);
        Assert.Contains(c.Items, i => i.Name == "VBA/ThisDocument.cls");
    }

    private const string RunSource = "Sub AutoOpen()\r\n  Shell \"calc.exe\"\r\n  MsgBox \"hello world\"\r\nEnd Sub\r\n";

    private static OfficeFileView.Facts Compiled(string source, string cached, ushort version = 0x0097, Func<List<(string, byte[])>, List<(string, byte[])>>? edit = null)
    {
        var cache = new Dictionary<string, byte[]> { ["Module1"] = Encoding.Latin1.GetBytes("\x01\x02" + cached + "\x03") };
        var streams = VbaStreams("Macros/", (version, cache), ("Module1", "standard", source));
        if (edit != null) streams = edit(streams);
        return View(Compound([("WordDocument", new byte[600]), .. streams]))!;
    }

    private static void AssertState(OfficeFileView.Facts f, string state, bool finding)
    {
        Assert.Equal(state, Assert.Single(f.Projects[0].Modules).CompiledCode);
        Assert.Equal(finding, f.Findings.Any(r => r.Keyword == "VBA compiled code differs from source"));
    }

    [Fact]
    public void A_module_whose_source_strings_are_in_its_compiled_code_matches_by_strings()
    {
        var f = Compiled(RunSource, "calc.exe hello world");
        Assert.Equal("0x0097", Assert.Single(f.Projects).Version);
        AssertState(f, "strings_match", false);
        Assert.Contains("opcodes are not compared", f.Projects[0].Modules[0].CompiledNote, StringComparison.Ordinal);
    }

    [Fact]
    public void A_module_whose_source_strings_are_not_in_its_compiled_code_differs()
    {
        var f = Compiled(RunSource, "benign text only");
        AssertState(f, "differs", true);
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Location: "VBA/Module1" } && r.Description.Contains("2 of 2", StringComparison.Ordinal));
    }

    [Fact]
    public void A_project_written_without_a_compiled_cache_is_purged_and_not_a_finding()
    {
        var f = View(WordDocument())!;
        Assert.All(f.Projects[0].Modules, m => Assert.Equal("purged", m.CompiledCode));
        Assert.Equal("0xFFFF", f.Projects[0].Version);
        Assert.DoesNotContain(f.Findings, r => r.Keyword == "VBA compiled code differs from source");
    }

    [Fact]
    public void A_module_with_no_source_string_to_compare_is_unverified()
    {
        AssertState(Compiled("Sub AutoOpen()\r\n  x = 1\r\nEnd Sub\r\n", "anything"), "unverified", false);
    }

    [Fact]
    public void A_missing_project_stream_leaves_the_comparison_unverified()
    {
        var f = Compiled(RunSource, "benign", edit: s => [.. s.Where(x => !x.Item1.EndsWith("_VBA_PROJECT", StringComparison.Ordinal))]);
        AssertState(f, "unverified", false);
        Assert.Contains("project stream", f.Projects[0].Modules[0].CompiledNote, StringComparison.Ordinal);
    }

    [Fact]
    public void A_project_stream_without_its_signature_leaves_the_comparison_unverified()
    {
        var f = Compiled(RunSource, "benign", edit: s => [.. s.Select(x => x.Item1.EndsWith("_VBA_PROJECT", StringComparison.Ordinal) ? (x.Item1, new byte[] { 1, 2, 3 }) : x)]);
        AssertState(f, "unverified", false);
    }

    [Fact]
    public void A_missing_module_stream_leaves_the_comparison_unverified()
    {
        var f = Compiled(RunSource, "benign", edit: s => [.. s.Where(x => !x.Item1.EndsWith("VBA/Module1", StringComparison.Ordinal))]);
        AssertState(f, "unverified", false);
        Assert.Equal("module stream not found", f.Projects[0].Modules[0].CompiledNote);
    }

    [Fact]
    public void A_text_offset_past_the_module_stream_leaves_the_comparison_unverified()
    {
        var f = Compiled(RunSource, "benign", edit: s => [.. s.Select(x => x.Item1.EndsWith("VBA/Module1", StringComparison.Ordinal) ? (x.Item1, new byte[] { 1, 2 }) : x)]);
        AssertState(f, "unverified", false);
    }

    [Fact]
    public void A_version_of_0xFFFF_with_cache_bytes_is_purged()
    {
        AssertState(Compiled(RunSource, "benign", version: 0xFFFF), "purged", false);
    }

    [Fact]
    public void A_doubled_quote_in_a_source_string_is_matched_as_one_quote()
    {
        AssertState(Compiled("Sub AutoOpen()\r\n  s = \"say \"\"hi\"\" now\"\r\nEnd Sub\r\n", "say \"hi\" now"), "strings_match", false);
    }

    [Fact]
    public void A_string_in_a_conditional_compilation_block_is_not_compared()
    {
        var src = "Sub AutoOpen()\r\n  MsgBox \"hello world\"\r\n#If Win64 Then\r\n  MsgBox \"only on win64\"\r\n#End If\r\nEnd Sub\r\n";
        AssertState(Compiled(src, "hello world"), "strings_match", false);
    }

    [Fact]
    public void A_string_after_a_colon_and_Rem_is_not_compared()
    {
        var src = "Sub AutoOpen()\r\n  MsgBox \"hello world\": Rem \"not code\"\r\nEnd Sub\r\n";
        AssertState(Compiled(src, "hello world"), "strings_match", false);
    }

    [Fact]
    public void A_package_encrypted_with_excels_built_in_password_is_decrypted_and_read()
    {
        var bin = Compound(VbaStreams("", ("Module1", "standard", "Sub Auto_Open()\r\n  Shell \"calc\"\r\nEnd Sub\r\n")));
        var xlsm = Ooxml(("xl/workbook.xml", "<workbook/>"u8.ToArray()), ("xl/vbaProject.bin", bin));
        var f = View(StandardEncrypted(xlsm, "VelvetSweatshop"), "a.xlsm")!;
        Assert.Equal("Excel workbook (OOXML), encrypted", f.Format);
        Assert.Equal("EncryptedPackage/xl/vbaProject.bin/", Assert.Single(f.Projects).Storage);
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Auto_Open", Location: "Module1:2" });
        Assert.Contains(f.Notes, n => n.Contains("standard encryption, password VelvetSweatshop", StringComparison.Ordinal));

        var other = View(StandardEncrypted(xlsm, "a long secret"), "b.xlsm")!;
        Assert.True(other.Encrypted);
        Assert.Empty(other.Projects);
        Assert.Contains(other.Notes, n => n.Contains("not decrypted", StringComparison.Ordinal));
    }

    [Fact]
    public void A_given_password_decrypts_a_package_and_a_wrong_one_is_named_not_decrypted()
    {
        var xlsm = Ooxml(("xl/workbook.xml", "<workbook/>"u8.ToArray()), ("xl/data.txt", "member text"u8.ToArray()));
        var locked = StandardEncrypted(xlsm, "caller secret");
        using (ContainerPassword.Enter("caller secret"))
        {
            Assert.Contains(Containers.Open(locked, "a.xlsx", AnalysisLimits.Default, default).Items, i => i.Name == "EncryptedPackage.zip");
            Assert.Equal("Excel workbook (OOXML), encrypted", View(locked, "a.xlsx")!.Format);
        }
        using (ContainerPassword.Enter("another secret"))
        {
            var f = View(locked, "a.xlsx")!;
            Assert.Contains(f.Notes, n => n.Contains("not decrypted (the password did not decrypt it)", StringComparison.Ordinal));
            Assert.DoesNotContain(f.Notes, n => n.Contains("secret", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void A_given_password_decrypts_an_agile_package_and_a_wrong_one_is_named_not_decrypted()
    {
        var xlsx = Ooxml(("xl/workbook.xml", "<workbook/>"u8.ToArray()), ("xl/data.bin", new byte[9000]));
        var locked = AgileEncrypted(xlsx, "caller secret");
        using (ContainerPassword.Enter("caller secret"))
        {
            var item = Containers.Open(locked, "a.xlsx", AnalysisLimits.Default, default).Items.Single(i => i.Name == "EncryptedPackage.zip");
            Assert.Equal(xlsx, item.Bytes);
            Assert.Contains(View(locked, "a.xlsx")!.Notes, n => n.Contains("agile encryption", StringComparison.Ordinal));
        }
        using (ContainerPassword.Enter("another secret"))
            Assert.Contains(View(locked, "a.xlsx")!.Notes, n => n.Contains("not decrypted (the password did not decrypt it)", StringComparison.Ordinal));
    }

    [Fact]
    public void A_given_password_replaces_the_built_in_ones()
    {
        var xlsm = Ooxml(("xl/workbook.xml", "<workbook/>"u8.ToArray()));
        using var _ = ContainerPassword.Enter("caller secret");
        Assert.Contains(View(StandardEncrypted(xlsm, "VelvetSweatshop"), "a.xlsx")!.Notes, n => n.Contains("the password did not decrypt it", StringComparison.Ordinal));
    }

    [Fact]
    public void An_ole_package_object_is_extracted_under_its_embedded_name()
    {
        var exe = ContainerFixtures.Module("Payload");
        var doc = Compound([("WordDocument", new byte[10]), ("ObjectPool/_1234/\u0001Ole10Native", Ole10Native("invoice.exe", @"C:\Users\a\invoice.exe", exe))]);
        var c = Containers.Open(doc, "doc.doc", AnalysisLimits.Default, default);
        var item = Assert.Single(c.Items, i => i.Name == "ObjectPool/_1234/invoice.exe");
        Assert.Equal(exe, item.Bytes);
        Assert.Contains(c.Entries!, e => e.Path == "ObjectPool/_1234/[1]Ole10Native");
        var o = Assert.Single(View(doc)!.Objects);
        Assert.Equal((@"C:\Users\a\invoice.exe", ".NET assembly"), (o.SourcePath, o.Kind));
    }

    [Fact]
    public void Excel_4_macro_sheets_are_decoded_with_their_visibility_and_auto_open()
    {
        var book = Biff8Workbook("Macro1", 2, Call(110, "calc.exe"), Call(149, "URLMON", "URLDownloadToFileA", "JJCCJJ"), Call(54));
        var f = View(Compound([("Workbook", book)]), "b.xls")!;
        Assert.Equal("Excel workbook", f.Format);
        Assert.Contains(f.Sheets!, s => s is { Name: "Macro1", Type: "macro sheet", State: "very hidden" });
        Assert.Equal(3, f.XlmFormulas);
        Assert.Contains("Name Auto_Open = !A1", f.DefinedNames!);
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Auto_Open" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "REGISTER" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "XLM macro" });
        var text = Encoding.UTF8.GetString(Containers.Open(Compound([("Workbook", book)]), "b.xls", AnalysisLimits.Default, default).Items.Single(i => i.Name == "xlm_macros.txt").Bytes);
        Assert.Contains("Macro1!A1: EXEC(\"calc.exe\")", text);
        Assert.Contains("Macro1!A2: REGISTER(\"URLMON\",\"URLDownloadToFileA\",\"JJCCJJ\")", text);
        Assert.Contains("Macro1!A3: HALT()", text);
    }

    [Fact]
    public void An_xlsm_macro_sheet_is_read_from_its_parts()
    {
        var wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"M\" sheetId=\"1\" state=\"hidden\" r:id=\"rId1\"/></sheets><definedNames><definedName name=\"_xlnm.Auto_Open\">M!$A$1</definedName></definedNames></workbook>";
        var rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"x\" Target=\"macrosheets/sheet1.xml\"/></Relationships>";
        var sheet = "<xm:macrosheet xmlns:xm=\"x\"><sheetData><row><c r=\"A1\"><f>EXEC(\"calc\")</f></c></row></sheetData></xm:macrosheet>";
        var f = View(Ooxml(("xl/workbook.xml", Encoding.UTF8.GetBytes(wb)), ("xl/_rels/workbook.xml.rels", Encoding.UTF8.GetBytes(rels)), ("xl/macrosheets/sheet1.xml", Encoding.UTF8.GetBytes(sheet))), "a.xlsm")!;
        Assert.Contains(f.Sheets!, s => s is { Name: "M", Type: "macro sheet", State: "hidden" });
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Auto_Open" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    private static byte[] XlsbRec(int id, params byte[][] parts)
    {
        var body = parts.SelectMany(p => p).ToArray();
        var head = id < 0x80 ? new[] { (byte)id } : new[] { (byte)(0x80 | id & 0x7F), (byte)(id >> 7) };
        var len = new List<byte>();
        int n = body.Length;
        do { var v = (byte)(n & 0x7F); n >>= 7; len.Add(n > 0 ? (byte)(v | 0x80) : v); } while (n > 0);
        return [.. head, .. len, .. body];
    }

    private static byte[] XlsbU32(int v) => BitConverter.GetBytes(v);

    private static byte[] XlsbWide(string s) => [.. XlsbU32(s.Length), .. Encoding.Unicode.GetBytes(s)];

    private const string XlsbNs = "http://schemas.openxmlformats.org/package/2006/relationships";

    private static string XlsbRels(string target) =>
        $"<Relationships xmlns=\"{XlsbNs}\"><Relationship Id=\"rId1\" Type=\"x\" Target=\"{target}\"/></Relationships>";

    private static byte[] XlsbBook(byte[]? name = null) =>
        XlsbRec(156, XlsbU32(2), XlsbU32(1), XlsbWide("rId1"), XlsbWide("M"))
            .Concat(name == null ? [] : XlsbRec(39, XlsbU32(0), [0], XlsbU32(-1), XlsbWide("_xlnm.Auto_Open"), XlsbU32(name.Length), name, XlsbU32(0))).ToArray();

    private static byte[] XlsbPackage(byte[] book, byte[]? sheet, string rels)
    {
        var parts = new List<(string, byte[])> { ("xl/workbook.bin", book), ("xl/_rels/workbook.bin.rels", Encoding.UTF8.GetBytes(rels)) };
        if (sheet != null) parts.Add(("xl/macrosheets/sheet1.bin", sheet));
        return Ooxml(parts.ToArray());
    }

    private static OfficeFileView.Facts? XlsbView(byte[] book, byte[]? sheet, string? rels = null) =>
        View(XlsbPackage(book, sheet, rels ?? XlsbRels("macrosheets/sheet1.bin")), "a.xlsb");

    // The formula is EXEC("calc"): function 110 with one argument.
    private static readonly byte[] XlsbExec = [0x17, 4, 0, .. Encoding.Unicode.GetBytes("calc"), 0x42, 1, 110, 0];

    private static byte[] XlsbCell(int id, int valueBytes, byte[] formula) =>
        XlsbRec(id, XlsbU32(0), XlsbU32(0), id == 8 ? XlsbWide("") : new byte[valueBytes], [0, 0], XlsbU32(formula.Length), formula, XlsbU32(0));

    private static byte[] XlsbSheet(params byte[][] cells) => XlsbRec(0, XlsbU32(0)).Concat(cells.SelectMany(c => c)).ToArray();

    [Fact]
    public void An_xlsb_macro_sheet_is_decoded_from_its_binary_records()
    {
        // Formula A1 for the name; EXEC("calc") for the cell.
        byte[] name = [0x24, 0, 0, 0, 0, 0, 0];
        var f = XlsbView(XlsbBook(name), XlsbSheet(XlsbCell(8, 0, XlsbExec)))!;
        Assert.Contains(f.Sheets!, s => s is { Name: "M", Type: "macro sheet", State: "very hidden" });
        Assert.Equal(1, f.XlmFormulas);
        Assert.Contains("Name Auto_Open = A1", f.DefinedNames!);
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Auto_Open" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    [Theory]
    [InlineData(9, 8)]
    [InlineData(10, 1)]
    [InlineData(11, 1)]
    public void An_xlsb_formula_cell_skips_its_cached_value_before_the_formula(int id, int value)
    {
        var f = XlsbView(XlsbBook(), XlsbSheet(XlsbCell(id, value, XlsbExec)))!;
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    [Fact]
    public void An_xlsb_record_longer_than_127_bytes_is_read()
    {
        byte[] wide = [0x17, 100, 0, .. Encoding.Unicode.GetBytes(new string('a', 100)), 0x42, 1, 110, 0];
        var f = XlsbView(XlsbBook(), XlsbSheet(XlsbCell(8, 0, wide)))!;
        Assert.Equal(1, f.XlmFormulas);
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    [Fact]
    public void A_truncated_xlsb_record_ends_the_list_without_failing()
    {
        var cell = XlsbCell(8, 0, XlsbExec);
        var f = XlsbView(XlsbBook(), XlsbSheet(cell, cell[..^5]))!;
        Assert.Equal(1, f.XlmFormulas);
    }

    [Fact]
    public void A_missing_xlsb_macro_sheet_part_is_named()
    {
        var f = XlsbView(XlsbBook(), null)!;
        Assert.Contains(f.Notes!, n => n.Contains("part xl/macrosheets/sheet1.bin is missing"));
    }

    [Fact]
    public void An_xlsb_macro_sheet_without_a_relationship_is_still_read()
    {
        var f = XlsbView(XlsbBook(), XlsbSheet(XlsbCell(8, 0, XlsbExec)), $"<Relationships xmlns=\"{XlsbNs}\"/>")!;
        Assert.Contains(f.Sheets!, s => s is { Name: "sheet1", Type: "macro sheet" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    [Fact]
    public void An_xlsb_cell_takes_the_text_of_the_shared_formula_that_holds_it()
    {
        // Cell A1 is a PtgExp token; the shared record after it covers A1:A1.
        var f = XlsbView(XlsbBook(), ExpSheet(XlsbRec(427, XlsbU32(0), XlsbU32(0), XlsbU32(0), XlsbU32(0), XlsbU32(XlsbExec.Length), XlsbExec, XlsbU32(0))))!;
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    [Fact]
    public void An_xlsb_cell_takes_the_text_of_the_array_formula_that_holds_it()
    {
        // Cell A1 is a PtgExp token; the array record has a flag byte after its range.
        var f = XlsbView(XlsbBook(), ExpSheet(XlsbRec(426, XlsbU32(0), XlsbU32(0), XlsbU32(0), XlsbU32(0), new byte[] { 0 }, XlsbU32(XlsbExec.Length), XlsbExec, XlsbU32(0))))!;
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    [Fact]
    public void An_xlsb_cell_outside_every_shared_range_stays_empty_and_is_noted()
    {
        // The shared record covers B2:B2 only.
        var f = XlsbView(XlsbBook(), ExpSheet(XlsbRec(427, XlsbU32(1), XlsbU32(1), XlsbU32(1), XlsbU32(1), XlsbU32(XlsbExec.Length), XlsbExec, XlsbU32(0))))!;
        Assert.DoesNotContain(f.Findings, r => r.Keyword == "EXEC");
        Assert.Contains(f.Notes!, n => n.Contains("1 shared-formula cells have no shared record"));
    }

    [Fact]
    public void An_xlsb_shared_record_shorter_than_its_range_is_skipped()
    {
        // The record holds 12 bytes, so no range is read.
        var f = XlsbView(XlsbBook(), ExpSheet(XlsbRec(427, XlsbU32(0), XlsbU32(0), XlsbU32(0))))!;
        Assert.Contains(f.Notes!, n => n.Contains("1 shared-formula cells have no shared record"));
    }

    private static byte[] ExpSheet(byte[] record) => XlsbSheet(XlsbCell(8, 0, [0x01, 0, 0, 0, 0])).Concat(record).ToArray();

    [Fact]
    public void An_xlsb_workbook_without_sheet_records_is_reported_as_unread()
    {
        using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(Ooxml(("xl/workbook.bin", Array.Empty<byte>()))));
        Assert.Contains(XlmMacros.FromOoxml(zip, default)!.Notes, n => n.Contains("no sheet records read"));
    }

    [Fact]
    public void An_xlsb_hidden_name_and_a_truncated_formula_are_marked()
    {
        var book = XlsbRec(156, XlsbU32(0), XlsbU32(1), XlsbWide("rId1"), XlsbWide("M"))
            .Concat(XlsbRec(39, XlsbU32(1), [0], XlsbU32(-1), XlsbWide("Hid"), XlsbU32(4), [0x24, 0, 0, 0], XlsbU32(0))).ToArray();
        var f = XlsbView(book, null)!;
        Assert.Contains(f.DefinedNames!, n => n.StartsWith("Name Hid (hidden) =") && n.EndsWith('?'));
    }

    [Fact]
    public void An_xlsb_sheet_stops_at_the_formula_cell_limit()
    {
        var cell = XlsbCell(8, 0, XlsbExec);
        var f = XlsbView(XlsbBook(), XlsbSheet(Enumerable.Repeat(cell, 20_001).ToArray()))!;
        Assert.Equal(20_000, f.XlmFormulas);
        Assert.Contains(f.Notes!, n => n.Contains("stopped at 20,000 formula cells"));
    }

    [Fact]
    public void An_xlsb_read_honours_a_cancelled_token()
    {
        // A workbook part of 5,000 empty records, past the cancellation check interval.
        var book = Enumerable.Repeat(XlsbRec(1), 5000).SelectMany(r => r).ToArray();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(Ooxml(("xl/workbook.bin", book))));
        Assert.Throws<OperationCanceledException>(() => XlmMacros.FromOoxml(zip, cts.Token));
    }

    [Fact]
    public void A_plain_xlsb_reports_no_macro_findings()
    {
        var book = XlsbRec(156, XlsbU32(0), XlsbU32(1), XlsbWide("rId1"), XlsbWide("S"));
        var f = XlsbView(book, null, XlsbRels("worksheets/sheet1.bin"));
        Assert.True(f == null || f.Findings.Count == 0);
    }

    [Fact]
    public void A_powerpoint_97_presentation_reads_the_vba_storage_it_compresses()
    {
        var vba = Compound(VbaStreams("", ("Module1", "standard", "Sub Action_Click()\r\n  Shell \"calc\"\r\nEnd Sub\r\n")));
        var zlib = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(zlib, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true)) z.Write(vba);
        // A DocumentContainer (version 0xF) holding one ExOleObjStg atom, instance 1: decompressed size, then zlib data.
        var atom = new MemoryStream();
        atom.Write(BitConverter.GetBytes((ushort)0x0010)); atom.Write(BitConverter.GetBytes((ushort)0x1011));
        atom.Write(BitConverter.GetBytes((uint)(4 + zlib.Length))); atom.Write(BitConverter.GetBytes((uint)vba.Length)); atom.Write(zlib.ToArray());
        var stream = new MemoryStream();
        stream.Write(BitConverter.GetBytes((ushort)0x000F)); stream.Write(BitConverter.GetBytes((ushort)0x03E8)); stream.Write(BitConverter.GetBytes((uint)atom.Length));
        stream.Write(atom.ToArray());
        var ppt = Compound([("PowerPoint Document", stream.ToArray()), ("Current User", new byte[20])]);
        var f = View(ppt, "a.ppt")!;
        Assert.Equal("PowerPoint presentation", f.Format);
        Assert.Equal("PowerPoint Document/ExOleObjStg@0x8/", Assert.Single(f.Projects).Storage);
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Action_Click", Location: "Module1:2" });
        Assert.Contains(Containers.Open(ppt, "a.ppt", AnalysisLimits.Default, default).Items, i => i.Name == "PowerPoint Document/ExOleObjStg@0x8/VBA/Module1.bas");
    }

    [Fact]
    public void A_sylk_file_with_a_macro_sheet_option_is_read_as_excel_4_macros()
    {
        var slk = "ID;PWXL;N;E\r\nO;L;E;D;V0\r\nNN;NAuto_Open;ER1C1\r\nC;Y1;X1;KFALSE;EEXEC(\"calc\")\r\nC;Y2;EHALT()\r\nE\r\n"u8.ToArray();
        var f = View(slk, "a.slk")!;
        Assert.Equal("SYLK spreadsheet", f.Format);
        Assert.Equal(2, f.XlmFormulas);
        Assert.Contains(f.Findings, r => r is { Type: "AutoExec", Keyword: "Auto_Open" });
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "EXEC" });
    }

    /// <summary>A OneNote section: its header GUID, a UTF-16 file name property and FileDataStoreObject records.</summary>
    internal static byte[] OneNoteSection(params byte[][] files) => OneNoteSectionNamed(["invoice.hta"], files);

    /// <summary>A OneNote section whose UTF-16 file name properties are <paramref name="names"/>.</summary>
    internal static byte[] OneNoteSectionNamed(string[] names, params byte[][] files)
    {
        var o = new MemoryStream();
        o.Write(new Guid("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3").ToByteArray());
        o.Write(new byte[64]);
        foreach (var name in names) o.Write(Encoding.Unicode.GetBytes($"\0{name}\0"));
        foreach (var f in files)
        {
            while (o.Length % 8 != 0) o.WriteByte(0);
            o.Write(new Guid("BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC").ToByteArray());
            o.Write(BitConverter.GetBytes((ulong)f.Length)); o.Write(new byte[12]); o.Write(f);
            while (o.Length % 8 != 0) o.WriteByte(0);
            o.Write(new Guid("71FBA722-0F79-4A0B-BB13-899256426B24").ToByteArray());
        }
        return o.ToArray();
    }

    [Fact]
    public void A_onenote_section_gives_its_embedded_files_named_by_content()
    {
        var hta = "<html><head><HTA:APPLICATION id=\"x\"/><script>new ActiveXObject('WScript.Shell').Run('calc')</script></head></html>"u8.ToArray();
        var exe = ContainerFixtures.Module("Payload");
        var one = OneNoteSection(hta, exe);
        var c = Containers.Open(one, "a.one", AnalysisLimits.Default, default);
        Assert.Equal("OneNote section", c.Kind);
        Assert.Equal(hta, c.Items.Single(i => i.Name == "embedded_1.hta").Bytes);
        Assert.Equal(exe, c.Items.Single(i => i.Name == "embedded_2.dll").Bytes);
        Assert.Contains(c.Notes, n => n.Contains("invoice.hta", StringComparison.Ordinal));
        var f = View(one, "a.one")!;
        Assert.Equal(2, f.Objects.Count);
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "embedded_1.hta" });
    }

    [Fact]
    public void A_onenote_embedded_file_takes_its_stored_name_and_a_script_is_flagged()
    {
        var cmd = "@echo off\r\nstart calc.exe\r\n"u8.ToArray();
        var one = OneNoteSectionNamed(["Invoice 2024.cmd"], cmd);
        var c = Containers.Open(one, "a.one", AnalysisLimits.Default, default);
        Assert.Equal(cmd, c.Items.Single(i => i.Name == "Invoice 2024.cmd").Bytes);
        var f = View(one, "a.one")!;
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "Invoice 2024.cmd" });
    }

    [Fact]
    public void A_onenote_script_without_a_stored_name_is_typed_by_its_text()
    {
        var ps = "$u = 'x'\r\nWrite-Host $u\r\n"u8.ToArray();
        var f = View(OneNoteSectionNamed([], ps), "a.one")!;
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "embedded_1.ps1" });
    }

    [Fact]
    public void A_onenote_file_named_as_a_document_but_holding_a_script_is_flagged()
    {
        var vbs = "Dim s\r\nSet s = CreateObject(\"WScript.Shell\")\r\n"u8.ToArray();
        var f = View(OneNoteSectionNamed(["notes.txt"], vbs), "a.one")!;
        Assert.Contains(f.Findings, r => r is { Type: "Suspicious", Keyword: "notes.txt" } && r.Description.Contains(".vbs", StringComparison.Ordinal));
    }

    [Fact]
    public void A_onenote_text_note_is_not_flagged()
    {
        var f = View(OneNoteSectionNamed(["notes.txt"], "meeting at noon, bring the printed agenda"u8.ToArray()), "a.one");
        Assert.Empty(f?.Findings ?? []);
    }

    [Fact]
    public void A_version_4_compound_file_reads_its_4096_byte_sectors_after_a_full_sector_header()
    {
        // Version 4: a 4096-byte header sector, one FAT sector, one directory sector holding the root and one stream.
        var data = new byte[4096 * 4];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(data, 0);
        BitConverter.GetBytes((ushort)0x3E).CopyTo(data, 24); BitConverter.GetBytes((ushort)4).CopyTo(data, 26);
        BitConverter.GetBytes((ushort)0xFFFE).CopyTo(data, 28); BitConverter.GetBytes((ushort)12).CopyTo(data, 30); BitConverter.GetBytes((ushort)6).CopyTo(data, 32);
        BitConverter.GetBytes(1u).CopyTo(data, 44); BitConverter.GetBytes(1u).CopyTo(data, 48); BitConverter.GetBytes(4096u).CopyTo(data, 56);
        BitConverter.GetBytes(0xFFFFFFFEu).CopyTo(data, 60); BitConverter.GetBytes(0xFFFFFFFEu).CopyTo(data, 68);
        for (int i = 0; i < 109; i++) BitConverter.GetBytes(i == 0 ? 0u : 0xFFFFFFFFu).CopyTo(data, 76 + i * 4);
        var fat = new uint[1024];
        Array.Fill(fat, 0xFFFFFFFFu);
        fat[0] = 0xFFFFFFFD; fat[1] = 0xFFFFFFFE; fat[2] = 0xFFFFFFFE;
        Buffer.BlockCopy(fat, 0, data, 4096, 4096);
        void Entry(int index, string name, byte type, uint child, uint start, uint size)
        {
            int at = 4096 * 2 + index * 128;
            var n = Encoding.Unicode.GetBytes(name);
            n.CopyTo(data, at);
            BitConverter.GetBytes((ushort)(n.Length + 2)).CopyTo(data, at + 64);
            data[at + 66] = type;
            BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(data, at + 68); BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(data, at + 72); BitConverter.GetBytes(child).CopyTo(data, at + 76);
            BitConverter.GetBytes(start).CopyTo(data, at + 116); BitConverter.GetBytes(size).CopyTo(data, at + 120);
        }
        Entry(0, "Root Entry", 5, 1, 0xFFFFFFFE, 0);
        Entry(1, "Big", 2, 0xFFFFFFFF, 2, 4096);
        "payload"u8.ToArray().CopyTo(data, 4096 * 3);
        var cf = CompoundFile.Read(data, "v4.bin");
        Assert.StartsWith("payload", Encoding.ASCII.GetString(cf.Read(cf.Find("Big")!, 1 << 20)), StringComparison.Ordinal);
    }

    [Fact]
    public void A_looping_sector_chain_ends_with_a_note()
    {
        var doc = WordDocument();
        // Point the first FAT entry after the FAT itself back at itself: the directory chain loops.
        var start = BitConverter.ToUInt32(doc, 48);
        BitConverter.GetBytes(start).CopyTo(doc, 512 + (int)start * 4);
        var c = Containers.Open(doc, "doc.doc", AnalysisLimits.Default, default);
        Assert.Contains(c.Notes, n => n.Contains("loops", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(CompoundFileReader), typeof(CompoundFile), typeof(OfficeDocument), typeof(OfficeFileView), typeof(OneNoteReader))]
    public void Fuzzed_documents_never_throw_past_a_tool_error()
    {
        var bin = Compound(VbaStreams("", ("Module1", "standard", StartupMacro)));
        var seeds = new[]
        {
            ("doc.doc", WordDocument()), ("b.xls", Compound([("Workbook", Biff8Workbook("M", 1, Call(110, "calc")))])),
            ("a.docm", Ooxml(("word/document.xml", "<w:document/>"u8.ToArray()), ("word/vbaProject.bin", bin))), ("a.one", OneNoteSection("@echo off"u8.ToArray(), [1, 2, 3])),
        };
        foreach (var (name, seed) in seeds)
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, name, AnalysisLimits.Default, default); } catch (ToolError) { }
                try { View(b, name); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }
}
