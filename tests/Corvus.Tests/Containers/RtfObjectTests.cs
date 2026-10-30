using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>Rich Text Format documents: OLE objects, their classes, templates and damaged object data.</summary>
public sealed class RtfObjectTests
{
    private const string Letter = @"{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}\pard Dear customer,\par Your order has shipped.\par}";

    private static byte[] Lp(string s) => [.. BitConverter.GetBytes(s.Length + 1), .. Encoding.Latin1.GetBytes(s + "\0")];

    private static byte[] EmbeddedHeader(string progId, byte[] native) =>
        [.. BitConverter.GetBytes(0x501), .. BitConverter.GetBytes(2), .. Lp(progId), .. BitConverter.GetBytes(0), .. BitConverter.GetBytes(0), .. BitConverter.GetBytes(native.Length), .. native];

    private static string Rtf(string progId, byte[] objdata, string extra = "") =>
        @"{\rtf1{\object\objemb" + extra + @"{\*\objclass " + progId + @"}{\*\objdata " + Convert.ToHexString(objdata) + @"}}\par}";

    private static OfficeFileView.Facts? View(string rtf) => View(Encoding.Latin1.GetBytes(rtf));

    private static OfficeFileView.Facts? View(byte[] data) =>
        Inspect(data)?.Detail as OfficeFileView.Facts;

    private static FileView? Inspect(byte[] data) => new OfficeFileView().Inspect(new FileInput("doc.rtf", data, Blob.Identify(data)), default);

    [Fact]
    public void An_ole_package_and_a_remote_template_are_reported()
    {
        var package = Ole10Native("notes.txt", @"C:\Users\a\notes.txt", "hello"u8.ToArray())[4..];
        var rtf = @"{\rtf1{\*\template https://example.test/t/normal.dotm}" + Rtf("Package", EmbeddedHeader("Package", package))[6..];
        var view = Inspect(Encoding.Latin1.GetBytes(rtf))!;
        var facts = (OfficeFileView.Facts)view.Detail!;
        var file = Assert.Single(facts.Objects);
        Assert.Equal(("notes.txt", @"C:\Users\a\notes.txt"), (file.Name, file.SourcePath));
        Assert.Contains(view.Findings!, f => f is { Rule: "office/ole-class", Level: "noteworthy" } && f.Evidence.StartsWith("OLE Package", StringComparison.Ordinal));
        Assert.Contains(view.Findings!, f => f is { Rule: "office/template", Level: "review" } && f.Evidence.StartsWith("https://example.test/t/normal.dotm", StringComparison.Ordinal));
    }

    [Fact]
    public void An_equation_editor_object_is_noteworthy()
    {
        var view = Inspect(Encoding.Latin1.GetBytes(Rtf("Equation.3", EmbeddedHeader("Equation.3", [1, 2, 3, 4]))))!;
        Assert.Contains(view.Findings!, f => f is { Rule: "office/ole-class", Level: "noteworthy" } && f.Evidence.StartsWith("Equation Editor 3.0", StringComparison.Ordinal));
    }

    [Fact]
    public void A_plain_letter_reports_nothing()
    {
        Assert.Null(Inspect(Encoding.Latin1.GetBytes(Letter)));
        var plain = Inspect(Encoding.Latin1.GetBytes(Letter), "office");
        Assert.Empty(plain!.Findings!);
    }

    [Fact]
    public void A_local_template_and_a_picture_object_are_not_noteworthy()
    {
        var rtf = @"{\rtf1{\*\template C:\Users\a\Normal.dotm}{\object\objemb{\*\objclass Paint.Picture}{\*\objdata " + Convert.ToHexString(EmbeddedHeader("Paint.Picture", [9, 9])) + @"}}}";
        var view = Inspect(Encoding.Latin1.GetBytes(rtf))!;
        Assert.DoesNotContain(view.Findings!, f => f.Level == "noteworthy");
        Assert.DoesNotContain(view.Findings!, f => f.Rule == "office/template");
    }

    [Fact]
    public void A_linked_object_target_is_reviewed()
    {
        var header = (byte[])[.. BitConverter.GetBytes(0x501), .. BitConverter.GetBytes(1), .. Lp("Word.Document.8"), .. Lp("https://example.test/a.doc"), .. Lp("")];
        var rtf = @"{\rtf1{\object\objautlink\objupdate{\*\objclass Word.Document.8}{\*\objdata " + Convert.ToHexString(header) + @"}}}";
        var facts = View(rtf)!;
        Assert.Contains(facts.Links, l => l is { Type: "objautlink", Target: "https://example.test/a.doc" });
        Assert.Contains(facts.Notes, n => n.Contains("objupdate", StringComparison.Ordinal));
    }

    [Fact]
    public void Damaged_object_data_is_noted_as_partial_or_unknown()
    {
        var odd = View(@"{\rtf1{\object\objemb{\*\objclass Equation.3}{\*\objdata 0105000}}}")!;
        Assert.Contains(odd.Notes, n => n.Contains("odd number", StringComparison.Ordinal));
        Assert.Contains(odd.Notes, n => n.Contains("not an OLE 1.0", StringComparison.Ordinal));
        var text = View(@"{\rtf1{\object\objemb{\*\objclass Equation.3}{\*\objdata 0105xyz00}}}")!;
        Assert.Contains(text.Notes, n => n.Contains("not hexadecimal", StringComparison.Ordinal));
    }

    [Fact]
    public void The_class_table_names_each_class_by_progid_and_class_id()
    {
        Assert.Equal("Equation Editor 3.0", OleClasses.FromClsid(new("0002CE02-0000-0000-C000-000000000046"))!.Name);
        Assert.Equal("OLE Package", OleClasses.FromClsid(new("F20DA720-C02F-11CE-927B-0800095AE340"))!.Name);
        Assert.Equal("OLE Package", OleClasses.FromProgId("package")!.Name);
        Assert.Null(OleClasses.FromProgId("Paint.Picture"));
    }

    private static FileView? Inspect(byte[] data, string view) =>
        new OfficeFileView().Inspect(new FileInput("doc.rtf", data, Blob.Identify(data)) { Options = new FileViewOptions(view) }, default);

    [Fact]
    [FuzzEntry(typeof(RtfObjects), typeof(OleClasses))]
    public void Fuzzed_rtf_documents_never_throw_past_a_tool_error()
    {
        var package = Ole10Native("notes.txt", "n.txt", "hello"u8.ToArray())[4..];
        var seeds = new[]
        {
            Encoding.Latin1.GetBytes(Rtf("Package", EmbeddedHeader("Package", package), @"\objupdate") + @"{\*\template https://example.test/t.dotm}"),
            Encoding.Latin1.GetBytes(Letter),
        };
        foreach (var seed in seeds)
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, "doc.rtf", AnalysisLimits.Default, default); } catch (ToolError) { }
                try { Inspect(b); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }
}
