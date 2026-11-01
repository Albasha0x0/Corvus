using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Services.Analysis;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>Embedded objects read by class: Equation Editor with its MTEF lengths, Package, HTML document and HTML form controls.</summary>
public sealed class OleClassTests
{
    private static readonly Guid Equation2 = new("0002CE02-0000-0000-C000-000000000046");
    private static readonly Guid Equation3 = new("0002CE03-0000-0000-C000-000000000046");

    private static byte[] Mtef(string fontName, bool terminate = true, int? declared = null, int header = 28, int trailing = 0)
    {
        byte[] records = [3, 1, 1, 3, 10, 1, 1, 8, 0x5A, 0x5A, .. Encoding.ASCII.GetBytes(fontName), .. terminate ? new byte[] { 0 } : [], 0];
        var body = records.Concat(new byte[trailing]).ToArray();
        var count = declared ?? records.Length;
        return [.. BitConverter.GetBytes((ushort)header), .. BitConverter.GetBytes(0x00020000), .. BitConverter.GetBytes((ushort)0),
            .. BitConverter.GetBytes(count), .. new byte[16], .. body];
    }

    private static OfficeFileView.Facts Facts(byte[] stream, Guid clsid) => Inspect(Compound([("Equation Native", stream)], clsid));

    private static OfficeFileView.Facts Inspect(byte[] data)
    {
        var view = new OfficeFileView().Inspect(new FileInput("object.bin", data, Blob.Identify(data)) { Options = new FileViewOptions("office") }, default);
        return (OfficeFileView.Facts)view!.Detail!;
    }

    private static FileView View(byte[] data) =>
        new OfficeFileView().Inspect(new FileInput("object.bin", data, Blob.Identify(data)) { Options = new FileViewOptions("office") }, default)!;

    [Theory]
    [InlineData("0002CE02-0000-0000-C000-000000000046", "Equation Editor 3.0")]
    [InlineData("0002CE03-0000-0000-C000-000000000046", "Equation Editor 3.0")]
    [InlineData("25336920-03F9-11CF-8FD0-00AA00686F13", "HTML document")]
    [InlineData("5512D112-5CC6-11CF-8D67-00AA00BDCE1D", "HTML form control")]
    public void An_object_is_named_by_the_class_id_of_its_root_storage(string clsid, string name)
    {
        var view = View(Compound([("Contents", new byte[] { 1 })], new Guid(clsid)));
        Assert.Contains(view.Findings!, f => f is { Rule: "office/ole-class", Level: "noteworthy" } && f.Evidence.StartsWith(name, StringComparison.Ordinal));
    }

    [Fact]
    public void A_package_stream_names_the_package_class()
    {
        var view = View(Compound([("\u0001Ole10Native", Ole10Native("a.txt", "a.txt", "x"u8.ToArray()))]));
        Assert.Contains(view.Findings!, f => f.Rule == "office/ole-class" && f.Evidence.StartsWith("OLE Package", StringComparison.Ordinal));
    }

    [Fact]
    public void A_consistent_equation_stream_has_no_length_notes()
    {
        var facts = Facts(Mtef("Times New Roman"), Equation3);
        Assert.DoesNotContain(facts.Notes, n => n.Contains("Equation Native", StringComparison.Ordinal));
    }

    [Fact]
    public void A_font_name_past_its_buffer_is_noted()
    {
        var facts = Facts(Mtef(new string('A', 40)), Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("40 bytes, past its 32-byte buffer", StringComparison.Ordinal));
    }

    [Fact]
    public void A_font_name_without_a_terminator_is_noted()
    {
        var facts = Facts(Mtef("AAAA", terminate: false)[..^1], Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("without a terminator", StringComparison.Ordinal));
    }

    [Fact]
    public void A_declared_length_past_the_stream_is_noted()
    {
        var facts = Facts(Mtef("Arial", declared: 5000), Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("declares 5,000 bytes", StringComparison.Ordinal));
    }

    [Fact]
    public void Bytes_after_the_declared_length_are_noted()
    {
        var facts = Facts(Mtef("Arial", trailing: 6), Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("6 bytes follow", StringComparison.Ordinal));
    }

    [Fact]
    public void A_header_length_other_than_28_is_noted()
    {
        var facts = Facts(Mtef("Arial", header: 40), Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("header length is 40", StringComparison.Ordinal));
    }

    [Fact]
    public void A_stream_shorter_than_the_header_is_unknown()
    {
        var facts = Facts(new byte[10], Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("its content is unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unread_record_names_the_offset_where_reading_stopped()
    {
        var stream = Mtef("Arial");
        stream[28 + 5] = 0x04;
        var facts = Facts(stream, Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("are not read", StringComparison.Ordinal));
    }

    private static IEnumerable<Finding> ClassFindings(FileView v) => v.Findings!.Where(f => f.Rule == "office/ole-class");

    [Fact]
    public void A_package_stream_names_its_holding_storage_not_the_root()
    {
        var view = View(Compound([("ObjectPool/_1/Ole10Native", Ole10Native("a.txt", "a.txt", "x"u8.ToArray()))]));
        var f = Assert.Single(ClassFindings(view));
        Assert.Equal("ObjectPool/_1", f.Location);
    }

    [Fact]
    public void An_unreadable_package_stream_adds_a_note_and_no_class()
    {
        var view = View(Compound([("Ole10Native", new byte[] { 1, 2 })]));
        Assert.Empty(ClassFindings(view));
        Assert.Contains(((OfficeFileView.Facts)view.Detail!).Notes, n => n.Contains("not a readable OLE Package", StringComparison.Ordinal));
    }

    [Fact]
    public void A_nested_equation_stream_is_named_and_read()
    {
        var view = View(Compound([("ObjectPool/_1/Equation Native", Mtef("Arial", declared: 5000))]));
        Assert.Equal("ObjectPool/_1", Assert.Single(ClassFindings(view)).Location);
        Assert.Contains(((OfficeFileView.Facts)view.Detail!).Notes, n => n.Contains("declares 5,000 bytes", StringComparison.Ordinal));
    }

    [Fact]
    public void Two_equation_streams_are_both_read()
    {
        var view = View(Compound([("ObjectPool/_1/Equation Native", Mtef("Arial", declared: 5000)), ("ObjectPool/_2/Equation Native", Mtef("Arial", declared: 6000))]));
        var notes = ((OfficeFileView.Facts)view.Detail!).Notes;
        Assert.Contains(notes, n => n.Contains("declares 5,000", StringComparison.Ordinal));
        Assert.Contains(notes, n => n.Contains("declares 6,000", StringComparison.Ordinal));
    }

    [Fact]
    public void A_truncated_line_record_is_noted()
    {
        var stream = Mtef("Arial");
        stream = [.. stream[..33], 1];
        var facts = Facts(stream, Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("record truncated", StringComparison.Ordinal));
    }

    [Fact]
    public void A_nudge_past_the_end_of_the_stream_is_noted()
    {
        var stream = Mtef("Arial");
        stream = [.. stream[..33], 1, 8, 0x80];
        var facts = Facts(stream, Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("record truncated", StringComparison.Ordinal));
    }

    [Fact]
    public void A_line_spacing_past_the_end_of_the_stream_is_noted()
    {
        var stream = Mtef("Arial");
        stream = [.. stream[..33], 1, 4];
        var facts = Facts(stream, Equation2);
        Assert.Contains(facts.Notes, n => n.Contains("record truncated", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0x5512D110u, true)]
    [InlineData(0x5512D12Fu, true)]
    [InlineData(0x5512D10Fu, false)]
    [InlineData(0x5512D130u, false)]
    public void The_forms_html_range_is_bounded_by_its_first_and_last_class_id(uint first, bool named)
    {
        Assert.Equal(named, OleClasses.FromClsid(OleClasses.FormsHtmlId(first)) != null);
    }

    [Fact]
    public void A_forms_html_first_field_with_another_tail_is_not_named()
    {
        Assert.Null(OleClasses.FromClsid(new Guid(0x5512D112, 0x5CC6, 0x11CF, 0x8D, 0x67, 0x00, 0xAA, 0x00, 0xBD, 0xCE, 0x1E)));
    }

    [Fact]
    public void A_class_found_by_rtf_and_by_a_compound_object_is_listed_once()
    {
        var doc = new OfficeDocument { Format = "x" };
        doc.AddClass("object 1", "OLE Package", true);
        doc.AddClass("object 1", "OLE Package", true);
        Assert.Single(doc.Classes);
    }

    [Fact]
    [FuzzEntry(typeof(EquationNative))]
    public void Fuzzed_equation_streams_never_throw()
    {
        var failures = FormatFuzz.Run(Mtef("Times New Roman"), b => EquationNative.Read(b, "e", []), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
