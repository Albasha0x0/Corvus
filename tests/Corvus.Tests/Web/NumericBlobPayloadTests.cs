using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Pages that build a file in a Blob from a numeric array yield that file as a member.</summary>
public sealed class NumericBlobPayloadTests
{
    private const string Save =
        "var blob = new Blob([bytes], { type: 'application/zip' }); var a = document.createElement('a'); " +
        "a.href = URL.createObjectURL(blob); a.download = 'invoice.zip'; a.click();";

    private static string Decimal(byte[] data) => string.Join(",", data);

    private static string Hex(byte[] data) => string.Join(", ", data.Select(b => "0x" + b.ToString("x2")));

    private static string ListScript(string list) => $"var bytes = new Uint8Array([{list}]); {Save}";

    private static ContainerContents Open(string page, string name) =>
        Containers.Open(Encoding.UTF8.GetBytes(page), name, AnalysisLimits.Default, default);

    [Fact]
    public void An_html_page_that_builds_a_zip_from_a_number_list_yields_the_zip()
    {
        var zip = BlobPayloadTests.ArchiveBytes(8000);
        var c = Open(BlobPayloadTests.Html(ListScript(Decimal(zip))), "invoice.html");
        Assert.Equal(zip, c.Items.Single(i => i.Name == "payload_1.zip").Bytes);
    }

    [Fact]
    public void An_svg_that_builds_a_zip_from_a_hex_list_yields_the_zip_and_a_finding()
    {
        var zip = BlobPayloadTests.ArchiveBytes(8000);
        var page = BlobPayloadTests.Svg(ListScript(Hex(zip)));
        Assert.Equal(zip, Open(page, "logo.svg").Items.Single().Bytes);
        var view = new ScriptFileView().Inspect(new FileInput("logo.svg", Encoding.UTF8.GetBytes(page), "text"), default)!;
        Assert.Contains(view.Findings, f => f is { Rule: "page/blob-payload", Level: "noteworthy", Source: "page" });
        Assert.Contains(((ScriptFileView.Facts)view.Detail).Payloads!, p => p.Kind == "zip");
    }

    [Fact]
    public void A_fromCharCode_built_zip_is_carved()
    {
        var zip = BlobPayloadTests.ArchiveBytes(8000);
        var script = $"var bytes = String.fromCharCode({Decimal(zip)}); {Save}";
        var c = Open(BlobPayloadTests.Html(script), "invoice.html");
        Assert.Equal(zip, c.Items.Single().Bytes);
    }

    [Fact]
    public void A_number_list_of_plain_text_bytes_is_not_carved()
    {
        var text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("plain text row\n", 500)));
        Assert.Empty(Open(BlobPayloadTests.Html(ListScript(Decimal(text))), "app.html").Items);
    }

    [Fact]
    public void A_page_with_a_number_list_and_no_blob_reports_nothing()
    {
        var zip = BlobPayloadTests.ArchiveBytes(8000);
        var script = $"var bytes = new Uint8Array([{Decimal(zip)}]); window.table = bytes;";
        Assert.Empty(Open(BlobPayloadTests.Html(script), "app.html").Items);
    }

    [Fact]
    public void The_same_file_in_base64_and_numbers_is_carved_once()
    {
        var zip = BlobPayloadTests.ArchiveBytes(8000);
        var script = BlobPayloadTests.Script($"'{Convert.ToBase64String(zip)}'") + $" var again = new Uint8Array([{Decimal(zip)}]);";
        Assert.Single(Open(BlobPayloadTests.Html(script), "invoice.html").Items);
    }
}
