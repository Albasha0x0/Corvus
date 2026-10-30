using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Standalone HTML and SVG pages that build a file in a Blob and save it yield that file as a member.</summary>
public sealed class BlobPayloadTests
{
    private static byte[] ArchiveBytes(int size)
    {
        var data = new byte[size];
        new Random(7).NextBytes(data);
        return ContainerFixtures.Zip(("report.bin", data));
    }

    private static string Script(string literal, string name = "invoice.zip") =>
        $"var data = {literal}; var bin = atob(data); var bytes = new Uint8Array(bin.length); " +
        "for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i); " +
        $"var blob = new Blob([bytes], {{ type: 'application/zip' }}); var a = document.createElement('a'); " +
        $"a.href = URL.createObjectURL(blob); a.download = '{name}'; a.click();";

    private static string Html(string script) => $"<html><body><button>Open</button><script>{script}</script></body></html>";

    private static string Svg(string script) =>
        $"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"10\" height=\"10\"><script type=\"application/ecmascript\"><![CDATA[{script}]]></script></svg>";

    private static ContainerContents Open(string page, string name) => Containers.Open(Encoding.UTF8.GetBytes(page), name, AnalysisLimits.Default, default);

    private static FileView? View(string page, string name) =>
        new ScriptFileView().Inspect(new FileInput(name, Encoding.UTF8.GetBytes(page), "text"), default);

    [Fact]
    public void An_html_page_that_builds_a_zip_in_a_blob_yields_the_zip()
    {
        var zip = ArchiveBytes(8000);
        var c = Open(Html(Script($"'{Convert.ToBase64String(zip)}'")), "invoice.html");
        Assert.Equal(zip, c.Items.Single(i => i.Name == "payload_1.zip").Bytes);
    }

    [Fact]
    public void An_svg_that_builds_a_zip_in_a_blob_yields_the_zip_and_a_finding()
    {
        var zip = ArchiveBytes(8000);
        var page = Svg(Script($"'{Convert.ToBase64String(zip)}'"));
        Assert.Equal(zip, Open(page, "logo.svg").Items.Single().Bytes);
        var view = View(page, "logo.svg")!;
        Assert.Contains(view.Findings, f => f is { Rule: "page/blob-payload", Level: "noteworthy", Source: "page" });
        Assert.Contains(((ScriptFileView.Facts)view.Detail).Payloads!, p => p.Kind == "zip");
    }

    [Fact]
    public void A_literal_split_across_concatenated_strings_is_carved()
    {
        var b64 = Convert.ToBase64String(ArchiveBytes(8000));
        var half = b64.Length / 2;
        var c = Open(Html(Script($"'{b64[..half]}' + '{b64[half..]}'")), "invoice.html");
        Assert.Single(c.Items);
    }

    [Fact]
    public void A_web_app_export_button_reports_nothing()
    {
        const string script = "document.getElementById('export').onclick = function () { var rows = JSON.stringify(window.table); " +
            "var blob = new Blob([rows], { type: 'application/json' }); var a = document.createElement('a'); " +
            "a.href = URL.createObjectURL(blob); a.download = 'table.json'; a.click(); };";
        var page = Html(script);
        Assert.Empty(Open(page, "app.html").Items);
        Assert.Empty(View(page, "app.html")?.Findings ?? []);
    }

    [Fact]
    public void A_page_that_loads_script_files_is_not_read_for_payloads()
    {
        var page = Html(Script($"'{Convert.ToBase64String(ArchiveBytes(8000))}'")).Replace("<button>", "<script src=\"app.js\"></script><button>", StringComparison.Ordinal);
        Assert.Empty(Open(page, "app.html").Items);
    }

    [Fact]
    public void A_payload_of_4_KiB_or_less_is_not_carved()
    {
        var small = ContainerFixtures.Zip(("a.txt", "x"u8.ToArray()));
        Assert.Empty(Open(Html(Script($"'{Convert.ToBase64String(small)}'")), "invoice.html").Items);
    }

    [Fact]
    public void A_large_image_literal_is_not_carved()
    {
        var png = new byte[9000];
        new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(png, 0);
        Assert.Empty(Open(Html(Script($"'{Convert.ToBase64String(png)}'", "chart.png")), "chart.html").Items);
    }

    [Fact]
    [FuzzEntry(typeof(BlobPayloadReader))]
    public void Fuzzed_pages_never_throw_past_a_tool_error()
    {
        var page = Encoding.UTF8.GetBytes(Svg(Script($"'{Convert.ToBase64String(ArchiveBytes(6000))}'")));
        var failures = FormatFuzz.Run(page, b =>
        {
            try { Containers.Open(b, "logo.svg", AnalysisLimits.Default, default); } catch (ToolError) { }
            try { new ScriptFileView().Inspect(new FileInput("logo.svg", b, "text"), default); } catch (ToolError) { }
        }, 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
