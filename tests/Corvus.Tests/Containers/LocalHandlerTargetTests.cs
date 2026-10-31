using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>Local-handler schemes and UNC paths in Office relationships, HTML attributes, PDF actions and Windows shell files.</summary>
public sealed class LocalHandlerTargetTests
{
    private static FileView View(IFileSummaryView view, string name, byte[] data) =>
        view.Inspect(new FileInput(name, data, Blob.Identify(data)) { Options = new FileViewOptions(view.Name) }, default)!;

    private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Docx(string target) => Ooxml(
        ("word/document.xml", Text("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"/>")),
        ("word/_rels/document.xml.rels", Text("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            $"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"{target}\" TargetMode=\"External\"/></Relationships>")));

    [Fact]
    public void A_search_ms_relationship_target_is_reported_at_its_part()
    {
        var f = Assert.Single(View(new OfficeFileView(), "a.docx", Docx("search-ms:query=x&amp;crumb=location:file")).Findings);
        Assert.Equal(("link/local-handler", "review", "word/_rels/document.xml.rels"), (f.Rule, f.Level, f.Location));
        Assert.Contains("search-ms: protocol handler", f.Evidence);
    }

    [Fact]
    public void An_https_relationship_target_is_not_reported()
    {
        Assert.DoesNotContain(View(new OfficeFileView(), "a.docx", Docx("https://example.com/a")).Findings, f => f.Rule == "link/local-handler");
    }

    [Fact]
    public void An_html_page_with_an_ms_msdt_link_is_reported()
    {
        var page = Text("<!doctype html><a href=\"ms-msdt:/id PCWDiagnostic /skip force\">x</a><a href='https://example.com/'>y</a><form action=\"\\\\host\\share\\f\"></form>");
        var found = View(new PageFileView(), "p.html", page).Findings;
        Assert.Equal(["href attribute", "action attribute"], found.Select(f => f.Location));
        Assert.Contains("ms-msdt: protocol handler", found[0].Evidence);
        Assert.Contains("UNC path", found[1].Evidence);
    }

    [Fact]
    public void An_html_page_with_only_https_and_mailto_links_reports_nothing_new()
    {
        var page = Text("<!doctype html><a href=\"https://example.com/\">y</a><a href=\"mailto:a@example.com\">m</a><img src=\"a.png\"><div data-href=\"search-ms:query=x\"></div>");
        Assert.Empty(View(new PageFileView(), "p.html", page).Findings);
    }

    [Fact]
    public void An_svg_link_with_a_search_ms_target_is_reported()
    {
        var svg = Text("<svg xmlns=\"http://www.w3.org/2000/svg\"><a href=\"search-ms:query=x\"><text>y</text></a></svg>");
        Assert.Contains(View(new PageFileView(), "p.svg", svg).Findings, f => f.Rule == "link/local-handler");
    }

    [Fact]
    public void A_PDF_URI_and_remote_go_to_action_with_local_targets_are_reported()
    {
        var pdf = Text("%PDF-1.4\n1 0 obj\n<</Type/Catalog/OpenAction 2 0 R>>\nendobj\n2 0 obj\n<</S/URI/URI(search-ms:query=x)>>\nendobj\n" +
                       "3 0 obj\n<</S/GoToR/F(\\\\\\\\host\\\\share\\\\a.pdf)>>\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF\n");
        var found = View(new PdfFileView(), "a.pdf", pdf).Findings.Where(f => f.Rule == "link/local-handler").ToList();
        Assert.Equal(2, found.Count);
    }

    [Fact]
    public void A_library_pointing_at_a_WebDAV_share_names_the_location()
    {
        var xml = Text("<?xml version=\"1.0\"?><libraryDescription xmlns=\"http://schemas.microsoft.com/windows/2009/library\"><searchConnectorDescriptionList><searchConnectorDescription>" +
            "<simpleLocation><url>\\\\host.example@SSL\\DavWWWRoot\\share</url></simpleLocation></searchConnectorDescription></searchConnectorDescriptionList></libraryDescription>");
        var view = View(new ShellFileView(), "docs.library-ms", xml);
        Assert.Equal("UNC path to a WebDAV share", Assert.Single(((ShellFileView.Facts)view.Detail).Targets).Kind);
        Assert.Contains(view.Highlights, h => h.Contains("UNC path to a WebDAV share"));
        Assert.Equal("link/local-handler", Assert.Single(view.Findings).Rule);
    }

    [Fact]
    public void A_search_connector_with_an_http_location_names_a_network_location_without_a_finding()
    {
        var xml = Text("<searchConnectorDescription xmlns=\"http://schemas.microsoft.com/windows/2009/searchConnector\"><simpleLocation><url>https://example.com/dav</url></simpleLocation></searchConnectorDescription>");
        var view = View(new ShellFileView(), "x.searchConnector-ms", xml);
        Assert.Equal("network location (WebDAV)", Assert.Single(((ShellFileView.Facts)view.Detail).Targets).Kind);
        Assert.Empty(view.Findings);
    }

    [Fact]
    public void A_url_file_to_https_reports_nothing_beyond_its_target()
    {
        var view = View(new ShellFileView(), "a.url", Text("[InternetShortcut]\r\nURL=https://example.com/\r\nIconFile=C:\\x.ico\r\n"));
        Assert.Equal(["URL", "IconFile"], ((ShellFileView.Facts)view.Detail).Targets.Select(t => t.Field));
        Assert.Empty(view.Findings);
    }

    [Fact]
    public void A_url_file_with_a_search_ms_target_is_reported()
    {
        var view = View(new ShellFileView(), "a.url", Text("[InternetShortcut]\nURL=search-ms:query=x\n"));
        Assert.Equal("URL", Assert.Single(view.Findings).Location);
    }

    [Fact]
    public void A_malformed_library_file_notes_its_targets_as_unknown()
    {
        var view = View(new ShellFileView(), "a.library-ms", Text("<libraryDescription><url>"));
        Assert.Contains("unknown", Assert.Single(((ShellFileView.Facts)view.Detail).Notes));
    }
}
