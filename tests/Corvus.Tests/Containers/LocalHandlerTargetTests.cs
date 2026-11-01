using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;
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

    public static IEnumerable<object[]> HandlerSchemes() => HandlerTargets.Schemes.Select(s => new object[] { s });

    private static string Expected(string scheme) =>
        scheme == "ms-officecmd" ? scheme + ": protocol handler, parameters unspecified" : scheme + ": protocol handler";

    [Theory]
    [MemberData(nameof(HandlerSchemes))]
    public void Each_handler_scheme_is_reported_in_an_Office_relationship(string scheme)
    {
        var view = View(new OfficeFileView(), "a.docx", Docx(scheme + ":x"));
        var found = Assert.Single(view.Findings, f => f.Rule == "link/local-handler");
        Assert.Contains(Expected(scheme), found.Evidence);
    }

    [Theory]
    [MemberData(nameof(HandlerSchemes))]
    public void Each_handler_scheme_is_reported_in_a_PDF_URI_action(string scheme)
    {
        var pdf = Text("%PDF-1.4\n1 0 obj\n<</Type/Catalog/OpenAction 2 0 R>>\nendobj\n" +
                       "2 0 obj\n<</S/URI/URI(" + scheme + ":x)>>\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF\n");
        var found = Assert.Single(View(new PdfFileView(), "a.pdf", pdf).Findings, f => f.Rule == "link/local-handler");
        Assert.Contains(Expected(scheme), found.Evidence);
    }

    [Theory]
    [InlineData("MS-OFFICECMD:")]
    [InlineData("ms-officecmd:{\"id\":1}")]
    [InlineData("ms-officecmd:{not json")]
    public void An_ms_officecmd_target_is_matched_by_scheme_whatever_its_parameters(string target)
    {
        Assert.Equal("ms-officecmd: protocol handler, parameters unspecified", LocalHandlerTargets.Match(target));
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

    [Fact]
    public void A_console_file_lists_its_snap_ins_task_commands_and_script_strings()
    {
        var xml = Text("<?xml version=\"1.0\"?><MMC_ConsoleFile><ScopeTree><SnapIns><SnapIn CLSID=\"{C96401CF-0E17-11D3-885B-00C04F72C717}\"/></SnapIns></ScopeTree>" +
            "<ConsoleTaskpads><Task><Command Command=\"powershell.exe\" Params=\"-e SQBFAFgAIAAoAEcAZQB0AC0ARABhAHQAZQApAA==\"/></Task></ConsoleTaskpads>" +
            "<StringTable><Strings><String ID=\"1\">res://apds.dll/redirect.html?target=javascript:eval(x)</String></Strings></StringTable></MMC_ConsoleFile>");
        var view = View(new ShellFileView(), "a.msc", xml);
        var facts = (ShellFileView.Facts)view.Detail;
        Assert.Equal("{C96401CF-0E17-11D3-885B-00C04F72C717}", Assert.Single(facts.SnapIns!));
        Assert.Equal(["Task/Command", "StringTable"], facts.Targets.Select(t => t.Field));
        Assert.Equal("resource reference with a script URL", facts.Targets[1].Kind);
        Assert.Contains(view.Findings, f => f.Rule == "launcher/command-line");
    }

    [Fact]
    public void A_console_file_that_is_not_well_formed_has_unknown_snap_ins()
    {
        var view = View(new ShellFileView(), "a.msc", Text("<MMC_ConsoleFile><SnapIns>"));
        var facts = (ShellFileView.Facts)view.Detail;
        Assert.Null(facts.SnapIns);
        Assert.Contains("unknown", Assert.Single(facts.Notes));
        Assert.DoesNotContain(view.Highlights, h => h.Contains("Snap-ins"));
    }

    [Fact]
    public void A_console_file_without_snap_ins_or_tasks_has_an_empty_snap_in_list()
    {
        var view = View(new ShellFileView(), "a.msc", Text("<MMC_ConsoleFile/>"));
        var facts = (ShellFileView.Facts)view.Detail;
        Assert.Empty(facts.SnapIns!);
        Assert.Empty(facts.Targets);
        Assert.DoesNotContain(view.Highlights, h => h.Contains("Snap-ins"));
    }

    [Fact]
    public void A_console_task_with_child_element_values_and_a_handler_in_its_params_is_classified()
    {
        var xml = Text("<MMC_ConsoleFile><Task><Command>cmd.exe</Command><params>ms-msdt:/id PCWDiagnostic</params></Task>" +
            "<SnapIns><snapin clsid=\"{A}\"/><snapin clsid=\"{A}\"/></SnapIns><Strings><String>search-ms:query=x</String></Strings></MMC_ConsoleFile>");
        var view = View(new ShellFileView(), "a.msc", xml);
        var facts = (ShellFileView.Facts)view.Detail;
        Assert.Equal("{A}", Assert.Single(facts.SnapIns!));
        Assert.Equal("cmd.exe ms-msdt:/id PCWDiagnostic", facts.Targets[0].Value);
        Assert.NotNull(facts.Targets[0].Kind);
        Assert.Equal("StringTable", facts.Targets[1].Field);
        Assert.NotNull(facts.Targets[1].Kind);
    }

    [Fact]
    public void A_cancelled_console_read_throws()
    {
        var data = Text("<MMC_ConsoleFile><SnapIns><SnapIn CLSID=\"{A}\"/></SnapIns></MMC_ConsoleFile>");
        var view = new ShellFileView();
        var input = new FileInput("a.msc", data, Blob.Identify(data)) { Options = new FileViewOptions(view.Name) };
        Assert.ThrowsAny<OperationCanceledException>(() => view.Inspect(input, new CancellationToken(true)));
    }

    private static ShellFileView.Facts Shell(string name, byte[] data) => (ShellFileView.Facts)View(new ShellFileView(), name, data).Detail;

    [Fact]
    public void An_scf_file_with_a_unc_icon_file_is_reported_and_its_command_id_is_not()
    {
        var view = View(new ShellFileView(), "a.scf", Text("[Shell]\r\nCommand=2\r\nIconFile=\\\\host\\share\\i.ico\r\n"));
        var target = Assert.Single(((ShellFileView.Facts)view.Detail).Targets);
        Assert.Equal(("IconFile", "UNC path"), (target.Field, target.Kind?[..8]));
        Assert.Equal("IconFile", Assert.Single(view.Findings).Location);
    }

    [Fact]
    public void A_desktop_ini_icon_resource_on_a_share_is_reported()
    {
        var view = View(new ShellFileView(), "desktop.ini", Text("[.ShellClassInfo]\nIconResource=\\\\host\\share\\i.dll,0\nInfoTip=text\n"));
        Assert.Equal(["IconResource", "InfoTip"], ((ShellFileView.Facts)view.Detail).Targets.Select(t => t.Field));
        Assert.Equal("IconResource", Assert.Single(view.Findings).Location);
    }

    [Fact]
    public void An_inf_file_lists_the_command_lines_of_the_sections_it_names()
    {
        var facts = Shell("a.inf", Text("[DefaultInstall]\nRunPostSetupCommands=Post,Gone\nRegisterDlls=Reg\nAddReg=Keys\n" +
            "[Post]\ncmd.exe /c echo x\n[Reg]\n11,,a.dll,1\n[Keys]\nHKLM,Software\\Microsoft\\Windows\\CurrentVersion\\Run,App,,C:\\p\\a.exe\nHKLM,Software\\Other,Name,,v\n"));
        Assert.Equal([("RunPostSetupCommands", "command"), ("RegisterDlls", "module registration"), (@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\App", "autostart value")],
            facts.Targets.Select(t => (t.Field, t.Kind!)));
        Assert.Contains("[Gone]", Assert.Single(facts.Notes));
    }

    [Fact]
    public void A_reg_file_lists_run_values_in_ansi_and_utf16_text()
    {
        const string reg = "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n\"App\"=\"C:\\\\p\\\\a.exe \\\"x\\\"\"\r\n";
        foreach (var bytes in new[] { Text(reg), Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(reg)).ToArray() })
        {
            var target = Assert.Single(Shell("a.reg", bytes).Targets);
            Assert.Equal(("App", "C:\\p\\a.exe \"x\"", "autostart value"), (target.Field[(target.Field.LastIndexOf('\\') + 1)..], target.Value, target.Kind));
        }
    }

    [Fact]
    public void A_reg_file_decodes_expandable_values_and_counts_binary_ones()
    {
        var facts = Shell("a.reg", Text("[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"A\"=hex(2):25,00,70,00,25,00,00,00\n\"B\"=hex:01,02,\\\n  03\n"));
        Assert.Equal("%p%", Assert.Single(facts.Targets).Value);
        Assert.Contains("1 non-string", Assert.Single(facts.Notes));
    }

    [Fact]
    public void A_reg_file_skips_unrelated_services_values_and_deleted_keys()
    {
        var facts = Shell("a.reg", Text("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\S]\n\"DisplayName\"=\"n\"\n\"ImagePath\"=\"C:\\\\s.exe\"\n" +
            "[-HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Gone\"=\"x\"\n"));
        Assert.Equal("C:\\s.exe", Assert.Single(facts.Targets).Value);
    }

    [Fact]
    public void An_appinstaller_file_lists_http_and_dependency_locations()
    {
        var xml = "<AppInstaller xmlns=\"http://schemas.microsoft.com/appx/appinstaller/2017\" Uri=\"https://example.com/a.appinstaller\"><MainPackage Uri=\"http://example.com/a.msix\"/>" +
            "<Dependencies><Package Uri=\"https://example.com/d.msix\"/></Dependencies><UpdateSettings><OnLaunch HoursBetweenUpdateChecks=\"0\"/></UpdateSettings></AppInstaller>";
        var targets = Shell("a.appinstaller", Text(xml)).Targets;
        Assert.Equal([("AppInstaller/Uri", null), ("MainPackage/Uri", "unencrypted location"), ("Package/Uri", null), ("UpdateSettings/OnLaunch", "update setting")],
            targets.Select(t => (t.Field, t.Kind)));
    }

    [Fact]
    public void A_malformed_appinstaller_file_notes_its_targets_as_unknown()
    {
        Assert.Contains("unknown", Assert.Single(Shell("a.appinstaller", Text("<AppInstaller><MainPackage")).Notes));
    }

    [Fact]
    public void An_empty_shell_file_reports_no_target_and_names_the_next_view()
    {
        foreach (var name in new[] { "a.scf", "desktop.ini", "a.inf", "a.reg", "a.appinstaller" })
        {
            var view = View(new ShellFileView(), name, name == "a.appinstaller" ? Text("<AppInstaller/>") : Text(" "));
            Assert.Contains("no target", view.Highlights[0]);
            Assert.Contains("view=script", Assert.Single(((ShellFileView.Facts)view.Detail).Notes));
        }
    }

    [Fact]
    public void A_url_file_with_an_ms_appinstaller_target_is_reported()
    {
        var view = View(new ShellFileView(), "a.url", Text("[InternetShortcut]\nURL=ms-appinstaller:?source=https://example.com/a.msix\n"));
        Assert.Contains("ms-appinstaller: protocol handler", Assert.Single(view.Findings).Evidence);
    }
}
