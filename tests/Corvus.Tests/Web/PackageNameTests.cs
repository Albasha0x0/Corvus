using System.Text;
using Corvus.Core;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>Names that disguise a file's type and package names close to popular ones.</summary>
public sealed class PackageNameTests
{
    private static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    private static ContainerContents Open(params string[] names) =>
        Containers.Open(ContainerFixtures.Zip([.. names.Select(n => (n, U("x")))]), "a.zip", AnalysisLimits.Default, default, allFiles: true);

    [Fact]
    public void A_bidi_control_in_a_zip_member_name_is_named()
    {
        var c = Open("invoice\u202Etxt.exe", "readme.txt");
        var note = Assert.Single(c.Notes, n => n.Contains("disguise", StringComparison.Ordinal));
        Assert.Contains("U+202E", note, StringComparison.Ordinal);
    }

    [Fact]
    public void A_runnable_after_a_document_extension_is_named()
    {
        Assert.Contains(Open("invoice.pdf.exe").Notes, n => n.Contains("invoice.pdf.exe", StringComparison.Ordinal));
    }

    [Fact]
    public void A_name_padded_with_spaces_before_its_extension_is_named()
    {
        Assert.Contains(Open("invoice.pdf" + new string(' ', 30) + ".exe").Notes, n => n.Contains("padded", StringComparison.Ordinal));
    }

    [Fact]
    public void Harmless_member_names_report_nothing()
    {
        var c = Open("report.v2.pdf", "setup.exe", "data.tar.gz", "my notes.txt", "a.b.c.js", "dir.exe/readme.txt");
        Assert.DoesNotContain(c.Notes, n => n.Contains("disguise", StringComparison.Ordinal));
    }

    [Fact]
    public void A_package_with_a_disguised_member_name_gets_one_review_finding()
    {
        var path = Path.Combine(Path.GetTempPath(), "names-" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            File.WriteAllBytes(path, ContainerFixtures.Zip(
                ("package.json", U("""{"name":"quiet-tool","version":"1.0.0"}""")), ("a.pdf.exe", U("x")), ("b.doc.scr", U("x"))));
            var r = PackageReview.Review(path, default)!;
            Assert.Single(r.Findings, f => f is { Rule: "package/member-name", Level: "review" });
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("react-dom-utils", "react-dom")]
    [InlineData("secure-lodash", "lodash")]
    [InlineData("@typess/node", "@types/node")]
    [InlineData("\u0441halk", "chalk")]
    [InlineData("rnoment", "moment")]
    public void A_name_near_a_popular_one_is_reported(string name, string popular)
    {
        Assert.Equal(popular, PackageReview.CloseTo(name, PopularNames.Npm));
    }

    [Theory]
    [InlineData("react-dom")]
    [InlineData("react-dom-router-extras-kit")]
    [InlineData("lodash-es")]
    [InlineData("axios-retry")]
    [InlineData("@swc/core")]
    [InlineData("my-app")]
    public void Harmless_package_names_are_not_reported(string name)
    {
        Assert.Null(PackageReview.CloseTo(name, PopularNames.Npm));
    }

    [Theory]
    [InlineData("Newtonsoft.Jsonn", "Newtonsoft.Json")]
    [InlineData("Serilog-Utils", "Serilog")]
    public void A_name_near_a_popular_NuGet_id_is_reported(string name, string popular)
    {
        Assert.Equal(popular, PackageReview.CloseTo(name, PopularNames.NuGet));
    }

    [Fact]
    public void A_name_near_a_popular_gem_is_reported()
    {
        Assert.Equal("rails", PackageReview.CloseTo("railz", PopularNames.RubyGems));
        Assert.Null(PackageReview.CloseTo("rails", PopularNames.RubyGems));
    }

    [Fact]
    public void A_mail_attachment_with_a_disguised_name_is_named_in_the_highlights()
    {
        var bytes = U("From: a@example.com\r\nTo: b@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x\r\nContent-Type: application/octet-stream; name=invoice.pdf.exe\r\nContent-Disposition: attachment; filename=invoice.pdf.exe\r\n\r\nraw\r\n--x--\r\n");
        var view = new Corvus.Services.Analysis.MailFileView().Inspect(new Corvus.Services.Analysis.FileInput("m.eml", bytes, Blob.Identify(bytes)), default)!;
        Assert.Contains(view.Highlights, h => h.Contains("disguise", StringComparison.Ordinal) && h.Contains("invoice.pdf.exe", StringComparison.Ordinal));
    }
}
