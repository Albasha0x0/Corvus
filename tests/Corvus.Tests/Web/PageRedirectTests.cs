using System.Text;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Standalone pages are read for forms posting to another origin, password inputs in them, meta refresh and location redirects.</summary>
public sealed class PageRedirectTests
{
    private static IReadOnlyList<Finding> Read(string page, string name = "page.html") =>
        new PageFileView().Inspect(new FileInput(name, Encoding.UTF8.GetBytes(page), "text"), default)?.Findings ?? [];

    private static string Login(string action) =>
        $"<!doctype html>\n<html><body>\n<form method=\"post\" action=\"{action}\">\n<input type=\"text\" name=\"u\">\n<input type=\"password\" name=\"p\">\n</form></body></html>";

    [Fact]
    public void A_login_form_posting_to_another_host_yields_the_form_and_password_findings()
    {
        var f = Read(Login("https://other.example/login"));
        Assert.Contains(f, x => x is { Rule: "page/foreign-form", Level: "review", Location: "<form> line 3" });
        Assert.Contains(f, x => x is { Rule: "page/password-foreign-form", Location: "<input> line 5" });
    }

    [Fact]
    public void A_login_form_with_a_relative_action_yields_nothing() => Assert.Empty(Read(Login("/login")));

    [Fact]
    public void A_meta_refresh_to_a_url_yields_a_finding() =>
        Assert.Contains(Read("<!doctype html><html><head><meta http-equiv=\"refresh\" content=\"0; url=https://other.example/\"></head></html>"),
            x => x is { Rule: "page/meta-refresh", Location: "<meta> line 1" });

    [Fact]
    public void A_location_replace_call_with_a_literal_yields_a_finding() =>
        Assert.Contains(Read("<!doctype html><html><body><script>\nlocation.replace('https://other.example/');\n</script></body></html>"),
            x => x is { Rule: "page/script-redirect", Location: "<script> line 2" });

    [Fact]
    public void An_svg_script_assigning_location_yields_a_finding() =>
        Assert.Contains(Read("<svg xmlns=\"http://www.w3.org/2000/svg\"><script><![CDATA[window.location = \"https://other.example/\";]]></script></svg>", "logo.svg"),
            x => x.Rule == "page/script-redirect");

    [Fact]
    public void A_script_assigning_a_fragment_yields_nothing() =>
        Assert.Empty(Read("<!doctype html><html><body><script>\nlocation.href = '#top';\n</script></body></html>"));

    [Fact]
    public void Commented_out_script_lines_yield_nothing() =>
        Assert.Empty(Read("<!doctype html><html><body><script>\n// location.replace('https://other.example/');\n/* location = 'https://other.example/'; */\n</script></body></html>"));

    [Fact]
    public void A_redirect_after_a_slash_slash_inside_a_string_yields_a_finding() =>
        Assert.Contains(Read("<!doctype html><html><body><script>\nvar a = 'https://x.example/'; location.replace('https://other.example/');\n</script></body></html>"),
            x => x is { Rule: "page/script-redirect", Location: "<script> line 2" });

    [Fact]
    public void A_redirect_after_a_multiline_block_comment_keeps_its_line() =>
        Assert.Contains(Read("<!doctype html><html><body><script>\n/* a\nb\nc */\nlocation.replace('https://other.example/');\n</script></body></html>"),
            x => x is { Rule: "page/script-redirect", Location: "<script> line 5" });

    [Fact]
    public void A_redirect_after_a_regex_literal_holding_a_quote_yields_a_finding() =>
        Assert.Contains(Read("<!doctype html><html><body><script>\nvar r=/'/; location.replace('https://evil.example/')\n</script></body></html>"),
            x => x.Rule == "page/script-redirect");

    [Fact]
    public void A_redirect_after_a_template_literal_holding_slashes_yields_a_finding() =>
        Assert.Contains(Read("<!doctype html><html><body><script>\nvar t=`http://a.example`; location.replace('https://other.example/');\n</script></body></html>"),
            x => x.Rule == "page/script-redirect");

    [Fact]
    public void A_fragment_with_leading_space_is_skipped_and_a_later_redirect_is_reported() =>
        Assert.Single(Read("<!doctype html><html><body><script>\nlocation = ' #a'; location.replace('https://other.example/');\n</script></body></html>"),
            x => x.Rule == "page/script-redirect");

    [Fact]
    public void An_article_with_links_and_a_get_search_form_yields_nothing() =>
        Assert.Empty(Read("<!doctype html><html><body><a href=\"https://other.example/\">x</a><form method=\"get\" action=\"https://search.example/q\"><input name=\"q\"></form>" +
            "<script>if (location.href == \"https://a.example/\") { run(); }</script></body></html>"));

    [Fact]
    public void A_plain_svg_yields_no_view() =>
        Assert.Null(new PageFileView().Inspect(new FileInput("a.svg", Encoding.UTF8.GetBytes("<svg xmlns=\"http://www.w3.org/2000/svg\"><circle r=\"1\"/></svg>"), "text"), default));
}
