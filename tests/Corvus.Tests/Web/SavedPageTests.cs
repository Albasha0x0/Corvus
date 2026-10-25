using System.Security.Cryptography;
using System.Text;
using Corvus.Services.Analysis;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>Saved web pages: scripts with their Subresource Integrity checked, import maps and meta Content Security Policy.</summary>
public sealed class SavedPageTests : IDisposable
{
    // The example script of the W3C SRI and CSP Level 3 specifications, with the hashes they print.
    private const string Hello = "alert('Hello, world.');";
    private const string HelloSha384 = "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO";
    private const string HelloSha256 = "'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng='";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private PageFileView.Facts View(string html, params (string Path, string Text)[] files)
    {
        foreach (var (path, text) in files)
        {
            var full = Path.Combine(_dir.Path, path);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text);
        }
        var page = Path.Combine(_dir.Path, "ledger.html");
        var bytes = Encoding.UTF8.GetBytes(html);
        File.WriteAllBytes(page, bytes);
        return (PageFileView.Facts)new PageFileView().Inspect(new FileInput(page, bytes, "text"), default)!.Detail;
    }

    private static string Sri(string alg, string text) => alg + "-" + Convert.ToBase64String(alg switch
    {
        "sha256" => SHA256.HashData(Encoding.UTF8.GetBytes(text)),
        "sha384" => SHA384.HashData(Encoding.UTF8.GetBytes(text)),
        _ => SHA512.HashData(Encoding.UTF8.GetBytes(text)),
    });

    [Fact]
    public void Integrity_is_checked_with_the_strongest_listed_algorithm_only()
    {
        var bytes = Encoding.UTF8.GetBytes(Hello);
        Assert.Equal("match (sha384)", SavedPage.CheckIntegrity(HelloSha384, bytes));
        Assert.Equal("match (sha384)", SavedPage.CheckIntegrity("sha256-wrong " + HelloSha384 + "?ct=application/javascript", bytes));
        Assert.StartsWith("mismatch (sha512", SavedPage.CheckIntegrity(Sri("sha256", Hello) + " sha512-wrong", bytes), StringComparison.Ordinal);
        Assert.StartsWith("no supported hash", SavedPage.CheckIntegrity("md5-abc", bytes), StringComparison.Ordinal);
        Assert.Equal("unknown (sha384; bytes not saved)", SavedPage.CheckIntegrity(HelloSha384, null));
    }

    [Fact]
    public void A_saved_page_checks_each_script_against_the_file_saved_beside_it()
    {
        var facts = View($"""
            <!DOCTYPE html>
            <!-- saved from url=(0035)https://ledger.example.com/reports -->
            <html><head><title>Ledger &amp; reports</title>
            <script src="ledger_files/app.js" integrity="{Sri("sha384", "run()")}"></script>
            <script src='ledger_files/lib.js' integrity="{Sri("sha256", "old")}"></script>
            <script src="https://cdn.example.net/chart.js"></script>
            <script src="https://cdn.example.net/table.js" integrity="{HelloSha384}"></script>
            <script src="data:text/javascript;base64,{Convert.ToBase64String(Encoding.UTF8.GetBytes(Hello))}" integrity="{HelloSha384}"></script>
            <script src="ledger_files/missing.js" integrity="{HelloSha384}"></script>
            <script src="../outside.js"></script>
            <link rel="stylesheet" href="ledger_files/site.css" integrity="{Sri("sha512", "body{}")}">
            <!-- <script src="commented.js"></script> -->
            <script>document.write("<!--");</script>
            <script src="ledger_files/after.js"></script>
            </head></html>
            """, ("ledger_files/app.js", "run()"), ("ledger_files/lib.js", "new"), ("ledger_files/site.css", "body{}"), ("ledger_files/after.js", ""));
        Assert.Equal("https://ledger.example.com/reports", facts.Url);
        Assert.Equal("Ledger & reports", facts.Title);
        // A browser skips the commented element; "<!--" inside a script's text opens no comment.
        Assert.Single(facts.Resources, x => x.Location == "inline");
        var r = facts.Resources.Where(x => x.Source != null).ToDictionary(x => x.Source!);
        Assert.Equal(9, r.Count);
        Assert.Equal("saved", r["ledger_files/after.js"].Location);
        Assert.Equal(("saved", "match (sha384)"), (r["ledger_files/app.js"].Location, r["ledger_files/app.js"].IntegrityCheck));
        Assert.StartsWith("mismatch (sha256: the bytes hash to " + Sri("sha256", "new"), r["ledger_files/lib.js"].IntegrityCheck, StringComparison.Ordinal);
        Assert.Equal("remote", r["https://cdn.example.net/chart.js"].Location);
        Assert.Contains("code from https://cdn.example.net without integrity", r["https://cdn.example.net/chart.js"].Notes!);
        Assert.Contains(r["https://cdn.example.net/table.js"].Notes!, n => n.StartsWith("integrity on a cross-origin resource without crossorigin", StringComparison.Ordinal));
        Assert.Equal("match (sha384)", r.Values.Single(x => x.Location == "data").IntegrityCheck);
        Assert.Equal(("not saved", "unknown (sha384; bytes not saved)"), (r["ledger_files/missing.js"].Location, r["ledger_files/missing.js"].IntegrityCheck));
        Assert.Equal("outside", r["../outside.js"].Location);
        Assert.Null(r["../outside.js"].Size);
        Assert.Equal(("link", "match (sha512)"), (r["ledger_files/site.css"].Element, r["ledger_files/site.css"].IntegrityCheck));
        Assert.Contains(facts.Review, x => x.StartsWith("ledger_files/lib.js: integrity mismatch", StringComparison.Ordinal));
        Assert.Contains(facts.Notes, n => n.StartsWith("no Content-Security-Policy meta element; a policy in the response headers is unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void Inline_scripts_are_allowed_or_blocked_as_the_meta_policy_reads()
    {
        var facts = View($"""
            <!doctype html><html><head>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' {HelloSha256} 'nonce-r4nd' 'unsafe-inline'; frame-ancestors 'none'">
            <meta http-equiv="content-security-policy-report-only" content="script-src 'none'">
            <script>{Hello}</script>
            <script nonce="r4nd">start()</script>
            <script type="module">import "./other.js"</script>
            <script type="application/json">[1]</script>
            </head></html>
            """);
        var inline = facts.Resources.Where(r => r.Location == "inline").ToList();
        Assert.Equal(["classic", "classic", "module", "data block"], inline.Select(r => r.Kind));
        Assert.Equal(HelloSha256, inline[0].CspHash);
        Assert.Equal(["allowed by hash", "allowed by nonce", "blocked by script-src", null], inline.Select(r => r.CspVerdict));
        var policy = Assert.Single(facts.Policies);
        Assert.Equal("script-src", policy.ScriptDirective);
        // 'unsafe-inline' is ignored when a hash or nonce is listed, so it is not a weakness here.
        Assert.Empty(SavedPage.Weaknesses(policy));
        Assert.Contains("frame-ancestors in a meta element is ignored by browsers", facts.Notes);
        Assert.Contains("a report-only policy in a meta element is ignored by browsers", facts.Notes);
        Assert.Contains(facts.Review, x => x == "inline module script: blocked by script-src");
    }

    [Fact]
    public void Script_URLs_are_matched_against_the_policy_sources()
    {
        var known = View($"""
            <!doctype html><!-- saved from url=(0035)https://ledger.example.com/reports -->
            <meta http-equiv="Content-Security-Policy" content="script-src 'self' https://cdn.example.net/lib/ *.example.org:8443 'nonce-n1' '{HelloSha384}'">
            <script src="ledger_files/app.js"></script>
            <script src="http://ledger.example.com/app.js"></script>
            <script src="https://cdn.example.net/lib/chart.js"></script>
            <script src="https://cdn.example.net/other.js"></script>
            <script src="https://a.example.org:8443/x.js"></script>
            <script src="https://example.org:8443/x.js"></script>
            <script src="https://cdn.example.com/x.js" nonce="n1"></script>
            <script src="https://cdn.example.com/t.js" integrity="{HelloSha384}" crossorigin="anonymous"></script>
            """);
        Assert.Equal(["allowed by 'self'", "blocked by script-src", "allowed by https://cdn.example.net/lib/", "blocked by script-src",
            "allowed by *.example.org:8443", "blocked by script-src", "allowed by nonce", "allowed by hash (integrity)"], known.Resources.Select(r => r.CspVerdict));
        Assert.Contains("https://cdn.example.net/other.js: blocked by script-src", known.Review);

        // No saved-from comment or base element: a verdict that depends on the page's origin or scheme is unknown.
        var unknown = View("""
            <!doctype html><meta http-equiv="Content-Security-Policy" content="script-src 'self' cdn.example.net">
            <script src="app.js"></script>
            <script src="https://cdn.example.net/a.js"></script>
            <script src="http://cdn.example.net/a.js"></script>
            <script src="https://other.example/a.js"></script>
            """);
        Assert.Equal(["allowed by 'self'", "allowed by cdn.example.net", "unknown (the page's URL is not saved)", "unknown (the page's URL is not saved)"],
            unknown.Resources.Select(r => r.CspVerdict));

        var strict = View("""
            <!doctype html><meta http-equiv="Content-Security-Policy" content="script-src 'nonce-n1' 'strict-dynamic' https:">
            <script src="https://cdn.example.net/a.js"></script>
            <script src="https://cdn.example.net/b.js" nonce="n1"></script>
            """);
        Assert.Equal(["blocked by script-src ('strict-dynamic' needs a nonce or hash)", "allowed by nonce"], strict.Resources.Select(r => r.CspVerdict));
    }

    [Fact]
    public void A_policy_without_hashes_names_what_weakens_it()
    {
        var facts = View("""
            <!doctype html><meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:">
            <script>go()</script>
            """);
        Assert.Equal("allowed by 'unsafe-inline'", Assert.Single(facts.Resources).CspVerdict);
        Assert.Equal(["default-src allows 'unsafe-inline'", "default-src allows 'unsafe-eval'", "default-src allows https:", "default-src allows data:"],
            SavedPage.Weaknesses(facts.Policies.Single()));
    }

    [Fact]
    public void Import_maps_list_their_entries_and_name_addresses_on_other_origins()
    {
        var facts = View("""
            <!doctype html><base href="https://ledger.example.com/app/">
            <script type="importmap">
            { "imports": { "ledger": "./js/ledger.js", "chart": "https://cdn.example.net/chart.mjs" },
              "scopes": { "/admin/": { "ledger": "/admin/ledger.js" } },
              "integrity": { "https://cdn.example.net/chart.mjs": "sha384-abc" } }
            </script>
            <script type="importmap">{ not json</script>
            """);
        Assert.Equal("https://ledger.example.com/app/", facts.Url);
        Assert.Equal([(null, "ledger", false), (null, "chart", true), ("/admin/", "ledger", false)], facts.Imports.Select(i => (i.Scope, i.Specifier, i.OtherOrigin)));
        Assert.Equal(new SavedPage.ImportIntegrity("https://cdn.example.net/chart.mjs", "sha384-abc"), Assert.Single(facts.ModuleIntegrity));
        Assert.Contains(facts.Notes, n => n.StartsWith("an import map that is not valid JSON is ignored by the browser", StringComparison.Ordinal));
        Assert.Contains("import map: chart maps to https://cdn.example.net/chart.mjs", facts.Review);
        Assert.Empty(facts.Resources);
    }
}
