using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Markdig;
using Markdig.Extensions.AutoIdentifiers;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;

namespace Corvus.DocsSite;

/// <summary>A page written: its Markdown source and HTML output (paths relative to the repository and site), and title.</summary>
public sealed record SitePage(string Source, string Output, string Title);

/// <summary>What a build wrote, the files it copied beside the pages, and each unresolved link as "page: target".</summary>
public sealed record SiteReport(IReadOnlyList<SitePage> Pages, IReadOnlyList<string> Copied, IReadOnlyList<string> Broken);

/// <summary>
/// Writes README.md and docs/ as a static HTML site; links to other repository files point at <c>source</c> (kept as
/// written when null). A link to a missing file or heading is reported, never dropped.
/// </summary>
public static partial class Site
{
    private const string Docs = "docs/";

    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .UsePipeTables().UseEmphasisExtras().UseTaskLists().UseFootnotes().UseAutoLinks()
        .UseAutoIdentifiers(AutoIdentifierOptions.GitHub).Build();

    [GeneratedRegex(@"\b(?:id|name)=""([^""]+)""")]
    private static partial Regex Anchor();

    [GeneratedRegex(@"^[a-zA-Z][a-zA-Z0-9+.-]*:")]
    private static partial Regex Scheme();

    /// <summary>Builds the site into <paramref name="output"/>, which is created if missing; files already there are overwritten.</summary>
    public static SiteReport Build(string root, string output, string? source)
    {
        var files = Tracked(root);
        var known = files.ToHashSet(StringComparer.Ordinal);
        var sources = files.Where(f => f == "README.md" || (f.StartsWith(Docs, StringComparison.Ordinal) && f.EndsWith(".md", StringComparison.Ordinal)))
            .Order(StringComparer.Ordinal).ToList();
        var pages = new List<SitePage>();
        var bodies = new Dictionary<string, string>(StringComparer.Ordinal);
        var ids = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var copies = new SortedSet<string>(StringComparer.Ordinal);
        var broken = new List<string>();
        var anchors = new List<(string Page, string Target, string Id)>();

        foreach (var page in sources)
        {
            var doc = Markdown.Parse(File.ReadAllText(Path.Combine(root, page)), Pipeline);
            string html = HtmlPath(page);
            foreach (var link in doc.Descendants<LinkInline>())
                if (link.Url is { } url) link.Url = Resolve(page, url, known, source, copies, broken, anchors);
            string body = Markdown.ToHtml(doc, Pipeline);
            bodies[html] = body;
            ids[html] = [.. Anchor().Matches(body).Select(m => WebUtility.HtmlDecode(m.Groups[1].Value))];
            var heading = doc.Descendants<HeadingBlock>().FirstOrDefault();
            string title = heading?.Inline is { } inline ? string.Concat(inline.Descendants<LiteralInline>().Select(l => l.Content.ToString())) : "";
            pages.Add(new SitePage(page, html, title.Length > 0 ? title : Path.GetFileNameWithoutExtension(page)));
        }
        foreach (var (page, target, id) in anchors)
            if (!ids[HtmlPath(target)].Contains(id)) broken.Add($"{page}: {target}#{id}");

        foreach (var page in pages)
        {
            string path = Path.Combine(output, page.Output);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, Layout(page, pages, bodies[page.Output]));
        }
        foreach (var file in copies)
        {
            string path = Path.Combine(output, file);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.Copy(Path.Combine(root, file), path, overwrite: true);
        }
        return new SiteReport(pages, [.. copies], broken);
    }

    /// <summary>The repository's tracked files ('/' separators); every file when git cannot list them (no work tree).</summary>
    private static List<string> Tracked(string root)
    {
        try
        {
            using var git = Process.Start(new ProcessStartInfo("git", ["-C", root, "ls-files", "-z"])
            {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
            })!;
            string listed = git.StandardOutput.ReadToEnd();
            git.WaitForExit();
            var files = listed.Split('\0', StringSplitOptions.RemoveEmptyEntries).ToList();
            if (git.ExitCode == 0 && files.Count > 0) return files;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // No git on PATH: the directory walk below.
        }
        return [.. Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
            .Where(f => !f.StartsWith(".git/", StringComparison.Ordinal))];
    }

    private static string HtmlPath(string page) => page == "README.md" ? "index.html" : page[..^3] + ".html";

    /// <summary>The URL a page's link takes in the site; an unresolved one is reported and kept as written.</summary>
    private static string Resolve(string page, string url, HashSet<string> known, string? source, SortedSet<string> copies,
        List<string> broken, List<(string, string, string)> anchors)
    {
        string html = HtmlPath(page);
        if (url.Length == 0 || Scheme().IsMatch(url) || url.StartsWith("//", StringComparison.Ordinal)) return url;
        int hash = url.IndexOf('#', StringComparison.Ordinal);
        string fragment = hash < 0 ? "" : url[(hash + 1)..];
        string path = hash < 0 ? url : url[..hash];
        int query = path.IndexOf('?', StringComparison.Ordinal);
        if (query >= 0) path = path[..query];
        if (path.Length == 0)
        {
            if (fragment.Length > 0) anchors.Add((page, page, Uri.UnescapeDataString(fragment)));
            return url;
        }

        string? target = Combine(path.StartsWith('/') ? "" : Path.GetDirectoryName(page)!.Replace('\\', '/'), Uri.UnescapeDataString(path));
        string suffix = fragment.Length > 0 ? "#" + fragment : "";
        if (target != null && target.EndsWith('/')) target = target.TrimEnd('/');
        if (target != null && known.Contains(target))
        {
            if (target == "README.md" || (target.StartsWith(Docs, StringComparison.Ordinal) && target.EndsWith(".md", StringComparison.Ordinal)))
            {
                if (fragment.Length > 0) anchors.Add((page, target, Uri.UnescapeDataString(fragment)));
                return Relative(html, HtmlPath(target)) + suffix;
            }
            if (target.StartsWith(Docs, StringComparison.Ordinal))
            {
                copies.Add(target);
                return Relative(html, target) + suffix;
            }
            return source == null ? url : $"{source.TrimEnd('/')}/{target}{suffix}";
        }
        if (target != null && known.Any(f => f.StartsWith(target + "/", StringComparison.Ordinal)))
        {
            if (known.Contains(target + "/README.md") && (target + "/").StartsWith(Docs, StringComparison.Ordinal))
                return Relative(html, HtmlPath(target + "/README.md")) + suffix;
            return source == null ? url : $"{source.TrimEnd('/').Replace("/blob/", "/tree/", StringComparison.Ordinal)}/{target}{suffix}";
        }
        broken.Add($"{page}: {url}");
        return url;
    }

    /// <summary>A repository path from a page folder and a relative path; null when it leaves the repository.</summary>
    private static string? Combine(string folder, string relative)
    {
        var parts = new List<string>(folder.Split('/', StringSplitOptions.RemoveEmptyEntries));
        foreach (var part in relative.Split('/'))
        {
            if (part is "" or ".") continue;
            if (part == "..")
            {
                if (parts.Count == 0) return null;
                parts.RemoveAt(parts.Count - 1);
            }
            else parts.Add(part);
        }
        return string.Join('/', parts) + (relative.EndsWith('/') ? "/" : "");
    }

    private static string Relative(string from, string to)
    {
        var a = from.Split('/')[..^1];
        var b = to.Split('/');
        int common = 0;
        while (common < a.Length && common < b.Length - 1 && a[common] == b[common]) common++;
        return string.Join('/', Enumerable.Repeat("..", a.Length - common).Concat(b[common..]));
    }

    private static string Layout(SitePage page, List<SitePage> pages, string body)
    {
        var nav = new StringBuilder();
        string? group = null;
        foreach (var p in pages)
        {
            string folder = p.Output.Contains('/', StringComparison.Ordinal) ? p.Output[..p.Output.LastIndexOf('/')] : "";
            if (folder != group)
            {
                if (group != null) nav.Append("</ul>");
                group = folder;
                if (folder.Length > 0) nav.Append("<h2>").Append(WebUtility.HtmlEncode(folder)).Append("</h2>");
                nav.Append("<ul>");
            }
            nav.Append("<li><a href=\"").Append(WebUtility.HtmlEncode(Relative(page.Output, p.Output))).Append('"')
                .Append(p == page ? " aria-current=\"page\"" : "").Append('>').Append(WebUtility.HtmlEncode(p.Title)).Append("</a></li>");
        }
        nav.Append("</ul>");
        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{WebUtility.HtmlEncode(page.Title)}} · Corvus</title>
            <style>
            :root { --fg: #1f2328; --bg: #ffffff; --muted: #59636e; --line: #d1d9e0; --code: #f6f8fa; --link: #0969da; }
            @media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --bg: #0d1117; --muted: #9198a1; --line: #3d444d; --code: #151b23; --link: #4493f8; } }
            body { margin: 0; display: flex; color: var(--fg); background: var(--bg); font: 15px/1.6 system-ui, sans-serif; }
            nav { flex: 0 0 15rem; padding: 1rem; border-right: 1px solid var(--line); font-size: 14px; }
            nav h2 { font-size: 12px; text-transform: uppercase; color: var(--muted); margin: 1rem 0 .25rem; }
            nav ul { list-style: none; margin: 0; padding: 0; }
            nav a[aria-current] { font-weight: 600; }
            main { flex: 1; min-width: 0; max-width: 60rem; padding: 1rem 2rem; }
            a { color: var(--link); }
            pre, code { background: var(--code); font: 13px/1.45 ui-monospace, monospace; }
            pre { padding: .75rem; overflow-x: auto; }
            table { border-collapse: collapse; display: block; overflow-x: auto; }
            th, td { border: 1px solid var(--line); padding: .3rem .6rem; vertical-align: top; }
            @media (max-width: 50rem) { body { display: block; } nav { border-right: 0; border-bottom: 1px solid var(--line); } main { padding: 1rem; } }
            </style>
            </head>
            <body>
            <nav>{{nav}}</nav>
            <main>
            {{body}}
            </main>
            </body>
            </html>

            """;
    }
}
