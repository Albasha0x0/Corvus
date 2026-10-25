using System.ComponentModel;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web;

/// <summary>
/// A saved web page read as the browser would load it, nothing run: each script and integrity-bearing link with where
/// its bytes are (inline, a saved file beside the page, a data: URL, or not saved), its Subresource Integrity checked
/// against those bytes, the import maps, and the Content Security Policy of its meta elements with each inline script's
/// verdict under it. Response headers are not saved with a page, so a policy they may set is unknown, not absent.
/// </summary>
public static partial class SavedPage
{
    /// <summary>A script or link element. Location: inline, saved, data, remote or outside (a path leaving the page's folder, not read).</summary>
    public sealed record Resource(string Element, string Kind, string? Source, string Location, string? File, long? Size,
        [property: Description("The integrity attribute as written.")] string? Integrity,
        [property: Description("match, mismatch, unknown (bytes not saved), or no supported hash; with the algorithm compared.")] string? IntegrityCheck,
        string? CrossOrigin,
        [property: Description("An inline script's hash in CSP source form ('sha256-...').")] string? CspHash,
        [property: Description("A script's verdict under the meta policy: allowed by hash, nonce, 'unsafe-inline' or the source matching its URL, blocked, unknown, or no policy.")] string? CspVerdict,
        IReadOnlyList<string>? Notes);

    /// <summary>An import map entry: the scope it applies in (null for top-level imports), the specifier and the address it maps to.</summary>
    public sealed record ImportEntry(string? Scope, string Specifier, string Address, bool OtherOrigin);

    /// <summary>An import map integrity entry: the module URL and the metadata the browser checks it against.</summary>
    public sealed record ImportIntegrity(string Url, string Integrity);

    /// <summary>One policy from a meta element: its directives as written and the source list that governs scripts.</summary>
    public sealed record Policy(IReadOnlyDictionary<string, IReadOnlyList<string>> Directives, string ScriptDirective, IReadOnlyList<string> ScriptSources);

    /// <summary>The page: its URL from the saved-from comment or base element (null when neither is saved), resources, import maps and policies.</summary>
    public sealed record Page(string? Url, string? Title, IReadOnlyList<Resource> Resources, IReadOnlyList<ImportEntry> Imports,
        IReadOnlyList<ImportIntegrity> ModuleIntegrity, IReadOnlyList<Policy> Policies, IReadOnlyList<string> Notes);

    private const int MaxResources = 2_000, MaxImports = 5_000;
    private const long MaxSavedFile = 64L << 20;

    /// <summary>Reads <paramref name="html"/> (the page at <paramref name="path"/>); saved files are looked up under the page's folder only.</summary>
    public static Page Read(string html, string path, CancellationToken ct)
    {
        var notes = new List<string>();
        var savedFrom = SavedFrom().Match(html) is { Success: true } sf ? sf.Groups[1].Value : null;
        // Inside a script element "<!--" is script text, not a comment.
        var body = CommentOrScript().Replace(html, m => m.Value.StartsWith("<!--", StringComparison.Ordinal) ? " " : m.Value);
        string? baseHref = null, title = null;
        if (StartTag("base").Match(body) is { Success: true } b && Attributes(b.Groups[1].Value).TryGetValue("href", out var href)) baseHref = href;
        if (Title().Match(body) is { Success: true } t) title = WebUtility.HtmlDecode(t.Groups[1].Value).Trim() is { Length: > 0 } tt ? tt : null;
        var pageUrl = Absolute(baseHref, Absolute(savedFrom, null)) ?? Absolute(savedFrom, null);
        var folder = Path.GetDirectoryName(Path.GetFullPath(path))!;

        var policies = new List<Policy>();
        foreach (Match m in StartTag("meta").Matches(body))
        {
            var a = Attributes(m.Groups[1].Value);
            if (!a.TryGetValue("http-equiv", out var equiv) || !a.TryGetValue("content", out var content)) continue;
            if (equiv.Equals("content-security-policy", StringComparison.OrdinalIgnoreCase)) policies.Add(ParsePolicy(content, notes));
            else if (equiv.Equals("content-security-policy-report-only", StringComparison.OrdinalIgnoreCase))
                notes.Add("a report-only policy in a meta element is ignored by browsers");
        }

        var resources = new List<Resource>();
        var imports = new List<ImportEntry>();
        var importIntegrity = new List<ImportIntegrity>();
        foreach (Match m in ScriptElement().Matches(body))
        {
            ct.ThrowIfCancellationRequested();
            if (resources.Count >= MaxResources) { notes.Add($"resources after the first {MaxResources:N0} not read"); break; }
            var a = Attributes(m.Groups[1].Value);
            var type = a.GetValueOrDefault("type")?.Trim().ToLowerInvariant() ?? "";
            var kind = type switch
            {
                "" or "text/javascript" or "application/javascript" or "text/ecmascript" or "application/ecmascript" or "text/jscript" => "classic",
                "module" => "module",
                "importmap" => "import map",
                "speculationrules" => "speculation rules",
                _ => "data block",
            };
            if (kind == "import map")
            {
                ReadImportMap(m.Groups[2].Value, pageUrl, imports, importIntegrity, notes);
                continue;
            }
            a.TryGetValue("src", out var src);
            resources.Add(src != null && kind is "classic" or "module"
                ? External("script", kind, src, a, folder, pageUrl, policies)
                : Inline(kind, m.Groups[2].Value, a, policies));
        }
        foreach (Match m in StartTag("link").Matches(body))
        {
            var a = Attributes(m.Groups[1].Value);
            var rel = a.GetValueOrDefault("rel")?.Trim().ToLowerInvariant() ?? "";
            if (!a.TryGetValue("href", out var linkHref) || !(a.ContainsKey("integrity") || rel is "modulepreload" || rel.Split(' ').Contains("stylesheet"))) continue;
            if (resources.Count >= MaxResources) break;
            resources.Add(External("link", rel, linkHref, a, folder, pageUrl, null));
        }
        if (policies.Count == 0) notes.Add("no Content-Security-Policy meta element; a policy in the response headers is unknown (headers are not saved with a page)");
        return new Page(pageUrl, title, resources, imports, importIntegrity, policies, notes);
    }

    private static Resource External(string element, string kind, string src, Dictionary<string, string> a, string folder, string? pageUrl, List<Policy>? policies)
    {
        var notes = new List<string>();
        a.TryGetValue("integrity", out var integrity);
        a.TryGetValue("crossorigin", out var cors);
        string location;
        string? file = null;
        byte[]? bytes = null;
        if (src.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            location = "data";
            bytes = DataUrl(src);
            if (bytes == null) notes.Add("data: URL not decoded");
        }
        else if (Uri.TryCreate(src, UriKind.Absolute, out var abs) && abs.Scheme is not "file" || src.StartsWith("//", StringComparison.Ordinal))
        {
            location = "remote";
            var origin = Origin(src.StartsWith("//", StringComparison.Ordinal) ? "https:" + src : src);
            if (integrity != null && cors == null && pageUrl != null && origin != null && origin != Origin(pageUrl))
                notes.Add("integrity on a cross-origin resource without crossorigin: the browser refuses it (no CORS response to check)");
            if (integrity == null && pageUrl != null && origin != null && origin != Origin(pageUrl) && element == "script")
                notes.Add($"code from {origin} without integrity");
        }
        else
        {
            var relative = Uri.UnescapeDataString(src.Split('?', '#')[0]).Replace('\\', '/');
            string? full = null;
            try { full = Path.GetFullPath(Path.Combine(folder, relative.TrimStart('/'))); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { }
            if (full == null) { location = "not saved"; notes.Add("not a file path on this system"); }
            else if (!full.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) location = "outside";
            else if (File.Exists(full))
            {
                location = "saved";
                file = Path.GetRelativePath(folder, full).Replace('\\', '/');
                var length = new FileInfo(full).Length;
                if (length <= MaxSavedFile) bytes = File.ReadAllBytes(full);
                else notes.Add($"{length:N0} bytes, over the {MaxSavedFile >> 20} MiB read limit");
            }
            else location = "not saved";
        }
        var verdict = policies == null ? null : policies.Count == 0 ? "no policy" : ExternalVerdict(policies, src, pageUrl, a.GetValueOrDefault("nonce"), integrity);
        return new Resource(element, kind, src, location, file, bytes?.Length, integrity, integrity == null ? null : CheckIntegrity(integrity, bytes), cors,
            null, verdict, notes.Count > 0 ? notes : null);
    }

    private static Resource Inline(string kind, string text, Dictionary<string, string> a, List<Policy> policies)
    {
        var notes = new List<string>();
        string? hash = null, verdict = null;
        if (kind is "classic" or "module")
        {
            // CSP hashes the element's text as UTF-8, entity references not decoded.
            hash = "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text))) + "'";
            verdict = policies.Count == 0 ? "no policy" : Verdict(policies, hash, a.GetValueOrDefault("nonce"));
        }
        if (a.ContainsKey("integrity")) notes.Add("integrity on an inline script has no effect");
        return new Resource("script", kind, null, "inline", null, Encoding.UTF8.GetByteCount(text), a.GetValueOrDefault("integrity"), null, null,
            hash, verdict, notes.Count > 0 ? notes : null);
    }

    // Every policy applies: an inline script runs only when each one allows it.
    private static string Verdict(List<Policy> policies, string hash, string? nonce)
    {
        var reasons = new List<string>();
        foreach (var p in policies)
        {
            var s = p.ScriptSources;
            if (s.Count == 0) { reasons.Add($"allowed ({p.ScriptDirective} absent)"); continue; }
            if (s.Contains(hash, StringComparer.Ordinal)) { reasons.Add("allowed by hash"); continue; }
            if (nonce != null && s.Contains($"'nonce-{nonce}'", StringComparer.Ordinal)) { reasons.Add("allowed by nonce"); continue; }
            bool hashesOrNonces = s.Any(x => x.StartsWith("'sha", StringComparison.Ordinal) || x.StartsWith("'nonce-", StringComparison.Ordinal) || x == "'strict-dynamic'");
            if (s.Contains("'unsafe-inline'", StringComparer.Ordinal) && !hashesOrNonces) { reasons.Add("allowed by 'unsafe-inline'"); continue; }
            return "blocked by " + p.ScriptDirective;
        }
        return reasons.Distinct().Count() == 1 ? reasons[0] : string.Join("; ", reasons);
    }

    // Every policy applies: a script loads only when each one allows its URL; an unknown verdict outranks an allowed one.
    private static string ExternalVerdict(List<Policy> policies, string src, string? pageUrl, string? nonce, string? integrity)
    {
        var reasons = new List<string>();
        foreach (var p in policies)
        {
            var reason = UrlVerdict(p, src, pageUrl, nonce, integrity);
            if (reason.StartsWith("blocked", StringComparison.Ordinal)) return reason;
            reasons.Add(reason);
        }
        return reasons.FirstOrDefault(r => r.StartsWith("unknown", StringComparison.Ordinal)) ?? string.Join("; ", reasons.Distinct());
    }

    // CSP Level 3, "Does url match source list": a parser-inserted script needs a nonce, its integrity hashes, or a
    // matching source; 'strict-dynamic' leaves only the first two.
    private static string UrlVerdict(Policy p, string src, string? pageUrl, string? nonce, string? integrity)
    {
        var s = p.ScriptSources;
        if (s.Count == 0) return $"allowed ({p.ScriptDirective} absent)";
        if (nonce != null && s.Contains($"'nonce-{nonce}'", StringComparer.Ordinal)) return "allowed by nonce";
        var hashes = integrity?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Select(t => t.Split('?')[0])
            .Where(t => t.StartsWith("sha256-", StringComparison.Ordinal) || t.StartsWith("sha384-", StringComparison.Ordinal) || t.StartsWith("sha512-", StringComparison.Ordinal)).ToList();
        if (hashes is { Count: > 0 } && hashes.All(h => s.Contains($"'{h}'", StringComparer.Ordinal))) return "allowed by hash (integrity)";
        if (s.Contains("'strict-dynamic'", StringComparer.Ordinal)) return $"blocked by {p.ScriptDirective} ('strict-dynamic' needs a nonce or hash)";
        bool relative = !src.StartsWith("//", StringComparison.Ordinal) && (src.StartsWith('/') || !Uri.TryCreate(src, UriKind.Absolute, out _));
        // An unsaved page URL is tried as both an https: and an http: page; a source that differs between them is unknown.
        Uri[] pages = pageUrl != null && Uri.TryCreate(pageUrl, UriKind.Absolute, out var page) ? [page] : [new("https://page.invalid/"), new("http://page.invalid/")];
        bool unknown = false;
        foreach (var x in s)
        {
            var results = pages.Select(pg => Uri.TryCreate(pg, src, out var url) ? SourceMatches(x, url, pg, pages.Length == 1 || relative) : false).Distinct().ToList();
            if (results is [true]) return $"allowed by {x}";
            if (results.Count > 1 || results.Contains(null)) unknown = true;
        }
        return unknown ? "unknown (the page's URL is not saved)" : "blocked by " + p.ScriptDirective;
    }

    /// <summary>Whether source expression <paramref name="x"/> matches <paramref name="url"/> on <paramref name="page"/>; null when it depends on an unknown origin.</summary>
    private static bool? SourceMatches(string x, Uri url, Uri page, bool originKnown)
    {
        if (x.Equals("'self'", StringComparison.OrdinalIgnoreCase))
            return !originKnown ? null : url.Host == page.Host && (url.Scheme == page.Scheme && url.Port == page.Port || page.Scheme == "http" && url.Scheme == "https" && url.IsDefaultPort);
        if (x.StartsWith('\'')) return false;
        if (x == "*") return url.Scheme is "http" or "https" or "ftp" || url.Scheme == page.Scheme;
        if (x.EndsWith(':') && !x.Contains('/')) return SchemeMatches(x[..^1].ToLowerInvariant(), url.Scheme);
        string rest = x;
        string? scheme = null;
        if (x.IndexOf("://", StringComparison.Ordinal) is var i and > 0) { scheme = x[..i].ToLowerInvariant(); rest = x[(i + 3)..]; }
        if (!SchemeMatches(scheme ?? page.Scheme, url.Scheme)) return false;
        int slash = rest.IndexOf('/');
        string hostPort = slash < 0 ? rest : rest[..slash], host = hostPort;
        string? path = slash < 0 ? null : rest[slash..], port = null;
        if (hostPort.LastIndexOf(':') is var c and >= 0) { host = hostPort[..c]; port = hostPort[(c + 1)..]; }
        host = host.ToLowerInvariant();
        bool hostOk = host == "*" || (host.StartsWith("*.", StringComparison.Ordinal) ? url.Host.EndsWith(host[1..], StringComparison.Ordinal) : url.Host == host);
        bool portOk = port switch
        {
            null => url.IsDefaultPort,
            "*" => true,
            _ => int.TryParse(port, out var n) && (n == url.Port || n == 80 && url.Scheme == "https" && url.Port == 443),
        };
        if (!hostOk || !portOk) return false;
        if (path is null or "") return true;
        var want = Uri.UnescapeDataString(path);
        var have = Uri.UnescapeDataString(url.AbsolutePath);
        return want.EndsWith('/') ? have.StartsWith(want, StringComparison.Ordinal) : have == want;
    }

    // CSP's "scheme-part match": a source scheme also admits its secure upgrade.
    private static bool SchemeMatches(string source, string scheme) => source == scheme || (source, scheme) is ("http", "https") or ("ws", "wss") or ("ws", "http") or ("ws", "https") or ("wss", "https");

    /// <summary>The SRI verdict for <paramref name="integrity"/> over <paramref name="bytes"/> (null when not saved): only the strongest listed algorithm counts.</summary>
    public static string CheckIntegrity(string integrity, byte[]? bytes)
    {
        var tokens = integrity.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Split('?')[0]).Select(t => (Alg: t.Split('-')[0].ToLowerInvariant(), Digest: t.Contains('-') ? t[(t.IndexOf('-') + 1)..] : ""))
            .Where(t => t.Alg is "sha256" or "sha384" or "sha512").ToList();
        if (tokens.Count == 0) return "no supported hash (the browser loads it unchecked)";
        var alg = tokens.Max(t => t.Alg)!;
        if (bytes == null) return $"unknown ({alg}; bytes not saved)";
        var digest = Convert.ToBase64String(alg switch { "sha256" => SHA256.HashData(bytes), "sha384" => SHA384.HashData(bytes), _ => SHA512.HashData(bytes) });
        return tokens.Any(t => t.Alg == alg && t.Digest == digest) ? $"match ({alg})" : $"mismatch ({alg}: the bytes hash to {alg}-{digest})";
    }

    private static Policy ParsePolicy(string content, List<string> notes)
    {
        var directives = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var part in content.Split(';'))
        {
            var tokens = part.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0) continue;
            var name = tokens[0].ToLowerInvariant();
            // The first occurrence of a directive wins.
            if (!directives.ContainsKey(name)) directives[name] = tokens[1..];
            if (name is "frame-ancestors" or "report-uri" or "sandbox") notes.Add($"{name} in a meta element is ignored by browsers");
        }
        var directive = new[] { "script-src-elem", "script-src", "default-src" }.FirstOrDefault(directives.ContainsKey) ?? "script-src";
        return new Policy(directives, directive, directives.GetValueOrDefault(directive) ?? []);
    }

    /// <summary>What a policy's script sources allow that weakens it: 'unsafe-inline' (when no hash or nonce overrides it), 'unsafe-eval', wildcards and scheme-only sources.</summary>
    public static IEnumerable<string> Weaknesses(Policy p)
    {
        var s = p.ScriptSources;
        if (s.Count == 0) { yield return $"no {p.ScriptDirective}: scripts are not restricted"; yield break; }
        bool overridden = s.Any(x => x.StartsWith("'sha", StringComparison.Ordinal) || x.StartsWith("'nonce-", StringComparison.Ordinal));
        if (s.Contains("'unsafe-inline'", StringComparer.Ordinal) && !overridden) yield return $"{p.ScriptDirective} allows 'unsafe-inline'";
        if (s.Contains("'unsafe-eval'", StringComparer.Ordinal)) yield return $"{p.ScriptDirective} allows 'unsafe-eval'";
        foreach (var x in s.Where(x => x is "*" or "data:" or "http:" or "https:" or "blob:"))
            yield return $"{p.ScriptDirective} allows {x}";
    }

    private static void ReadImportMap(string json, string? pageUrl, List<ImportEntry> imports, List<ImportIntegrity> integrity, List<string> notes)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16, CommentHandling = JsonCommentHandling.Disallow });
            if (doc.RootElement.ValueKind != JsonValueKind.Object) { notes.Add("an import map that is not a JSON object is ignored"); return; }
            if (doc.RootElement.TryGetProperty("imports", out var top)) AddMap(null, top, pageUrl, imports);
            if (doc.RootElement.TryGetProperty("scopes", out var scopes) && scopes.ValueKind == JsonValueKind.Object)
                foreach (var scope in scopes.EnumerateObject()) AddMap(scope.Name, scope.Value, pageUrl, imports);
            if (doc.RootElement.TryGetProperty("integrity", out var map) && map.ValueKind == JsonValueKind.Object)
                foreach (var e in map.EnumerateObject().Where(e => e.Value.ValueKind == JsonValueKind.String)) integrity.Add(new(e.Name, e.Value.GetString()!));
            if (imports.Count > MaxImports) { notes.Add($"import map entries after the first {MaxImports:N0} not listed"); imports.RemoveRange(MaxImports, imports.Count - MaxImports); }
        }
        catch (JsonException ex) { notes.Add($"an import map that is not valid JSON is ignored by the browser ({ex.Message.Split('.')[0]})"); }
    }

    private static void AddMap(string? scope, JsonElement map, string? pageUrl, List<ImportEntry> imports)
    {
        if (map.ValueKind != JsonValueKind.Object) return;
        var page = pageUrl != null ? Origin(pageUrl) : null;
        foreach (var e in map.EnumerateObject())
        {
            if (imports.Count > MaxImports) return;
            var address = e.Value.ValueKind == JsonValueKind.String ? e.Value.GetString()! : "(not a string: ignored)";
            var origin = Origin(address.StartsWith("//", StringComparison.Ordinal) ? "https:" + address : address);
            imports.Add(new ImportEntry(scope, e.Name, address, origin != null && origin != page));
        }
    }

    private static string? Absolute(string? url, string? relativeTo) =>
        url == null ? null
        : Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is "http" or "https" ? u.ToString()
        : relativeTo != null && Uri.TryCreate(new Uri(relativeTo), url, out var r) ? r.ToString() : null;

    private static string? Origin(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is "http" or "https" ? u.GetLeftPart(UriPartial.Authority).ToLowerInvariant() : null;

    private static byte[]? DataUrl(string url)
    {
        int comma = url.IndexOf(',');
        if (comma < 0) return null;
        var meta = url[5..comma];
        var data = url[(comma + 1)..];
        try
        {
            return meta.EndsWith(";base64", StringComparison.OrdinalIgnoreCase)
                ? Convert.FromBase64String(Uri.UnescapeDataString(data))
                : Encoding.UTF8.GetBytes(Uri.UnescapeDataString(data));
        }
        catch (FormatException) { return null; }
    }

    /// <summary>A start tag's attributes, names lowercased, values entity-decoded; the first of a repeated name wins as in HTML.</summary>
    private static Dictionary<string, string> Attributes(string text)
    {
        var a = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match m in Attribute().Matches(text))
        {
            var name = m.Groups[1].Value.ToLowerInvariant();
            var value = m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Success ? m.Groups[3].Value : m.Groups[4].Success ? m.Groups[4].Value : "";
            a.TryAdd(name, WebUtility.HtmlDecode(value));
        }
        return a;
    }

    private static Regex StartTag(string name) => name switch
    {
        "base" => BaseTag(),
        "meta" => MetaTag(),
        _ => LinkTag(),
    };

    // A whole page is read: NonBacktracking matches in linear time, so no match timeout.
    [GeneratedRegex(@"<!--\s*saved from url=\(\d+\)(\S+?)\s*-->", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex SavedFrom();

    [GeneratedRegex(@"<!--.*?-->|<script\b[^>]*>.*?</script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.NonBacktracking)]
    private static partial Regex CommentOrScript();

    [GeneratedRegex(@"<script\b([^>]*)>(.*?)</script\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.NonBacktracking)]
    private static partial Regex ScriptElement();

    [GeneratedRegex(@"<title\b[^>]*>(.*?)</title\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.NonBacktracking)]
    private static partial Regex Title();

    [GeneratedRegex(@"<base\b([^>]*)>", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex BaseTag();

    [GeneratedRegex(@"<meta\b([^>]*)>", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex MetaTag();

    [GeneratedRegex(@"<link\b([^>]*)>", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex LinkTag();

    [GeneratedRegex(@"([^\s=/>""']+)(?:\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+)))?", RegexOptions.NonBacktracking)]
    private static partial Regex Attribute();
}
