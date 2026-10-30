using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    /// <summary>Permissions that reach page data, the network stack, other extensions or the system.</summary>
    private static readonly HashSet<string> SensitivePermissions = new(StringComparer.Ordinal)
    {
        "cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", "debugger", "nativeMessaging",
        "proxy", "management", "history", "clipboardRead", "downloads", "scripting", "tabs", "webNavigation", "privacy", "contentSettings",
        "desktopCapture", "tabCapture", "pageCapture", "identity", "browsingData", "topSites", "geolocation", "userScripts", "offscreen",
    };

    private static readonly HashSet<string> SystemPermissions = new(StringComparer.Ordinal) { "debugger", "nativeMessaging", "proxy", "management", "userScripts" };

    private static readonly Regex FetchedEval = R(@"(?:\.text\(\)|responseText)[^;]{0,200}?(?:;[^;]{0,200}?){0,2}\b(?:eval|new\s+Function)\s*\(");

    private static readonly Regex ExtensionLookup = R(@"getExtension\s*\(\s*['""`]([\w-]{1,100})\.([\w.-]{1,100})['""`]\s*\)(\s*[?!]?\.\s*(?:packageJSON|extensionPath|extensionUri)\b)?");

    private static readonly Regex RepositoryOwner = R(@"(?:github|gitlab)\.com[/:]([\w.-]{1,100})/([\w.-]{1,100}?)(?:\.git)?(?:[/#?]|$)");

    private static readonly Regex CookieSend = R(@"(?:chrome|browser)\.cookies\.getAll\s*\([\s\S]{0,400}?(?:\bfetch\s*\(\s*['""`]https?://|sendBeacon\s*\(\s*['""`]https?://)");

    private static bool IsBroadHost(string pattern) =>
        pattern is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*" or "*://*" or "file:///*" or "*://*/" || pattern.StartsWith("*://*/", StringComparison.Ordinal);

    // An MCPB manifest names manifest_version as a string.
    private static bool IsExtensionManifest(PackageFiles files, string path) =>
        Json(files, path) is { ValueKind: JsonValueKind.Object } m && m.TryGetProperty("manifest_version", out var v) && v.ValueKind == JsonValueKind.Number;

    private static PackageReport? Extension(PackageFiles files, CancellationToken ct)
    {
        var path = Root(files, "manifest.json");
        if (path == null || Json(files, path) is not { ValueKind: JsonValueKind.Object } m) return null;
        var root = Folder(path);
        var findings = new List<PackageFinding>();
        var notes = new List<string>();
        int mv = m.TryGetProperty("manifest_version", out var v) && v.TryGetInt32(out var n) ? n : 0;
        var permissions = Strings(m, "permissions").Concat(Strings(m, "optional_permissions").Select(p => p + " (optional)")).ToList();
        var hosts = Strings(m, "host_permissions").Concat(Strings(m, "optional_host_permissions").Select(p => p + " (optional)")).ToList();
        // Manifest v2 lists host patterns among the permissions.
        hosts.AddRange(permissions.Where(p => p.Contains("://", StringComparison.Ordinal) || p.StartsWith("<all_urls>", StringComparison.Ordinal)));
        permissions.RemoveAll(p => p.Contains("://", StringComparison.Ordinal) || p.StartsWith("<all_urls>", StringComparison.Ordinal));
        var content = new List<ContentScript>();
        if (m.TryGetProperty("content_scripts", out var cs) && cs.ValueKind == JsonValueKind.Array)
            foreach (var c in cs.EnumerateArray())
                content.Add(new ContentScript(Strings(c, "matches").ToList(), Strings(c, "js").ToList(), Str(c, "run_at"),
                    c.TryGetProperty("all_frames", out var af) && af.ValueKind == JsonValueKind.True));
        var entries = new List<PackageEntryPoint>();
        if (m.TryGetProperty("background", out var bg) && bg.ValueKind == JsonValueKind.Object)
        {
            if (Str(bg, "service_worker") is { } sw) entries.Add(new PackageEntryPoint("background", "service_worker", sw));
            if (Str(bg, "page") is { } page) entries.Add(new PackageEntryPoint("background", "page", page));
            foreach (var s in Strings(bg, "scripts")) entries.Add(new PackageEntryPoint("background", "script", s));
        }
        foreach (var (key, kind) in new[] { ("action", "popup"), ("browser_action", "popup"), ("page_action", "popup") })
            if (m.TryGetProperty(key, out var a) && Str(a, "default_popup") is { } popup) entries.Add(new PackageEntryPoint(kind, key, popup));
        foreach (var key in new[] { "options_page", "devtools_page" })
            if (Str(m, key) is { } page) entries.Add(new PackageEntryPoint(key, key, page));
        if (m.TryGetProperty("chrome_url_overrides", out var overrides) && overrides.ValueKind == JsonValueKind.Object)
            foreach (var o in overrides.EnumerateObject()) entries.Add(new PackageEntryPoint("url override", o.Name, o.Value.ValueKind == JsonValueKind.String ? o.Value.GetString() : null));
        foreach (var c in content) foreach (var js in c.Files) entries.Add(new PackageEntryPoint("content script", string.Join(" ", c.Matches.Take(3)), js));

        var sensitive = permissions.Select(p => p.Replace(" (optional)", "")).Where(SensitivePermissions.Contains).Distinct().ToList();
        bool broad = hosts.Any(h => IsBroadHost(h.Replace(" (optional)", ""))) || content.Any(c => c.Matches.Any(IsBroadHost));
        if (sensitive.Any(SystemPermissions.Contains))
            findings.Add(new PackageFinding("package/system-permissions", "review", "permission", $"permissions that reach the browser or system: {string.Join(", ", sensitive.Where(SystemPermissions.Contains))}", path));
        if (broad && sensitive.Count > 0)
            findings.Add(new PackageFinding("package/all-sites-permissions", "review", "permission", $"every site, with {string.Join(", ", sensitive.Take(8))}", path));
        else if (broad) findings.Add(new PackageFinding("package/all-sites", "review", "permission", "runs on or reads every site", path));
        var csp = m.TryGetProperty("content_security_policy", out var c2) ? c2.ValueKind == JsonValueKind.String ? c2.GetString() : c2.ToString() : null;
        if (csp != null && Regex.IsMatch(csp, @"'unsafe-eval'|script-src[^;]*\bhttps?:", RegexOptions.NonBacktracking))
            findings.Add(new PackageFinding("package/csp-remote-code", "noteworthy", "remote code", $"the content security policy allows eval or remote scripts: {Clip(csp, 160)}", path));
        bool allSitesScript = content.Any(c => c.Matches.Any(IsBroadHost));
        findings.AddRange(HeaderRemovals(files, root, m, allSitesScript));
        if (Str(m, "update_url") is { } update && !Regex.IsMatch(update, @"^https://(clients2\.google\.com|edge\.microsoft\.com|addons\.mozilla\.org)/", RegexOptions.NonBacktracking))
            findings.Add(new PackageFinding("package/external-update", "review", "update", $"updates from outside the browser's store: {update}", path));
        if (m.TryGetProperty("externally_connectable", out var ec) && Strings(ec, "matches").Any(IsBroadHost))
            findings.Add(new PackageFinding("package/externally-connectable", "review", "permission", "any site can message the extension (externally_connectable)", path));
        var scripts = Capped(files, [.. entries.Where(e => e.Target != null && e.Target.EndsWith(".js", StringComparison.Ordinal)).Select(e => Resolve(root, e.Target!))
            .Concat(files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && p.EndsWith(".js", StringComparison.Ordinal)))
            .Distinct()]);
        var allSitesFiles = content.Where(c => c.Matches.Any(IsBroadHost)).SelectMany(c => c.Files).Select(f => Resolve(root, f)).ToHashSet(StringComparer.Ordinal);
        foreach (var script in scripts)
        {
            if (files.Text(script) is not { } code) continue;
            // A content script on every site sees what every page copies.
            findings.AddRange(Scan(script, code, install: false, ct).Where(f => f.Level == "noteworthy" || f.Category is "transformed code" or "credentials" or "clipboard")
                .Select(f => f.Rule == "package/clipboard-address" && allSitesFiles.Contains(script) ? f with { Level = "noteworthy" } : f));
            if (FetchedEval.IsMatch(code)) findings.Add(new PackageFinding("package/fetched-eval", "noteworthy", "remote code", "evaluates code it fetches", script));
            if (CookieSend.IsMatch(code)) findings.Add(new PackageFinding("package/cookie-send", "noteworthy", "credentials", "reads every cookie and sends data to a fixed address", script));
            if (DynamicHeaderRemovals(code) is { Headers.Count: > 0 } dynamic)
                findings.Add(new PackageFinding("package/header-removal", dynamic.EveryUrl && allSitesScript ? "noteworthy" : "review", "page security",
                    $"updateDynamicRules or updateSessionRules removes response header(s): {string.Join(", ", dynamic.Headers.Take(5))}", script));
        }
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        if (files.Crx is { } crx)
        {
            notes.AddRange(crx.Notes);
            if (crx.Proofs > 0 && crx.Verified < crx.Proofs)
                findings.Add(new PackageFinding("package/crx-proof-failed", "noteworthy", "signature", $"{crx.Proofs - crx.Verified} of {crx.Proofs} CRX key proofs do not verify"));
        }
        var name = Str(m, "name");
        return new PackageReport(mv >= 3 ? "browser extension (manifest v3)" : $"browser extension (manifest v{mv})", name, Str(m, "version"))
        {
            Publisher = Str(m, "author") ?? Str(m, "homepage_url"), Description = Clip(Str(m, "description")), EntryPoints = entries,
            Permissions = permissions, HostPermissions = hosts.Distinct().ToList(), ContentScripts = content.Count > 0 ? content : null,
            Binaries = binaries.Count > 0 ? binaries : null, Signature = files.Crx, Findings = findings, Notes = notes,
        };
    }

    /// <summary>Response headers that keep a page's own script, framing and window policy.</summary>
    private static readonly HashSet<string> PageSecurityHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "content-security-policy", "content-security-policy-report-only", "x-frame-options", "cross-origin-opener-policy",
    };

    /// <summary>One finding per static declarativeNetRequest rules file whose modifyHeaders rules remove or empty a page security header; empty when none.</summary>
    private static IEnumerable<PackageFinding> HeaderRemovals(PackageFiles files, string root, JsonElement manifest, bool allSitesScript)
    {
        if (!manifest.TryGetProperty("declarative_net_request", out var dnr) || dnr.ValueKind != JsonValueKind.Object || !dnr.TryGetProperty("rule_resources", out var resources) || resources.ValueKind != JsonValueKind.Array)
            yield break;
        foreach (var resource in resources.EnumerateArray())
        {
            if (Str(resource, "path") is not { } rel) continue;
            var path = Resolve(root, rel);
            if (Json(files, path) is not { ValueKind: JsonValueKind.Array } rules) continue;
            var removed = new List<string>();
            bool everyUrl = false;
            foreach (var rule in rules.EnumerateArray())
            {
                if (rule.ValueKind != JsonValueKind.Object || !rule.TryGetProperty("action", out var action) || Str(action, "type") != "modifyHeaders"
                    || !action.TryGetProperty("responseHeaders", out var headers) || headers.ValueKind != JsonValueKind.Array) continue;
                var id = rule.TryGetProperty("id", out var i) ? i.ToString() : "?";
                int before = removed.Count;
                foreach (var h in headers.EnumerateArray())
                    if (Str(h, "header") is { } header && PageSecurityHeaders.Contains(header)
                        && (Str(h, "operation") == "remove" || Str(h, "operation") == "set" && string.IsNullOrWhiteSpace(Str(h, "value"))))
                        removed.Add($"{header} (rule {id})");
                if (removed.Count > before && EveryUrl(rule)) everyUrl = true;
            }
            if (removed.Count == 0) continue;
            var disabled = resource.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.False
                ? "; disabled at install, can be enabled by the extension" : "";
            yield return new PackageFinding("package/header-removal", everyUrl && allSitesScript ? "noteworthy" : "review", "page security",
                $"{removed.Count} response header removal(s): {string.Join(", ", removed.Take(5))}{disabled}", path);
        }
    }

    private static readonly Regex DynamicRulesCall = R(@"\.update(?:Dynamic|Session)Rules\s*\(");
    private static readonly Regex SecurityHeaderLiteral = new(@"['""`](content-security-policy(?:-report-only)?|x-frame-options|cross-origin-opener-policy)['""`]", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    private static readonly Regex RemoveLiteral = R(@"['""`]remove['""`]");
    private static readonly Regex UrlCondition = R(@"\b(?:urlFilter|regexFilter|requestDomains)\b");
    private static readonly Regex EveryUrlFilter = R(@"\burlFilter['""]?\s*:\s*['""`](?:\*|<all_urls>)['""`]");

    /// <summary>Page security headers that updateDynamicRules or updateSessionRules calls remove, and whether such a call has no URL condition; empty headers when none.</summary>
    private static (List<string> Headers, bool EveryUrl) DynamicHeaderRemovals(string code)
    {
        var headers = new List<string>();
        bool everyUrl = false;
        foreach (Match m in DynamicRulesCall.Matches(code).Take(50))
        {
            // The call's text runs to its closing parenthesis, at most 8 KiB on.
            int end = m.Index + m.Length, depth = 1, limit = Math.Min(code.Length, end + (8 << 10));
            while (end < limit && depth > 0) depth += code[end++] switch { '(' => 1, ')' => -1, _ => 0 };
            var call = code[m.Index..end];
            if (!RemoveLiteral.IsMatch(call)) continue;
            var found = SecurityHeaderLiteral.Matches(call).Select(h => h.Groups[1].Value).ToList();
            if (found.Count == 0) continue;
            headers.AddRange(found);
            everyUrl |= !UrlCondition.IsMatch(call) || EveryUrlFilter.IsMatch(call);
        }
        return (headers.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), everyUrl);
    }

    /// <summary>True when a rule's condition names no URL filter or domain list, or matches every URL.</summary>
    private static bool EveryUrl(JsonElement rule)
    {
        if (!rule.TryGetProperty("condition", out var c) || c.ValueKind != JsonValueKind.Object) return true;
        if (c.TryGetProperty("regexFilter", out _) || c.TryGetProperty("requestDomains", out _)) return false;
        return Str(c, "urlFilter") is null or "*" or "<all_urls>";
    }

    private static IEnumerable<string> Strings(JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) yield break;
        if (v.ValueKind == JsonValueKind.String) { yield return v.GetString()!; yield break; }
        if (v.ValueKind != JsonValueKind.Array) yield break;
        foreach (var item in v.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String) yield return item.GetString()!;
            else if (item.ValueKind == JsonValueKind.Object && Str(item, "resources") == null)
                foreach (var r in Strings(item, "resources")) yield return r; // web_accessible_resources v3
    }

    // --- VS Code extensions ---

    private static PackageReport? Vsix(PackageFiles files, CancellationToken ct)
    {
        var findings = new List<PackageFinding>();
        var notes = new List<string>();
        string? id = null, version = null, publisher = null, display = null;
        if (Root(files, "extension.vsixmanifest") is { } manifest && files.Text(manifest) is { } xml)
        {
            try
            {
                var doc = Core.BoundedXml.Parse(xml);
                var identity = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Identity");
                id = identity?.Attribute("Id")?.Value;
                version = identity?.Attribute("Version")?.Value;
                publisher = identity?.Attribute("Publisher")?.Value;
                display = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "DisplayName")?.Value;
            }
            catch (System.Xml.XmlException ex) { notes.Add("extension.vsixmanifest: " + ex.Message); }
        }
        var pkgPath = files.Has("extension/package.json") ? "extension/package.json" : Root(files, "package.json");
        var pkg = pkgPath != null ? Json(files, pkgPath) : null;
        var root = pkgPath != null ? Folder(pkgPath) : "extension/";
        var entries = new List<PackageEntryPoint>();
        var scripts = new List<PackageScript>();
        if (pkg is { ValueKind: JsonValueKind.Object } p)
        {
            foreach (var key in new[] { "main", "browser" })
                if (Str(p, key) is { } target) entries.Add(new PackageEntryPoint(key, key, target));
            var activation = Strings(p, "activationEvents").ToList();
            foreach (var a in activation) entries.Add(new PackageEntryPoint("activation", a, null));
            if (activation.Contains("*") || activation.Contains("onStartupFinished"))
                findings.Add(new PackageFinding("package/startup-activation", "review", "activation", $"activates when the editor starts ({string.Join(", ", activation.Where(a => a is "*" or "onStartupFinished"))})", pkgPath));
            if (p.TryGetProperty("contributes", out var contributes) && contributes.ValueKind == JsonValueKind.Object)
            {
                if (contributes.TryGetProperty("commands", out var commands) && commands.ValueKind == JsonValueKind.Array)
                    foreach (var c in commands.EnumerateArray().Take(100))
                        if (Str(c, "command") is { } cmd) entries.Add(new PackageEntryPoint("command", cmd, Str(c, "title")));
                foreach (var key in new[] { "customEditors", "webviews", "views", "terminal", "taskDefinitions", "debuggers", "authentication" })
                    if (contributes.TryGetProperty(key, out var c) && c.ValueKind is JsonValueKind.Array or JsonValueKind.Object)
                        entries.Add(new PackageEntryPoint("contributes", key, null));
            }
            if (p.TryGetProperty("scripts", out var s) && s.ValueKind == JsonValueKind.Object)
                foreach (var script in s.EnumerateObject())
                    if (script.Value.ValueKind == JsonValueKind.String)
                    {
                        // VS Code runs vscode:uninstall on removal; the other scripts run at build time.
                        bool runs = script.Name == "vscode:uninstall";
                        scripts.Add(new PackageScript(script.Name, Clip(script.Value.GetString())!, runs));
                        if (runs) findings.Add(new PackageFinding("package/uninstall-script", "review", "install script", $"runs when uninstalled: {Clip(script.Value.GetString())}", pkgPath));
                    }
            id ??= Str(p, "name");
            version ??= Str(p, "version");
            publisher ??= Str(p, "publisher");
            display ??= Str(p, "displayName");
            foreach (var key in new[] { "extensionDependencies", "extensionPack" })
                foreach (var dep in Strings(p, key)) entries.Add(new PackageEntryPoint(key, dep, null));
        }
        // Zero-width characters let a display name imitate another extension's.
        if (display != null && Corvus.Core.Format.EscapeCodePoints(display) != display)
            findings.Add(new PackageFinding("package/invisible-name", "noteworthy", "name", $"the display name '{Corvus.Core.Format.EscapeInvisible(display)}' carries invisible characters", pkgPath));
        if (pkg is { ValueKind: JsonValueKind.Object } m && Str(m, "publisher") is { } author && CopiedRepository(m, author) is { } copied)
            findings.Add(new PackageFinding("package/extension-clone", "noteworthy", "name",
                $"names the source repository of a popular extension, {copied.Repository}, which publisher{(copied.Publishers.Length == 1 ? "" : "s")} {string.Join(", ", copied.Publishers)} ship{(copied.Publishers.Length == 1 ? "s" : "")}, under the publisher '{author}'", pkgPath));
        var loaded = entries.Where(e => e.Kind is "main" or "browser").Select(e => Resolve(root, e.Target!))
            .Select(t => !files.Has(t) && files.Has(t + ".js") ? t + ".js" : t).ToList();
        if (pkg is { ValueKind: JsonValueKind.Object } q && Str(q, "publisher") is { } own && Str(q, "name") is { } name)
            findings.AddRange(ForeignExtensionIds(files, loaded, own, name, q));
        findings.AddRange(ScanLoaded(files, root, loaded, ct, extension: true));
        findings.AddRange(EditorContentSends(files, root, ct));
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        return new PackageReport("vscode extension", publisher != null && id != null && !id.Contains('.') ? $"{publisher}.{id}" : id, version)
        {
            Publisher = publisher, Description = Clip(display), Scripts = scripts, EntryPoints = entries,
            Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }

    /// <summary>The popular repository the manifest names and its publishers when <paramref name="publisher"/> is not
    /// one of them; null otherwise.</summary>
    private static (string Repository, string[] Publishers)? CopiedRepository(JsonElement pkg, string publisher)
    {
        var repo = Str(pkg, "repository") ?? (pkg.TryGetProperty("repository", out var r) && r.ValueKind == JsonValueKind.Object ? Str(r, "url") : null);
        if (repo == null || RepositoryOwner.Match(repo) is not { Success: true } m || !repo.Contains("github.com", StringComparison.OrdinalIgnoreCase)) return null;
        var key = $"{m.Groups[1].Value}/{m.Groups[2].Value}";
        return PopularNames.EditorExtensionRepositories.TryGetValue(key, out var publishers) && !publishers.Contains(publisher, StringComparer.OrdinalIgnoreCase)
            ? (key.ToLowerInvariant(), publishers) : null;
    }

    // Copied code still reads the original extension's install data by its id.
    private static IEnumerable<PackageFinding> ForeignExtensionIds(PackageFiles files, List<string> loaded, string own, string name, JsonElement pkg)
    {
        var repo = Str(pkg, "repository") ?? (pkg.TryGetProperty("repository", out var r) && r.ValueKind == JsonValueKind.Object ? Str(r, "url") : null);
        var match = repo != null ? RepositoryOwner.Match(repo) : Match.Empty;
        string? owner = match.Success ? match.Groups[1].Value : null, repoName = match.Success ? match.Groups[2].Value : null;
        // An original never lists its own id as a dependency or pack member.
        var declared = Strings(pkg, "extensionDependencies").Concat(Strings(pkg, "extensionPack")).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var star = Strings(pkg, "activationEvents").Contains("*");
        PackageFinding? first = null;
        foreach (var path in loaded.Distinct())
        {
            if (files.Text(path) is not { } code) continue;
            foreach (Match m in ExtensionLookup.Matches(code))
            {
                string publisher = m.Groups[1].Value, target = m.Groups[2].Value;
                if (publisher.Equals(own, StringComparison.OrdinalIgnoreCase) || declared.Contains($"{publisher}.{target}")) continue;
                var sameName = target.Equals(name, StringComparison.OrdinalIgnoreCase);
                if (!sameName && !(publisher.Equals(owner, StringComparison.OrdinalIgnoreCase) && target.Equals(repoName, StringComparison.OrdinalIgnoreCase))) continue;
                // A presence check is how a renamed extension finds its old id, so only
                // reading the looked-up extension's data is noteworthy.
                var reads = star && m.Groups[3].Success;
                var finding = new PackageFinding("package/foreign-extension-id", reads ? "noteworthy" : "review", "name",
                    $"looks up '{publisher}.{target}': {(sameName ? "its own name" : "its repository owner")} under a publisher other than '{own}'", path);
                if (reads) { yield return finding; yield break; }
                first ??= finding;
            }
        }
        if (first != null) yield return first;
    }

    private static readonly Regex InstallCommand = R(@"workbench\.extensions\.installExtension['""`]\s*,\s*(?:[\w$.]*Uri\.file\s*\(\s*(?<f>[A-Za-z_$][\w$]*)\s*\)|(?<v>[A-Za-z_$][\w$]*)\s*[,)])");
    private static readonly Regex InstallCli = R(@"--install-extension(?:\s+\$\{\s*(?<c>[A-Za-z_$][\w$]*)\s*\}|['""`]\s*[,+]\s*(?<c>[A-Za-z_$][\w$]*))");
    private static readonly Regex Assignment = R(@"(?:^|[^\w$.])(?<n>[A-Za-z_$][\w$]*)\s*=");
    private static readonly Regex UriFileOf = R(@"^\s*[\w$.]*Uri\.file\s*\(\s*(?<f>[A-Za-z_$][\w$]*)\s*\)");
    private static readonly Regex NetworkRead = R(@"\bfetch\s*\(|\baxios\b|\bhttps?\.(?:get|request)\s*\(|\.arrayBuffer\s*\(");
    private static readonly Regex FileWrite = R(@"\b(?:writeFile(?:Sync)?|createWriteStream)\s*\(\s*(?<w>[A-Za-z_$][\w$]*)\s*[,)]");
    private const int Window = 3000;

    /// <summary>A package/extension-sideload finding when code installs an
    /// extension from a file it writes from a network response; null otherwise.</summary>
    private static PackageFinding? Sideload(string path, string code)
    {
        if (!NetworkRead.IsMatch(code) || !FileWrite.IsMatch(code)) return null;
        foreach (Match m in InstallCommand.Matches(code).Take(20))
            if ((m.Groups["f"].Success ? m.Groups["f"].Value : BoundTo(code, m.Groups["v"].Value, m.Index, uri: true)) is { } f
                && WrittenFromResponse(code, f, m.Index)) return SideloadFinding(path);
        foreach (Match m in InstallCli.Matches(code).Take(20))
            if (BoundTo(code, m.Groups["c"].Value, m.Index, uri: false) is { } f && WrittenFromResponse(code, f, m.Index)) return SideloadFinding(path);
        return null;
    }

    private static PackageFinding SideloadFinding(string path) =>
        new("package/extension-sideload", "noteworthy", "remote code", "installs an extension from a file it writes from a network response", path);

    // Minified bundles reuse short names in every scope, so only the nearest
    // assignment before the call binds the name.
    private static string? BoundTo(string code, string name, int before, bool uri)
    {
        int start = Math.Max(0, before - Window);
        Match? last = null;
        for (var m = Assignment.Match(code, start, before - start); m.Success; m = m.NextMatch())
            if (m.Groups["n"].Value == name && m.Index + m.Length < code.Length && code[m.Index + m.Length] is not ('=' or '>')) last = m;
        if (last is null) return null;
        int at = last.Index + last.Length, len = Math.Min(300, code.Length - at);
        if (uri) return UriFileOf.Match(code, at, len) is { Success: true } f ? f.Groups["f"].Value : null;
        int end = code.AsSpan(at, len).IndexOfAny(';', '\n') is var e and >= 0 ? e : len;
        return code.AsSpan(at, end).Contains(".vsix", StringComparison.Ordinal) ? name : null;
    }

    private static bool WrittenFromResponse(string code, string file, int before)
    {
        int start = Math.Max(0, before - Window);
        for (var w = FileWrite.Match(code, start, before - start); w.Success; w = w.NextMatch())
            if (w.Groups["w"].Value == file && NetworkRead.Match(code, Math.Max(0, w.Index - Window), Math.Min(Window, w.Index)).Success) return true;
        return false;
    }

    private const string EditorText = @"(?:\.getText\(\)|readFileSync\(\s*[\w$.]*\.(?:fileName|fsPath)\b)";
    private const string FixedUrl = @"['""`](?<scheme>https?)://(?<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])[^'""`\s]*['""`]\s*,";
    private const string FixedPost = @"(?:\bfetch\w*|\(0,\s*[\w$]+\.default\))\s*\(\s*" + FixedUrl + @"\s*\{[^;]{0,200}?\bmethod\s*:\s*['""`]POST['""`]";
    // The literal absolute URL keeps route registrations such as app.post('/x') out.
    private const string ClientPost = @"\b[\w$.]+\.post\s*\(\s*" + FixedUrl;
    private static readonly Regex EditorTextPost = R(EditorText + @"[\s\S]{0,400}?" + FixedPost + "|" + FixedPost + @"[^;]{0,400}?\bbody\s*:[^;]{0,200}?" + EditorText);
    private static readonly Regex EditorTextClientPost = R(EditorText + @"[\s\S]{0,400}?" + ClientPost + "|" + ClientPost + @"[^;]{0,400}?" + EditorText);
    private static readonly Regex RemoteFrame = new(@"<iframe\b[^>]{0,400}?\bsrc\s*=\s*['""]?https?://(?<host>[A-Za-z0-9.-]+)[^>]{0,400}>", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    private const string ZeroSize = @"(?:^|[^\w-])(?:width|height)\s*[:=]\s*['""]?0(?:px)?[\s;'""}>]";
    private static readonly Regex HiddenFrameAttribute = new(ZeroSize + @"|display\s*:\s*none|visibility\s*:\s*hidden", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    // A brace or tag end before the selector keeps descendant and @media rules out.
    private static readonly Regex HiddenFrameStyle = new(@"(?:^|[}>])\s*iframe\s*\{[^}]{0,200}?(?:" + ZeroSize + @"|display\s*:\s*none|visibility\s*:\s*hidden)", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    private static readonly Regex OwnScriptOrPage = R(@"\.(?:c|m)?js$|\.html?$");

    /// <summary>True for localhost names and loopback or private addresses; false for any other host.</summary>
    private static bool IsLocalHost(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
        || System.Net.IPAddress.TryParse(host.Trim('[', ']'), out var ip) && (System.Net.IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal
            || ip.GetAddressBytes() is [10, ..] or [192, 168, ..] or [172, >= 16 and < 32, ..] or [0, 0, 0, 0]);

    /// <summary>One finding per extension script that posts document text to a fixed remote host, and per script or page holding a hidden remote iframe; empty when none.</summary>
    private static IEnumerable<PackageFinding> EditorContentSends(PackageFiles files, string root, CancellationToken ct)
    {
        var sources = files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && OwnScriptOrPage.IsMatch(p)
                                             && !p.Contains("node_modules/", StringComparison.Ordinal) && files.Size(p) <= MaxScannedSourceBytes)
            .Order(StringComparer.Ordinal).ToList();
        foreach (var path in Capped(files, sources))
        {
            ct.ThrowIfCancellationRequested();
            if (files.Text(path) is not { } text) continue;
            bool script = path.EndsWith("js", StringComparison.Ordinal);
            if (script && EditorTextPost.Matches(text).Concat(EditorTextClientPost.Matches(text)).FirstOrDefault(m => !IsLocalHost(m.Groups["host"].Value)) is { } send)
                yield return new PackageFinding("package/editor-content-send", send.Groups["scheme"].Value == "http" ? "noteworthy" : "review", "exfiltration",
                    $"posts editor document text to {send.Groups["scheme"].Value}://{send.Groups["host"].Value}", path);
            // A style rule in a script string can target any view, so only pages apply it.
            bool styled = !script && HiddenFrameStyle.IsMatch(text);
            if (RemoteFrame.Matches(text).FirstOrDefault(m => !IsLocalHost(m.Groups["host"].Value) && (styled || HiddenFrameAttribute.IsMatch(m.Value))) is { } frame)
                yield return new PackageFinding("package/hidden-frame", "noteworthy", "remote content", $"a hidden iframe loads {frame.Groups["host"].Value}", path);
        }
    }
}
