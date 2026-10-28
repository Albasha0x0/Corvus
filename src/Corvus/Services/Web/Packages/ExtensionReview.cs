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

    private static readonly Regex CookieSend = R(@"(?:chrome|browser)\.cookies\.getAll\s*\([\s\S]{0,400}?(?:\bfetch\s*\(\s*['""`]https?://|sendBeacon\s*\(\s*['""`]https?://)");

    private static bool IsBroadHost(string pattern) =>
        pattern is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*" or "*://*" or "file:///*" or "*://*/" || pattern.StartsWith("*://*/", StringComparison.Ordinal);

    private static bool IsExtensionManifest(PackageFiles files, string path) =>
        Json(files, path) is { ValueKind: JsonValueKind.Object } m && m.TryGetProperty("manifest_version", out _);

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
            findings.Add(new PackageFinding("review", "permission", $"permissions that reach the browser or system: {string.Join(", ", sensitive.Where(SystemPermissions.Contains))}", path));
        if (broad && sensitive.Count > 0)
            findings.Add(new PackageFinding("review", "permission", $"every site, with {string.Join(", ", sensitive.Take(8))}", path));
        else if (broad) findings.Add(new PackageFinding("review", "permission", "runs on or reads every site", path));
        var csp = m.TryGetProperty("content_security_policy", out var c2) ? c2.ValueKind == JsonValueKind.String ? c2.GetString() : c2.ToString() : null;
        if (csp != null && Regex.IsMatch(csp, @"'unsafe-eval'|script-src[^;]*\bhttps?:", RegexOptions.NonBacktracking))
            findings.Add(new PackageFinding("noteworthy", "remote code", $"the content security policy allows eval or remote scripts: {Clip(csp, 160)}", path));
        if (Str(m, "update_url") is { } update && !Regex.IsMatch(update, @"^https://(clients2\.google\.com|edge\.microsoft\.com|addons\.mozilla\.org)/", RegexOptions.NonBacktracking))
            findings.Add(new PackageFinding("review", "update", $"updates from outside the browser's store: {update}", path));
        if (m.TryGetProperty("externally_connectable", out var ec) && Strings(ec, "matches").Any(IsBroadHost))
            findings.Add(new PackageFinding("review", "permission", "any site can message the extension (externally_connectable)", path));
        var scripts = Capped(files, [.. entries.Where(e => e.Target != null && e.Target.EndsWith(".js", StringComparison.Ordinal)).Select(e => Resolve(root, e.Target!))
            .Concat(files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && p.EndsWith(".js", StringComparison.Ordinal)))
            .Distinct()]);
        foreach (var script in scripts)
        {
            if (files.Text(script) is not { } code) continue;
            findings.AddRange(Scan(script, code, install: false, ct).Where(f => f.Level == "noteworthy" || f.Category is "transformed code" or "credentials"));
            if (FetchedEval.IsMatch(code)) findings.Add(new PackageFinding("noteworthy", "remote code", "evaluates code it fetches", script));
            if (CookieSend.IsMatch(code)) findings.Add(new PackageFinding("noteworthy", "credentials", "reads every cookie and sends data to a fixed address", script));
        }
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        if (files.Crx is { } crx)
        {
            notes.AddRange(crx.Notes);
            if (crx.Proofs > 0 && crx.Verified < crx.Proofs)
                findings.Add(new PackageFinding("noteworthy", "signature", $"{crx.Proofs - crx.Verified} of {crx.Proofs} CRX key proofs do not verify"));
        }
        var name = Str(m, "name");
        return new PackageReport(mv >= 3 ? "browser extension (manifest v3)" : $"browser extension (manifest v{mv})", name, Str(m, "version"))
        {
            Publisher = Str(m, "author") ?? Str(m, "homepage_url"), Description = Clip(Str(m, "description")), EntryPoints = entries,
            Permissions = permissions, HostPermissions = hosts.Distinct().ToList(), ContentScripts = content.Count > 0 ? content : null,
            Binaries = binaries.Count > 0 ? binaries : null, Signature = files.Crx, Findings = findings, Notes = notes,
        };
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
                findings.Add(new PackageFinding("review", "activation", $"activates when the editor starts ({string.Join(", ", activation.Where(a => a is "*" or "onStartupFinished"))})", pkgPath));
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
                        if (runs) findings.Add(new PackageFinding("review", "install script", $"runs when uninstalled: {Clip(script.Value.GetString())}", pkgPath));
                    }
            id ??= Str(p, "name");
            version ??= Str(p, "version");
            publisher ??= Str(p, "publisher");
            display ??= Str(p, "displayName");
            foreach (var key in new[] { "extensionDependencies", "extensionPack" })
                foreach (var dep in Strings(p, key)) entries.Add(new PackageEntryPoint(key, dep, null));
        }
        // Zero-width characters let a display name imitate another extension's.
        if (display != null && Corvus.Core.Format.EscapeInvisible(display) != display)
            findings.Add(new PackageFinding("noteworthy", "name", $"the display name '{Corvus.Core.Format.EscapeInvisible(display)}' carries invisible characters", pkgPath));
        var loaded = entries.Where(e => e.Kind is "main" or "browser").Select(e => Resolve(root, e.Target!))
            .Select(t => !files.Has(t) && files.Has(t + ".js") ? t + ".js" : t);
        findings.AddRange(ScanLoaded(files, root, loaded, ct));
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        return new PackageReport("vscode extension", publisher != null && id != null && !id.Contains('.') ? $"{publisher}.{id}" : id, version)
        {
            Publisher = publisher, Description = Clip(display), Scripts = scripts, EntryPoints = entries,
            Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }
}
