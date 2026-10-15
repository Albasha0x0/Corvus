using System.ComponentModel;
using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>A webPreferences value found in the app's JavaScript: the setting, its source text and file:line:column.</summary>
public sealed record ElectronSetting(string Setting, string Value, string Site);

public sealed record ElectronPackage(string? Name, string? ProductName, string? Version,
    [property: Description("package.json main (index.js when absent).")] string Main,
    [property: Description("Whether main names a file of the app.")] bool MainFound, int Dependencies);

public sealed record ElectronArchive(string Path, int Files, int Unpacked, int Links, int HeaderBytes, string HeaderSha256,
    [property: Description("good (matches the hash the app declares), bad, or absent (none declared).")] string HeaderIntegrity,
    [property: Description("Where the declared header hash was found.")] string? DeclaredIn,
    [property: Description("File verdicts by status: ok, hash_mismatch, block_mismatch, no_integrity, unpacked_missing...")] IReadOnlyDictionary<string, int> FileIntegrity);

/// <summary>Static facts of an Electron app (its executable, or an .asar beside it); nothing is launched.</summary>
public sealed record ElectronFacts(
    [property: Description("The Electron binary the versions and fuses come from.")] string? Executable,
    string? ElectronVersion, string? ChromiumVersion, string? NodeVersion,
    [property: Description("The strings the versions were read from.")] IReadOnlyList<string> VersionEvidence,
    [property: Description("Fuse wire version (1 is decoded; others are reported, not guessed).")] int? FuseWireVersion,
    IReadOnlyList<Electron.Fuse> Fuses, ElectronArchive? Archive, ElectronPackage? Package,
    [property: Description("Values in webPreferences objects of the app's own JavaScript (node_modules skipped), with file:line:column.")] IReadOnlyList<ElectronSetting> WebPreferences,
    [property: Description("Preload scripts, contextBridge keys, IPC channels (main and renderer), child_process and shell sinks, native add-ons; with file:line:column.")]
    IReadOnlyList<ElectronRow> Surface,
    IReadOnlyList<string> Notes)
{
    /// <summary>Settings worth a highlight: what the app sets for these differs from nothing else in the summary.</summary>
    internal IEnumerable<string> Highlights()
    {
        if (ElectronVersion != null)
            yield return $"Electron {ElectronVersion}" + (ChromiumVersion != null || NodeVersion != null
                ? $" ({string.Join(", ", new[] { ChromiumVersion != null ? $"Chromium {ChromiumVersion}" : null, NodeVersion != null ? $"Node {NodeVersion}" : null }.OfType<string>())})" : "") + ".";
        if (Fuses.Count > 0)
            yield return $"Electron fuses: enabled {Join(Fuses.Where(f => f.State == "enabled"))}; disabled {Join(Fuses.Where(f => f.State == "disabled"))}" +
                         (Fuses.Any(f => f.State is not ("enabled" or "disabled")) ? $"; other {string.Join(", ", Fuses.Where(f => f.State is not ("enabled" or "disabled")).Select(f => $"{f.Name} {f.State}"))}" : "") + ".";
        else if (FuseWireVersion is { } wire and not 1) yield return $"Electron fuse wire version {wire} (not decoded).";
        if (Archive is { } a)
        {
            yield return $"ASAR header integrity {a.HeaderIntegrity}" + (a.DeclaredIn != null ? $" ({a.DeclaredIn})" : "") + ".";
            int failing = a.FileIntegrity.Where(s => !s.Key.StartsWith("ok", StringComparison.Ordinal) && s.Key != "no_integrity").Sum(s => s.Value);
            if (failing > 0) yield return $"{failing} ASAR file(s) fail their integrity check (list_assemblies with path lists them).";
        }
        if (Package is { } p)
            yield return $"Main entry {p.Main} (package.json){(p.MainFound ? "" : ", not found in the app")}.";
        foreach (var s in WebPreferences.Where(s => s.Setting is "nodeIntegration" or "contextIsolation" or "sandbox" or "webSecurity").Take(6))
            yield return $"webPreferences {s.Setting}: {s.Value} at {s.Site}.";
        if (Surface.Count > 0)
            yield return "Surface: " + string.Join(", ", Surface.GroupBy(r => r.Kind).Select(g => $"{g.Count()} {g.Key}")) +
                         " (search_container kind=electron lists them).";

        static string Join(IEnumerable<Electron.Fuse> fuses) => fuses.Any() ? string.Join(", ", fuses.Select(f => f.Name)) : "none";
    }
}

/// <summary>Builds <see cref="ElectronFacts"/> for summarize_file.</summary>
internal static class ElectronInspector
{
    private const int MaxScriptFiles = 400, MaxSettings = 200;
    private const long MaxScriptBytes = 16 * 1024 * 1024, MaxScannedBytes = 96 * 1024 * 1024;

    private static readonly HashSet<string> Interesting = new(StringComparer.Ordinal)
    {
        "nodeIntegration", "nodeIntegrationInWorker", "nodeIntegrationInSubFrames", "contextIsolation", "sandbox", "webSecurity",
        "allowRunningInsecureContent", "preload", "webviewTag", "enableRemoteModule", "experimentalFeatures",
    };

    /// <summary>The app's files: listing and bounded reads, from an archive or a resources/app folder.</summary>
    private sealed record AppFiles(string Label, IReadOnlyList<(string Path, long Size)> Files, Func<string, byte[]?> Read);

    /// <summary>Facts for an Electron executable or .asar; null for anything else.</summary>
    public static ElectronFacts? Of(string path, byte[] bytes, CancellationToken ct)
    {
        var kind = Blob.Identify(bytes);
        var notes = new List<string>();
        Electron.BinaryFacts? binary = null;
        string? archivePath = null, appFolder = null;
        if (kind == "asar")
        {
            archivePath = path;
            foreach (var exe in Electron.LayoutOf(path).Executables.Take(4))
            {
                try
                {
                    using var f = File.OpenRead(exe);
                    var scanned = Electron.Scan(f, exe, ct);
                    if (scanned.IsElectron) { binary = scanned; break; }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            if (binary == null) notes.Add("No Electron binary found beside the archive (expected two folders up, or the framework of a macOS bundle): versions and fuses unknown.");
        }
        else if (kind is "native PE" or "elf" or "mach-o")
        {
            binary = Electron.Scan(new MemoryStream(bytes, writable: false), path, ct);
            if (!binary.IsElectron) return null;
            var resources = Path.Combine(Path.GetDirectoryName(path) ?? "", "resources");
            if (File.Exists(Path.Combine(resources, "app.asar"))) archivePath = Path.Combine(resources, "app.asar");
            else if (Directory.Exists(Path.Combine(resources, "app"))) appFolder = Path.Combine(resources, "app");
            else notes.Add("No resources/app.asar or resources/app folder beside the executable.");
        }
        else return null;

        ElectronArchive? archive = null;
        AppFiles? app = null;
        FileStream? stream = null;
        try
        {
            if (archivePath != null)
            {
                try
                {
                    stream = File.OpenRead(archivePath);
                    var survey = AsarContainer.Read(stream, archivePath, _ => false, AnalysisLimits.Default, ct);
                    var a = survey.Archive;
                    archive = new ElectronArchive(archivePath, survey.Files, survey.Unpacked, survey.Links, a.HeaderLength, a.HeaderSha256,
                        survey.Integrity.HeaderStatus, survey.Integrity.Declared?.Source, survey.Integrity.Files);
                    var s = stream;
                    app = new AppFiles(Path.GetFileName(archivePath),
                        a.Entries.Where(e => e.Kind == AsarEntryKind.File && !e.UnsafeName).Select(e => (e.Path, e.Size)).ToList(),
                        p => a.Find(p) is { Unpacked: false } e ? a.ReadPacked(s, e, MaxScriptBytes) : null);
                    notes.AddRange(a.Issues.Take(5).Select(i => "archive: " + i));
                }
                catch (ToolError ex) { notes.Add($"{archivePath}: {ex.Message}"); }
            }
            else if (appFolder != null) app = Folder(appFolder);

            var package = app != null ? Package(app, notes) : null;
            var surface = new List<ElectronRow>();
            var settings = app != null ? WebPreferences(app, package?.Main, notes, surface, ct) : [];
            surface.InsertRange(0, settings.Where(s => s.Setting == "preload").Select(s => new ElectronRow("preload", s.Value, s.Site)));
            return new ElectronFacts(binary?.Path, binary?.ElectronVersion, binary?.ChromiumVersion, binary?.NodeVersion, binary?.Evidence ?? [],
                binary?.FuseWireVersion, binary?.Fuses ?? [], archive, package, settings, surface, notes);
        }
        finally { stream?.Dispose(); }
    }

    private static AppFiles Folder(string root)
    {
        var files = new List<(string, long)>();
        try
        {
            foreach (var f in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, MaxRecursionDepth = 32 }))
            {
                files.Add((Path.GetRelativePath(root, f).Replace('\\', '/'), new FileInfo(f).Length));
                if (files.Count >= 200_000) break;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return new AppFiles(Path.GetFileName(root), files, p =>
        {
            try
            {
                var full = SafeFile.UnderRoot(root, p);
                using var s = File.OpenRead(full);
                return Blob.ReadBounded(s, MaxScriptBytes);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError) { return null; }
        });
    }

    private static ElectronPackage? Package(AppFiles app, List<string> notes)
    {
        if (!app.Files.Any(f => f.Path == "package.json")) { notes.Add("No package.json at the app root."); return null; }
        var bytes = app.Read("package.json");
        if (bytes == null) return null;
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            var root = doc.RootElement;
            string? Str(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            var main = (Str("main") ?? "index.js").Replace('\\', '/');
            var normalized = AsarArchive.Normalize(main) ?? main;
            bool found = app.Files.Any(f => f.Path == normalized || f.Path == normalized + ".js" || f.Path == normalized + "/index.js");
            int deps = root.TryGetProperty("dependencies", out var d) && d.ValueKind == JsonValueKind.Object ? d.EnumerateObject().Count() : 0;
            return new ElectronPackage(Str("name"), Str("productName"), Str("version"), main, found, deps);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) // InvalidOperationException: invalid UTF-8 in a string
        {
            notes.Add($"package.json is not valid JSON ({ex.Message}).");
            return null;
        }
    }

    /// <summary>
    /// webPreferences object literals in the app's own scripts (main entry first, node_modules skipped): each top-level
    /// property of interest with its source text; a webPreferences that is not a literal is reported as its expression.
    /// </summary>
    private static List<ElectronSetting> WebPreferences(AppFiles app, string? main, List<string> notes, List<ElectronRow> surface, CancellationToken ct)
    {
        var scripts = app.Files.Where(f => IsScript(f.Path) && !f.Path.StartsWith("node_modules/", StringComparison.Ordinal) && !f.Path.Contains("/node_modules/", StringComparison.Ordinal))
            .OrderBy(f => main != null && (f.Path == main || f.Path == main + ".js") ? 0 : 1).ThenBy(f => f.Path, StringComparer.Ordinal).ToList();
        var result = new List<ElectronSetting>();
        long scanned = 0;
        int files = 0;
        foreach (var (path, size) in scripts)
        {
            ct.ThrowIfCancellationRequested();
            if (files >= MaxScriptFiles || scanned + size > MaxScannedBytes || result.Count >= MaxSettings)
            {
                notes.Add($"webPreferences scan stopped after {files} of {scripts.Count} script files (limits).");
                break;
            }
            if (size > MaxScriptBytes) continue;
            var bytes = app.Read(path);
            if (bytes == null) continue;
            files++;
            scanned += bytes.Length;
            var text = Encoding.UTF8.GetString(bytes);
            Scan(text, path, result);
            ElectronSurface.Scan(text, path, surface);
        }
        return result;
    }

    private static bool IsScript(string path) =>
        path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase);

    internal static void Scan(string text, string path, List<ElectronSetting> result)
    {
        int line = 1, lineStart = 0, counted = 0;
        string Site(int at)
        {
            for (; counted < at; counted++)
                if (text[counted] == '\n') { line++; lineStart = counted + 1; }
            return $"{path}:{line}:{at - lineStart + 1}";
        }
        for (int at = 0, found = 0; found < 50 && (at = text.IndexOf("webPreferences", at, StringComparison.Ordinal)) >= 0; at += 14)
        {
            int p = at + 14;
            if (at > 0 && (char.IsLetterOrDigit(text[at - 1]) || text[at - 1] is '_' or '$')) continue;
            if (p < text.Length && text[p] is '"' or '\'') p++;
            p = SkipSpace(text, p);
            if (p >= text.Length || text[p] != ':') continue;
            p = SkipSpace(text, p + 1);
            found++;
            if (p < text.Length && text[p] == '{')
            {
                foreach (var (key, value, keyAt) in Properties(text, p))
                    if (Interesting.Contains(key) && result.Count < MaxSettings) result.Add(new ElectronSetting(key, Normalize(value), Site(keyAt)));
            }
            else if (result.Count < MaxSettings)
            {
                var expression = Value(text, p, out _);
                result.Add(new ElectronSetting("webPreferences", Normalize(expression), Site(at)));
            }
        }
    }

    private static int SkipSpace(string text, int p)
    {
        while (p < text.Length && char.IsWhiteSpace(text[p])) p++;
        return p;
    }

    /// <summary>"!0" and "!1" as minifiers write true and false.</summary>
    private static string Normalize(string value) => value switch
    {
        "!0" => "true",
        "!1" => "false",
        "void 0" => "undefined",
        _ => value.Length > 120 ? value[..117] + "..." : value,
    };

    /// <summary>Top-level properties of the object literal at <paramref name="open"/> (a '{'), within 16 KB.</summary>
    private static IEnumerable<(string Key, string Value, int KeyAt)> Properties(string text, int open)
    {
        int end = Math.Min(text.Length, open + 16 * 1024);
        int p = open + 1;
        while (p < end)
        {
            p = SkipSpace(text, p);
            if (p >= end || text[p] == '}') yield break;
            int keyAt = p;
            string key;
            if (text[p] is '"' or '\'')
            {
                char q = text[p];
                int close = text.IndexOf(q, p + 1);
                if (close < 0 || close >= end) yield break;
                key = text[(p + 1)..close];
                p = close + 1;
            }
            else
            {
                int start = p;
                while (p < end && (char.IsLetterOrDigit(text[p]) || text[p] is '_' or '$')) p++;
                key = text[start..p];
                if (key.Length == 0) // spread, computed key or something else: skip the property
                {
                    Value(text, p, out var next);
                    if (next >= end || text[next] != ',') yield break;
                    p = next + 1;
                    continue;
                }
            }
            p = SkipSpace(text, p);
            string value;
            if (p < end && text[p] == ':') value = Value(text, SkipSpace(text, p + 1), out p);
            else value = "(shorthand: a variable of that name)";
            yield return (key, value, keyAt);
            p = SkipSpace(text, p);
            if (p < end && text[p] == ',') p++;
            else yield break;
        }
    }

    /// <summary>An expression up to the next top-level ',' or closing bracket, strings and nesting skipped.</summary>
    private static string Value(string text, int start, out int end)
    {
        int depth = 0, p = start, limit = Math.Min(text.Length, start + 4096);
        while (p < limit)
        {
            char c = text[p];
            if (c is '"' or '\'' or '`')
            {
                int close = p + 1;
                while (close < limit && text[close] != c) close += text[close] == '\\' ? 2 : 1;
                p = close + 1;
                continue;
            }
            if (c is '{' or '[' or '(') depth++;
            else if (c is '}' or ']' or ')')
            {
                if (depth == 0) break;
                depth--;
            }
            else if (c is ',' or ';' && depth == 0) break;
            p++;
        }
        end = Math.Min(p, text.Length);
        return text[start..end].Trim();
    }
}
