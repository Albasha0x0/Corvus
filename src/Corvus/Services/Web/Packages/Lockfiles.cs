using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

/// <param name="Source">registry, git, url or path.</param>
/// <param name="InstallScript">The lockfile records that the package runs a script at install.</param>
public sealed record LockedPackage(string Name, string Version, string Source, string? Resolved, string? Integrity, bool InstallScript);

/// <summary>A lockfile's resolved packages in file order; Notes name entries that could not be read.</summary>
public sealed record Lockfile(string Format, string Ecosystem, IReadOnlyList<LockedPackage> Packages, IReadOnlyList<string> Notes);

/// <summary>npm, pnpm, yarn, poetry, uv and hashed pip requirement lockfiles read as resolved packages; nothing is installed or run.</summary>
public static partial class Lockfiles
{
    /// <summary>Lockfiles larger than this are not read.</summary>
    public const int MaxBytes = 64 << 20;

    /// <summary>Whether <paramref name="fileName"/> names a lockfile format; requirement files also need a --hash option.</summary>
    public static bool Named(string fileName) => fileName.ToLowerInvariant() is "package-lock.json" or "npm-shrinkwrap.json" or "pnpm-lock.yaml" or "yarn.lock"
        or "poetry.lock" or "uv.lock" || Requirements(fileName);

    private static bool Requirements(string fileName) =>
        fileName.StartsWith("requirements", StringComparison.OrdinalIgnoreCase) && fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase);

    /// <summary>The lockfile <paramref name="text"/> named <paramref name="fileName"/>; null when the name is not a lockfile or the text is not one.</summary>
    public static Lockfile? Read(string fileName, string text)
    {
        var name = Path.GetFileName(fileName).ToLowerInvariant();
        var notes = new List<string>();
        var (format, ecosystem, packages) = name switch
        {
            "package-lock.json" or "npm-shrinkwrap.json" => (Path.GetFileNameWithoutExtension(name), "npm", Npm(text, notes)),
            "pnpm-lock.yaml" => ("pnpm-lock", "npm", Pnpm(text, notes)),
            "yarn.lock" => (text.Contains("__metadata:", StringComparison.Ordinal) ? "yarn.lock (berry)" : "yarn.lock (v1)", "npm", Yarn(text)),
            "poetry.lock" => ("poetry.lock", "pypi", Toml(text, poetry: true)),
            "uv.lock" => ("uv.lock", "pypi", Toml(text, poetry: false)),
            _ when Requirements(name) && text.Contains("--hash=", StringComparison.Ordinal) => ("requirements.txt", "pypi", Pip(text)),
            _ => (null, null, null),
        };
        return format == null || packages == null ? null : new Lockfile(format, ecosystem!, packages, notes);
    }

    /// <summary>Lockfiles read under a folder, at most this many.</summary>
    public const int MaxFiles = 500;

    // Installed trees and tool folders hold copies, not the project's own lockfiles.
    private static readonly HashSet<string> SkippedFolders = new(StringComparer.OrdinalIgnoreCase) { "node_modules", ".git", ".venv", "venv", ".yarn", ".pnpm-store", "__pycache__" };

    /// <summary>
    /// Lockfile paths under <paramref name="root"/>, relative with '/' separators, sorted; <paramref name="complete"/> is false when
    /// <see cref="MaxFiles"/> or a folder that could not be listed stopped the walk. A file path yields itself when it is a lockfile.
    /// </summary>
    public static List<string> Find(string root, CancellationToken ct, out bool complete)
    {
        complete = true;
        var found = new List<string>();
        if (File.Exists(root))
        {
            if (Named(Path.GetFileName(root))) found.Add(Path.GetFileName(root));
            return found;
        }
        var pending = new Stack<(string Path, int Depth)>([(root, 0)]);
        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, depth) = pending.Pop();
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir))
                    if (Named(Path.GetFileName(f)))
                    {
                        if (found.Count == MaxFiles)
                        {
                            complete = false;
                            return [.. found.Order(StringComparer.Ordinal)];
                        }
                        found.Add(Path.GetRelativePath(root, f).Replace('\\', '/'));
                    }
                if (depth < 12)
                    foreach (var d in Directory.EnumerateDirectories(dir))
                        if (!SkippedFolders.Contains(Path.GetFileName(d)) && !new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint)) pending.Push((d, depth + 1));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { complete = false; }
        }
        return [.. found.Order(StringComparer.Ordinal)];
    }

    /// <summary>The lockfile at <paramref name="path"/>; null when it is not one, is larger than <see cref="MaxBytes"/> or cannot be read.</summary>
    public static Lockfile? Load(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Length > MaxBytes ? null : Read(path, File.ReadAllText(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The source of an npm resolved value or version spec: git, path, url, or registry for a tarball under a registry's /-/ path.</summary>
    internal static string NpmSource(string? resolved)
    {
        if (string.IsNullOrEmpty(resolved)) return "registry";
        if (resolved.StartsWith("git", StringComparison.Ordinal) || resolved.StartsWith("github:", StringComparison.Ordinal)
            || resolved.Contains("codeload.github.com", StringComparison.Ordinal)) return "git";
        if (resolved.StartsWith("file:", StringComparison.Ordinal) || resolved.StartsWith("link:", StringComparison.Ordinal)
            || resolved.StartsWith("workspace:", StringComparison.Ordinal) || resolved.StartsWith("portal:", StringComparison.Ordinal)) return "path";
        if (!resolved.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return "registry";
        return resolved.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && resolved.Contains("/-/", StringComparison.Ordinal) ? "registry" : "url";
    }

    private static List<LockedPackage>? Npm(string text, List<string> notes)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 256, AllowTrailingCommas = true }); }
        catch (JsonException e)
        {
            notes.Add("not JSON: " + e.Message);
            return null;
        }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            var list = new List<LockedPackage>();
            // Lockfile version 2 and 3 key every installed copy by its node_modules path.
            if (doc.RootElement.TryGetProperty("packages", out var packages) && packages.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in packages.EnumerateObject())
                {
                    if (p.Name.Length == 0 || p.Value.ValueKind != JsonValueKind.Object) continue;
                    int at = p.Name.LastIndexOf("node_modules/", StringComparison.Ordinal);
                    bool link = Bool(p.Value, "link");
                    var name = Str(p.Value, "name") ?? (at >= 0 ? p.Name[(at + "node_modules/".Length)..] : p.Name);
                    var resolved = Str(p.Value, "resolved");
                    var source = link || at < 0 ? "path" : NpmSource(resolved);
                    list.Add(new LockedPackage(name, Str(p.Value, "version") ?? "", source, resolved, Str(p.Value, "integrity"), Bool(p.Value, "hasInstallScript")));
                }
                return list;
            }
            // Lockfile version 1 nests dependencies; a git dependency's version is its URL.
            void Walk(JsonElement deps, int depth)
            {
                if (depth > 64 || deps.ValueKind != JsonValueKind.Object) return;
                foreach (var d in deps.EnumerateObject())
                {
                    if (d.Value.ValueKind != JsonValueKind.Object) continue;
                    var version = Str(d.Value, "version") ?? "";
                    var resolved = Str(d.Value, "resolved") ?? (NpmSource(version) != "registry" ? version : null);
                    list.Add(new LockedPackage(d.Name, version, NpmSource(resolved), resolved, Str(d.Value, "integrity"), false));
                    if (d.Value.TryGetProperty("dependencies", out var inner)) Walk(inner, depth + 1);
                }
            }
            if (doc.RootElement.TryGetProperty("dependencies", out var top)) Walk(top, 0);
            return list;
        }
    }

    private static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool Bool(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static List<LockedPackage> Pnpm(string text, List<string> notes)
    {
        var list = new List<LockedPackage>();
        bool v5 = Regex.Match(text, @"(?m)^lockfileVersion:\s*'?(\d+)", RegexOptions.NonBacktracking) is { Success: true } m && m.Groups[1].Value == "5";
        var lines = text.Split('\n');
        int i = Array.FindIndex(lines, l => l.TrimEnd('\r') == "packages:");
        if (i < 0) return list;
        for (i++; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (line.Length > 0 && line[0] != ' ' && line[0] != '#') break;
            if (!line.StartsWith("  ", StringComparison.Ordinal) || line.Length < 3 || line[2] == ' ' || !line.EndsWith(':')) continue;
            var key = line[2..^1].Trim('\'', '"');
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            for (; i + 1 < lines.Length && lines[i + 1].StartsWith("    ", StringComparison.Ordinal); i++)
            {
                var f = lines[i + 1].TrimEnd('\r').Trim();
                int colon = f.IndexOf(':');
                if (colon > 0 && !lines[i + 1].StartsWith("      ", StringComparison.Ordinal)) fields[f[..colon]] = f[(colon + 1)..].Trim();
            }
            var (name, version) = PnpmKey(key, v5);
            if (fields.TryGetValue("name", out var n)) name = n.Trim('\'', '"');
            if (fields.TryGetValue("version", out var v)) version = v.Trim('\'', '"');
            if (name.Length == 0)
            {
                notes.Add($"pnpm entry {key}: no name");
                continue;
            }
            var resolution = fields.GetValueOrDefault("resolution") ?? "";
            string Inline(string field) => Regex.Match(resolution, field + @":\s*'?([^,'}]+)", RegexOptions.NonBacktracking).Groups[1].Value.Trim();
            var (source, resolved) = Inline("commit") is { Length: > 0 } commit ? ("git", Inline("repo") + "#" + commit)
                : Inline("directory") is { Length: > 0 } dir ? ("path", dir)
                : Inline("tarball") is { Length: > 0 } tarball ? (tarball.StartsWith("file:", StringComparison.Ordinal) ? "path" : NpmSource(tarball), tarball)
                : ("registry", (string?)null);
            list.Add(new LockedPackage(name, version, source, resolved, Inline("integrity") is { Length: > 0 } sri ? sri : null,
                fields.GetValueOrDefault("requiresBuild") == "true"));
        }
        return list;
    }

    /// <summary>A pnpm package key split into name and version; peer suffixes, in parentheses (v6+) or after an underscore (v5), are left out.</summary>
    internal static (string Name, string Version) PnpmKey(string key, bool v5)
    {
        key = key.TrimStart('/');
        if (key.IndexOf('(') is > 0 and var paren) key = key[..paren];
        if (v5)
        {
            int slash = key.LastIndexOf('/');
            if (slash <= 0) return ("", "");
            var version = key[(slash + 1)..];
            return (key[..slash], version.IndexOf('_') is > 0 and var u ? version[..u] : version);
        }
        int at = key.LastIndexOf('@');
        return at > 0 ? (key[..at], key[(at + 1)..]) : ("", "");
    }

    private static List<LockedPackage> Yarn(string text)
    {
        var list = new List<LockedPackage>();
        string? spec = null;
        string version = "", resolved = "", integrity = "";
        bool berry = false;
        void Flush()
        {
            if (spec == null) return;
            var first = spec.Split(',')[0].Trim().Trim('"');
            int at = first.IndexOf('@', 1);
            var name = at > 0 ? first[..at] : first;
            // Berry names the resolution "name@npm:1.2.3"; other protocols leave the registry.
            var range = at > 0 ? first[(at + 1)..] : "";
            var source = resolved.Contains("@npm:", StringComparison.Ordinal) || resolved.Length == 0 && range.StartsWith("npm:", StringComparison.Ordinal) ? "registry"
                : resolved.Contains("@workspace:", StringComparison.Ordinal) || resolved.Contains("@patch:", StringComparison.Ordinal) ? "path"
                : NpmSource(berry && resolved.IndexOf('@', 1) is > 0 and var r ? resolved[(r + 1)..] : resolved);
            if (name != "__metadata")
                list.Add(new LockedPackage(name, version, source, resolved.Length > 0 ? resolved : null, integrity.Length > 0 ? integrity : null, false));
            spec = null;
            version = resolved = integrity = "";
            berry = false;
        }
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line[0] == '#') continue;
            if (line[0] != ' ')
            {
                Flush();
                if (line.EndsWith(':')) spec = line[..^1];
                continue;
            }
            if (!line.StartsWith("  ", StringComparison.Ordinal) || line.StartsWith("   ", StringComparison.Ordinal)) continue;
            var (key, value) = YarnField(line.Trim());
            switch (key)
            {
                case "version": version = value; break;
                case "resolved": resolved = value; break;
                case "resolution": resolved = value; berry = true; break;
                case "integrity" or "checksum": integrity = value; break;
            }
        }
        Flush();
        return list;
    }

    /// <summary>A yarn field line, v1 (key "value") or berry (key: value), with quotes removed.</summary>
    private static (string Key, string Value) YarnField(string line)
    {
        int split = line.IndexOfAny([' ', ':']);
        if (split <= 0) return ("", "");
        return (line[..split].Trim('"'), line[(split + 1)..].TrimStart(':').Trim().Trim('"'));
    }

    private static List<LockedPackage> Toml(string text, bool poetry)
    {
        var list = new List<LockedPackage>();
        var blocks = PackageTable().Split(text);
        var hashes = poetry ? MetadataFiles(text) : null;
        foreach (var block in blocks.Skip(1))
        {
            // The table ends at the next top-level table other than its own sub-tables.
            var body = block[..OtherTable(block)];
            int sub = body.IndexOf("\n[", StringComparison.Ordinal);
            var head = sub >= 0 ? body[..sub] : body;
            string Field(string text0, string key) => Regex.Match(text0, $@"(?m)^{key}\s*=\s*""([^""]*)""", RegexOptions.NonBacktracking).Groups[1].Value;
            var name = Normalize(Field(head, "name"));
            if (name.Length == 0) continue;
            var version = Field(head, "version");
            string source = "registry";
            string? resolved = null;
            if (poetry)
            {
                if (body.IndexOf("\n[package.source]", StringComparison.Ordinal) is >= 0 and var at)
                {
                    var table = body[(at + 1)..];
                    table = table.IndexOf("\n[", StringComparison.Ordinal) is > 0 and var next ? table[..next] : table;
                    var type = Field(table, "type");
                    var url = Field(table, "url");
                    var commit = Field(table, "resolved_reference");
                    (source, resolved) = type switch
                    {
                        "git" => ("git", url + (commit.Length > 0 ? "#" + commit : "")),
                        "url" => ("url", url),
                        "file" or "directory" => ("path", url),
                        _ => ("registry", url.Length > 0 ? url : null),
                    };
                }
            }
            else if (Regex.Match(head, @"(?m)^source\s*=\s*\{\s*(\w+)\s*=\s*""([^""]*)""", RegexOptions.NonBacktracking) is { Success: true } s)
            {
                resolved = s.Groups[2].Value;
                source = s.Groups[1].Value switch
                {
                    "registry" => "registry",
                    "git" => "git",
                    "url" => "url",
                    _ => "path",
                };
            }
            var found = Regex.Matches(body, @"hash\s*=\s*""([^""]+)""", RegexOptions.NonBacktracking).Select(m => m.Groups[1].Value)
                .Concat(hashes?.GetValueOrDefault(name) ?? []).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            list.Add(new LockedPackage(name, version, source, resolved, found.Count > 0 ? string.Join(" ", found) : null, false));
        }
        return list;
    }

    /// <summary>Poetry 1.1 and earlier keep file hashes in [metadata.files], keyed by normalized name.</summary>
    private static Dictionary<string, List<string>> MetadataFiles(string text)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        int at = text.IndexOf("[metadata.files]", StringComparison.Ordinal);
        if (at < 0) return map;
        string? current = null;
        foreach (var raw in text[at..].Split('\n').Skip(1))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith('[')) break;
            if (Regex.Match(line, @"^""?([A-Za-z0-9._-]+)""?\s*=\s*\[", RegexOptions.NonBacktracking) is { Success: true } k) current = Normalize(k.Groups[1].Value);
            if (current == null) continue;
            foreach (Match h in Regex.Matches(line, @"hash\s*=\s*""([^""]+)""", RegexOptions.NonBacktracking))
                (map.TryGetValue(current, out var l) ? l : map[current] = []).Add(h.Groups[1].Value);
        }
        return map;
    }

    private static List<LockedPackage> Pip(string text)
    {
        var list = new List<LockedPackage>();
        foreach (var logical in Regex.Replace(text, @"\\\r?\n", " ", RegexOptions.NonBacktracking).Split('\n'))
        {
            var line = logical.Split(" #")[0].Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var hashes = Regex.Matches(line, @"--hash[= ]([^\s]+)", RegexOptions.NonBacktracking).Select(m => m.Groups[1].Value).Order(StringComparer.Ordinal).ToList();
            string? Integrity() => hashes.Count > 0 ? string.Join(" ", hashes) : null;
            if (Regex.Match(line, @"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;]+)", RegexOptions.NonBacktracking) is { Success: true } pin)
                list.Add(new LockedPackage(Normalize(pin.Groups[1].Value), pin.Groups[2].Value, "registry", null, Integrity(), false));
            else if (Regex.Match(line, @"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*@\s*(\S+)", RegexOptions.NonBacktracking) is { Success: true } direct)
            {
                var url = direct.Groups[2].Value;
                var source = url.StartsWith("git+", StringComparison.Ordinal) ? "git" : url.StartsWith("file:", StringComparison.Ordinal) ? "path" : "url";
                list.Add(new LockedPackage(Normalize(direct.Groups[1].Value), "", source, url, Integrity(), false));
            }
        }
        return list;
    }

    /// <summary>
    /// Packages added, removed or changed between two reads of one lockfile, keyed "<paramref name="where"/>: name@version", in key order.
    /// Old and New name the level and source; a git or URL source added or taken on, or an integrity changed for one version, is noteworthy.
    /// </summary>
    public static IReadOnlyList<Core.EvidenceChange> Diff(Lockfile old, Lockfile @new, string where)
    {
        // Copies of one name@version are one row; a copy from outside the registry decides its source.
        static Dictionary<string, LockedPackage> Keyed(Lockfile l) => l.Packages.GroupBy(p => $"{p.Name}@{p.Version}", StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.OrderBy(p => p.Source == "registry" ? 1 : 0).First() with { InstallScript = g.Any(p => p.InstallScript) }, StringComparer.Ordinal);
        static bool Outside(LockedPackage p) => p.Source is "git" or "url";
        static string Describe(LockedPackage p, bool noteworthy) => (noteworthy ? "noteworthy: " : "") + p.Source
            + (p.Resolved != null && p.Source != "registry" ? " " + p.Resolved : "") + (p.InstallScript ? ", runs a script at install" : "");
        var before = Keyed(old);
        var after = Keyed(@new);
        var rows = new List<Core.EvidenceChange>();
        foreach (var key in before.Keys.Union(after.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            bool had = before.TryGetValue(key, out var o), has = after.TryGetValue(key, out var n);
            if (!had)
            {
                rows.Add(new Core.EvidenceChange("added", $"{where}: {key}", null, Describe(n!, Outside(n!)), null));
                continue;
            }
            if (!has)
            {
                rows.Add(new Core.EvidenceChange("removed", $"{where}: {key}", Describe(o!, false), null, null));
                continue;
            }
            var fields = new List<string>();
            bool noteworthy = false;
            if (o!.Source != n!.Source)
            {
                fields.Add("source");
                noteworthy |= Outside(n);
            }
            if (o.Integrity != null && n.Integrity != null && o.Integrity != n.Integrity)
            {
                fields.Add("integrity");
                noteworthy = true;
            }
            if (!o.InstallScript && n.InstallScript) fields.Add("install script");
            if (fields.Count > 0) rows.Add(new Core.EvidenceChange("changed", $"{where}: {key}", Describe(o, false), Describe(n, noteworthy), fields));
        }
        return rows;
    }

    /// <summary>A Python distribution name normalized as package indexes compare it: lowercase, runs of '-', '_' and '.' as one '-'.</summary>
    internal static string Normalize(string name) => Regex.Replace(name.Trim().ToLowerInvariant(), "[-_.]+", "-", RegexOptions.NonBacktracking);

    [GeneratedRegex(@"(?m)^\[\[package\]\][ \t]*\r?$", RegexOptions.NonBacktracking)]
    private static partial Regex PackageTable();

    /// <summary>Where the first top-level table other than a [package.*] sub-table starts in <paramref name="block"/>; its length when none does.</summary>
    private static int OtherTable(string block)
    {
        for (int at = 0; at < block.Length; at = block.IndexOf('\n', at) is var nl and >= 0 ? nl + 1 : block.Length)
            if (block[at] == '[' && !block.AsSpan(at).StartsWith("[package.")) return at;
        return block.Length;
    }
}
