using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private const int MaxScannedSources = 200;
    private const long MaxScannedSourceBytes = 16 << 20;

    /// <summary>The first <see cref="MaxScannedSources"/> of <paramref name="sources"/>; the rest are named in the package's not-read list.</summary>
    private static List<string> Capped(PackageFiles files, List<string> sources)
    {
        if (sources.Count > MaxScannedSources)
            files.NotRead.Add($"{sources.Count - MaxScannedSources} source(s) past the first {MaxScannedSources}, from {sources[MaxScannedSources]}");
        return sources.Take(MaxScannedSources).ToList();
    }

    private static readonly Regex NotImported = new(@"(?:^|/)(?:tests?|testing|examples?|docs?|benchmarks?)/|(?:^|/)(?:test_[^/]*|[^/]*_test|conftest)\.py$", RegexOptions.NonBacktracking);

    private static readonly Regex StealerKit = new(@"(?i)\b(?:browser[_-]cookie3|discord[_-]?webhook|robloxpy|discord_webhook)\b", RegexOptions.NonBacktracking);

    private static PackageReport? Python(PackageFiles files, CancellationToken ct)
    {
        var findings = new List<PackageFinding>();
        var notes = new List<string>();
        var scripts = new List<PackageScript>();
        var entries = new List<PackageEntryPoint>();
        var loaded = new List<(string From, string Module)>();
        string moduleRoot = "";
        HashSet<string>? topLevel = null;
        string? name = null, version = null, summary = null, author = null, record = null;
        int deps = 0;
        var manifests = new List<(string Path, string? Text)>();
        var distInfo = files.Paths.Where(p => p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal)).OrderBy(p => p.Length).FirstOrDefault();
        string ecosystem;
        if (distInfo != null)
        {
            ecosystem = "pypi wheel";
            var info = distInfo[..^"METADATA".Length];
            (name, version, summary, author, deps) = Metadata(files.Text(distInfo));
            manifests.Add((distInfo, RequiresDist(files.Text(distInfo))));
            if (files.Text(info + "entry_points.txt") is { } ep) entries.AddRange(EntryPoints(ep));
            record = Record(files, info + "RECORD", findings);
            if (files.Text(info + "top_level.txt") is { } top)
                topLevel = [.. top.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)];
            foreach (var script in files.Paths.Where(p => Regex.IsMatch(p, @"^[^/]+\.data/scripts/[^/]+$", RegexOptions.NonBacktracking)))
                entries.Add(new PackageEntryPoint("script", script[(script.LastIndexOf('/') + 1)..], script));
            // Import lines in top-level .pth files run at every interpreter start.
            foreach (var pth in files.Paths.Where(p => !p.Contains('/') && p.EndsWith(".pth", StringComparison.Ordinal)))
            {
                var text = files.Text(pth) ?? "";
                var imports = text.Split('\n').Where(l => Regex.IsMatch(l, @"^\s*import\s", RegexOptions.NonBacktracking)).ToList();
                if (imports.Count == 0) continue;
                foreach (var line in imports)
                    foreach (var module in line.Trim()[6..].Split(';')[0].Split(',', StringSplitOptions.TrimEntries))
                        loaded.Add((pth, module.Split(' ')[0]));
                findings.Add(new PackageFinding("package/startup-pth", "review", "install script", $"{pth} runs at every interpreter start: {Clip(string.Join("; ", imports.Select(l => l.Trim())), 200)}", pth));
                findings.AddRange(Scan(pth + ".py", string.Join("\n", imports), install: true, ct).Where(f => f.Level == "noteworthy" || f.Category != "install script"));
                scripts.Add(new PackageScript(pth, Clip(string.Join("; ", imports.Select(l => l.Trim())), 300)!, true));
            }
        }
        else
        {
            ecosystem = "pypi sdist";
            var root = files.Paths.Where(IsSdistFile).Select(Folder).OrderBy(p => p.Length).First();
            moduleRoot = root;
            if (files.Text(root + "PKG-INFO") is { } pkgInfo) (name, version, summary, author, deps) = Metadata(pkgInfo);
            manifests.Add((root + "PKG-INFO", RequiresDist(files.Text(root + "PKG-INFO"))));
            foreach (var file in new[] { "setup.py", "setup.cfg", "pyproject.toml" }) manifests.Add((root + file, files.Text(root + file)));
            foreach (var eggInfo in files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && Regex.IsMatch(p[root.Length..], @"^[^/]+\.egg-info/requires\.txt$", RegexOptions.NonBacktracking)).Take(4))
                manifests.Add((eggInfo, files.Text(eggInfo)));
            if (files.Text(root + "setup.py") is { } setup)
            {
                // pip runs setup.py to build an sdist, so its module-level code runs at install.
                scripts.Add(new PackageScript("setup.py", "python setup.py (run by pip to build the package)", true));
                if (Regex.IsMatch(setup, @"\bcmdclass\s*=|class\s+\w+\s*\(\s*(?:_?install|develop|egg_info|build_py|build_ext|sdist|bdist_\w+)\s*\)", RegexOptions.NonBacktracking))
                    findings.Add(new PackageFinding("package/setup-cmdclass", "review", "install script", "setup.py replaces a setuptools command (cmdclass): its code runs while installing", root + "setup.py"));
                findings.AddRange(Scan(root + "setup.py", SetupCode(files, root, setup), install: true, ct));
                foreach (Match m in LocalImport.Matches(setup))
                {
                    var module = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[3].Value;
                    loaded.Add(("setup.py", module));
                    if (m.Groups[2].Success)
                        foreach (var member in m.Groups[2].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                            loaded.Add(("setup.py", $"{module}.{member}"));
                }
                name ??= Regex.Match(setup, @"\bname\s*=\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking).Groups[1].Value is { Length: > 0 } n ? n : null;
                version ??= Regex.Match(setup, @"\bversion\s*=\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking).Groups[1].Value is { Length: > 0 } v ? v : null;
                foreach (Match m in Regex.Matches(setup, @"['""]([\w.-]+)\s*=\s*([\w.]+:[\w.]+)['""]", RegexOptions.NonBacktracking))
                    entries.Add(new PackageEntryPoint("console_scripts", m.Groups[1].Value, m.Groups[2].Value));
            }
            if (files.Text(root + "pyproject.toml") is { } pyproject)
            {
                var backend = Regex.Match(pyproject, @"build-backend\s*=\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking).Groups[1].Value;
                if (Regex.IsMatch(pyproject, @"\bbackend-path\s*=", RegexOptions.NonBacktracking))
                {
                    findings.Add(new PackageFinding("package/in-tree-backend", "review", "install script", $"an in-tree build backend ({backend}) runs from the package while installing", root + "pyproject.toml"));
                    scripts.Add(new PackageScript("build-backend", backend, true));
                }
                name ??= Regex.Match(pyproject, @"(?m)^\s*name\s*=\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking).Groups[1].Value is { Length: > 0 } pn ? pn : null;
                version ??= Regex.Match(pyproject, @"(?m)^\s*version\s*=\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking).Groups[1].Value is { Length: > 0 } pv ? pv : null;
                foreach (Match m in ProjectScripts().Matches(pyproject))
                    foreach (Match e in Regex.Matches(m.Groups[2].Value, @"(?m)^\s*['""]?([\w.-]+)['""]?\s*=\s*['""]([^'""]+)['""]", RegexOptions.NonBacktracking))
                        entries.Add(new PackageEntryPoint(m.Groups[1].Value == "scripts" ? "console_scripts" : "gui_scripts", e.Groups[1].Value, e.Groups[2].Value));
            }
            if (files.Text(root + "setup.cfg") is { } cfg && EntryPointSection().Match(cfg) is { Success: true } cfgEntries)
                entries.AddRange(EntryPoints(CfgGroup().Replace(cfgEntries.Groups[1].Value, "[$1]")));
        }
        // Import-time code, __init__ modules first; tests, examples and docs are not imported.
        List<string> sources = [.. files.Paths.Where(p => p.EndsWith(".py", StringComparison.Ordinal) && !p.EndsWith("setup.py", StringComparison.Ordinal) && !NotImported.IsMatch(p))
            .OrderBy(p => p.EndsWith("__init__.py", StringComparison.Ordinal) ? 0 : 1).ThenBy(p => p.Count(c => c == '/'))];
        foreach (var source in Capped(files, sources))
            if (files.Text(source) is { } code)
                findings.AddRange(Scan(source, code, install: false, ct, entry: source.EndsWith("__init__.py", StringComparison.Ordinal))
                    .Where(f => f.Level == "noteworthy" || f.Category is "transformed code" or "credentials" or "build step" or "clipboard"));
        var binaries = Binaries(files);
        // Cython keeps a module's constants in one zlib stream.
        var extensions = binaries.Where(p => files.Bytes(p) is { } b && b.AsSpan().IndexOf("__pyx_"u8) >= 0).ToList();
        if (extensions.Count > MaxExtensions) notes.Add($"partial: {extensions.Count - MaxExtensions} Cython extension(s) past the first {MaxExtensions} not read");
        int undecoded = 0;
        long budget = MaxScannedSourceBytes;
        var buffer = new byte[MaxTableBytes];
        foreach (var ext in extensions.Take(MaxExtensions))
        {
            if (CythonStrings(files.Bytes(ext)!, buffer, ref budget, ct) is { } strings)
                findings.AddRange(Scan(ext, strings, install: false, ct, peel: false)
                    .Where(f => f.Level == "noteworthy" || f.Category is "transformed code" or "credentials" or "build step" or "clipboard"));
            else if (budget <= 0) { notes.Add($"partial: Cython string tables past the first {MaxScannedSourceBytes >> 20} MiB not read, from {ext}"); break; }
            else undecoded++;
        }
        if (undecoded > 0) notes.Add($"partial: {undecoded} Cython extension(s) with no decoded string table; their strings were not read");
        // Past the cap, a byte prefilter keeps a decoded file run in a large
        // package in view.
        foreach (var source in sources.Skip(MaxScannedSources))
            if (files.Bytes(source) is { } bytes && bytes.AsSpan().IndexOf("b64decode"u8) >= 0 && bytes.AsSpan().IndexOf("subprocess"u8) >= 0
                && files.Text(source) is { } code && WritesDecodedAndRuns(code))
                findings.Add(new PackageFinding("package/decoded-file-run", "noteworthy", "process", DecodedFileRun, source));
        // Scripts at the package root, beside the modules, can be started
        // from module code. Build scripts there run at neither import nor
        // install, so only transformed code is kept.
        var rootScripts = files.Paths.Where(p => p.StartsWith(moduleRoot, StringComparison.Ordinal) && !p.AsSpan(moduleRoot.Length).Contains('/')
                                                 && (p.EndsWith(".js", StringComparison.Ordinal) || p.EndsWith(".sh", StringComparison.Ordinal))).ToList();
        files.NotRead.AddRange(rootScripts.Where(p => files.Size(p) > MaxScannedSourceBytes && files.Bytes(p) != null)
            .Select(p => $"{p} (source over {MaxScannedSourceBytes >> 20} MiB)"));
        foreach (var script in Capped(files, [.. rootScripts.Where(p => files.Size(p) <= MaxScannedSourceBytes)]))
            if (files.Text(script) is { } code)
                findings.AddRange(Scan(script, code, install: false, ct, peel: false).Where(f => f is { Level: "noteworthy", Category: "transformed code" }));
        // Cookie, webhook and session libraries together mark a credential collector.
        var requires = string.Join("\n", files.Paths.Where(p => p.EndsWith("/setup.py", StringComparison.Ordinal) || p == "setup.py" || p.EndsWith("/PKG-INFO", StringComparison.Ordinal)
                                                              || p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal) || p.EndsWith("/requires.txt", StringComparison.Ordinal))
            .Select(p => files.Text(p) ?? ""));
        var kit = StealerKit.Matches(requires).Select(m => m.Value.ToLowerInvariant().Replace('-', '_')).Distinct().ToList();
        if (kit.Count >= 2) findings.Add(new PackageFinding("package/stealer-dependencies", "noteworthy", "credentials", $"depends on {string.Join(", ", kit)}: browser cookie, Discord webhook and Roblox session libraries together"));
        if (CompiledOnly(files, Modules(files, moduleRoot, topLevel), loaded) is { } compiledOnly) findings.Add(compiledOnly);
        var outside = new List<string>();
        string? outsideAt = null;
        foreach (var (path, text) in manifests)
            foreach (Match m in DirectReference.Matches(text ?? "").Take(MaxDependencies))
            {
                var url = m.Groups["url"].Value;
                var dep = m.Groups["name"].Success ? m.Groups["name"].Value : EggName.Match(url) is { Success: true } egg ? egg.Groups[1].Value : "(unnamed)";
                var kind = url.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ? "file"
                    : url.IndexOf('+') is > 0 and var plus && plus < url.IndexOf(':') ? url[..plus].ToLowerInvariant() : "url";
                var item = SourceUrl.Match(url) is { Success: true } h ? $"{dep} ({kind}, {h.Groups["host"].Value.ToLowerInvariant()})" : $"{dep} ({kind})";
                if (outside.Count < MaxDependencies && !outside.Contains(item)) { outside.Add(item); outsideAt ??= path; }
            }
        if (outside.Count > 0)
            findings.Add(new PackageFinding("package/dependency-source", scripts.Any(s => s.AtInstall) ? "noteworthy" : "review", "dependency",
                $"{outside.Count} dependenc{(outside.Count == 1 ? "y" : "ies")} from outside the registry: {string.Join(", ", outside.Take(5))}", outsideAt));
        if (HighVersion(version) is { } high)
            findings.Add(new PackageFinding("package/high-version", "review", "version", $"version {high} has a major version of 99 or higher"));
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        if (name != null && CloseTo(name, PopularNames.PyPI) is { } popular)
            findings.Add(new PackageFinding("package/close-name", scripts.Any(s => s.AtInstall) ? "noteworthy" : "review", "name", $"the name '{name}' is close to the popular package '{popular}'"));
        findings.AddRange(CommandNames(name, entries, scripts.Any(s => s.AtInstall), distInfo != null ? distInfo[..^"METADATA".Length] + "entry_points.txt" : null));
        return new PackageReport(ecosystem, name, version)
        {
            Publisher = author, Description = Clip(summary), Scripts = scripts, EntryPoints = entries, Dependencies = deps,
            Binaries = binaries.Count > 0 ? binaries : null, Record = record, Findings = findings, Notes = notes,
        };
    }

    private const int MaxExtensions = 64, MaxStreamTries = 2048, MaxTableBytes = 4 << 20;

    /// <summary>A Cython extension's string table, inflated from the first zlib stream holding module names; null when none decodes within the bounds or the budget runs out.</summary>
    internal static string? CythonStrings(byte[] image, byte[] buffer, ref long budget, CancellationToken ct)
    {
        int tries = 0;
        for (int at = -1, next; budget > 0 && tries < MaxStreamTries && (next = image.AsSpan(at + 1).IndexOf((byte)0x78)) >= 0 && (at += next + 1) + 2 < image.Length;)
        {
            // A zlib header: deflate, 32 KiB window, no preset dictionary,
            // check bits a multiple of 31.
            if ((image[at] << 8 | image[at + 1]) % 31 != 0 || (image[at + 1] & 0x20) != 0) continue;
            ct.ThrowIfCancellationRequested();
            tries++;
            int read = 0, limit = (int)Math.Min(buffer.Length, budget);
            try
            {
                using var z = new ZLibStream(new MemoryStream(image, at, image.Length - at, writable: false), CompressionMode.Decompress);
                for (int n; read < limit && (n = z.Read(buffer, read, limit - read)) > 0;) read += n;
            }
            catch (InvalidDataException) { continue; }
            finally { budget -= read; }
            var table = buffer.AsSpan(0, read);
            if (table.IndexOf("__test__"u8) >= 0 || table.IndexOf("__name__"u8) >= 0) return System.Text.Encoding.UTF8.GetString(table);
        }
        return null;
    }

    // PEP 508 direct references (name @ url) and bare VCS URLs (git+https://...#egg=name).
    private static readonly Regex DirectReference = R(@"(?<name>[A-Za-z0-9][\w.-]*)\s*(?:\[[^\]\n]*\])?\s*@\s*(?<url>(?:(?:git|hg|svn|bzr)\+[a-z]+://|https?://|file:)[^\s'"";,]+)|(?<url>(?:git|hg|svn|bzr)\+[a-z]+://[^\s'"";,]+)");
    private static readonly Regex EggName = R(@"#egg=([\w.-]+)");

    /// <summary>The Requires-Dist lines of core metadata, so URLs in its description are not read as dependencies.</summary>
    private static string? RequiresDist(string? text) =>
        text == null ? null : string.Join("\n", text.Split('\n').Where(l => l.StartsWith("Requires-Dist:", StringComparison.Ordinal)));

    // A section starts at its header and ends at the next one, so the lookahead keeps work linear.
    [GeneratedRegex(@"(?ms)^\[project\.(scripts|gui-scripts)\]\s*$(.*?)(?=^\[|\z)")]
    private static partial Regex ProjectScripts();

    [GeneratedRegex(@"(?ms)^\[options\.entry_points\]\s*$(.*?)(?=^\[|\z)")]
    private static partial Regex EntryPointSection();

    // An unindented "group =" line opens a group; its indented lines are the entries.
    [GeneratedRegex(@"(?m)^([\w.-]+)[ \t]*=[ \t\r]*$", RegexOptions.NonBacktracking)]
    private static partial Regex CfgGroup();

    private static readonly Regex LocalImport =new(@"(?m)^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import[ \t]+([\w, \t]+)|import[ \t]+([\w.]+))", RegexOptions.NonBacktracking);

    /// <summary>Importable modules under <paramref name="root"/> by dotted name: Compiled when only a .pyc ships, Path its first file; tests and setup.py excluded.</summary>
    private static Dictionary<string, (bool Compiled, string Path)> Modules(PackageFiles files, string root, HashSet<string>? topLevel)
    {
        var modules = new Dictionary<string, (bool, string)>(StringComparer.Ordinal);
        foreach (var path in files.Paths.Order(StringComparer.Ordinal))
        {
            bool source = path.EndsWith(".py", StringComparison.Ordinal), compiled = path.EndsWith(".pyc", StringComparison.Ordinal);
            // Without a source the import system ignores __pycache__, so only a .pyc in
            // the package folder itself imports alone.
            if (!source && !compiled || !path.StartsWith(root, StringComparison.Ordinal) || ("/" + path).Contains("/__pycache__/", StringComparison.Ordinal)
                || path.Contains(".dist-info/", StringComparison.Ordinal) || path.Contains(".egg-info/", StringComparison.Ordinal) || NotImported.IsMatch(path)) continue;
            var rel = path[root.Length..^(source ? 3 : 4)];
            if (rel.StartsWith("src/", StringComparison.Ordinal)) rel = rel[4..];
            if (rel == "setup") continue;
            if (rel.EndsWith("/__init__", StringComparison.Ordinal)) rel = rel[..^9];
            var module = rel.Replace('/', '.');
            if (topLevel != null && !topLevel.Contains(module.Split('.')[0])) continue;
            modules[module] = modules.TryGetValue(module, out var seen) ? (seen.Item1 && compiled, seen.Item2) : (compiled, path);
        }
        return modules;
    }

    /// <summary>The compiled-only finding, noteworthy when a .pth file or setup.py imports such a module; null when every module has source.</summary>
    private static PackageFinding? CompiledOnly(PackageFiles files, Dictionary<string, (bool Compiled, string Path)> modules, List<(string From, string Module)> loaded)
    {
        var compiled = modules.Where(m => m.Value.Compiled).OrderBy(m => m.Key, StringComparer.Ordinal).ToList();
        if (compiled.Count == 0) return null;
        // Importing a.b also runs a, so any compiled-only prefix counts.
        var started = loaded.Where(l => Prefixes(l.Module).Any(p => modules.TryGetValue(p, out var m) && m.Compiled))
            .Select(l => $"{l.From} imports {l.Module}").Distinct().ToList();
        var detail = $"{compiled.Count} of {modules.Count} modules compiled only, without .py source: {string.Join(", ", compiled.Take(5).Select(m => m.Key))}";
        if (started.Count > 0) detail += $"; runs without asking: {string.Join(", ", started.Take(5))}";
        if (files.Unlisted > 0) detail += $"; partial: files past the first {PackageFiles.MaxEntries:N0} not listed";
        return new PackageFinding("package/compiled-only", started.Count > 0 ? "noteworthy" : "review", "transformed code", detail, compiled[0].Value.Path);
    }

    private static IEnumerable<string> Prefixes(string module)
    {
        for (int dot = module.IndexOf('.'); dot > 0; dot = module.IndexOf('.', dot + 1)) yield return module[..dot];
        yield return module;
    }

    /// <summary>setup.py with the package's own modules it imports (pip runs them too), up to eight small files.</summary>
    private static string SetupCode(PackageFiles files, string root, string setup)
    {
        var text = new System.Text.StringBuilder(setup);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in LocalImport.Matches(setup))
        {
            var module = (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[3].Value).Replace('.', '/');
            var names = m.Groups[2].Success ? m.Groups[2].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) : [];
            var candidates = names.Select(n => $"{root}{module}/{n}.py").Concat([$"{root}{module}.py", $"{root}{module}/__init__.py"]);
            foreach (var path in candidates)
                if (seen.Count < 8 && files.Has(path) && files.Size(path) <= 64 << 10 && seen.Add(path) && files.Text(path) is { } code)
                    text.Append('\n').Append(code);
        }
        return text.ToString();
    }

    /// <summary>Core metadata (METADATA / PKG-INFO): name, version, summary, author and the count of Requires-Dist.</summary>
    private static (string?, string?, string?, string?, int) Metadata(string? text)
    {
        if (text == null) return (null, null, null, null, 0);
        string? Header(string key) => Regex.Match(text, $@"(?m)^{key}:\s*(.+?)\s*$", RegexOptions.NonBacktracking) is { Success: true } m ? m.Groups[1].Value : null;
        int deps = Regex.Count(text, @"(?m)^Requires-Dist:", RegexOptions.NonBacktracking);
        return (Header("Name"), Header("Version"), Header("Summary"), Header("Author") ?? Header("Author-email"), deps);
    }

    /// <summary>entry_points.txt: each group's name = module:function lines.</summary>
    private static IEnumerable<PackageEntryPoint> EntryPoints(string text)
    {
        string group = "";
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('[') && line.EndsWith(']')) { group = line[1..^1].Trim(); continue; }
            int eq = line.IndexOf('=');
            if (eq > 0 && group.Length > 0) yield return new PackageEntryPoint(group, line[..eq].Trim(), line[(eq + 1)..].Trim());
        }
    }

    /// <summary>A wheel's RECORD checked against its files: sha256 equal, different, or the file not listed.</summary>
    private static string? Record(PackageFiles files, string path, List<PackageFinding> findings)
    {
        if (files.Text(path) is not { } text) return null;
        var listed = new HashSet<string>(StringComparer.Ordinal);
        int match = 0, differ = 0;
        var differing = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            var parts = line.Trim().Split(',');
            if (parts.Length < 2 || parts[0].Length == 0) continue;
            var file = parts[0].Trim('"');
            listed.Add(file);
            if (!parts[1].StartsWith("sha256=", StringComparison.Ordinal) || files.Bytes(file) is not { } bytes) continue;
            var digest = Convert.ToBase64String(SHA256.HashData(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            if (digest == parts[1][7..]) match++;
            else { differ++; differing.Add(file); }
        }
        var unlisted = files.Paths.Where(p => !listed.Contains(p) && !p.EndsWith("/RECORD.jws", StringComparison.Ordinal) && !p.EndsWith("/RECORD.p7s", StringComparison.Ordinal)).ToList();
        if (differ > 0) findings.Add(new PackageFinding("package/record-differs", "noteworthy", "record", $"{differ} file(s) differ from their RECORD hash: {string.Join(", ", differing.Take(5))}", differing[0]));
        if (unlisted.Count > 0) findings.Add(new PackageFinding("package/record-unlisted", "review", "record", $"{unlisted.Count} file(s) not listed in RECORD: {string.Join(", ", unlisted.Take(5))}", unlisted[0]));
        return $"{match} match, {differ} differ, {unlisted.Count} not listed";
    }
}
