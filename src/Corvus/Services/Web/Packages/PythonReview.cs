using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private const int MaxScannedSources = 200;

    private static readonly Regex NotImported = new(@"(?:^|/)(?:tests?|testing|examples?|docs?|benchmarks?)/|(?:^|/)(?:test_[^/]*|[^/]*_test|conftest)\.py$", RegexOptions.Compiled);

    private static readonly Regex StealerKit = new(@"(?i)\b(?:browser[_-]cookie3|discord[_-]?webhook|robloxpy|discord_webhook)\b", RegexOptions.Compiled);

    private static PackageReport? Python(PackageFiles files, CancellationToken ct)
    {
        var findings = new List<PackageFinding>();
        var notes = new List<string>();
        var scripts = new List<PackageScript>();
        var entries = new List<PackageEntryPoint>();
        string? name = null, version = null, summary = null, author = null, record = null;
        int deps = 0;
        var distInfo = files.Paths.Where(p => p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal)).OrderBy(p => p.Length).FirstOrDefault();
        string ecosystem;
        if (distInfo != null)
        {
            ecosystem = "pypi wheel";
            var info = distInfo[..^"METADATA".Length];
            (name, version, summary, author, deps) = Metadata(files.Text(distInfo));
            if (files.Text(info + "entry_points.txt") is { } ep) entries.AddRange(EntryPoints(ep));
            record = Record(files, info + "RECORD", findings);
            foreach (var script in files.Paths.Where(p => Regex.IsMatch(p, @"^[^/]+\.data/scripts/[^/]+$")))
                entries.Add(new PackageEntryPoint("script", script[(script.LastIndexOf('/') + 1)..], script));
            // .pth files at the top of site-packages: their import lines run at every interpreter start
            foreach (var pth in files.Paths.Where(p => !p.Contains('/') && p.EndsWith(".pth", StringComparison.Ordinal)))
            {
                var text = files.Text(pth) ?? "";
                var imports = text.Split('\n').Where(l => Regex.IsMatch(l, @"^\s*import\s")).ToList();
                if (imports.Count == 0) continue;
                findings.Add(new PackageFinding("review", "install script", $"{pth} runs at every interpreter start: {Clip(string.Join("; ", imports.Select(l => l.Trim())), 200)}", pth));
                findings.AddRange(Scan(pth + ".py", string.Join("\n", imports), install: true, ct).Where(f => f.Level == "noteworthy" || f.Category != "install script"));
                scripts.Add(new PackageScript(pth, Clip(string.Join("; ", imports.Select(l => l.Trim())), 300)!, true));
            }
        }
        else
        {
            ecosystem = "pypi sdist";
            var root = files.Paths.Where(IsSdistFile).Select(Folder).OrderBy(p => p.Length).First();
            if (files.Text(root + "PKG-INFO") is { } pkgInfo) (name, version, summary, author, deps) = Metadata(pkgInfo);
            if (files.Text(root + "setup.py") is { } setup)
            {
                // pip runs setup.py to build or install an sdist: its module-level code runs at install
                scripts.Add(new PackageScript("setup.py", "python setup.py (run by pip to build the package)", true));
                if (Regex.IsMatch(setup, @"\bcmdclass\s*=|class\s+\w+\s*\(\s*(?:_?install|develop|egg_info|build_py|build_ext|sdist|bdist_\w+)\s*\)"))
                    findings.Add(new PackageFinding("review", "install script", "setup.py replaces a setuptools command (cmdclass): its code runs while installing", root + "setup.py"));
                findings.AddRange(Scan(root + "setup.py", setup, install: true, ct));
                name ??= Regex.Match(setup, @"\bname\s*=\s*['""]([^'""]+)['""]").Groups[1].Value is { Length: > 0 } n ? n : null;
                version ??= Regex.Match(setup, @"\bversion\s*=\s*['""]([^'""]+)['""]").Groups[1].Value is { Length: > 0 } v ? v : null;
                foreach (Match m in Regex.Matches(setup, @"['""]([\w.-]+)\s*=\s*([\w.]+:[\w.]+)['""]"))
                    entries.Add(new PackageEntryPoint("console_scripts", m.Groups[1].Value, m.Groups[2].Value));
            }
            if (files.Text(root + "pyproject.toml") is { } pyproject)
            {
                var backend = Regex.Match(pyproject, @"build-backend\s*=\s*['""]([^'""]+)['""]").Groups[1].Value;
                if (Regex.IsMatch(pyproject, @"\bbackend-path\s*="))
                {
                    findings.Add(new PackageFinding("review", "install script", $"an in-tree build backend ({backend}) runs from the package while installing", root + "pyproject.toml"));
                    scripts.Add(new PackageScript("build-backend", backend, true));
                }
                name ??= Regex.Match(pyproject, @"(?m)^\s*name\s*=\s*['""]([^'""]+)['""]").Groups[1].Value is { Length: > 0 } pn ? pn : null;
                version ??= Regex.Match(pyproject, @"(?m)^\s*version\s*=\s*['""]([^'""]+)['""]").Groups[1].Value is { Length: > 0 } pv ? pv : null;
                foreach (Match m in Regex.Matches(pyproject, @"(?ms)^\[project\.(scripts|gui-scripts)\]\s*$(.*?)(?=^\[|\z)"))
                    foreach (Match e in Regex.Matches(m.Groups[2].Value, @"(?m)^\s*['""]?([\w.-]+)['""]?\s*=\s*['""]([^'""]+)['""]"))
                        entries.Add(new PackageEntryPoint(m.Groups[1].Value == "scripts" ? "console_scripts" : "gui_scripts", e.Groups[1].Value, e.Groups[2].Value));
            }
            if (files.Text(root + "setup.cfg") is { } cfg && Regex.Match(cfg, @"(?ms)^\[options\.entry_points\]\s*$(.*?)(?=^\[|\z)") is { Success: true } cfgEntries)
                entries.AddRange(EntryPoints("[x]\n" + cfgEntries.Groups[1].Value.Replace("\n    ", "\n")).Select(e => e with { Kind = "entry point" }));
        }
        // import-time code: package __init__ modules (and the rest within a bound)
        // tests, examples and docs ship in sdists but are not imported
        foreach (var source in files.Paths.Where(p => p.EndsWith(".py", StringComparison.Ordinal) && !p.EndsWith("setup.py", StringComparison.Ordinal) && !NotImported.IsMatch(p))
                     .OrderBy(p => p.EndsWith("__init__.py", StringComparison.Ordinal) ? 0 : 1).ThenBy(p => p.Count(c => c == '/')).Take(MaxScannedSources))
            if (files.Text(source) is { } code)
                findings.AddRange(Scan(source, code, install: false, ct, entry: source.EndsWith("__init__.py", StringComparison.Ordinal))
                    .Where(f => f.Level == "noteworthy" || f.Category is "transformed code" or "credentials"));
        // dependencies that together make a credential stealer: browser cookies, Discord webhooks, Roblox sessions
        var requires = string.Join("\n", files.Paths.Where(p => p.EndsWith("/setup.py", StringComparison.Ordinal) || p == "setup.py" || p.EndsWith("/PKG-INFO", StringComparison.Ordinal)
                                                              || p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal) || p.EndsWith("/requires.txt", StringComparison.Ordinal))
            .Select(p => files.Text(p) ?? ""));
        var kit = StealerKit.Matches(requires).Select(m => m.Value.ToLowerInvariant().Replace('-', '_')).Distinct().ToList();
        if (kit.Count >= 2) findings.Add(new PackageFinding("noteworthy", "credentials", $"depends on {string.Join(", ", kit)}: browser cookie, Discord webhook and Roblox session libraries together"));
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        if (name != null && CloseTo(name, PopularNames.PyPI) is { } popular)
            findings.Add(new PackageFinding(scripts.Any(s => s.AtInstall) ? "noteworthy" : "review", "name", $"the name '{name}' is close to the popular package '{popular}'"));
        return new PackageReport(ecosystem, name, version)
        {
            Publisher = author, Description = Clip(summary), Scripts = scripts, EntryPoints = entries, Dependencies = deps,
            Binaries = binaries.Count > 0 ? binaries : null, Record = record, Findings = findings, Notes = notes,
        };
    }

    /// <summary>Core metadata (METADATA / PKG-INFO): name, version, summary, author and the count of Requires-Dist.</summary>
    private static (string?, string?, string?, string?, int) Metadata(string? text)
    {
        if (text == null) return (null, null, null, null, 0);
        string? Header(string key) => Regex.Match(text, $@"(?m)^{key}:\s*(.+?)\s*$") is { Success: true } m ? m.Groups[1].Value : null;
        int deps = Regex.Count(text, @"(?m)^Requires-Dist:");
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
        if (differ > 0) findings.Add(new PackageFinding("noteworthy", "record", $"{differ} file(s) differ from their RECORD hash: {string.Join(", ", differing.Take(5))}", differing[0]));
        if (unlisted.Count > 0) findings.Add(new PackageFinding("review", "record", $"{unlisted.Count} file(s) not listed in RECORD: {string.Join(", ", unlisted.Take(5))}", unlisted[0]));
        return $"{match} match, {differ} differ, {unlisted.Count} not listed";
    }
}
