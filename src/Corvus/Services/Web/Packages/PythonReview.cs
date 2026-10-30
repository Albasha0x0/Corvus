using System.IO.Compression;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core.Models;
using Corvus.Core.Python;

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

    private static IEnumerable<string> ImportTimeSources(PackageFiles files) =>
        files.Paths.Where(p => p.EndsWith(".py", StringComparison.Ordinal) && !p.EndsWith("setup.py", StringComparison.Ordinal) && !NotImported.IsMatch(p))
            .OrderBy(p => p.EndsWith("__init__.py", StringComparison.Ordinal) ? 0 : 1).ThenBy(p => p.Count(c => c == '/'));

    private static readonly Regex CredentialLibraries = new(@"(?i)\b(?:browser[_-]cookie3|discord[_-]?webhook|robloxpy|discord_webhook)\b", RegexOptions.NonBacktracking);

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
            foreach (var file in new[] { "setup.py", "setup.cfg", "pyproject.toml", "requirements.txt" }) manifests.Add((root + file, files.Text(root + file)));
            foreach (var eggInfo in files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && Regex.IsMatch(p[root.Length..], @"^[^/]+\.egg-info/requires\.txt$", RegexOptions.NonBacktracking)).Take(4))
                manifests.Add((eggInfo, files.Text(eggInfo)));
            if (files.Text(root + "setup.py") is { } setup)
            {
                // pip runs setup.py to build an sdist, so its module-level code runs at install.
                scripts.Add(new PackageScript("setup.py", "python setup.py (run by pip to build the package)", true));
                if (Regex.IsMatch(setup, @"\bcmdclass\s*=|class\s+\w+\s*\(\s*(?:_?install|develop|egg_info|build_py|build_ext|sdist|bdist_\w+)\s*\)", RegexOptions.NonBacktracking))
                    findings.Add(new PackageFinding("package/setup-cmdclass", "review", "install script", "setup.py replaces a setuptools command (cmdclass): its code runs while installing", root + "setup.py"));
                var (joined, chain) = SetupCode(files, root, setup);
                findings.AddRange(Scan(root + "setup.py", joined, install: true, ct, notRead: files.NotRead)
                    .Select(f => chain == null ? f : f with { Detail = $"{f.Detail} (install code {chain})" }));
                if (AbsentImportCall(files, root, setup) is { } absent) findings.Add(absent);
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
        List<string> sources = [.. ImportTimeSources(files)];
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
        if (DisguisedBinary(files) is { } disguised) findings.Add(disguised);
        // Cookie, webhook and session libraries together mark a credential collector.
        var requires = string.Join("\n", files.Paths.Where(p => p.EndsWith("/setup.py", StringComparison.Ordinal) || p == "setup.py" || p.EndsWith("/PKG-INFO", StringComparison.Ordinal)
                                                              || p.EndsWith(".dist-info/METADATA", StringComparison.Ordinal) || p.EndsWith("/requires.txt", StringComparison.Ordinal))
            .Select(p => files.Text(p) ?? ""));
        var kit = CredentialLibraries.Matches(requires).Select(m => m.Value.ToLowerInvariant().Replace('-', '_')).Distinct().ToList();
        if (kit.Count >= 2) findings.Add(new PackageFinding("package/credential-collection-dependencies", "noteworthy", "credentials", $"depends on {string.Join(", ", kit)}: browser cookie, chat webhook and session libraries together"));
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
        findings.AddRange(PickleCode(files, distInfo == null ? moduleRoot + "setup.py" : null, notes, ct));
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

    // A bytewise XOR: bytes(b ^ k for b in d), bytearray(...), ord(c) ^ k,
    // buf[i] ^= k or lambda b: b ^ k.
    private static readonly Regex ByteXor = R(@"\b(?:bytes|bytearray)\s*\(\s*\[?\s*\w+\s*\^\s*\w+\s+for\s|\bord\s*\(\s*\w+\s*\)\s*\^|\w+\s*\[\s*\w+\s*\]\s*\^=|lambda\s+\w+\s*:\s*\w+\s*\^");
    private static readonly Regex BinaryWrite = R(@"\bopen\s*\([^\n]{0,200}['""][wa]b\+?['""]|\.write_bytes\s*\(");

    private static readonly (string Format, byte[] Magic)[] HeaderMagics =
    [
        ("ELF", [0x7F, (byte)'E', (byte)'L', (byte)'F']),
        ("Mach-O", [0xFE, 0xED, 0xFA, 0xCE]), ("Mach-O", [0xFE, 0xED, 0xFA, 0xCF]),
        ("Mach-O", [0xCE, 0xFA, 0xED, 0xFE]), ("Mach-O", [0xCF, 0xFA, 0xED, 0xFE]),
    ];

    /// <summary>The format and key when <paramref name="b"/> starts with a PE, ELF or Mach-O header XORed with one nonzero byte; null otherwise.</summary>
    internal static (string Format, byte Key)? XorExecutable(ReadOnlySpan<byte> b)
    {
        if (b.Length < 64) return null;
        static bool Starts(ReadOnlySpan<byte> at, ReadOnlySpan<byte> magic, byte key)
        {
            for (int i = 0; i < magic.Length; i++)
                if ((at[i] ^ key) != magic[i]) return false;
            return true;
        }
        byte k = (byte)(b[0] ^ 'M');
        // A PE image is MZ plus the PE signature where e_lfanew points.
        if (k != 0 && Starts(b, "MZ"u8, k))
        {
            long pe = BinaryPrimitives.ReadUInt32LittleEndian(b[0x3C..]) ^ (k * 0x01010101u);
            if (pe >= 64 && pe <= b.Length - 4 && Starts(b[(int)pe..], "PE\0\0"u8, k)) return ("PE", k);
        }
        foreach (var (format, magic) in HeaderMagics)
        {
            k = (byte)(b[0] ^ magic[0]);
            if (k != 0 && Starts(b, magic, k)) return (format, k);
        }
        return null;
    }

    /// <summary>The disguised-binary finding for the first .py file that is not UTF-8 and decodes to an executable under a one-byte XOR key; null when none.</summary>
    private static PackageFinding? DisguisedBinary(PackageFiles files)
    {
        var strict = new UTF8Encoding(false, throwOnInvalidBytes: true);
        foreach (var path in files.Paths.Where(p => p.EndsWith(".py", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            if (files.Bytes(path) is not { } b || XorExecutable(b) is not ({ } format, var key)) continue;
            try { strict.GetCharCount(b); continue; }
            catch (DecoderFallbackException) { }
            var writer = files.Paths.Where(p => p.EndsWith(".py", StringComparison.Ordinal) && p != path).Order(StringComparer.Ordinal)
                .FirstOrDefault(p => files.Text(p) is { } code && ByteXor.IsMatch(code) && BinaryWrite.IsMatch(code));
            var detail = $"{path} is a {format} image XORed with the key 0x{key:X2}";
            return new PackageFinding("package/disguised-binary", writer != null ? "noteworthy" : "review", "binary",
                writer != null ? $"{detail}; {writer} XORs file bytes and writes the result" : detail, path);
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

    /// <summary>
    /// setup.py joined with the package's own modules it imports, directly or
    /// through other modules (pip runs them too), within the reach budget.
    /// </summary>
    private static (string Code, string? Chain) SetupCode(PackageFiles files, string root, string setup) =>
        Reach(files, root + "setup.py", setup, (_, code) => LocalImports(files, root, code));

    /// <summary>
    /// The package's own module files an import line names: the module, its
    /// package __init__ and each imported submodule.
    /// </summary>
    private static IEnumerable<string> LocalImports(PackageFiles files, string root, string code)
    {
        foreach (Match m in LocalImport.Matches(code))
        {
            var module = (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[3].Value).Replace('.', '/');
            var names = m.Groups[2].Success ? m.Groups[2].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) : [];
            foreach (var path in names.Select(n => $"{root}{module}/{n}.py").Concat([$"{root}{module}.py", $"{root}{module}/__init__.py"]))
                if (files.Has(path)) yield return path;
        }
    }

    private static readonly Regex TopLevelCall = R(@"(?m)^([A-Za-z_]\w*)(?:\.\w+)*[ \t]*\(");
    // Column-0 imports: from-import members, bare or parenthesized, or an
    // import with its alias.
    private static readonly Regex SetupImport = R(@"(?m)^(?:from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*|[\w, \t]+)|import[ \t]+([\w.]+)(?:[ \t]+as[ \t]+(\w+))?)");
    // Requirement lists in setup.py and pyproject.toml, and the
    // indented setup_requires entry in setup.cfg.
    private static readonly Regex BuildRequires = R(@"requires[ \t]*=[ \t]*\[[^\]]*\]|(?m)^setup_requires[ \t]*=[^\n]*(?:\n[ \t]+[^\n]*)*");
    private static readonly Regex RequirementName = R(@"^[ \t]*([A-Za-z0-9][\w.-]*)");
    private static readonly HashSet<string> SetupModules = new(StringComparer.Ordinal) { "setuptools", "pkg_resources", "_distutils_hack" };
    // Import names whose normalized distribution name differs.
    private static readonly Dictionary<string, string> Distribution = new(StringComparer.Ordinal)
    {
        ["skbuild"] = "scikit_build", ["grpc_tools"] = "grpcio_tools", ["google"] = "protobuf", ["yaml"] = "pyyaml", ["pil"] = "pillow",
    };

    /// <summary>The setup-absent-import finding when setup.py calls, at module level, a name it imports from a top-level module the archive does not hold; null otherwise or when the file list is partial.</summary>
    private static PackageFinding? AbsentImportCall(PackageFiles files, string root, string setup)
    {
        if (files.Unlisted > 0) return null;
        var declared = new[] { "setup.py", "setup.cfg", "pyproject.toml" }
            .SelectMany(f => BuildRequires.Matches(files.Text(root + f) ?? ""))
            .SelectMany(m => m.Value[(m.Value.IndexOf('=') + 1)..].Split((char[])['"', '\'', ',', '[', '\n', '\r']))
            .Select(t => RequirementName.Match(t)).Where(n => n.Success)
            .Select(n => n.Groups[1].Value.ToLowerInvariant().Replace('-', '_').Replace('.', '_')).ToHashSet(StringComparer.Ordinal);
        var bindings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match m in SetupImport.Matches(setup))
        {
            var module = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[3].Value;
            var top = module.Split('.')[0];
            var name = top.ToLowerInvariant();
            if (top.Length == 0 || PyStdlib.Contains(top) || SetupModules.Contains(top) || declared.Contains(Distribution.GetValueOrDefault(name, name))
                || Ships(files, root, top)) continue;
            if (!m.Groups[2].Success) bindings.TryAdd(m.Groups[4].Success ? m.Groups[4].Value : top, module);
            else
                foreach (var member in m.Groups[2].Value.TrimStart('(').Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                    bindings.TryAdd(member.Split((char[])[' ', '\t', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries)[^1], module);
        }
        var call = TopLevelCall.Matches(setup).FirstOrDefault(c => bindings.ContainsKey(c.Groups[1].Value));
        return call == null ? null : new PackageFinding("package/setup-absent-import", "noteworthy", "install script",
            $"setup.py calls {Clip(call.Value.TrimEnd('(', ' ', '\t'), 80)} from {bindings[call.Groups[1].Value]}, a module the archive does not hold", root + "setup.py");
    }

    /// <summary>True when <paramref name="root"/> or its src/ folder holds <paramref name="top"/>.py, a <paramref name="top"/>/ package or a compiled <paramref name="top"/> extension.</summary>
    private static bool Ships(PackageFiles files, string root, string top) =>
        files.Paths.Any(p => ((string[])[root, root + "src/"]).Any(d => p.StartsWith(d, StringComparison.Ordinal) && p[d.Length..] is var rest
            && (rest.StartsWith(top + "/", StringComparison.Ordinal) || rest == top + ".py"
                || (rest.StartsWith(top + ".", StringComparison.Ordinal) && !rest.Contains('/') && (rest.EndsWith(".so", StringComparison.Ordinal) || rest.EndsWith(".pyd", StringComparison.Ordinal))))));

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

    // An import at module level, in a top-level try block included.
    private static readonly Regex SetupModuleImport = R(@"(?m)^(?:try:[ \t]*\r?\n)?[ \t]{0,4}(?:import[ \t]+(?<m>[A-Za-z_][\w.]*)|from[ \t]+(?<m>[A-Za-z_][\w.]*)[ \t]+import\b)");

    /// <summary>True when the line holding <paramref name="index"/> starts without indentation.</summary>
    private static bool TopLevel(string text, int index)
    {
        var start = text.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        return start < text.Length && text[start] is not (' ' or '\t');
    }
    private static readonly Regex UnsafeLoad = R(@"\btorch\.load\([^\r\n]*\bweights_only\s*=\s*False|\bpickle\.load\(\s*open\([^)\r\n]*(?:__file__|\.(?:pt|pth|pkl|ckpt)['""])");

    private static readonly Regex ModelLiteral = R(@"['""]([^'""\r\n]*\.(?:pt|pth|pkl|ckpt))['""]");

    private static string BaseName(string path) => path[(path.LastIndexOfAny(['/', '\\']) + 1)..];

    /// <summary>Model pickles that import code-running globals, and unsafe loads in setup.py or import-time code; empty when none.</summary>
    private static List<PackageFinding> PickleCode(PackageFiles files, string? setup, List<string> notes, CancellationToken ct)
    {
        var findings = new List<PackageFinding>();
        var models = new List<(string Path, List<string> Code)>();
        foreach (var path in files.Paths.Where(ModelRisk.IsModelFile).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (files.Bytes(path) is not { } bytes)
            {
                notes.Add($"{path}: model file not read; its pickle is not checked");
                continue;
            }
            var scan = ModelRisk.Scan(path, bytes, ct);
            if (scan.NotRead != null) notes.Add($"{path}: {scan.NotRead}; not checked");
            if (scan.Code.Count > 0) models.Add((path, [.. scan.Code]));
            else if (scan.Other.Count > 0)
                findings.Add(new PackageFinding("package/pickle-code", "review", "binary",
                    $"{path}: the pickle imports {string.Join(", ", scan.Other.Take(5))}, outside torch.load(weights_only=True)'s allowlist", path));
            foreach (var hit in scan.Hits)
                findings.Add(new PackageFinding("package/model-code", hit.Level, "binary", $"{path}: {hit.Detail}", path));
        }
        var loads = new List<(string Path, bool Install, HashSet<string> Names)>();
        // Setup.py first, then the import-time scan's sources in its order; that
        // scan names the sources past the cap in the not-read list.
        var sources = ImportTimeSources(files).Take(MaxScannedSources);
        if (setup != null) sources = sources.Prepend(setup);
        // Packages setup.py imports at module level run their __init__ during the install.
        var setupImports = setup != null && files.Text(setup) is { } setupCode
            ? SetupModuleImport.Matches(setupCode).Select(i => "/" + i.Groups["m"].Value.Replace('.', '/') + "/__init__.py").ToList() : [];
        foreach (var source in sources)
        {
            if (files.Text(source) is not { } code || UnsafeLoad.Match(code) is not { Success: true } m) continue;
            var named = ModelLiteral.Matches(code).Select(l => BaseName(l.Groups[1].Value)).ToHashSet(StringComparer.Ordinal);
            var unshipped = named.Where(n => !files.Paths.Any(p => BaseName(p) == n)).ToList();
            foreach (var name in unshipped) notes.Add($"{source} names {name}, which the package does not ship; not checked");
            bool install = source == setup;
            // A load alone is review; setup.py naming a model that runs code or
            // that the package does not ship is noteworthy.
            bool noteworthy = install && (unshipped.Count > 0 || models.Any(x => named.Contains(BaseName(x.Path))));
            bool imported = !install && setupImports.Any(i => source.EndsWith(i, StringComparison.Ordinal))
                && UnsafeLoad.Matches(code).Any(u => TopLevel(code, u.Index) && !InComment(code, u.Index));
            loads.Add((source, install, named));
            findings.Add(new PackageFinding("package/pickle-load", noteworthy || imported ? "noteworthy" : "review", "binary",
                $"{source} loads a pickle with code allowed: {Clip(m.Value, 160)}" + (install ? ", while installing" : imported ? ", at module level of a package setup.py imports" : ""), source));
        }
        foreach (var (path, code) in models)
        {
            var loader = loads.FirstOrDefault(l => l.Names.Contains(BaseName(path)));
            var detail = $"{path}: the pickle imports {string.Join(", ", code.Take(5))}, which runs when it is loaded";
            if (loader.Path != null) detail += $"; {loader.Path} loads it with code allowed" + (loader.Install ? ", while installing" : "");
            // Test and example pickles are not loaded unless a loader names them.
            var level = loader.Path == null && NotImported.IsMatch(path) ? "review" : "noteworthy";
            findings.Add(new PackageFinding("package/pickle-code", level, "binary", detail, path));
        }
        return findings;
    }
}
