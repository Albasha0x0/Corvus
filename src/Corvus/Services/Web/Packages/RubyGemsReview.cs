using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    private const int MaxGemExtensions = 20;

    /// <summary>The gemspec of a .gem or of a source folder's root, or null when the package holds none.</summary>
    private static string? GemSpecPath(PackageFiles files) =>
        files.Container == "gem" ? PackageFiles.GemSpec
            : files.Paths.Where(p => p.EndsWith(".gemspec", StringComparison.Ordinal) && p.Count(c => c == '/') <= (files.Container == "folder" ? 0 : 1))
                .OrderBy(p => p.Length).ThenBy(p => p, StringComparer.Ordinal).FirstOrDefault();

    private static PackageReport? RubyGems(PackageFiles files, CancellationToken ct)
    {
        var specPath = GemSpecPath(files)!;
        var notes = new List<string>();
        var findings = new List<PackageFinding>();
        var scripts = new List<PackageScript>();
        var entries = new List<PackageEntryPoint>();
        var root = files.Container == "gem" ? PackageFiles.GemData : Folder(specPath);
        if (files.Text(specPath) is not { } spec)
        {
            notes.Add(files.Has(specPath) ? $"{specPath} was not read (see partial): name, extensions and dependencies unknown"
                : $"the gem holds no {specPath}: name, extensions and dependencies unknown");
            return new PackageReport("rubygems", null, null) { Notes = notes };
        }
        // A .gem carries the gemspec as YAML; a source folder carries it as Ruby.
        var gem = files.Container == "gem" ? YamlGemSpec(spec) : RubyGemSpec(spec, notes);
        foreach (var exe in gem.Executables) entries.Add(new PackageEntryPoint("executable", exe, gem.BinDir + "/" + exe));
        var extensions = gem.Extensions.SelectMany(e => e.Contains('*') || e.Contains('?') ? Glob(files, root, e) : [e]).Distinct().ToList();
        if (extensions.Count > MaxGemExtensions)
            files.NotRead.AddRange(extensions.Skip(MaxGemExtensions).Select(e => $"{root}{e} (extension past the first {MaxGemExtensions})"));
        foreach (var ext in extensions.Take(MaxGemExtensions))
        {
            var target = Resolve(root, ext);
            // RubyGems builds each extension when the gem is installed.
            scripts.Add(new PackageScript(ext, ExtensionBuild(ext), true));
            findings.Add(new PackageFinding("package/install-script", "info", "install script", $"extension {ext}: {ExtensionBuild(ext)}", specPath));
            if (files.Text(target) is { } code) findings.AddRange(Scan(target, RubyInstallCode(files, target, code), install: true, ct));
            else if (files.Has(target)) notes.Add($"extension {ext} was not read (see partial)");
            else notes.Add($"extension {ext}, which the package does not hold");
        }
        findings.AddRange(ScanLoaded(files, root, entries.Select(e => Resolve(root, e.Target!)), ct));
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        return new PackageReport("rubygems", gem.Name, gem.Version)
        {
            Publisher = gem.Author, Description = Clip(gem.Summary), Scripts = scripts, EntryPoints = entries, Dependencies = gem.Dependencies,
            Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }

    private sealed record GemSpec(string? Name, string? Version, string? Summary, string? Author, int Dependencies, string BinDir, List<string> Executables, List<string> Extensions);

    private static string ExtensionBuild(string ext) => Path.GetFileName(ext).ToLowerInvariant() switch
    {
        "extconf.rb" => "ruby extconf.rb, then make",
        "cmakelists.txt" => "cmake, then make",
        "cargo.toml" => "cargo build",
        "configure" => "./configure, then make",
        _ when ext.EndsWith("Rakefile", StringComparison.OrdinalIgnoreCase) || ext.EndsWith(".rb", StringComparison.Ordinal) => "rake",
        _ => "built by RubyGems",
    };

    /// <summary>The gemspec YAML in a .gem's metadata.gz: top-level scalars and lists, runtime dependencies counted.</summary>
    private static GemSpec YamlGemSpec(string yaml)
    {
        string? Scalar(string key) => Regex.Match(yaml, $@"(?m)^{key}:[ \t]*(.*?)[ \t]*$", RegexOptions.NonBacktracking) is { Success: true } m ? YamlValue(m.Groups[1].Value) : null;
        var version = Regex.Match(yaml, @"(?m)^version:[^\n]*\n[ \t]+version:[ \t]*(\S+)", RegexOptions.NonBacktracking) is { Success: true } v ? YamlValue(v.Groups[1].Value) : Scalar("version");
        int deps = Regex.Count(yaml, @"(?m)^[ \t]+type:[ \t]*:runtime[ \t\r]*$", RegexOptions.NonBacktracking);
        return new GemSpec(Scalar("name"), version, Scalar("summary"), YamlList(yaml, "authors").FirstOrDefault(), deps,
            Scalar("bindir") ?? "bin", YamlList(yaml, "executables"), YamlList(yaml, "extensions"));
    }

    // Block scalars (| or >) and empty values read as unknown.
    private static string? YamlValue(string raw)
    {
        raw = raw.Trim();
        if (raw.Length >= 2 && (raw[0] == '"' && raw[^1] == '"' || raw[0] == '\'' && raw[^1] == '\'')) raw = raw[1..^1];
        return raw.Length == 0 || raw[0] is '|' or '>' or '!' || raw is "[]" or "~" or "null" ? null : raw;
    }

    /// <summary>The items of a top-level YAML list: "key:" followed by "- item" lines, or "key: []".</summary>
    private static List<string> YamlList(string yaml, string key)
    {
        var block = Regex.Match(yaml, $@"(?m)^{key}:[ \t]*\r?\n((?:-[ \t][^\n]*\n?)*)", RegexOptions.NonBacktracking);
        return block.Success
            ? [.. block.Groups[1].Value.Split('\n').Where(l => l.StartsWith('-')).Select(l => YamlValue(l[1..])).OfType<string>()]
            : [];
    }

    private static readonly Regex RubyString = R(@"""([^""\n]*)""|'([^'\n]*)'");
    private static readonly Regex RubyWords = R(@"%[wWiI][\[({<]([^\])}>]*)[\])}>]");

    /// <summary>A Ruby gemspec read by pattern; extensions set by an expression it cannot read are named in <paramref name="notes"/>.</summary>
    private static GemSpec RubyGemSpec(string ruby, List<string> notes)
    {
        string? Field(string key) => Regex.Match(ruby, $@"\.{key}\s*=\s*(?:""([^""\n]*)""|'([^'\n]*)')", RegexOptions.NonBacktracking) is { Success: true } m
            ? m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value : null;
        List<string> List(string key)
        {
            var items = new List<string>();
            foreach (Match m in Regex.Matches(ruby, $@"\.{key}\s*(?:=|\+=|<<|\.push|\.concat)\s*([^\n]*)", RegexOptions.NonBacktracking))
            {
                var expr = m.Groups[1].Value;
                var found = RubyString.Matches(expr).Select(s => s.Groups[1].Success ? s.Groups[1].Value : s.Groups[2].Value)
                    .Concat(RubyWords.Matches(expr).SelectMany(w => w.Groups[1].Value.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries))).ToList();
                if (found.Count == 0) notes.Add($"{key} set by an expression not read: {Clip(expr.Trim(), 120)}");
                items.AddRange(found);
            }
            return items;
        }
        int deps = Regex.Count(ruby, @"\.add_(?:runtime_)?dependency\b", RegexOptions.NonBacktracking);
        var author = Field("author") ?? List("authors").FirstOrDefault();
        return new GemSpec(Field("name"), Field("version"), Field("summary"), author, deps, Field("bindir") ?? "bin", List("executables"), List("extensions"));
    }

    /// <summary>Files under <paramref name="root"/> matching a gemspec glob (* within a folder, ** across folders, ?).</summary>
    private static IEnumerable<string> Glob(PackageFiles files, string root, string pattern)
    {
        var regex = new Regex("^" + Regex.Escape(pattern).Replace(@"\*\*/", "(?:[^/]*/)*").Replace(@"\*", "[^/]*").Replace(@"\?", "[^/]") + "$", RegexOptions.NonBacktracking);
        return files.Paths.Where(p => p.StartsWith(root, StringComparison.Ordinal) && regex.IsMatch(p[root.Length..]))
            .Select(p => p[root.Length..]).Order(StringComparer.Ordinal);
    }

    private static readonly Regex RequireRelative = R(@"\brequire_relative\s*\(?\s*['""]([^'""\n]+)['""]");

    /// <summary>An extension's build file joined with the small files beside it that it loads by require_relative, up to eight.</summary>
    private static string RubyInstallCode(PackageFiles files, string target, string code)
    {
        var text = new System.Text.StringBuilder(code);
        var seen = new HashSet<string>(StringComparer.Ordinal) { target };
        foreach (Match m in RequireRelative.Matches(code))
        {
            var rel = m.Groups[1].Value;
            var path = Resolve(Folder(target), rel.EndsWith(".rb", StringComparison.Ordinal) ? rel : rel + ".rb");
            if (seen.Count < 8 && files.Size(path) <= 64 << 10 && seen.Add(path) && files.Text(path) is { } more) text.Append('\n').Append(more);
        }
        return text.ToString();
    }
}
