using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    /// <summary>Lifecycle scripts npm runs when the package is installed from a registry.</summary>
    private static readonly HashSet<string> NpmInstallScripts = new(StringComparer.Ordinal) { "preinstall", "install", "postinstall" };

    /// <summary>Scripts npm also runs on npm install inside a source folder or git checkout.</summary>
    private static readonly HashSet<string> NpmLocalInstallScripts = new(StringComparer.Ordinal) { "preprepare", "prepare", "postprepare" };

    /// <summary>Node built-in module names a registry package can also take.</summary>
    private static readonly HashSet<string> NodeBuiltins = new(StringComparer.Ordinal) { "child_process", "net", "http", "https", "fs", "path", "os", "crypto" };

    private static readonly Regex NetworkCommand = new(@"(?:^|[\s;&|(`'""])(?:[\w.-]*/)*(?:curl|wget|nc|ncat|nslookup|dig|Invoke-WebRequest|iwr)(?:\.exe)?\s", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    private static PackageReport? Npm(PackageFiles files, CancellationToken ct)
    {
        var manifestPath = Root(files, "package.json")!;
        var root = Folder(manifestPath);
        if (Json(files, manifestPath) is not { ValueKind: JsonValueKind.Object } pkg) return null;
        var name = Str(pkg, "name");
        var findings = new List<PackageFinding>();
        var notes = new List<string>();
        var scripts = new List<PackageScript>();
        bool source = files.Container is "folder" or "zip";
        if (pkg.TryGetProperty("scripts", out var s) && s.ValueKind == JsonValueKind.Object)
            foreach (var p in s.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.String)
                    scripts.Add(new PackageScript(p.Name, p.Value.GetString()!, NpmInstallScripts.Contains(p.Name) || source && NpmLocalInstallScripts.Contains(p.Name)));
        // node-gyp builds a binding.gyp at install even without an install script.
        bool gyp = files.Has(root + "binding.gyp") && !scripts.Any(x => x.Name is "install" or "preinstall");
        if (gyp) scripts.Add(new PackageScript("install", "node-gyp rebuild (binding.gyp)", true));
        foreach (var script in scripts.Where(x => x.AtInstall))
        {
            findings.Add(new PackageFinding("package/install-script", "review", "install script", $"{script.Name}: {Clip(script.Command)}", manifestPath));
            foreach (var f in Scan(manifestPath + "#scripts." + script.Name, script.Command, install: true, ct)) findings.Add(f);
            if (NetworkCommand.IsMatch(script.Command))
                findings.Add(new PackageFinding("package/install-network-tool", "noteworthy", "install script", $"{script.Name} runs a network tool: {Clip(script.Command, 160)}", manifestPath));
            // Reads the file a node, node --require or node -e "require(...)" command runs.
            foreach (var run in NodeTargets(script.Command).Concat(ShellTargets.Matches(script.Command).Select(m => m.Groups["t"].Value)).Distinct())
            {
                var target = Resolve(root, run);
                if (!files.Has(target) && files.Has(target + ".js")) target += ".js";
                if (files.Text(target) is { } code)
                {
                    var (joined, chain) = InstallCode(files, root, target, code);
                    findings.AddRange(Scan(target, joined, install: true, ct, notRead: files.NotRead)
                        .Select(f => chain == null ? f : f with { Detail = $"{f.Detail} (install code {chain})" }));
                }
                else if (files.Has(target) && files.Bytes(target) == null) notes.Add($"{script.Name} runs {run}, which was not read (see partial)");
                else notes.Add($"{script.Name} runs {run}, which the package does not hold");
            }
        }
        var entries = new List<PackageEntryPoint>();
        foreach (var key in new[] { "main", "module", "browser", "types" })
            if (Str(pkg, key) is { } target) entries.Add(new PackageEntryPoint(key, key, target));
        if (pkg.TryGetProperty("bin", out var bin))
        {
            if (bin.ValueKind == JsonValueKind.String) entries.Add(new PackageEntryPoint("bin", name ?? "bin", bin.GetString()));
            else if (bin.ValueKind == JsonValueKind.Object)
                foreach (var b in bin.EnumerateObject()) entries.Add(new PackageEntryPoint("bin", b.Name, b.Value.ValueKind == JsonValueKind.String ? b.Value.GetString() : null));
        }
        if (pkg.TryGetProperty("exports", out var exports))
        {
            if (exports.ValueKind == JsonValueKind.String) entries.Add(new PackageEntryPoint("exports", ".", exports.GetString()));
            else if (exports.ValueKind == JsonValueKind.Object)
                foreach (var e in exports.EnumerateObject().Take(50)) entries.Add(new PackageEntryPoint("exports", e.Name, Target(e.Value)));
        }
        // Loaded code: main and bin files, else index.js.
        var loaded = entries.Where(e => e.Kind is "main" or "bin" && e.Target != null).Take(10).Select(e => Resolve(root, e.Target!))
            .Select(t => files.Has(t) || !files.Has(t + ".js") ? t : t + ".js").ToList();
        if (!loaded.Any(files.Has)) loaded.Add(root + "index.js");
        findings.AddRange(ScanLoaded(files, root, loaded, ct));
        var binaries = Binaries(files);
        if (binaries.Count > 0) findings.Add(new PackageFinding("package/binary", "review", "binary", $"{binaries.Count} native or executable file(s): {string.Join(", ", binaries.Take(5))}", binaries[0]));
        if (name != null && CloseTo(name, PopularNames.Npm) is { } popular)
            findings.Add(new PackageFinding("package/close-name", scripts.Any(x => x.AtInstall) ? "noteworthy" : "review", "name", $"the name '{name}' is close to the popular package '{popular}'"));
        findings.AddRange(CommandNames(name, entries, scripts.Any(x => x.AtInstall), manifestPath));
        int deps = 0;
        var outside = new List<string>();
        var builtins = new HashSet<string>(StringComparer.Ordinal);
        var builtinElsewhere = false;
        var plain = false;
        bool self = false;
        var pinned = new List<string>();
        var aliases = new List<string>();
        foreach (var key in new[] { "dependencies", "optionalDependencies", "peerDependencies" })
            if (pkg.TryGetProperty(key, out var d) && d.ValueKind == JsonValueKind.Object)
                foreach (var dep in d.EnumerateObject())
                {
                    deps++;
                    if (NodeBuiltins.Contains(dep.Name))
                    {
                        builtins.Add(dep.Name);
                        if (dep.Value.ValueKind == JsonValueKind.String && dep.Value.GetString()!.Trim() is var spec
                            && (spec.StartsWith("npm:", StringComparison.OrdinalIgnoreCase) || (key != "peerDependencies" && NpmSource(spec) is not null)))
                            builtinElsewhere = true;
                    }
                    if (key != "peerDependencies" && dep.Name == name) self = true;
                    // npm installs peer dependencies from the registry, whatever their range says.
                    if (key != "peerDependencies" && deps <= MaxDependencies && dep.Value.ValueKind == JsonValueKind.String && NpmSource(dep.Value.GetString()!) is { } from)
                    {
                        outside.Add($"{dep.Name} ({from})");
                        plain |= PlainTransport(dep.Value.GetString()!);
                        if (key != "peerDependencies" && from.StartsWith("git", StringComparison.Ordinal) && CommitRef.IsMatch(dep.Value.GetString()!)) pinned.Add(dep.Name);
                    }
                    if (key != "peerDependencies" && dep.Value.ValueKind == JsonValueKind.String && SubstitutedAlias(dep.Name, dep.Value.GetString()!, name) is { } alias)
                        aliases.Add(alias);
                }
        // A fork pinned to one commit that no shipped code loads runs only
        // through npm's install of it.
        var unusedPin = pinned.Count > 0 && pinned.Any(p => !NamedByCode(files, root, manifestPath, p));
        if (outside.Count > 0)
            findings.Add(new PackageFinding("package/dependency-source", scripts.Any(x => x.AtInstall) || plain || unusedPin ? "noteworthy" : "review", "dependency",
                $"{outside.Count} dependenc{(outside.Count == 1 ? "y" : "ies")} from outside the registry: {string.Join(", ", outside.Take(5))}", manifestPath));
        // A bundler resolves a dependency of a built-in name in place of the built-in;
        // registry placeholders of these names are inert, so only other code is noteworthy.
        if (builtins.Count > 0)
            findings.Add(new PackageFinding("package/builtin-dependency", builtinElsewhere ? "noteworthy" : "review", "dependency",
                $"dependenc{(builtins.Count == 1 ? "y" : "ies")} named after a Node built-in module: {string.Join(", ", builtins.Take(5))}", manifestPath));
        if (CarrierEntry(files, loaded, pkg) is { } carrier)
            findings.Add(new PackageFinding("package/carrier", "noteworthy", "dependency",
                $"{carrier} holds no require, import or export and is the only code file; its dependencies are installed but never loaded", carrier));
        if (aliases.Count > 0)
            findings.Add(new PackageFinding("package/dependency-alias", "noteworthy", "dependency",
                $"installs another package under an unscoped name: {string.Join(", ", aliases.Take(5))}", manifestPath));
        findings.AddRange(LookalikeDependencies(files, root, pkg, name, scripts, entries, manifestPath));
        if (self) findings.Add(new PackageFinding("package/self-dependency", "review", "dependency", $"lists its own name '{name}' as a dependency", manifestPath));
        // A scope is owned by its publisher, so only an unscoped name can shadow a private one.
        if (name is { } n && !n.StartsWith('@') && HighVersion(Str(pkg, "version")) is { } high)
            findings.Add(new PackageFinding("package/high-version", "review", "version", $"version {high} has a major version of 99 or higher", manifestPath));
        return new PackageReport("npm", name, Str(pkg, "version"))
        {
            Publisher = Person(pkg, "author"), Description = Clip(Str(pkg, "description")), Scripts = scripts, EntryPoints = entries,
            Dependencies = deps, Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }

    /// <summary>The source kind and host of an npm dependency range fetched from outside the registry, else null.</summary>
    private static string? NpmSource(string range)
    {
        range = range.Trim();
        if (range.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) return "file";
        if (range.StartsWith("link:", StringComparison.OrdinalIgnoreCase)) return "link";
        if (GitHostShorthand.Match(range) is { Success: true } hosted)
            return "git, " + hosted.Groups[1].Value.ToLowerInvariant() switch { "gitlab" => "gitlab.com", "bitbucket" => "bitbucket.org", "gist" => "gist.github.com", _ => "github.com" };
        if (GitScp.Match(range) is { Success: true } scp) return $"git, {scp.Groups[1].Value.ToLowerInvariant()}";
        if (SourceUrl.Match(range) is { Success: true } url)
        {
            var (scheme, host, path) = (url.Groups["scheme"].Value.ToLowerInvariant(), url.Groups["host"].Value.ToLowerInvariant(), url.Groups["path"].Value);
            if (scheme.StartsWith("git", StringComparison.Ordinal) || scheme == "ssh") return $"git, {host}";
            if (scheme is "http" or "https") return $"{(path.EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? "git" : "tarball")}, {host}";
        }
        return GitHubShorthand.IsMatch(range) ? "git, github.com" : null;
    }

    /// <summary>The loaded entry when it is the only small code file, loads nothing and runtime dependencies are declared; else null.</summary>
    private static string? CarrierEntry(PackageFiles files, List<string> loaded, JsonElement pkg)
    {
        if (!pkg.TryGetProperty("dependencies", out var d) || d.ValueKind != JsonValueKind.Object || !d.EnumerateObject().Any()) return null;
        var code = files.Paths.Where(p => NodeCodeFile.IsMatch(p)).Take(2).ToList();
        // A bin script without an extension is code too, so the entry must be the only loaded file.
        if (code.Count != 1 || files.Size(code[0]) > 200 || !loaded.Where(files.Has).Distinct().SequenceEqual([code[0]])) return null;
        return files.Text(code[0]) is { } text && !ModuleKeyword.IsMatch(text) ? code[0] : null;
    }

    private static readonly Regex NodeCodeFile = R(@"\.(?:c|m)?[jt]sx?$");
    private static readonly Regex CommitRef = R(@"#[0-9a-fA-F]{7,40}$");

    /// <summary>"name (npm:@scope/target@range)" when an unscoped dependency installs a scoped package of the
    /// package's own scope or at a floating range (latest, *, none); else null.</summary>
    private static string? SubstitutedAlias(string dependency, string range, string? name)
    {
        range = range.Trim();
        if (dependency.StartsWith('@') || !range.StartsWith("npm:@", StringComparison.OrdinalIgnoreCase)) return null;
        var target = range[4..];
        var at = target.IndexOf('@', 1);
        var (module, version) = at < 0 ? (target, "") : (target[..at], target[(at + 1)..]);
        var slash = module.IndexOf('/');
        if (slash < 2) return null;
        var own = name is { } n && n.StartsWith('@') && n.IndexOf('/') is > 1 and var i && string.Equals(n[..i], module[..slash], StringComparison.OrdinalIgnoreCase);
        return own || version is "" or "latest" or "*" ? $"{dependency} ({range})" : null;
    }

    /// <summary>True when a shipped source file under <paramref name="root"/> names <paramref name="module"/> in quotes,
    /// when one was not read, or when none ships; false when every read file leaves it unnamed.</summary>
    private static bool NamedByCode(PackageFiles files, string root, string manifestPath, string module)
    {
        var read = 0;
        foreach (var path in files.Paths.Where(p => p != manifestPath && p.StartsWith(root, StringComparison.Ordinal)
            && ScannedSources.Any(e => p.EndsWith(e, StringComparison.OrdinalIgnoreCase))))
        {
            if (files.Text(path) is not { } text || NamesModule(text, module)) return true;
            read++;
        }
        return read == 0;
    }
    private static readonly Regex ModuleKeyword = R(@"\b(?:require|import|exports?)\b");
    /// <summary>True for a range fetched over http, git+http or git://, whose code is not protected in transit; false for any other range.</summary>
    private static bool PlainTransport(string range) =>
        SourceUrl.Match(range.Trim()) is { Success: true } url && url.Groups["scheme"].Value.ToLowerInvariant() is "http" or "git+http" or "git";

    private const int MaxDependencies = 1000;

    /// <summary>One finding naming the unscoped runtime dependencies that hold a popular name as whole tokens and that
    /// no shipped file or script names: noteworthy when one is from outside the registry, spells the popular name once
    /// filler words are removed, or the package runs at install, else review; empty when none, when the package ships
    /// no code file, or when a shipped code file was not read. Bundler output clears only the names it holds.</summary>
    private static IEnumerable<PackageFinding> LookalikeDependencies(PackageFiles files, string root, JsonElement pkg, string? name,
        List<PackageScript> scripts, List<PackageEntryPoint> entries, string manifestPath)
    {
        if (!pkg.TryGetProperty("dependencies", out var d) || d.ValueKind != JsonValueKind.Object) yield break;
        // A package named after a popular one may depend on its own family.
        var own = name == null ? "" : Normalize(name[(name.IndexOf('/') + 1)..]);
        var named = new Dictionary<string, string>(StringComparer.Ordinal);
        var outside = new HashSet<string>(StringComparer.Ordinal);
        var filler = new HashSet<string>(StringComparer.Ordinal);
        foreach (var dep in d.EnumerateObject().Take(MaxDependencies))
        {
            if (dep.Name.StartsWith('@') || PopularNames.Npm.Contains(dep.Name) || PopularRun(dep.Name, own) is not { } popular) continue;
            named.TryAdd(dep.Name, popular);
            if (FillerSpelling(dep.Name) is { } spelled && spelled == popular) filler.Add(dep.Name);
            if (dep.Value.ValueKind == JsonValueKind.String && NpmSource(dep.Value.GetString()!) != null) outside.Add(dep.Name);
        }
        foreach (var script in scripts) named.Keys.Where(k => script.Command.Contains(k, StringComparison.Ordinal)).ToList().ForEach(k => named.Remove(k));
        var entryFiles = entries.Where(e => e.Kind is "main" or "bin" or "exports" && e.Target != null).Select(e => Resolve(root, e.Target!)).ToHashSet(StringComparer.Ordinal);
        var code = files.Paths.Where(p => p != manifestPath && p.StartsWith(root, StringComparison.Ordinal)
            && (entryFiles.Contains(p) || ScannedSources.Any(e => p.EndsWith(e, StringComparison.OrdinalIgnoreCase)))).ToList();
        if (named.Count == 0 || code.Count == 0) yield break;
        foreach (var path in code)
        {
            if (files.Text(path) is not { } text) yield break;
            named.Keys.Where(k => NamesModule(text, k)).ToList().ForEach(k => named.Remove(k));
            if (named.Count == 0) yield break;
        }
        var level = scripts.Any(x => x.AtInstall) || named.Keys.Any(k => outside.Contains(k) || filler.Contains(k)) ? "noteworthy" : "review";
        yield return new PackageFinding("package/dependency-lookalike", level, "dependency",
            $"{named.Count} dependenc{(named.Count == 1 ? "y" : "ies")} that no shipped code names, under a popular name with affixes: {string.Join(", ", named.Take(5).Select(n => $"{n.Key} ({n.Value})"))}", manifestPath);
    }

    /// <summary>The popular name that the tokens of <paramref name="name"/> spell once one or more filler words are
    /// removed; null when no filler word is present or the rest spells no popular name.</summary>
    private static string? FillerSpelling(string name)
    {
        var t = name.ToLowerInvariant().Split(['-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        var rest = t.Where(x => !FillerWords.Contains(x)).ToArray();
        return rest.Length < t.Length && rest.Length > 0 && PopularBare.TryGetValue(string.Concat(rest), out var p) ? p : null;
    }

    private static readonly HashSet<string> FillerWords = new(["easy", "simple", "lite", "fast", "my", "the", "new", "pro", "plus", "better", "smart"], StringComparer.Ordinal);

    /// <summary>The popular name that a run of whole tokens of <paramref name="name"/> spells, outside
    /// <paramref name="own"/>; null when none.</summary>
    private static string? PopularRun(string name, string own)
    {
        var t = name.ToLowerInvariant().Split(['-', '_', '.'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < t.Length; i++)
        {
            var run = "";
            for (int j = i; j < t.Length && run.Length < 64; j++)
                if (PopularBare.TryGetValue(run += t[j], out var p) && !own.Contains(run, StringComparison.Ordinal)) return p;
        }
        return null;
    }

    // Short names such as ws or pg sit inside too many ordinary names.
    private static readonly Dictionary<string, string> PopularBare = PopularNames.Npm.Where(p => !p.StartsWith('@'))
        .GroupBy(Normalize).Where(g => g.Key.Length >= 4).ToDictionary(g => g.Key, g => g.Min(StringComparer.Ordinal)!, StringComparer.Ordinal);

    private static readonly string[] ScannedSources =
        [".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".cts", ".mts", ".vue", ".svelte", ".json", ".css", ".scss", ".less", ".gyp"];

    /// <summary>True when <paramref name="text"/> holds <paramref name="module"/> in quotes, alone or before a subpath.</summary>
    private static bool NamesModule(string text, string module)
    {
        foreach (var quote in "'\"`")
        {
            var needle = quote + module;
            for (int i = text.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = text.IndexOf(needle, i + 1, StringComparison.Ordinal))
                if (i + needle.Length < text.Length && (text[i + needle.Length] == quote || text[i + needle.Length] == '/')) return true;
        }
        return false;
    }

    private static readonly Regex GitHostShorthand = R(@"^(?i)(github|gitlab|bitbucket|gist):");
    private static readonly Regex SourceUrl = R(@"^(?<scheme>[A-Za-z][\w+.-]*)://(?:[^@/\s]*@)?(?<host>[^/:#?\s]+)(?<path>[^#?\s]*)");
    private static readonly Regex GitScp = R(@"^(?:git\+)?[\w.-]+@([\w.-]+):");
    // npm reads user/repo, with an optional #ref, as a GitHub repository.
    private static readonly Regex GitHubShorthand = R(@"^[\w.-]+/[\w.-]+(?:#\S*)?$");

    private static IEnumerable<string> NodeTargets(string command)
    {
        var runs = NodeScript.Matches(command).Select(m => m.Groups["t"].Value)
            .Concat(NodeRequire.Matches(command).Select(m => m.Groups["t"].Value));
        if (NodeEval.IsMatch(command))
            runs = runs.Concat(RequireLiteral.Matches(command).Select(m => m.Groups[1].Value));
        return runs.Distinct();
    }

    // A shell or batch file the command runs: by an interpreter, a ./ path, or its name.
    private static readonly Regex ShellTargets = R(@"(?:^|[\s;&|(])(?:(?:ba|z)?sh\s+|cmd(?:\.exe)?\s+/c\s+|call\s+)?(?<t>(?:\./)?[\w./-]+\.(?:sh|bat|cmd))\b");

    // NonBacktracking takes no backreference, so each quote form is its own branch.
    private static readonly Regex NodeScript = R(@"\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*(?:'(?<t>[^\s'""&|;]+\.(?:c|m)?js)'|""(?<t>[^\s'""&|;]+\.(?:c|m)?js)""|(?<t>[^\s'""&|;]+\.(?:c|m)?js))");
    private static readonly Regex NodeRequire = R(@"\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*?(?:-r|--require)[\s=]+(?:'(?<t>\.{1,2}/[^\s'""&|;]+)'|""(?<t>\.{1,2}/[^\s'""&|;]+)""|(?<t>\.{1,2}/[^\s'""&|;]+))");
    private static readonly Regex NodeEval = R(@"\bnode(?:\.exe)?\s+(?:-e|--eval|-p|--print)\b");
    private static readonly Regex RequireLiteral = R(@"\brequire\(\s*\\?['""`](\.{1,2}/[^'""`\\]+)\\?['""`]\s*\)");

    /// <summary>
    /// Install-time code joined with the package files it loads by path or by a
    /// module under node_modules, within the reach budget.
    /// </summary>
    private static (string Code, string? Chain) InstallCode(PackageFiles files, string root, string target, string code) =>
        Reach(files, target, code, (path, text) => LoadedModules(files, root, path, text));

    /// <summary>
    /// The package files a script loads: literal paths beside it or at the
    /// root, and bare module names under a node_modules folder.
    /// </summary>
    private static IEnumerable<string> LoadedModules(PackageFiles files, string root, string path, string code)
    {
        foreach (Match m in LocalScript.Matches(code))
        {
            var rel = m.Groups[1].Value;
            if (new[] { Resolve(Folder(path), rel), Resolve(root, rel) }.SelectMany(c => new[] { c, c + ".js", c + "/index.js" }).FirstOrDefault(files.Has) is { } found)
                yield return found;
        }
        foreach (Match m in BareModule.Matches(code))
            if (NodeModule(files, root, path, m.Groups["m"].Value) is { } found) yield return found;
    }

    /// <summary>
    /// The file Node resolves a bare module name to from the node_modules
    /// folders between the script and the package root; null when the package
    /// does not hold it.
    /// </summary>
    private static string? NodeModule(PackageFiles files, string root, string path, string name)
    {
        for (var folder = Folder(path); folder.StartsWith(root, StringComparison.Ordinal); folder = Folder(folder.TrimEnd('/')))
        {
            var module = folder + "node_modules/" + name;
            var main = Json(files, module + "/package.json") is { } pkg ? Str(pkg, "main") : null;
            var candidates = new[] { module, module + ".js", main == null ? null : Resolve(module + "/", main), main == null ? null : Resolve(module + "/", main) + ".js", module + "/index.js" };
            if (candidates.FirstOrDefault(c => c != null && files.Has(c)) is { } found) return found;
            if (folder.Length == 0 || folder == root) break;
        }
        return null;
    }

    private static readonly Regex LocalScript = R(@"['""`](\.{1,2}/[^'""`\s]+|[\w@.-]+(?:/[\w@.-]+)*\.(?:c|m)?js)['""`]");
    private static readonly Regex BareModule = R(@"\brequire\(\s*['""](?<m>[@\w][\w@.-]*(?:/[\w@.-]+)*)['""]\s*\)|\bfrom\s+['""](?<m>[@\w][\w@.-]*(?:/[\w@.-]+)*)['""]|\bimport\s*\(\s*['""](?<m>[@\w][\w@.-]*(?:/[\w@.-]+)*)['""]\s*\)");

    private static string? Target(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Object => e.EnumerateObject().Select(p => Target(p.Value)).FirstOrDefault(t => t != null),
        JsonValueKind.Array => e.EnumerateArray().Select(Target).FirstOrDefault(t => t != null),
        _ => null,
    };

    /// <summary>A path inside the package, relative to its root folder.</summary>
    private static string Resolve(string root, string relative)
    {
        var parts = new List<string>();
        foreach (var part in (root + relative.Replace('\\', '/')).Split('/'))
        {
            if (part is "" or ".") continue;
            if (part == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(part);
        }
        return string.Join('/', parts);
    }

    internal static JsonElement? Json(PackageFiles files, string path)
    {
        if (files.Text(path) is not { } text) return null;
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip, MaxDepth = 64 });
            return doc.RootElement.Clone();
        }
        catch (JsonException) { return null; }
    }

    internal static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string? Person(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() : Str(v, "name") : null;

    internal static string? Clip(string? s, int max = 300) => s == null ? null : s.Length > max ? s[..max] + "…" : s;
}
