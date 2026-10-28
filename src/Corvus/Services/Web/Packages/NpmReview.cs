using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    /// <summary>Lifecycle scripts npm runs when the package is installed from a registry.</summary>
    private static readonly HashSet<string> NpmInstallScripts = new(StringComparer.Ordinal) { "preinstall", "install", "postinstall" };

    /// <summary>Scripts npm also runs on npm install inside a source folder or git checkout.</summary>
    private static readonly HashSet<string> NpmLocalInstallScripts = new(StringComparer.Ordinal) { "preprepare", "prepare", "postprepare" };

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
            foreach (var run in NodeTargets(script.Command))
            {
                var target = Resolve(root, run);
                if (!files.Has(target) && files.Has(target + ".js")) target += ".js";
                if (files.Text(target) is { } code) findings.AddRange(Scan(target, InstallCode(files, root, target, code), install: true, ct));
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
        int deps = 0;
        foreach (var key in new[] { "dependencies", "optionalDependencies", "peerDependencies" })
            if (pkg.TryGetProperty(key, out var d) && d.ValueKind == JsonValueKind.Object) deps += d.EnumerateObject().Count();
        return new PackageReport("npm", name, Str(pkg, "version"))
        {
            Publisher = Person(pkg, "author"), Description = Clip(Str(pkg, "description")), Scripts = scripts, EntryPoints = entries,
            Dependencies = deps, Binaries = binaries.Count > 0 ? binaries : null, Findings = findings, Notes = notes,
        };
    }

    private static IEnumerable<string> NodeTargets(string command)
    {
        var runs = NodeScript.Matches(command).Select(m => m.Groups["t"].Value)
            .Concat(NodeRequire.Matches(command).Select(m => m.Groups["t"].Value));
        if (NodeEval.IsMatch(command))
            runs = runs.Concat(RequireLiteral.Matches(command).Select(m => m.Groups[1].Value));
        return runs.Distinct();
    }

    // NonBacktracking takes no backreference, so each quote form is its own branch.
    private static readonly Regex NodeScript = R(@"\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*(?:'(?<t>[^\s'""&|;]+\.(?:c|m)?js)'|""(?<t>[^\s'""&|;]+\.(?:c|m)?js)""|(?<t>[^\s'""&|;]+\.(?:c|m)?js))");
    private static readonly Regex NodeRequire = R(@"\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*?(?:-r|--require)[\s=]+(?:'(?<t>\.{1,2}/[^\s'""&|;]+)'|""(?<t>\.{1,2}/[^\s'""&|;]+)""|(?<t>\.{1,2}/[^\s'""&|;]+))");
    private static readonly Regex NodeEval = R(@"\bnode(?:\.exe)?\s+(?:-e|--eval|-p|--print)\b");
    private static readonly Regex RequireLiteral = R(@"\brequire\(\s*\\?['""`](\.{1,2}/[^'""`\\]+)\\?['""`]\s*\)");

    /// <summary>Install-time code joined with the package files it loads by literal path, two levels deep.</summary>
    private static string InstallCode(PackageFiles files, string root, string target, string code)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { target };
        var text = new System.Text.StringBuilder(code);
        var queue = new Queue<(string Path, string Code, int Depth)>([(target, code, 0)]);
        while (queue.TryDequeue(out var item))
        {
            if (item.Depth >= 2) continue;
            foreach (Match m in LocalScript.Matches(item.Code))
            {
                var rel = m.Groups[1].Value;
                // Runners start small scripts; a bundled CLI's chunks over 64 KiB are scanned as loaded code.
                var found = new[] { Resolve(Folder(item.Path), rel), Resolve(root, rel) }.SelectMany(c => new[] { c, c + ".js", c + "/index.js" })
                    .FirstOrDefault(c => files.Has(c) && files.Size(c) <= 64 << 10);
                if (found == null || seen.Count >= 8 || !seen.Add(found) || files.Text(found) is not { } more) continue;
                text.Append('\n').Append(more);
                queue.Enqueue((found, more, item.Depth + 1));
            }
        }
        return text.ToString();
    }

    private static readonly Regex LocalScript = R(@"['""`](\.{1,2}/[^'""`\s]+|[\w@.-]+(?:/[\w@.-]+)*\.(?:c|m)?js)['""`]");

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
