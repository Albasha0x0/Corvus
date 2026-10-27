using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core.Python;
using Corvus.Native.Pe;

namespace Corvus.Services.Analysis.Dependencies;

internal static partial class DependencyInventory
{
    private const double ModuleVersion = 0.6, ImportName = 0.4;
    private const string Beside = " (beside the executable)";
    private const int MaxMetadataBytes = 1 << 20, MaxRuntimeBytes = 64 << 20;

    /// <summary>Import names whose distribution is named otherwise; any other import name is taken as the distribution's.</summary>
    private static readonly Dictionary<string, string> Distributions = new(StringComparer.Ordinal)
    {
        ["yaml"] = "PyYAML", ["PIL"] = "Pillow", ["cv2"] = "opencv-python", ["sklearn"] = "scikit-learn", ["skimage"] = "scikit-image",
        ["bs4"] = "beautifulsoup4", ["dateutil"] = "python-dateutil", ["Crypto"] = "pycryptodome", ["Cryptodome"] = "pycryptodomex",
        ["OpenSSL"] = "pyOpenSSL", ["jwt"] = "PyJWT", ["serial"] = "pyserial", ["usb"] = "pyusb", ["zmq"] = "pyzmq", ["dotenv"] = "python-dotenv",
        ["docx"] = "python-docx", ["pptx"] = "python-pptx", ["magic"] = "python-magic", ["git"] = "GitPython", ["wx"] = "wxPython",
        ["gi"] = "PyGObject", ["nacl"] = "PyNaCl", ["socks"] = "PySocks", ["fitz"] = "PyMuPDF", ["attr"] = "attrs", ["websocket"] = "websocket-client",
        ["pkg_resources"] = "setuptools", ["_distutils_hack"] = "setuptools", ["_cffi_backend"] = "cffi", ["mpl_toolkits"] = "matplotlib",
        ["win32api"] = "pywin32", ["win32con"] = "pywin32", ["win32com"] = "pywin32", ["win32gui"] = "pywin32", ["pythoncom"] = "pywin32",
        ["pywintypes"] = "pywin32", ["win32comext"] = "pywin32",
    };

    /// <summary>The modules each freezer adds to run the program; they belong to the freezer, not to a dependency.</summary>
    private static bool IsFreezerModule(string top) =>
        top.StartsWith("pyimod", StringComparison.Ordinal) || top.StartsWith("pyi_", StringComparison.Ordinal) || top.StartsWith("_pyi_", StringComparison.Ordinal)
        || top.StartsWith("__nuitka", StringComparison.Ordinal) || top.Contains("__mypyc", StringComparison.Ordinal)
        || top is "PyInstaller" or "py2exe" or "zipextimporter" or "_memimporter" or "boot_common" or "nuitka" or "__main__" or "__parents_main__" or "__startup__"
            or "BUILD_CONSTANTS";

    /// <summary>A release version as PEP 440 writes one: 1.2, 2.0.7, 3.0rc1, 1.0.post2, 1.0.dev3, 1.0+local.</summary>
    private static readonly Regex ReleaseVersion = new(@"^\d{1,9}(\.\d{1,9}){0,5}([-_.]?(a|b|c|rc|alpha|beta|post|dev)\.?\d{0,9}){0,3}(\+[A-Za-z0-9.]{1,64})?$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex Requirement = new(@"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", RegexOptions.CultureInvariant);

    private sealed record Distribution(string Name, string Version, string MetadataPath, List<string> TopLevel, List<string> Requires);

    /// <summary>Adds a frozen Python program's interpreter, bundled distributions and other top-level packages.</summary>
    private static void FromPython(Builder b, FrozenApp app, string path, CancellationToken ct)
    {
        b.Sources.Add($"{app.Freezer} contents ({app.Kind})");
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        byte[]? Bytes(FrozenEntry e, int max)
        {
            if (e.Load != null) return e.Size <= max ? e.Load() : null;
            if (!e.Role.EndsWith(Beside, StringComparison.Ordinal) || dir == null || e.Path.Split('/').Contains("..")) return null;
            try
            {
                var file = Path.Combine(dir, e.Path);
                return File.Exists(file) && new FileInfo(file).Length <= max ? File.ReadAllBytes(file) : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        }

        var scripts = app.EntryScripts.Select(s => s.EndsWith(".py", StringComparison.OrdinalIgnoreCase) ? s[..^3] : s).ToList();
        var script = scripts.ToHashSet(StringComparer.Ordinal);
        if (b.Subject == null && scripts.Count > 0)
            b.Subject = new DependencyComponent(b.NewRef("python-app"), scripts[0], null, "python", "application", null, Manifest, "manifest-analysis",
                $"{app.Freezer} entry script");
        Interpreter(b, app, e => Bytes(e, MaxRuntimeBytes));

        // The top-level packages the program bundles, each with the paths that name it.
        var tops = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        void Top(string name, string location)
        {
            if (name.Length == 0 || PyStdlib.Contains(name) || IsFreezerModule(name) || script.Contains(name)) return;
            if (!tops.TryGetValue(name, out var list)) tops[name] = list = [];
            if (list.Count < 3 && !list.Contains(location)) list.Add(location);
        }
        var modules = new Dictionary<string, FrozenEntry>(StringComparer.Ordinal);
        foreach (var e in app.Entries)
        {
            var inner = Inner(e.Path);
            if (e.Role is FrozenApp.Module or FrozenApp.Package or FrozenApp.Encrypted || e.Role.StartsWith(FrozenApp.Module + Beside, StringComparison.Ordinal)
                || e.Role.StartsWith(FrozenApp.Package + Beside, StringComparison.Ordinal))
            {
                if (FrozenApp.ModuleOf(inner) is not { } m) continue;
                modules.TryAdd(m.Name, e);
                Top(m.Name.Split('.')[0], e.Path);
            }
            else if (e.Role.StartsWith(FrozenApp.Native, StringComparison.Ordinal))
                Top(inner.Contains('/') ? inner[..inner.IndexOf('/')] : inner.Split('.')[0], e.Path);
        }
        var main = app.Entries.FirstOrDefault(e => e.Role.StartsWith("main binary", StringComparison.Ordinal))?.Path ?? "the executable";
        foreach (var (module, _) in app.CompiledModules) Top(module.Split('.')[0], $"{main} (compiled module {module.Split('.')[0]})");

        // Distributions by their metadata; each claims the import names its top_level.txt lists, or its own name.
        var distributions = new List<Distribution>();
        var siblings = app.Entries.Where(e => FrozenApp.IsPackageMetadata(e.Path)).GroupBy(e => e.Path[..Math.Max(0, e.Path.LastIndexOf('/'))]).ToList();
        foreach (var e in app.Entries.Where(e => FrozenApp.IsPackageMetadata(e.Path) && !e.Path.EndsWith("/top_level.txt", StringComparison.Ordinal)))
        {
            ct.ThrowIfCancellationRequested();
            if (Bytes(e, MaxMetadataBytes) is not { } bytes) continue;
            var (name, version, requires) = Headers(bytes);
            if (name == null) continue;
            var folder = e.Path.EndsWith(".egg-info", StringComparison.OrdinalIgnoreCase) ? e.Path : e.Path[..Math.Max(0, e.Path.LastIndexOf('/'))];
            var topLevel = siblings.FirstOrDefault(g => g.Key == folder)?.FirstOrDefault(s => s.Path.EndsWith("/top_level.txt", StringComparison.Ordinal)) is { } t
                           && Bytes(t, MaxMetadataBytes) is { } list
                ? Encoding.UTF8.GetString(list).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(n => n.Replace('/', '.').Split('.')[0]).ToList()
                : [];
            if (version == null)
            {
                b.Notes.Add($"{e.Path}: no Version field, so the packages of {name} are listed by import name");
                continue;
            }
            if (distributions.Any(d => Purl.PyPIName(d.Name) == Purl.PyPIName(name) && d.Version == version)) continue;
            distributions.Add(new Distribution(name, version, e.Path, topLevel, requires));
        }
        var refs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var d in distributions)
        {
            var claimed = new List<string>();
            var names = d.TopLevel.Count > 0 ? d.TopLevel : [.. tops.Keys.Where(t => Purl.PyPIName(Distributions.GetValueOrDefault(t, t)) == Purl.PyPIName(d.Name))];
            foreach (var t in names)
                if (tops.Remove(t, out var at)) claimed.AddRange(at);
            var purl = Purl.PyPI(d.Name, d.Version);
            var c = new DependencyComponent(b.NewRef(purl), d.Name, d.Version, "pypi", "library", purl, Manifest, "manifest-analysis",
                d.MetadataPath.EndsWith("METADATA", StringComparison.Ordinal) ? "distribution metadata (.dist-info METADATA)" : "distribution metadata (.egg-info PKG-INFO)")
            {
                Locations = [d.MetadataPath, .. claimed],
            };
            refs[Purl.PyPIName(d.Name)] = c.Ref;
            b.Components.Add(c);
        }

        // The rest by import name: __version__ in the package or a version module gives the version.
        int fromModule = 0, unknown = 0;
        // Import names of one distribution (win32api, win32con) make one component.
        foreach (var group in tops.GroupBy(t => Distributions.GetValueOrDefault(t.Key, t.Key)).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            var name = group.Key;
            var imports = group.Select(t => t.Key).Order(StringComparer.Ordinal).ToList();
            var (version, module) = imports.Select(top => app.Compiled ? CompiledVersion(app, top) : ModuleVersionOf(modules, top, e => Bytes(e, MaxMetadataBytes)))
                .FirstOrDefault(v => v.Item1 != null);
            var purl = version != null ? Purl.PyPI(name, version) : null;
            if (version != null) fromModule++;
            else unknown++;
            var c = new DependencyComponent(b.NewRef(purl ?? $"pypi:{name}"), name, version, "pypi", "library", purl, version != null ? ModuleVersion : ImportName,
                "binary-analysis", version != null
                    ? $"__version__ in module {module}; the distribution is named from the import name {string.Join(", ", imports)}"
                    : $"import name {string.Join(", ", imports)}; no distribution metadata or __version__, so the version is unknown")
            {
                Locations = [.. group.SelectMany(t => t.Value).Distinct().Take(3)],
            };
            refs.TryAdd(Purl.PyPIName(name), c.Ref);
            b.Components.Add(c);
        }
        // Requires-Dist names a distribution, whether its metadata or its import name found it.
        foreach (var d in distributions)
        {
            var from = refs[Purl.PyPIName(d.Name)];
            b.Read(from);
            foreach (var r in d.Requires)
                if (refs.TryGetValue(Purl.PyPIName(r), out var to) && to != from) b.Edge(from, to);
        }
        if (fromModule > 0)
            b.Notes.Add($"{fromModule} Python package version(s) come from __version__ and the name from the import name (confidence {ModuleVersion})");
        if (unknown > 0)
            b.Notes.Add($"{unknown} Python package(s) are named by import name only: version unknown, no package URL");
        if (app.Compiled && app.CompiledModules.Count == 0)
            b.Notes.Add("Nuitka compiled the program's modules to native code and its constants named none: the packages compiled into it are unknown");
    }

    /// <summary>The interpreter: the full version from the runtime library's version resource or version string, else major.minor.</summary>
    private static void Interpreter(Builder b, FrozenApp app, Func<FrozenEntry, byte[]?> bytes)
    {
        if (app.Version is not { } v) return;
        var runtimes = app.Entries.Where(e => e.Role.StartsWith(FrozenApp.Runtime, StringComparison.Ordinal) && PyVersion.FromLibraryName(Path.GetFileName(e.Path)) == v).ToList();
        string? full = null, source = null;
        foreach (var r in runtimes)
        {
            if (bytes(r) is not { } image) continue;
            (full, source) = RuntimeVersion(image, v, Path.GetFileName(r.Path));
            if (full != null) break;
        }
        var purl = full != null ? $"pkg:generic/python@{Purl.Encode(full)}" : null;
        b.Components.Add(new DependencyComponent(b.NewRef(purl ?? $"python@{PyVersion.Label(v)}"), "python", full ?? PyVersion.Label(v), "python", "framework", purl,
            full != null ? Manifest : AssemblyVersionOnly, "binary-analysis",
            full != null ? $"Python {full} from {source}" : $"Python {PyVersion.Label(v)} from {app.VersionSource ?? "the archive"}; the micro version is unknown")
        {
            Locations = [.. runtimes.Select(r => r.Path)],
        });
        if (full == null) b.Notes.Add($"Python {PyVersion.Label(v)}: only the major and minor version were read, so the interpreter has no package URL");
    }

    /// <summary>The version a runtime library names: its PE version resource, else a "3.12.4" string; null when neither reads.</summary>
    internal static (string?, string?) RuntimeVersion(byte[] image, (int Major, int Minor) v, string name)
    {
        var prefix = $"{v.Major}.{v.Minor}.";
        try
        {
            if (image.Length >= 2 && image[0] == 'M' && image[1] == 'Z' && PeFile.FromBytes(image, name).VersionInfo is { } info)
                foreach (var key in new[] { "ProductVersion", "FileVersion" })
                    if (info.Get(key)?.Trim() is { } text && text.StartsWith(prefix, StringComparison.Ordinal) && ReleaseVersion.IsMatch(text))
                        return (text, $"the {key} of {name}");
        }
        catch (Exception ex) when (ex is Core.ToolError or BadImageFormatException or ArgumentException) { }
        var pattern = new Regex(@"\x00(" + Regex.Escape(prefix) + @"\d{1,3}(?:(?:a|b|rc)\d{1,3})?)\x00", RegexOptions.CultureInvariant);
        return pattern.Match(Encoding.Latin1.GetString(image)) is { Success: true } m ? (m.Groups[1].Value, $"the version string in {name}") : (null, null);
    }

    /// <summary>A path inside the program: after the archive it was extracted from and the folder beside the executable it sits in.</summary>
    private static string Inner(string path)
    {
        var inner = path.Split("_extracted/")[^1];
        foreach (var folder in new[] { "_internal/", "lib/" })
            if (inner.StartsWith(folder, StringComparison.Ordinal)) return inner[folder.Length..];
        return inner;
    }

    /// <summary>The modules that bind a package's __version__, in the order they are read: the package, then its version modules.</summary>
    private static string[] VersionModules(string top) =>
        [top, $"{top}.__version__", $"{top}._version", $"{top}.version", $"{top}.__about__", $"{top}.package_data"];

    /// <summary>The __version__ string bound in a package or its version module, and that module; nulls when none reads.</summary>
    private static (string?, string?) ModuleVersionOf(Dictionary<string, FrozenEntry> modules, string top, Func<FrozenEntry, byte[]?> bytes)
    {
        foreach (var name in VersionModules(top))
        {
            if (!modules.TryGetValue(name, out var e) || bytes(e) is not { Length: >= 16 } pyc || PyVersion.FromMagic(pyc) is not { } v) continue;
            if (PyMarshal.TryRead(pyc, v, out _, PyVersion.HeaderLength(v)) is PyCode code
                && PyDisassembler.ModuleStrings(code, v).GetValueOrDefault("__version__") is { } version && ReleaseVersion.IsMatch(version))
                return (version, name);
        }
        return (null, null);
    }

    /// <summary>The same from the __version__ strings Nuitka's constants keep.</summary>
    private static (string?, string?) CompiledVersion(FrozenApp app, string top)
    {
        foreach (var name in VersionModules(top))
            if (app.CompiledModules.FirstOrDefault(m => m.Module == name).Version is { } version && ReleaseVersion.IsMatch(version))
                return (version, name);
        return (null, null);
    }

    /// <summary>Name, Version and the Requires-Dist names (without extras) of a METADATA or PKG-INFO header block.</summary>
    private static (string? Name, string? Version, List<string> Requires) Headers(byte[] bytes)
    {
        string? name = null, version = null;
        var requires = new List<string>();
        foreach (var raw in Encoding.UTF8.GetString(bytes).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            // The headers end at the first blank line; the description follows.
            if (line.Length == 0) break;
            int colon = line.IndexOf(':');
            if (colon <= 0 || char.IsWhiteSpace(line[0])) continue;
            var value = line[(colon + 1)..].Trim();
            switch (line[..colon])
            {
                case "Name": name ??= value; break;
                case "Version": version ??= value.Length > 0 ? value : null; break;
                case "Requires-Dist" when !value.Contains("extra ==", StringComparison.Ordinal) && !value.Contains("extra==", StringComparison.Ordinal):
                    if (Requirement.Match(value) is { Success: true } m) requires.Add(m.Groups[1].Value);
                    break;
            }
        }
        return (name, version, requires);
    }
}
