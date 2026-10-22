using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json.Serialization;
using Corvus.Native;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>A hash of a component: algorithm as CycloneDX names it (SHA-256, SHA-512), value in lowercase hex.</summary>
public sealed record ComponentHash(string Algorithm, string Value);

/// <summary>
/// A component of a file's dependency inventory. Purl is set only with package-level evidence (a package manifest, an
/// assembly's informational version, a build's module list); Confidence (0-1) and Technique say how the identity was
/// read, Source names what it was read from, Locations where in the file the component's code is.
/// </summary>
public sealed record DependencyComponent(string Ref, string Name, string? Version, string Ecosystem, string Type, string? Purl, double Confidence,
    string Technique, string Source)
{
    public IReadOnlyList<string> Locations { get; init; } = [];

    public IReadOnlyList<ComponentHash> Hashes { get; init; } = [];

    /// <summary>The assembly version from the component's metadata; null when it was not read from an assembly.</summary>
    public string? AssemblyVersion { get; init; }

    /// <summary>Whether the version is known; false means unknown, not absent.</summary>
    public bool VersionKnown => Version != null;

    /// <summary>"excluded" for a component the program does not load (no runtime asset, a build-time crate); null otherwise.</summary>
    public string? Scope { get; init; }
}

/// <summary>A component and the components it depends on, by Ref.</summary>
public sealed record DependencyEdge(string From, IReadOnlyList<string> To);

/// <summary>
/// view=dependencies: the components a file ships (NuGet packages from deps.json or assembly metadata, the .NET runtime,
/// Go modules, Rust crates) with their package URLs and evidence, the edges between them, and what was read.
/// </summary>
public sealed record DependencyFacts(DependencyComponent? Subject, int ComponentTotal, int WithPurl, IReadOnlyList<DependencyComponent> Components,
    int EdgeTotal, IReadOnlyList<string> Sources, IReadOnlyList<string> Notes)
{
    /// <summary>Every component (Components lists the first <see cref="DependencyInventory.MaxListed"/>).</summary>
    [JsonIgnore] public IReadOnlyList<DependencyComponent> All { get; init; } = [];

    [JsonIgnore] public IReadOnlyList<DependencyEdge> Edges { get; init; } = [];
}

/// <summary>Builds a file's <see cref="DependencyFacts"/> from what summarize_file already unpacked and the native image's build records.</summary>
internal static class DependencyInventory
{
    public const int MaxListed = 500;
    private const double Manifest = 1.0, InformationalVersion = 0.7, AssemblyVersionOnly = 0.5, SourcePath = 0.8;
    private const string FrameworkName = "Microsoft.NETCore.App";

    private sealed class Builder
    {
        public readonly List<DependencyComponent> Components = [];
        public readonly Dictionary<string, List<string>> Edges = new(StringComparer.Ordinal);
        public readonly List<string> Sources = [], Notes = [];
        public DependencyComponent? Subject;
        private readonly HashSet<string> refs = new(StringComparer.Ordinal);

        public string NewRef(string preferred)
        {
            var r = preferred;
            for (int i = 2; !refs.Add(r); i++) r = $"{preferred}#{i}";
            return r;
        }

        /// <summary>Records that <paramref name="from"/>'s dependencies were read, so it has an entry even with none.</summary>
        public List<string> Read(string from) => Edges.TryGetValue(from, out var list) ? list : Edges[from] = [];

        public void Edge(string from, string to)
        {
            var list = Read(from);
            if (!list.Contains(to)) list.Add(to);
        }
    }

    /// <summary>The inventory, or null when the file names no component beside itself.</summary>
    public static DependencyFacts? Of(FileInput input, IReadOnlyList<UnpackService.ManagedAssembly> assemblies, IReadOnlyList<DepsJson> manifests,
        IReadOnlyDictionary<string, FileView> views, CancellationToken ct)
    {
        var b = new Builder();
        var claimed = new HashSet<UnpackService.ManagedAssembly>();
        foreach (var deps in manifests) FromDepsJson(b, deps, input.Path, assemblies, claimed);
        FromAssemblies(b, input.Path, assemblies.Where(a => !claimed.Contains(a)).ToList(), ct);
        if (views.ContainsKey("go") || views.ContainsKey("rust")) FromNative(b, input, views);
        if (b.Components.Count == 0) return null;
        var edges = b.Edges.Select(e => new DependencyEdge(e.Key, e.Value)).ToList();
        if (b.Components.Count > MaxListed) b.Notes.Add($"components: the first {MaxListed} of {b.Components.Count:N0} listed; sbomPath writes all");
        return new DependencyFacts(b.Subject, b.Components.Count, b.Components.Count(c => c.Purl != null), [.. b.Components.Take(MaxListed)],
            edges.Sum(e => e.To.Count), b.Sources, b.Notes) { All = b.Components, Edges = edges };
    }

    /// <summary>Packages, runtime packs and projects of a deps.json; assemblies its assets name are claimed.</summary>
    private static void FromDepsJson(Builder b, DepsJson deps, string source, IReadOnlyList<UnpackService.ManagedAssembly> assemblies,
        HashSet<UnpackService.ManagedAssembly> claimed)
    {
        b.Sources.Add($"deps.json {deps.Path}{(deps.RuntimeTarget != null ? $" (target {deps.RuntimeTarget})" : "")}");
        var byFile = assemblies.GroupBy(a => FileName(a.Path), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        var byName = deps.Libraries.GroupBy(l => l.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        // The app is the project named like the file (App.exe, App.dll, App.deps.json), else the first project.
        var app = Path.GetFileNameWithoutExtension(source);
        var root = deps.Libraries.FirstOrDefault(l => l.Type == "project" && l.Name.Equals(app, StringComparison.OrdinalIgnoreCase))
                   ?? deps.Libraries.FirstOrDefault(l => l.Type == "project");
        var loads = Loads(deps.Libraries, byName);
        var refOf = new Dictionary<DepsLibrary, string>();
        foreach (var lib in deps.Libraries)
        {
            var located = lib.Assets.Select(FileName).Where(byFile.ContainsKey).SelectMany(f => byFile[f]).ToList();
            claimed.UnionWith(located);
            bool package = lib.Type is "package" or "runtimepack";
            var purl = package ? Purl.NuGet(lib.Name, lib.Version) : null;
            var c = new DependencyComponent(b.NewRef(purl ?? $"nuget:{lib.Name}@{lib.Version}"), lib.Name, lib.Version, "nuget",
                lib.Type == "runtimepack" ? "framework" : lib == root ? "application" : "library", purl, Manifest, "manifest-analysis", $"deps.json library ({lib.Type})")
            {
                Locations = [.. located.Select(a => a.Path).Distinct()],
                Hashes = lib.Sha512 != null ? [new ComponentHash("SHA-512", lib.Sha512)] : [],
                Scope = loads.Contains(lib) ? null : "excluded",
            };
            refOf[lib] = c.Ref;
            if (lib == root && b.Subject == null) b.Subject = c;
            else b.Components.Add(c);
        }
        foreach (var lib in deps.Libraries)
        {
            b.Read(refOf[lib]);
            foreach (var (name, _) in lib.Dependencies)
                if (byName.TryGetValue(name, out var to)) b.Edge(refOf[lib], refOf[to]);
        }
        int excluded = b.Components.Count(c => c.Scope == "excluded" && c.Source.StartsWith("deps.json", StringComparison.Ordinal));
        if (excluded > 0)
            b.Notes.Add($"{excluded} deps.json librar{(excluded == 1 ? "y has" : "ies have")} no runtime asset in or below it (scope excluded): " +
                        "the program does not load its code");
    }

    /// <summary>The libraries that list an asset or depend, directly or not, on one that does.</summary>
    private static HashSet<DepsLibrary> Loads(IReadOnlyList<DepsLibrary> libraries, Dictionary<string, DepsLibrary> byName)
    {
        var memo = new Dictionary<DepsLibrary, bool>();
        bool Visit(DepsLibrary lib)
        {
            if (memo.TryGetValue(lib, out var known)) return known;
            // A cycle counts as not loading until an asset is found on it.
            memo[lib] = false;
            bool result = lib.Assets.Count > 0 || lib.Dependencies.Keys.Any(n => byName.TryGetValue(n, out var d) && Visit(d));
            return memo[lib] = result;
        }
        return [.. libraries.Where(Visit)];
    }

    private sealed record Identity(string Name, string? Version, string? Informational, string? FileVersion, string? Token);

    /// <summary>Assemblies no manifest claims: the runtime rolled into one framework, the rest by their own metadata.</summary>
    private static void FromAssemblies(Builder b, string source, List<UnpackService.ManagedAssembly> assemblies, CancellationToken ct)
    {
        if (assemblies.Count == 0) return;
        var read = new List<(UnpackService.ManagedAssembly Assembly, Identity Id)>();
        int unreadable = 0, satellites = 0;
        foreach (var a in assemblies)
        {
            ct.ThrowIfCancellationRequested();
            if (Read(a.Bytes) is not { } id) { unreadable++; continue; }
            if (id.Name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)) { satellites++; continue; }
            read.Add((a, id));
        }
        b.Sources.Add($"assembly metadata ({read.Count} assemblies without a manifest entry)");
        // The runtime's assemblies share System.Private.CoreLib's source commit (the informational version's
        // "+commit"); CoreLib alone may carry a servicing label, so the others give the version.
        var coreLib = read.FirstOrDefault(r => r.Id.Name == "System.Private.CoreLib");
        var commit = coreLib.Id?.Informational is { } cv ? Commit(cv) : null;
        var framework = commit == null ? [] : read.Where(r => r.Id.Token != null && InspectionService.FrameworkTokens.Contains(r.Id.Token)
                                                              && r.Id.Informational != null && Commit(r.Id.Informational) == commit).ToList();
        var runtime = framework.Where(f => f != coreLib).Select(f => Strip(f.Id.Informational!)).GroupBy(v => v).MaxBy(g => g.Count())?.Key
                      ?? (coreLib.Id?.Informational is { } rv ? Strip(rv) : null);
        if (framework.Count > 0)
        {
            b.Components.Add(new DependencyComponent(b.NewRef($"nuget:{FrameworkName}@{runtime}"), FrameworkName, runtime, "nuget", "framework", null,
                InformationalVersion, "binary-analysis", $"System.Private.CoreLib informational version, shared by {framework.Count} assemblies")
            {
                Locations = [.. framework.Select(f => f.Assembly.Path)],
            });
            b.Notes.Add($"{FrameworkName} {runtime}: no runtime pack is named without a deps.json, so it has no package URL");
        }
        foreach (var (a, id) in read.Except(framework))
        {
            bool self = a.Origin is UnpackService.HostOrigin or UnpackService.ApphostAppOrigin or "the file itself"
                        || b.Subject == null && id.Name.Equals(Path.GetFileNameWithoutExtension(source), StringComparison.OrdinalIgnoreCase);
            var informational = id.Informational is { } iv && Strip(iv) is { } s && char.IsAsciiDigit(s[0]) ? s : null;
            // An assembly version does not name a package version: a library without an informational version has an
            // unknown version; the file's own assembly keeps it as the application's version.
            var version = informational ?? (self ? id.Version : null);
            var purl = informational != null && !self ? Purl.NuGet(id.Name, informational) : null;
            var c = new DependencyComponent(b.NewRef(purl ?? $"nuget:{id.Name}@{version ?? id.Version}"), id.Name, version, "nuget", self ? "application" : "library", purl,
                informational != null ? InformationalVersion : AssemblyVersionOnly, "binary-analysis",
                informational != null ? "assembly name and informational version" : "assembly name; no informational version, so the package version is unknown")
            {
                Locations = [a.Path], Hashes = [new ComponentHash("SHA-256", a.Sha256)], AssemblyVersion = id.Version,
            };
            if (self && b.Subject == null) b.Subject = c;
            else if (Merge(b, c, a.Path) is false) b.Components.Add(c);
        }
        if (unreadable > 0) b.Notes.Add($"{unreadable} assemblies have unreadable metadata: their identity is unknown");
        if (satellites > 0) b.Notes.Add($"{satellites} satellite resource assemblies are part of the assembly they translate");
        int versionOnly = b.Components.Count(c => c.Ecosystem == "nuget" && c.Purl == null && c.Confidence == AssemblyVersionOnly);
        if (versionOnly > 0) b.Notes.Add($"{versionOnly} assemblies carry no informational version: their package version is unknown and they have no package URL");
    }

    /// <summary>Adds a location to an equal component already listed (the same assembly twice); false when there is none.</summary>
    private static bool Merge(Builder b, DependencyComponent c, string location)
    {
        int i = b.Components.FindIndex(x => x.Name == c.Name && x.Version == c.Version && x.Ecosystem == c.Ecosystem);
        if (i < 0) return false;
        b.Components[i] = b.Components[i] with { Locations = [.. b.Components[i].Locations, location] };
        return true;
    }

    private static Identity? Read(byte[] bytes)
    {
        try
        {
            using var pe = new PEReader(new MemoryStream(bytes, writable: false));
            if (!pe.HasMetadata) return null;
            var md = pe.GetMetadataReader();
            if (!md.IsAssembly) return null;
            var def = md.GetAssemblyDefinition();
            string? informational = null, file = null;
            foreach (var h in def.GetCustomAttributes())
            {
                var attr = md.GetCustomAttribute(h);
                switch (AttributeName(md, attr))
                {
                    case "AssemblyInformationalVersionAttribute": informational = StringArgument(md, attr); break;
                    case "AssemblyFileVersionAttribute": file = StringArgument(md, attr); break;
                }
            }
            var key = md.GetBlobBytes(def.PublicKey);
            string? token = key.Length switch
            {
                0 => null,
                8 => Convert.ToHexStringLower(key),
                _ => Convert.ToHexStringLower(System.Security.Cryptography.SHA1.HashData(key)[^8..].Reverse().ToArray()),
            };
            return new Identity(md.GetString(def.Name), def.Version.ToString(), informational, file, token);
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException) { return null; }
    }

    private static string? AttributeName(MetadataReader md, CustomAttribute attr) => attr.Constructor.Kind switch
    {
        HandleKind.MemberReference when md.GetMemberReference((MemberReferenceHandle)attr.Constructor).Parent is { Kind: HandleKind.TypeReference } parent
            => md.GetString(md.GetTypeReference((TypeReferenceHandle)parent).Name),
        HandleKind.MethodDefinition => md.GetString(md.GetTypeDefinition(md.GetMethodDefinition((MethodDefinitionHandle)attr.Constructor).GetDeclaringType()).Name),
        _ => null,
    };

    /// <summary>The single string argument of an attribute blob (prolog 0x0001, then a SerString); null for anything else.</summary>
    private static string? StringArgument(MetadataReader md, CustomAttribute attr)
    {
        var r = md.GetBlobReader(attr.Value);
        if (r.Length < 3 || r.ReadUInt16() != 1) return null;
        return r.ReadSerializedString();
    }

    /// <summary>The build metadata of an informational version (the source commit after "+"), or null.</summary>
    private static string? Commit(string version) => version.IndexOf('+') is var i and >= 0 && i + 1 < version.Length ? version[(i + 1)..].Trim() : null;

    /// <summary>An informational version without its build metadata ("+commit"); null when empty.</summary>
    private static string? Strip(string version)
    {
        var v = version.Split('+')[0].Trim();
        return v.Length > 0 ? v : null;
    }

    private static string FileName(string path) => path[(path.LastIndexOfAny(['/', '\\']) + 1)..];

    /// <summary>Go modules from the build information and Rust crates from the cargo-auditable list or the source paths.</summary>
    private static void FromNative(Builder b, FileInput input, IReadOnlyDictionary<string, FileView> views)
    {
        INativeImage image;
        try { image = NativeImageLoader.FromBytes(input.Image, input.Path); }
        catch (Exception ex) when (ex is Core.ToolError or BadImageFormatException or ArgumentException or InvalidOperationException) { return; }
        if (views.ContainsKey("go") && Native.Go.GoBuildInfo.Of(image) is { } go) FromGo(b, go);
        if (views.GetValueOrDefault("rust")?.Detail is RustFileView.Facts rust)
        {
            if (rust.Section == "source paths") FromRustSourcePaths(b, input.Image);
            else if (RustAudit.Of(image, input.Image) is { } audit) FromRust(b, audit);
        }
    }

    private static void FromGo(Builder b, Native.Go.GoBuildInfo go)
    {
        b.Sources.Add("Go build information");
        string? subject = null;
        if (go.Main is { } main)
        {
            var version = main.Version is "" or "(devel)" ? null : main.Version;
            var purl = version != null ? Purl.Golang(main.Path, version) : null;
            b.Subject ??= new DependencyComponent(b.NewRef(purl ?? $"golang:{main.Path}"), main.Path, version, "golang", "application", purl, Manifest,
                "manifest-analysis", "Go build information (main module)");
            subject = b.Subject.Ref;
        }
        var std = go.GoVersion.StartsWith("go", StringComparison.Ordinal) ? go.GoVersion[2..].Split(' ')[0] : go.GoVersion;
        var stdPurl = Purl.Golang("stdlib", std);
        var stdlib = new DependencyComponent(b.NewRef(stdPurl), "stdlib", std, "golang", "library", stdPurl, Manifest, "manifest-analysis",
            $"Go build information (toolchain {go.GoVersion})");
        b.Components.Add(stdlib);
        if (subject != null) b.Edge(subject, stdlib.Ref);
        foreach (var m in go.Dependencies)
        {
            // A replace directive names the module whose code was compiled.
            var used = m.Replace ?? m;
            bool local = used.Version.Length == 0;
            var purl = local ? null : Purl.Golang(used.Path, used.Version);
            var c = new DependencyComponent(b.NewRef(purl ?? $"golang:{used.Path}"), used.Path, local ? null : used.Version, "golang", "library", purl, Manifest,
                "manifest-analysis", m.Replace != null ? $"Go build information (replaces {m.Path} {m.Version})" : "Go build information");
            b.Components.Add(c);
            if (subject != null) b.Edge(subject, c.Ref);
        }
        int locals = go.Dependencies.Count(m => (m.Replace ?? m).Version.Length == 0);
        if (locals > 0) b.Notes.Add($"{locals} Go modules are replaced by local directories: no version, no package URL");
    }

    private static void FromRust(Builder b, RustAudit audit)
    {
        b.Sources.Add($"cargo-auditable dependency list ({audit.Section})");
        var refs = new string[audit.Packages.Count];
        for (int i = 0; i < audit.Packages.Count; i++)
        {
            var p = audit.Packages[i];
            var purl = p.Source == "crates.io" ? Purl.Cargo(p.Name, p.Version) : null;
            var c = new DependencyComponent(b.NewRef(purl ?? $"cargo:{p.Name}@{p.Version}"), p.Name, p.Version, "cargo", p.Root ? "application" : "library", purl,
                Manifest, "manifest-analysis", $"cargo-auditable ({p.Source}, {p.Kind})") { Scope = p.Kind == "build" ? "excluded" : null };
            refs[i] = c.Ref;
            if (p.Root && b.Subject == null) b.Subject = c;
            else b.Components.Add(c);
        }
        for (int i = 0; i < audit.Packages.Count; i++)
        {
            b.Read(refs[i]);
            foreach (var d in audit.Packages[i].Dependencies)
                if (d >= 0 && d < refs.Length) b.Edge(refs[i], refs[d]);
        }
        int other = audit.Packages.Count(p => !p.Root && p.Source != "crates.io");
        if (other > 0) b.Notes.Add($"{other} crates come from a git, local or other registry source: no package URL");
        b.Notes.AddRange(audit.Issues);
    }

    private static void FromRustSourcePaths(Builder b, byte[] image)
    {
        var crates = RustFileView.RegistryCrates(image);
        if (crates.Count == 0) return;
        b.Sources.Add("crates.io registry source paths");
        foreach (var (name, version) in crates)
        {
            var purl = Purl.Cargo(name, version);
            b.Components.Add(new DependencyComponent(b.NewRef(purl), name, version, "cargo", "library", purl, SourcePath, "binary-analysis",
                "crates.io registry source path"));
        }
        b.Notes.Add("crates from source paths: those with no panic location or assertion in the build are not named, and no edges are known");
    }
}
