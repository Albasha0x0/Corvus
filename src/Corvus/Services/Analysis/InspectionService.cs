using System.Text.Json.Serialization;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.NativeAot;

namespace Corvus.Services.Analysis;

/// <summary>
/// Static analyses of a loaded assembly or a file: features, typed values, embedded content and a combined summary.
/// <see cref="Summarize"/> also opens containers and summarizes the assemblies inside.
/// </summary>
public sealed class InspectionService(AssemblyWorkspace workspace, NativeCodeService? code = null)
{
    private static AnalysisLimits Limits => AnalysisLimits.Default;
    private const int MaxSummarizedAssemblies = 8;
    private const int MaxSummaryContents = 5;
    private const int MaxSummaryEmbeddedAssemblies = 10;
    private const int TopValues = 10;

    public sealed record FeatureReport(string Assembly, int MethodsScanned, IReadOnlyList<Feature> Features, IReadOnlyList<string> Notes);

    public sealed record ValueReport(string Assembly, int Total, IReadOnlyList<ExtractedValue> Values, IReadOnlyList<string> Notes);

    public sealed record EmbeddedReport(string Assembly, IReadOnlyList<EmbeddedContent> Contents,
        string? OutputDirectory, IReadOnlyList<string> Notes);

    public sealed record FileFacts(string Path, long Size, string Md5, string Sha1, string Sha256, string Type, double Entropy, CertificateInfo Certificate);

    public sealed record IdentityFacts(string Name, string? Version, string Mvid, string? TargetFramework, string Kind, string Architecture,
        bool ReadyToRun, string? Merged, int Types, int Methods,
        IReadOnlyList<string> References);

    public sealed record SignatureFacts(bool StrongNamed, string? PublicKeyToken, CertificateInfo Certificate);

    public sealed record WrappingFacts(IReadOnlyList<string> EmbeddedAssemblies, IReadOnlyList<EmbeddedContent> Contents, IReadOnlyList<string> HighEntropySections)
    {
        /// <summary>Total embedded assemblies; EmbeddedAssemblies may be truncated.</summary>
        public int EmbeddedAssemblyTotal { get; init; }
    }

    public sealed record ValueSummary(int Total, IReadOnlyDictionary<string, int> ByType, IReadOnlyList<ExtractedValue> Top);

    public sealed record AssemblySummary(string Path, string Sha256, IdentityFacts Identity, SignatureFacts Signature, MarkerFacts Markers,
        WrappingFacts Wrapping, IReadOnlyList<Feature> Features, ValueSummary Values, IReadOnlyList<EntryPoint> EntryPoints,
        IReadOnlyList<string> Highlights, IReadOnlyList<string> Notes);

    public sealed record FileSummary(FileFacts File, string Container, IReadOnlyList<AssemblySummary> Assemblies, IReadOnlyList<string> Highlights,
        IReadOnlyList<string> Notes)
    {
        /// <summary>Set for a NativeAOT image: runtime version, module header and the recovery stages.</summary>
        public NativeAotSummary? NativeAot { get; init; }

        /// <summary>Set for an ELF or Mach-O image (the default slice of a universal file).</summary>
        public NativeImageFacts? NativeImage { get; init; }

        /// <summary>Packers and protectors a native image shows signs of, with the evidence (detection only).</summary>
        public IReadOnlyList<Native.PackerFinding>? Packers { get; init; }

        /// <summary>Set for an Android package: manifest facts, runtimes with evidence, ABIs, DEX, signature.</summary>
        public Mobile.AndroidPackageFacts? Android { get; init; }

        /// <summary>Set for a loaded native image: counts, sections, entry points, top functions and strings, import groups, call graph shape.</summary>
        public NativeTriage? Triage { get; init; }

        /// <summary>Set for an Electron executable or .asar: versions, fuses, archive integrity, package.json entry, webPreferences values.</summary>
        public ElectronFacts? Electron { get; init; }

        /// <summary>Set for a Go program: toolchain, main package and module, dependencies (first 64) and build settings.</summary>
        public GoBuildFacts? Go { get; init; }

        /// <summary>The views that apply to the file (<see cref="IFileSummaryView"/>), by name; the typed properties above are the built-in ones.</summary>
        [JsonIgnore] public IReadOnlyDictionary<string, FileView> Views { get; init; } = new Dictionary<string, FileView>();
    }

    public sealed record GoBuildFacts(string GoVersion, string? Path, Native.Go.GoModule? Main, int DependencyTotal, IReadOnlyList<Native.Go.GoModule> Dependencies,
        IReadOnlyList<Native.Go.GoSetting> Settings)
    {
        private const int MaxDependencies = 64;

        /// <summary>The build information of a PE, ELF or Mach-O file, or null.</summary>
        public static GoBuildFacts? Of(string path, byte[] bytes)
        {
            Native.INativeImage? image;
            try
            {
                image = Native.NativeImageLoader.Detect(bytes) switch
                {
                    Native.NativeFileKind.Pe => Native.Pe.PeFile.FromBytes(bytes, path),
                    Native.NativeFileKind.Elf => Native.Elf.ElfFile.FromBytes(bytes, path),
                    Native.NativeFileKind.MachO or Native.NativeFileKind.MachOFat => Native.MachO.MachOFile.FromBytes(bytes, path),
                    _ => null,
                };
            }
            catch (Exception ex) when (ex is ToolError or InvalidOperationException or ArgumentException or BadImageFormatException) { return null; }
            if (image == null || Native.Go.GoBuildInfo.Of(image) is not { } go) return null;
            return new GoBuildFacts(go.GoVersion, go.Path, go.Main, go.Dependencies.Count, [.. go.Dependencies.Take(MaxDependencies)], go.Settings);
        }

        public string Highlight()
        {
            string? Setting(string key) => Settings.FirstOrDefault(s => s.Key == key)?.Value;
            var parts = new List<string> { $"Go program built with {GoVersion}" };
            if (Main != null) parts.Add($"module {Main.Path} {Main.Version}");
            else if (Path != null) parts.Add($"package {Path}");
            parts.Add($"{DependencyTotal} dependencies");
            if (Setting("GOOS") is { } os && Setting("GOARCH") is { } arch) parts.Add($"{os}/{arch}");
            if (Setting("vcs.revision") is { } rev) parts.Add($"revision {rev}" + (Setting("vcs.modified") == "true" ? " (modified)" : ""));
            return string.Join(", ", parts) + ".";
        }
    }

    private sealed record Scanned(ModuleDef Module, ModuleScan Scan, byte[] Image, string Label);

    /// <summary>Runs work on a loaded assembly (under the read lock) or a file (module disposed afterwards).</summary>
    private T WithAssembly<T>(string? assembly, string? path, Func<Scanned, T> work, CancellationToken ct)
    {
        if ((assembly == null) == (path == null))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass either assembly (an assembly loaded in the workspace) or path (a file).");
        if (assembly != null)
            return workspace.Read(() =>
            {
                var asm = workspace.Get(assembly);
                return Guard(asm.Id, () => work(new Scanned(asm.Module, ModuleScan.Of(asm, Limits, ct), asm.OriginalBytes, asm.Id)));
            });

        var (full, bytes) = ReadFile(path!);
        var kind = Blob.Identify(bytes);
        if (kind != ".NET assembly")
            throw new ToolError(ErrorCode.Unsupported, $"{full} is not a .NET assembly ({kind}).", kind is "native PE" or "NativeAOT executable" or "elf" or "mach-o"
                ? $"this tool reads .NET metadata; for a native image: search_native_strings image={full}, survey_features path={full}"
                : $"unpack_container path={full} extracts a container's assemblies (pass one of them here); summarize_file path={full} describes the file");
        using var module = LoadModule(bytes, full);
        return Guard(Path.GetFileName(full), () => work(new Scanned(module, ModuleScan.Of(module, Limits, ct), bytes, Path.GetFileName(full))));
    }

    /// <summary>
    /// dnlib reads metadata lazily, so corruption surfaces at first access; converts such exceptions into a ToolError.
    /// </summary>
    private static T Guard<T>(string label, Func<T> work)
    {
        try { return work(); }
        catch (Exception ex) when (ex is not ToolError and not OperationCanceledException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{label}: unreadable .NET metadata, analysis stopped ({ex.GetType().Name}: {ex.Message}).");
        }
    }

    private static (string Full, byte[] Bytes) ReadFile(string path)
    {
        if (Directory.Exists(Path.GetFullPath(path))) throw new ToolError(ErrorCode.InvalidArgument, $"{Path.GetFullPath(path)} is a directory; pass a file (list_assemblies with path lists the assemblies a folder or container holds).");
        var full = InputFiles.RequireRegularFile(path);
        if (!File.Exists(full)) throw Targets.FileNotFound(path);
        var length = new FileInfo(full).Length;
        if (length > Math.Min(Limits.MaxTotalBytes, Array.MaxLength)) throw new ToolError(ErrorCode.LimitExceeded, $"{full} is too large to analyze ({length:N0} bytes).");
        return (full, File.ReadAllBytes(full));
    }

    private static ModuleDefMD LoadModule(byte[] bytes, string label)
    {
        try { return ModuleDefMD.Load(bytes); }
        catch (Exception ex) { throw new ToolError(ErrorCode.MalformedInput, $"{label}: unreadable .NET metadata ({ex.Message})."); }
    }

    public FeatureReport SurveyFeatures(string? assembly, string? path, string? category, CancellationToken ct)
    {
        if (NativeSurvey(assembly, path, ct) is { } native) return Filter(native, category);
        return WithAssembly(assembly, path, s => Filter(new FeatureReport(s.Label, s.Scan.MethodsScanned, Features.Detect(s.Scan, ct), s.Scan.Notes), category), ct);
    }

    private static FeatureReport Filter(FeatureReport report, string? category) =>
        category == null || category.Equals("all", StringComparison.OrdinalIgnoreCase) ? report : report with
        {
            Features = [.. report.Features.Where(c => c.Category.Equals(category, StringComparison.OrdinalIgnoreCase)
                                                     || (c.Attack?.StartsWith(category, StringComparison.OrdinalIgnoreCase) ?? false))],
        };

    /// <summary>
    /// The survey of a native image: a loaded one (assembly names it and no managed assembly matches) through its code index,
    /// or a native PE file (path) indexed for this call without loading it; null when the input is not native.
    /// </summary>
    private FeatureReport? NativeSurvey(string? assembly, string? path, CancellationToken ct)
    {
        if ((assembly == null) == (path == null)) return null;
        NativeCodeIndex index;
        string label;
        if (assembly != null)
        {
            if (code == null) return null;
            var native = workspace.Read(() =>
            {
                if (workspace.FindNative(assembly) is not { } n) return null;
                try { workspace.Get(assembly); return null; } // a managed assembly of that name wins
                catch (ToolError) { return n; }
            });
            if (native == null) return null;
            index = code.Index(native, null, ct).GetAwaiter().GetResult();
            label = native.Id;
        }
        else
        {
            var full = InputFiles.RequireRegularFile(path!);
            if (!File.Exists(full)) return null;
            var head = new byte[Math.Min(4096, new FileInfo(full).Length)];
            using (var f = File.OpenRead(full)) f.ReadExactly(head);
            var kind = Native.NativeImageLoader.Detect(head);
            if (kind == Native.NativeFileKind.Unknown) return null;
            var (_, bytes) = ReadFile(path!);
            if (kind == Native.NativeFileKind.Pe && Blob.Identify(bytes) is not ("native PE" or "NativeAOT executable")) return null;
            if (code != null && workspace.Read(() => workspace.FindNative(full)) is { } loaded)
            {
                index = code.Index(loaded, null, ct).GetAwaiter().GetResult();
                label = loaded.Id;
            }
            else
            {
                Native.INativeImage image;
                try { image = Native.NativeImageLoader.Open(full); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
                {
                    throw new ToolError(ErrorCode.MalformedInput, $"{full}: not a readable native image ({ex.Message}).");
                }
                index = NativeCodeIndex.Build(image, ct: ct);
                label = Path.GetFileName(full);
            }
        }
        var scan = new NativeFeatureScan(index, ct);
        var found = Features.Detect(scan, ct);
        var notes = new List<string> { "native image: rules over static and late-bound imports, call arguments, strings, sections and RTTI class names" };
        if (index.Support != CodeSupport.Full) notes.Add(index.SupportNote ?? "instructions are not decoded: imports, strings and sections only");
        notes.AddRange(index.Truncations);
        notes.AddRange(scan.Notes);
        return new FeatureReport(label, index.Functions.Count, found, notes);
    }

    /// <summary>Typed values sorted by type (in <see cref="Values.Types"/> order), count descending, then value.</summary>
    public ValueReport ExtractStrings(string? assembly, string? path, IReadOnlyCollection<string>? types, CancellationToken ct)
    {
        types = types?.Select(t => t.Trim().ToLowerInvariant()).Where(t => t.Length > 0).ToList();
        var unknown = types?.Where(t => !Values.Types.Contains(t)).ToList();
        if (unknown is { Count: > 0 })
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown value type(s): {string.Join(", ", unknown)}.", $"pass types from: {string.Join(", ", Values.Types)}");
        return WithAssembly(assembly, path, s =>
        {
            var found = Values.Find(s.Scan, Embedded.Find(s.Scan, Limits, ct), ct);
            if (types is { Count: > 0 }) found = [.. found.Where(i => types.Contains(i.Type))];
            return new ValueReport(s.Label, found.Count, found, s.Scan.Notes);
        }, ct);
    }

    /// <summary>
    /// Finds embedded content. With save or load, writes items as embedded_NN.ext to a dedicated directory; with load,
    /// also loads the .NET assemblies.
    /// </summary>
    public EmbeddedReport ExtractEmbedded(string? assembly, string? path, bool save, string? outputDirectory, bool load, CancellationToken ct,
        bool xorText = false, bool includeMedia = false)
    {
        var (label, source, sha, contents, notes) = assembly == null && ContainerInput(path) is { } container
            ? EmbeddedInContainer(container, xorText, ct)
            : WithAssembly(assembly, path, s =>
                (s.Label, assembly != null ? workspace.Get(assembly).FilePath : Path.GetFullPath(path!), Blob.Sha256(s.Image), Embedded.Find(s.Scan, Limits, ct, xorText), s.Scan.Notes), ct);
        if (!includeMedia && contents.Any(c => Blob.IsMedia(c.Kind)))
        {
            // Images are common and rarely relevant; only counted unless requested.
            var media = contents.Where(c => Blob.IsMedia(c.Kind)).GroupBy(c => c.Kind).Select(g => $"{g.Count()} {g.Key}");
            notes.Add($"Images not listed: {string.Join(", ", media)} (includeMedia=true lists and saves them).");
            contents = contents.Where(c => !Blob.IsMedia(c.Kind)).ToList();
        }
        if (!save && !load && outputDirectory == null) return new EmbeddedReport(label, contents, null, notes);

        var root = UnpackService.PrepareOutput(outputDirectory ?? UnpackService.DefaultOutput(source, sha, "corvus-embedded"), source, sha);
        var written = new List<EmbeddedContent>();
        for (int i = 0; i < contents.Count; i++)
        {
            var p = contents[i];
            var file = Blob.WriteUnique(root, Blob.SafeRelativePath($"embedded_{i + 1:D2}{Extension(p)}", $"embedded_{i + 1:D2}"), p.Bytes);
            string? loadedAs = null;
            if (load && p.Kind == ".NET assembly")
            {
                try { loadedAs = workspace.Load(file).Id; }
                catch (ToolError ex) { notes.Add($"Could not load {Path.GetFileName(file)}: {ex.Message}"); }
            }
            written.Add(p with { SavedTo = file, LoadedAs = loadedAs });
        }
        return new EmbeddedReport(label, written, root, notes);
    }

    /// <summary>The managed assemblies of a container file (not itself an assembly), or null for any other input.</summary>
    private static (string Full, string Sha, List<UnpackService.ManagedAssembly> Assemblies, List<string> Notes)? ContainerInput(string? path)
    {
        if (path == null || Directory.Exists(Path.GetFullPath(path)) || !File.Exists(path)) return null;
        var (full, bytes) = ReadFile(path);
        if (Blob.Identify(bytes) == ".NET assembly") return null;
        var managed = UnpackService.Managed(full, Limits, CancellationToken.None);
        return managed.Assemblies.Count == 0 ? null : (full, Blob.Sha256(bytes), managed.Assemblies, managed.Notes);
    }

    /// <summary>Embedded content of every managed assembly in a container; each source starts with the assembly's inner path.</summary>
    private static (string, string, string, List<EmbeddedContent>, List<string>) EmbeddedInContainer(
        (string Full, string Sha, List<UnpackService.ManagedAssembly> Assemblies, List<string> Notes) container, bool xorText, CancellationToken ct)
    {
        var contents = new List<EmbeddedContent>();
        var notes = new List<string>(container.Notes);
        foreach (var a in container.Assemblies)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var module = LoadModule(a.Bytes, a.Path);
                Guard(a.Path, () =>
                {
                    var scan = ModuleScan.Of(module, Limits, ct);
                    contents.AddRange(Embedded.Find(scan, Limits, ct, xorText).Select(c => c with { Source = $"{a.Path}: {c.Source}" }));
                    notes.AddRange(scan.Notes.Select(n => $"{a.Path}: {n}"));
                    return 0;
                });
            }
            catch (ToolError ex) { notes.Add(ex.Message); }
        }
        notes.Insert(0, $"{container.Assemblies.Count} assemblies in the container searched.");
        return (Path.GetFileName(container.Full), container.Full, container.Sha, contents, notes);
    }

    private static string Extension(EmbeddedContent p) => p.Kind switch
    {
        ".NET assembly" => ".dll",
        "native PE" or "NativeAOT executable" => p.Detail?.EndsWith("DLL", StringComparison.Ordinal) == true ? ".dll" : ".exe", // .exe is defanged on write
        "zip" => ".zip",
        "gzip" => ".gz",
        "text" => ".txt",
        _ => ".bin",
    };

    public FileSummary Summarize(string? assembly, string? path, CancellationToken ct)
    {
        if ((assembly == null) == (path == null))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass either assembly (an assembly loaded in the workspace) or path (a file).");
        if (assembly != null)
        {
            return workspace.Read(() =>
            {
                var asm = workspace.Get(assembly);
                var file = Facts(asm.FilePath, asm.OriginalBytes);
                var one = Guard(asm.Id, () => SummarizeAssembly(Path.GetFileName(asm.FilePath), asm.Module, ModuleScan.Of(asm, Limits, ct), asm.OriginalBytes, ct));
                var notes = asm.IsDirty ? new List<string> { "The assembly has unsaved edits: the code scanned is the edited module; hashes and signature are the file's." } : [];
                notes.AddRange(MappingNotes(asm.OriginalBytes));
                return new FileSummary(file, "none (loaded assembly)", [one], one.Highlights, notes);
            });
        }

        var (full, bytes) = ReadFile(path!);
        var facts = Facts(full, bytes);
        var fileHighlights = new List<string>();
        if (facts.Certificate is { Present: true } fileSig) fileHighlights.AddRange(SignatureHighlights(fileSig, "the file"));
        if (UnityLayout.FileHint(full, bytes) is { } layout) fileHighlights.Add(layout);
        var viewNotes = new List<string>();
        var views = Views(new FileInput(full, bytes, facts.Type), viewNotes, ct);
        foreach (var v in views.Values) fileHighlights.AddRange(v.Highlights);
        FileSummary WithViews(FileSummary s)
        {
            var native = views.GetValueOrDefault("native")?.Detail as NativeFileView.Facts;
            return s with
            {
                NativeImage = native?.Image, Packers = native?.Packers, NativeAot = native?.NativeAot,
                Android = views.GetValueOrDefault("android")?.Detail as Mobile.AndroidPackageFacts,
                Electron = views.GetValueOrDefault("electron")?.Detail as ElectronFacts,
                Go = views.GetValueOrDefault("go")?.Detail as GoBuildFacts,
                Views = views,
            };
        }
        (string Source, string Container, List<UnpackService.ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries) managed;
        try { managed = UnpackService.Managed(full, Limits, ct); }
        catch (ToolError ex)
        {
            return WithViews(new FileSummary(facts, "unreadable container", [], [.. fileHighlights, $"The file is damaged: {ex.Message}"], [ex.Message, .. viewNotes]));
        }
        var reportNotes = new List<string>(managed.Notes);
        reportNotes.AddRange(MappingNotes(bytes));
        var summarized = new List<AssemblySummary>();
        // Order: host, main, libraries, framework; satellite assemblies are skipped.
        var ranked = managed.Assemblies.Select((a, i) => (a, i, Rank: Rank(a, full))).ToList();
        var satellites = ranked.Count(r => r.Rank == AssemblyRank.Satellite);
        var candidates = ranked.Where(r => r.Rank != AssemblyRank.Satellite).OrderBy(r => r.Rank).ThenBy(r => r.i).ToList();
        var found = new List<(string Path, IReadOnlyList<string> Highlights)>(); // captured before Brief() drops them
        var copies = new Dictionary<string, List<string>>(StringComparer.Ordinal); // identity -> other builds of the same assembly
        foreach (var (a, _, rank) in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (summarized.Count >= MaxSummarizedAssemblies) break;
            try
            {
                using var module = LoadModule(a.Bytes, a.Path);
                var identity = module.Assembly?.FullName ?? module.Name.String;
                if (copies.TryGetValue(identity, out var paths)) { paths.Add(a.Path); continue; } // e.g. per-TFM builds in one package
                copies[identity] = [];
                var one = Guard(a.Path, () => SummarizeAssembly(a.Path, module, ModuleScan.Of(module, Limits, ct), a.Bytes, ct));
                if (rank == AssemblyRank.Framework)
                    one = one with { Highlights = one.Highlights.Where(IsProblem).ToList() }; // framework capabilities are not findings
                found.Add((one.Path, one.Highlights));
                summarized.Add(summarized.Count == 0 ? one : Brief(one));
            }
            catch (ToolError ex)
            {
                reportNotes.Add(ex.Message);
                if (managed.Container.StartsWith("none", StringComparison.Ordinal))
                    fileHighlights.Add($"The .NET metadata is damaged: {ex.Message}");
            }
        }
        foreach (var (identity, paths) in copies.Where(c => c.Value.Count > 0))
            reportNotes.Add($"{identity.Split(',')[0]}: {paths.Count} more build(s) of the same assembly not summarized ({string.Join(", ", paths.Take(6))}).");
        int skipped = candidates.Count - summarized.Count - copies.Sum(c => c.Value.Count);
        if (skipped > 0)
            reportNotes.Add($"Summarized {summarized.Count} of {candidates.Count} assemblies (the app's own first, framework libraries last; the first in full, " +
                            "the others in brief); list_assemblies with path lists them all, summarize_file on an extracted one (unpack_container) gives its details.");
        else if (summarized.Count > 1)
            reportNotes.Add("The first assembly is summarized in full, the others in brief: summarize_file on an extracted one (unpack_container) gives its details.");
        if (satellites > 0)
            reportNotes.Add($"{satellites} satellite resource assembly(ies) (translations) not summarized.");
        if (managed.Assemblies.Count == 0)
            reportNotes.Add("No managed assemblies inside: nothing to summarize beyond the file facts.");

        var highlights = new List<string>(fileHighlights);
        foreach (var (assemblyPath, list) in found)
            highlights.AddRange(found.Count == 1 ? list : list.Select(h => $"[{assemblyPath}] {h}"));
        reportNotes.AddRange(viewNotes);
        return WithViews(new FileSummary(facts, managed.Container, summarized, highlights.Distinct().ToList(), reportNotes));
    }

    /// <summary>Every <see cref="IFileSummaryView"/> that applies to the file, by name; a view that fails is a note.</summary>
    private static Dictionary<string, FileView> Views(FileInput file, List<string> notes, CancellationToken ct)
    {
        var views = new Dictionary<string, FileView>(StringComparer.Ordinal);
        foreach (var provider in Providers.Of<IFileSummaryView>())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (provider.Inspect(file, ct) is { } view) views[provider.Name] = view;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                notes.Add($"The {provider.Name} view could not read the file: {ex.Message}");
            }
        }
        return views;
    }

    private static IEnumerable<string> MappingNotes(byte[] bytes) =>
        PeImage.TryParse(bytes) is { Overlaps.Count: > 0 } pe
            ? [$"PE section mappings overlap ({string.Join("; ", pe.Overlaps)}); RVAs mapped differently by both are ambiguous and not read."]
            : [];

    private enum AssemblyRank { Host, Main, Library, Framework, Satellite }

    /// <summary>Reduced form for secondary assemblies: no evidence, values or content list.</summary>
    private static AssemblySummary Brief(AssemblySummary a) => a with
    {
        Features = a.Features.Select(f => f with { Evidence = [] }).ToList(),
        Values = a.Values with { Top = [] },
        Wrapping = new WrappingFacts(a.Wrapping.EmbeddedAssemblies.Take(3).ToList(), [], a.Wrapping.HighEntropySections) { EmbeddedAssemblyTotal = a.Wrapping.EmbeddedAssemblyTotal },
        Identity = a.Identity with { References = a.Identity.References.Take(5).ToList() },
        Notes = a.Notes.Take(3).ToList(),
        Highlights = [], // aggregated into the file's highlights
    };

    // Public key tokens of Microsoft framework assemblies.
    private static readonly HashSet<string> FrameworkTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", "cc7b13ffcd2ddd51", "adb9793829ddae60", "7cec85d7bea7798e",
    };

    /// <summary>Summary ordering rank of a contained assembly.</summary>
    private static AssemblyRank Rank(UnpackService.ManagedAssembly a, string source)
    {
        if (a.Origin == UnpackService.HostOrigin) return AssemblyRank.Host;
        var file = a.Path.Replace('\\', '/');
        var name = Path.GetFileNameWithoutExtension(file);
        if (name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)) return AssemblyRank.Satellite;
        if (name.Equals(Path.GetFileNameWithoutExtension(source), StringComparison.OrdinalIgnoreCase)) return AssemblyRank.Main;
        try
        {
            using var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(a.Bytes, writable: false));
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            var key = md.GetBlobBytes(md.GetAssemblyDefinition().PublicKey);
            if (key.Length > 0)
            {
                var token = Convert.ToHexStringLower(System.Security.Cryptography.SHA1.HashData(key).AsSpan(^8).ToArray().Reverse().ToArray());
                if (FrameworkTokens.Contains(token)) return AssemblyRank.Framework;
            }
        }
        catch (Exception) { }
        return AssemblyRank.Library;
    }

    /// <summary>Highlights reported even for framework assemblies: toolchain markers, changes after signing, container wrapping, invalid IL.</summary>
    private static bool IsProblem(string h) =>
        h.StartsWith("Processed with", StringComparison.Ordinal) || h.Contains("does not match", StringComparison.Ordinal)
        || h.Contains("does not verify", StringComparison.Ordinal) || h.Contains("unreadable", StringComparison.Ordinal)
        || h.StartsWith("High-entropy", StringComparison.Ordinal) || h.Contains("not valid IL", StringComparison.Ordinal);

    private static FileFacts Facts(string path, byte[] bytes) =>
        new(path, bytes.Length, Blob.Md5(bytes), Blob.Sha1(bytes), Blob.Sha256(bytes), Blob.Identify(bytes), Math.Round(Blob.Entropy(bytes), 2),
            PeImage.TryParse(bytes) != null ? Certificates.Read(bytes) : new CertificateInfo(false));

    private static AssemblySummary SummarizeAssembly(string path, ModuleDef module, ModuleScan scan, byte[] image, CancellationToken ct)
    {
        var notes = new List<string>(scan.Notes);
        var pe = PeImage.TryParse(image);
        var identity = Identity(module, image, pe);
        var signature = new SignatureFacts(pe != null && (pe.CorFlags(image) & 0x8) != 0, Token(module),
            pe != null ? Certificates.Read(image) : new CertificateInfo(false));
        var markers = Markers.Detect(scan);

        var embedded = new List<string>();
        try
        {
            var inner = Containers.Open(image, path, Limits, ct);
            embedded.AddRange(inner.Items.Where(i => Blob.Identify(i.Bytes) == ".NET assembly").Select(i => $"{i.Name} ({i.Origin})"));
        }
        catch (ToolError ex) { notes.Add(ex.Message); }
        var contents = Embedded.Find(scan, Limits, ct);
        var sections = pe == null ? [] : HighEntropySections(module, pe, image);
        var media = contents.Where(c => Blob.IsMedia(c.Kind)).ToList();
        var listed = contents.Where(c => !Blob.IsMedia(c.Kind)).Take(MaxSummaryContents).ToList();
        if (media.Count > 0 || listed.Count < contents.Count - media.Count)
            notes.Add($"Embedded content: {contents.Count} item(s), {listed.Count} listed" +
                      (media.Count > 0 ? $"; images not listed: {string.Join(", ", media.GroupBy(m => m.Kind).Select(g => $"{g.Count()} {g.Key}"))}" : "") +
                      ". extract_embedded lists everything.");
        int embeddedTotal = embedded.Count;
        if (embedded.Count > MaxSummaryEmbeddedAssemblies)
        {
            notes.Add($"{embedded.Count} embedded assemblies, {MaxSummaryEmbeddedAssemblies} listed; list_assemblies with path lists them all.");
            embedded = embedded.Take(MaxSummaryEmbeddedAssemblies).ToList();
        }
        var wrapping = new WrappingFacts(embedded, listed, sections) { EmbeddedAssemblyTotal = embeddedTotal };

        // Keep one evidence line, preferring strings / native imports over APIs, with one location.
        var features = Features.Detect(scan, ct)
            .Select(f => f with
            {
                Evidence = f.Evidence.OrderBy(e => e.Feature.StartsWith("api:", StringComparison.Ordinal) ? 1 : 0).Take(1)
                    .Select(e => e with { Locations = e.Locations.Take(1).ToList() }).ToList(),
            }).ToList();
        var values = Values.Find(scan, contents, ct);
        var valueSummary = new ValueSummary(values.Count, values.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count()), values.Take(TopValues).ToList());
        var entryPoints = EntryPoints.Find(module, image);
        var health = IlHealth.Assess(image, ct);
        if (health.Invalid > 0) notes.Add(health.Describe());

        return new AssemblySummary(path, Blob.Sha256(image), identity, signature, markers, wrapping, features, valueSummary, entryPoints,
            [.. health.MostlyInvalid ? ["Method bodies are not valid IL (encrypted or dumped before decryption)"] : Array.Empty<string>(),
             .. Highlights(identity, signature, markers, wrapping, features, valueSummary, entryPoints)], notes);
    }

    private static IdentityFacts Identity(ModuleDef module, byte[] image, PeImage? pe)
    {
        string? tfm = null;
        try
        {
            tfm = module.Assembly?.CustomAttributes.Find("System.Runtime.Versioning.TargetFrameworkAttribute")?.ConstructorArguments.FirstOrDefault().Value?.ToString();
        }
        catch (Exception) { }
        var kind = module.Kind switch
        {
            ModuleKind.Console => "console application",
            ModuleKind.Windows => "GUI application",
            ModuleKind.Dll => "library",
            _ => "netmodule",
        };
        string arch = "unknown";
        if (pe != null)
        {
            uint flags = pe.CorFlags(image);
            arch = pe.Machine == 0x14c && (flags & 0x1) != 0 && (flags & 0x2) == 0
                ? (flags & 0x20000) != 0 ? "AnyCPU (32-bit preferred)" : "AnyCPU"
                : pe.MachineName;
        }
        List<TypeDef> types;
        try { types = MetadataUtil.CountedTypes(module); } catch (Exception) { types = []; }
        List<string> references;
        try { references = module.GetAssemblyRefs().Select(r => $"{r.Name} {r.Version}").Take(100).ToList(); } catch (Exception) { references = []; }
        return new IdentityFacts(module.Assembly?.Name.String ?? module.Name.String, module.Assembly?.Version?.ToString(), module.Mvid?.ToString() ?? "",
            tfm, kind, arch, AssemblyTraits.IsReadyToRun(image), AssemblyTraits.MergeNote(module), types.Count, types.Sum(t => t.Methods.Count), references);
    }

    /// <summary>
    /// PE sections with entropy 7.2+, excluding the managed resources span (compressed resources in .text are normal).
    /// </summary>
    private static List<string> HighEntropySections(ModuleDef module, PeImage pe, byte[] image)
    {
        (long Start, long End) resources = (0, 0);
        if (module is ModuleDefMD md && md.Metadata.ImageCor20Header.Resources is { Size: > 0 } dir)
        {
            long at = pe.RvaToOffset((uint)dir.VirtualAddress);
            if (at > 0) resources = (at, at + dir.Size);
        }
        var result = new List<string>();
        foreach (var sec in pe.Sections)
        {
            if (sec.RawSize < 4096 || sec.RawPointer + (long)sec.RawSize > image.Length) continue;
            long start = sec.RawPointer, end = start + sec.RawSize;
            var parts = resources.End > start && resources.Start < end
                ? new[] { (start, Math.Max(start, resources.Start)), (Math.Min(end, resources.End), end) }
                : new[] { (start, end) };
            var bytes = parts.Where(p => p.Item2 > p.Item1).SelectMany(p => image.AsSpan((int)p.Item1, (int)(p.Item2 - p.Item1)).ToArray()).ToArray();
            if (bytes.Length < 4096) continue;
            double entropy = Blob.Entropy(bytes);
            if (entropy >= 7.2) result.Add($"{sec.Name} (entropy {entropy:F2}{(bytes.Length < sec.RawSize ? ", managed resources excluded" : "")})");
        }
        return result;
    }

    private static string? Token(ModuleDef module)
    {
        var token = module.Assembly?.PublicKeyToken;
        return token == null || token.IsNullOrEmpty ? null : token.ToString();
    }

    /// <summary>Categories whose ATT&amp;CK-mapped features appear in highlights.</summary>
    private static readonly HashSet<string> NotableCategories = new(StringComparer.Ordinal)
    {
        "injection", "persistence", "collection", "credential access", "anti-analysis", "defense evasion", "privilege escalation",
        "impact", "code loading", "execution",
    };

    private static List<string> Highlights(IdentityFacts identity, SignatureFacts signature, MarkerFacts markers, WrappingFacts wrapping,
        IReadOnlyList<Feature> features, ValueSummary values, IReadOnlyList<EntryPoint> entryPoints)
    {
        var h = new List<string>();
        foreach (var tool in markers.Tools) h.Add($"Processed with {tool} (toolchain marker found).");
        h.AddRange(markers.Indicators.Take(2));
        if (signature.Certificate is { Present: true } sig) h.AddRange(SignatureHighlights(sig, "the assembly"));
        if (identity.Merged != null) h.Add(identity.Merged);
        if (wrapping.EmbeddedAssemblyTotal > 0) h.Add($"{wrapping.EmbeddedAssemblyTotal} embedded assembly(ies) (Costura or similar).");
        // Costura assemblies and PDBs are already counted above.
        foreach (var p in wrapping.Contents.Where(c => !(c.Source.StartsWith("resource 'costura.", StringComparison.OrdinalIgnoreCase)
                                                         && c.Kind is ".NET assembly" or "portable pdb" or "pdb")).Take(5))
        {
            var how = p.Encoding.Count > 0 ? $", encoded as {string.Join(" > ", p.Encoding)}" : "";
            h.Add(p.Kind.StartsWith("high-entropy", StringComparison.Ordinal)
                ? $"High-entropy data ({p.Size:N0} bytes, possibly encrypted) in {p.Source}."
                : $"Embedded {p.Kind}{(p.Detail != null && p.Kind != "text" ? $" ({p.Detail})" : "")} in {p.Source}{how}.");
        }
        if (wrapping.Contents.Count > 5) h.Add($"{wrapping.Contents.Count - 5} more embedded item(s) listed.");
        foreach (var s in wrapping.HighEntropySections) h.Add($"High-entropy PE section {s}: wrapped or encrypted code?");
        foreach (var c in features.Where(c => c.Attack != null && NotableCategories.Contains(c.Category)
                                                  || c.Attack is "T1105" or "T1102" or "T1095"))
            h.Add($"Can {c.Name} ({c.Attack} {c.AttackName}).");
        var network = new[] { "url", "domain", "ipv4", "ipv6" }.Where(values.ByType.ContainsKey).Select(t => $"{values.ByType[t]} {t}").ToList();
        if (network.Count > 0) h.Add($"Network values: {string.Join(", ", network)}.");
        foreach (var e in entryPoints.Where(e => e.Kind is not "Main"))
            h.Add($"Entry point: {e.Kind}: {e.Member}.");
        return h;
    }

    private static IEnumerable<string> SignatureHighlights(CertificateInfo sig, string what)
    {
        if (sig.Problem != null) yield return $"Authenticode signature on {what} is unreadable: {sig.Problem}.";
        else if (sig.DigestMatches == false) yield return $"Authenticode digest of {what} does not match: it was modified after signing.";
        else if (sig.SignatureValid == false) yield return $"Authenticode signature of {what} does not verify.";
        else yield return $"{char.ToUpperInvariant(what[0])}{what[1..]} is Authenticode-signed by {sig.Signer} ({sig.Chain}).";
    }
}
