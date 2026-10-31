using System.Text.Json.Serialization;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.NativeAot;

namespace Corvus.Services.Analysis;

/// <summary>Static analyses of a loaded assembly or a file: features, typed values, embedded content and file summaries.</summary>
public sealed class InspectionService(AssemblyWorkspace workspace, NativeCodeService? code = null, Mobile.DexService? dex = null,
    AotNavigator? aot = null, AotStringService? literals = null)
{
    private static AnalysisLimits Limits => AnalysisLimits.Default;
    private const int MaxSummarizedAssemblies = 8;
    private const int MaxSummaryContents = 5;
    private const int MaxSummaryEmbeddedAssemblies = 10;
    private const int TopValues = 10;

    /// <summary>summarize_file streams a file above this size (<see cref="FileInput.StreamAbove"/>; lower in tests).</summary>
    public long StreamAbove { get; init; } = FileInput.StreamAbove;

    public sealed record FeatureReport(string Assembly, int MethodsScanned, IReadOnlyList<Feature> Features, IReadOnlyList<string> Notes);

    public sealed record ValueReport(string Assembly, int Total, IReadOnlyList<ExtractedValue> Values, IReadOnlyList<string> Notes)
    {
        /// <summary>Why some assemblies or assets were not read; null when every one meant to be read was.</summary>
        public string? Partial { get; init; }

        /// <summary>What Partial counts: "assemblies", "assets" or both, as the coverage record names its limitations.</summary>
        public IReadOnlyList<string> PartialIn { get; init; } = ["assemblies"];
    }

    /// <summary>Bounds of an asset read: bytes (at most <see cref="AssetFileStrings.MaxBytes"/>), an optional time limit that keeps what was read, and the layout cache folder (null: default).</summary>
    public sealed record AssetReadLimits(long MaxBytes, TimeSpan? Time = null, string? AotCache = null)
    {
        public static readonly AssetReadLimits Default = new(AssetFileStrings.MaxBytes);
    }

    public sealed record EmbeddedReport(string Assembly, IReadOnlyList<EmbeddedContent> Contents,
        string? OutputDirectory, IReadOnlyList<string> Notes);

    public sealed record FileFacts(string Path, long Size, string Md5, string Sha1, string Sha256, string Type, double Entropy, CertificateInfo Certificate)
    {
        /// <summary>The import hash of a PE image with regular imports (MD5 over "library.function" terms, as pefile computes it); null otherwise.</summary>
        public string? Imphash { get; init; }

        /// <summary>The TLSH digest ("T1" form); null when the input has none, with the reason in <see cref="TlshAbsent"/>.</summary>
        public string? Tlsh { get; init; }

        /// <summary>Why <see cref="Tlsh"/> is null; null when it is present.</summary>
        public string? TlshAbsent { get; init; }
    }

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
        IReadOnlyList<string> Highlights, IReadOnlyList<string> Notes)
    {
        /// <summary>With <see cref="FileViewOptions.Stix"/>: network values up to <see cref="MaxNetworkValues"/> + 1 (a cut shows); null otherwise.</summary>
        [JsonIgnore] public IReadOnlyList<ExtractedValue>? NetworkValues { get; init; }
    }

    /// <summary>The network values a STIX bundle lists per file; beyond it the bundle is labelled partial.</summary>
    public const int MaxNetworkValues = 5_000;

    private static readonly HashSet<string> NetworkTypes = new(StringComparer.Ordinal) { "url", "domain", "ipv4", "ipv6", "email" };

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

        /// <summary>The findings of every view that applies, strongest first; empty when none found anything.</summary>
        public IReadOnlyList<Finding> Findings() => [.. Views.Values.SelectMany(v => v.Findings).OrderByDescending(f => FindingLevel.Rank(f.Level))];
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

    /// <summary>Converts exceptions from dnlib's lazy metadata reads into a ToolError.</summary>
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

    /// <summary>A source folder summarized by its package view: what it runs on open, install, checkout or build.</summary>
    private static FileSummary SourceFolder(string folder, CancellationToken ct)
    {
        var view = PackageFileView.Of(Web.Packages.PackageReview.Review(folder, ct)!);
        var facts = new FileFacts(folder, 0, "", "", "", "folder", 0, new CertificateInfo(false));
        return new FileSummary(facts, "folder", [], [.. view.Highlights, "A folder: list_assemblies with path lists the assemblies it holds."], [])
            { Views = new Dictionary<string, FileView> { ["package"] = view } };
    }

    /// <summary>The file for summarize_file: any size, streamed above <see cref="StreamAbove"/>.</summary>
    private FileInput OpenInput(string path)
    {
        if (Directory.Exists(Path.GetFullPath(path))) throw new ToolError(ErrorCode.InvalidArgument, $"{Path.GetFullPath(path)} is a directory; pass a file (list_assemblies with path lists the assemblies a folder or container holds).");
        var full = InputFiles.RequireRegularFile(path);
        if (!File.Exists(full)) throw Targets.FileNotFound(path);
        return FileInput.Open(full, StreamAbove);
    }

    private static ModuleDefMD LoadModule(byte[] bytes, string label)
    {
        try { return MetadataRows.Load(bytes); }
        catch (Exception ex) { throw new ToolError(ErrorCode.MalformedInput, $"{label}: unreadable .NET metadata ({ex.Message})."); }
    }

    public FeatureReport SurveyFeatures(string? assembly, string? path, string? category, CancellationToken ct) => Survey(assembly, path, category, true, ct);

    /// <summary>A loaded build's survey with kept capa labels, never running capa; CapaLabelled false means its labels are unknown.</summary>
    public (FeatureReport Report, bool CapaLabelled) BuildSurvey(string assembly, CancellationToken ct)
    {
        var (subject, file, generation) = workspace.Read(() =>
        {
            // A managed assembly of that name wins, as in the survey.
            try { var asm = workspace.Get(assembly); return ((object)asm, asm.FilePath, workspace.Generation); }
            catch (ToolError) when (workspace.FindNative(assembly) is { } n) { return (n, n.FilePath, workspace.Generation); }
        });
        if (subject is LoadedNative { Image: Native.MachO.MachOFile })
            throw new ToolError(ErrorCode.Unsupported, "the comparison reads PE, ELF and .NET builds; survey_features lists a Mach-O build's");
        bool capa = NativeCapa.Cached(file) is { State: "matched" };
        // A native image's index is rebuilt by reanalysis without a workspace edit, so it is part of the key.
        object? index = subject is LoadedNative native && code != null ? code.Index(native, null, ct).GetAwaiter().GetResult() : null;
        if (_surveys.TryGetValue(subject, out var kept) && kept.Generation == generation && kept.Index == index && kept.Capa == capa) return (kept.Report, capa);
        var report = Survey(assembly, null, null, false, ct);
        Interlocked.Increment(ref _surveysRun);
        _surveys.AddOrUpdate(subject, new KeptSurvey(generation, index, capa, report));
        return (report, capa);
    }

    /// <summary>The file of a loaded assembly or native image (a managed assembly of that name wins); not_found when neither is loaded.</summary>
    public string BuildFile(string assembly) => workspace.Read(() =>
    {
        try { return workspace.Get(assembly).FilePath; }
        catch (ToolError) when (workspace.FindNative(assembly) is { } n) { return n.FilePath; }
    });

    /// <summary>The last build survey of each loaded assembly or native image, valid while its key matches.</summary>
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<object, KeptSurvey> _surveys = new();

    private sealed record KeptSurvey(int Generation, object? Index, bool Capa, FeatureReport Report);

    private int _surveysRun;

    /// <summary>Build surveys run rather than reused (tests).</summary>
    internal int SurveysRun => Volatile.Read(ref _surveysRun);

    private FeatureReport Survey(string? assembly, string? path, string? category, bool runCapa, CancellationToken ct)
    {
        if (assembly == null && path != null && AppSurvey(path, ct) is { } app) return Filter(app, category);
        if (NativeSurvey(assembly, path, category, ct) is { } native) return Filter(native, category);
        var aotCapa = assembly != null && runCapa ? CapaSurvey(assembly, ct) : null;
        var file = aotCapa != null ? null : path != null ? Path.GetFullPath(path) : workspace.Read(() => workspace.Get(assembly!).FilePath);
        var labels = file != null ? CapaLabels(file, category, ct) : null;
        var report = WithAssembly(assembly, path, s =>
        {
            var found = new FeatureReport(s.Label, s.Scan.MethodsScanned, Features.Detect(s.Scan, ct), s.Scan.Notes);
            // .NET locations are method tokens, named while the module is open.
            return labels != null ? WithLabels(found, labels, token => s.Module.ResolveToken((uint)token) is IMethod m
                ? $"0x{token:X8} {m.DeclaringType?.FullName}::{m.Name}" : $"0x{token:X8}") : found;
        }, ct);
        if (aotCapa is { } capa)
            report = report with
            {
                Features = [.. report.Features, .. capa.Rules.Select(r => new Feature(r.Name, CapaCategory, [new Evidence(r.Namespace ?? "(no namespace)", r.Matches, r.Methods)]))],
                Notes = [.. report.Notes, $"category {CapaCategory}: rules of {capa.Checker ?? "capa"} over the native binary's direct calls, {capa.State}",
                    .. capa.Notes.Select(n => $"{CapaCategory}: {n}")],
            };
        return Filter(report, category);
    }

    /// <summary>The category of capa's rules; each rule's evidence is its namespace, at the functions it matched.</summary>
    private const string CapaCategory = "capa";

    /// <summary>Most functions named per capa label; the count covers them all.</summary>
    private const int MaxCapaLocations = 5;

    /// <summary>capa's labels of a file: run for category capa, else kept ones; null when none are kept and capa is not set up.</summary>
    private static CapaReport? CapaLabels(string file, string? category, CancellationToken ct)
    {
        if (!string.Equals(category, CapaCategory, StringComparison.OrdinalIgnoreCase))
            return NativeCapa.Cached(file) ?? (Native.Providers.ExternalTools.Locate(Native.Providers.ExternalTools.Capa) != null
                ? new(NativeCapa.NotChecked, null, false, null, [], [$"capa was not run: category={CapaCategory} runs it over the whole file"]) : null);
        return File.Exists(file) ? NativeCapa.Analyze(file, ct)
            : new(NativeCapa.NotChecked, null, false, null, [], [$"capa reads files on disk; {Path.GetFileName(file)} is not one"]);
    }

    /// <summary><paramref name="report"/> plus capa's labels as category capa features; a file-scope label is at "(file)".</summary>
    private static FeatureReport WithLabels(FeatureReport report, CapaReport capa, Func<ulong, string> name) => report with
    {
        Features = [.. report.Features, .. capa.Labels.Select(l =>
        {
            int count = Math.Max(1, l.Addresses.Count);
            List<string> at = l.Addresses.Count == 0 ? ["(file)"] : [.. l.Addresses.Take(MaxCapaLocations).Select(name)];
            return new Feature(l.Name, CapaCategory, [new Evidence(l.Namespace ?? "(no namespace)", count, at),
                .. l.Attack.Select(a => new Evidence($"ATT&CK {a}", count, [])), .. l.Mbc.Select(m => new Evidence($"MBC {m}", count, []))]);
        })],
        Notes = [.. report.Notes, $"category {CapaCategory}: labels of {capa.Checker ?? "capa"} over the whole file, {capa.State}",
            .. capa.Notes.Select(n => $"{CapaCategory}: {n}")],
    };

    /// <summary>capa's capabilities when <paramref name="assembly"/> is a dummy assembly with [Address] attributes; null otherwise.</summary>
    private CapaCapabilities? CapaSurvey(string assembly, CancellationToken ct)
    {
        if (aot == null || literals == null) return null;
        var image = workspace.Read(() => aot.ImageOf(workspace.Get(assembly)));
        return image?.Dump == null ? null : AotCapa.Survey(workspace, image, literals, ct);
    }

    private static FeatureReport Filter(FeatureReport report, string? category) =>
        category == null || category.Equals("all", StringComparison.OrdinalIgnoreCase) ? report : report with
        {
            Features = [.. report.Features.Where(c => c.Category.Equals(category, StringComparison.OrdinalIgnoreCase)
                                                     || (c.Rule?.Masvs?.StartsWith(category, StringComparison.OrdinalIgnoreCase) ?? false))],
        };

    /// <summary>The survey of a loaded native image or a native file indexed for this call; null when the input is not native.</summary>
    private FeatureReport? NativeSurvey(string? assembly, string? path, string? category, CancellationToken ct)
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
                // A managed assembly of that name wins.
                try { workspace.Get(assembly); return null; }
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
        var plist = index.Image is Native.MachO.MachOFile ? AppleFileView.BundleInfo(index.Image.Path) : null;
        var report = NativeReport(index, label, plist, ct);
        if (index.Image is Native.MachO.MachOFile)
            return string.Equals(category, CapaCategory, StringComparison.OrdinalIgnoreCase)
                ? report with { Notes = [.. report.Notes, $"category {CapaCategory}: not checked: capa reads PE, ELF and .NET files"] } : report;
        if (CapaLabels(index.Image.Path, category, ct) is not { } capa) return report;
        var imageBase = index.Image.ImageBase;
        return WithLabels(report, capa, at =>
        {
            var va = capa.Rebase(at, imageBase);
            var named = va >= imageBase && va - imageBase <= uint.MaxValue && index.FunctionAt((uint)(va - imageBase)) is { } f
                ? $" {index.NameAt(f.Start) ?? f.Name}" : "";
            return $"0x{va:X}{named}";
        });
    }

    /// <summary>The rules over a native image's code index; a Mach-O image also gets the Apple app rules (with its bundle's Info.plist).</summary>
    private static FeatureReport NativeReport(NativeCodeIndex index, string label, Core.Mobile.PlistDict? plist, CancellationToken ct)
    {
        var scan = new NativeFeatureScan(index, ct);
        var mobile = index.Image is Native.MachO.MachOFile ? new MobileSubject { Platform = "apple", InfoPlist = plist } : null;
        var found = Features.Detect(scan, ct, mobile);
        var notes = new List<string> { "native image: rules over static and late-bound imports, call arguments, strings, sections and RTTI class names" };
        if (mobile != null) notes.Add($"Apple app rules (MASVS) over Objective-C references, symbols and strings{(plist != null ? " and Info.plist" : "; no bundle Info.plist found")}");
        if (index.Support != CodeSupport.Full) notes.Add(index.SupportNote ?? "instructions are not decoded: imports, strings and sections only");
        notes.AddRange(index.Truncations);
        notes.AddRange(scan.Notes);
        return new FeatureReport(label, index.Functions.Count, found, notes);
    }

    /// <summary>The survey of an Android package, DEX file or .ipa with its platform's rules; null for any other file.</summary>
    private FeatureReport? AppSurvey(string path, CancellationToken ct)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) return null;
        var head = new byte[Math.Min(Core.Mobile.DexFile.HeaderSize, new FileInfo(full).Length)];
        using (var f = File.OpenRead(full)) f.ReadExactly(head);
        if (Core.Mobile.DexFile.IsDex(head)) return AndroidSurvey(full, false, ct);
        if (!Blob.StartsWith(head, "PK\x03\x04"u8)) return null;
        bool android = false, ipa = false;
        try
        {
            using var zip = System.IO.Compression.ZipFile.OpenRead(full);
            foreach (var e in zip.Entries)
            {
                var n = e.FullName;
                ipa |= n.StartsWith("Payload/", StringComparison.Ordinal) && n.EndsWith(".app/Info.plist", StringComparison.Ordinal);
                android |= n is "AndroidManifest.xml" or "base/manifest/AndroidManifest.xml" || (!n.Contains('/') && n.StartsWith("classes", StringComparison.Ordinal) && n.EndsWith(".dex", StringComparison.Ordinal))
                           || n.EndsWith(".apk", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch (InvalidDataException) { return null; }
        if (ipa) return IpaSurvey(full, ct);
        return android ? AndroidSurvey(full, true, ct) : null;
    }

    private FeatureReport AndroidSurvey(string full, bool package, CancellationToken ct)
    {
        var index = dex?.Index(full, ct) ?? Mobile.DexIndex.Load(full, Limits, ct);
        var notes = new List<string> { "Android app: MASVS rules over DEX code, the manifest and the network security config; library packages counted apart" };
        Core.Mobile.AndroidManifestSummary? manifest = null;
        Core.Mobile.AndroidNetworkSecurityConfig? config = null;
        string? configFile = null;
        Dictionary<string, string>? pins = null;
        if (package)
            try
            {
                using var apk = Core.Mobile.AndroidPackage.Open(full, Limits);
                pins = CertificatePins(apk, ct);
                manifest = Core.Mobile.AndroidManifestSummary.Of(apk.Manifest, apk.Resources);
                if (manifest.Application.NetworkSecurityConfig is { } reference && reference.IndexOf(" = res/", StringComparison.Ordinal) is var at and > 0
                    && apk.Read(reference[(at + 3)..]) is { } xml)
                {
                    configFile = reference[(at + 3)..];
                    var doc = Core.Mobile.AxmlDocument.IsAxml(xml) ? Core.Mobile.AxmlDocument.Read(xml) : Core.Mobile.AabProto.ReadXml(xml);
                    config = Core.Mobile.AndroidNetworkSecurityConfig.Of(doc, apk.Resources == null ? null : apk.Resources.Name);
                }
            }
            catch (ToolError e) { notes.Add($"manifest not read: {e.Message}"); }
        var subject = new MobileSubject { Platform = "android", Dex = index, Manifest = manifest, NetworkConfig = config, NetworkConfigFile = configFile, CertificatePins = pins };
        var found = Features.Detect(subject, ct);
        return MobileReport(Path.GetFileName(full), index.Methods.Count, found, [.. notes, .. index.Notes.Take(5), .. subject.Notes]);
    }

    /// <summary>SHA-256 SPKI digests of the certificate files a package carries outside META-INF (at most 200 files of 1 MB), to "file #index subject".</summary>
    private static Dictionary<string, string> CertificatePins(Core.Mobile.AndroidPackage apk, CancellationToken ct)
    {
        var pins = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in apk.Entries.Where(n => !n.StartsWith("META-INF/", StringComparison.Ordinal) && CertificateFile.HasCertificateExtension(n)).Take(200))
        {
            if (apk.Length(name) is <= 0 or > 1 << 20 || apk.Read(name) is not { } bytes) continue;
            try
            {
                foreach (var c in CertificateFile.Read(bytes, checkMachine: false, ct).Certificates)
                    pins.TryAdd(c.Pin["sha256/".Length..], $"{name} #{c.Index} {c.Subject}");
            }
            catch (InvalidDataException) { }
        }
        return pins;
    }

    private FeatureReport IpaSurvey(string full, CancellationToken ct)
    {
        var (_, bytes) = ReadFile(full);
        if (AppleFileView.IpaApp(bytes, Limits.MaxItemBytes) is not { } app)
            throw new ToolError(ErrorCode.MalformedInput, $"{full}: no readable Payload/*.app main executable.", $"summarize_file path={full} view=apple describes the bundle");
        Native.INativeImage image;
        try { image = Native.NativeImageLoader.FromBytes(app.Bytes, app.Executable); }
        catch (Exception ex) when (ex is ToolError or InvalidOperationException or ArgumentException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{app.Executable}: not a readable Mach-O image ({ex.Message}).");
        }
        var report = NativeReport(NativeCodeIndex.Build(image, ct: ct), app.Executable, app.Info, ct);
        return report with { Notes = [$"{app.Executable}: the app's main executable; frameworks are not scanned", .. report.Notes] };
    }

    /// <summary>Drops weakness findings seen only in library code, naming them in a note.</summary>
    private static FeatureReport MobileReport(string label, int methods, List<Feature> found, List<string> notes)
    {
        var libraryOnly = found.Where(f => f.Rule != null && f.Evidence.All(e => e.Count == 0)).ToList();
        if (libraryOnly.Count > 0)
            notes.Add("In library code only, left out: " + string.Join(", ", libraryOnly.Select(f => $"{f.Rule!.Id} ({f.Evidence.Sum(e => e.Library ?? 0)})")));
        return new FeatureReport(label, methods, [.. found.Except(libraryOnly)], notes);
    }

    /// <summary>Typed values by type order, count descending, then value; asset inputs are read within <paramref name="assets"/>.</summary>
    public ValueReport ExtractStrings(string? assembly, string? path, IReadOnlyCollection<string>? types, CancellationToken ct, AssetReadLimits? assets = null)
    {
        types = types?.Select(t => t.Trim().ToLowerInvariant()).Where(t => t.Length > 0).ToList();
        var unknown = types?.Where(t => !Values.Types.Contains(t)).ToList();
        if (unknown is { Count: > 0 })
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown value type(s): {string.Join(", ", unknown)}.", $"pass types from: {string.Join(", ", Values.Types)}");
        if (assembly == null && path != null && (File.Exists(path) || Directory.Exists(path)))
        {
            assets ??= AssetReadLimits.Default;
            // The time limit stops extraction and reading with what was read; ct still cancels.
            using var time = new CancellationTokenSource();
            if (assets.Time is { } t)
            {
                if (t > TimeSpan.Zero) time.CancelAfter(t);
                else time.Cancel();
            }
            if (AssetInput(path, time.Token, ct) is { } assetInput)
            {
                var key = AssetReadKey(path, assetInput, types, assets);
                lock (LastAssetRead)
                    if (LastAssetRead.Key == key && DateTime.UtcNow - LastAssetRead.At < AssetReadReuse) return LastAssetRead.Report!;
                var report = StringsInAssets(assetInput, types, assets, time.Token, ct);
                lock (LastAssetRead) (LastAssetRead.Key, LastAssetRead.At, LastAssetRead.Report) = (key, DateTime.UtcNow, report);
                return report;
            }
        }
        if (assembly == null && ContainerInput(path) is { } container) return StringsInContainer(container, types, ct);
        return WithAssembly(assembly, path, s =>
        {
            var found = Values.Find(s.Scan, Embedded.Find(s.Scan, Limits, ct), out int encodedDropped, ct);
            if (types is { Count: > 0 }) found = [.. found.Where(i => types.Contains(i.Type))];
            return new ValueReport(s.Label, found.Count, found, s.Scan.Notes) { Partial = encodedDropped > 0 ? EncodedGap(encodedDropped) : null };
        }, ct);
    }

    /// <summary>Typed values of up to <see cref="MaxSummarizedAssemblies"/> own assemblies of a container; Partial names those not read.</summary>
    // Host, main, then libraries; framework assemblies only when there are no others; satellites and duplicates skipped.
    private static ValueReport StringsInContainer((string Full, string Sha, List<UnpackService.ManagedAssembly> Assemblies, List<string> Notes) container,
        IReadOnlyCollection<string>? types, CancellationToken ct)
    {
        var notes = new List<string>(container.Notes);
        var ranked = container.Assemblies.DistinctBy(a => a.Sha256).Select((a, i) => (a, i, Rank: Rank(a, container.Full)))
            .Where(r => r.Rank != AssemblyRank.Satellite).OrderBy(r => r.Rank).ThenBy(r => r.i).ToList();
        var own = ranked.Where(r => r.Rank != AssemblyRank.Framework).Select(r => r.a).ToList();
        int framework = ranked.Count - own.Count;
        var chosen = own.Count > 0 ? own : ranked.Select(r => r.a).ToList();
        var unread = new List<string>();
        var parts = AssemblyValues(chosen.Take(MaxSummarizedAssemblies), notes, unread, out int encodedDropped, ct);
        var found = Values.Join(parts);
        if (types is { Count: > 0 }) found = [.. found.Where(i => types.Contains(i.Type))];
        int read = Math.Min(chosen.Count, MaxSummarizedAssemblies) - unread.Count;
        notes.Insert(0, $"{read} of the container's {chosen.Count} {(own.Count > 0 ? "own" : "framework")} assemblies read" +
                        (own.Count > 0 && framework > 0 ? $"; {framework} framework assemblies skipped" : "") + ".");
        var gaps = new List<string>();
        if (chosen.Count > MaxSummarizedAssemblies) gaps.Add($"the first {MaxSummarizedAssemblies} of {chosen.Count} assemblies are read, host and main first");
        if (unread.Count > 0) gaps.Add($"{unread.Count} assemblies are unreadable ({string.Join(", ", unread.Take(3))})");
        if (encodedDropped > 0) gaps.Add(EncodedGap(encodedDropped));
        return new ValueReport(Path.GetFileName(container.Full), found.Count, found, notes) { Partial = gaps.Count > 0 ? string.Join("; ", gaps) : null };
    }

    // The last asset read is kept briefly so paging sees the same rows a time-limited read produced.
    private static readonly TimeSpan AssetReadReuse = TimeSpan.FromMinutes(5);
    private static readonly AssetRead LastAssetRead = new();

    private sealed class AssetRead
    {
        public string? Key;
        public DateTime At;
        public ValueReport? Report;
    }

    /// <summary>The key of <see cref="LastAssetRead"/>: the path, a hash of every input file's stamp, the types and the limits.</summary>
    private static string AssetReadKey(string path, AssetStringsInput input, IReadOnlyCollection<string>? types, AssetReadLimits assets)
    {
        // Keyed on every file read, not a folder's write time, which a change in a subfolder leaves as it was.
        var files = new System.Text.StringBuilder();
        foreach (var piece in input.Files.SelectMany(f => f.Pieces)) Stamp(piece);
        foreach (var a in input.Assemblies) files.Append(a.Path).Append('|').Append(a.Sha256).Append('\n');
        // Class layouts come from the native build and its cache entry, so both are part of the key.
        if (input.AotBuild is { } build)
        {
            Stamp(build.Metadata);
            if (build.Binary.Length > 0) Stamp(build.Binary);
            files.Append(assets.AotCache).Append('|').Append(AotBuildLoader.CachedDummies(build, assets.AotCache) != null).Append('\n');
        }
        return $"{Path.GetFullPath(path)}|{Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(files.ToString())))}" +
               $"|{string.Join(",", types ?? [])}|{assets.MaxBytes}|{assets.Time?.Ticks}";

        void Stamp(string file)
        {
            var info = new FileInfo(file);
            files.Append(file).Append('|').Append(info.Exists ? info.Length : -1).Append('|').Append(info.Exists ? info.LastWriteTimeUtc.Ticks : 0).Append('\n');
        }
    }

    /// <summary>The typed values of each assembly, by its path; an unreadable one is added to <paramref name="unread"/> with its error in the notes.</summary>
    private static List<(string, IReadOnlyList<ExtractedValue>)> AssemblyValues(IEnumerable<UnpackService.ManagedAssembly> assemblies, List<string> notes,
        List<string> unread, out int encodedDropped, CancellationToken ct)
    {
        var parts = new List<(string, IReadOnlyList<ExtractedValue>)>();
        int dropped = 0;
        foreach (var a in assemblies)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var module = LoadModule(a.Bytes, a.Path);
                parts.Add((a.Path, Guard(a.Path, () =>
                {
                    var scan = ModuleScan.Of(module, Limits, ct);
                    notes.AddRange(scan.Notes.Select(n => $"{a.Path}: {n}"));
                    var values = Values.Find(scan, Embedded.Find(scan, Limits, ct), out int over, ct);
                    if (over > 0) notes.Add($"{a.Path}: {over:N0} encoded values past the first {Values.MaxEncoded} are not listed");
                    dropped += over;
                    return values;
                })));
            }
            catch (ToolError ex)
            {
                unread.Add(a.Path);
                notes.Add(ex.Message);
            }
        }
        encodedDropped = dropped;
        return parts;
    }

    private static string EncodedGap(int dropped) => $"{dropped:N0} encoded values past {Values.MaxEncoded} per assembly are not listed";

    /// <summary>Asset input to read: label, native build above it (null: none), asset files, own assemblies and notes.</summary>
    private sealed record AssetStringsInput(string Label, AotBuildFiles? AotBuild, List<AssetFileStrings.AssetFile> Files, List<UnpackService.ManagedAssembly> Assemblies, int OtherAssemblies,
        bool Aot, List<string> Notes, string? Partial);

    /// <summary>A serialized asset file, a build folder or a package holding one (extracted); null otherwise; a folder without a build is refused with reason not_a_build.</summary>
    private static AssetStringsInput? AssetInput(string? path, CancellationToken stop, CancellationToken ct)
    {
        if (path == null) return null;
        var full = Path.GetFullPath(path);
        var notes = new List<string>();
        string? partial = null;
        if (File.Exists(full) && Core.Assets.SerializedFile.IsAssetFile(full))
        {
            full = InputFiles.RequireRegularFile(path);
            return new(Path.GetFileName(full), AssetFileView.AotBuildAbove(Path.GetDirectoryName(full)!), [new(Path.GetFileName(full), [full])], [], 0, false, notes, null);
        }
        string root;
        if (Directory.Exists(full)) root = full;
        else if (PackageFiles.HoldsPlayerData(full))
        {
            if (AotPackages.Extract(full, null, ct: ct, assets: true, stop: stop) is not { } app) return null;
            root = app;
            notes.Add($"Read from the data folder of {Path.GetFileName(full)}, extracted to {app}.");
            var skipped = AotPackages.SkippedAssets(app);
            if (skipped.Count > 0)
                partial = $"{skipped.Count} package entries are not extracted ({string.Join("; ", skipped.Take(3))})";
        }
        else return null;
        var data = BuildSummary.DataFolder(root, ct);
        if (data == null)
        {
            if (!Directory.Exists(full)) return null;
            throw new ToolError(ErrorCode.Unsupported,
                $"{full} has no <Product>_Data, assets/bin/Data or .app/Data folder in it or 4 folders above: reason not_a_build.",
                "pass a file, or a build folder") { Details = new { reason = "not_a_build", path = full } };
        }
        notes.AddRange(data.Value.Notes);
        var files = AssetFileStrings.Files(data.Value.Data, data.Value.Streaming, notes);
        var managed = Path.Combine(data.Value.Data, "Managed");
        var (own, others) = Directory.Exists(managed) ? BuildOwnAssemblies(managed, data.Value.Data) : (new List<UnpackService.ManagedAssembly>(), 0);
        bool aot = AotBuildFiles.MetadataIn(data.Value.Data) != null || Directory.Exists(Path.Combine(data.Value.Data, "il2cpp_data"))
                      || File.Exists(Path.Combine(managed, "Metadata", AotBuildFiles.MetadataFileName));
        return new(Path.GetFileName(full), AssetFileView.AotBuildAbove(data.Value.Data), files, own, others, aot, notes, partial);
    }

    // Runtime and class library assemblies of a Managed folder; their strings are not the program's own.
    private static readonly string[] EnginePrefixes = ["UnityEngine", "UnityEditor", "Unity.", "Mono.", "System", "Microsoft.", "mscorlib", "netstandard", "Boo.", "UnityScript"];

    /// <summary>The first <see cref="MaxSummarizedAssemblies"/> own assemblies of a Managed folder, Assembly-CSharp first, and the count not read.</summary>
    private static (List<UnpackService.ManagedAssembly>, int) BuildOwnAssemblies(string managed, string data)
    {
        var own = Directory.EnumerateFiles(managed, "*.dll")
            .Where(f => !EnginePrefixes.Any(p => Path.GetFileName(f).StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(f => Path.GetFileNameWithoutExtension(f) switch { "Assembly-CSharp" => 0, "Assembly-CSharp-firstpass" => 1, _ => 2 })
            .ThenBy(f => Path.GetFileName(f), StringComparer.OrdinalIgnoreCase).ToList();
        var read = new List<UnpackService.ManagedAssembly>();
        foreach (var f in own.Take(MaxSummarizedAssemblies))
        {
            var bytes = File.ReadAllBytes(f);
            read.Add(new UnpackService.ManagedAssembly(Path.GetRelativePath(data, f).Replace('\\', '/'), bytes, Blob.Sha256(bytes), "managed folder"));
        }
        return (read, own.Count - read.Count);
    }

    // Largest build files a layout read is attempted on; larger ones are left to load_assembly.
    private const long MaxAotMetadataBytes = 512L << 20, MaxAotBinaryBytes = 2L << 30;

    /// <summary>Reads the build into the dummy assembly cache for class layouts, bounded by size and time; true when this call read it. Nothing stays loaded in the workspace.</summary>
    // Field types are in the binary, so a build without one is not read; an unfinished read leaves its layouts unknown.
    private static bool ReadAotLayouts(AotBuildFiles build, string? cache, List<string> notes, CancellationToken stop, CancellationToken ct)
    {
        const string NotRead = "Build not read for class layouts";
        if (AotBuildLoader.CachedDummies(build, cache) != null) return false;
        if (build.Binary.Length == 0)
        {
            notes.Add($"{NotRead}: field types are in the native binary, which is not beside the metadata.");
            return false;
        }
        long metadata = new FileInfo(build.Metadata).Length, binary = new FileInfo(build.Binary).Length;
        if (metadata > MaxAotMetadataBytes || binary > MaxAotBinaryBytes)
        {
            notes.Add(metadata > MaxAotMetadataBytes
                ? $"{NotRead}: the metadata is {metadata:N0} bytes, over {MaxAotMetadataBytes:N0}; load_assembly the build folder reads it."
                : $"{NotRead}: the binary is {binary:N0} bytes, over {MaxAotBinaryBytes:N0}; load_assembly the build folder reads it.");
            return false;
        }
        if (stop.IsCancellationRequested)
        {
            notes.Add($"{NotRead}: the time limit had passed.");
            return false;
        }
        var watch = System.Diagnostics.Stopwatch.StartNew();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stop);
        try
        {
            using var scratch = new AssemblyWorkspace();
            new AotBuildLoader(scratch, cache).Load(build, loadBinary: false, null, linked.Token);
            notes.Add($"Build read for class layouts in {watch.Elapsed.TotalSeconds:0.0} s; load_assembly reuses it.");
            return true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            notes.Add($"{NotRead}: the time limit ended the read after {watch.Elapsed.TotalSeconds:0.0} s.");
        }
        catch (ToolError e)
        {
            notes.Add($"{NotRead}: {e.Message}");
        }
        return false;
    }

    /// <summary>Typed values of own assemblies and asset fields as one list; Partial names the limits reached and assets left unread.</summary>
    private static ValueReport StringsInAssets(AssetStringsInput input, IReadOnlyCollection<string>? types, AssetReadLimits limits,
        CancellationToken stop, CancellationToken ct)
    {
        var notes = new List<string>(input.Notes);
        var gaps = new List<string>();
        var partialIn = new List<string>();
        if (input.Partial != null)
        {
            gaps.Add(input.Partial);
            partialIn.Add("assets");
        }
        var unread = new List<string>();
        var parts = AssemblyValues(input.Assemblies, notes, unread, out int encodedDropped, ct);
        if (input.Assemblies.Count > 0 || input.OtherAssemblies > 0)
            notes.Add($"{input.Assemblies.Count - unread.Count} of the build's {input.Assemblies.Count + input.OtherAssemblies} own assemblies read; runtime and class library assemblies skipped.");
        if (input.OtherAssemblies > 0 || unread.Count > 0)
        {
            if (input.OtherAssemblies > 0) gaps.Add($"the first {MaxSummarizedAssemblies} own assemblies are read, Assembly-CSharp first");
            if (unread.Count > 0) gaps.Add($"{unread.Count} assemblies are unreadable ({string.Join(", ", unread.Take(3))})");
            partialIn.Add("assemblies");
        }
        if (encodedDropped > 0)
        {
            gaps.Add(EncodedGap(encodedDropped));
            if (!partialIn.Contains("assemblies")) partialIn.Add("assemblies");
        }
        var aot = input.AotBuild;
        if ((input.Aot || aot != null) && input.Assemblies.Count == 0)
            notes.Add("Code strings are in global-metadata.dat, not read here; load_assembly the build folder, then search_strings.");
        var assets = AssetFileStrings.Read(input.Files, limits.MaxBytes, stop, ct, limits.AotCache);
        // The build read takes seconds to minutes, so it runs only when an asset needs a layout from it.
        if (aot != null && assets.Unread > 0 && ReadAotLayouts(aot, limits.AotCache, notes, stop, ct))
            assets = AssetFileStrings.Read(input.Files, limits.MaxBytes, stop, ct, limits.AotCache);
        parts.AddRange(assets.Parts);
        notes.AddRange(assets.Notes);
        if (assets.Partial != null)
        {
            gaps.Add(assets.Partial);
            if (!partialIn.Contains("assets")) partialIn.Add("assets");
        }
        var found = Values.Join(parts);
        if (types is { Count: > 0 }) found = [.. found.Where(i => types.Contains(i.Type))];
        return new ValueReport(input.Label, found.Count, found, notes)
        {
            Partial = gaps.Count > 0 ? string.Join("; ", gaps) : null,
            PartialIn = partialIn.Count > 0 ? partialIn : ["assemblies"],
        };
    }

    /// <summary>Finds embedded content; save or load writes embedded_NN.ext files to a dedicated folder, and load also loads assemblies.</summary>
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
        var zone = new ZoneMark();
        for (int i = 0; i < contents.Count; i++)
        {
            var p = contents[i];
            var file = Blob.WriteUnique(root, Blob.SafeRelativePath($"embedded_{i + 1:D2}{Extension(p)}", $"embedded_{i + 1:D2}"), p.Bytes, zone);
            string? loadedAs = null;
            if (load && p.Kind == ".NET assembly")
            {
                try { loadedAs = workspace.Load(file).Id; }
                catch (ToolError ex) { notes.Add($"Could not load {Path.GetFileName(file)}: {ex.Message}"); }
            }
            written.Add(p with { SavedTo = file, LoadedAs = loadedAs });
        }
        if (zone.Note is { } unmarked) notes.Add(unmarked);
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
        // SafeRelativePath appends .bin to .exe on write.
        "native PE" or "NativeAOT executable" => p.Detail?.EndsWith("DLL", StringComparison.Ordinal) == true ? ".dll" : ".exe",
        "zip" => ".zip",
        "jmod" => ".jmod",
        "gzip" => ".gz",
        "text" => ".txt",
        _ => ".bin",
    };

    public FileSummary Summarize(string? assembly, string? path, CancellationToken ct, FileViewOptions? options = null)
    {
        if ((assembly == null) == (path == null))
            throw new ToolError(ErrorCode.InvalidArgument, "Pass either assembly (an assembly loaded in the workspace) or path (a file).");
        if (assembly != null)
        {
            return workspace.Read(() =>
            {
                var asm = workspace.Get(assembly);
                var file = Facts(asm.FilePath, asm.OriginalBytes);
                var one = Guard(asm.Id, () => SummarizeAssembly(Path.GetFileName(asm.FilePath), asm.Module, ModuleScan.Of(asm, Limits, ct), asm.OriginalBytes, ct, options?.AllNetworkValues == true));
                var notes = asm.IsDirty ? new List<string> { "The assembly has unsaved edits: the code scanned is the edited module; hashes and signature are the file's." } : [];
                notes.AddRange(MappingNotes(asm.OriginalBytes));
                return new FileSummary(file, "none (loaded assembly)", [one], one.Highlights, notes);
            });
        }

        // A bundle folder is summarized through its main executable, whose apple view describes the bundle.
        if (AppleFileView.MainExecutable(path!) is { } executable) path = executable;
        else if (Directory.Exists(Path.GetFullPath(path!))) return SourceFolder(Path.GetFullPath(path!), ct);
        var input = OpenInput(path!);
        input.Options = options ?? FileViewOptions.None;
        var full = input.Path;
        var facts = Facts(input, ct);
        var fileHighlights = new List<string>();
        if (facts.Certificate is { Present: true } fileSig) fileHighlights.AddRange(SignatureHighlights(fileSig, "the file"));
        if (PlayerLayout.FileHint(full, input.Streamed ? input.Head : input.Bytes) is { } layout) fileHighlights.Add(layout);
        var viewNotes = new List<string>();
        var views = Views(input, viewNotes, ct);
        foreach (var v in views.Values) fileHighlights.AddRange(v.Highlights);
        FileSummary WithViews(FileSummary s)
        {
            var native = views.GetValueOrDefault("native")?.Detail as NativeFileView.Facts;
            s = s with
            {
                NativeImage = native?.Image, Packers = native?.Packers, NativeAot = native?.NativeAot,
                Android = views.GetValueOrDefault("android")?.Detail as Mobile.AndroidPackageFacts,
                Electron = views.GetValueOrDefault("electron")?.Detail as ElectronFacts,
                Go = views.GetValueOrDefault("go")?.Detail as GoBuildFacts,
                Views = views,
            };
            if (input.Options.View != "indicators") return s;
            var indicators = IndicatorList.Of(s);
            views["indicators"] = new FileView(indicators, [$"{indicators.Total:N0} indicators ({string.Join(", ", indicators.ByType.Select(t => $"{t.Value:N0} {t.Key}"))})."]);
            return s;
        }
        (string Source, string Container, List<UnpackService.ManagedAssembly> Assemblies, List<string> Notes, List<ContainerEntry>? Entries,
            List<UnpackService.ManagedAssembly> Manifests, List<NameIssue> Names) managed;
        try { managed = UnpackService.Managed(input, facts.Sha256, Limits, ct); }
        catch (ToolError ex)
        {
            return WithViews(new FileSummary(facts, "unreadable container", [], [.. fileHighlights, $"The file is damaged: {ex.Message}"], [ex.Message, .. viewNotes]));
        }
        DependencyView(input, managed.Assemblies, managed.Manifests, views, viewNotes, ct);
        if (ArchiveNameView.Of(managed.Names) is { } entryNames) views["entries"] = entryNames;
        var reportNotes = new List<string>(managed.Notes);
        // The section table is in the headers.
        reportNotes.AddRange(MappingNotes(input.Streamed ? input.Head : input.Bytes));
        if (input.Streamed)
        {
            reportNotes.Add($"Read as a stream ({input.Length:N0} bytes): hashes, captures, databases, zip, HAR, flows, packages and archives in bounded memory.");
            if (input.ImageLength < input.Length)
                reportNotes.Add($"The native image ends at byte {input.ImageLength:N0}; the {input.Length - input.ImageLength:N0} bytes after it (an overlay) are not held.");
        }
        var summarized = new List<AssemblySummary>();
        // Order: host, main, libraries, framework; satellite assemblies are skipped.
        var ranked = managed.Assemblies.Select((a, i) => (a, i, Rank: Rank(a, full))).ToList();
        var satellites = ranked.Count(r => r.Rank == AssemblyRank.Satellite);
        var candidates = ranked.Where(r => r.Rank != AssemblyRank.Satellite).OrderBy(r => r.Rank).ThenBy(r => r.i).ToList();
        // Highlights are captured before Brief() drops them.
        var found = new List<(string Path, IReadOnlyList<string> Highlights)>();
        // Assembly identity to the other builds of it, such as per-TFM builds in one package.
        var copies = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var (a, _, rank) in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (summarized.Count >= MaxSummarizedAssemblies) break;
            try
            {
                using var module = LoadModule(a.Bytes, a.Path);
                var identity = module.Assembly?.FullName ?? module.Name.String;
                if (copies.TryGetValue(identity, out var paths)) { paths.Add(a.Path); continue; }
                copies[identity] = [];
                var one = Guard(a.Path, () => SummarizeAssembly(a.Path, module, ModuleScan.Of(module, Limits, ct), a.Bytes, ct, input.Options.AllNetworkValues));
                // Framework capabilities are not findings.
                if (rank == AssemblyRank.Framework)
                    one = one with { Highlights = one.Highlights.Where(IsProblem).ToList() };
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
            reportNotes.Add($"Summarized {summarized.Count} of {candidates.Count} assemblies (own first, framework last; the first in full, the others in brief); " +
                            "list_assemblies with path lists them all; unpack_container, then summarize_file, details one.");
        else if (summarized.Count > 1)
            reportNotes.Add("The first assembly is summarized in full, the others in brief; unpack_container, then summarize_file, details one.");
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

    /// <summary>Adds view=dependencies, built from the assemblies and manifests already unpacked and the go and rust views.</summary>
    private static void DependencyView(FileInput input, List<UnpackService.ManagedAssembly> assemblies, List<UnpackService.ManagedAssembly> manifests,
        Dictionary<string, FileView> views, List<string> notes, CancellationToken ct)
    {
        try
        {
            var parsed = new List<Dependencies.DepsJson>();
            foreach (var m in manifests)
            {
                if (Dependencies.DepsJson.Parse(m.Path, m.Bytes) is { } deps) parsed.Add(deps);
                else notes.Add($"{m.Path}: not a readable deps.json; its packages are unknown.");
            }
            if (Dependencies.DependencyInventory.Of(input, assemblies, parsed, views, ct) is { } facts)
                views["dependencies"] = new FileView(facts, facts.Advisories is { Findings.Count: > 0 } a
                    ? [$"{a.Findings.Count} advisories for {a.Findings.Select(f => f.Component).Distinct().Count()} components ({a.Checker})."] : []);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            notes.Add($"The dependencies view could not read the file: {ex.Message}");
        }
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
            // A wrong table= or columns= for the view asked for is the caller's error.
            catch (ToolError ex) when (file.Options.View == provider.Name && ex.Code is ErrorCode.InvalidArgument or ErrorCode.NotFound)
            {
                throw;
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
        // Aggregated into the file's highlights.
        Highlights = [],
    };

    // Public key tokens of Microsoft framework assemblies.
    internal static readonly HashSet<string> FrameworkTokens = new(StringComparer.OrdinalIgnoreCase)
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

    private static FileFacts Facts(FileInput input, CancellationToken ct)
    {
        if (!input.Streamed) return Facts(input.Path, input.Bytes);
        var (md5, sha1, sha256, entropy, (tlsh, tlshAbsent)) = input.Hashes(ct);
        CertificateInfo certificate;
        if (PeImage.TryParse(input.Head) == null) certificate = new CertificateInfo(false);
        else
            using (var stream = input.OpenRead()) certificate = Certificates.Read(stream, input.Head);
        return new(input.Path, input.Length, md5, sha1, sha256, input.Kind, Math.Round(entropy, 2), certificate) { Tlsh = tlsh, TlshAbsent = tlshAbsent };
    }

    private static FileFacts Facts(string path, byte[] bytes)
    {
        bool pe = PeImage.TryParse(bytes) != null;
        var (tlsh, tlshAbsent) = Tlsh.Of(bytes);
        return new(path, bytes.Length, Blob.Md5(bytes), Blob.Sha1(bytes), Blob.Sha256(bytes), Blob.Identify(bytes), Math.Round(Blob.Entropy(bytes), 2),
            pe ? Certificates.Read(bytes) : new CertificateInfo(false))
        {
            Imphash = pe ? Imphash(bytes) : null,
            Tlsh = tlsh,
            TlshAbsent = tlshAbsent,
        };
    }

    private static string? Imphash(byte[] bytes)
    {
        try { return Native.Pe.ImportHash.Of(Native.Pe.PeFile.FromBytes(bytes)); }
        catch (Exception e) when (e is not OperationCanceledException) { return null; }
    }

    private static AssemblySummary SummarizeAssembly(string path, ModuleDef module, ModuleScan scan, byte[] image, CancellationToken ct, bool network = false)
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
        var values = Values.Find(scan, contents, out int encodedDropped, ct);
        if (encodedDropped > 0) notes.Add($"{encodedDropped:N0} encoded values past the first {Values.MaxEncoded} are not counted");
        var valueSummary = new ValueSummary(values.Count, values.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count()), values.Take(TopValues).ToList());
        var entryPoints = EntryPoints.Find(module, image);
        var health = IlHealth.Assess(image, ct);
        if (health.Invalid > 0) notes.Add(health.Describe());

        return new AssemblySummary(path, Blob.Sha256(image), identity, signature, markers, wrapping, features, valueSummary, entryPoints,
            [.. health.MostlyInvalid ? ["Method bodies are not valid IL (encrypted or dumped before decryption)"] : Array.Empty<string>(),
             .. Highlights(identity, signature, markers, wrapping, features, valueSummary, entryPoints)], notes)
        {
            NetworkValues = network ? [.. values.Where(v => NetworkTypes.Contains(v.Type)).Take(MaxNetworkValues + 1)] : null,
        };
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

    /// <summary>PE sections with entropy 7.2+, excluding the managed resources span, where compressed resources are normal.</summary>
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

    /// <summary>Feature categories that appear in highlights.</summary>
    private static readonly HashSet<string> NotableCategories = new(StringComparer.Ordinal)
    {
        "cross-process", "autostart", "local data", "protected storage", "environment checks", "system changes", "privileges",
        "system control", "code loading", "execution",
    };

    /// <summary>Network features that always appear in highlights.</summary>
    private static readonly HashSet<string> NotableNames = new(StringComparer.Ordinal)
    {
        "download files", "communicate through a web service (Telegram, Discord, Pastebin...)", "use raw TCP / UDP sockets",
    };

    private static List<string> Highlights(IdentityFacts identity, SignatureFacts signature, MarkerFacts markers, WrappingFacts wrapping,
        IReadOnlyList<Feature> features, ValueSummary values, IReadOnlyList<EntryPoint> entryPoints)
    {
        var h = new List<string>();
        var transformers = markers.Transformers ?? [];
        foreach (var o in transformers) h.Add($"Transformed with {o.Name} ({o.Confidence}: {string.Join("; ", o.Evidence)}).");
        foreach (var tool in markers.Tools.Where(t => !transformers.Any(o => t.Contains(o.Name, StringComparison.Ordinal))))
            h.Add($"Processed with {tool} (toolchain marker found).");
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
        foreach (var s in wrapping.HighEntropySections) h.Add($"High-entropy PE section {s}: possibly wrapped or encrypted code.");
        foreach (var c in features.Where(c => NotableCategories.Contains(c.Category) || NotableNames.Contains(c.Name)))
            h.Add($"Can {c.Name} ({c.Category}).");
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
