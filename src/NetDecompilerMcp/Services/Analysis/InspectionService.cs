using System.Text.Json.Serialization;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>
/// Analyses of one .NET assembly, without executing it: feature rules (<see cref="Features"/>), typed values
/// (<see cref="Values"/>), embedded content (<see cref="Embedded"/>), and a summary that adds file hashes, identity,
/// strong name and Authenticode signature, protector markers, packing and entry points. Input is a loaded assembly
/// (read under the workspace read lock) or a file read into memory. <see cref="Summarize"/> also opens containers
/// (bundles, packages, archives) and summarizes up to 25 of the assemblies inside.
/// </summary>
public sealed class InspectionService(AssemblyWorkspace workspace)
{
    private static AnalysisLimits Limits => AnalysisLimits.Default;
    private const int MaxSummarizedAssemblies = 8;
    private const int MaxSummaryContents = 5;
    private const int MaxSummaryEmbeddedAssemblies = 10;
    private const int TopValues = 10;

    // ------------------------------------------------------------------ result shapes

    public sealed record FeatureReport(string Assembly, int MethodsScanned, IReadOnlyList<Feature> Features, IReadOnlyList<string> Notes);

    public sealed record ValueReport(string Assembly, int Total, IReadOnlyList<ExtractedValue> Values,
        string? SavedTo, IReadOnlyList<string> Notes);

    public sealed record EmbeddedReport(string Assembly, IReadOnlyList<EmbeddedContent> Contents,
        string? OutputDirectory, IReadOnlyList<string> Notes);

    public sealed record FileFacts(string Path, long Size, string Md5, string Sha1, string Sha256, string Type, double Entropy, CertificateInfo Certificate);

    public sealed record IdentityFacts(string Name, string? Version, string Mvid, string? TargetFramework, string Kind, string Architecture,
        bool ReadyToRun, string? Merged, int Types, int Methods,
        IReadOnlyList<string> References);

    public sealed record SignatureFacts(bool StrongNamed, string? PublicKeyToken, CertificateInfo Certificate);

    public sealed record PackingFacts(IReadOnlyList<string> EmbeddedAssemblies, IReadOnlyList<EmbeddedContent> Contents, IReadOnlyList<string> HighEntropySections)
    {
        /// <summary>All embedded assemblies (EmbeddedAssemblies lists the first ones).</summary>
        public int EmbeddedAssemblyTotal { get; init; }
    }

    public sealed record ValueSummary(int Total, IReadOnlyDictionary<string, int> ByType, IReadOnlyList<ExtractedValue> Top);

    public sealed record AssemblySummary(string Path, string Sha256, IdentityFacts Identity, SignatureFacts Signature, MarkerFacts Markers,
        PackingFacts Packing, IReadOnlyList<Feature> Features, ValueSummary Values, IReadOnlyList<EntryPoint> EntryPoints,
        IReadOnlyList<string> Highlights, IReadOnlyList<string> Notes);

    public sealed record FileSummary(FileFacts File, string Container, IReadOnlyList<AssemblySummary> Assemblies, IReadOnlyList<string> Highlights,
        IReadOnlyList<string> Notes);

    // ------------------------------------------------------------------ one assembly: loaded, or a file

    private sealed record Scanned(ModuleDef Module, ModuleScan Scan, byte[] Image, string Label);

    /// <summary>Runs <paramref name="work"/> on one .NET assembly: a loaded one (read lock held) or a file (module disposed after).</summary>
    private T WithAssembly<T>(string? assembly, string? path, Func<Scanned, T> work, CancellationToken ct)
    {
        if ((assembly == null) == (path == null))
            throw new ToolError("Pass either assembly (an assembly loaded in the workspace) or path (a file).");
        if (assembly != null)
            return workspace.Read(() =>
            {
                var asm = workspace.Get(assembly);
                return Guard(asm.Id, () => work(new Scanned(asm.Module, ModuleScan.Of(asm, Limits, ct), asm.OriginalBytes, asm.Id)));
            });

        var (full, bytes) = ReadFile(path!);
        var kind = Blob.Identify(bytes);
        if (kind != ".NET assembly")
            throw new ToolError($"{full} is not a .NET assembly ({kind}). For a container (bundle, package, APK) use summarize_file, or unpack_container and pass one of its assemblies.");
        using var module = LoadModule(bytes, full);
        return Guard(Path.GetFileName(full), () => work(new Scanned(module, ModuleScan.Of(module, Limits, ct), bytes, Path.GetFileName(full))));
    }

    /// <summary>
    /// dnlib reads metadata lazily, so corrupt tables and signature blobs surface wherever they are first touched (a null
    /// signature, a bad row index). Anything other than a ToolError or a cancellation becomes one clear error.
    /// </summary>
    private static T Guard<T>(string label, Func<T> work)
    {
        try { return work(); }
        catch (Exception ex) when (ex is not ToolError and not OperationCanceledException)
        {
            throw new ToolError($"{label}: unreadable .NET metadata, analysis stopped ({ex.GetType().Name}: {ex.Message}).");
        }
    }

    private static (string Full, byte[] Bytes) ReadFile(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new ToolError($"File not found: {full}");
        var length = new FileInfo(full).Length;
        if (length > Math.Min(Limits.MaxTotalBytes, Array.MaxLength)) throw new ToolError($"{full} is too large to analyze ({length:N0} bytes).");
        return (full, File.ReadAllBytes(full));
    }

    private static ModuleDefMD LoadModule(byte[] bytes, string label)
    {
        try { return ModuleDefMD.Load(bytes); }
        catch (Exception ex) { throw new ToolError($"{label}: unreadable .NET metadata ({ex.Message})."); }
    }

    // ------------------------------------------------------------------ features

    public FeatureReport SurveyFeatures(string? assembly, string? path, string? category, CancellationToken ct) =>
        WithAssembly(assembly, path, s =>
        {
            var found = Features.Detect(s.Scan, ct);
            if (category != null)
                found = [.. found.Where(c => c.Category.Equals(category, StringComparison.OrdinalIgnoreCase)
                                          || (c.Attack?.StartsWith(category, StringComparison.OrdinalIgnoreCase) ?? false))];
            return new FeatureReport(s.Label, s.Scan.MethodsScanned, found, s.Scan.Notes);
        }, ct);

    // ------------------------------------------------------------------ values

    public ValueReport ExtractStrings(string? assembly, string? path, IReadOnlyCollection<string>? types, string? savePath, string? format, bool overwrite,
        CancellationToken ct)
    {
        var unknown = types?.Where(t => !Values.Types.Contains(t)).ToList();
        if (unknown is { Count: > 0 })
            throw new ToolError($"Unknown value type(s): {string.Join(", ", unknown)}. Types: {string.Join(", ", Values.Types)}.");
        var fmt = (format ?? (savePath != null && savePath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) ? "csv" : "json")).ToLowerInvariant();
        if (fmt is not ("json" or "csv")) throw new ToolError($"Unknown format '{format}': use json or csv.");

        var report = WithAssembly(assembly, path, s =>
        {
            var found = Values.Find(s.Scan, Embedded.Find(s.Scan, Limits, ct), ct);
            if (types is { Count: > 0 }) found = [.. found.Where(i => types.Contains(i.Type))];
            return new ValueReport(s.Label, found.Count, found, null, s.Scan.Notes);
        }, ct);

        if (savePath == null) return report;
        var target = Path.GetFullPath(savePath);
        if (File.Exists(target) && !overwrite) throw new ToolError($"{target} exists: pass overwrite=true to replace it.");
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllText(target, fmt == "csv" ? Values.ToCsv(report.Values) : Values.ToJson(report.Values));
        return report with { SavedTo = target };
    }

    // ------------------------------------------------------------------ contents

    /// <summary>
    /// Finds embedded content. With save or load, writes each item as embedded_NN.ext (runnable extensions defanged) to a
    /// directory of its own (new, empty, or an earlier extraction of the same file) and, with load, loads the .NET ones.
    /// </summary>
    public EmbeddedReport ExtractEmbedded(string? assembly, string? path, bool save, string? outputDirectory, bool load, CancellationToken ct,
        bool xorText = false, bool includeMedia = false)
    {
        var (label, source, sha, contents, notes) = WithAssembly(assembly, path, s =>
            (s.Label, assembly != null ? workspace.Get(assembly).FilePath : Path.GetFullPath(path!), Blob.Sha256(s.Image), Embedded.Find(s.Scan, Limits, ct, xorText), s.Scan.Notes), ct);
        if (!includeMedia && contents.Any(c => Blob.IsMedia(c.Kind)))
        {
            // UI images and icons are common and rarely interesting: counted, listed (and saved) only on request
            var media = contents.Where(c => Blob.IsMedia(c.Kind)).GroupBy(c => c.Kind).Select(g => $"{g.Count()} {g.Key}");
            notes.Add($"Images not listed: {string.Join(", ", media)} (includeMedia=true lists and saves them).");
            contents = contents.Where(c => !Blob.IsMedia(c.Kind)).ToList();
        }
        if (!save && !load && outputDirectory == null) return new EmbeddedReport(label, contents, null, notes);

        var root = UnpackService.PrepareOutput(outputDirectory ?? UnpackService.DefaultOutput(source, sha, "netdecomp-embedded"), source, sha);
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

    private static string Extension(EmbeddedContent p) => p.Kind switch
    {
        ".NET assembly" => ".dll",
        "native PE" or "NativeAOT executable" => p.Detail?.EndsWith("DLL", StringComparison.Ordinal) == true ? ".dll" : ".exe", // defanged on write
        "zip" => ".zip",
        "gzip" => ".gz",
        "text" => ".txt",
        _ => ".bin",
    };

    // ------------------------------------------------------------------ summary

    public FileSummary Summarize(string? assembly, string? path, CancellationToken ct)
    {
        if ((assembly == null) == (path == null))
            throw new ToolError("Pass either assembly (an assembly loaded in the workspace) or path (a file).");
        if (assembly != null)
        {
            return workspace.Read(() =>
            {
                var asm = workspace.Get(assembly);
                var file = Facts(asm.FilePath, asm.OriginalBytes);
                var one = Guard(asm.Id, () => SummarizeAssembly(Path.GetFileName(asm.FilePath), asm.Module, ModuleScan.Of(asm, Limits, ct), asm.OriginalBytes, ct));
                var notes = asm.IsDirty ? new List<string> { "The assembly has unsaved edits: the code scanned is the edited module; hashes and signature are the file's." } : [];
                return new FileSummary(file, "none (loaded assembly)", [one], one.Highlights, notes);
            });
        }

        var (full, bytes) = ReadFile(path!);
        var facts = Facts(full, bytes);
        var fileHighlights = new List<string>();
        if (facts.Certificate is { Present: true } fileSig) fileHighlights.AddRange(SignatureHighlights(fileSig, "the file"));
        if (UnityLayout.FileHint(full, bytes) is { } layout) fileHighlights.Add(layout);
        (string Source, string Container, List<UnpackService.ManagedAssembly> Assemblies, List<string> Notes) managed;
        try { managed = UnpackService.Managed(full, Limits, ct); }
        catch (ToolError ex)
        {
            // a damaged container: the file facts still stand
            return new FileSummary(facts, "unreadable container", [], [.. fileHighlights, $"The file is damaged: {ex.Message}"], [ex.Message]);
        }
        var reportNotes = new List<string>(managed.Notes);
        var summarized = new List<AssemblySummary>();
        // The app's own code first: the host file, the assembly named like the file, other libraries; framework
        // libraries last; satellite resource assemblies (translations) are not summarized.
        var ranked = managed.Assemblies.Select((a, i) => (a, i, Rank: Rank(a, full))).ToList();
        var satellites = ranked.Count(r => r.Rank == AssemblyRank.Satellite);
        var candidates = ranked.Where(r => r.Rank != AssemblyRank.Satellite).OrderBy(r => r.Rank).ThenBy(r => r.i).ToList();
        var found = new List<(string Path, IReadOnlyList<string> Highlights)>(); // before the brief form drops them
        var copies = new Dictionary<string, List<string>>(StringComparer.Ordinal); // identity -> paths of the same assembly built for other targets
        foreach (var (a, _, rank) in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (summarized.Count >= MaxSummarizedAssemblies) break;
            try
            {
                using var module = LoadModule(a.Bytes, a.Path);
                var identity = module.Assembly?.FullName ?? module.Name.String;
                if (copies.TryGetValue(identity, out var paths)) { paths.Add(a.Path); continue; } // e.g. lib/net45 and lib/netstandard2.0 of one package
                copies[identity] = [];
                var one = Guard(a.Path, () => SummarizeAssembly(a.Path, module, ModuleScan.Of(module, Limits, ct), a.Bytes, ct));
                if (rank == AssemblyRank.Framework)
                    one = one with { Highlights = one.Highlights.Where(IsProblem).ToList() }; // a known library's capabilities are not findings
                // full detail for the first (the host / main assembly); the others in brief (summarize_file on them for more)
                found.Add((one.Path, one.Highlights));
                summarized.Add(summarized.Count == 0 ? one : Brief(one));
            }
            catch (ToolError ex)
            {
                // a damaged assembly (truncated, metadata overwritten): reported, with the file facts; in a container
                // the other assemblies are still summarized
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
        return new FileSummary(facts, managed.Container, summarized, highlights.Distinct().ToList(), reportNotes);
    }

    private enum AssemblyRank { Host, Main, Library, Framework, Satellite }

    /// <summary>A secondary assembly of a container: feature names without evidence, value counts without values, no content list.</summary>
    private static AssemblySummary Brief(AssemblySummary a) => a with
    {
        Features = a.Features.Select(f => f with { Evidence = [] }).ToList(),
        Values = a.Values with { Top = [] },
        Packing = new PackingFacts(a.Packing.EmbeddedAssemblies.Take(3).ToList(), [], a.Packing.HighEntropySections) { EmbeddedAssemblyTotal = a.Packing.EmbeddedAssemblyTotal },
        Identity = a.Identity with { References = a.Identity.References.Take(5).ToList() },
        Notes = a.Notes.Take(3).ToList(),
        Highlights = [], // listed once, in the file's highlights
    };

    private static readonly HashSet<string> FrameworkTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", "cc7b13ffcd2ddd51", "adb9793829ddae60", "7cec85d7bea7798e",
    };

    /// <summary>Where an assembly of a container comes in the summary (see <see cref="Summarize"/>).</summary>
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

    /// <summary>Highlights that are problems whatever the assembly: protection, tampering, packing, hidden code.</summary>
    private static bool IsProblem(string h) =>
        h.StartsWith("Protected with", StringComparison.Ordinal) || h.Contains("does not match", StringComparison.Ordinal)
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
        var packing = new PackingFacts(embedded, listed, sections) { EmbeddedAssemblyTotal = embeddedTotal };

        // the summary keeps the most specific evidence line (a string or native import before a common API) with one
        // location; survey_features has them all
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

        return new AssemblySummary(path, Blob.Sha256(image), identity, signature, markers, packing, features, valueSummary, entryPoints,
            [.. health.MostlyInvalid ? ["Method bodies are not valid IL (encrypted or dumped before decryption)"] : Array.Empty<string>(),
             .. Highlights(identity, signature, markers, packing, features, valueSummary, entryPoints)], notes);
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
    /// PE sections whose bytes look packed or encrypted (entropy 7.2+), not counting the managed resources: images and
    /// compressed assets embedded as resources live in .text of every .NET image and say nothing about packed code.
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
            // the section minus the resources span (when the span lies inside it)
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

    // ------------------------------------------------------------------ highlights

    /// <summary>Categories whose ATT&amp;CK-mapped features are listed in highlights (discovery and data-handling categories are not).</summary>
    private static readonly HashSet<string> NotableCategories = new(StringComparer.Ordinal)
    {
        "injection", "persistence", "collection", "credential access", "anti-analysis", "defense evasion", "privilege escalation",
        "impact", "code loading", "execution",
    };

    private static List<string> Highlights(IdentityFacts identity, SignatureFacts signature, MarkerFacts markers, PackingFacts packing,
        IReadOnlyList<Feature> features, ValueSummary values, IReadOnlyList<EntryPoint> entryPoints)
    {
        var h = new List<string>();
        foreach (var tool in markers.Tools) h.Add($"Protected with {tool} (marker found).");
        h.AddRange(markers.Indicators.Take(2));
        if (signature.Certificate is { Present: true } sig) h.AddRange(SignatureHighlights(sig, "the assembly"));
        if (identity.Merged != null) h.Add(identity.Merged);
        if (packing.EmbeddedAssemblyTotal > 0) h.Add($"{packing.EmbeddedAssemblyTotal} embedded assembly(ies) (Costura or similar).");
        // Costura's embedded assemblies and their PDBs are counted above, not listed one by one
        foreach (var p in packing.Contents.Where(c => !(c.Source.StartsWith("resource 'costura.", StringComparison.OrdinalIgnoreCase)
                                                         && c.Kind is ".NET assembly" or "portable pdb" or "pdb")).Take(5))
        {
            var how = p.Encoding.Count > 0 ? $", encoded as {string.Join(" > ", p.Encoding)}" : "";
            h.Add(p.Kind.StartsWith("high-entropy", StringComparison.Ordinal)
                ? $"High-entropy data ({p.Size:N0} bytes, possibly encrypted) in {p.Source}."
                : $"Embedded {p.Kind}{(p.Detail != null && p.Kind != "text" ? $" ({p.Detail})" : "")} in {p.Source}{how}.");
        }
        if (packing.Contents.Count > 5) h.Add($"{packing.Contents.Count - 5} more embedded item(s) listed.");
        foreach (var s in packing.HighEntropySections) h.Add($"High-entropy PE section {s}: packed or encrypted code?");
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
