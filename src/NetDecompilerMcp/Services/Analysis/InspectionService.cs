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
    private const int MaxSummarizedAssemblies = 25;
    private const int TopValues = 25;

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

    public sealed record PackingFacts(IReadOnlyList<string> EmbeddedAssemblies, IReadOnlyList<EmbeddedContent> Contents, IReadOnlyList<string> HighEntropySections);

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
        bool xorText = false)
    {
        var (label, source, sha, contents, notes) = WithAssembly(assembly, path, s =>
            (s.Label, assembly != null ? workspace.Get(assembly).FilePath : Path.GetFullPath(path!), Blob.Sha256(s.Image), Embedded.Find(s.Scan, Limits, ct, xorText), s.Scan.Notes), ct);
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
        var managed = UnpackService.Managed(full, Limits, ct);
        var reportNotes = new List<string>(managed.Notes);
        var summarized = new List<AssemblySummary>();
        foreach (var a in managed.Assemblies.Take(MaxSummarizedAssemblies))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var module = LoadModule(a.Bytes, a.Path);
                summarized.Add(Guard(a.Path, () => SummarizeAssembly(a.Path, module, ModuleScan.Of(module, Limits, ct), a.Bytes, ct)));
            }
            catch (ToolError ex)
            {
                // the file is the assembly: nothing else to report on. In a container, the other assemblies still are.
                if (managed.Container.StartsWith("none", StringComparison.Ordinal)) throw;
                reportNotes.Add(ex.Message);
            }
        }
        if (managed.Assemblies.Count > MaxSummarizedAssemblies)
            reportNotes.Add($"Summarized the first {MaxSummarizedAssemblies} of {managed.Assemblies.Count} assemblies; list_assemblies with path lists them all.");
        if (managed.Assemblies.Count == 0)
            reportNotes.Add("No managed assemblies inside: nothing to summarize beyond the file facts.");

        var highlights = new List<string>();
        if (facts.Certificate is { Present: true } sig) highlights.AddRange(SignatureHighlights(sig, "the file"));
        foreach (var t in summarized)
            highlights.AddRange(summarized.Count == 1 ? t.Highlights : t.Highlights.Select(h => $"[{t.Path}] {h}"));
        return new FileSummary(facts, managed.Container, summarized, highlights.Distinct().ToList(), reportNotes);
    }

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
            embedded.AddRange(inner.Items.Select(i => $"{i.Name} ({i.Origin})"));
        }
        catch (ToolError ex) { notes.Add(ex.Message); }
        var contents = Embedded.Find(scan, Limits, ct);
        var sections = pe == null ? [] : pe.Sections
            .Where(s => s.RawSize >= 4096 && s.RawPointer + (long)s.RawSize <= image.Length)
            .Select(s => (s.Name, Entropy: Blob.Entropy(image.AsSpan((int)s.RawPointer, (int)s.RawSize))))
            .Where(s => s.Entropy >= 7.2).Select(s => $"{s.Name} (entropy {s.Entropy:F2})").ToList();
        var packing = new PackingFacts(embedded, contents, sections);

        var features = Features.Detect(scan, ct);
        var values = Values.Find(scan, contents, ct);
        var valueSummary = new ValueSummary(values.Count, values.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count()), values.Take(TopValues).ToList());
        var entryPoints = EntryPoints.Find(module, image);

        return new AssemblySummary(path, Blob.Sha256(image), identity, signature, markers, packing, features, valueSummary, entryPoints,
            Highlights(identity, signature, markers, packing, features, valueSummary, entryPoints), notes);
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
        try { types = module.GetTypes().ToList(); } catch (Exception) { types = []; }
        List<string> references;
        try { references = module.GetAssemblyRefs().Select(r => $"{r.Name} {r.Version}").Take(100).ToList(); } catch (Exception) { references = []; }
        return new IdentityFacts(module.Assembly?.Name.String ?? module.Name.String, module.Assembly?.Version?.ToString(), module.Mvid?.ToString() ?? "",
            tfm, kind, arch, AssemblyTraits.IsReadyToRun(image), AssemblyTraits.MergeNote(module), types.Count, types.Sum(t => t.Methods.Count), references);
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
        if (packing.EmbeddedAssemblies.Count > 0) h.Add($"{packing.EmbeddedAssemblies.Count} embedded assembly(ies) (Costura or similar).");
        foreach (var p in packing.Contents.Take(5))
        {
            var how = p.Encoding.Count > 0 ? $", encoded as {string.Join(" > ", p.Encoding)}" : "";
            h.Add(p.Kind.StartsWith("high-entropy", StringComparison.Ordinal)
                ? $"High-entropy data ({p.Size:N0} bytes, possibly encrypted) in {p.Source}."
                : $"Embedded {p.Kind}{(p.Detail != null && p.Kind != "text" ? $" ({p.Detail})" : "")} in {p.Source}{how}.");
        }
        if (packing.Contents.Count > 5) h.Add($"{packing.Contents.Count - 5} more embedded item(s).");
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
