using System.Text;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>Assembly overview used by the get_assembly_info tool and the assembly info resource.</summary>
public sealed class AssemblyReport(AssemblyWorkspace workspace, Il2CppService il2cpp)
{
    /// <summary>A reference of the assembly and where it resolves.</summary>
    public sealed record ReferenceStatus(string Name, [property: System.ComponentModel.Description("Where it resolves, or not found.")] string Status);

    /// <summary>The overview's facts as fields (get_assembly_info's structured content).</summary>
    public sealed record Summary(
        string Id,
        string FullName,
        string File,
        [property: System.ComponentModel.Description("SHA-256 of the file as loaded (unsaved edits not included).")] string Sha256,
        string Mvid,
        string Runtime,
        string Kind,
        string Machine,
        string? TargetFramework,
        [property: System.ComponentModel.Description("Ns.Type::Method of the entry point.")] string? EntryPoint,
        int Types,
        int NestedTypes,
        int Namespaces,
        int Methods,
        int Fields,
        int Resources,
        bool ReferenceAssembly,
        [property: System.ComponentModel.Description("Il2Cpp dummy DLL: methods with [Address] attributes.")] int Il2CppAddressedMethods,
        [property: System.ComponentModel.Description("Method bodies that are not valid IL.")] int InvalidBodies,
        [property: System.ComponentModel.Description("Exception clauses of valid bodies with bad flags, ranges outside the code or off instruction boundaries, or a misplaced filter.")] int InvalidExceptionClauses,
        IReadOnlyList<string> UnsavedEdits,
        [property: System.ComponentModel.Description("Assembly references.")] int ReferenceCount,
        [property: System.ComponentModel.Description("References that resolve to nothing.")] int UnresolvedReferences,
        [property: System.ComponentModel.Description("Structural metadata problems: root and streams, every bad table, coded or heap index, P/Invoke rows.")] int MetadataIssueCount)
    {
        [System.ComponentModel.Description("The transformation tool, with evidence; view=transforms adds 'layer: ' rows.")] public IReadOnlyList<Analysis.TransformerFinding>? Transformers { get; init; }
        [System.ComponentModel.Description("view=references or all.")] public IReadOnlyList<ReferenceStatus>? References { get; init; }
        [System.ComponentModel.Description("view=metadata or all: assembly attributes (first 40).")] public IReadOnlyList<string>? Attributes { get; init; }
        [System.ComponentModel.Description("view=metadata or all: row counts of the non-empty metadata tables, in table order.")] public IReadOnlyList<TableRows>? Tables { get; init; }
        [System.ComponentModel.Description("view=metadata or all.")] public IReadOnlyList<HeapSize>? Heaps { get; init; }
        [System.ComponentModel.Description("view=metadata or all: the first 50 metadata problems.")] public IReadOnlyList<MetadataIssue>? MetadataIssues { get; init; }
    }

    /// <summary>What get_assembly_info shows: summary, references, metadata, all, or transforms (not part of all: it runs a dry run).</summary>
    public static readonly string[] Views = ["summary", "references", "metadata", "all", "transforms"];

    /// <summary>Rows of a metadata table.</summary>
    public sealed record TableRows(string Table, uint Rows);

    /// <summary>A metadata heap's size and the width of the table columns that index it (none for #US: only tokens reach it).</summary>
    public sealed record HeapSize(string Heap, uint Bytes, int? IndexBytes);

    /// <summary>Call under the workspace read lock.</summary>
    public string Build(LoadedAssembly asm) => Build(asm, "all", out _);

    /// <summary>The overview text of <paramref name="view"/>, and its facts as <paramref name="summary"/>. Call under the workspace read lock.</summary>
    public string Build(LoadedAssembly asm, string view, out Summary summary, CancellationToken ct = default)
    {
        bool all = view == "all", references = all || view == "references", metadata = all || view == "metadata";
        var m = asm.Module;
        var types = MetadataUtil.CountedTypes(m);
        var sb = new StringBuilder();
        sb.AppendLine($"Id: {asm.Id}");
        sb.AppendLine($"Assembly: {asm.FullAssemblyName}");
        sb.AppendLine($"File: {asm.FilePath}");
        sb.AppendLine($"Module: {m.Name}  MVID {m.Mvid}");
        sb.AppendLine($"SHA-256: {asm.OriginalSha256}{(asm.IsDirty ? " (file as loaded; unsaved edits not included)" : "")}");
        sb.AppendLine($"Runtime: {m.RuntimeVersion}  Kind: {m.Kind}  Machine: {m.Machine}  IL-only: {m.IsILOnly}  32-bit required: {m.Is32BitRequired}");
        var tfa = m.Assembly?.CustomAttributes.FirstOrDefault(c => c.TypeFullName == "System.Runtime.Versioning.TargetFrameworkAttribute");
        if (tfa?.ConstructorArguments.Count > 0)
            sb.AppendLine($"Target framework: {tfa.ConstructorArguments[0].Value}");
        if (m.EntryPoint != null)
            sb.AppendLine($"Entry point: {Format.MemberLabel(m.EntryPoint)}  ({Format.Token(m.EntryPoint)})");
        sb.AppendLine($"Types: {types.Count} ({types.Count(t => t.DeclaringType != null)} nested)  Namespaces: {MetadataUtil.NamespaceCount(types)}  " +
                      $"Methods: {m.GetTypes().Sum(t => t.Methods.Count)}  Fields: {m.GetTypes().Sum(t => t.Fields.Count)}  Resources: {m.Resources.Count}");
        if (MetadataUtil.IsReferenceAssembly(m))
            sb.AppendLine("Reference assembly: metadata only (compile-time API surface); method bodies are `throw null`. Load the implementation " +
                          "(the runtime's assembly, or the package's lib/ folder instead of ref/) to read code.");
        int addressed = il2cpp.GetIndex(asm).Count;
        if (addressed > 0)
            sb.AppendLine($"Il2Cpp metadata: {addressed} methods carry [Address] attributes (dummy DLL; method bodies are stubs — use get_il2cpp_info / find_method_by_address).");
        var health = asm.BodyHealth;
        if (health.MostlyInvalid)
            sb.AppendLine($"IL: {health.Describe()} Load the decrypted image (e.g. a dump taken after the code ran) to read code.");
        else if (health.Invalid > 0)
            sb.AppendLine($"IL: {health.Invalid} of {health.Bodies} method bodies are not valid IL (e.g. " +
                          string.Join(", ", m.GetTypes().SelectMany(t => t.Methods).Where(health.IsInvalid).Take(3).Select(Format.MemberLabel)) + ").");
        if (health.InvalidClauseCount > 0)
            sb.AppendLine($"Exception clauses: {health.InvalidClauseCount} invalid in {health.InvalidClauses.Count} method(s) (e.g. " +
                          string.Join("; ", m.GetTypes().SelectMany(t => t.Methods).Where(x => health.ClauseIssues(x).Count > 0).Take(3)
                              .Select(x => $"{Format.MemberLabel(x)} {health.ClauseIssues(x)[0]}")) + "); get_il shows them per method.");
        var transformers = Analysis.Transformers.Identify(m);
        foreach (var o in transformers) sb.AppendLine($"Transformer: {o.Name} ({o.Confidence}): {string.Join("; ", o.Evidence)}");
        if (view == "transforms")
        {
            var layers = Simplify.TransformLayers.Read(asm, ct);
            var identified = transformers.ToList();
            sb.AppendLine(layers.Count == 0 ? "Transforms: none seen" : "Transforms (a simplify_methods dry run; nothing is changed):");
            foreach (var l in layers)
            {
                string[] evidence = [$"{l.Sites} site(s), {l.Restored} restored", l.Evidence, .. l.Reasons,
                    .. Simplify.TransformLayers.Joined(l, identified).Select(j => "identified: " + j)];
                sb.AppendLine($"  {l.Layer}: {l.State}, {string.Join("; ", evidence)}");
                transformers.Add(new("layer: " + l.Layer, l.State, evidence));
            }
        }
        if (ReadyToRunService.Summary(workspace, asm) is { } readyToRun)
            sb.AppendLine(readyToRun);
        if (asm.IsDirty)
            sb.AppendLine($"Unsaved edits: {string.Join("; ", asm.Edits)}");
        var (tables, heaps) = Inventory(m);
        var metadataText = new StringBuilder();
        var (issueCount, issues) = AppendMetadataIssues(metadataText, asm);
        if (metadata)
        {
            AppendPeInfo(sb, m);
            sb.AppendLine("Metadata tables (rows): " + string.Join(", ", tables.Select(t => $"{t.Table} {t.Rows}")));
            sb.AppendLine("Metadata heaps: " + string.Join(", ", heaps.Select(h => $"{h.Heap} {h.Bytes} bytes{(h.IndexBytes is { } w ? $" ({w}-byte indexes)" : "")}")));
            sb.Append(metadataText);
        }
        else if (issueCount > 0) sb.AppendLine($"Metadata issues: {issueCount} (view=metadata lists them)");

        var referenceText = new StringBuilder("References:\n");
        var referenceRows = new List<ReferenceStatus>();
        foreach (var r in m.GetAssemblyRefs())
        {
            var target = workspace.LocateReference(r.Name, r.Version, r.PublicKeyOrToken?.Token?.Data, asm.FilePath, Frameworks.ResolvesAsNetFramework(m), Frameworks.RequesterFramework(m));
            var status = target?.Describe() ?? "not found";
            // Flag a resolved major version that differs from the requested one; .NET Framework 2.0-4.x unification is expected.
            if (target?.File is { } file && r.Version is { } wanted && !Frameworks.IsWildcard(wanted)
                && !(wanted.Major <= 4 && Frameworks.IsNetFrameworkAssembly(r.Name)))
            {
                Version? found = null;
                try { found = System.Reflection.AssemblyName.GetAssemblyName(file).Version; } catch (Exception) { }
                if (found != null && !Frameworks.IsWildcard(found) && found.Major != wanted.Major)
                    status += $", version {found} (no {wanted.Major}.x on this machine)";
            }
            referenceText.AppendLine($"  {r.FullName}  [{status}]");
            referenceRows.Add(new ReferenceStatus(r.FullName, status));
        }
        int unresolved = referenceRows.Count(r => r.Status == "not found");
        if (references) sb.Append(referenceText);
        else sb.AppendLine($"References: {referenceRows.Count}{(unresolved > 0 ? $", {unresolved} not found: " + string.Join(", ", referenceRows.Where(r => r.Status == "not found").Take(10).Select(r => r.Name.Split(',')[0])) : ", all resolved")} (view=references lists them)");

        var attrs = m.Assembly?.CustomAttributes.Where(c => c != tfa).ToList() ?? [];
        if (attrs.Count > 0 && metadata)
        {
            sb.AppendLine("Assembly attributes:");
            foreach (var ca in attrs.Take(40)) sb.AppendLine("  " + Format.Attribute(ca));
        }
        else if (attrs.Count > 0) sb.AppendLine($"Assembly attributes: {attrs.Count} (view=metadata, or get_attributes)");
        summary = new Summary(asm.Id, asm.FullAssemblyName, asm.FilePath, asm.OriginalSha256, m.Mvid?.ToString() ?? "", m.RuntimeVersion ?? "", m.Kind.ToString(), m.Machine.ToString(),
            tfa?.ConstructorArguments.Count > 0 ? tfa.ConstructorArguments[0].Value?.ToString() : null,
            m.EntryPoint != null ? Format.MemberLabel(m.EntryPoint) : null,
            types.Count, types.Count(t => t.DeclaringType != null), MetadataUtil.NamespaceCount(types),
            m.GetTypes().Sum(t => t.Methods.Count), m.GetTypes().Sum(t => t.Fields.Count), m.Resources.Count,
            MetadataUtil.IsReferenceAssembly(m), addressed, health.Invalid, health.InvalidClauseCount, asm.Edits.Select(e => e.ToString()).ToList(),
            referenceRows.Count, unresolved, issueCount)
        {
            Transformers = transformers.Count > 0 ? transformers : null,
            References = references ? referenceRows : null,
            Attributes = metadata ? attrs.Take(40).Select(Format.Attribute).ToList() : null,
            Tables = metadata ? tables : null,
            Heaps = metadata ? heaps : null,
            MetadataIssues = metadata ? issues.Take(50).ToList() : null,
        };
        return sb.ToString();
    }

    /// <summary>Non-empty tables of the tables stream in use, and the heaps with their index widths.</summary>
    private static (List<TableRows> Tables, List<HeapSize> Heaps) Inventory(ModuleDefMD m)
    {
        var md = m.Metadata;
        var t = md.TablesStream;
        var tables = t.MDTables.Where(x => x.Rows > 0).Select(x => new TableRows(x.Name, x.Rows)).ToList();
        List<HeapSize> heaps =
        [
            new("#Strings", md.StringsStream?.StreamLength ?? 0, t.HasBigStrings ? 4 : 2),
            new("#US", md.USStream?.StreamLength ?? 0, null),
            new("#Blob", md.BlobStream?.StreamLength ?? 0, t.HasBigBlob ? 4 : 2),
            new("#GUID", md.GuidStream?.StreamLength ?? 0, t.HasBigGUID ? 4 : 2),
        ];
        return (tables, heaps);
    }

    private static void AppendPeInfo(StringBuilder sb, ModuleDefMD m)
    {
        try
        {
            var pe = m.Metadata.PEImage;
            var fh = pe.ImageNTHeaders.FileHeader;
            var oh = pe.ImageNTHeaders.OptionalHeader;
            var stamp = DateTimeOffset.FromUnixTimeSeconds(fh.TimeDateStamp);
            sb.AppendLine($"PE: {(oh.Magic == 0x20B ? "PE32+" : "PE32")}  ImageBase 0x{oh.ImageBase:X}  Subsystem {oh.Subsystem}  " +
                          $"Characteristics {fh.Characteristics}  DllCharacteristics {oh.DllCharacteristics}");
            sb.AppendLine($"Timestamp: 0x{fh.TimeDateStamp:X8}{(stamp.Year is > 1995 and < 2100 ? $" ({stamp:yyyy-MM-dd HH:mm} UTC)" : " (deterministic build hash)")}  " +
                          $"CLR flags: {m.Metadata.ImageCor20Header.Flags}  Metadata version: {m.Metadata.VersionString}");
            sb.AppendLine("Sections:");
            foreach (var s in pe.ImageSectionHeaders)
                sb.AppendLine($"  {s.DisplayName,-8} VA 0x{(uint)s.VirtualAddress:X8}  VSize 0x{s.VirtualSize:X}  Raw 0x{s.PointerToRawData:X}+0x{s.SizeOfRawData:X}  flags 0x{s.Characteristics:X8}");
            sb.AppendLine("Metadata streams: " + string.Join(", ", m.Metadata.AllStreams.Select(st => $"{st.Name} ({st.StreamLength} bytes)")));
        }
        catch (Exception ex)
        {
            sb.AppendLine($"PE: unavailable ({ex.Message})");
        }
    }

    /// <summary>Structural metadata problems (as code transformers leave them) with their locations; nothing when there are none.</summary>
    private static (int Count, List<MetadataIssue> Issues) AppendMetadataIssues(StringBuilder sb, LoadedAssembly asm)
    {
        var implMap = MetadataSurvey.ImplMapRows(asm.Module).Values.ToList();
        var rows = MetadataSurvey.Rows(asm.Module, asm.OriginalBytes);
        // ImplMapRows already names the bad ModuleRef rows that P/Invokes use, more specifically.
        var named = implMap.Select(i => i.FileOffset).ToHashSet();
        var swept = rows.Issues.Where(i => !named.Contains(i.FileOffset)).ToList();
        var issues = MetadataSurvey.Survey(asm.OriginalBytes).Concat(implMap).Concat(swept).ToList();
        int count = issues.Count + rows.Count - rows.Issues.Count;
        if (count == 0) return (0, issues);
        sb.AppendLine($"Metadata issues ({count}{(count > 20 ? ", first 20" : "")}; the rest of the metadata is read leniently):");
        foreach (var issue in issues.Take(20))
            sb.AppendLine($"  {issue.Code} at {issue.Location}{(issue.FileOffset != null ? $", file offset {issue.FileOffset}" : "")}: {issue.Detail}");
        return (count, issues);
    }
}
