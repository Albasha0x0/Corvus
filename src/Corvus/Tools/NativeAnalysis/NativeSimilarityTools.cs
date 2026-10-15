using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Services;
using static Corvus.Tools.ToolSupport;

namespace Corvus.Tools;

/// <summary>find_similar_functions: look-alike functions in one image or across loaded images, duplicates and near-duplicate clusters.</summary>
[McpServerToolType]
public sealed class NativeSimilarityTools(AssemblyWorkspace workspace, NativeCodeService code)
{
    private const int MaxShared = 8;
    private const int MaxMembers = 50;

    public sealed record SimilarMatch(string Image, string Address, string Name, double Score,
        [property: Description("identical (same bytes, addresses masked), same_shape (same graph and shapes; registers, offsets or " +
                               "constants differ), contains (most of the query's code), similar.")] string Kind,
        [property: Description("Jaccard of instruction-shape 3-grams (registers, addresses, immediates ignored).")] double Code,
        [property: Description("Share of the query's 3-grams found in this function.")] double Containment,
        int Instructions, int Blocks,
        [property: Description("Blocks and edges, query -> this function; same_graph when the CFG shapes match.")] string Cfg,
        IReadOnlyList<string> SharedStrings, IReadOnlyList<string> SharedConstants, IReadOnlyList<string> SharedImports,
        [property: Description("Called by both (same image only).")] IReadOnlyList<string> SharedCallees);

    public sealed record GroupMember(string Address, string Name, int Instructions, uint Size,
        [property: Description("Score against the group's first member (clusters: sketch estimate).")] double Score);

    public sealed record FunctionGroup(int Id,
        [property: Description("identical, same_shape or similar (near-duplicates linked by score).")] string Kind,
        int Members,
        [property: Description("Bytes of the members after the first.")] long RedundantBytes,
        [property: Description("The first 50, by address.")] IReadOnlyList<GroupMember> Functions);

    public sealed record SimilarityReport(string Image,
        [property: Description("similar, duplicates or clusters.")] string View,
        string? Function, string? Address,
        [property: Description("Functions scanned (similar) or candidate pairs scored (clusters).")] int Compared,
        int Offset, int Total, bool Truncated,
        [property: Description("view=similar: matches (image, address, name, score, kind, code, containment, cfg...); " +
                               "else groups (id, kind, members, redundantBytes, functions).")] IReadOnlyList<object> Items,
        IReadOnlyList<string> Notes);

    [McpServerTool(Name = "find_similar_functions", Title = "Find similar functions", UseStructuredContent = true, OutputSchemaType = typeof(SimilarityReport))]
    [Description("Functions like a given one in a native image, ranked by score with evidence: instruction-shape similarity (registers, " +
                 "addresses, constants ignored), containment, CFG shape, shared strings, constants, imports, callees. scope=all: every loaded " +
                 "image of the architecture. view=duplicates: same-shape groups; view=clusters: near-duplicates image-wide.")]
    public Task<string> FindSimilarFunctions(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("view=similar: an address in the function.")] string? address = null,
        [Description("similar (default with address), duplicates or clusters (default without).")] string? view = null,
        [Description("image (default) or all (view=similar).")] string? scope = null,
        [Description("Least score 0-1 (default 0.5; clusters 0.8).")] double? minScore = null,
        [Description("Smallest function compared, in instructions (1-1000).")] int minInstructions = 5,
        [Description(RowOffsetDescription)] int offset = 0,
        [Description("Items to return (max 500).")] int limit = 20,
        [Description(MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        bool hasAddress = !string.IsNullOrWhiteSpace(address);
        var v = (view ?? (hasAddress ? "similar" : "clusters")).Trim().ToLowerInvariant();
        if (v is not ("similar" or "duplicates" or "clusters"))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "use similar, duplicates or clusters");
        if (v == "similar" && !hasAddress)
            throw new ToolError(ErrorCode.InvalidArgument, "view=similar needs address.", "pass the function's address, or view=clusters");
        if (v != "similar" && hasAddress)
            throw new ToolError(ErrorCode.InvalidArgument, $"address applies to view=similar, not {v}.", "omit address, or use view=similar");
        var sc = (scope ?? "image").Trim().ToLowerInvariant();
        if (sc is not ("image" or "all")) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown scope '{scope}'.", "use image or all");
        if (sc == "all" && v != "similar") throw new ToolError(ErrorCode.InvalidArgument, "scope=all applies to view=similar.", "omit scope");
        double min = minScore ?? (v == "clusters" ? 0.8 : 0.5);
        if (double.IsNaN(min) || min is < 0 or > 1) throw new ToolError(ErrorCode.InvalidArgument, $"minScore must be 0-1, not {minScore}.");
        if (minInstructions is < 1 or > 1000) throw new ToolError(ErrorCode.InvalidArgument, $"minInstructions must be 1-1000, not {minInstructions}.");
        offset = Math.Max(0, offset);
        limit = ClampLimit(limit, 500);

        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var home = await Prints(native, progress, cancellationToken);
        var index = home.Index;
        var notes = new List<string>();
        if (home.Failed > 0) notes.Add($"{home.Failed} function(s) could not be decoded and are not compared");
        notes.AddRange(index.Truncations);

        if (v == "similar")
        {
            uint rva = NativeCodeTools.Address(index, address!);
            if (index.FunctionAt(rva) is not { } fn || !home.ByStart.TryGetValue(fn.Start, out var q))
                throw new ToolError(ErrorCode.NotFound, $"{Va(index, rva)} is in no function.", "pass an address inside a function (list_functions)");
            // In load order (ties rank by it).
            var scopeImages = new List<ImagePrints>();
            var ids = new Dictionary<NativeCodeIndex, string> { [index] = native.Id };
            if (sc == "image") scopeImages.Add(home);
            else
                foreach (var other in workspace.Read(() => workspace.Natives.ToList()))
                {
                    if (ReferenceEquals(other, native)) { scopeImages.Add(home); continue; }
                    if (other.Image.Arch != index.Image.Arch) continue;
                    try
                    {
                        var prints = await Prints(other, progress, cancellationToken);
                        scopeImages.Add(prints);
                        ids[prints.Index] = other.Id;
                    }
                    catch (ToolError e) { notes.Add($"{other.Id} skipped: {e.Message}"); }
                }
            if (!scopeImages.Contains(home)) scopeImages.Insert(0, home);
            var q0 = home.Functions[q];
            if (q0.Failed || q0.Sketch == null) notes.Add("the function's code could not be decoded, so nothing is compared");
            // One pool per query, whatever the page, so pages of one query never overlap or skip.
            const int keep = SimilarFunctions.MaxRescored;
            int compared = 0;
            var hits = await Task.Run(() => SimilarFunctions.Similar(home, q, scopeImages, min, minInstructions, keep, cancellationToken, out compared), cancellationToken);
            if (hits.Count >= keep / 2) notes.Add($"only the {keep} best sketch candidates were rescored; raise minScore to see a complete list");
            var page = hits.Skip(offset).Take(limit).Select(h => Match(home, q0, h, ids[h.Image.Index])).ToList();
            var head = $"Functions like {Name(index, fn)} at {Va(index, fn.Start)} [{native.Id}], {Plural(compared, "function")} compared\n" + Notes(notes);
            return ToolOutput.List(page, offset, limit, hits.Count, MatchRow,
                rows => new SimilarityReport(native.Id, v, Name(index, fn), Va(index, fn.Start), compared, offset, hits.Count, offset + rows.Count < hits.Count,
                    rows, notes), "similar function", head);
        }

        int pairs = 0;
        var groups = await Task.Run(() => v == "duplicates"
            ? SimilarFunctions.Duplicates(home, minInstructions, cancellationToken)
            : SimilarFunctions.Clusters(home, min, minInstructions, cancellationToken, out pairs), cancellationToken);
        if (v == "clusters") notes.Add("scores are sketch estimates; view=similar on a member rescores exactly");
        var shown = groups.Skip(offset).Take(limit).Select((g, k) => Group(home, g, offset + k + 1)).ToList();
        int scanned = v == "clusters" ? pairs : home.Functions.Length;
        var title = $"{(v == "clusters" ? "Near-duplicate clusters" : "Duplicate groups")} in {native.Id}, " +
                    $"{(v == "clusters" ? Plural(scanned, "candidate pair") + " scored" : Plural(scanned, "function") + " compared")}\n" + Notes(notes);
        return ToolOutput.List(shown, offset, limit, groups.Count, GroupRow,
            rows => new SimilarityReport(native.Id, v, null, null, scanned, offset, groups.Count, offset + rows.Count < groups.Count, rows, notes), "group", title);
    });

    private static string Notes(List<string> notes) => string.Concat(notes.Select(n => $"Note: {n}\n"));

    private static string MatchRow(SimilarMatch m)
    {
        var evidence = new List<string>();
        if (m.SharedStrings.Count > 0) evidence.Add("strings " + string.Join(", ", m.SharedStrings.Select(Format.EscapeMarkers)));
        if (m.SharedConstants.Count > 0) evidence.Add("constants " + string.Join(", ", m.SharedConstants));
        if (m.SharedImports.Count > 0) evidence.Add("imports " + string.Join(", ", m.SharedImports));
        if (m.SharedCallees.Count > 0) evidence.Add("callees " + string.Join(", ", m.SharedCallees));
        return $"{m.Score:0.00}  {m.Kind,-10} {m.Address}  {m.Name}  [{m.Image}]  code {m.Code:0.00}, contains {m.Containment:0.00}, {m.Instructions} insns, cfg {m.Cfg}" +
               (evidence.Count > 0 ? "; " + string.Join("; ", evidence) : "");
    }

    private static string GroupRow(FunctionGroup g) =>
        $"#{g.Id} {g.Kind}: {Plural(g.Members, "member")}, {g.RedundantBytes:N0} redundant bytes: " +
        string.Join(", ", g.Functions.Take(8).Select(f => $"{f.Name} {f.Address}")) + (g.Members > 8 ? ", ..." : "");

    /// <summary>The image's prints (feature sketches), indexing it first; progress covers both.</summary>
    private async Task<ImagePrints> Prints(LoadedNative native, IProgress<ProgressNotificationValue> progress, CancellationToken ct)
    {
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
            { Progress = p.Done, Total = p.Total > 0 ? p.Total : null, Message = $"indexing {native.Id}: {p.Phase}" })), ct);
        if (index.Support != CodeSupport.Full) throw NativeEngineCode.Unsupported(index, null, "x86, x64, ARM64 and ARM32 images are compared");
        int total = index.Functions.Count;
        return await Task.Run(() => ImagePrints.Of(index, ct, new Progress<int>(done => progress.Report(new ProgressNotificationValue
            { Progress = done, Total = total, Message = $"sketching {native.Id}: {done:N0} of {total:N0} functions" }))), ct);
    }

    private static SimilarMatch Match(ImagePrints home, FunctionPrint q, SimilarHit h, string imageId)
    {
        var index = h.Image.Index;
        var c = h.Image.Functions[h.Index];
        string cfg = $"blocks {q.Blocks} -> {c.Blocks}, edges {q.Edges} -> {c.Edges}" + (q.GraphHash == c.GraphHash ? ", same_graph" : "");
        return new SimilarMatch(imageId, Va(index, c.Start), Name(index, c.Function), h.Score, h.Kind, h.Code, h.Containment,
            c.Instructions, c.Blocks, cfg,
            h.SharedStrings.Take(MaxShared).Select(s => s.Length > 80 ? s[..80] + "…" : s).ToList(),
            h.SharedConstants.Take(MaxShared).Select(k => $"0x{k:X}").ToList(),
            h.SharedImports.Take(MaxShared).ToList(),
            h.SharedCallees.Take(MaxShared).Select(i => Name(home.Index, home.Functions[i].Function)).ToList());
    }

    private static FunctionGroup Group(ImagePrints home, SimilarGroup g, int id)
    {
        var f = home.Functions;
        var members = g.Members.Take(MaxMembers).Select((i, k) => new GroupMember(Va(home.Index, f[i].Start), Name(home.Index, f[i].Function), f[i].Instructions, f[i].Size, g.Scores[k])).ToList();
        return new FunctionGroup(id, g.Kind, g.Members.Length, g.Members.Skip(1).Sum(i => (long)f[i].Size), members);
    }

    private static string Va(NativeCodeIndex index, uint rva) => NativeAddress.Va(index.Image, rva);

    private static string Name(NativeCodeIndex index, NativeFunction f) => index.NameAt(f.Start) ?? f.Name;
}
