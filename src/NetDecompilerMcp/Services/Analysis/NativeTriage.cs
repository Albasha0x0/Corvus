using System.ComponentModel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Services.Analysis;

[Description("First-look triage of a loaded native image, from its code index.")]
public sealed record NativeTriage(
    int Functions, [property: Description("Named by an export, symbols, metadata or the user.")] int Named, int Unnamed, int Thunks,
    [property: Description("Recognized as library code by an engine.")] int Library, int Strings, int Imports, int Exports,
    IReadOnlyList<TriageSegment> Segments,
    [property: Description("Entry point, TLS callbacks and exports, each at its own address (PE ordinals apart).")] IReadOnlyList<TriageEntry> EntryPoints,
    [property: Description("Most referenced functions (import thunks and library code left out), with a role.")] IReadOnlyList<TriageFunction> TopFunctions,
    [property: Description("Most referenced strings.")] IReadOnlyList<TriageString> TopStrings,
    [property: Description("Imports by capability group (static and late-bound).")] IReadOnlyList<CapabilityGroup> ImportGroups,
    [property: Description("Imported APIs in no group.")] int OtherImports,
    TriageCallGraph CallGraph);

public sealed record TriageSegment(string Name, string Start, [property: Description("Exclusive.")] string End, string Access);

public sealed record TriageEntry(string Address, [property: Description("entry, tls_callback or export.")] string Kind, string Name, int? Ordinal);

public sealed record TriageFunction(string Address, string Name, long Size,
    [property: Description("References to its start (calls, jumps, pointers).")] int References, int Callees,
    [property: Description("thunk (a jump or 8 bytes or less), wrapper (one callee, under 100 bytes), leaf (no calls), dispatcher (over 10 callees) or complex.")] string Role);

public sealed record TriageString(string Address, string Text, int References);

public sealed record CapabilityGroup(string Group, int Count, IReadOnlyList<string> Apis);

public sealed record TriageCallGraph(int Edges,
    [property: Description("Functions nothing references.")] int Roots,
    [property: Description("Functions that call nothing.")] int Leaves,
    [property: Description("The first roots, exports and the entry point first.")] IReadOnlyList<string> RootNames);

public static class NativeTriageBuilder
{
    private const int Top = 15;

    public static NativeTriage Build(NativeCodeIndex index, CancellationToken ct)
    {
        var image = index.Image;
        string Va(uint r) => NativeAddress.Va(image, r);
        string Name(NativeFunction f) => index.NameAt(f.Start) ?? f.Name;
        int named = 0, thunks = 0, library = 0, edges = 0, leaves = 0;
        var callees = new Dictionary<uint, int>();
        var roots = new List<NativeFunction>();
        foreach (var f in index.Functions)
        {
            ct.ThrowIfCancellationRequested();
            if (index.Sourced.NameAt(f.Start) != null || f.KnownName != null) named++;
            if ((f.Flags & FunctionFlags.Thunk) != 0) thunks++;
            if (EngineLibraryNames.IsLibrary(index, f.Start)) library++;
            int calls = index.Callees(f).Select(c => c.Target).Distinct().Count();
            callees[f.Start] = calls;
            edges += calls;
            if (calls == 0) leaves++;
            if (index.CountRefsTo(f.Start) == 0) roots.Add(f);
        }
        var entryish = new HashSet<uint>(image.Exports.Where(e => e.ForwardedTo == null).Select(e => e.Rva)) { image.EntryPointRva };
        var top = index.Functions.Where(f => f.ThunkImport == null && !EngineLibraryNames.IsLibrary(index, f.Start))
            .Select(f => (F: f, Refs: index.CountRefsTo(f.Start))).Where(x => x.Refs > 0)
            .OrderByDescending(x => x.Refs).ThenBy(x => x.F.Start).Take(Top)
            .Select(x => new TriageFunction(Va(x.F.Start), Name(x.F), x.F.Size, x.Refs, callees.GetValueOrDefault(x.F.Start), Role(x.F, callees.GetValueOrDefault(x.F.Start))))
            .ToList();
        var strings = index.Strings.Select(s => (S: s, Refs: index.CountRefsTo(s.Rva))).Where(x => x.Refs > 0)
            .OrderByDescending(x => x.Refs).ThenBy(x => x.S.Rva).Take(Top)
            .Select(x => new TriageString(Va(x.S.Rva), (x.S.Encoding == StringEncoding.Utf16 ? "L" : "") + "\"" + Format.Clip(index.ReadString(x.S, 200), 120) + "\"", x.Refs))
            .ToList();
        var apis = image.Imports.Where(i => i.Name != null).Select(i => (i.Module, i.Name!)).ToList();
        if (CallAnalysis.Supports(index)) apis.AddRange(CallAnalysis.For(index).DynamicImports(ct).Imports.Select(d => (d.Module ?? "", d.Name)));
        var groups = ApiCapabilities.Classify(apis, examples: 8);
        int other = apis.Select(a => ApiCapabilities.Bare(a.Item2)).Distinct(StringComparer.Ordinal)
            .Count(a => !ApiCapabilities.Classify([("", a)]).Any());
        bool ordinals = image.Format == ImageFormat.Pe;
        var entries = new List<TriageEntry>();
        if (image.EntryPointRva != 0) entries.Add(new TriageEntry(Va(image.EntryPointRva), "entry", index.NameAt(image.EntryPointRva) ?? "entry", null));
        entries.AddRange(image.TlsCallbackRvas.Select(t => new TriageEntry(Va(t), "tls_callback", index.NameAt(t) ?? Va(t), null)));
        entries.AddRange(image.Exports.Where(e => e.ForwardedTo == null).Take(200)
            .Select(e => new TriageEntry(Va(e.Rva), "export", e.Name ?? $"#{e.Ordinal}", ordinals ? (int)e.Ordinal : null)));
        return new NativeTriage(index.Functions.Count, named, index.Functions.Count - named, thunks, library, index.Strings.Count,
            image.Imports.Count, image.Exports.Count,
            image.Sections.Select(s => new TriageSegment(s.Name, Va(s.Rva), Va(s.Rva + s.VirtualSize),
                $"{((s.Access & SectionAccess.Read) != 0 ? 'r' : '-')}{((s.Access & SectionAccess.Write) != 0 ? 'w' : '-')}{((s.Access & SectionAccess.Execute) != 0 ? 'x' : '-')}")).ToList(),
            entries, top, strings, groups.Select(g => new CapabilityGroup(g.Group, g.Count, g.Apis)).ToList(), other,
            new TriageCallGraph(edges, roots.Count, leaves, roots.OrderBy(f => entryish.Contains(f.Start) ? 0 : 1).ThenBy(f => f.Start).Take(25).Select(Name).ToList()));
    }

    /// <summary>A function's shape from its size and distinct call targets.</summary>
    internal static string Role(NativeFunction f, int callees) =>
        (f.Flags & FunctionFlags.Thunk) != 0 || f.Size <= 8 ? "thunk"
        : callees == 1 && f.Size < 100 ? "wrapper"
        : callees == 0 ? "leaf"
        : callees > 10 ? "dispatcher"
        : "complex";
}
