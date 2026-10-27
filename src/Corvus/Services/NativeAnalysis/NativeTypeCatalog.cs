using System.ComponentModel;
using dnlib.DotNet;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Msvc;
using Corvus.Native.Pdb;
using Corvus.Native.Providers;

namespace Corvus.Services;

[Description("A field of a type, a base subobject, a vftable pointer, a static member or a padding gap.")]
public sealed record NativeTypeField(
    [property: Description("Offset in bytes from the start of the type; -1 for static members and virtual bases.")] long Offset,
    [property: Description("Size in bytes (a bit field's storage unit); -1 when unknown.")] long Size,
    [property: Description("Name; nested rows (depth > 0) are dotted paths such as header.magic.")] string Name,
    [property: Description("C spelling of the field's type.")] string Type,
    [property: Description("Id of the field's type for get_native_type id=...; null for scalars.")] string? TypeId,
    [property: Description("member, base, vbase, vfptr, static, padding or header (AOT object header).")] string Kind,
    [property: Description("First bit of a bit field in its storage unit.")] int? BitOffset,
    [property: Description("Width of a bit field in bits.")] int? BitSize,
    [property: Description("Source-specific detail: the managed type and declaring class for AOT metadata, computed offsets.")] string? Note)
{
    [Description("read=true: the field's value in the image's bytes.")]
    public string? Value { get; init; }
}

public sealed record NativeTypeEnumerator(string Name, [property: Description("The value in hex (two's complement for negatives).")] string Hex, long Value);

public sealed record NativeTypeParameter(string? Name, string Type, string? TypeId);

public sealed record NativeTypeFunction(string Return, string? ReturnId, IReadOnlyList<NativeTypeParameter> Parameters, bool Variadic, string Convention,
    [property: Description("The this pointer's type of a member function; null otherwise.")] string? This);

public sealed record NativeTypeBase([property: Description("Offset of the base subobject; -1 for a virtual base.")] long Offset, string Name, string? Id, bool Virtual);

public sealed record NativeVftableSlot(int Index, [property: Description("Byte offset of the slot in the vftable ([rax+40h] reads slot 8 on x64).")] long Offset, string Address, string? Name);

public sealed record NativeVftable(
    [property: Description("VA of the vftable.")] string Address,
    [property: Description("Offset of the subobject whose vftable pointer points here.")] long SubobjectOffset,
    [property: Description("Slots in the vftable.")] int Slots,
    [property: Description("One page of the slots (offset / limit).")] IReadOnlyList<NativeVftableSlot> Entries);

[Description("A native type with its layout.")]
public sealed record NativeTypeView(
    [property: Description("Stable id: pdb:0x1A2B (type record), pdb:Name (typedef), rtti:<type descriptor VA>, metadata:Ns.Type (#statics), ida:Name.")] string Id,
    string Name,
    [property: Description("struct, class, union, enum, typedef, pointer, array, function, bitfield, scalar, modifier, interface or statics.")] string Kind,
    [property: Description("pdb, rtti, pdb+rtti, metadata or the engine's id.")] string Source,
    [property: Description("Size in bytes; -1 when the source does not record it (RTTI).")] long Size,
    [property: Description("Alignment; for PDB types computed from the members (the PDB records none).")] long? Alignment,
    [property: Description("A member is not at its natural alignment (#pragma pack).")] bool Packed,
    [property: Description("Only a forward declaration exists in the source.")] bool ForwardOnly,
    [property: Description("Id of the pointee, array element, enum's underlying type or typedef's target.")] string? Referenced,
    long? ArrayCount,
    [property: Description("Fields in offset order, one page of them.")] IReadOnlyList<NativeTypeField> Fields,
    [property: Description("Fields in total (after depth expansion).")] int TotalFields,
    [property: Description("Enumerators sorted by value, one page of them.")] IReadOnlyList<NativeTypeEnumerator> Enumerators,
    [property: Description("Every enumerator is a power of two or a combination of them.")] bool FlagsLike,
    NativeTypeFunction? Function,
    IReadOnlyList<NativeTypeBase> Bases,
    IReadOnlyList<NativeVftable> Vftables,
    [property: Description("Data symbols (PDB globals) of this type: count, and the first names.")] int GlobalsOfType,
    IReadOnlyList<string> Globals,
    [property: Description("C declaration (format=c, or the engine's own).")] string? Declaration,
    IReadOnlyList<string> Notes);

[Description("A type a name matched.")]
public sealed record NativeTypeCandidate(string Id, string Name, string Kind, long Size, string Source);

[Description("The field at an offset: one path per overlapping member (unions, bit fields sharing a unit).")]
public sealed record NativeFieldPath(
    [property: Description("C path from the type: players[3].pos.y.")] string Path,
    [property: Description("Offset of the field reached, from the start of the type the path starts at.")] long Offset,
    [property: Description("Type of the field reached.")] string Type,
    [property: Description("Bytes into that field (0 at its start).")] long Remainder);

/// <summary>Native types from every source of an image (PDB, RTTI, metadata layouts, engine), by name, id or typed address.</summary>
public sealed partial class NativeTypeCatalog(AssemblyWorkspace workspace, NativeCodeService? code = null)
{
    public const string Pdb = "pdb", Rtti = "rtti", Metadata = "metadata", Engine = "engine", ObjC = "objc", Swift = "swift";
    /// <summary>Most rows of a substring search; most nested fields an expansion adds.</summary>
    public const int MaxCandidates = 5000, MaxExpandedFields = 20_000;
    private const int MaxPathDepth = 16, MaxPaths = 64;

    /// <summary>The sources of one image for one call.</summary>
    public sealed class Context
    {
        public required LoadedNative Native { get; init; }
        public PdbFile? PdbFile { get; init; }
        public PdbTypeModel? Model { get; init; }
        public NativeCodeIndex? Index { get; init; }
        public INativeDecompilerSession? Session { get; init; }
        /// <summary>The engine was asked for explicitly (source=engine): its types are candidates even when another source has the name.</summary>
        public bool EngineRequested { get; init; }
        public required IReadOnlySet<string> Sources { get; init; }
        public List<string> Notes { get; } = [];
        /// <summary>The page of vftable slots views carry.</summary>
        public int SlotOffset { get; set; }
        public int SlotLimit { get; set; } = 200;
        internal readonly Dictionary<string, NativeTypeView> Views = new(StringComparer.Ordinal);
        internal MsvcRttiResult? RttiResult;
        internal List<TypeDef>? AotMetadataTypes;
        internal AotNativeNames.Applied? AotApplied;
        public bool Uses(string source) => Sources.Contains(source);
        public string Va(uint rva) => NativeAddress.Va(Native.Image, rva);
    }

    /// <summary>Opens the requested <paramref name="sources"/> (pdb, rtti, metadata, engine) of <paramref name="native"/>; a PDB
    /// beside the image is found by the code index build.</summary>
    public async Task<Context> Open(LoadedNative native, IReadOnlySet<string> sources, INativeDecompilerSession? session, bool engineRequested, CancellationToken ct)
    {
        PdbFile? pdb = null;
        NativeCodeIndex? index = code?.Ready(native);
        if (sources.Contains(Pdb))
        {
            // A matching PDB beside the image (DWARF for ELF and Mach-O) is read during the first index build.
            if (PdbService.StateOf(native) == null && code != null && native.Image.Format is ImageFormat.Pe or ImageFormat.Elf or ImageFormat.MachO)
                index = await code.Index(native, null, ct).ConfigureAwait(false);
            pdb = PdbService.StateOf(native)?.Pdb;
        }
        var model = pdb != null ? await Task.Run(() => PdbTypeModel.Of(pdb, PointerSize(native), ct), ct).ConfigureAwait(false) : null;
        var context = new Context { Native = native, PdbFile = pdb, Model = model, Index = index ?? code?.Ready(native), Session = session, EngineRequested = engineRequested, Sources = sources };
        if (sources.Contains(Pdb) && pdb == null) context.Notes.Add("no PDB is loaded for the image (load_pdb)");
        // The IPI stream only matters for prototypes.
        if (model != null) context.Notes.AddRange(model.Notes.Where(n => n.Contains("TPI", StringComparison.Ordinal)).Select(n => "pdb: " + n));
        return context;
    }

    private static int PointerSize(LoadedNative native) => native.Image.Is64Bit ? 8 : 4;

    private static MsvcRttiResult? RttiOf(Context c, CancellationToken ct)
    {
        if (!c.Uses(Rtti)) return null;
        return c.RttiResult ??= c.Native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, ct));
    }

    private List<TypeDef> AotTypesOf(Context c)
    {
        if (!c.Uses(Metadata)) return [];
        if (c.AotMetadataTypes != null) return c.AotMetadataTypes;
        c.AotApplied = AotNativeNames.Of(c.Native);
        c.AotMetadataTypes = c.AotApplied == null ? [] : workspace.Read(() => c.AotApplied.Image.Assemblies.SelectMany(a => a.Module.GetTypes()).ToList());
        return c.AotMetadataTypes;
    }

    /// <summary>A candidate and how to build its view (null for an engine type listed by a search: read by id).</summary>
    private sealed record Hit(NativeTypeCandidate Candidate, Func<NativeTypeView>? View);

    /// <summary>The type named <paramref name="name"/> (exact, then case-insensitive), else substring candidates; Ambiguous on several definitions.</summary>
    public async Task<(Func<NativeTypeView>? View, IReadOnlyList<NativeTypeCandidate> Candidates, int Total)> Find(Context c, string name, int offset, int limit,
        CancellationToken ct)
    {
        // A glob (* and ?) lists every match, never one type.
        if (Wildcard.IsPattern(name))
        {
            var literal = name.Split('*', '?').MaxBy(p => p.Length) ?? "";
            var globbed = await Collect(c, n => Wildcard.Matches(n, name), literal, null, ct).ConfigureAwait(false);
            var all = Ordered(globbed);
            return (null, all.Skip(offset).Take(limit).ToList(), all.Count);
        }
        foreach (var comparison in new[] { StringComparison.Ordinal, StringComparison.OrdinalIgnoreCase })
        {
            var hits = await Collect(c, n => string.Equals(n, name, comparison), name, comparison, ct).ConfigureAwait(false);
            if (hits.Count == 1 && hits[0].View is { } only) return (only, [], 1);
            if (hits.Count > 1)
                throw new ToolError(ErrorCode.Ambiguous, $"{hits.Count} types are named '{name}': " +
                    string.Join("; ", hits.Take(20).Select(h => $"{h.Candidate.Id} ({h.Candidate.Kind}{SizeText(h.Candidate.Size)}, {h.Candidate.Source})")) +
                    (hits.Count > 20 ? $"; +{hits.Count - 20} more" : ""),
                    "pass id= with one of these ids");
        }
        var found = await Collect(c, n => n.Contains(name, StringComparison.OrdinalIgnoreCase), name, null, ct).ConfigureAwait(false);
        var ordered = Ordered(found);
        return (null, ordered.Skip(offset).Take(limit).ToList(), ordered.Count);
    }

    private static List<NativeTypeCandidate> Ordered(List<Hit> hits) =>
        hits.Select(h => h.Candidate).OrderBy(x => x.Name.Length).ThenBy(x => x.Name, StringComparer.Ordinal).ThenBy(x => x.Id, StringComparer.Ordinal).ToList();

    private static string SizeText(long size) => size >= 0 ? $", {size} bytes" : "";

    /// <summary>Types whose name <paramref name="match"/> accepts; <paramref name="exact"/>: the comparison of an exact-name lookup, null for a substring search.</summary>
    private async Task<List<Hit>> Collect(Context c, Func<string, bool> match, string text, StringComparison? exact, CancellationToken ct)
    {
        var hits = new List<Hit>();
        var pdbByName = new Dictionary<string, List<Hit>>(StringComparer.Ordinal);
        if (c.Model is { } model)
        {
            IEnumerable<string> names = exact == StringComparison.Ordinal ? model.Named(text).Count > 0 ? [text] : [] : model.Names.Where(match);
            foreach (var n in names)
                // Compilands repeat anonymous-namespace types and lambdas under unique names: one per layout.
                foreach (var same in Definitions(model, n))
                {
                    if (hits.Count >= MaxCandidates) break;
                    var index = same.First();
                    var others = same.Skip(1).Select(PdbId).ToList();
                    var node = model.Node(index)!;
                    NativeTypeView Build()
                    {
                        var v = PdbView(c, index);
                        if (others.Count == 0) return v;
                        return v with { Notes = [.. v.Notes, $"{others.Count} identical definition(s) from other compilands: {string.Join(", ", others.Take(10))}{(others.Count > 10 ? ", ..." : "")}"] };
                    }
                    var hit = new Hit(new NativeTypeCandidate(PdbId(index), node.Name, KindOf(node), node.Forward ? -1 : node.Size, Pdb), Build);
                    hits.Add(hit);
                    (pdbByName.TryGetValue(n, out var l) ? l : pdbByName[n] = []).Add(hit);
                }
            // S_UDT names that differ from their tag.
            foreach (var t in c.PdbFile!.Typedefs)
            {
                if (hits.Count >= MaxCandidates) break;
                if (!match(t.Name) || pdbByName.ContainsKey(t.Name) || IsTag(model, t)) continue;
                var typedef = t;
                var hit = new Hit(new NativeTypeCandidate(Pdb + ":" + t.Name, t.Name, "typedef", model.SizeOf(t.TypeIndex), Pdb), () => TypedefView(c, typedef));
                hits.Add(hit);
                pdbByName[t.Name] = [hit];
            }
        }
        if (RttiOf(c, ct) is { } rtti)
            foreach (var cls in rtti.Classes.Where(x => match(x.Name)))
            {
                if (hits.Count >= MaxCandidates) break;
                var k = cls;
                // The PDB's single definition of the class takes RTTI's vftables.
                if (pdbByName.TryGetValue(cls.Name, out var same) && same.Count == 1 && same[0].Candidate.Id.StartsWith("pdb:0x", StringComparison.Ordinal))
                {
                    var pdbHit = same[0];
                    int at = hits.IndexOf(pdbHit);
                    hits[at] = new Hit(pdbHit.Candidate with { Source = Pdb + "+" + Rtti }, () => WithRtti(c, pdbHit.View!(), k));
                    continue;
                }
                hits.Add(new Hit(new NativeTypeCandidate(RttiId(c, cls), cls.Name, cls.Kind, (long?)cls.Pascal?.InstanceSize ?? -1, Rtti), () => RttiView(c, k)));
            }
        foreach (var t in AotTypesOf(c))
        {
            if (hits.Count >= MaxCandidates) break;
            var key = AotNames.TypeKey(t);
            if (!match(key) && !match(t.Name.String)) continue;
            var type = t;
            hits.Add(new Hit(new NativeTypeCandidate(Metadata + ":" + key, key, t.IsValueType ? "struct" : t.IsInterface ? "interface" : "class", -1, Metadata),
                () => AotView(c, type, statics: false)));
        }
        CollectApple(c, match, hits, ct);
        if (c.Session is { } session)
        {
            var known = hits.Select(h => h.Candidate.Name).ToHashSet(StringComparer.Ordinal);
            var engineHits = new List<Hit>();
            if (exact != null)
            {
                var detail = await TryEngineType(session, text, ct).ConfigureAwait(false);
                if (detail != null && match(detail.Name)) engineHits.Add(EngineHit(session, detail));
            }
            else
            {
                var list = await session.ListTypesAsync(text, null, 0, Math.Max(1, MaxCandidates - hits.Count), ct).ConfigureAwait(false);
                foreach (var e in list.Types.Where(e => match(e.Name)))
                {
                    engineHits.Add(new Hit(new NativeTypeCandidate(session.ProviderId + ":" + e.Name, e.Name, e.Kind, e.Size, session.ProviderId), null));
                }
            }
            // Types the image's own sources describe were pushed into the engine from them: the same type.
            hits.AddRange(c.EngineRequested ? engineHits : engineHits.Where(h => !known.Contains(h.Candidate.Name)));
        }
        return hits;
    }

    /// <summary>The records named <paramref name="name"/> grouped by layout; forward-only records only when no definition has the name.</summary>
    private static IEnumerable<List<uint>> Definitions(PdbTypeModel model, string name)
    {
        var named = model.Named(name);
        if (named is [var single]) return [[single]];
        var defined = named.Where(i => model.DefinitionOf(i) != 0).ToList();
        return (defined.Count > 0 ? defined : named).GroupBy(i => Layout(model, i)).Select(g => g.ToList());
    }

    /// <summary>A record's layout as text: kind, size, members (offset, name, type, bits) and enumerators.</summary>
    private static string Layout(PdbTypeModel model, uint index)
    {
        var node = model.Node(index)!;
        var sb = new System.Text.StringBuilder($"{node.Kind};{node.Size};{node.Forward}");
        foreach (var m in node.Members) sb.Append($";{m.Kind},{m.Offset},{m.Name},{model.Spell(m.Type)},{m.BitLength},{m.BitPosition}");
        foreach (var e in node.Enumerators) sb.Append($";{e.Name}={e.Value}");
        return sb.ToString();
    }

    private static bool IsTag(PdbTypeModel model, PdbTypedef t)
    {
        if (t.TypeIndex < 0x1000 || model.DefinitionOf(t.TypeIndex) is not (> 0 and var def)) return false;
        return model.Node(def)?.Name == t.Name;
    }

    private static async Task<NativeTypeDetail?> TryEngineType(INativeDecompilerSession session, string name, CancellationToken ct)
    {
        try { return await session.GetTypeAsync(name, ct).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound) { return null; }
    }

    private static Hit EngineHit(INativeDecompilerSession session, NativeTypeDetail d) =>
        new(new NativeTypeCandidate(session.ProviderId + ":" + d.Name, d.Name, d.Kind, d.Size, session.ProviderId), () => EngineView(session.ProviderId, d));

    /// <summary>The type with id <paramref name="id"/> (as views and candidates list them).</summary>
    public async Task<NativeTypeView> Get(Context c, string id, CancellationToken ct)
    {
        var view = await TryGet(c, id, ct).ConfigureAwait(false);
        return view ?? throw new ToolError(ErrorCode.NotFound, $"No type has id '{id}' in {c.Native.Id}.",
            "ids look like pdb:0x1A2B, pdb:Name, rtti:0x140012000, metadata:Ns.Type or ida:Name; name= searches by name");
    }

    private async Task<NativeTypeView?> TryGet(Context c, string id, CancellationToken ct)
    {
        int colon = id.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0) return null;
        var (prefix, rest) = (id[..colon].Trim().ToLowerInvariant(), id[(colon + 1)..].Trim());
        switch (prefix)
        {
            case Pdb when c.Model is { } model:
                if (NativeAddress.Number(rest) is { } index && index <= uint.MaxValue && model.Node((uint)index) != null) return PdbView(c, (uint)index);
                return c.PdbFile!.Typedefs.FirstOrDefault(t => t.Name == rest) is { } typedef ? TypedefView(c, typedef) : null;
            case Rtti:
                if (NativeAddress.Number(rest) is not { } va || RttiOf(c, ct) is not { } rtti) return null;
                var rva = va - c.Native.Image.ImageBase;
                return rtti.Classes.FirstOrDefault(x => x.TypeDescriptorRva == rva) is { } cls
                    ? (PdbClass(c, cls.Name) is { } pdb ? WithRtti(c, PdbView(c, pdb), cls) : RttiView(c, cls)) : null;
            case ObjC or Swift:
                return AppleView(c, prefix, rest, ct);
            case Metadata:
            {
                bool statics = rest.EndsWith("#statics", StringComparison.Ordinal);
                var key = statics ? rest[..^"#statics".Length] : rest;
                return AotTypesOf(c).FirstOrDefault(t => AotNames.TypeKey(t) == key) is { } t ? AotView(c, t, statics) : null;
            }
            default:
                if (c.Session is { } session && string.Equals(prefix, session.ProviderId, StringComparison.OrdinalIgnoreCase))
                    return await TryEngineType(session, rest, ct).ConfigureAwait(false) is { } d ? EngineView(session.ProviderId, d) : null;
                return null;
        }
    }

    /// <summary>The PDB's single definition of a class RTTI names, or null.</summary>
    private static uint? PdbClass(Context c, string name) => c.Model?.Named(name) is [var only] ? only : null;

    /// <summary>What a typed address is: the type, where it starts, the field path into it.</summary>
    public sealed record TypedAddress(NativeTypeView Type, string Owner, uint Start, IReadOnlyList<NativeFieldPath> Paths, string Note);

    /// <summary>The type at <paramref name="rva"/> (PDB global, RTTI structure or metadata slot); null when no source types it.</summary>
    public TypedAddress? AtAddress(Context c, uint rva, CancellationToken ct)
    {
        if (c.Model is { } model && GlobalAt(c.PdbFile!, model, rva) is { } g)
        {
            var type = model.DefinitionOf(g.Type) is > 0 and var def ? def : g.Type;
            var view = PdbView(c, type);
            var paths = Paths(c, view, rva - g.Symbol.Rva!.Value, ct);
            return new TypedAddress(view, g.Symbol.Name, g.Symbol.Rva!.Value, paths, $"PDB {(g.Symbol.Kind == PdbSymbolKind.GlobalData ? "global" : "static")} {g.Symbol.Name} ({model.Spell(g.Type)}, {g.Size} bytes)");
        }
        if (RttiOf(c, ct) is { } rtti)
        {
            int slotSize = PointerSize(c.Native);
            foreach (var cls in rtti.Classes)
            {
                foreach (var v in cls.Vtables)
                    if (rva >= v.VftableRva && rva < v.VftableRva + (uint)(v.SlotRvas.Count * slotSize))
                    {
                        int slot = (int)((rva - v.VftableRva) / (uint)slotSize);
                        var view = PdbClass(c, cls.Name) is { } p ? WithRtti(c, PdbView(c, p), cls) : RttiView(c, cls);
                        var target = v.SlotRvas[slot];
                        return new TypedAddress(view, $"{cls.Name}::`vftable'", v.VftableRva, [],
                            $"vftable of {cls.Name} (subobject +0x{v.Offset:X}), slot {slot} -> {c.Va(target)}{(c.Index?.NameAt(target) is { } n ? " " + n : "")}");
                    }
                if (rva == cls.TypeDescriptorRva || cls.Vtables.Any(v => v.LocatorRva == rva))
                    return new TypedAddress(PdbClass(c, cls.Name) is { } p ? WithRtti(c, PdbView(c, p), cls) : RttiView(c, cls), cls.Name, rva, [],
                        rva == cls.TypeDescriptorRva ? $"RTTI type descriptor of {cls.Name}" : $"RTTI complete object locator of {cls.Name}");
            }
        }
        if (AotTypesOf(c).Count > 0 && c.AotApplied?.Image.Script is { } script && script.MetadataAt(rva) is { } entry
            && script.MetadataAddress(entry) == rva && AotNames.MetadataSubject(script.MetadataName(entry)) is { } subject)
        {
            var metadata = script.MetadataName(entry);
            var key = AotNames.StripArgs(subject.EndsWith("[]", StringComparison.Ordinal) ? subject[..^2] : subject);
            if (c.AotMetadataTypes!.FirstOrDefault(t => AotNames.TypeKey(t) == key) is { } type)
                return new TypedAddress(AotView(c, type, statics: false), metadata, rva, [], $"AOT metadata slot {metadata}: the class of {key}");
        }
        return null;
    }

    /// <summary>The PDB data symbol covering <paramref name="rva"/> (the nearest start wins), its type record and size.</summary>
    public static (PdbSymbol Symbol, uint Type, long Size)? GlobalAt(PdbFile pdb, PdbTypeModel model, uint rva)
    {
        var symbols = pdb.Symbols;
        int lo = 0, hi = symbols.Count - 1, last = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (symbols[mid].Rva is { } r && r <= rva) { last = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        for (int i = last, seen = 0; i >= 0 && seen < 256; i--, seen++)
        {
            var s = symbols[i];
            if (s.Kind is not (PdbSymbolKind.GlobalData or PdbSymbolKind.LocalData) || s.TypeIndex == 0) continue;
            long size = model.SizeOf(s.TypeIndex);
            if (rva - s.Rva!.Value < (ulong)Math.Max(1, size)) return (s, s.TypeIndex, size);
        }
        return null;
    }

    /// <summary>One line for resolve_address: the PDB global covering <paramref name="rva"/> and the field there; null when none.</summary>
    public static string? DescribeTypedData(LoadedNative native, uint rva)
    {
        if (PdbService.StateOf(native)?.Pdb is not { } pdb) return null;
        // The type stream is read only when a data symbol starts before the address.
        if (!pdb.Symbols.Any(s => s.Kind is PdbSymbolKind.GlobalData or PdbSymbolKind.LocalData && s.TypeIndex != 0 && s.Rva <= rva)) return null;
        PdbTypeModel model;
        try { model = PdbTypeModel.Of(pdb, PointerSize(native)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
        if (GlobalAt(pdb, model, rva) is not { } g) return null;
        var c = new Context { Native = native, PdbFile = pdb, Model = model, Sources = new HashSet<string> { Pdb } };
        var start = g.Symbol.Rva!.Value;
        var view = PdbView(c, model.DefinitionOf(g.Type) is > 0 and var def ? def : g.Type);
        var paths = Paths(c, view, rva - start, default);
        var at = rva == start ? g.Symbol.Name : $"{g.Symbol.Name}+0x{rva - start:X}";
        if (paths.Count == 0) return $"typed data: {at} ({model.Spell(g.Type)})";
        return $"typed data: {at} = " + string.Join(" | ", paths.Take(4).Select(p => FormatPath(g.Symbol.Name, p)));
    }

    /// <summary>"g.players[3].pos.y (float)", with the bytes into the field when the address is inside it.</summary>
    public static string FormatPath(string owner, NativeFieldPath p) =>
        $"{owner}{(p.Path.StartsWith('[') ? "" : ".")}{p.Path} ({p.Type}{(p.Remainder > 0 ? $", +0x{p.Remainder:X} into it" : "")})";

    /// <summary>The field paths at <paramref name="offset"/>, through by-value structs, unions and arrays; one per overlapping member.</summary>
    public static List<NativeFieldPath> Paths(Context c, NativeTypeView view, long offset, CancellationToken ct)
    {
        var paths = new List<NativeFieldPath>();
        Walk(c, view, offset, "", 0, 0, paths, ct);
        return paths;
    }

    private static void Walk(Context c, NativeTypeView view, long offset, string prefix, long baseOffset, int depth, List<NativeFieldPath> paths, CancellationToken ct)
    {
        if (paths.Count >= MaxPaths) return;
        ct.ThrowIfCancellationRequested();
        if (view.Kind == "array" && view.ArrayCount is > 0 && view.Size > 0)
        {
            long es = view.Size / view.ArrayCount.Value;
            long i = es > 0 ? offset / es : 0;
            var element = es > 0 && depth < MaxPathDepth && view.Referenced is { } elementId ? Resolve(c, elementId) : null;
            var path = $"{prefix}[{i}]";
            if (element is { Kind: "struct" or "class" or "union" or "array" } && i < view.ArrayCount)
                Walk(c, element, offset - i * es, path, baseOffset + i * es, depth + 1, paths, ct);
            else paths.Add(new NativeFieldPath(path, baseOffset + i * es, element?.Name ?? ElementName(view.Name), offset - i * es));
            return;
        }
        var hits = view.Fields.Where(f => f.Kind is "member" or "base" or "vfptr" or "header" && f.Offset >= 0 && offset >= f.Offset && offset < f.Offset + Math.Max(1, f.Size)).ToList();
        if (hits.Count == 0)
        {
            if (prefix.Length > 0) paths.Add(new NativeFieldPath(prefix, baseOffset, view.Name, offset));
            else if (view.Fields.FirstOrDefault(f => f.Kind == "padding" && offset >= f.Offset && offset < f.Offset + f.Size) is { } pad)
                paths.Add(new NativeFieldPath(pad.Name, pad.Offset, pad.Type, offset - pad.Offset));
            return;
        }
        foreach (var f in hits)
        {
            var name = f.Kind == "base" ? $"({f.Type})" : f.Name;
            var path = prefix.Length == 0 ? name : $"{prefix}.{name}";
            var inner = f.BitSize == null && f.TypeId != null && depth < MaxPathDepth ? Resolve(c, f.TypeId) : null;
            if (inner is { Kind: "struct" or "class" or "union" or "array" } && inner.Fields.Count + (inner.Kind == "array" ? 1 : 0) > 0)
                Walk(c, inner, offset - f.Offset, path, baseOffset + f.Offset, depth + 1, paths, ct);
            else paths.Add(new NativeFieldPath(f.BitSize is { } bits ? $"{path} (bits {f.BitOffset}..{f.BitOffset + bits - 1})" : path, baseOffset + f.Offset, f.Type,
                offset - f.Offset));
        }
    }

    /// <summary>"int" of "int[4]"; the name itself when it is not an array spelling.</summary>
    private static string ElementName(string array) =>
        array.EndsWith(']') && array.LastIndexOf('[') is > 0 and var at ? array[..at].TrimEnd() : array;

    /// <summary>Follows dotted offsets in <paramref name="at"/>, each through the pointer field the previous reached ([[p+48h]+10h] is 0x48.0x10).</summary>
    public static List<NativeFieldPath> FollowPath(Context c, NativeTypeView view, string at, CancellationToken ct)
    {
        var parts = at.Split(['.', '>'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(p => p.TrimStart('+').TrimEnd('-')).ToList();
        var current = view;
        var prefix = "";
        List<NativeFieldPath> paths = [];
        for (int i = 0; i < parts.Count; i++)
        {
            if (NativeAddress.Number(parts[i]) is not { } offset || offset > int.MaxValue)
                throw new ToolError(ErrorCode.InvalidArgument, $"'{parts[i]}' in at='{at}' is not an offset.", "use a hex offset such as 0x48, or 0x48.0x10 to read through a pointer field");
            paths = Paths(c, current, (long)offset, ct);
            if (prefix.Length > 0) paths = paths.Select(p => p with { Path = $"{prefix}->{p.Path}" }).ToList();
            if (i == parts.Count - 1) break;
            // The next offset applies to what the single field reached points to.
            var target = paths.Count == 1 ? PointeeAt(c, current, (long)offset) : null;
            if (target == null)
                throw new ToolError(ErrorCode.InvalidArgument, $"The field at 0x{offset:X} of {current.Name} ({(paths.Count == 1 ? paths[0].Type : $"{paths.Count} overlapping fields")}) is not a pointer to a known type, so '{parts[i + 1]}' cannot be followed.",
                    "pass the offsets up to that field, then get_native_type the pointee by name");
            prefix = paths[0].Path;
            current = target;
        }
        return paths;
    }

    /// <summary>The type a pointer field at <paramref name="offset"/> points to, or null.</summary>
    private static NativeTypeView? PointeeAt(Context c, NativeTypeView view, long offset)
    {
        var field = Leaf(c, view, offset, 0);
        if (field?.TypeId is not { } id || Resolve(c, id) is not { Kind: "pointer", Referenced: { } pointee }) return null;
        return Resolve(c, pointee);
    }

    private static NativeTypeField? Leaf(Context c, NativeTypeView view, long offset, int depth)
    {
        if (depth > MaxPathDepth) return null;
        if (view.Kind == "array" && view.ArrayCount is > 0 && view.Referenced is { } e && Resolve(c, e) is { } element)
        {
            long es = view.Size / view.ArrayCount.Value;
            return es > 0 ? Leaf(c, element, offset % es, depth + 1) : null;
        }
        var f = view.Fields.FirstOrDefault(f => f.Kind is "member" or "base" or "vfptr" or "header" && f.Offset >= 0 && offset >= f.Offset && offset < f.Offset + Math.Max(1, f.Size));
        if (f == null) return null;
        var inner = f.TypeId != null ? Resolve(c, f.TypeId) : null;
        return inner is { Kind: "struct" or "class" or "union" or "array" } ? Leaf(c, inner, offset - f.Offset, depth + 1) ?? f : f;
    }

    /// <summary>A view by id for path walking: built-in sources only (engine types have no ids for their members).</summary>
    private static NativeTypeView? Resolve(Context c, string id)
    {
        if (c.Views.TryGetValue(id, out var cached)) return cached;
        NativeTypeView? view = null;
        if (id.StartsWith("pdb:0x", StringComparison.Ordinal) && c.Model != null && NativeAddress.Number(id[4..]) is { } index && index <= uint.MaxValue)
            view = c.Model.Node((uint)index) != null ? PdbView(c, (uint)index) : null;
        else if (id.StartsWith("metadata:", StringComparison.Ordinal) && c.AotMetadataTypes is { } types)
        {
            var key = id["metadata:".Length..];
            view = types.FirstOrDefault(t => AotNames.TypeKey(t) == key) is { } t ? AotView(c, t, statics: false) : null;
        }
        if (view != null && c.Views.Count < 4096) c.Views[id] = view;
        return view;
    }

    /// <summary>The fields with by-value members expanded <paramref name="depth"/> levels (arrays: element [0]); pointers are not followed.</summary>
    public static List<NativeTypeField> Expand(Context c, NativeTypeView view, int depth, List<string> notes)
    {
        var rows = new List<NativeTypeField>();
        var visiting = new HashSet<string>(StringComparer.Ordinal) { view.Id };
        bool capped = false, arrays = false;
        void Add(IReadOnlyList<NativeTypeField> fields, string prefix, long baseOffset, int level)
        {
            foreach (var f in fields)
            {
                if (rows.Count >= MaxExpandedFields) { capped = true; return; }
                var name = prefix.Length == 0 ? f.Name : $"{prefix}.{f.Name}";
                rows.Add(f with { Name = name, Offset = f.Offset >= 0 ? baseOffset + f.Offset : f.Offset });
                if (level >= depth || f.Offset < 0 || f.TypeId == null || f.BitSize != null || !visiting.Add(f.TypeId)) continue;
                var inner = Resolve(c, f.TypeId);
                if (inner is { Kind: "array", ArrayCount: > 0, Referenced: { } e } && Resolve(c, e) is { Kind: "struct" or "class" or "union" } element && visiting.Add(element.Id))
                {
                    arrays = true;
                    Add(element.Fields, name + "[0]", baseOffset + f.Offset, level + 1);
                    visiting.Remove(element.Id);
                }
                else if (inner is { Kind: "struct" or "class" or "union" }) Add(inner.Fields, name, baseOffset + f.Offset, level + 1);
                visiting.Remove(f.TypeId);
            }
        }
        Add(view.Fields, "", 0, 0);
        if (arrays) notes.Add("array members are expanded for element [0]; the others repeat at the element size");
        if (capped) notes.Add($"expansion stopped at {MaxExpandedFields:N0} fields: lower depth");
        return rows;
    }

    private static string PdbId(uint index) => $"pdb:0x{index:X}";

    private static string RttiId(Context c, MsvcRttiClass cls) => $"rtti:{c.Va(cls.TypeDescriptorRva)}";

    private static string KindOf(PdbTypeNode node) => node.Kind switch
    {
        PdbTypeKind.Simple => "scalar",
        PdbTypeKind.Procedure or PdbTypeKind.MemberFunction => "function",
        _ => node.Kind.ToString().ToLowerInvariant(),
    };

    /// <summary>A type through modifiers and forward references: what a field's or pointer's id should name.</summary>
    private static uint Strip(PdbTypeModel model, uint index)
    {
        for (int i = 0; i < 16 && index >= 0x1000; i++)
        {
            var node = model.Node(index);
            if (node is { Kind: PdbTypeKind.Modifier }) index = node.Element;
            else if (node is { IsAggregate: true } or { Kind: PdbTypeKind.Enum }) return model.DefinitionOf(index) is > 0 and var def ? def : index;
            else return index;
        }
        return index;
    }

    private static string? TypeIdOf(PdbTypeModel model, uint index) => Strip(model, index) is >= 0x1000 and var t ? PdbId(t) : null;

    private static NativeTypeView Empty(string id, string name, string kind, string source, long size) =>
        new(id, name, kind, source, size, null, false, false, null, null, [], 0, [], false, null, [], [], 0, [], null, []);

    private static NativeTypeView PdbView(Context c, uint index)
    {
        var model = c.Model!;
        if (model.DefinitionOf(index) is > 0 and var def) index = def;
        var node = model.Node(index) ?? throw new ToolError(ErrorCode.NotFound, $"The PDB has no type record 0x{index:X}.");
        var view = Empty(PdbId(index), node.Name, KindOf(node), Pdb, node.Size);
        var notes = new List<string>();
        switch (node.Kind)
        {
            case PdbTypeKind.Struct or PdbTypeKind.Class or PdbTypeKind.Interface or PdbTypeKind.Union:
            {
                if (node.Forward)
                {
                    notes.Add("only a forward declaration is in the PDB: no members");
                    view = view with { ForwardOnly = true, Size = -1 };
                    break;
                }
                var fields = new List<NativeTypeField>();
                var bases = new List<NativeTypeBase>();
                foreach (var m in node.Members)
                {
                    var spelled = model.Spell(m.Type);
                    long size = model.SizeOf(m.Type);
                    var kind = m.Kind switch
                    {
                        PdbMemberKind.Base => "base", PdbMemberKind.VirtualBase => "vbase", PdbMemberKind.Vfptr => "vfptr", PdbMemberKind.Static => "static", _ => "member",
                    };
                    if (m.Kind is PdbMemberKind.Base or PdbMemberKind.VirtualBase) bases.Add(new NativeTypeBase(m.Offset, spelled, TypeIdOf(model, m.Type), m.Kind == PdbMemberKind.VirtualBase));
                    var name = m.Kind is PdbMemberKind.Base or PdbMemberKind.VirtualBase ? $"<base {spelled}>" : m.Name;
                    fields.Add(new NativeTypeField(m.Offset, size, name, spelled, TypeIdOf(model, m.Type), kind,
                        m.BitLength >= 0 ? m.BitPosition : null, m.BitLength >= 0 ? m.BitLength : null, null));
                }
                var ordered = fields.Select((f, i) => (f, i)).OrderBy(x => x.f.Offset < 0 ? 1 : 0).ThenBy(x => x.f.Offset).ThenBy(x => x.i).Select(x => x.f).ToList();
                if (node.Kind != PdbTypeKind.Union) ordered = WithPadding(ordered, node.Size);
                var (align, packed) = Alignment(model, node);
                view = view with { Fields = ordered, TotalFields = ordered.Count, Bases = bases, Alignment = align, Packed = packed };
                notes.Add("alignment computed from the members (the PDB records none)");
                break;
            }
            case PdbTypeKind.Enum:
            {
                var values = node.Enumerators.Select((e, i) => (e, i)).OrderBy(x => x.e.Value).ThenBy(x => x.i)
                    .Select(x => new NativeTypeEnumerator(x.e.Name, Hex(x.e.Value, node.Size), x.e.Value)).ToList();
                view = view with { Enumerators = values, FlagsLike = FlagsLike(node.Enumerators.Select(e => e.Value).ToList()), Referenced = TypeIdOf(model, node.Element) ?? model.Spell(node.Element) };
                break;
            }
            case PdbTypeKind.Pointer or PdbTypeKind.Modifier or PdbTypeKind.Bitfield:
                view = view with { Referenced = TypeIdOf(model, node.Element) };
                break;
            case PdbTypeKind.Array:
                view = view with { Referenced = TypeIdOf(model, node.Element), ArrayCount = node.Count };
                break;
            case PdbTypeKind.Procedure or PdbTypeKind.MemberFunction:
            {
                var f = node.Function!;
                view = view with
                {
                    Function = new NativeTypeFunction(model.Spell(f.Return), TypeIdOf(model, f.Return),
                        f.Parameters.Select(p => new NativeTypeParameter(null, model.Spell(p), TypeIdOf(model, p))).ToList(), f.Variadic, f.Convention,
                        f.This != 0 ? model.Spell(f.This) : null),
                };
                break;
            }
        }
        return view with { Notes = notes };
    }

    /// <summary>Explicit gap rows between members and before the end.</summary>
    private static List<NativeTypeField> WithPadding(List<NativeTypeField> fields, long size)
    {
        var rows = new List<NativeTypeField>();
        long end = 0;
        int pad = 0;
        foreach (var f in fields)
        {
            if (f.Offset > end && f.Kind != "static" && f.Kind != "vbase")
                rows.Add(new NativeTypeField(end, f.Offset - end, $"<padding {pad++}>", $"unsigned char[{f.Offset - end}]", null, "padding", null, null, null));
            rows.Add(f);
            if (f.Offset >= 0) end = Math.Max(end, f.Offset + Math.Max(0, f.Size));
        }
        if (size > end) rows.Add(new NativeTypeField(end, size - end, $"<padding {pad}>", $"unsigned char[{size - end}]", null, "padding", null, null, null));
        return rows;
    }

    /// <summary>Natural alignment from the members, and whether a member sits off its own alignment.</summary>
    private static (long Align, bool Packed) Alignment(PdbTypeModel model, PdbTypeNode node)
    {
        long align = 1;
        bool packed = false;
        foreach (var m in node.Members.Where(m => m.Offset >= 0 && m.Kind != PdbMemberKind.Static))
        {
            long a = AlignOf(model, m.Type, 0);
            align = Math.Max(align, a);
            if (m.Offset % a != 0) packed = true;
        }
        return (align, packed || (node.Size > 0 && node.Size % align != 0));
    }

    private static long AlignOf(PdbTypeModel model, uint type, int depth)
    {
        if (depth > 8) return 1;
        var node = model.Node(Strip(model, type));
        return node switch
        {
            null => 1,
            { Kind: PdbTypeKind.Array or PdbTypeKind.Bitfield or PdbTypeKind.Enum } => AlignOf(model, node.Element, depth + 1),
            { IsAggregate: true } => node.Members.Where(m => m.Offset >= 0 && m.Kind != PdbMemberKind.Static).Select(m => AlignOf(model, m.Type, depth + 1)).DefaultIfEmpty(1).Max(),
            _ => Math.Clamp(node.Size is 10 or 16 ? 8 : node.Size, 1, 8),
        };
    }

    private static string Hex(long value, long size) =>
        value >= 0 ? $"0x{value:X}" : size is > 0 and < 8 ? $"0x{value & ((1L << (int)(size * 8)) - 1):X}" : $"0x{value:X}";

    /// <summary>True for two or more single-bit values with every other value a combination, excluding plain counts.</summary>
    public static bool FlagsLike(IReadOnlyList<long> values)
    {
        var bits = values.Where(v => v > 0 && (v & (v - 1)) == 0).ToList();
        if (bits.Count < 2) return false;
        long all = bits.Aggregate(0L, (a, b) => a | b);
        if (!values.All(v => v >= 0 && (v & ~all) == 0)) return false;
        var distinct = values.Where(v => v > 0).Distinct().Order().ToList();
        return distinct[^1] != distinct.Count;
    }

    /// <summary>The PDB data symbols whose type is <paramref name="view"/>'s (count and the first ten).</summary>
    public static NativeTypeView WithGlobals(Context c, NativeTypeView view)
    {
        if (!view.Id.StartsWith("pdb:0x", StringComparison.Ordinal) || NativeAddress.Number(view.Id[4..]) is not { } id) return view;
        var (count, globals) = GlobalsOf(c, (uint)id);
        return view with { GlobalsOfType = count, Globals = globals };
    }

    private static (int Count, IReadOnlyList<string> First) GlobalsOf(Context c, uint index)
    {
        if (c.PdbFile is not { } pdb || c.Model is not { } model) return (0, []);
        int count = 0;
        var first = new List<string>();
        // A global can be listed both in the globals stream and in its module's stream: count it once.
        var seen = new HashSet<(string, uint?)>();
        foreach (var s in pdb.Symbols)
        {
            if (s.Kind is not (PdbSymbolKind.GlobalData or PdbSymbolKind.LocalData) || s.TypeIndex == 0 || Strip(model, s.TypeIndex) != index) continue;
            if (!seen.Add((s.Name, s.Rva))) continue;
            count++;
            if (first.Count < 10) first.Add(s.Rva is { } r ? $"{s.Name} at {c.Va(r)}" : s.Name);
        }
        return (count, first);
    }

    private static NativeTypeView TypedefView(Context c, PdbTypedef t)
    {
        var model = c.Model!;
        var target = Strip(model, t.TypeIndex);
        var spelled = model.Spell(t.TypeIndex);
        // A typedef of a struct reads as the struct: its layout is what is asked for.
        if (model.Node(target) is { IsAggregate: true } or { Kind: PdbTypeKind.Enum })
        {
            var view = PdbView(c, target);
            return view with { Notes = [$"{t.Name} is a typedef of {spelled}", .. view.Notes] };
        }
        return Empty(Pdb + ":" + t.Name, t.Name, "typedef", Pdb, model.SizeOf(t.TypeIndex)) with
        {
            Referenced = TypeIdOf(model, t.TypeIndex), Declaration = $"typedef {spelled} {t.Name};", Notes = [$"typedef of {spelled}"],
        };
    }

    private static NativeTypeView RttiView(Context c, MsvcRttiClass cls)
    {
        if (cls.Pascal is { } pascal) return PascalView(c, cls, pascal);
        var view = Empty(RttiId(c, cls), cls.Name, cls.Kind, Rtti, -1);
        var fields = cls.Vtables.Select(v => new NativeTypeField(v.Offset, PointerSize(c.Native), "__vftable", $"{cls.Name}::`vftable' *", null, "vfptr", null, null,
            v.Offset == 0 ? null : $"subobject +0x{v.Offset:X}")).ToList();
        return view with
        {
            Fields = fields, TotalFields = fields.Count, Bases = Bases(c, cls), Vftables = Vftables(c, cls),
            Notes = ["RTTI records bases and vftables, not fields or size" + (c.PdbFile == null ? "; load_pdb adds the members when a PDB exists" : "")],
        };
    }

    /// <summary>An Object Pascal class: the VMT gives the instance size, the VMT pointer at 0 and the published fields (object references).</summary>
    private static NativeTypeView PascalView(Context c, MsvcRttiClass cls, Native.Pascal.PascalClass pascal)
    {
        int ptr = PointerSize(c.Native);
        var ids = c.RttiResult?.Classes.Where(k => k.Pascal != null).GroupBy(k => k.Name).ToDictionary(g => g.Key, g => RttiId(c, g.First()), StringComparer.Ordinal) ?? [];
        var fields = new List<NativeTypeField> { new(0, ptr, "__vmt", $"{cls.Name}::`vmt' *", null, "vfptr", null, null, null) };
        fields.AddRange(pascal.PublishedFields.OrderBy(f => f.Offset).Select(f => new NativeTypeField(f.Offset, ptr, f.Name, f.Type ?? "TObject", f.Type is { } t ? ids.GetValueOrDefault(t) : null,
            "member", null, null, "published")));
        return Empty(RttiId(c, cls), cls.Name, cls.Kind, Rtti, pascal.InstanceSize) with
        {
            Fields = fields, TotalFields = fields.Count, Bases = Bases(c, cls), Vftables = Vftables(c, cls),
            Notes = [$"{pascal.Compiler} VMT{(pascal.Unit != null ? $", unit {pascal.Unit}" : "")}: the instance size and published fields only"],
        };
    }

    private static NativeTypeView WithRtti(Context c, NativeTypeView pdb, MsvcRttiClass cls) =>
        pdb with { Source = Pdb + "+" + Rtti, Bases = Bases(c, cls), Vftables = Vftables(c, cls), Notes = [.. pdb.Notes, $"RTTI: {RttiId(c, cls)}"] };

    private static List<NativeTypeBase> Bases(Context c, MsvcRttiClass cls)
    {
        var rtti = c.RttiResult;
        return cls.Bases.Where(b => b.Depth == 1).Select(b => new NativeTypeBase(b.IsVirtual ? -1 : b.Mdisp, b.Name,
            rtti?.Classes.FirstOrDefault(x => x.TypeDescriptorRva == b.TypeDescriptorRva) is { } k ? RttiId(c, k) : null, b.IsVirtual)).ToList();
    }

    /// <summary>The class's vftables, slots paged by the context's slot offset and limit.</summary>
    private static List<NativeVftable> Vftables(Context c, MsvcRttiClass cls) =>
        cls.Vtables.Select(v => new NativeVftable(c.Va(v.VftableRva), v.Offset, v.SlotRvas.Count,
            v.SlotRvas.Select((target, i) => new NativeVftableSlot(i, (long)i * PointerSize(c.Native), c.Va(target), c.Index?.NameAt(target))).Skip(c.SlotOffset).Take(c.SlotLimit).ToList())).ToList();

    private static NativeTypeView AotView(Context c, TypeDef type, bool statics)
    {
        var key = AotNames.TypeKey(type);
        var layout = new AotLayout();
        var s = statics ? layout.StaticsOf(type) : layout.Of(type);
        var view = Empty(Metadata + ":" + key + (statics ? "#statics" : ""), key, statics ? "statics" : type.IsValueType ? "struct" : type.IsInterface ? "interface" : "class", Metadata,
            s == null ? -1 : (long)s.Size);
        var notes = new List<string>();
        if (s == null)
        {
            notes.Add(type.HasGenericParameters ? "a generic definition has no single layout: its instances differ" : statics ? "no static fields with dumped offsets" : "no instance fields");
            return view with { Notes = notes };
        }
        var structs = layout.Structs.Where(x => !x.Statics).ToDictionary(x => "struct " + x.CName, x => x.Title, StringComparer.Ordinal);
        var fields = new List<NativeTypeField>();
        if (!statics && !type.IsValueType)
        {
            fields.Add(new NativeTypeField(0, (long)layout.PointerSize, "klass", "Il2CppClass *", null, "header", null, null, null));
            fields.Add(new NativeTypeField((long)layout.PointerSize, (long)layout.PointerSize, "monitor", "void *", null, "header", null, null, null));
        }
        foreach (var m in s.Members)
        {
            var typeId = structs.TryGetValue(m.CType, out var title) && !title.Contains('<', StringComparison.Ordinal) ? Metadata + ":" + title.Replace('/', '.') : null;
            var note = m.Managed + (m.Owner != type.Name.String ? $", declared in {m.Owner}" : "") + (m.Computed ? ", offset computed" : "");
            fields.Add(new NativeTypeField((long)m.Offset, (long)m.Size, m.Name, m.Count > 0 ? $"{m.CType}[{m.Count}]" : m.CType, typeId, "member", null, null, note));
        }
        if (!statics && type.Fields.Any(f => f.IsStatic && !f.IsLiteral)) notes.Add($"static fields: id {Metadata}:{key}#statics");
        return view with { Fields = fields, TotalFields = fields.Count, Alignment = (long)s.Align, Notes = notes };
    }

    private static NativeTypeView EngineView(string provider, NativeTypeDetail d)
    {
        var fields = d.Members.Select(m => new NativeTypeField(m.Offset, m.Size, m.Name, m.Type, null, "member", m.BitOffset, m.BitSize, m.Comment)).ToList();
        return Empty(provider + ":" + d.Name, d.Name, d.Kind, provider, d.Size) with
        {
            Fields = fields, TotalFields = fields.Count, Declaration = d.Declaration.TrimEnd(), Alignment = d.Alignment, Packed = d.Packed,
        };
    }
}
