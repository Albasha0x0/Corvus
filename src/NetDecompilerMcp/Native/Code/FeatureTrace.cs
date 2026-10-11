using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Calls;

namespace NetDecompilerMcp.Native.Code;

[Flags]
public enum FeatureKinds
{
    None = 0,
    Strings = 1,
    Names = 2,
    Imports = 4,
    Exports = 8,
    Classes = 16,
    All = Strings | Names | Imports | Exports | Classes,
}

/// <summary>A polymorphic class for seeding: its name, vftable and slot targets (from RTTI).</summary>
public sealed record FeatureClass(string Name, uint Vftable, IReadOnlyList<uint> Slots);

/// <summary>A match of the query: kind string, name, import, export or class; its references found, or why it failed.</summary>
public sealed record FeatureSeed(int Id, string Kind, uint Rva, string Text, int References, string? Error);

/// <summary>Why a function is in the trace: the site, what happens there and the seed it involves.</summary>
public sealed record FeatureEvidence(uint Site, string Kind, string Detail, int Seed);

/// <param name="Score">Distinct seeds x3 + decoded API calls + 2 when exported or the entry point - 3 for library code - 2 when larger than 64 KB.</param>
public sealed record FeatureFunction(NativeFunction Function, string Name, int Score, IReadOnlyList<int> Seeds, IReadOnlyList<FeatureEvidence> Evidence, int EvidenceTotal,
    IReadOnlyList<string> Flags);

/// <summary>A caller that reaches several feature functions within the caller depth: likely the feature's controller.</summary>
public sealed record FeatureHub(NativeFunction Function, string Name, IReadOnlyList<uint> Reaches, int Depth);

public sealed record FeatureTraceResult(string Query, IReadOnlyList<FeatureSeed> Seeds, int TotalSeeds, IReadOnlyList<FeatureFunction> Functions, IReadOnlyList<FeatureHub> Hubs,
    bool HubsTruncated, IReadOnlyList<string> Notes);

/// <summary>
/// From a text to the code behind it: seeds (strings, names, imports, exports, RTTI classes matching the query), their
/// references (string interiors included, one pointer-table hop, import calls with their arguments), the functions holding
/// them ranked by evidence, and hubs (callers reaching several of those functions). Every stage is bounded; a seed that
/// fails records its error and the rest continues. Results are cached per index and names version.
/// </summary>
public sealed class FeatureTrace
{
    public const int MaxEvidencePerSeed = 200;
    private const int MaxHubNodes = 5000;
    private const int HubSources = 20;
    private const int MaxTableSlots = 64;
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<NativeCodeIndex, Dictionary<string, FeatureTraceResult>> Cache = new();

    private readonly NativeCodeIndex _index;
    private readonly CallAnalysis? _calls;
    private readonly Func<string, bool> _match;
    private readonly List<FeatureSeed> _seeds = [];
    private readonly List<FeatureEvidence> _evidence = [];
    private readonly List<string> _notes = [];
    private readonly HashSet<uint> _seeded = [];
    private readonly Dictionary<int, int> _perSeed = [];
    private readonly int _maxSeeds;
    private int _total;

    private FeatureTrace(NativeCodeIndex index, Func<string, bool> match, int maxSeeds)
    {
        _index = index;
        _calls = CallAnalysis.Supports(index) ? CallAnalysis.For(index) : null;
        _match = match;
        _maxSeeds = maxSeeds;
    }

    public static FeatureTraceResult Run(NativeCodeIndex index, string query, bool regex, FeatureKinds kinds, int maxSeeds, int callerDepth, IReadOnlyList<FeatureClass> classes,
        CancellationToken ct)
    {
        var key = $"{query}|{regex}|{kinds}|{maxSeeds}|{callerDepth}|{classes.Count}|{index.Sourced.Version}";
        var cache = Cache.GetValue(index, _ => []);
        lock (cache) if (cache.TryGetValue(key, out var hit)) return hit;
        Func<string, bool> match;
        if (regex)
        {
            Regex pattern;
            try { pattern = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit); }
            catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex: {ex.Message}"); }
            var timeouts = new RegexTimeouts();
            match = t => timeouts.IsMatch(pattern, t);
        }
        else match = t => t.Contains(query, StringComparison.OrdinalIgnoreCase);
        var trace = new FeatureTrace(index, match, maxSeeds);
        var result = trace.Execute(query, kinds, callerDepth, classes, ct);
        lock (cache)
        {
            if (cache.Count > 16) cache.Clear();
            cache[key] = result;
        }
        return result;
    }

    private string Va(uint rva) => NativeAddress.Va(_index.Image, rva);

    private FeatureTraceResult Execute(string query, FeatureKinds kinds, int callerDepth, IReadOnlyList<FeatureClass> classes, CancellationToken ct)
    {
        if (kinds.HasFlag(FeatureKinds.Strings)) Strings(ct);
        if (kinds.HasFlag(FeatureKinds.Names)) Names(ct);
        if (kinds.HasFlag(FeatureKinds.Imports)) Imports(ct);
        if (kinds.HasFlag(FeatureKinds.Exports)) Exports(ct);
        if (kinds.HasFlag(FeatureKinds.Classes)) Classes(classes, ct);
        if (_total > _seeds.Count) _notes.Add($"{_total} matches; the first {_seeds.Count} were followed (maxSeeds)");
        var functions = Aggregate();
        var (hubs, cut) = callerDepth > 0 ? Hubs(functions, callerDepth, ct) : ([], false);
        return new FeatureTraceResult(query, _seeds, _total, functions, hubs, cut, _notes);
    }

    /// <summary>Counts a match and, under the seed budget, follows it; a failure is recorded on the seed.</summary>
    private void Seed(string kind, uint rva, string text, Action<int> follow, CancellationToken ct)
    {
        _total++;
        if (_seeds.Count >= _maxSeeds || !_seeded.Add(rva)) return;
        int id = _seeds.Count;
        int before = _evidence.Count;
        string? error = null;
        try { follow(id); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            error = e.Message;
        }
        ct.ThrowIfCancellationRequested();
        _seeds.Add(new FeatureSeed(id, kind, rva, text, _evidence.Count - before, error));
    }

    private void Add(uint site, string kind, string detail, int seed)
    {
        int n = _perSeed.GetValueOrDefault(seed);
        if (n >= MaxEvidencePerSeed) return;
        _perSeed[seed] = n + 1;
        _evidence.Add(new FeatureEvidence(site, kind, detail, seed));
    }

    private void Strings(CancellationToken ct)
    {
        foreach (var s in _index.Strings)
        {
            ct.ThrowIfCancellationRequested();
            var text = _index.ReadString(s, 400);
            if (!_match(text)) continue;
            var quoted = $"{(s.Encoding == StringEncoding.Utf16 ? "L" : "")}\"{Format.Clip(text, 120)}\"";
            uint length = (uint)Math.Max(1, s.Length * (s.Encoding == StringEncoding.Utf16 ? 2 : 1));
            Seed("string", s.Rva, quoted, id =>
            {
                foreach (var x in _index.RefsToRange(s.Rva, s.Rva + length))
                {
                    if (_index.FunctionAt(x.From) != null)
                        Add(x.From, "string", $"{(x.Kind == XrefKind.Read ? "reads" : "uses")} {quoted}{(x.To != s.Rva ? $" at +0x{x.To - s.Rva:X}" : "")}", id);
                    else if (x.Kind == XrefKind.Pointer) Table(x.From, quoted, id);
                }
            }, ct);
        }
    }

    /// <summary>One indirection: a pointer to the string in a table of pointers, and the code that uses the table's start.</summary>
    private void Table(uint slot, string quoted, int seed)
    {
        int ptr = _index.Image.Is64Bit ? 8 : 4;
        uint at = slot;
        for (int k = 0; k < MaxTableSlots && at >= (uint)ptr; k++)
        {
            var users = _index.RefsTo(at).Where(r => _index.FunctionAt(r.From) != null && r.Kind is XrefKind.Address or XrefKind.Read).ToList();
            if (users.Count > 0)
            {
                foreach (var u in users) Add(u.From, "table", $"uses the pointer table at {Va(at)} holding {quoted} (slot {(slot - at) / ptr})", seed);
                return;
            }
            uint prev = at - (uint)ptr;
            if (!_index.RefsFrom(prev, at).Any(r => r.Kind == XrefKind.Pointer)) return;
            at = prev;
        }
    }

    private void Names(CancellationToken ct)
    {
        foreach (var f in _index.Functions)
        {
            ct.ThrowIfCancellationRequested();
            var name = _index.NameAt(f.Start) ?? f.KnownName;
            if (name == null || !_match(name) || f.ThunkImport != null) continue;
            Seed("name", f.Start, name, id => Add(f.Start, "named", $"named {name}", id), ct);
        }
        foreach (var (rva, name, _, _) in _index.Sourced.In(0, uint.MaxValue))
        {
            ct.ThrowIfCancellationRequested();
            if (name == null || _index.FunctionByStart(rva) != null || !_match(name)) continue;
            Seed("name", rva, name, id =>
            {
                foreach (var x in _index.RefsTo(rva).Where(x => _index.FunctionAt(x.From) != null))
                    Add(x.From, "data", $"{x.Kind.ToString().ToLowerInvariant()} [{name}]", id);
            }, ct);
        }
    }

    private void Imports(CancellationToken ct)
    {
        foreach (var imp in _index.Image.Imports)
        {
            ct.ThrowIfCancellationRequested();
            var full = NativeCodeIndex.ImportName(imp);
            if (!_match(full)) continue;
            Seed("import", imp.SlotRva, full, id =>
            {
                if (_calls != null)
                    foreach (var c in _calls.CallsTo(imp, MaxEvidencePerSeed, ct)) Add(c.Rva, "call", c.Display, id);
                else
                    foreach (var c in _index.Callers(imp)) Add(c.From, "call", $"calls {full}", id);
                foreach (var x in _index.RefsTo(imp.SlotRva).Where(x => x.Kind is XrefKind.Read or XrefKind.Address && _index.FunctionAt(x.From) != null))
                    Add(x.From, "pointer", $"loads the pointer of {full}", id);
            }, ct);
        }
        if (_calls == null) return;
        foreach (var d in _calls.DynamicImports(ct).Imports)
        {
            if (!_match(d.FullName)) continue;
            Seed("import", d.CallSite, $"{d.FullName} (GetProcAddress)", id =>
            {
                Add(d.CallSite, "resolve", $"resolves {d.FullName}: {d.How}", id);
                foreach (var site in d.PointerCalls) Add(site, "call", _calls.CallAt(site, ct)?.Display ?? $"calls {d.FullName} through its pointer", id);
            }, ct);
        }
    }

    private void Exports(CancellationToken ct)
    {
        foreach (var e in _index.Image.Exports)
        {
            ct.ThrowIfCancellationRequested();
            if (e.Name == null || e.ForwardedTo != null || !_match(e.Name)) continue;
            Seed("export", e.Rva, e.Name, id => Add(e.Rva, "exported", $"exported as {e.Name}", id), ct);
        }
    }

    private void Classes(IReadOnlyList<FeatureClass> classes, CancellationToken ct)
    {
        foreach (var c in classes)
        {
            ct.ThrowIfCancellationRequested();
            if (!_match(c.Name)) continue;
            Seed("class", c.Vftable, c.Name, id =>
            {
                foreach (var x in _index.RefsTo(c.Vftable).Where(x => _index.FunctionAt(x.From) != null))
                    Add(x.From, "vftable", $"installs or reads {c.Name}'s vftable (constructor, destructor or a virtual call)", id);
                foreach (var (slot, i) in c.Slots.Select((s, i) => (s, i)).DistinctBy(x => x.s).Take(64))
                    if (_index.FunctionByStart(slot) != null) Add(slot, "method", $"slot {i} of {c.Name}'s vftable", id);
            }, ct);
        }
    }

    private List<FeatureFunction> Aggregate()
    {
        var byFunction = new Dictionary<NativeFunction, List<FeatureEvidence>>();
        foreach (var e in _evidence)
            if (_index.FunctionAt(e.Site) is { } f)
            {
                if (!byFunction.TryGetValue(f, out var list)) byFunction[f] = list = [];
                list.Add(e);
            }
        var image = _index.Image;
        var result = new List<FeatureFunction>(byFunction.Count);
        foreach (var (f, list) in byFunction)
        {
            var seeds = list.Select(e => e.Seed).Distinct().Order().ToList();
            var flags = new List<string>();
            int score = seeds.Count * 3 + list.Count(e => e.Kind == "call" && e.Detail.Contains('('));
            if (f.Start == image.EntryPointRva || image.Exports.Any(x => x.Rva == f.Start)) { score += 2; flags.Add("entry or export"); }
            if (_index.Sourced.NameAt(f.Start, NativeNameSource.Ida) != null) { score -= 3; flags.Add("library"); }
            if (f.Size > 64 * 1024) { score -= 2; flags.Add("large"); }
            var ordered = list.OrderBy(e => e.Site).ToList();
            result.Add(new FeatureFunction(f, _index.NameAt(f.Start) ?? f.Name, score, seeds, ordered.Take(20).ToList(), ordered.Count, flags));
        }
        return result.OrderByDescending(x => x.Score).ThenByDescending(x => x.Seeds.Count).ThenBy(x => x.Function.Start).ToList();
    }

    /// <summary>Callers within <paramref name="depth"/> of the top functions that reach two or more of them.</summary>
    private (List<FeatureHub>, bool) Hubs(List<FeatureFunction> functions, int depth, CancellationToken ct)
    {
        var reaches = new Dictionary<NativeFunction, (HashSet<uint> Targets, int Depth)>();
        int nodes = 0;
        bool cut = false;
        foreach (var top in functions.Take(HubSources))
        {
            var seen = new HashSet<NativeFunction> { top.Function };
            var level = new List<NativeFunction> { top.Function };
            for (int d = 1; d <= depth && level.Count > 0 && !cut; d++)
            {
                var next = new List<NativeFunction>();
                foreach (var f in level)
                    foreach (var c in _index.Callers(f, CallEdgeFilter.Direct))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (c.Caller is not { } caller || !seen.Add(caller)) continue;
                        if (++nodes > MaxHubNodes) { cut = true; break; }
                        if (!reaches.TryGetValue(caller, out var r)) reaches[caller] = r = ([], d);
                        r.Targets.Add(top.Function.Start);
                        reaches[caller] = (r.Targets, Math.Min(r.Depth, d));
                        next.Add(caller);
                    }
                level = next;
            }
        }
        var hubs = reaches.Where(r => r.Value.Targets.Count >= 2)
            .Select(r => new FeatureHub(r.Key, _index.NameAt(r.Key.Start) ?? r.Key.Name, r.Value.Targets.Order().ToList(), r.Value.Depth))
            .OrderByDescending(h => h.Reaches.Count).ThenBy(h => h.Depth).ThenBy(h => h.Function.Start).ToList();
        if (cut) _notes.Add($"the hub search stopped at {MaxHubNodes} callers");
        return (hubs, cut);
    }
}
