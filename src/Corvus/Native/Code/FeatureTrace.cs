using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Calls;

namespace Corvus.Native.Code;

[Flags]
public enum FeatureKinds
{
    None = 0,
    Strings = 1,
    Names = 2,
    Imports = 4,
    Exports = 8,
    Classes = 16,
    /// <summary>Immediates and displacements in code equal to the query's number (only when the query is one).</summary>
    Constants = 32,
    All = Strings | Names | Imports | Exports | Classes | Constants,
}

/// <summary>An open engine session's view for a trace: its defined strings and its references to an address (blocking calls).</summary>
public sealed record FeatureEngine(string Id, IReadOnlyList<(uint Rva, string Text)> Strings, Func<uint, IReadOnlyList<uint>> RefsTo);

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

    private const int MaxConstantFunctions = 2000;
    private const int MaxScannedInstructions = 2_000_000;
    private readonly NativeCodeIndex _index;
    private readonly CallAnalysis? _calls;
    private FeatureEngine? _engine;
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

    /// <param name="query">Text to find; "quoted" matches whole strings and names exactly; a number also seeds the constants in code.</param>
    /// <param name="engine">An open engine session: its strings join the seeds, its references stand in where the built-in index has none.</param>
    public static FeatureTraceResult Run(NativeCodeIndex index, string query, bool regex, FeatureKinds kinds, int maxSeeds, int callerDepth, IReadOnlyList<FeatureClass> classes,
        CancellationToken ct, FeatureEngine? engine = null)
    {
        var key = $"{query}|{regex}|{kinds}|{maxSeeds}|{callerDepth}|{classes.Count}|{index.Sourced.Version}|{engine?.Id}";
        var cache = Cache.GetValue(index, _ => []);
        lock (cache) if (cache.TryGetValue(key, out var hit)) return hit;
        Func<string, bool> match;
        if (!regex && query.Length >= 2 && query[0] == '"' && query[^1] == '"')
        {
            var exact = query[1..^1];
            match = t => t.Equals(exact, StringComparison.OrdinalIgnoreCase);
        }
        else if (regex)
        {
            Regex pattern;
            try { pattern = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeouts.Limit); }
            catch (ArgumentException ex) { throw new ToolError(ErrorCode.InvalidArgument, $"Invalid regex: {ex.Message}"); }
            var timeouts = new RegexTimeouts();
            match = t => timeouts.IsMatch(pattern, t);
        }
        else match = t => t.Contains(query, StringComparison.OrdinalIgnoreCase);
        var trace = new FeatureTrace(index, match, maxSeeds) { _engine = engine };
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
        if (kinds.HasFlag(FeatureKinds.Constants) && !query.StartsWith('"') && Number(query) is { } value) Constants(value, ct);
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
                if (_perSeed.GetValueOrDefault(id) == 0) EngineRefs(s.Rva, $"uses {quoted}", id);
            }, ct);
        }
        if (_engine == null) return;
        // strings only the engine defines
        foreach (var (rva, text) in _engine.Strings)
        {
            ct.ThrowIfCancellationRequested();
            if (_seeded.Contains(rva) || !_match(text)) continue;
            var quoted = $"\"{Format.Clip(text, 120)}\"";
            Seed("string", rva, quoted, id => EngineRefs(rva, $"uses {quoted}", id), ct);
        }
    }

    /// <summary>The engine's code references to <paramref name="rva"/>, where the built-in index found none.</summary>
    private void EngineRefs(uint rva, string detail, int seed)
    {
        if (_engine == null) return;
        foreach (var from in _engine.RefsTo(rva))
            if (_index.FunctionAt(from) != null) Add(from, "engine_xref", $"{detail} ({_engine.Id})", seed);
    }

    private static ulong? Number(string query)
    {
        var t = query.Trim();
        if (t.Length == 0 || t.Length > 20) return null;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || t.EndsWith('h') || t.EndsWith('H')) return NativeAddress.Number(t);
        if (t.StartsWith('-') && long.TryParse(t, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out long negative))
            return (ulong)negative;
        return t.All(char.IsAsciiDigit) && ulong.TryParse(t, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out ulong n) ? n : null;
    }

    /// <summary>The instructions with an immediate or displacement equal to <paramref name="value"/>, with the call each one feeds.</summary>
    private void Constants(ulong value, CancellationToken ct)
    {
        var text = value < 10 ? value.ToString(System.Globalization.CultureInfo.InvariantCulture) : $"0x{value:X}";
        List<(uint Site, string Detail)> hits;
        Exception? failure = null;
        bool supported = _calls != null || Arm64Trace.Supports(_index) || Arm32Trace.Supports(_index);
        try { hits = _calls != null ? X86Constants(value, ct) : Arm64Trace.Supports(_index) ? Arm64Constants(value, ct) : supported ? Arm32Constants(value, ct) : []; }
        catch (Exception e) when (e is not OperationCanceledException) { (hits, failure) = ([], e); }
        if (!supported) _notes.Add("constants in code are searched on x86 / x64 and ARM only");
        // no instruction holds it: no seed (one at address 0 with no references reads as a match)
        if (hits.Count == 0 && failure == null) return;
        Seed("constant", hits.Count > 0 ? hits[0].Site : 0, text, id =>
        {
            if (failure != null) throw failure;
            foreach (var (site, detail) in hits) Add(site, "constant", detail, id);
        }, ct);
    }

    private List<(uint, string)> X86Constants(ulong value, CancellationToken ct)
    {
        var functions = new List<NativeFunction>();
        bool fits32 = value <= uint.MaxValue || value >> 31 == 0x1_FFFF_FFFF;
        if (value >= 0x100)
        {
            // the encoded immediate or displacement: 4 bytes (sign-extended to 64 bits when needed), else 8
            var pattern = fits32 ? BitConverter.GetBytes((uint)value) : BitConverter.GetBytes(value);
            var seen = new HashSet<uint>();
            foreach (var section in _index.Image.Sections.Where(s => s.IsExecutable))
            {
                var bytes = new byte[section.MappedSize];
                int n = _index.Image.Read(section.Rva, bytes);
                for (int at = bytes.AsSpan(0, n).IndexOf(pattern); at >= 0; )
                {
                    ct.ThrowIfCancellationRequested();
                    if (_index.FunctionAt(section.Rva + (uint)at) is { } f && seen.Add(f.Start)) functions.Add(f);
                    int next = bytes.AsSpan(at + 1, n - at - 1).IndexOf(pattern);
                    at = next < 0 ? -1 : at + 1 + next;
                }
            }
        }
        else functions.AddRange(_index.Functions);
        var result = new List<(uint, string)>();
        int scanned = 0;
        foreach (var f in functions.Take(MaxConstantFunctions))
        {
            ct.ThrowIfCancellationRequested();
            var code = _calls!.Code(f, ct);
            IReadOnlyList<CallSiteInfo>? calls = null;
            foreach (var d in code.Blocks.SelectMany(b => b).DistinctBy(d => d.Rva).OrderBy(d => d.Rva))
            {
                if (++scanned > MaxScannedInstructions) { _notes.Add($"the constant search stopped after {MaxScannedInstructions:N0} instructions"); return result; }
                if (!Holds(d.I, value, fits32)) continue;
                calls ??= _calls.CallsIn(f, ct);
                result.Add((d.Rva, Feeds(d.I.ToString(), d.Rva, value, calls)));
                if (result.Count >= MaxEvidencePerSeed) return result;
            }
        }
        if (functions.Count > MaxConstantFunctions) _notes.Add($"the constant is in {functions.Count} functions; the first {MaxConstantFunctions} were searched");
        return result;
    }

    private static bool Holds(in Iced.Intel.Instruction x, ulong value, bool fits32)
    {
        for (int k = 0; k < x.OpCount; k++)
            switch (x.GetOpKind(k))
            {
                case Iced.Intel.OpKind.Immediate8 or Iced.Intel.OpKind.Immediate8to16 or Iced.Intel.OpKind.Immediate8to32 or Iced.Intel.OpKind.Immediate8to64
                    or Iced.Intel.OpKind.Immediate16 or Iced.Intel.OpKind.Immediate32 or Iced.Intel.OpKind.Immediate32to64 or Iced.Intel.OpKind.Immediate64:
                    ulong imm = x.GetImmediate(k);
                    if (imm == value || fits32 && (uint)imm == (uint)value) return true;
                    break;
                case Iced.Intel.OpKind.Memory when x.MemoryBase is not (Iced.Intel.Register.RIP or Iced.Intel.Register.EIP) && x.MemoryDisplacement64 != 0:
                    if (x.MemoryDisplacement64 == value || fits32 && (uint)x.MemoryDisplacement64 == (uint)value) return true;
                    break;
            }
        return false;
    }

    /// <summary>The instruction, and the call whose argument it sets when one does.</summary>
    private string Feeds(string instruction, uint site, ulong value, IReadOnlyList<CallSiteInfo> calls)
    {
        var va = Va(site);
        var call = calls.FirstOrDefault(c => c.Arguments.Any(a => a.Value is { } v && (v == value || (uint)v == (uint)value) && a.Derivation.Contains(va, StringComparison.OrdinalIgnoreCase)));
        return call != null ? $"{instruction} -> {call.Display}" : instruction;
    }

    private List<(uint, string)> Arm64Constants(ulong value, CancellationToken ct)
    {
        var trace = Arm64Trace.For(_index);
        var result = new List<(uint, string)>();
        int scanned = 0;
        foreach (var f in _index.Functions)
        {
            ct.ThrowIfCancellationRequested();
            var code = trace.Code(f, ct);
            IReadOnlyList<CallSiteInfo>? calls = null;
            foreach (var s in code.Blocks.SelectMany(b => b))
            {
                if (++scanned > MaxScannedInstructions) { _notes.Add($"the constant search stopped after {MaxScannedInstructions:N0} instructions"); return result; }
                bool holds = false;
                var insn = s.I;
                for (int k = 1; k < insn.OperandCount && !holds; k++) holds = A64Function.Imm(in insn, k) is { } imm && (ulong)imm == value;
                // mov / movk sequences build wider constants
                if (!holds && s.I.Mnemonic == AsmArm64.Arm64Mnemonic.MOVK && A64Function.Gpr(s.I, 0) is var r and >= 0 and < 31)
                    holds = trace.ConstantAfter(f, s.Rva, $"x{r}", ct) is { } built && (built == value || (uint)built == (uint)value && value <= uint.MaxValue);
                if (!holds) continue;
                calls ??= trace.Calls.CallsIn(f, ct);
                result.Add((s.Rva, Feeds(s.Text, s.Rva, value, calls)));
                if (result.Count >= MaxEvidencePerSeed) return result;
            }
        }
        return result;
    }

    /// <summary>ARM32: immediates, movw / movt pairs and literal-pool words equal to the value (its low 32 bits).</summary>
    private List<(uint, string)> Arm32Constants(ulong value, CancellationToken ct)
    {
        var result = new List<(uint, string)>();
        if (value > uint.MaxValue && value >> 31 != 0x1_FFFF_FFFF) return result;
        uint want = (uint)value;
        var trace = Arm32Trace.For(_index);
        Span<byte> word = stackalloc byte[4];
        int scanned = 0;
        foreach (var f in _index.Functions)
        {
            ct.ThrowIfCancellationRequested();
            var code = trace.Code(f, ct);
            IReadOnlyList<CallSiteInfo>? calls = null;
            foreach (var s in code.Blocks.SelectMany(b => b))
            {
                if (++scanned > MaxScannedInstructions) { _notes.Add($"the constant search stopped after {MaxScannedInstructions:N0} instructions"); return result; }
                var i = s.I;
                bool holds = false;
                for (int k = 1; k < i.OperandCount && !holds; k++) holds = i.Op(k).Kind == ArmOperandKind.Immediate && (uint)i.Op(k).Value == want && i.Mnemonic != "movt";
                if (!holds && i.Mnemonic == "movt" && A32Function.Dest(i) is var r and >= 0)
                    holds = trace.ConstantAfter(f, s.Rva, ArmInstruction.RegisterNames[r], ct) == want;
                if (!holds && want >= 0x100 && i.Loads && s.Facts.HasMem && A32Function.Memory(i) is { Reg: A32Function.Pc } && i.AccessSize == 4
                    && _index.Image.Read(s.Facts.MemTarget, word) == 4)
                    holds = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(word) == want;
                if (!holds) continue;
                calls ??= trace.Calls.CallsIn(f, ct);
                result.Add((s.Rva, Feeds(s.Text, s.Rva, value, calls)));
                if (result.Count >= MaxEvidencePerSeed) return result;
            }
        }
        return result;
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
                if (_perSeed.GetValueOrDefault(id) == 0) EngineRefs(rva, $"uses [{name}]", id);
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
