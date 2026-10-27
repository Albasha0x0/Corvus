using System.Diagnostics;
using System.Runtime.CompilerServices;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>One decoder call or computed String[] table read and its result; <see cref="Evaluated"/> is false when an argument is not constant.</summary>
/// <remarks><see cref="Wrapper"/> names the String call that turns an array decoder's result into a string; null and -1 otherwise.</remarks>
public sealed record DexFoldSite(string Method, int Offset, string Decoder, DexFold Fold, bool Evaluated = true, string? Wrapper = null, int WrapperOffset = -1);

/// <summary>The decoder calls of a package, with the methods that were not reached within the time limit.</summary>
public sealed record DexPackageFolds(IReadOnlyList<DexFoldSite> Sites, int MethodsLeft);

/// <summary>Finds and evaluates a package's string decoder calls with constant arguments and computed String[] table reads; results kept per package.</summary>
public sealed class DexStringFolding
{
    /// <summary>The time one package-wide pass may take; a later pass continues where it stopped.</summary>
    public static readonly TimeSpan PackageTimeLimit = TimeSpan.FromSeconds(10);

    private const int MaxArrayLiteral = 65_536;
    private static readonly ConditionalWeakTable<DexIndex, DexStringFolding> Cache = [];

    private readonly DexIndex _index;
    private readonly DalvikEvaluator _evaluator;
    private readonly Dictionary<string, List<DexFoldSite>> _methods = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _tableWriters = new(StringComparer.Ordinal);
    private readonly Dictionary<string, bool> _stateless = new(StringComparer.Ordinal);
    private HashSet<string>? _superclasses;
    private readonly object _lock = new();

    private DexStringFolding(DexIndex index)
    {
        _index = index;
        _evaluator = new DalvikEvaluator(new Program(index));
    }

    /// <summary>The folding state kept for <paramref name="index"/>.</summary>
    public static DexStringFolding For(DexIndex index) => Cache.GetValue(index, i => new DexStringFolding(i));

    private sealed class Program(DexIndex index) : IDexProgram
    {
        private Dictionary<string, List<string>>? _writers;

        public (DexFile File, DexClass Class, DexEncodedMethod Method)? FindMethod(string descriptor) =>
            index.Methods.TryGetValue(descriptor, out var m) ? (m.File, m.Class, m.Encoded) : null;

        public (DexFile File, DexClass Class)? FindClass(string descriptor) =>
            index.Classes.TryGetValue(descriptor, out var c) ? (c.File, c.Class) : null;

        public IReadOnlyList<string> StaticWriters(string field)
        {
            _writers ??= index.Refs.Where(r => r.Kind == DexRefKind.Write && r.Opcode is >= 0x67 and <= 0x6d)
                .GroupBy(r => index.KeyText(r.Target), StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Select(r => index.KeyText(r.From)).Distinct(StringComparer.Ordinal).ToList(), StringComparer.Ordinal);
            return _writers.TryGetValue(field, out var list) ? list : [];
        }
    }

    /// <summary>A method of the package returning a string, with at least one parameter, that <see cref="Callable"/> accepts.</summary>
    public bool IsDecoder(string descriptor) =>
        _index.Methods.TryGetValue(descriptor, out var m) && m.Ref.Proto.ReturnType == "Ljava/lang/String;" && m.Ref.Proto.Parameters.Count > 0 && Callable(m);

    /// <summary>A method of the package returning a char or byte array, with at least one parameter, that <see cref="Callable"/> accepts.</summary>
    public bool IsArrayDecoder(string descriptor) =>
        _index.Methods.TryGetValue(descriptor, out var m) && m.Ref.Proto.ReturnType is "[C" or "[B" && m.Ref.Proto.Parameters.Count > 0 && Callable(m);

    /// <summary>A static method, or an instance method of an unextended Object subclass without instance fields, so the receiver need not be known.</summary>
    private bool Callable(DexMethodEntry m)
    {
        if ((m.Encoded.Access & 0x8) != 0) return true;
        // Constructors, abstract and native methods.
        if ((m.Encoded.Access & 0x10500) != 0 || m.Encoded.CodeOffset == 0) return false;
        lock (_stateless)
        {
            if (_stateless.TryGetValue(m.Class.Descriptor, out var known)) return known;
            _superclasses ??= [.. _index.Classes.Values.Select(c => c.Class.SuperClass).OfType<string>()];
            return _stateless[m.Class.Descriptor] = m.Class.SuperClass == "Ljava/lang/Object;" && (m.Class.Access & 0x600) == 0
                && !_superclasses.Contains(m.Class.Descriptor) && m.File.ClassData(m.Class).Fields.All(f => f.IsStatic);
        }
    }

    /// <summary>An invoke opcode a decoder call takes: invoke-static, invoke-virtual or invoke-direct, plain or range.</summary>
    public static bool IsCall(int opcode) => opcode is 0x6e or 0x70 or 0x71 or 0x74 or 0x76 or 0x77;

    /// <summary>The opcode a site's code shows: aget-object for a table read, else the invoke its decoder takes.</summary>
    public string Opcode(DexFoldSite site) =>
        !site.Decoder.Contains('(') ? "aget-object"
        : !_index.Methods.TryGetValue(site.Decoder, out var m) || (m.Encoded.Access & 0x8) != 0 ? "invoke-static"
        : (m.Encoded.Access & 0x2) != 0 ? "invoke-direct" : "invoke-virtual";

    // Registers before a decoder's arguments: the receiver of an instance decoder.
    private int Receivers(string descriptor) => _index.Methods.TryGetValue(descriptor, out var m) && (m.Encoded.Access & 0x8) == 0 ? 1 : 0;

    /// <summary>A static String[] field declared by a class of the package.</summary>
    public bool IsTable(string field) =>
        field.EndsWith(":[Ljava/lang/String;", StringComparison.Ordinal) && field.IndexOf("->", StringComparison.Ordinal) is > 0 and var at
        && _index.Classes.ContainsKey(field[..at]);

    /// <summary>A method other than the static initializer that stores into or passes on a String[] field's array; null when none.</summary>
    private string? TableWriter(string field)
    {
        lock (_tableWriters)
        {
            if (_tableWriters.TryGetValue(field, out var cached)) return cached;
            string? writer = null;
            if (_index.FindKey(field) is int key)
            {
                var initializer = field[..field.IndexOf("->", StringComparison.Ordinal)] + "-><clinit>()V";
                foreach (var reader in _index.Refs.Where(r => r.Target == key && r.Kind == DexRefKind.Read && r.Opcode == 0x62).Select(r => _index.KeyText(r.From)).Distinct(StringComparer.Ordinal))
                    if (reader != initializer && (!_index.Methods.TryGetValue(reader, out var m) || StoresInto(m, field))) { writer = reader; break; }
            }
            return _tableWriters[field] = writer;
        }
    }

    private static bool StoresInto(DexMethodEntry m, string field)
    {
        if (m.Encoded.CodeOffset == 0 || m.File.Code(m.Encoded.CodeOffset) is not { } code) return false;
        var held = new HashSet<int>();
        foreach (var i in Dalvik.Decode(code.Instructions))
        {
            int op = i.Opcode;
            if (op is 0x11 or 0x26 or 0x69 or >= 0x5b and <= 0x5f && held.Contains(i.A) || op is >= 0x4b and <= 0x51 && held.Contains(i.B)
                || op is >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78 && i.Arguments.Any(held.Contains))
                return true;
            if (op == 0x62 && m.File.Field(i.Index).Descriptor == field || op is >= 0x07 and <= 0x09 && held.Contains(i.B)) held.Add(i.A);
            else if (op is >= 0x01 and <= 0x0d or >= 0x12 and <= 0x1c or >= 0x20 and <= 0x23 or >= 0x44 and <= 0x4a or >= 0x52 and <= 0x58 or >= 0x60 and <= 0x66 or >= 0x7b and <= 0xe2)
                held.Remove(i.A);
        }
        return false;
    }

    /// <summary>The string is in the string table of a DEX file of the package (sorted, so searched by halves).</summary>
    private bool IsLiteral(string s)
    {
        foreach (var f in _index.Files)
        {
            int lo = 0, hi = f.StringCount - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1, c = string.CompareOrdinal(f.String(mid), s);
                if (c == 0) return true;
                if (c < 0) lo = mid + 1;
                else hi = mid - 1;
            }
        }
        return false;
    }

    // The String calls that turn an array decoder's result into the string, with the array type each reads.
    private static readonly Dictionary<string, string> Wrappers = new(StringComparer.Ordinal)
    {
        ["Ljava/lang/String;->valueOf([C)Ljava/lang/String;"] = "[C",
        ["Ljava/lang/String;->copyValueOf([C)Ljava/lang/String;"] = "[C",
        ["Ljava/lang/String;-><init>([C)V"] = "[C",
        ["Ljava/lang/String;-><init>([B)V"] = "[B",
        ["Ljava/lang/String;-><init>([BLjava/lang/String;)V"] = "[B",
        ["Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V"] = "[B",
    };

    /// <summary>The decoder calls of one method, in code order; empty when it has none or no code.</summary>
    public IReadOnlyList<DexFoldSite> Method(DexMethodEntry m)
    {
        lock (_lock)
        {
            if (_methods.TryGetValue(m.Descriptor, out var cached)) return cached;
            return _methods[m.Descriptor] = Scan(m);
        }
    }

    /// <summary>The decoder calls of every method; methods not reached within <paramref name="limit"/> (default <see cref="PackageTimeLimit"/>) are counted.</summary>
    public DexPackageFolds Package(CancellationToken ct, TimeSpan? limit = null)
    {
        _index.EnsureCode(ct);
        var callers = _index.Refs.Where(r => r.Kind == DexRefKind.Call && IsCall(r.Opcode) && Decodes(_index.KeyText(r.Target))
                || r.Kind == DexRefKind.Read && r.Opcode == 0x62 && IsTable(_index.KeyText(r.Target)))
            .Select(r => r.From).Distinct().Select(_index.KeyText).Order(StringComparer.Ordinal).ToList();
        var sites = new List<DexFoldSite>();
        var clock = Stopwatch.StartNew();
        int left = 0;
        foreach (var caller in callers)
        {
            ct.ThrowIfCancellationRequested();
            bool done;
            lock (_lock) done = _methods.ContainsKey(caller);
            if (!done && clock.Elapsed > (limit ?? PackageTimeLimit)) { left++; continue; }
            if (_index.Methods.TryGetValue(caller, out var m)) sites.AddRange(Method(m));
        }
        return new DexPackageFolds(sites, left);
    }

    private List<DexFoldSite> Scan(DexMethodEntry m)
    {
        var sites = new List<DexFoldSite>();
        if (m.Encoded.CodeOffset == 0 || m.File.Code(m.Encoded.CodeOffset) is not { } code) return sites;
        var insns = Dalvik.Decode(code.Instructions);
        if (!insns.Any(i => IsCall(i.Opcode) && Decodes(m.File.Method(i.Index).Descriptor) || i.Opcode == 0x62 && IsTable(m.File.Field(i.Index).Descriptor)))
            return sites;
        var starts = BlockStarts(code, insns);
        Pass(m, code, insns, starts, null, sites);
        // Values from earlier blocks are read only for a call that lacks one a constant load could give.
        if (insns.Count > MaxEntryInstructions || !sites.Any(s => !s.Evaluated)) return sites;
        var loaded = insns.Where(i => i.Opcode is >= 0x12 and <= 0x1c or >= 0x60 and <= 0x66).Select(i => i.A).ToHashSet();
        if (!insns.Any(i => IsCall(i.Opcode) && sites.Any(s => !s.Evaluated && s.Offset == i.Offset) && i.Arguments.Any(loaded.Contains))) return sites;
        var evaluated = sites.Where(s => s.Evaluated).DistinctBy(s => s.Offset).ToDictionary(s => s.Offset);
        var entries = BlockEntries(m, code, insns, starts);
        sites.Clear();
        Pass(m, code, insns, starts, entries, sites, evaluated);
        return sites;
    }

    /// <summary>Methods longer than this read each block on its own.</summary>
    private const int MaxEntryInstructions = 4096;

    private void Pass(DexMethodEntry m, DexCode code, List<DalvikInstruction> insns, HashSet<int> starts, Dictionary<int, Dictionary<int, object?>>? entries,
        List<DexFoldSite> sites, Dictionary<int, DexFoldSite>? evaluated = null)
    {
        var frame = new Frame(this, m, code, insns) { Evaluated = evaluated };
        foreach (var i in insns)
        {
            if (starts.Contains(i.Offset)) frame.Enter(entries?.GetValueOrDefault(i.Offset));
            frame.Step(i, sites);
        }
        // A wrapped call's site is added at its String call, after decoder calls that may lie in between.
        sites.Sort((a, b) => a.Offset.CompareTo(b.Offset));
    }

    private bool Decodes(string descriptor) => IsDecoder(descriptor) || IsArrayDecoder(descriptor);

    /// <summary>Rounds of the block entry pass at most; beyond them every block starts with nothing known.</summary>
    private const int MaxEntryRounds = 32;

    /// <summary>The numbers and strings every path into each block agrees on; handlers and unreached blocks start with nothing.</summary>
    private Dictionary<int, Dictionary<int, object?>> BlockEntries(DexMethodEntry m, DexCode code, List<DalvikInstruction> insns, HashSet<int> starts)
    {
        var order = starts.Append(0).Distinct().Order().ToList();
        var handlers = code.Tries.SelectMany(t => t.Handlers.Select(h => h.Item2)).ToHashSet();
        var entries = new Dictionary<int, Dictionary<int, object?>> { [0] = [] };
        var frame = new Frame(this, m, code, insns);
        var byOffset = insns.Select((i, k) => (i.Offset, k)).ToDictionary(p => p.Offset, p => p.k);
        bool changed = true;
        for (int round = 0; changed; round++)
        {
            if (round > MaxEntryRounds) return [];
            changed = false;
            for (int b = 0; b < order.Count; b++)
            {
                if (!entries.TryGetValue(order[b], out var entry) || !byOffset.TryGetValue(order[b], out int k)) continue;
                int end = b + 1 < order.Count ? order[b + 1] : int.MaxValue;
                frame.Enter(entry);
                DalvikInstruction last = insns[k];
                for (; k < insns.Count && insns[k].Offset < end; k++) frame.Step(last = insns[k], null);
                var exit = frame.Constants();
                foreach (int next in Successors(code, insns, last, end))
                {
                    if (handlers.Contains(next)) continue;
                    if (!entries.TryGetValue(next, out var prior)) { entries[next] = new(exit); changed = true; }
                    else
                        foreach (var (reg, value) in prior.ToList())
                            if (!exit.TryGetValue(reg, out var other) || !Equals(other, value)) { prior.Remove(reg); changed = true; }
                }
            }
        }
        return entries;
    }

    /// <summary>The block starts control reaches after <paramref name="last"/>, the final instruction of a block ending at <paramref name="end"/>.</summary>
    private static IEnumerable<int> Successors(DexCode code, List<DalvikInstruction> insns, DalvikInstruction last, int end)
    {
        switch (last.Format)
        {
            case DalvikFormat.F10t or DalvikFormat.F20t or DalvikFormat.F30t:
                yield return last.Target;
                yield break;
            case DalvikFormat.F21t or DalvikFormat.F22t:
                yield return last.Target;
                break;
            case DalvikFormat.F31t when last.Opcode is 0x2b or 0x2c && insns.FirstOrDefault(p => p.Offset == last.Target) is { IsPayload: true } payload:
                foreach (var (_, target) in Dalvik.SwitchTargets(code.Instructions, payload, last.Offset)) yield return target;
                break;
        }
        if (last.Opcode is not (>= 0x0e and <= 0x11 or 0x27) && end != int.MaxValue) yield return end;
    }

    /// <summary>Register values while one method is read in code order; one block at a time.</summary>
    private sealed class Frame(DexStringFolding owner, DexMethodEntry m, DexCode code, List<DalvikInstruction> insns)
    {
        private readonly Dictionary<int, object?> _known = [];
        // Arrays a call or an unknown store may have changed; arrays from static state are never written here.
        private readonly HashSet<DalvikArray> _changed = new(ReferenceEqualityComparer.Instance);
        // Copies of static String[] tables, with their fields; a copy keeps what a later decoder run does to the table out.
        private readonly Dictionary<DalvikArray, string> _tables = new(ReferenceEqualityComparer.Instance);
        private object? _pending;
        private bool _hasPending;

        /// <summary>Calls an earlier pass evaluated, by offset: reused rather than run again.</summary>
        public Dictionary<int, DexFoldSite>? Evaluated { get; init; }

        /// <summary>Starts a block with <paramref name="entry"/> known; null knows nothing.</summary>
        public void Enter(Dictionary<int, object?>? entry)
        {
            _known.Clear();
            if (entry != null) foreach (var (reg, value) in entry) _known[reg] = value;
            _hasPending = false;
        }

        /// <summary>The numbers and strings known now; arrays stay inside their block.</summary>
        public Dictionary<int, object?> Constants() => _known.Where(kv => kv.Value is int or long or string).ToDictionary();

        private bool Known(int reg, out object? v) => _known.TryGetValue(reg, out v) && v is not ArrayCall && !(v is DalvikArray a && _changed.Contains(a));

        private void Forget(int reg, bool wide = false) { _known.Remove(reg); if (wide) _known.Remove(reg + 1); }

        /// <summary>Applies one instruction; decoder calls are evaluated and recorded into <paramref name="sites"/>, or left unknown when it is null.</summary>
        public void Step(DalvikInstruction i, List<DexFoldSite>? sites)
        {
            bool setsPending = false;
            int op = i.Opcode;
            switch (op)
            {
                case >= 0x01 and <= 0x09:
                    if (_known.TryGetValue(i.B, out var moved)) _known[i.A] = moved;
                    else Forget(i.A, op is >= 0x04 and <= 0x06);
                    break;
                case >= 0x0a and <= 0x0c:
                    if (_hasPending) _known[i.A] = _pending;
                    else Forget(i.A, op == 0x0b);
                    break;
                case >= 0x12 and <= 0x15: _known[i.A] = (int)i.Literal; break;
                case >= 0x16 and <= 0x19: _known[i.A] = i.Literal; Forget(i.A + 1); break;
                case 0x1a or 0x1b: _known[i.A] = m.File.String(i.Index); break;
                case 0x23:
                    if (_known.TryGetValue(i.B, out var size) && size is int n and >= 0 and <= MaxArrayLiteral && m.File.Type(i.Index) is ['[', _, ..] arrayType)
                        _known[i.A] = new DalvikArray(arrayType, n);
                    else Forget(i.A);
                    break;
                case 0x24 or 0x25:
                {
                    var type = m.File.Type(i.Index);
                    if (type.Length > 1 && type[0] == '[' && type[1] is not ('J' or 'D') && i.Arguments.All(r => Known(r, out _)))
                    {
                        var array = new DalvikArray(type, i.Arguments.Count);
                        for (int k = 0; k < i.Arguments.Count; k++)
                            array[k] = array.Type[1] is 'L' or '[' ? (_known[i.Arguments[k]] is 0 ? null : _known[i.Arguments[k]]) : _known[i.Arguments[k]] as int? ?? 0;
                        _pending = array;
                    }
                    else _pending = null;
                    _hasPending = _pending != null;
                    setsPending = true;
                    break;
                }
                case 0x26:
                    if (_known.TryGetValue(i.A, out var target) && target is DalvikArray { Primitives: not null, Shared: false } filled && !_changed.Contains(filled)
                        && insns.FirstOrDefault(p => p.Offset == i.Target) is { Format: DalvikFormat.FillArrayPayload } payload)
                    {
                        var values = Dalvik.ArrayData(code.Instructions, payload, out _);
                        if (values.Count <= filled.Length)
                            for (int k = 0; k < values.Count; k++) filled[k] = filled.Type[1] is 'J' or 'D' ? values[k] : (object)(int)values[k];
                        else _changed.Add(filled);
                    }
                    else if (_known.TryGetValue(i.A, out var other) && other is DalvikArray o) _changed.Add(o);
                    break;
                case >= 0x4b and <= 0x51:
                    if (_known.TryGetValue(i.B, out var into) && into is DalvikArray dest)
                    {
                        if (!dest.Shared && !_changed.Contains(dest) && Known(i.C, out var index) && index is int at && (uint)at < (uint)dest.Length && Known(i.A, out var value))
                        {
                            if (dest.References != null) dest[at] = value is 0 ? null : value;
                            else if (value is int or long) dest[at] = value;
                            else _changed.Add(dest);
                        }
                        else _changed.Add(dest);
                    }
                    break;
                case >= 0x60 and <= 0x66:
                {
                    var field = m.File.Field(i.Index).Descriptor;
                    if (!owner._evaluator.TryReadStatic(field, out var staticValue)) Forget(i.A, op == 0x61);
                    else if (staticValue is DalvikArray { Type: "[Ljava/lang/String;" } table && owner.IsTable(field))
                    {
                        var copy = table.Copy();
                        _tables[copy] = field;
                        _known[i.A] = copy;
                    }
                    else _known[i.A] = staticValue;
                    break;
                }
                case 0x46:
                {
                    if (!_known.TryGetValue(i.B, out var from) || from is not DalvikArray { References: not null } array || _changed.Contains(array)
                        || !Known(i.C, out var index) || index is not int at || (uint)at >= (uint)array.Length || array[at] is not string element)
                    {
                        Forget(i.A);
                        break;
                    }
                    var field = _tables.GetValueOrDefault(array);
                    var writer = field != null ? owner.TableWriter(field) : null;
                    if (sites != null && field != null && !owner.IsLiteral(element))
                        sites.Add(new(m.Descriptor, i.Offset, field, writer == null
                            ? new(DexFoldStatus.Simplified, element, null)
                            : new(DexFoldStatus.Unknown, null, $"mutable-static: elements of {field} are written by {writer}")));
                    if (writer == null) _known[i.A] = element;
                    else Forget(i.A);
                    break;
                }
                case >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78:
                {
                    var callee = m.File.Method(i.Index);
                    if (sites != null && IsCall(op) && owner.IsDecoder(callee.Descriptor))
                    {
                        var site = Evaluated?.GetValueOrDefault(i.Offset) ?? owner.Call(m, i, callee, Known);
                        sites.Add(site);
                        _pending = site.Fold.Value;
                        _hasPending = site.Fold.Status == DexFoldStatus.Simplified;
                    }
                    else if (sites != null && IsCall(op) && owner.IsArrayDecoder(callee.Descriptor))
                    {
                        _pending = new ArrayCall(i, callee, owner.Receivers(callee.Descriptor), Known);
                        _hasPending = true;
                    }
                    else if (sites == null || !Wrappers.TryGetValue(callee.Descriptor, out var wrapped) || !Wrapped(i, callee, wrapped, sites)) _hasPending = false;
                    // The callee may write the arrays it is passed.
                    foreach (var r in i.Arguments)
                        if (_known.TryGetValue(r, out var passed) && passed is DalvikArray { Shared: false } array) _changed.Add(array);
                    setsPending = true;
                    break;
                }
                case 0x0e or >= 0x0f and <= 0x11 or 0x1d or 0x1e or 0x1f or >= 0x27 and <= 0x3d or >= 0x59 and <= 0x5f or >= 0x67 and <= 0x6d or 0x00:
                    break;
                default:
                    if (!i.IsPayload) Forget(i.A, true);
                    break;
            }
            if (!setsPending) _hasPending = false;
        }

        /// <summary>Records an array decoder call whose result <paramref name="wrapper"/> turns into a string; false when the array is not one.</summary>
        private bool Wrapped(DalvikInstruction i, DexMethodRef wrapper, string arrayType, List<DexFoldSite> sites)
        {
            bool init = wrapper.Name == "<init>";
            int first = init ? 1 : 0;
            if (i.Arguments.Count <= first || !_known.TryGetValue(i.Arguments[first], out var v) || v is not ArrayCall call
                || call.Callee.Proto.ReturnType != arrayType)
                return false;
            var site = Evaluated?.GetValueOrDefault(call.Offset) ?? owner.Wrapped(m, call, i, wrapper, Known);
            sites.Add(site);
            var value = site.Fold.Status == DexFoldStatus.Simplified ? site.Fold.Value : null;
            if (init)
            {
                if (value != null) _known[i.Arguments[0]] = value;
                else Forget(i.Arguments[0]);
                _hasPending = false;
            }
            else
            {
                _pending = value;
                _hasPending = value != null;
            }
            return true;
        }
    }

    /// <summary>An array decoder call not yet turned into a string: its constant arguments or the refusal; never passed on.</summary>
    private sealed class ArrayCall
    {
        public int Offset { get; }
        public DexMethodRef Callee { get; }
        public List<object?>? Arguments { get; }
        public string? Refusal { get; }

        public ArrayCall(DalvikInstruction i, DexMethodRef callee, int receivers, KnownRegister known)
        {
            Offset = i.Offset;
            Callee = callee;
            Arguments = Constants(i, callee.Proto.Parameters, receivers, 1, known, out var refusal);
            Refusal = refusal;
        }
    }

    private DexFoldSite Call(DexMethodEntry m, DalvikInstruction i, DexMethodRef callee, KnownRegister known)
    {
        if (Constants(i, callee.Proto.Parameters, Receivers(callee.Descriptor), 1, known, out var refusal) is not { } args)
            return new(m.Descriptor, i.Offset, callee.Descriptor, new(DexFoldStatus.Unknown, null, refusal), Evaluated: false);
        return new(m.Descriptor, i.Offset, callee.Descriptor, _evaluator.Fold(callee.Descriptor, args));
    }

    private DexFoldSite Wrapped(DexMethodEntry m, ArrayCall call, DalvikInstruction i, DexMethodRef wrapper, KnownRegister known)
    {
        DexFoldSite Site(DexFold fold, bool evaluated = true) => new(m.Descriptor, call.Offset, call.Callee.Descriptor, fold, evaluated, wrapper.Descriptor, i.Offset);
        if (call.Arguments == null) return Site(new(DexFoldStatus.Unknown, null, call.Refusal), false);
        // The String call's arguments after the array: a charset name or a Charset.
        if (Constants(i, wrapper.Proto.Parameters.Skip(1), wrapper.Name == "<init>" ? 2 : 1, 2, known, out var refusal) is not { } extra)
            return Site(new(DexFoldStatus.Unknown, null, $"{refusal} ({wrapper.Descriptor})"), false);
        return Site(_evaluator.Fold(call.Callee.Descriptor, call.Arguments, wrapper, extra));
    }

    /// <summary>Constant values of <paramref name="parameters"/> from register <paramref name="first"/> on; null with the refusal when one is unknown.</summary>
    private static List<object?>? Constants(DalvikInstruction i, IEnumerable<string> parameters, int first, int number, KnownRegister known, out string? refusal)
    {
        var args = new List<object?>();
        int k = first, p = number;
        foreach (var type in parameters)
        {
            int reg = k < i.Arguments.Count ? i.Arguments[k] : -1;
            if (reg < 0 || !known(reg, out var v))
            {
                refusal = $"not-constant: argument {p} (v{reg}) is not the same constant on every path to the call";
                return null;
            }
            args.Add(type.Length > 1 && v is 0 ? null : v);
            k += type is "J" or "D" ? 2 : 1;
            p++;
        }
        refusal = null;
        return args;
    }

    private delegate bool KnownRegister(int reg, out object? value);

    /// <summary>Offsets where a basic block starts: branch and switch targets, try starts and handlers, and code after a branch.</summary>
    private static HashSet<int> BlockStarts(DexCode code, List<DalvikInstruction> insns)
    {
        var starts = new HashSet<int>();
        var at = insns.ToDictionary(i => i.Offset);
        foreach (var i in insns)
        {
            switch (i.Format)
            {
                case DalvikFormat.F10t or DalvikFormat.F20t or DalvikFormat.F30t or DalvikFormat.F21t or DalvikFormat.F22t:
                    starts.Add(i.Target);
                    break;
                case DalvikFormat.F31t when i.Opcode is 0x2b or 0x2c && at.TryGetValue(i.Target, out var payload) && payload.IsPayload:
                    foreach (var (_, target) in Dalvik.SwitchTargets(code.Instructions, payload, i.Offset)) starts.Add(target);
                    break;
            }
            if (i.Opcode is >= 0x0e and <= 0x11 or 0x27 or >= 0x28 and <= 0x2a or >= 0x2b and <= 0x2c or >= 0x32 and <= 0x3d) starts.Add(i.Offset + i.Length);
        }
        foreach (var t in code.Tries)
        {
            starts.Add(t.Start);
            foreach (var (_, handler) in t.Handlers) starts.Add(handler);
        }
        return starts;
    }
}
