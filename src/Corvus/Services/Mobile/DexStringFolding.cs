using System.Diagnostics;
using System.Runtime.CompilerServices;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>
/// One call to a string decoder: the calling method, the call's code offset, the decoder and what the call returns.
/// <see cref="Evaluated"/> is false when an argument is not a constant, so the decoder did not run.
/// </summary>
public sealed record DexFoldSite(string Method, int Offset, string Decoder, DexFold Fold, bool Evaluated = true);

/// <summary>The decoder calls of a package, with the methods that were not reached within the time limit.</summary>
public sealed record DexPackageFolds(IReadOnlyList<DexFoldSite> Sites, int MethodsLeft);

/// <summary>
/// Finds the calls to string decoders of a package (static methods of its DEX code that return a string, called with
/// constant arguments) and evaluates them. Arguments are constants loaded in the call's basic block: numbers, strings,
/// arrays built there, values of static fields as their class initializers leave them when no other code writes them, and
/// strings earlier decoder calls return. Results are kept per package while it is loaded.
/// </summary>
public sealed class DexStringFolding
{
    /// <summary>The time one package-wide pass may take; a later pass continues where it stopped.</summary>
    public static readonly TimeSpan PackageTimeLimit = TimeSpan.FromSeconds(10);

    private const int MaxArrayLiteral = 65_536;
    private static readonly ConditionalWeakTable<DexIndex, DexStringFolding> Cache = [];

    private readonly DexIndex _index;
    private readonly DalvikEvaluator _evaluator;
    private readonly Dictionary<string, List<DexFoldSite>> _methods = new(StringComparer.Ordinal);
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

    /// <summary>A static method of the package returning a string, with at least one parameter.</summary>
    public bool IsDecoder(string descriptor) =>
        _index.Methods.TryGetValue(descriptor, out var m) && (m.Encoded.Access & 0x8) != 0 && m.Ref.Proto.ReturnType == "Ljava/lang/String;"
        && m.Ref.Proto.Parameters.Count > 0;

    /// <summary>The decoder calls of one method, in code order; empty when it has none or no code.</summary>
    public IReadOnlyList<DexFoldSite> Method(DexMethodEntry m)
    {
        lock (_lock)
        {
            if (_methods.TryGetValue(m.Descriptor, out var cached)) return cached;
            return _methods[m.Descriptor] = Scan(m);
        }
    }

    /// <summary>The decoder calls of every method that has one; methods not reached within <see cref="PackageTimeLimit"/> are counted.</summary>
    public DexPackageFolds Package(CancellationToken ct)
    {
        _index.EnsureCode(ct);
        var callers = _index.Refs.Where(r => r.Kind == DexRefKind.Call && r.Opcode is 0x71 or 0x77 && IsDecoder(_index.KeyText(r.Target)))
            .Select(r => r.From).Distinct().Select(_index.KeyText).Order(StringComparer.Ordinal).ToList();
        var sites = new List<DexFoldSite>();
        var clock = Stopwatch.StartNew();
        int left = 0;
        foreach (var caller in callers)
        {
            ct.ThrowIfCancellationRequested();
            bool done;
            lock (_lock) done = _methods.ContainsKey(caller);
            if (!done && clock.Elapsed > PackageTimeLimit) { left++; continue; }
            if (_index.Methods.TryGetValue(caller, out var m)) sites.AddRange(Method(m));
        }
        return new DexPackageFolds(sites, left);
    }

    private List<DexFoldSite> Scan(DexMethodEntry m)
    {
        var sites = new List<DexFoldSite>();
        if (m.Encoded.CodeOffset == 0 || m.File.Code(m.Encoded.CodeOffset) is not { } code) return sites;
        var insns = Dalvik.Decode(code.Instructions);
        if (!insns.Any(i => i.Opcode is 0x71 or 0x77 && IsDecoder(m.File.Method(i.Index).Descriptor))) return sites;
        var starts = BlockStarts(code, insns);
        var known = new Dictionary<int, object?>();
        // Arrays a call or an unknown store may have changed; arrays from static state are never written here.
        var changed = new HashSet<DalvikArray>(ReferenceEqualityComparer.Instance);
        object? pending = null;
        bool hasPending = false;
        bool Known(int reg, out object? v) => known.TryGetValue(reg, out v) && !(v is DalvikArray a && changed.Contains(a));
        void Forget(int reg, bool wide = false) { known.Remove(reg); if (wide) known.Remove(reg + 1); }
        foreach (var i in insns)
        {
            if (starts.Contains(i.Offset)) { known.Clear(); hasPending = false; }
            bool setsPending = false;
            int op = i.Opcode;
            switch (op)
            {
                case >= 0x01 and <= 0x09:
                    if (known.TryGetValue(i.B, out var moved)) known[i.A] = moved;
                    else Forget(i.A, op is >= 0x04 and <= 0x06);
                    break;
                case >= 0x0a and <= 0x0c:
                    if (hasPending) known[i.A] = pending;
                    else Forget(i.A, op == 0x0b);
                    break;
                case >= 0x12 and <= 0x15: known[i.A] = (int)i.Literal; break;
                case >= 0x16 and <= 0x19: known[i.A] = i.Literal; Forget(i.A + 1); break;
                case 0x1a or 0x1b: known[i.A] = m.File.String(i.Index); break;
                case 0x23:
                    if (known.TryGetValue(i.B, out var size) && size is int n and >= 0 and <= MaxArrayLiteral && m.File.Type(i.Index) is ['[', _, ..] arrayType)
                        known[i.A] = new DalvikArray(arrayType, n);
                    else Forget(i.A);
                    break;
                case 0x24 or 0x25:
                {
                    var type = m.File.Type(i.Index);
                    if (type.Length > 1 && type[0] == '[' && type[1] is not ('J' or 'D') && i.Arguments.All(r => Known(r, out _)))
                    {
                        var array = new DalvikArray(type, i.Arguments.Count);
                        for (int k = 0; k < i.Arguments.Count; k++)
                            array[k] = array.Type[1] is 'L' or '[' ? (known[i.Arguments[k]] is 0 ? null : known[i.Arguments[k]]) : known[i.Arguments[k]] as int? ?? 0;
                        pending = array;
                    }
                    else pending = null;
                    hasPending = pending != null;
                    setsPending = true;
                    break;
                }
                case 0x26:
                    if (known.TryGetValue(i.A, out var target) && target is DalvikArray { Primitives: not null, Shared: false } filled && !changed.Contains(filled)
                        && insns.FirstOrDefault(p => p.Offset == i.Target) is { Format: DalvikFormat.FillArrayPayload } payload)
                    {
                        var values = Dalvik.ArrayData(code.Instructions, payload, out _);
                        if (values.Count <= filled.Length)
                            for (int k = 0; k < values.Count; k++) filled[k] = filled.Type[1] is 'J' or 'D' ? values[k] : (object)(int)values[k];
                        else changed.Add(filled);
                    }
                    else if (known.TryGetValue(i.A, out var other) && other is DalvikArray o) changed.Add(o);
                    break;
                case >= 0x4b and <= 0x51:
                    if (known.TryGetValue(i.B, out var into) && into is DalvikArray dest)
                    {
                        if (!dest.Shared && !changed.Contains(dest) && Known(i.C, out var index) && index is int at && (uint)at < (uint)dest.Length && Known(i.A, out var value))
                        {
                            if (dest.References != null) dest[at] = value is 0 ? null : value;
                            else if (value is int or long) dest[at] = value;
                            else changed.Add(dest);
                        }
                        else changed.Add(dest);
                    }
                    break;
                case >= 0x60 and <= 0x66:
                    if (_evaluator.TryReadStatic(m.File.Field(i.Index).Descriptor, out var staticValue)) known[i.A] = staticValue;
                    else Forget(i.A, op == 0x61);
                    break;
                case >= 0x6e and <= 0x72 or >= 0x74 and <= 0x78:
                {
                    var callee = m.File.Method(i.Index);
                    var descriptor = callee.Descriptor;
                    if (op is 0x71 or 0x77 && IsDecoder(descriptor))
                    {
                        var site = Call(m, i, callee, Known);
                        sites.Add(site);
                        pending = site.Fold.Value;
                        hasPending = site.Fold.Status == DexFoldStatus.Simplified;
                    }
                    else hasPending = false;
                    // The callee may write the arrays it is passed.
                    foreach (var r in i.Arguments)
                        if (known.TryGetValue(r, out var passed) && passed is DalvikArray { Shared: false } array) changed.Add(array);
                    setsPending = true;
                    break;
                }
                case 0x0e or >= 0x0f and <= 0x11 or 0x1d or 0x1e or 0x1f or >= 0x27 and <= 0x3d or >= 0x59 and <= 0x5f or >= 0x67 and <= 0x6d or 0x00:
                    break;
                default:
                    if (!i.IsPayload) Forget(i.A, true);
                    break;
            }
            if (!setsPending) hasPending = false;
        }
        return sites;
    }

    private DexFoldSite Call(DexMethodEntry m, DalvikInstruction i, DexMethodRef callee, KnownRegister known)
    {
        var args = new List<object?>();
        int k = 0;
        for (int p = 0; p < callee.Proto.Parameters.Count; p++)
        {
            var type = callee.Proto.Parameters[p];
            int reg = k < i.Arguments.Count ? i.Arguments[k] : -1;
            if (reg < 0 || !known(reg, out var v))
                return new(m.Descriptor, i.Offset, callee.Descriptor,
                    new(DexFoldStatus.Unknown, null, $"not-constant: argument {p + 1} (v{reg}) is not a constant in the call's block"), Evaluated: false);
            args.Add(type.Length > 1 && v is 0 ? null : v);
            k += type is "J" or "D" ? 2 : 1;
        }
        return new(m.Descriptor, i.Offset, callee.Descriptor, _evaluator.Fold(callee.Descriptor, args));
    }

    private delegate bool KnownRegister(int reg, out object? value);

    /// <summary>Offsets where a basic block starts: branch and switch targets, try starts and handlers, and code after a jump.</summary>
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
            if (i.Opcode is >= 0x0e and <= 0x11 or 0x27 or >= 0x28 and <= 0x2a) starts.Add(i.Offset + i.Length);
        }
        foreach (var t in code.Tries)
        {
            starts.Add(t.Start);
            foreach (var (_, handler) in t.Handlers) starts.Add(handler);
        }
        return starts;
    }
}
